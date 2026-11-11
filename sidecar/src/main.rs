//! CSG Sello de Integridad — sidecar HTTP.
//!
//! Envoltura HTTP fina (solo std: `TcpListener` + parseo manual) sobre el
//! crate real `sello_integridad` (`NotarioProtegido` + `Firmante`,
//! Ed25519 + SHA3-256). Ninguna criptografía se reimplementa aquí: el
//! sellado y la verificación los hace el crate; este binario solo traduce
//! entre HTTP/JSON y las llamadas al crate.
//!
//! Contrato (el que espera `tdcp/src/protection/csg-client.ts`, alineado
//! con `tdcp/server/csg-sidecar/main.py`):
//!
//! * `GET  /healthz`   -> `{ ok, service, notario, estructura_rota, version }`
//! * `GET  /v1/status` -> `{ notario_name, notario_pub, firmante_pub,
//!                          chain_tip, conatus, estructura_rota,
//!                          intentos_fallidos, total_sellos }`
//! * `POST /v1/seal`   `{ content_base64, label?, attributes?,
//!                       proyecto_id?, evento_id? }`
//!   -> sello `csg.sello.v1` (campos del `Sello` del crate + `schema`,
//!   `label`, `attributes`, `notario_pub`, `developmentOnly`).
//! * `POST /v1/verify` `{ content_base64, sello }`
//!   -> `{ todo_valido, checks { content_digest_match, cuerpo_no_alterado,
//!        firma_notario_valida, aceptado }, hash_contenido, schema }`
//!
//! Configuración por entorno:
//!
//! * `CSG_HOST` (def. `127.0.0.1`), `CSG_PORT` (def. `8010`)
//! * `CSG_NOTARIO_NAME` (def. `CSG-Notario`)
//! * `CSG_PROJECTS` (def. `tdcp`): proyectos para los que el firmante
//!   interno está autorizado, separados por comas.
//! * `CSG_UMBRAL_RUPTURA` (def. `8`), `CSG_FACTOR_ENDURECIMIENTO`
//!   (def. `1.5`), `CSG_RETARDO_BASE_MS` (def. `50`): política de
//!   conatus/ruptura del `NotarioProtegido` (mismos valores que el
//!   sidecar de referencia de TDCP).
//!
//! Notas de seguridad / comportamiento:
//!
//! * Las claves del notario y del firmante interno se generan al arrancar
//!   y viven solo en el proceso: al reiniciar cambian. Los sellos siguen
//!   siendo verificables porque cada sello lleva su `notario_pub` y
//!   `/v1/verify` verifica contra el `notario_pub` del propio sello.
//! * `label` y `attributes` son campos de sobre (envelope): se devuelven
//!   tal cual, NO forman parte del cuerpo firmado — igual que en el
//!   sidecar de referencia de TDCP.
//! * Reutilizar un `evento_id` ya sellado devuelve un sello rechazado
//!   (`aceptado: false`, `razon: "replay_detectado"`): es la protección
//!   anti-replay del crate. Sin `evento_id` el sidecar genera uno único.
//! * Un `proyecto_id` no autorizado devuelve un sello rechazado
//!   (`razon: "firmante_no_autorizado"`) y cuenta como fallo de conatus;
//!   tras `CSG_UMBRAL_RUPTURA` fallos la estructura se rompe y `/v1/seal`
//!   responde 503 hasta reiniciar el proceso (recuperación fuera de banda).

use std::io::{BufRead, BufReader, Read, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use sello_integridad::crypto::{sha3_256, to_hex};
use sello_integridad::{
    verificar_sello, ClaveMaestraDanio, Firmante, NotarioProtegido, PoliticaConatus, Sello,
};
use serde_json::{json, Value};

mod b64;

const SCHEMA: &str = "csg.sello.v1";
/// Límite de cuerpo JSON aceptado (64 MiB).
const MAX_BODY: usize = 64 * 1024 * 1024;
/// Límite de cabeceras aceptadas (64 KiB).
const MAX_HEADERS: usize = 64 * 1024;

struct Config {
    host: String,
    port: u16,
    notario_name: String,
    proyectos: Vec<String>,
    politica: PoliticaConatus,
}

impl Config {
    fn from_env() -> Self {
        let politica = PoliticaConatus {
            umbral_ruptura: env_u32("CSG_UMBRAL_RUPTURA", 8),
            factor_endurecimiento: env_f64("CSG_FACTOR_ENDURECIMIENTO", 1.5),
            retardo_base_ms: env_u64("CSG_RETARDO_BASE_MS", 50),
        };
        let proyectos = std::env::var("CSG_PROJECTS")
            .unwrap_or_else(|_| "tdcp".to_string())
            .split(',')
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty())
            .collect::<Vec<_>>();
        Self {
            host: std::env::var("CSG_HOST").unwrap_or_else(|_| "127.0.0.1".to_string()),
            port: env_u16("CSG_PORT", 8010),
            notario_name: std::env::var("CSG_NOTARIO_NAME")
                .unwrap_or_else(|_| "CSG-Notario".to_string()),
            proyectos: if proyectos.is_empty() {
                vec!["tdcp".to_string()]
            } else {
                proyectos
            },
            politica,
        }
    }
}

fn env_u16(key: &str, def: u16) -> u16 {
    std::env::var(key).ok().and_then(|v| v.parse().ok()).unwrap_or(def)
}
fn env_u32(key: &str, def: u32) -> u32 {
    std::env::var(key).ok().and_then(|v| v.parse().ok()).unwrap_or(def)
}
fn env_u64(key: &str, def: u64) -> u64 {
    std::env::var(key).ok().and_then(|v| v.parse().ok()).unwrap_or(def)
}
fn env_f64(key: &str, def: f64) -> f64 {
    std::env::var(key).ok().and_then(|v| v.parse().ok()).unwrap_or(def)
}

/// Estado compartido del sidecar: el notario protegido y el firmante
/// interno son los del crate; nada más.
struct Estado {
    notario: NotarioProtegido,
    firmante: Firmante,
    nombre: String,
    contador: AtomicU64,
}

impl Estado {
    fn nuevo(cfg: &Config) -> Self {
        let notario = NotarioProtegido::con_politica(
            cfg.notario_name.clone(),
            cfg.politica.clone(),
            Some(ClaveMaestraDanio::generar()),
        );
        let firmante = Firmante::generar("csg-sidecar");
        for proyecto in &cfg.proyectos {
            notario.registrar_firmante_autorizado(proyecto, firmante.clave_publica_hex());
        }
        Self {
            notario,
            firmante,
            nombre: cfg.notario_name.clone(),
            contador: AtomicU64::new(0),
        }
    }

    fn generar_evento_id(&self) -> String {
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0);
        let n = self.contador.fetch_add(1, Ordering::Relaxed);
        format!("evt-{nanos:x}-{n:x}")
    }
}

fn main() {
    let cfg = Config::from_env();
    let estado = Arc::new(Estado::nuevo(&cfg));
    let listener = TcpListener::bind((cfg.host.as_str(), cfg.port)).unwrap_or_else(|e| {
        eprintln!("[CSG] no se pudo escuchar en {}:{}: {e}", cfg.host, cfg.port);
        std::process::exit(1);
    });
    eprintln!(
        "[CSG] Notario={} pub={}…",
        estado.nombre,
        &estado.notario.clave_publica_hex()[..16]
    );
    eprintln!(
        "[CSG] Firmante interno pub={}… proyectos={:?}",
        &estado.firmante.clave_publica_hex()[..16],
        cfg.proyectos
    );
    eprintln!("[CSG] Escuchando en http://{}:{}", cfg.host, cfg.port);
    for stream in listener.incoming() {
        match stream {
            Ok(stream) => {
                let estado = Arc::clone(&estado);
                std::thread::spawn(move || atender(stream, &estado));
            }
            Err(e) => eprintln!("[CSG] error al aceptar conexión: {e}"),
        }
    }
}

fn atender(mut stream: TcpStream, estado: &Arc<Estado>) {
    let _ = stream.set_read_timeout(Some(Duration::from_secs(30)));
    let _ = stream.set_write_timeout(Some(Duration::from_secs(30)));
    let (status, cuerpo) = match leer_peticion(&mut stream) {
        Ok((metodo, ruta, body)) => {
            let r = enrutar(estado, &metodo, &ruta, body.as_deref());
            eprintln!("[CSG] {} {} -> {}", metodo, ruta, r.0);
            r
        }
        Err((status, msg)) => {
            eprintln!("[CSG] petición inválida -> {status} {msg}");
            (status, json!({ "error": msg }))
        }
    };
    let _ = escribir_respuesta(&mut stream, status, &cuerpo);
}

/// Lee una petición HTTP/1.x: línea de petición, cabeceras y cuerpo
/// según `Content-Length`. Devuelve `(método, ruta, cuerpo)`.
fn leer_peticion(stream: &mut TcpStream) -> Result<(String, String, Option<Vec<u8>>), (u16, String)> {
    let mut lector = BufReader::new(stream.try_clone().map_err(|e| (400, e.to_string()))?);
    let mut linea = String::new();
    lector
        .read_line(&mut linea)
        .map_err(|e| (400, format!("no se pudo leer la petición: {e}")))?;
    if linea.trim().is_empty() {
        return Err((400, "petición vacía".to_string()));
    }
    let partes: Vec<&str> = linea.trim_end().split_whitespace().collect();
    if partes.len() < 2 {
        return Err((400, "línea de petición inválida".to_string()));
    }
    let metodo = partes[0].to_string();
    let ruta = partes[1].split('?').next().unwrap_or("/").to_string();

    let mut content_length: usize = 0;
    let mut expect_continue = false;
    let mut leidas = 0usize;
    loop {
        let mut cab = String::new();
        lector
            .read_line(&mut cab)
            .map_err(|e| (400, format!("no se pudieron leer cabeceras: {e}")))?;
        leidas += cab.len();
        if leidas > MAX_HEADERS {
            return Err((431, "cabeceras demasiado grandes".to_string()));
        }
        let cab = cab.trim_end();
        if cab.is_empty() {
            break;
        }
        if let Some((k, v)) = cab.split_once(':') {
            match k.trim().to_ascii_lowercase().as_str() {
                "content-length" => {
                    content_length = v
                        .trim()
                        .parse()
                        .map_err(|_| (400, "Content-Length inválido".to_string()))?;
                }
                "expect" if v.trim().eq_ignore_ascii_case("100-continue") => {
                    expect_continue = true;
                }
                _ => {}
            }
        }
    }
    if content_length > MAX_BODY {
        return Err((413, "cuerpo demasiado grande".to_string()));
    }
    if expect_continue {
        let _ = stream.write_all(b"HTTP/1.1 100 Continue\r\n\r\n");
    }
    let cuerpo = if content_length > 0 {
        let mut buf = vec![0u8; content_length];
        lector
            .read_exact(&mut buf)
            .map_err(|e| (400, format!("no se pudo leer el cuerpo: {e}")))?;
        Some(buf)
    } else {
        None
    };
    Ok((metodo, ruta, cuerpo))
}

fn escribir_respuesta(stream: &mut TcpStream, status: u16, cuerpo: &Value) -> std::io::Result<()> {
    let datos = serde_json::to_string(cuerpo).unwrap_or_else(|_| "{\"error\":\"serialize\"}".into());
    let razon = match status {
        200 => "OK",
        204 => "No Content",
        400 => "Bad Request",
        404 => "Not Found",
        413 => "Content Too Large",
        431 => "Request Header Fields Too Large",
        500 => "Internal Server Error",
        503 => "Service Unavailable",
        _ => "OK",
    };
    let mut resp = format!(
        "HTTP/1.1 {status} {razon}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nAccess-Control-Allow-Origin: *\r\nAccess-Control-Allow-Methods: GET, POST, OPTIONS\r\nAccess-Control-Allow-Headers: Content-Type\r\nConnection: close\r\n\r\n",
        datos.len()
    );
    resp.push_str(&datos);
    stream.write_all(resp.as_bytes())
}

fn enrutar(estado: &Arc<Estado>, metodo: &str, ruta: &str, body: Option<&[u8]>) -> (u16, Value) {
    if metodo == "OPTIONS" {
        return (204, json!({}));
    }
    match (metodo, ruta) {
        ("GET", "/healthz") => {
            let prot = estado.notario.estado_proteccion();
            (
                200,
                json!({
                    "ok": true,
                    "service": "csg-sello-sidecar",
                    "notario": estado.nombre,
                    "estructura_rota": prot.estructura_rota,
                    "version": env!("CARGO_PKG_VERSION"),
                }),
            )
        }
        ("GET", "/v1/status") => {
            let prot = estado.notario.estado_proteccion();
            (
                200,
                json!({
                    "notario_name": estado.nombre,
                    "notario_pub": estado.notario.clave_publica_hex(),
                    "firmante_pub": estado.firmante.clave_publica_hex(),
                    "chain_tip": estado.notario.ultimo_hash(),
                    "conatus": prot.conatus,
                    "estructura_rota": prot.estructura_rota,
                    "intentos_fallidos": prot.intentos_fallidos,
                    "total_sellos": estado.notario.sellos().len(),
                }),
            )
        }
        ("POST", "/v1/seal") => sellar(estado, body),
        ("POST", "/v1/verify") => verificar(estado, body),
        _ => (404, json!({ "error": "not found" })),
    }
}

fn parse_json_body(body: Option<&[u8]>) -> Result<Value, (u16, Value)> {
    let raw = body.unwrap_or(b"{}");
    serde_json::from_slice(raw)
        .map_err(|_| (400, json!({ "error": "invalid JSON" })))
}

fn contenido_base64(body: &Value) -> Result<Vec<u8>, (u16, Value)> {
    match body.get("content_base64").and_then(|v| v.as_str()) {
        Some(s) if !s.is_empty() => b64::decode(s)
            .map_err(|e| (400, json!({ "error": format!("invalid content_base64: {e}") }))),
        _ => Err((400, json!({ "error": "content_base64 required" }))),
    }
}

/// POST /v1/seal — sella con el `NotarioProtegido` del crate.
fn sellar(estado: &Arc<Estado>, body: Option<&[u8]>) -> (u16, Value) {
    let body = match parse_json_body(body) {
        Ok(b) => b,
        Err(e) => return e,
    };
    let contenido = match contenido_base64(&body) {
        Ok(c) => c,
        Err(e) => return e,
    };
    let label = body
        .get("label")
        .and_then(|v| v.as_str())
        .unwrap_or("tdcp-integrity");
    let attributes = body
        .get("attributes")
        .filter(|v| v.is_object())
        .cloned()
        .unwrap_or_else(|| json!({}));
    let proyecto_id = body
        .get("proyecto_id")
        .and_then(|v| v.as_str())
        .unwrap_or("tdcp");
    let evento_id = match body.get("evento_id").and_then(|v| v.as_str()) {
        Some(s) if !s.is_empty() => s.to_string(),
        _ => estado.generar_evento_id(),
    };

    // El firmante interno del sidecar crea y firma el evento con el
    // contenido real; el notario lo sella (o lo rechaza con razón).
    let (evento, firma) = match estado
        .firmante
        .crear_evento_archivo(&contenido, proyecto_id, Some(evento_id))
    {
        Ok(p) => p,
        Err(e) => return (500, json!({ "error": format!("crear evento: {e}") })),
    };
    match estado
        .notario
        .sellar_archivo(&evento, &firma, &estado.firmante.clave_publica())
    {
        Ok(sello) => {
            // Sobre (envelope) csg.sello.v1: el Sello del crate más los
            // campos que lee el cliente TDCP. label/attributes NO se
            // firman (igual que en el sidecar de referencia de TDCP).
            let mut out = serde_json::to_value(&sello)
                .unwrap_or_else(|_| json!({ "error": "serialize" }));
            if let Some(obj) = out.as_object_mut() {
                obj.insert("schema".to_string(), json!(SCHEMA));
                obj.insert("label".to_string(), json!(label));
                obj.insert("attributes".to_string(), attributes);
                obj.insert(
                    "notario_pub".to_string(),
                    json!(estado.notario.clave_publica_hex()),
                );
                obj.insert("developmentOnly".to_string(), json!(false));
            }
            (200, out)
        }
        Err(e) => (
            503,
            json!({ "error": format!("{e}") }),
        ),
    }
}

/// POST /v1/verify — verifica con `verificar_sello` del crate.
fn verificar(estado: &Arc<Estado>, body: Option<&[u8]>) -> (u16, Value) {
    let body = match parse_json_body(body) {
        Ok(b) => b,
        Err(e) => return e,
    };
    let contenido = match contenido_base64(&body) {
        Ok(c) => c,
        Err(e) => return e,
    };
    let sello_val = match body.get("sello") {
        Some(v) if v.is_object() => v.clone(),
        _ => return (400, json!({ "error": "content_base64 and sello required" })),
    };
    let sello: Sello = match serde_json::from_value(sello_val.clone()) {
        Ok(s) => s,
        Err(e) => return (400, json!({ "error": format!("sello inválido: {e}") })),
    };

    let hash_contenido = to_hex(&sha3_256(&contenido));
    let content_digest_match = hash_contenido == sello.hash_contenido;

    // La clave del notario es la del propio sello si la trae (sellos de
    // otra instancia / otro arranque siguen verificándose); si no,
    // la del notario de este proceso.
    let notario_pub = sello_val
        .get("notario_pub")
        .and_then(|v| v.as_str())
        .filter(|s| !s.is_empty())
        .map(|s| s.to_string())
        .unwrap_or_else(|| estado.notario.clave_publica_hex());
    let reporte = match verificar_sello(&sello, &notario_pub, None) {
        Ok(r) => r,
        Err(e) => return (500, json!({ "error": format!("verificar sello: {e}") })),
    };

    let todo_valido = content_digest_match
        && reporte.checks.cuerpo_no_alterado
        && reporte.checks.firma_notario_valida
        && sello.aceptado;
    (
        200,
        json!({
            "todo_valido": todo_valido,
            "checks": {
                "content_digest_match": content_digest_match,
                "cuerpo_no_alterado": reporte.checks.cuerpo_no_alterado,
                "firma_notario_valida": reporte.checks.firma_notario_valida,
                "aceptado": sello.aceptado,
            },
            "hash_contenido": hash_contenido,
            "schema": sello_val.get("schema").and_then(|v| v.as_str()).unwrap_or(SCHEMA),
        }),
    )
}
