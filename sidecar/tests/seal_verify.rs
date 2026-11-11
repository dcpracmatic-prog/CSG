//! Test de integración: levanta el sidecar real y hace seal -> verify.
//!
//! Usa solo std + serde_json + el crate `sello_integridad` (para el hash
//! SHA3-256 y la verificación independiente del sello).

use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::process::{Child, Command};
use std::time::{Duration, Instant};

use sello_integridad::crypto::{sha3_256, to_hex};
use sello_integridad::{verificar_sello, Sello};

#[path = "../src/b64.rs"]
mod b64;

const CONTENIDO: &[u8] = b"contenido de prueba CSG - seal/verify";

fn puerto_libre() -> u16 {
    TcpListener::bind("127.0.0.1:0").unwrap().local_addr().unwrap().port()
}

fn levantar(puerto: u16) -> Child {
    let bin = env!("CARGO_BIN_EXE_csg-sidecar");
    let mut cmd = Command::new(bin);
    cmd.env("CSG_HOST", "127.0.0.1")
        .env("CSG_PORT", puerto.to_string())
        .env("CSG_NOTARIO_NAME", "Test-Notario")
        .env("CSG_RETARDO_BASE_MS", "0")
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null());
    cmd.spawn().expect("no se pudo lanzar csg-sidecar")
}

/// Petición HTTP/1.1 mínima sobre TcpStream. Devuelve (status, cuerpo JSON).
fn http(metodo: &str, puerto: u16, ruta: &str, body: Option<&serde_json::Value>) -> (u16, serde_json::Value) {
    let mut stream = TcpStream::connect(("127.0.0.1", puerto)).expect("conectar al sidecar");
    stream.set_read_timeout(Some(Duration::from_secs(10))).unwrap();
    let cuerpo = body.map(|b| b.to_string()).unwrap_or_default();
    let peticion = format!(
        "{metodo} {ruta} HTTP/1.1\r\nHost: 127.0.0.1:{puerto}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{cuerpo}",
        cuerpo.len()
    );
    stream.write_all(peticion.as_bytes()).unwrap();
    let mut resp = Vec::new();
    stream.read_to_end(&mut resp).unwrap();
    let texto = String::from_utf8_lossy(&resp);
    let status: u16 = texto
        .split_whitespace()
        .nth(1)
        .and_then(|s| s.parse().ok())
        .expect("status en la respuesta");
    let json_txt = texto.split("\r\n\r\n").nth(1).unwrap_or("{}");
    let valor: serde_json::Value =
        serde_json::from_str(json_txt).expect("cuerpo JSON en la respuesta");
    (status, valor)
}

fn esperar_salud(puerto: u16) {
    let inicio = Instant::now();
    loop {
        if TcpStream::connect(("127.0.0.1", puerto)).is_ok() {
            let (status, _) = http("GET", puerto, "/healthz", None);
            if status == 200 {
                return;
            }
        }
        if inicio.elapsed() > Duration::from_secs(15) {
            panic!("el sidecar no respondió /healthz en 15 s");
        }
        std::thread::sleep(Duration::from_millis(100));
    }
}

#[test]
fn seal_verify_ok_y_alterado() {
    let puerto = puerto_libre();
    let mut hijo = levantar(puerto);
    let _guarda = scopeguard(&mut hijo);
    esperar_salud(puerto);

    // GET /v1/status
    let (status, st) = http("GET", puerto, "/v1/status", None);
    assert_eq!(status, 200, "status: {st}");
    assert_eq!(st["notario_name"], "Test-Notario");
    assert!(!st["notario_pub"].as_str().unwrap().is_empty());

    // POST /v1/seal
    let (status, sello) = http(
        "POST",
        puerto,
        "/v1/seal",
        Some(&serde_json::json!({
            "content_base64": b64::encode(CONTENIDO),
            "label": "test-integracion",
            "attributes": { "origen": "cargo-test" },
            "proyecto_id": "tdcp",
        })),
    );
    assert_eq!(status, 200, "seal: {sello}");
    assert_eq!(sello["schema"], "csg.sello.v1");
    assert_eq!(sello["aceptado"], true, "sello rechazado: {sello}");
    assert_eq!(sello["label"], "test-integracion");
    assert_eq!(sello["attributes"]["origen"], "cargo-test");
    assert_eq!(sello["hash_contenido"], to_hex(&sha3_256(CONTENIDO)));
    assert_eq!(sello["developmentOnly"], false);
    let notario_pub = sello["notario_pub"].as_str().unwrap().to_string();
    assert!(!notario_pub.is_empty());

    // Verificación independiente con el crate (sin pasar por el sidecar).
    let sello_struct: Sello = serde_json::from_value(sello.clone()).unwrap();
    let reporte = verificar_sello(&sello_struct, &notario_pub, None).unwrap();
    assert!(reporte.todo_valido, "verificación independiente falló: {reporte:?}");

    // POST /v1/verify con el contenido original -> OK
    let (status, rep) = http(
        "POST",
        puerto,
        "/v1/verify",
        Some(&serde_json::json!({
            "content_base64": b64::encode(CONTENIDO),
            "sello": sello,
        })),
    );
    assert_eq!(status, 200, "verify: {rep}");
    assert_eq!(rep["todo_valido"], true, "verify OK esperado: {rep}");
    assert_eq!(rep["checks"]["content_digest_match"], true);
    assert_eq!(rep["checks"]["cuerpo_no_alterado"], true);
    assert_eq!(rep["checks"]["firma_notario_valida"], true);
    assert_eq!(rep["checks"]["aceptado"], true);
    assert_eq!(rep["hash_contenido"], to_hex(&sha3_256(CONTENIDO)));

    // POST /v1/verify con contenido alterado -> NO válido
    let (status, rep) = http(
        "POST",
        puerto,
        "/v1/verify",
        Some(&serde_json::json!({
            "content_base64": b64::encode(b"contenido ALTERADO"),
            "sello": sello,
        })),
    );
    assert_eq!(status, 200, "verify alterado: {rep}");
    assert_eq!(rep["todo_valido"], false, "contenido alterado debe ser NO válido");
    assert_eq!(rep["checks"]["content_digest_match"], false);
    // El sello en sí sigue intacto: cuerpo y firma siguen siendo válidos.
    assert_eq!(rep["checks"]["cuerpo_no_alterado"], true);
    assert_eq!(rep["checks"]["firma_notario_valida"], true);

    // POST /v1/verify con el sello manipulado (aceptado invertido) -> NO válido
    let mut sello_roto = sello.clone();
    sello_roto["aceptado"] = serde_json::json!(false);
    let (status, rep) = http(
        "POST",
        puerto,
        "/v1/verify",
        Some(&serde_json::json!({
            "content_base64": b64::encode(CONTENIDO),
            "sello": sello_roto,
        })),
    );
    assert_eq!(status, 200, "verify sello roto: {rep}");
    assert_eq!(rep["todo_valido"], false);
    assert_eq!(rep["checks"]["cuerpo_no_alterado"], false);
    assert_eq!(rep["checks"]["firma_notario_valida"], false);
    assert_eq!(rep["checks"]["aceptado"], false);

    // POST /v1/seal sin content_base64 -> 400
    let (status, err) = http("POST", puerto, "/v1/seal", Some(&serde_json::json!({})));
    assert_eq!(status, 400, "seal sin contenido: {err}");

    // POST /v1/seal con el mismo evento_id dos veces -> replay rechazado
    let cuerpo_replay = serde_json::json!({
        "content_base64": b64::encode(b"replay"),
        "proyecto_id": "tdcp",
        "evento_id": "evt-replay-test",
    });
    let (s1, sello1) = http("POST", puerto, "/v1/seal", Some(&cuerpo_replay));
    assert_eq!(s1, 200);
    assert_eq!(sello1["aceptado"], true);
    let (s2, sello2) = http("POST", puerto, "/v1/seal", Some(&cuerpo_replay));
    assert_eq!(s2, 200);
    assert_eq!(sello2["aceptado"], false, "replay debe rechazarse: {sello2}");
    assert_eq!(sello2["razon"], "replay_detectado");
}

/// Mata el proceso hijo al salir del test (también si hay panic).
struct Guarda<'a>(&'a mut Child);
fn scopeguard(hijo: &mut Child) -> Guarda<'_> {
    Guarda(hijo)
}
impl Drop for Guarda<'_> {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}
