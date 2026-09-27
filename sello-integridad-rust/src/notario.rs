//! Implementación del Notario - emisor de sellos
//!
//! El Notario es la autoridad que emite sellos de integridad.
//! Su clave privada es crítica: su compromiso invalida toda la cadena.

use parking_lot::RwLock;
use std::collections::{HashMap, HashSet};
use std::sync::Arc;

use crate::crypto::{json_canonico, sha3_256, to_hex, ClavePrivada, ClavePublica, FirmaBytes};
use crate::error::Result;
use crate::evento::{CuerpoSello, Evento, TipoEvento};
use crate::sello::{Sello, GENESIS_HASH};

/// Notario de integridad - emisor de sellos
///
/// # Seguridad
/// - La clave privada nunca sale de esta estructura
/// - El estado es thread-safe (RwLock para lectura concurrente)
/// - No acumula penalización entre eventos (diseño "vértice efímero")
///
/// # Persistencia
/// La cadena de sellos vive en memoria. Para producción, usar
/// `NotarioPersistente` o implementar `AlmacenSellos`.
pub struct Notario {
    /// Nombre identificador del notario
    nombre: String,

    /// Clave privada del notario (protegida, no clonable)
    clave_privada: ClavePrivada,

    /// Estado compartido thread-safe
    estado: Arc<RwLock<EstadoNotario>>,
}

/// Estado interno del notario
struct EstadoNotario {
    /// Eventos ya procesados (prevención de replay)
    vistos: HashSet<String>,

    /// Cadena de sellos emitidos
    sellos: Vec<Sello>,

    /// Hash del último sello (para encadenamiento)
    ultimo_hash: String,

    /// Firmantes autorizados por proyecto
    autorizados: HashMap<String, HashSet<String>>,
}

/// Heurística de depuración: ¿este `Value` tiene la forma de un
/// `Evento` serializado (los campos que produce `Evento::nuevo`)?
///
/// Solo se usa en `debug_assert!` dentro de `notarizar_transaccion`
/// para avisar en desarrollo/tests del uso confuso descrito en su
/// documentación; nunca cambia el comportamiento en release ni rechaza
/// nada — sigue siendo válido pasar una transacción que legítimamente
/// tenga estos mismos nombres de campo por otra razón.
fn parece_evento_serializado(value: &serde_json::Value) -> bool {
    let Some(obj) = value.as_object() else {
        return false;
    };
    ["evento_id", "hash_contenido", "tipo", "proyecto_id", "timestamp"]
        .iter()
        .all(|campo| obj.contains_key(*campo))
}

impl Notario {
    /// Crea un nuevo notario con clave generada aleatoriamente
    pub fn nuevo(nombre: impl Into<String>) -> Self {
        Self {
            nombre: nombre.into(),
            clave_privada: ClavePrivada::generar(),
            estado: Arc::new(RwLock::new(EstadoNotario {
                vistos: HashSet::new(),
                sellos: Vec::new(),
                ultimo_hash: GENESIS_HASH.to_string(),
                autorizados: HashMap::new(),
            })),
        }
    }

    /// Crea un notario desde una clave privada existente (para restauración)
    ///
    /// # Seguridad
    /// La clave privada se consume y se borra de la memoria original
    ///
    /// # Nota
    /// Este constructor deja el estado (cadena de sellos, `vistos`,
    /// autorizados) vacío. Para restaurar un notario que ya tenía
    /// historial, usar [`Self::desde_clave_y_estado`] con lo que se
    /// haya recuperado de un almacén persistente — de lo contrario la
    /// protección contra replay no cubre eventos ya sellados antes del
    /// reinicio.
    pub fn desde_clave(nombre: impl Into<String>, clave: ClavePrivada) -> Self {
        Self {
            nombre: nombre.into(),
            clave_privada: clave,
            estado: Arc::new(RwLock::new(EstadoNotario {
                vistos: HashSet::new(),
                sellos: Vec::new(),
                ultimo_hash: GENESIS_HASH.to_string(),
                autorizados: HashMap::new(),
            })),
        }
    }

    /// Crea un notario desde una clave privada y un estado previamente
    /// recuperado (cadena de sellos ya verificada + autorizados).
    ///
    /// # Uso
    /// Pensado para `NotarioPersistente::abrir`: los `sellos` deben
    /// venir de `AlmacenSellos::cargar_todos()` (que ya valida
    /// encadenamiento e integridad de cada registro), y `autorizados`
    /// de `AlmacenSellos::cargar_autorizados()`. `vistos` y
    /// `ultimo_hash` se derivan aquí mismo a partir de `sellos`, para
    /// no poder pasarlos inconsistentes por error del llamador.
    ///
    /// # Nota sobre `vistos`
    /// Solo los `evento_id` de sellos **aceptados** entran a `vistos`,
    /// igual que hace `procesar_evento` en memoria (que inserta en
    /// `vistos` únicamente tras pasar autorización y no-replay). Un
    /// `evento_id` que solo aparece en sellos *rechazados* (firma
    /// inválida, no autorizado) no debe bloquear un reintento legítimo
    /// posterior con el mismo id.
    pub fn desde_clave_y_estado(
        nombre: impl Into<String>,
        clave: ClavePrivada,
        sellos: Vec<Sello>,
        autorizados: HashMap<String, HashSet<String>>,
    ) -> Self {
        let mut vistos = HashSet::with_capacity(sellos.len());
        let mut ultimo_hash = GENESIS_HASH.to_string();
        for sello in &sellos {
            if sello.aceptado {
                vistos.insert(sello.evento_id.clone());
            }
            // El encadenamiento avanza con TODOS los sellos, aceptados
            // o no (así funciona emitir_sello: cada llamada, incluso de
            // rechazo, encadena sobre el hash anterior y actualiza
            // ultimo_hash).
            ultimo_hash = sello.cuerpo_hash.clone();
        }

        Self {
            nombre: nombre.into(),
            clave_privada: clave,
            estado: Arc::new(RwLock::new(EstadoNotario {
                vistos,
                sellos,
                ultimo_hash,
                autorizados,
            })),
        }
    }

    /// Snapshot del mapa de firmantes autorizados (para persistirlo).
    pub fn autorizados_snapshot(&self) -> HashMap<String, HashSet<String>> {
        self.estado.read().autorizados.clone()
    }

    /// Obtiene el nombre del notario
    pub fn nombre(&self) -> &str {
        &self.nombre
    }

    /// Obtiene la clave pública del notario (hex)
    pub fn clave_publica_hex(&self) -> String {
        self.clave_privada.clave_publica_hex()
    }

    /// Obtiene la clave pública del notario
    pub fn clave_publica(&self) -> ClavePublica {
        ClavePublica::from(&self.clave_privada)
    }

    /// Registra un firmante como autorizado para un proyecto
    ///
    /// # Seguridad
    /// Esto debe hacerse UNA VEZ, fuera de banda, con verificación de identidad.
    /// La criptografía no prueba identidad real por sí sola.
    pub fn registrar_firmante_autorizado(
        &self,
        proyecto_id: impl Into<String>,
        clave_publica_hex: impl Into<String>,
    ) {
        let mut estado = self.estado.write();
        estado
            .autorizados
            .entry(proyecto_id.into())
            .or_insert_with(HashSet::new)
            .insert(clave_publica_hex.into());
    }

    /// Verifica si un firmante está autorizado para un proyecto
    fn es_autorizado(&self, proyecto_id: &str, clave_publica_hex: &str) -> bool {
        let estado = self.estado.read();
        estado
            .autorizados
            .get(proyecto_id)
            .map(|set| set.contains(clave_publica_hex))
            .unwrap_or(false)
    }

    /// Sella un archivo (plano CAD, firmware, dataset) ya empaquetado
    /// como `Evento` firmado.
    ///
    /// # Uso típico
    /// El firmante construye el evento y su firma con
    /// `Firmante::crear_evento_archivo(contenido, proyecto_id, evento_id)`,
    /// que produce `(Evento, FirmaBytes)`. Ese par se pasa aquí tal cual:
    /// el notario NUNCA reconstruye el evento por su cuenta, porque
    /// `Evento` incluye un `timestamp` fijado en el momento de la firma
    /// — reconstruirlo produciría un timestamp distinto y la
    /// verificación fallaría siempre, incluso para el firmante legítimo.
    ///
    /// # Seguridad
    /// La firma se verifica contra el `Evento` canónico exacto antes de
    /// aceptar el sellado. Sin una firma válida de una clave autorizada,
    /// el evento se rechaza con razón `firma_invalida` — igual que
    /// `notarizar_transaccion`. Esto cierra la vía por la que alguien
    /// podría "sellar en nombre de" una clave pública ajena sin poseer
    /// la clave privada correspondiente.
    pub fn sellar_archivo(
        &self,
        evento: &Evento,
        firma: &FirmaBytes,
        firmante_pub: &ClavePublica,
    ) -> Result<Sello> {
        self.sellar_evento(evento, firma, firmante_pub)
    }

    /// Sella un `Evento` ya construido y firmado (alternativa genérica
    /// a `sellar_archivo`, sin implicar que el contenido viene de un
    /// archivo en disco).
    ///
    /// Ver la nota de seguridad y de diseño en [`Self::sellar_archivo`].
    pub fn sellar_evento(
        &self,
        evento: &Evento,
        firma: &FirmaBytes,
        firmante_pub: &ClavePublica,
    ) -> Result<Sello> {
        let firmante_hex = firmante_pub.to_hex();

        // Verificar la firma del firmante sobre el EVENTO EXACTO recibido
        // (mismo timestamp con el que fue firmado) ANTES de considerar
        // autorización o replay. Sin esto, cualquiera que conozca una
        // clave pública autorizada podría sellar en su nombre sin poseer
        // la clave privada correspondiente.
        let evento_canonico = evento.a_canonico()?;
        let firma_valida = firmante_pub.verificar(&evento_canonico, &firma.to_signature());

        if !firma_valida {
            return self.emitir_sello(
                &evento.evento_id,
                false,
                "firma_invalida",
                &evento.hash_contenido,
                &firmante_hex,
            );
        }

        self.procesar_evento(
            &evento.evento_id,
            evento,
            Some(firma),
            &firmante_hex,
            &evento.proyecto_id,
            &evento.hash_contenido,
        )
    }

    /// Notariza una transacción firmada
    ///
    /// # Diferencia con `sellar_archivo` / `sellar_evento`
    /// El `hash_contenido` que termina en el sello es el hash del JSON
    /// canónico de `transaccion` tal cual se recibe aquí — NO el hash
    /// de ningún archivo o payload que `transaccion` pudiera describir.
    /// Si `transaccion` es en realidad un `Evento` ya construido (por
    /// ejemplo `serde_json::to_value(&evento)`), el sello resultante
    /// atestigua el JSON del evento, no el `hash_contenido` que ese
    /// evento lleva dentro. Para atestiguar el contenido real de un
    /// archivo, usar `sellar_archivo`/`sellar_evento` con el
    /// `(Evento, FirmaBytes)` que produce
    /// `Firmante::crear_evento_archivo`, no pasar ese `Evento`
    /// serializado a esta función.
    ///
    /// # Argumentos
    /// * `transaccion` - Datos de la transacción (se canonicalizan)
    /// * `firma` - Firma del firmante sobre la transacción canónica
    /// * `firmante_pub` - Clave pública del firmante
    /// * `proyecto_id` - Proyecto al que pertenece
    pub fn notarizar_transaccion(
        &self,
        transaccion: &serde_json::Value,
        firma: &FirmaBytes,
        firmante_pub: &ClavePublica,
        proyecto_id: impl Into<String>,
    ) -> Result<Sello> {
        debug_assert!(
            !parece_evento_serializado(transaccion),
            "notarizar_transaccion() recibió lo que parece un Evento serializado; \
             el hash_contenido resultante será el del JSON del evento, no el del \
             archivo original. Usa sellar_archivo()/sellar_evento() para eso."
        );

        // Canonicalizar transacción
        let canonico = json_canonico(transaccion);
        let hash_contenido = to_hex(&sha3_256(canonico.as_bytes()));

        // Generar evento_id del hash si no tiene id
        let evento_id = transaccion
            .get("id")
            .and_then(|v| v.as_str())
            .map(|s| s.to_string())
            .unwrap_or_else(|| hash_contenido[..16].to_string());

        let proyecto = proyecto_id.into();
        let firmante_hex = firmante_pub.to_hex();

        // Verificar firma del firmante
        let firma_valida = firmante_pub.verificar(canonico.as_bytes(), &firma.to_signature());

        if !firma_valida {
            return self.emitir_sello(
                &evento_id,
                false,
                "firma_invalida",
                &hash_contenido,
                &firmante_hex,
            );
        }

        self.procesar_evento(
            &evento_id,
            &Evento::nuevo(
                evento_id.clone(),
                hash_contenido.clone(),
                TipoEvento::Transaccion,
                proyecto.clone(),
            ),
            Some(firma),
            &firmante_hex,
            &proyecto,
            &hash_contenido,
        )
    }

    /// Procesa un evento y emite sello correspondiente.
    ///
    /// # Precondición de seguridad
    /// Los llamadores (`sellar_evento`, `notarizar_transaccion`) YA deben
    /// haber verificado `firma` contra el contenido canónico del evento
    /// antes de invocar esta función; aquí solo se decide replay y
    /// autorización de la clave. `_firma` se conserva en la firma de la
    /// función como documentación del contrato (qué se firmó) y para
    /// una futura extensión de auditoría, no porque se re-verifique.
    fn procesar_evento(
        &self,
        evento_id: &str,
        _evento: &Evento,
        _firma: Option<&FirmaBytes>,
        clave_publica_hex: &str,
        proyecto_id: &str,
        hash_contenido: &str,
    ) -> Result<Sello> {
        // Verificar replay (liberar el guard de lectura antes de emitir_sello,
        // que necesita el candado de escritura; de lo contrario se produce deadlock).
        let es_replay = {
            let estado = self.estado.read();
            estado.vistos.contains(evento_id)
        };
        if es_replay {
            return self.emitir_sello(
                evento_id,
                false,
                "replay_detectado",
                hash_contenido,
                clave_publica_hex,
            );
        }

        // Verificar autorización
        if !self.es_autorizado(proyecto_id, clave_publica_hex) {
            return self.emitir_sello(
                evento_id,
                false,
                "firmante_no_autorizado",
                hash_contenido,
                clave_publica_hex,
            );
        }

        // Marcar como visto y emitir sello aceptado
        {
            let mut estado = self.estado.write();
            estado.vistos.insert(evento_id.to_string());
        }

        self.emitir_sello(evento_id, true, "atestado", hash_contenido, clave_publica_hex)
    }

    /// Emite un sello (interno)
    fn emitir_sello(
        &self,
        evento_id: &str,
        aceptado: bool,
        razon: &str,
        hash_contenido: &str,
        firmante_pub: &str,
    ) -> Result<Sello> {
        let mut estado = self.estado.write();

        let cuerpo = CuerpoSello::nuevo(
            evento_id,
            aceptado,
            razon,
            hash_contenido,
            firmante_pub,
            &estado.ultimo_hash,
        );

        let cuerpo_hash = cuerpo.hash_hex()?;

        // Firmar el hash del cuerpo (no el cuerpo completo, para eficiencia)
        let firma = self.clave_privada.firmar(cuerpo_hash.as_bytes());
        let firma_bytes = FirmaBytes::from_signature(&firma);

        let sello = Sello::desde_cuerpo(&cuerpo, firma_bytes)?;

        // Actualizar estado
        estado.sellos.push(sello.clone());
        estado.ultimo_hash = cuerpo_hash;

        Ok(sello)
    }

    /// Obtiene todos los sellos emitidos
    pub fn sellos(&self) -> Vec<Sello> {
        self.estado.read().sellos.clone()
    }

    /// Obtiene el último hash de la cadena
    pub fn ultimo_hash(&self) -> String {
        self.estado.read().ultimo_hash.clone()
    }

    /// Exporta la cadena completa como JSON
    pub fn exportar_cadena(&self) -> Result<String> {
        let estado = self.estado.read();

        let export = serde_json::json!({
            "notario": self.nombre,
            "notario_clave_publica": self.clave_publica_hex(),
            "ultimo_hash": estado.ultimo_hash,
            "total_sellos": estado.sellos.len(),
            "sellos": estado.sellos,
        });

        Ok(serde_json::to_string_pretty(&export)?)
    }

    /// Verifica toda la cadena de sellos (auditoría interna)
    pub fn verificar_cadena(&self) -> Result<Vec<crate::sello::ReporteVerificacion>> {
        let estado = self.estado.read();
        let notario_pub = self.clave_publica_hex();

        let mut reportes = Vec::new();
        let mut anterior_esperado: Option<String> = None;

        for sello in &estado.sellos {
            let reporte = crate::sello::verificar_sello(
                sello,
                &notario_pub,
                anterior_esperado.as_deref(),
            )?;
            anterior_esperado = Some(sello.cuerpo_hash.clone());
            reportes.push(reporte);
        }

        Ok(reportes)
    }
}

impl Drop for Notario {
    fn drop(&mut self) {
        // La clave privada se borra automáticamente via ClavePrivada::drop
        // Aquí podríamos agregar logging de auditoría
        tracing::info!("Notario '{}' destruido, clave privada borrada", self.nombre);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::firmante::Firmante;

    #[test]
    fn test_notario_nuevo() {
        let notario = Notario::nuevo("Test Notary");
        assert_eq!(notario.nombre(), "Test Notary");
        assert!(!notario.clave_publica_hex().is_empty());
        assert_eq!(notario.ultimo_hash(), GENESIS_HASH);
    }

    #[test]
    fn test_registrar_firmante() {
        let notario = Notario::nuevo("Test");
        let firmante = Firmante::generar("ing");

        notario.registrar_firmante_autorizado("p1", firmante.clave_publica_hex());

        let (evento, firma) = firmante
            .crear_evento_archivo(b"test content", "p1", Some("evt-1".to_string()))
            .unwrap();

        // Verificar que está autorizado (indirectamente vía sellar)
        let sello = notario
            .sellar_archivo(&evento, &firma, &firmante.clave_publica())
            .unwrap();

        assert!(sello.aceptado);
        assert_eq!(sello.razon, "atestado");
    }

    #[test]
    fn test_firmante_no_autorizado_rechazado() {
        let notario = Notario::nuevo("Test");
        let firmante = Firmante::generar("ing");
        let atacante = Firmante::generar("atacante");

        // Registrar solo al firmante legítimo
        notario.registrar_firmante_autorizado("p1", firmante.clave_publica_hex());

        // El atacante firma con SU PROPIA clave (firma criptográficamente
        // válida) pero esa clave nunca fue registrada como autorizada.
        let (evento, firma_atacante) = atacante
            .crear_evento_archivo(b"content", "p1", Some("evt-1".to_string()))
            .unwrap();

        let sello = notario
            .sellar_archivo(&evento, &firma_atacante, &atacante.clave_publica())
            .unwrap();

        assert!(!sello.aceptado);
        assert_eq!(sello.razon, "firmante_no_autorizado");
    }

    #[test]
    fn test_firma_invalida_rechazada() {
        // Caso distinto del anterior: aquí la clave SÍ está autorizada,
        // pero la firma no corresponde al evento presentado (por ejemplo,
        // el evento fue alterado después de firmarlo).
        let notario = Notario::nuevo("Test");
        let firmante = Firmante::generar("ing");

        notario.registrar_firmante_autorizado("p1", firmante.clave_publica_hex());

        let (mut evento, firma) = firmante
            .crear_evento_archivo(b"content", "p1", Some("evt-1".to_string()))
            .unwrap();

        // Alterar el evento DESPUÉS de firmarlo: la firma ya no es válida
        // para este evento.
        evento.hash_contenido = "0".repeat(64);

        let sello = notario
            .sellar_archivo(&evento, &firma, &firmante.clave_publica())
            .unwrap();

        assert!(!sello.aceptado);
        assert_eq!(sello.razon, "firma_invalida");
    }

    #[test]
    fn test_replay_detectado() {
        let notario = Notario::nuevo("Test");
        let firmante = Firmante::generar("ing");

        notario.registrar_firmante_autorizado("p1", firmante.clave_publica_hex());

        let (evento, firma) = firmante
            .crear_evento_archivo(b"content", "p1", Some("evt-1".to_string()))
            .unwrap();

        // Primer sellado
        let sello1 = notario
            .sellar_archivo(&evento, &firma, &firmante.clave_publica())
            .unwrap();
        assert!(sello1.aceptado);

        // Intento de replay (mismo evento, misma firma, mismo evento_id)
        let sello2 = notario
            .sellar_archivo(&evento, &firma, &firmante.clave_publica())
            .unwrap();
        assert!(!sello2.aceptado);
        assert_eq!(sello2.razon, "replay_detectado");
    }

    #[test]
    fn test_ataque_no_bloquea_legitimas() {
        let notario = Notario::nuevo("Test");
        let firmante = Firmante::generar("ing");

        notario.registrar_firmante_autorizado("p1", firmante.clave_publica_hex());

        // 50 ataques fallidos, cada uno con su propia clave (no autorizada)
        for i in 0..50 {
            let atacante = Firmante::generar(format!("atacante-{}", i));
            let contenido = format!("fraude-{}", i);
            let evento_id = format!("ataque-{}", i);
            let (evento, firma) = atacante
                .crear_evento_archivo(contenido.as_bytes(), "p1", Some(evento_id))
                .unwrap();

            let sello = notario
                .sellar_archivo(&evento, &firma, &atacante.clave_publica())
                .unwrap();
            assert!(!sello.aceptado);
        }

        // Evento legítimo después de los ataques
        let (evento_legit, firma_legit) = firmante
            .crear_evento_archivo(b"legitimo", "p1", Some("evt-final".to_string()))
            .unwrap();
        let sello_legit = notario
            .sellar_archivo(&evento_legit, &firma_legit, &firmante.clave_publica())
            .unwrap();
        assert!(sello_legit.aceptado);
    }

    #[test]
    fn test_encadenamiento() {
        let notario = Notario::nuevo("Test");
        let firmante = Firmante::generar("ing");

        notario.registrar_firmante_autorizado("p1", firmante.clave_publica_hex());

        let (evento_a, firma_a) = firmante
            .crear_evento_archivo(b"A", "p1", Some("e1".to_string()))
            .unwrap();
        let s1 = notario
            .sellar_archivo(&evento_a, &firma_a, &firmante.clave_publica())
            .unwrap();

        let (evento_b, firma_b) = firmante
            .crear_evento_archivo(b"B", "p1", Some("e2".to_string()))
            .unwrap();
        let s2 = notario
            .sellar_archivo(&evento_b, &firma_b, &firmante.clave_publica())
            .unwrap();

        // Verificar encadenamiento
        assert!(s2.verificar_encadenamiento(&s1.cuerpo_hash));
        assert!(!s2.verificar_encadenamiento(GENESIS_HASH));
    }
}

// ---------------------------------------------------------------------------
// Notario con protección CSG parcial (conatus + ruptura + damage_log cifrado)
// ---------------------------------------------------------------------------

use crate::error::SelloError;
use crate::proteccion::{
    fingerprint_intento, ClaveMaestraDanio, GestorProteccion, PoliticaConatus, EstadoProteccion,
};

/// Notario envuelto con política de conatus y ruptura estructural.
///
/// Los intentos fallidos (firma inválida, firmante no autorizado, replay)
/// incrementan el conatus, registran una huella cifrada (AES-GCM + Argon2)
/// y, tras el umbral, invalidan permanentemente la capacidad de emitir
/// sellos aceptados hasta una recuperación fuera de banda.
pub struct NotarioProtegido {
    inner: Notario,
    proteccion: GestorProteccion,
}

impl NotarioProtegido {
    /// Crea un notario protegido con política por defecto y clave maestra aleatoria
    pub fn nuevo(nombre: impl Into<String>) -> Self {
        Self {
            inner: Notario::nuevo(nombre),
            proteccion: GestorProteccion::con_defaults(),
        }
    }

    /// Crea con política y clave maestra explícitas
    pub fn con_politica(
        nombre: impl Into<String>,
        politica: PoliticaConatus,
        master: Option<ClaveMaestraDanio>,
    ) -> Self {
        Self {
            inner: Notario::nuevo(nombre),
            proteccion: GestorProteccion::nuevo(politica, master),
        }
    }

    pub fn nombre(&self) -> &str {
        self.inner.nombre()
    }

    pub fn clave_publica_hex(&self) -> String {
        self.inner.clave_publica_hex()
    }

    pub fn clave_publica(&self) -> ClavePublica {
        self.inner.clave_publica()
    }

    pub fn registrar_firmante_autorizado(
        &self,
        proyecto_id: impl Into<String>,
        clave_publica_hex: impl Into<String>,
    ) {
        self.inner
            .registrar_firmante_autorizado(proyecto_id, clave_publica_hex)
    }

    pub fn estructura_rota(&self) -> bool {
        self.proteccion.estructura_rota()
    }

    pub fn conatus(&self) -> f64 {
        self.proteccion.conatus()
    }

    pub fn estado_proteccion(&self) -> EstadoProteccion {
        self.proteccion.estado_snapshot()
    }

    /// Recuperación fuera de banda (requiere acceso privilegiado)
    pub fn reset_recuperacion(&self) {
        self.proteccion.reset_recuperacion()
    }

    /// Sella un evento aplicando la política de protección.
    ///
    /// Si la estructura está rota, rechaza de inmediato.
    /// Los fallos de verificación/autorización registran daño y pueden
    /// activar la ruptura.
    pub fn sellar_evento(
        &self,
        evento: &Evento,
        firma: &FirmaBytes,
        firmante_pub: &ClavePublica,
    ) -> Result<Sello> {
        if self.proteccion.estructura_rota() {
            return Err(SelloError::EstructuraRota);
        }

        // Retardo proporcional al conatus (endurecimiento)
        let retardo = self
            .proteccion
            .estado_snapshot()
            .retardo_ms(self.proteccion.politica());
        if retardo > 0 {
            std::thread::sleep(std::time::Duration::from_millis(retardo.min(5_000)));
        }

        let resultado = self.inner.sellar_evento(evento, firma, firmante_pub);

        match &resultado {
            Ok(sello) if !sello.aceptado => {
                // Fallo lógico (firma inválida, no autorizado, replay, ...)
                let fp_data = format!(
                    "{}:{}:{}",
                    evento.evento_id,
                    firmante_pub.to_hex(),
                    sello.razon
                );
                let fp = fingerprint_intento(fp_data.as_bytes());
                let _ = self.proteccion.registrar_fallo(&fp);
            }
            Err(_) => {
                let fp_data = format!("{}:{}", evento.evento_id, firmante_pub.to_hex());
                let fp = fingerprint_intento(fp_data.as_bytes());
                let _ = self.proteccion.registrar_fallo(&fp);
            }
            _ => {}
        }

        // Si tras el fallo la estructura se rompió, devolver error explícito
        // en la siguiente interacción; en esta devolvemos el sello de rechazo.
        resultado
    }

    pub fn sellar_archivo(
        &self,
        evento: &Evento,
        firma: &FirmaBytes,
        firmante_pub: &ClavePublica,
    ) -> Result<Sello> {
        self.sellar_evento(evento, firma, firmante_pub)
    }

    pub fn notarizar_transaccion(
        &self,
        evento_json: &serde_json::Value,
        firma: &FirmaBytes,
        firmante_pub: &ClavePublica,
        proyecto_id: &str,
    ) -> Result<Sello> {
        if self.proteccion.estructura_rota() {
            return Err(SelloError::EstructuraRota);
        }

        let retardo = self
            .proteccion
            .estado_snapshot()
            .retardo_ms(self.proteccion.politica());
        if retardo > 0 {
            std::thread::sleep(std::time::Duration::from_millis(retardo.min(5_000)));
        }

        let resultado =
            self.inner
                .notarizar_transaccion(evento_json, firma, firmante_pub, proyecto_id);

        match &resultado {
            Ok(sello) if !sello.aceptado => {
                let fp_data = format!(
                    "{}:{}:{}",
                    sello.evento_id,
                    firmante_pub.to_hex(),
                    sello.razon
                );
                let fp = fingerprint_intento(fp_data.as_bytes());
                let _ = self.proteccion.registrar_fallo(&fp);
            }
            Err(_) => {
                let fp = fingerprint_intento(firmante_pub.to_hex().as_bytes());
                let _ = self.proteccion.registrar_fallo(&fp);
            }
            _ => {}
        }

        resultado
    }

    pub fn sellos(&self) -> Vec<Sello> {
        self.inner.sellos()
    }

    pub fn ultimo_hash(&self) -> String {
        self.inner.ultimo_hash()
    }
}

#[cfg(test)]
mod tests_protegido {
    use super::*;
    use crate::firmante::Firmante;

    #[test]
    fn test_notario_protegido_ruptura() {
        let politica = PoliticaConatus {
            umbral_ruptura: 3,
            factor_endurecimiento: 1.6,
            retardo_base_ms: 0, // sin sleep en tests
        };
        let notario = NotarioProtegido::con_politica("Test", politica, Some(ClaveMaestraDanio::generar()));
        let firmante = Firmante::generar("ing");
        // NO registramos al firmante -> cada intento será rechazado

        let (evento, firma) = firmante
            .crear_evento_archivo(b"data", "p1", Some("e1".into()))
            .unwrap();

        for i in 0..3 {
            let sello = notario
                .sellar_evento(&evento, &firma, &firmante.clave_publica())
                .unwrap();
            assert!(!sello.aceptado, "intento {i} debería ser rechazado");
        }

        assert!(notario.estructura_rota());
        assert!(notario.conatus() > 1.0);

        // Tras ruptura, cualquier intento devuelve EstructuraRota
        let err = notario
            .sellar_evento(&evento, &firma, &firmante.clave_publica())
            .unwrap_err();
        assert!(matches!(err, SelloError::EstructuraRota));
    }

    #[test]
    fn test_notario_protegido_exito_no_sube_conatus() {
        let politica = PoliticaConatus {
            umbral_ruptura: 5,
            factor_endurecimiento: 1.6,
            retardo_base_ms: 0,
        };
        let notario = NotarioProtegido::con_politica("Test", politica, None);
        let firmante = Firmante::generar("ing");
        notario.registrar_firmante_autorizado("p1", firmante.clave_publica_hex());

        let (evento, firma) = firmante
            .crear_evento_archivo(b"data", "p1", Some("e-ok".into()))
            .unwrap();

        let sello = notario
            .sellar_evento(&evento, &firma, &firmante.clave_publica())
            .unwrap();
        assert!(sello.aceptado);
        assert!((notario.conatus() - 1.0).abs() < 1e-9);
        assert!(!notario.estructura_rota());
    }
}
