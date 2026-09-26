//! Protección por conatus y ruptura estructural (portabilidad parcial CSG)
//!
//! Cada intento fallido de sellado:
//! 1. Incrementa el conatus (endurecimiento exponencial).
//! 2. Registra una huella cifrada del intento (AES-GCM + Argon2).
//! 3. Tras un umbral configurable, marca la estructura como rota:
//!    el notario deja de emitir sellos aceptados.
//!
//! La clave maestra del damage_log NO reside en el token; se inyecta
//! en tiempo de ejecución (o desde HSM en el futuro).

use aes_gcm::{
    aead::{Aead, KeyInit},
    Aes256Gcm, Nonce,
};
use argon2::{Algorithm, Argon2, Params, Version};
use parking_lot::RwLock;
use rand::RngCore;
use serde::{Deserialize, Serialize};
use sha3::{Digest, Sha3_256};
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};
use zeroize::Zeroize;

use crate::error::{Result, SelloError};

/// Política de endurecimiento y ruptura
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PoliticaConatus {
    /// Número de fallos que activa la ruptura estructural
    pub umbral_ruptura: u32,
    /// Factor multiplicativo del conatus por cada fallo (p.ej. 1.6)
    pub factor_endurecimiento: f64,
    /// Retardo base en milisegundos (escalado por conatus)
    pub retardo_base_ms: u64,
}

impl Default for PoliticaConatus {
    fn default() -> Self {
        Self {
            umbral_ruptura: 5,
            factor_endurecimiento: 1.6,
            retardo_base_ms: 50,
        }
    }
}

/// Estado de protección asociado a un notario
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct EstadoProteccion {
    pub intentos_fallidos: u32,
    pub conatus: f64,
    pub estructura_rota: bool,
    /// Huellas cifradas: salt(16) || nonce(12) || ciphertext
    pub damage_log: Vec<Vec<u8>>,
}

impl Default for EstadoProteccion {
    fn default() -> Self {
        Self {
            intentos_fallidos: 0,
            conatus: 1.0,
            estructura_rota: false,
            damage_log: Vec::new(),
        }
    }
}

impl EstadoProteccion {
    pub fn nuevo() -> Self {
        Self::default()
    }

    /// Retardo sugerido en ms según el conatus actual
    pub fn retardo_ms(&self, politica: &PoliticaConatus) -> u64 {
        (politica.retardo_base_ms as f64 * self.conatus).round() as u64
    }
}

/// Material de clave maestra para cifrar el damage_log.
/// Debe residir fuera del token (memoria de proceso, HSM, etc.).
#[derive(Zeroize)]
#[zeroize(drop)]
pub struct ClaveMaestraDanio {
    bytes: [u8; 32],
}

impl ClaveMaestraDanio {
    /// Genera una clave maestra aleatoria (solo para demos / tests)
    pub fn generar() -> Self {
        let mut bytes = [0u8; 32];
        rand::rngs::OsRng.fill_bytes(&mut bytes);
        Self { bytes }
    }

    /// Importa desde bytes (el llamador debe zeroizar su copia)
    pub fn from_bytes(bytes: [u8; 32]) -> Self {
        Self { bytes }
    }

    /// Derivación Argon2id → clave AES-256
    fn derivar_clave_aes(&self, salt: &[u8]) -> Result<[u8; 32]> {
        // Parámetros moderados: balance seguridad/latencia en servidor
        let params = Params::new(19_456, 2, 1, Some(32))
            .map_err(|e| SelloError::Crypto(format!("Argon2 params: {e}")))?;
        let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);

        let mut out = [0u8; 32];
        argon2
            .hash_password_into(&self.bytes, salt, &mut out)
            .map_err(|e| SelloError::Crypto(format!("Argon2: {e}")))?;
        Ok(out)
    }
}

/// Cifra una huella de intento fallido con AES-256-GCM.
/// Formato almacenado: salt(16) || nonce(12) || ciphertext+tag
pub fn cifrar_huella(
    master: &ClaveMaestraDanio,
    attempt_no: u32,
    attempt_fingerprint: &[u8],
) -> Result<Vec<u8>> {
    let mut salt = [0u8; 16];
    let mut nonce_bytes = [0u8; 12];
    rand::rngs::OsRng.fill_bytes(&mut salt);
    rand::rngs::OsRng.fill_bytes(&mut nonce_bytes);

    let key_bytes = master.derivar_clave_aes(&salt)?;
    let cipher = Aes256Gcm::new_from_slice(&key_bytes)
        .map_err(|e| SelloError::Crypto(format!("AES key: {e}")))?;
    // Zeroizar clave derivada de la pila lo antes posible
    let mut key_bytes = key_bytes;
    key_bytes.zeroize();

    let plaintext = serde_json::to_vec(&serde_json::json!({
        "t": SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0),
        "attempt_no": attempt_no,
        "fp": hex::encode(attempt_fingerprint),
    }))?;

    let nonce = Nonce::from_slice(&nonce_bytes);
    let ciphertext = cipher
        .encrypt(nonce, plaintext.as_ref())
        .map_err(|e| SelloError::Crypto(format!("AES-GCM encrypt: {e}")))?;

    let mut out = Vec::with_capacity(16 + 12 + ciphertext.len());
    out.extend_from_slice(&salt);
    out.extend_from_slice(&nonce_bytes);
    out.extend_from_slice(&ciphertext);
    Ok(out)
}

/// Descifra una huella (solo para auditoría del dueño con la clave maestra)
pub fn descifrar_huella(master: &ClaveMaestraDanio, blob: &[u8]) -> Result<Vec<u8>> {
    if blob.len() < 16 + 12 + 16 {
        return Err(SelloError::Validacion(
            "Huella de daño demasiado corta".into(),
        ));
    }
    let salt = &blob[..16];
    let nonce_bytes = &blob[16..28];
    let ciphertext = &blob[28..];

    let key_bytes = master.derivar_clave_aes(salt)?;
    let cipher = Aes256Gcm::new_from_slice(&key_bytes)
        .map_err(|e| SelloError::Crypto(format!("AES key: {e}")))?;
    let mut key_bytes = key_bytes;
    key_bytes.zeroize();

    let nonce = Nonce::from_slice(nonce_bytes);
    cipher
        .decrypt(nonce, ciphertext)
        .map_err(|e| SelloError::Crypto(format!("AES-GCM decrypt: {e}")))
}

/// Hash de un intento (vector de firma, evento_id, etc.) para la huella
pub fn fingerprint_intento(datos: &[u8]) -> [u8; 32] {
    let mut hasher = Sha3_256::new();
    hasher.update(datos);
    let result = hasher.finalize();
    let mut out = [0u8; 32];
    out.copy_from_slice(&result);
    out
}

/// Gestor de protección thread-safe
pub struct GestorProteccion {
    politica: PoliticaConatus,
    estado: Arc<RwLock<EstadoProteccion>>,
    /// Clave maestra opcional; si es None, las huellas no se cifran (solo tests)
    master: Option<ClaveMaestraDanio>,
}

impl GestorProteccion {
    pub fn nuevo(politica: PoliticaConatus, master: Option<ClaveMaestraDanio>) -> Self {
        Self {
            politica,
            estado: Arc::new(RwLock::new(EstadoProteccion::nuevo())),
            master,
        }
    }

    pub fn con_defaults() -> Self {
        Self::nuevo(PoliticaConatus::default(), Some(ClaveMaestraDanio::generar()))
    }

    pub fn politica(&self) -> &PoliticaConatus {
        &self.politica
    }

    pub fn estado_snapshot(&self) -> EstadoProteccion {
        self.estado.read().clone()
    }

    pub fn estructura_rota(&self) -> bool {
        self.estado.read().estructura_rota
    }

    pub fn conatus(&self) -> f64 {
        self.estado.read().conatus
    }

    /// Registra un fallo: sube conatus, cifra huella, posiblemente rompe estructura.
    /// Devuelve true si la estructura acaba de romperse en esta llamada.
    pub fn registrar_fallo(&self, attempt_fingerprint: &[u8]) -> Result<bool> {
        let mut estado = self.estado.write();
        if estado.estructura_rota {
            return Ok(false);
        }

        estado.intentos_fallidos += 1;
        estado.conatus *= self.politica.factor_endurecimiento;

        if let Some(ref master) = self.master {
            let blob = cifrar_huella(master, estado.intentos_fallidos, attempt_fingerprint)?;
            estado.damage_log.push(blob);
        } else {
            // Sin clave maestra: almacenar solo el hash (no reversible a datos útiles)
            let fp = fingerprint_intento(attempt_fingerprint);
            estado.damage_log.push(fp.to_vec());
        }

        let rompio = estado.intentos_fallidos >= self.politica.umbral_ruptura;
        if rompio {
            estado.estructura_rota = true;
        }
        Ok(rompio)
    }

    /// Resetea el estado (solo para recuperación fuera de banda / tests)
    pub fn reset_recuperacion(&self) {
        let mut estado = self.estado.write();
        *estado = EstadoProteccion::nuevo();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_conatus_y_ruptura() {
        let politica = PoliticaConatus {
            umbral_ruptura: 3,
            factor_endurecimiento: 2.0,
            retardo_base_ms: 10,
        };
        let gestor = GestorProteccion::nuevo(politica, Some(ClaveMaestraDanio::generar()));

        assert!(!gestor.estructura_rota());
        assert!((gestor.conatus() - 1.0).abs() < 1e-9);

        let fp = b"intento-1";
        assert!(!gestor.registrar_fallo(fp).unwrap());
        assert!((gestor.conatus() - 2.0).abs() < 1e-9);

        assert!(!gestor.registrar_fallo(fp).unwrap());
        assert!((gestor.conatus() - 4.0).abs() < 1e-9);

        assert!(gestor.registrar_fallo(fp).unwrap()); // 3er fallo -> ruptura
        assert!(gestor.estructura_rota());
    }

    #[test]
    fn test_cifrar_descifrar_huella() {
        let master = ClaveMaestraDanio::generar();
        let fp = fingerprint_intento(b"datos-del-intento");
        let blob = cifrar_huella(&master, 1, &fp).unwrap();
        let plain = descifrar_huella(&master, &blob).unwrap();
        let v: serde_json::Value = serde_json::from_slice(&plain).unwrap();
        assert_eq!(v["attempt_no"], 1);
        assert!(v["fp"].as_str().unwrap().len() > 0);
    }

    #[test]
    fn test_descifrado_falla_con_clave_incorrecta() {
        let master = ClaveMaestraDanio::generar();
        let otra = ClaveMaestraDanio::generar();
        let blob = cifrar_huella(&master, 1, b"x").unwrap();
        assert!(descifrar_huella(&otra, &blob).is_err());
    }
}
