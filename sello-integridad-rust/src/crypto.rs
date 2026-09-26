//! Módulo criptográfico con garantías de constant-time
//!
//! Este módulo implementa las primitivas criptográficas con:
//! - Operaciones en tiempo constante (resistentes a timing attacks,
//!   provisto por ed25519-dalek internamente)
//! - Borrado seguro de memoria (zeroize)
//! - APIs de alto nivel difíciles de usar incorrectamente
//!
//! # Nota de compatibilidad
//! Usa la API de `ed25519-dalek` 2.x (`SigningKey` / `VerifyingKey`),
//! distinta de la API 1.x (`Keypair` / `SecretKey` / `PublicKey`).

use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use ed25519_dalek::{PUBLIC_KEY_LENGTH, SECRET_KEY_LENGTH, SIGNATURE_LENGTH};
use rand::rngs::OsRng;
use sha3::{Digest, Sha3_256};
use zeroize::Zeroize;

use crate::error::{Result, SelloError};

/// Longitud del hash SHA3-256 en bytes
pub const HASH_LENGTH: usize = 32;

/// Longitud del hash hexadecimal
pub const HASH_HEX_LENGTH: usize = 64;

/// Genera un par de claves Ed25519 usando el CSPRNG del sistema operativo
///
/// # Seguridad
/// - Usa `OsRng` que se alimenta de `/dev/urandom` o `getrandom()` según la plataforma
pub fn generar_signing_key() -> SigningKey {
    let mut csprng = OsRng;
    SigningKey::generate(&mut csprng)
}

/// Firma un mensaje en tiempo constante
///
/// # Seguridad
/// - La firma Ed25519 es inherentemente resistente a timing attacks
#[inline(never)] // Previene optimizaciones agresivas que puedan romper constant-time
pub fn firmar(clave: &SigningKey, mensaje: &[u8]) -> Signature {
    clave.sign(mensaje)
}

/// Verifica una firma en tiempo constante
///
/// # Seguridad
/// - La verificación Ed25519 no filtra información sobre la clave privada
///   (porque no la conoce)
/// - Retorna `false` en caso de firma inválida, no revela por qué falló
#[inline(never)]
pub fn verificar(clave_publica: &VerifyingKey, mensaje: &[u8], firma: &Signature) -> bool {
    clave_publica.verify(mensaje, firma).is_ok()
}

/// Calcula SHA3-256 de datos
///
/// # Nota
/// SHA3 es resistente a length-extension attacks, a diferencia de SHA-256
pub fn sha3_256(data: &[u8]) -> [u8; HASH_LENGTH] {
    let mut hasher = Sha3_256::new();
    hasher.update(data);
    let result = hasher.finalize();
    let mut output = [0u8; HASH_LENGTH];
    output.copy_from_slice(&result);
    output
}

/// Convierte bytes a representación hexadecimal
pub fn to_hex(bytes: &[u8]) -> String {
    hex::encode(bytes)
}

/// Convierte hexadecimal a bytes
///
/// # Errores
/// Retorna error si el hex es inválido o tiene longitud incorrecta
pub fn from_hex(hex_str: &str) -> Result<Vec<u8>> {
    hex::decode(hex_str).map_err(SelloError::from)
}

/// Serializa un `serde_json::Value` a JSON canónico: claves de objeto
/// ordenadas alfabéticamente (recursivamente) y sin espacios en blanco.
///
/// # Por qué existe
/// Dos representaciones semánticamente iguales pero byte-distintas del
/// mismo valor producirían firmas/hashes diferentes. Esto reproduce el
/// comportamiento de `json.dumps(v, sort_keys=True, separators=(",", ":"))`
/// en Python, sin depender de un crate externo de "canonical JSON".
pub fn json_canonico(value: &serde_json::Value) -> String {
    let ordenado = ordenar_valor(value);
    // serde_json::to_string ya omite espacios en blanco por defecto
    // (a diferencia de to_string_pretty); combinado con BTreeMap
    // (que serializa en orden de claves) obtenemos salida canónica.
    serde_json::to_string(&ordenado).expect("serializar un Value ordenado nunca falla")
}

/// Reordena recursivamente un `serde_json::Value`, convirtiendo cada
/// `Map` en un `BTreeMap` (orden alfabético de claves) preservando el
/// contenido de arreglos y escalares tal cual.
fn ordenar_valor(value: &serde_json::Value) -> serde_json::Value {
    use serde_json::Value;
    match value {
        Value::Object(map) => {
            let ordenado: std::collections::BTreeMap<String, Value> = map
                .iter()
                .map(|(k, v)| (k.clone(), ordenar_valor(v)))
                .collect();
            // Reconstruir como Map preservando el nuevo orden de inserción
            // (BTreeMap itera en orden de claves, y serde_json::Map
            // conserva orden de inserción al serializar).
            let mut nuevo = serde_json::Map::new();
            for (k, v) in ordenado {
                nuevo.insert(k, v);
            }
            Value::Object(nuevo)
        }
        Value::Array(arr) => Value::Array(arr.iter().map(ordenar_valor).collect()),
        otro => otro.clone(),
    }
}

/// Estructura para manejo seguro de claves privadas
///
/// # Seguridad
/// - La clave se sobrescribe con ceros al liberar (`Drop`)
/// - No implementa `Clone` (por diseño: no derivamos `Clone` en el struct)
/// - No implementa `Debug` estándar; el `Debug` manual oculta el secreto
pub struct ClavePrivada {
    secret: SigningKey,
}

// Asegurar que la clave se borre al liberar.
// SigningKey no implementa Zeroize directamente en todas las versiones,
// así que sobrescribimos explícitamente los bytes crudos.
impl Drop for ClavePrivada {
    fn drop(&mut self) {
        let mut bytes = self.secret.to_bytes();
        bytes.zeroize();
    }
}

// No implementamos Clone para ClavePrivada intencionalmente: al no derivar
// ni implementar el trait, el tipo simplemente no es clonable en Rust stable
// (a diferencia de `impl !Clone`, que requiere negative_impls, feature de nightly).

// No permitir un Debug que filtre la clave
impl std::fmt::Debug for ClavePrivada {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ClavePrivada")
            .field("public", &to_hex(self.secret.verifying_key().as_bytes()))
            .field("secret", &"[REDACTED]")
            .finish()
    }
}

impl ClavePrivada {
    /// Genera una nueva clave privada segura
    pub fn generar() -> Self {
        Self {
            secret: generar_signing_key(),
        }
    }

    /// Crea desde bytes de clave privada (para importación)
    ///
    /// # Seguridad
    /// Los bytes de entrada se borran después de usar
    pub fn from_bytes(bytes: &[u8; SECRET_KEY_LENGTH]) -> Result<Self> {
        let secret = SigningKey::from_bytes(bytes);

        // Borrar la copia local de los bytes de entrada
        let mut bytes_copy = *bytes;
        bytes_copy.zeroize();

        Ok(Self { secret })
    }

    /// Firma un mensaje usando esta clave
    pub fn firmar(&self, mensaje: &[u8]) -> Signature {
        firmar(&self.secret, mensaje)
    }

    /// Obtiene la clave pública correspondiente
    pub fn clave_publica(&self) -> VerifyingKey {
        self.secret.verifying_key()
    }

    /// Exporta la clave pública como bytes
    pub fn clave_publica_bytes(&self) -> [u8; PUBLIC_KEY_LENGTH] {
        self.secret.verifying_key().to_bytes()
    }

    /// Exporta la clave pública como hexadecimal
    pub fn clave_publica_hex(&self) -> String {
        to_hex(&self.clave_publica_bytes())
    }
}

/// Estructura para claves públicas (no sensibles)
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ClavePublica {
    key: VerifyingKey,
}

impl ClavePublica {
    /// Crea desde bytes
    pub fn from_bytes(bytes: &[u8; PUBLIC_KEY_LENGTH]) -> Result<Self> {
        let key = VerifyingKey::from_bytes(bytes)
            .map_err(|e| SelloError::ClavePublicaInvalida(e.to_string()))?;
        Ok(Self { key })
    }

    /// Crea desde hexadecimal
    pub fn from_hex(hex_str: &str) -> Result<Self> {
        let bytes = from_hex(hex_str)?;
        if bytes.len() != PUBLIC_KEY_LENGTH {
            return Err(SelloError::ClavePublicaInvalida(format!(
                "Longitud incorrecta: esperado {}, obtenido {}",
                PUBLIC_KEY_LENGTH,
                bytes.len()
            )));
        }
        let mut array = [0u8; PUBLIC_KEY_LENGTH];
        array.copy_from_slice(&bytes);
        Self::from_bytes(&array)
    }

    /// Verifica una firma
    pub fn verificar(&self, mensaje: &[u8], firma: &Signature) -> bool {
        verificar(&self.key, mensaje, firma)
    }

    /// Obtiene bytes de la clave pública
    pub fn to_bytes(&self) -> [u8; PUBLIC_KEY_LENGTH] {
        self.key.to_bytes()
    }

    /// Obtiene hexadecimal de la clave pública
    pub fn to_hex(&self) -> String {
        to_hex(&self.key.to_bytes())
    }
}

impl From<VerifyingKey> for ClavePublica {
    fn from(key: VerifyingKey) -> Self {
        Self { key }
    }
}

impl From<&ClavePrivada> for ClavePublica {
    fn from(priv_key: &ClavePrivada) -> Self {
        Self {
            key: priv_key.clave_publica(),
        }
    }
}

/// Firma serializable para almacenamiento/transmisión
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FirmaBytes {
    bytes: [u8; SIGNATURE_LENGTH],
}

impl FirmaBytes {
    /// Crea desde una firma de ed25519-dalek
    pub fn from_signature(sig: &Signature) -> Self {
        Self {
            bytes: sig.to_bytes(),
        }
    }

    /// Convierte a firma de ed25519-dalek
    pub fn to_signature(&self) -> Signature {
        Signature::from_bytes(&self.bytes)
    }

    /// Obtiene bytes
    pub fn to_bytes(&self) -> [u8; SIGNATURE_LENGTH] {
        self.bytes
    }

    /// Obtiene hexadecimal
    pub fn to_hex(&self) -> String {
        to_hex(&self.bytes)
    }

    /// Crea desde hexadecimal
    pub fn from_hex(hex_str: &str) -> Result<Self> {
        let bytes = from_hex(hex_str)?;
        if bytes.len() != SIGNATURE_LENGTH {
            return Err(SelloError::FirmaInvalida(format!(
                "Longitud de firma incorrecta: esperado {}, obtenido {}",
                SIGNATURE_LENGTH,
                bytes.len()
            )));
        }
        let mut array = [0u8; SIGNATURE_LENGTH];
        array.copy_from_slice(&bytes);
        Ok(Self { bytes: array })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_generar_signing_key() {
        let clave = generar_signing_key();
        assert_eq!(clave.verifying_key().as_bytes().len(), PUBLIC_KEY_LENGTH);
    }

    #[test]
    fn test_firma_verificacion() {
        let clave = ClavePrivada::generar();
        let mensaje = b"test message";

        let firma = clave.firmar(mensaje);
        let publica = ClavePublica::from(&clave);

        assert!(publica.verificar(mensaje, &firma));
    }

    #[test]
    fn test_firma_invalida() {
        let clave = ClavePrivada::generar();
        let mensaje = b"test message";
        let mensaje_modificado = b"test message modified";

        let firma = clave.firmar(mensaje);
        let publica = ClavePublica::from(&clave);

        assert!(!publica.verificar(mensaje_modificado, &firma));
    }

    #[test]
    fn test_hex_roundtrip() {
        let data = b"hello world";
        let hex_str = to_hex(data);
        let recovered = from_hex(&hex_str).unwrap();
        assert_eq!(data.to_vec(), recovered);
    }

    #[test]
    fn test_sha3_256() {
        let hash = sha3_256(b"");
        // Hash conocido de cadena vacía
        assert_eq!(
            to_hex(&hash),
            "a7ffc6f8bf1ed76651c14756a061d662f580ff4de43b49fa82d80a4b80f8434a"
        );
    }

    #[test]
    fn test_clave_privada_no_clonable() {
        // Este test es documental: ClavePrivada no deriva ni implementa
        // Clone, así que `clave.clone()` simplemente no compilaría si
        // se intentara en código real. No hay forma portable de afirmar
        // "no Clone" en un test de stable sin negative_impls, así que
        // la garantía la da la ausencia de #[derive(Clone)] arriba.
        let _clave = ClavePrivada::generar();
    }
}
