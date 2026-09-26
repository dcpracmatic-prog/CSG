//! Definición de errores del Sello de Integridad Técnica
//!
//! Todos los errores son explícitos y no filtran información sensible
//! sobre el estado interno del sistema.

use thiserror::Error;

/// Errores del sistema de sellado de integridad
#[derive(Error, Debug)]
pub enum SelloError {
    /// Error en operaciones criptográficas
    #[error("Error criptográfico: {0}")]
    Crypto(String),

    /// Firma inválida o no verificable
    #[error("Firma inválida: {0}")]
    FirmaInvalida(String),

    /// Clave pública malformada
    #[error("Clave pública inválida: {0}")]
    ClavePublicaInvalida(String),

    /// Error de serialización/deserialización
    #[error("Error de serialización: {0}")]
    Serializacion(String),

    /// Error de I/O en archivos
    #[error("Error de I/O: {0}")]
    Io(#[from] std::io::Error),

    /// Evento ya procesado (replay detectado)
    #[error("Replay detectado: evento {0} ya fue procesado")]
    ReplayDetectado(String),

    /// Firmante no autorizado para el proyecto
    #[error("Firmante no autorizado para el proyecto: {0}")]
    FirmanteNoAutorizado(String),

    /// Error en canonicalización JSON
    #[error("Error en canonicalización JSON: {0}")]
    Canonicalizacion(String),

    /// Error de validación de entrada
    #[error("Validación fallida: {0}")]
    Validacion(String),

    /// Error de encoding/decoding hexadecimal
    #[error("Error de encoding hexadecimal: {0}")]
    HexEncoding(String),

    /// Error de tiempo/timestamp
    #[error("Error de timestamp: {0}")]
    Timestamp(String),

    /// Estructura de protección rota tras umbral de intentos fallidos
    #[error("Estructura rota: el notario ha sido invalidado por exceso de intentos fallidos")]
    EstructuraRota,

    /// Operación rechazada por política de conatus (aún no rota)
    #[error("Rechazado por política de protección (conatus={0})")]
    ProteccionActiva(f64),
}

/// Resultado especializado para operaciones del sello
pub type Result<T> = std::result::Result<T, SelloError>;

/// Conversión de errores de ed25519-dalek
impl From<ed25519_dalek::SignatureError> for SelloError {
    fn from(e: ed25519_dalek::SignatureError) -> Self {
        SelloError::FirmaInvalida(e.to_string())
    }
}

/// Conversión de errores de serde_json
impl From<serde_json::Error> for SelloError {
    fn from(e: serde_json::Error) -> Self {
        SelloError::Serializacion(e.to_string())
    }
}

/// Conversión de errores de hex
impl From<hex::FromHexError> for SelloError {
    fn from(e: hex::FromHexError) -> Self {
        SelloError::HexEncoding(e.to_string())
    }
}
