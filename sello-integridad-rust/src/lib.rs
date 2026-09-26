//! # Sello de Integridad Técnica - Versión Rust
//!
//! Primitiva de attestación criptográfica para activos de ingeniería
//! (planos CAD, firmware, datasets) y transacciones internas.
//!
//! ## Características de seguridad
//!
//! - **Constant-time**: Operaciones criptográficas resistentes a timing attacks
//! - **Zeroize**: Borrado seguro de claves privadas en memoria
//! - **No clonable**: Las claves privadas no pueden copiarse accidentalmente
//! - **Thread-safe**: Estado protegido con locks apropiados
//! - **Auditable**: Código claro y verificable
//!
//! ## Ejemplo de uso
//!
//! ```rust
//! use sello_integridad::{Firmante, Notario, verificar_sello};
//!
//! // Setup (una vez)
//! let ingeniero = Firmante::generar("Arturo");
//! let notario = Notario::nuevo("Mi Empresa - Sellado");
//! notario.registrar_firmante_autorizado("proyecto-x", ingeniero.clave_publica_hex());
//!
//! // Sellar contenido
//! let contenido = b"plano_v1.dwg";
//! let (evento, firma) = ingeniero.crear_evento_archivo(contenido, "proyecto-x", None).unwrap();
//! let sello = notario.notarizar_transaccion(
//!     &serde_json::to_value(&evento).unwrap(),
//!     &firma,
//!     &ingeniero.clave_publica(),
//!     "proyecto-x",
//! ).unwrap();
//!
//! // Verificación independiente (meses después, por un tercero)
//! let reporte = verificar_sello(&sello, &notario.clave_publica_hex(), None).unwrap();
//! assert!(reporte.todo_valido);
//! ```

pub mod crypto;
pub mod error;
pub mod evento;
pub mod firmante;
pub mod notario;
pub mod persistencia;
pub mod proteccion;
pub mod sello;

// Re-exports principales para API limpia
pub use crypto::{ClavePrivada, ClavePublica, FirmaBytes};
pub use error::{Result, SelloError};
pub use evento::{CuerpoSello, Evento, TipoEvento};
pub use firmante::Firmante;
pub use notario::{Notario, NotarioProtegido};
pub use proteccion::{
    ClaveMaestraDanio, EstadoProteccion, GestorProteccion, PoliticaConatus,
};
pub use sello::{verificar_sello, ReporteVerificacion, Sello, GENESIS_HASH};

// Versión de la crate
pub const VERSION: &str = env!("CARGO_PKG_VERSION");

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_version() {
        assert!(!VERSION.is_empty());
    }

    #[test]
    fn test_flujo_completo() {
        // Setup
        let ingeniero = Firmante::generar("Arturo");
        let notario = Notario::nuevo("Test Notary");
        notario.registrar_firmante_autorizado("p1", ingeniero.clave_publica_hex());

        // Crear y firmar evento
        let contenido = b"test content";
        let (evento, firma) = ingeniero
            .crear_evento_archivo(contenido, "p1", Some("evt-1".to_string()))
            .unwrap();

        // Notarizar
        let sello = notario
            .notarizar_transaccion(
                &serde_json::to_value(&evento).unwrap(),
                &firma,
                &ingeniero.clave_publica(),
                "p1",
            )
            .unwrap();

        assert!(sello.aceptado);

        // Verificación independiente
        let reporte = verificar_sello(&sello, &notario.clave_publica_hex(), None).unwrap();
        assert!(reporte.todo_valido);
    }
}
