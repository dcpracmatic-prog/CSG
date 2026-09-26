//! Implementación del Firmante - autor de eventos
//!
//! El Firmante es quien crea y firma eventos (archivos, transacciones).
//! Su clave privada nunca debe salir de su control.

use crate::crypto::{json_canonico, sha3_256, to_hex, ClavePrivada, ClavePublica, FirmaBytes};
use crate::error::Result;
use crate::evento::{Evento, TipoEvento};

/// Firmante de eventos (ingeniero, sistema, autor)
///
/// # Seguridad
/// - La clave privada está protegida y se borra al liberar
/// - No es clonable (previene copias accidentales de la clave)
/// - Las firmas se producen en tiempo constante
pub struct Firmante {
    /// Nombre identificador del firmante
    nombre: String,

    /// Clave privada protegida
    clave: ClavePrivada,
}

impl Firmante {
    /// Genera un nuevo firmante con clave aleatoria
    pub fn generar(nombre: impl Into<String>) -> Self {
        Self {
            nombre: nombre.into(),
            clave: ClavePrivada::generar(),
        }
    }

    /// Crea un firmante desde una clave privada existente
    pub fn desde_clave(nombre: impl Into<String>, clave: ClavePrivada) -> Self {
        Self {
            nombre: nombre.into(),
            clave,
        }
    }

    /// Obtiene el nombre del firmante
    pub fn nombre(&self) -> &str {
        &self.nombre
    }

    /// Obtiene la clave pública del firmante
    pub fn clave_publica(&self) -> ClavePublica {
        ClavePublica::from(&self.clave)
    }

    /// Obtiene la clave pública en hexadecimal
    pub fn clave_publica_hex(&self) -> String {
        self.clave.clave_publica_hex()
    }

    /// Firma un evento
    ///
    /// # Seguridad
    /// - La firma es válida SOLO para estos bytes exactos
    /// - Cambiar cualquier campo invalida la firma
    /// - La operación es de tiempo constante
    pub fn firmar_evento(&self, evento: &Evento) -> Result<FirmaBytes> {
        let canonico = evento.a_canonico()?;
        let firma = self.clave.firmar(&canonico);
        Ok(FirmaBytes::from_signature(&firma))
    }

    /// Crea y firma un evento de archivo
    pub fn crear_evento_archivo(
        &self,
        contenido: &[u8],
        proyecto_id: impl Into<String>,
        evento_id: Option<String>,
    ) -> Result<(Evento, FirmaBytes)> {
        let hash_contenido = to_hex(&sha3_256(contenido));
        let eid = evento_id.unwrap_or_else(|| hash_contenido[..16].to_string());

        let evento = Evento::nuevo(
            eid,
            hash_contenido,
            TipoEvento::Archivo,
            proyecto_id,
        );

        let firma = self.firmar_evento(&evento)?;
        Ok((evento, firma))
    }

    /// Crea y firma un evento de transacción
    pub fn crear_evento_transaccion(
        &self,
        transaccion: &serde_json::Value,
        proyecto_id: impl Into<String>,
    ) -> Result<(Evento, FirmaBytes)> {
        // Canonicalizar transacción
        let canonico = json_canonico(transaccion);
        let hash_contenido = to_hex(&sha3_256(canonico.as_bytes()));

        let evento_id = transaccion
            .get("id")
            .and_then(|v| v.as_str())
            .map(|s| s.to_string())
            .unwrap_or_else(|| hash_contenido[..16].to_string());

        let evento = Evento::nuevo(
            evento_id,
            hash_contenido,
            TipoEvento::Transaccion,
            proyecto_id,
        );

        let firma = self.firmar_evento(&evento)?;
        Ok((evento, firma))
    }
}

impl Drop for Firmante {
    fn drop(&mut self) {
        tracing::debug!("Firmante '{}' destruido", self.nombre);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_firmante_generar() {
        let firmante = Firmante::generar("Arturo");
        assert_eq!(firmante.nombre(), "Arturo");
        assert!(!firmante.clave_publica_hex().is_empty());
    }

    #[test]
    fn test_firmar_evento() {
        let firmante = Firmante::generar("Test");
        let evento = Evento::nuevo(
            "evt-1",
            "hash123",
            TipoEvento::Archivo,
            "proyecto-x",
        );

        let firma = firmante.firmar_evento(&evento).unwrap();
        assert!(!firma.to_hex().is_empty());

        // Verificar firma
        let canonico = evento.a_canonico().unwrap();
        let pub_key = firmante.clave_publica();
        assert!(pub_key.verificar(&canonico, &firma.to_signature()));
    }

    #[test]
    fn test_crear_evento_archivo() {
        let firmante = Firmante::generar("Test");
        let contenido = b"test content";

        let (evento, firma) = firmante
            .crear_evento_archivo(contenido, "p1", Some("evt-1".to_string()))
            .unwrap();

        assert_eq!(evento.evento_id, "evt-1");
        assert_eq!(evento.proyecto_id, "p1");

        // Verificar que el hash coincide
        let hash_esperado = to_hex(&sha3_256(contenido));
        assert_eq!(evento.hash_contenido, hash_esperado);
    }
}
