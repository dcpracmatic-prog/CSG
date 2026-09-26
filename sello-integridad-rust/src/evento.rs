//! Definición de eventos y su canonicalización
//!
//! La canonicalización es CRÍTICA para la seguridad: dos representaciones
//! semánticamente iguales pero byte-distintas del mismo evento producirían
//! firmas diferentes, permitiendo ataques de confusión.

use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

use crate::crypto::{json_canonico, sha3_256};
use crate::error::{Result, SelloError};

/// Tipo de evento que se puede sellar
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TipoEvento {
    /// Archivo (plano CAD, firmware, dataset)
    Archivo,
    /// Transacción interna
    Transaccion,
    /// Autorización de acceso
    Autorizacion,
    /// Evento personalizado
    Custom(String),
}

/// Evento que será firmado y sellado
///
/// # Diseño
/// - Usa `BTreeMap` para garantizar orden determinista de campos
/// - La serialización es siempre canónica (mismo orden de bytes)
/// - No permite campos opcionales que puedan causar ambigüedad
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Evento {
    /// Identificador único del evento (prevención de replay)
    pub evento_id: String,

    /// Hash del contenido sellado (SHA3-256 en hex)
    pub hash_contenido: String,

    /// Tipo de evento
    pub tipo: TipoEvento,

    /// Proyecto/activo al que pertenece
    pub proyecto_id: String,

    /// Timestamp de creación del evento (Unix epoch, segundos)
    pub timestamp: u64,

    /// Metadatos adicionales (ordenados por BTreeMap)
    #[serde(default)]
    pub metadatos: BTreeMap<String, String>,
}

impl Evento {
    /// Crea un nuevo evento
    pub fn nuevo(
        evento_id: impl Into<String>,
        hash_contenido: impl Into<String>,
        tipo: TipoEvento,
        proyecto_id: impl Into<String>,
    ) -> Self {
        Self {
            evento_id: evento_id.into(),
            hash_contenido: hash_contenido.into(),
            tipo,
            proyecto_id: proyecto_id.into(),
            timestamp: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_secs())
                .unwrap_or(0),
            metadatos: BTreeMap::new(),
        }
    }

    /// Añade metadatos al evento
    pub fn con_metadato(mut self, clave: impl Into<String>, valor: impl Into<String>) -> Self {
        self.metadatos.insert(clave.into(), valor.into());
        self
    }

    /// Serializa el evento a JSON canónico
    ///
    /// # Seguridad
    /// La canonicalización garantiza que:
    /// - Los campos siempre aparecen en el mismo orden (alfabético)
    /// - No hay espacios en blanco significativos
    /// - Los números se representan sin ambigüedad
    pub fn a_canonico(&self) -> Result<Vec<u8>> {
        let json_value = serde_json::to_value(self)
            .map_err(|e| SelloError::Serializacion(e.to_string()))?;

        Ok(json_canonico(&json_value).into_bytes())
    }

    /// Calcula el hash del evento canónico
    pub fn hash_canonico(&self) -> Result<[u8; 32]> {
        let canonico = self.a_canonico()?;
        Ok(sha3_256(&canonico))
    }
}

/// Cuerpo del sello que será firmado por el notario
///
/// # Seguridad
/// Este es el objeto cuya integridad está protegida criptográficamente.
/// Cualquier modificación posterior invalida la firma.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct CuerpoSello {
    /// ID del evento sellado
    pub evento_id: String,

    /// Si el evento fue aceptado o rechazado
    pub aceptado: bool,

    /// Razón del rechazo (vacío si fue aceptado)
    pub razon: String,

    /// Timestamp del sellado (Unix epoch, segundos)
    pub timestamp: u64,

    /// Hash del contenido original
    pub hash_contenido: String,

    /// Clave pública del firmante (hex)
    pub firmante_pub: String,

    /// Hash del sello anterior en la cadena
    pub sello_anterior: String,
}

impl CuerpoSello {
    /// Crea el cuerpo de un sello
    pub fn nuevo(
        evento_id: impl Into<String>,
        aceptado: bool,
        razon: impl Into<String>,
        hash_contenido: impl Into<String>,
        firmante_pub: impl Into<String>,
        sello_anterior: impl Into<String>,
    ) -> Self {
        Self {
            evento_id: evento_id.into(),
            aceptado,
            razon: razon.into(),
            timestamp: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_secs())
                .unwrap_or(0),
            hash_contenido: hash_contenido.into(),
            firmante_pub: firmante_pub.into(),
            sello_anterior: sello_anterior.into(),
        }
    }

    /// Serializa a JSON canónico
    pub fn a_canonico(&self) -> Result<Vec<u8>> {
        let json_value = serde_json::to_value(self)
            .map_err(|e| SelloError::Serializacion(e.to_string()))?;

        Ok(json_canonico(&json_value).into_bytes())
    }

    /// Calcula el hash del cuerpo canónico
    pub fn hash_canonico(&self) -> Result<[u8; 32]> {
        let canonico = self.a_canonico()?;
        Ok(sha3_256(&canonico))
    }

    /// Calcula el hash del cuerpo en hexadecimal
    pub fn hash_hex(&self) -> Result<String> {
        Ok(crate::crypto::to_hex(&self.hash_canonico()?))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_evento_canonico_determinista() {
        let evento = Evento::nuevo(
            "test-1",
            "abc123",
            TipoEvento::Archivo,
            "proyecto-x",
        )
        .con_metadato("autor", "Arturo")
        .con_metadato("version", "1.0");

        let canonico1 = evento.a_canonico().unwrap();
        let canonico2 = evento.a_canonico().unwrap();

        assert_eq!(canonico1, canonico2);
    }

    #[test]
    fn test_evento_hash_unico() {
        let evento1 = Evento::nuevo("test-1", "abc", TipoEvento::Archivo, "p1");
        let evento2 = Evento::nuevo("test-2", "abc", TipoEvento::Archivo, "p1");

        let hash1 = evento1.hash_canonico().unwrap();
        let hash2 = evento2.hash_canonico().unwrap();

        assert_ne!(hash1, hash2);
    }

    #[test]
    fn test_cuerpo_sello_canonico() {
        let cuerpo = CuerpoSello::nuevo(
            "evt-1",
            true,
            "",
            "hash123",
            "pubkey456",
            "anterior789",
        );

        let canonico = cuerpo.a_canonico().unwrap();
        assert!(!canonico.is_empty());

        // Verificar que es determinista
        let canonico2 = cuerpo.a_canonico().unwrap();
        assert_eq!(canonico, canonico2);
    }
}
