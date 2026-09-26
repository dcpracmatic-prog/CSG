//! Implementación del Sello de Integridad Técnica
//!
//! Un Sello es la prueba criptográfica de que un evento específico
//! fue procesado por un notario en un momento dado.

use serde::{Deserialize, Serialize};

use crate::crypto::{to_hex, ClavePublica, FirmaBytes};
use crate::error::Result;
use crate::evento::CuerpoSello;

/// Hash génesis de la cadena (64 ceros en hex)
pub const GENESIS_HASH: &str = "0000000000000000000000000000000000000000000000000000000000000000";

/// Sello de integridad emitido por un notario
///
/// # Seguridad
/// - La firma del notario garantiza integridad del cuerpo
/// - El encadenamiento garantiza orden y no-repudio de la secuencia
/// - La verificación es independiente (solo requiere clave pública del notario)
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Sello {
    /// ID del evento sellado
    pub evento_id: String,

    /// Si el evento fue aceptado
    pub aceptado: bool,

    /// Razón del rechazo (vacío si aceptado)
    pub razon: String,

    /// Timestamp del sellado (Unix epoch, segundos)
    pub timestamp: u64,

    /// Hash del contenido original
    pub hash_contenido: String,

    /// Clave pública del firmante (hex)
    pub firmante_pub: String,

    /// Hash del sello anterior en la cadena
    pub sello_anterior: String,

    /// Hash del cuerpo del sello (lo que el notario firmó)
    pub cuerpo_hash: String,

    /// Firma del notario sobre el cuerpo_hash (hex)
    pub firma_notario: String,
}

impl Sello {
    /// Crea un nuevo sello a partir de un cuerpo y firma
    pub fn desde_cuerpo(cuerpo: &CuerpoSello, firma: FirmaBytes) -> Result<Self> {
        let cuerpo_hash = cuerpo.hash_hex()?;

        Ok(Self {
            evento_id: cuerpo.evento_id.clone(),
            aceptado: cuerpo.aceptado,
            razon: cuerpo.razon.clone(),
            timestamp: cuerpo.timestamp,
            hash_contenido: cuerpo.hash_contenido.clone(),
            firmante_pub: cuerpo.firmante_pub.clone(),
            sello_anterior: cuerpo.sello_anterior.clone(),
            cuerpo_hash,
            firma_notario: firma.to_hex(),
        })
    }

    /// Reconstruye el cuerpo del sello para verificación
    pub fn a_cuerpo(&self) -> CuerpoSello {
        CuerpoSello {
            evento_id: self.evento_id.clone(),
            aceptado: self.aceptado,
            razon: self.razon.clone(),
            timestamp: self.timestamp,
            hash_contenido: self.hash_contenido.clone(),
            firmante_pub: self.firmante_pub.clone(),
            sello_anterior: self.sello_anterior.clone(),
        }
    }

    /// Verifica la integridad del sello (sin verificar firma del notario)
    ///
    /// # Retorna
    /// `true` si el cuerpo_hash almacenado coincide con el recalculado
    pub fn verificar_integridad(&self) -> bool {
        match self.a_cuerpo().hash_hex() {
            Ok(recalculado) => recalculado == self.cuerpo_hash,
            Err(_) => false,
        }
    }

    /// Verifica la firma del notario
    ///
    /// # Argumentos
    /// * `notario_pub` - Clave pública del notario
    ///
    /// # Retorna
    /// `true` si la firma es válida para este cuerpo
    pub fn verificar_firma(&self, notario_pub: &ClavePublica) -> bool {
        // Primero verificar integridad del cuerpo
        if !self.verificar_integridad() {
            return false;
        }

        // Verificar firma sobre el cuerpo_hash
        match FirmaBytes::from_hex(&self.firma_notario) {
            Ok(firma) => notario_pub.verificar(self.cuerpo_hash.as_bytes(), &firma.to_signature()),
            Err(_) => false,
        }
    }

    /// Verifica el encadenamiento con el sello anterior
    ///
    /// # Argumentos
    /// * `anterior_esperado` - Hash del sello anterior esperado
    ///
    /// # Retorna
    /// `true` si el encadenamiento es correcto
    pub fn verificar_encadenamiento(&self, anterior_esperado: &str) -> bool {
        self.sello_anterior == anterior_esperado
    }

    /// Serializa a JSON
    pub fn a_json(&self) -> Result<String> {
        Ok(serde_json::to_string_pretty(self)?)
    }

    /// Deserializa desde JSON
    pub fn desde_json(json: &str) -> Result<Self> {
        Ok(serde_json::from_str(json)?)
    }
}

/// Reporte de verificación de un sello
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReporteVerificacion {
    /// ID del evento verificado
    pub evento_id: String,

    /// Resultados de cada verificación
    pub checks: ChecksVerificacion,

    /// Resultado global (todos los checks pasaron)
    pub todo_valido: bool,
}

/// Checks individuales de verificación
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ChecksVerificacion {
    /// El cuerpo no fue alterado
    pub cuerpo_no_alterado: bool,

    /// La firma del notario es válida
    pub firma_notario_valida: bool,

    /// El encadenamiento es correcto (None si no se verificó)
    pub encadenamiento_correcto: Option<bool>,
}

/// Verificación completa e independiente de un sello
///
/// # Seguridad
/// Esta función NO requiere el software del notario, solo su clave pública.
/// Cualquier tercero puede reimplementarla para verificar sellos.
///
/// # Argumentos
/// * `sello` - El sello a verificar
/// * `notario_pub_hex` - Clave pública del notario en hexadecimal
/// * `sello_anterior_esperado` - Hash del sello anterior (opcional, para verificar cadena)
pub fn verificar_sello(
    sello: &Sello,
    notario_pub_hex: &str,
    sello_anterior_esperado: Option<&str>,
) -> Result<ReporteVerificacion> {
    // Verificar integridad del cuerpo
    let cuerpo_no_alterado = sello.verificar_integridad();

    // Verificar firma del notario
    let firma_notario_valida = match ClavePublica::from_hex(notario_pub_hex) {
        Ok(pub_key) => sello.verificar_firma(&pub_key),
        Err(_) => false,
    };

    // Verificar encadenamiento si se proporcionó
    let encadenamiento_correcto = sello_anterior_esperado
        .map(|esperado| sello.verificar_encadenamiento(esperado));

    let checks = ChecksVerificacion {
        cuerpo_no_alterado,
        firma_notario_valida,
        encadenamiento_correcto,
    };

    // Todo válido = todos los checks true (ignorando None)
    let todo_valido = checks.cuerpo_no_alterado
        && checks.firma_notario_valida
        && checks.encadenamiento_correcto.unwrap_or(true);

    Ok(ReporteVerificacion {
        evento_id: sello.evento_id.clone(),
        checks,
        todo_valido,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::ClavePrivada;

    #[test]
    fn test_sello_desde_cuerpo() {
        let notario_key = ClavePrivada::generar();
        let notario_pub = ClavePublica::from(&notario_key);

        let cuerpo = CuerpoSello::nuevo(
            "evt-1",
            true,
            "",
            "hash123",
            "firmante-pub",
            GENESIS_HASH,
        );

        // El notario real (ver Notario::emitir_sello) firma el HASH
        // hexadecimal del cuerpo, no el JSON canónico del cuerpo. Los
        // tests deben reproducir exactamente ese contrato para que
        // verificar_firma() (que verifica contra cuerpo_hash.as_bytes())
        // tenga algo válido que verificar.
        let cuerpo_hash = cuerpo.hash_hex().unwrap();
        let firma = notario_key.firmar(cuerpo_hash.as_bytes());
        let firma_bytes = FirmaBytes::from_signature(&firma);

        let sello = Sello::desde_cuerpo(&cuerpo, firma_bytes).unwrap();

        assert_eq!(sello.evento_id, "evt-1");
        assert!(sello.aceptado);
        assert!(sello.verificar_integridad());
        assert!(sello.verificar_firma(&notario_pub));
    }

    #[test]
    fn test_verificacion_detecta_alteracion() {
        let notario_key = ClavePrivada::generar();
        let notario_pub = ClavePublica::from(&notario_key);

        let cuerpo = CuerpoSello::nuevo(
            "evt-1",
            true,
            "",
            "hash123",
            "firmante-pub",
            GENESIS_HASH,
        );

        let cuerpo_hash = cuerpo.hash_hex().unwrap();
        let firma = notario_key.firmar(cuerpo_hash.as_bytes());
        let firma_bytes = FirmaBytes::from_signature(&firma);

        let mut sello = Sello::desde_cuerpo(&cuerpo, firma_bytes).unwrap();

        // Alterar el sello
        sello.aceptado = false;

        assert!(!sello.verificar_integridad());
        assert!(!sello.verificar_firma(&notario_pub));
    }

    #[test]
    fn test_verificar_sello_independiente() {
        let notario_key = ClavePrivada::generar();
        let notario_pub_hex = notario_key.clave_publica_hex();

        let cuerpo = CuerpoSello::nuevo(
            "evt-1",
            true,
            "",
            "hash123",
            "firmante-pub",
            GENESIS_HASH,
        );

        let cuerpo_hash = cuerpo.hash_hex().unwrap();
        let firma = notario_key.firmar(cuerpo_hash.as_bytes());
        let firma_bytes = FirmaBytes::from_signature(&firma);

        let sello = Sello::desde_cuerpo(&cuerpo, firma_bytes).unwrap();

        let reporte = verificar_sello(&sello, &notario_pub_hex, None).unwrap();

        assert!(reporte.todo_valido);
        assert!(reporte.checks.cuerpo_no_alterado);
        assert!(reporte.checks.firma_notario_valida);
        assert_eq!(reporte.checks.encadenamiento_correcto, None);
    }
}
