//! Persistencia segura de la cadena de sellos
//!
//! La versión base mantiene la cadena en memoria. Este módulo
//! proporciona almacenamiento durable con integridad verificable.

use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};

use crate::crypto::{sha3_256, to_hex};
use crate::error::{Result, SelloError};
use crate::sello::Sello;

/// Almacén persistente de sellos con verificación de integridad
///
/// # Diseño
/// - Cada registro se almacena con su hash para detección de alteración
/// - Los escritos son atómicos (write-then-rename)
/// - La apertura verifica la cadena completa
pub struct AlmacenSellos {
    /// Directorio de almacenamiento
    directorio: PathBuf,

    /// Archivo de datos
    archivo_datos: PathBuf,

    /// Archivo de índice (para búsqueda rápida)
    archivo_indice: PathBuf,
}

/// Registro almacenado con metadatos de integridad
#[derive(Clone, Debug, Serialize, Deserialize)]
struct RegistroAlmacen {
    /// Posición en la cadena
    indice: u64,

    /// Hash del registro anterior
    hash_anterior: String,

    /// El sello almacenado
    sello: Sello,

    /// Hash de este registro (para verificación)
    hash_registro: String,
}

impl AlmacenSellos {
    /// Crea o abre un almacén en el directorio especificado
    pub fn abrir(directorio: impl AsRef<Path>) -> Result<Self> {
        let directorio = directorio.as_ref().to_path_buf();
        std::fs::create_dir_all(&directorio)?;

        let archivo_datos = directorio.join("sellos.dat");
        let archivo_indice = directorio.join("sellos.idx");

        let almacen = Self {
            directorio,
            archivo_datos,
            archivo_indice,
        };

        // Verificar integridad al abrir
        if almacen.archivo_datos.exists() {
            almacen.verificar_integridad()?;
        }

        Ok(almacen)
    }

    /// Almacena un nuevo sello
    ///
    /// # Atomicidad
    /// Se lee el contenido actual del archivo, se le añade la nueva
    /// línea en memoria, y el resultado completo se escribe a un
    /// archivo temporal que luego se renombra sobre el archivo final.
    /// `rename` dentro del mismo sistema de archivos es atómico a nivel
    /// de SO: un corte de energía o un `kill -9` a mitad del proceso
    /// deja intacto el archivo original o el nuevo completo, nunca una
    /// mezcla corrupta de ambos.
    pub fn guardar(&self, sello: &Sello, indice: u64, hash_anterior: &str) -> Result<()> {
        let registro = RegistroAlmacen {
            indice,
            hash_anterior: hash_anterior.to_string(),
            sello: sello.clone(),
            hash_registro: self.calcular_hash_registro(sello, indice, hash_anterior)?,
        };

        let linea = serde_json::to_string(&registro)?;

        // Contenido actual (vacío si el archivo aún no existe)
        let mut contenido_actual = if self.archivo_datos.exists() {
            std::fs::read_to_string(&self.archivo_datos)?
        } else {
            String::new()
        };

        if !contenido_actual.is_empty() && !contenido_actual.ends_with('\n') {
            contenido_actual.push('\n');
        }
        contenido_actual.push_str(&linea);
        contenido_actual.push('\n');

        // Escribir snapshot completo a un temporal único y renombrar:
        // esto es lo que hace la escritura atómica de verdad.
        let archivo_temp = self
            .directorio
            .join(format!("sellos.dat.tmp.{}", std::process::id()));
        std::fs::write(&archivo_temp, contenido_actual)?;
        std::fs::rename(&archivo_temp, &self.archivo_datos)?;

        Ok(())
    }

    /// Carga todos los sellos verificando integridad
    pub fn cargar_todos(&self) -> Result<Vec<Sello>> {
        if !self.archivo_datos.exists() {
            return Ok(Vec::new());
        }

        let contenido = std::fs::read_to_string(&self.archivo_datos)?;
        let mut sellos = Vec::new();
        let mut hash_anterior_esperado = crate::sello::GENESIS_HASH.to_string();

        for (i, linea) in contenido.lines().enumerate() {
            if linea.trim().is_empty() {
                continue;
            }

            let registro: RegistroAlmacen = serde_json::from_str(linea)
                .map_err(|e| SelloError::Serializacion(format!("Línea {}: {}", i + 1, e)))?;

            // Verificar índice
            if registro.indice != i as u64 {
                return Err(SelloError::Validacion(format!(
                    "Índice discontinuo en posición {}: esperado {}, encontrado {}",
                    i, i, registro.indice
                )));
            }

            // Verificar encadenamiento
            if registro.hash_anterior != hash_anterior_esperado {
                return Err(SelloError::Validacion(format!(
                    "Encadenamiento roto en posición {}",
                    i
                )));
            }

            // Verificar hash del registro
            let hash_calculado =
                self.calcular_hash_registro(&registro.sello, registro.indice, &registro.hash_anterior)?;

            if hash_calculado != registro.hash_registro {
                return Err(SelloError::Validacion(format!(
                    "Hash de registro inválido en posición {} - posible alteración",
                    i
                )));
            }

            // Clonar hash antes del move del sello
            hash_anterior_esperado = registro.sello.cuerpo_hash.clone();
            sellos.push(registro.sello);
        }

        Ok(sellos)
    }

    /// Verifica la integridad completa del almacén
    pub fn verificar_integridad(&self) -> Result<()> {
        self.cargar_todos().map(|_| ())
    }

    /// Calcula el hash de un registro
    ///
    /// Incluye la serialización canónica completa del sello para detectar
    /// cualquier alteración de campos (no solo cuerpo_hash y firma_notario).
    fn calcular_hash_registro(
        &self,
        sello: &Sello,
        indice: u64,
        hash_anterior: &str,
    ) -> Result<String> {
        let sello_json = serde_json::to_string(sello)
            .map_err(|e| SelloError::Serializacion(e.to_string()))?;
        let datos = format!("{}:{}:{}", indice, hash_anterior, sello_json);
        Ok(to_hex(&sha3_256(datos.as_bytes())))
    }

    /// Obtiene el último hash de la cadena almacenada
    pub fn ultimo_hash(&self) -> Result<String> {
        let sellos = self.cargar_todos()?;
        Ok(sellos
            .last()
            .map(|s| s.cuerpo_hash.clone())
            .unwrap_or_else(|| crate::sello::GENESIS_HASH.to_string()))
    }

    /// Obtiene el número de sellos almacenados
    pub fn len(&self) -> Result<usize> {
        Ok(self.cargar_todos()?.len())
    }

    /// Verifica si el almacén está vacío
    pub fn is_empty(&self) -> Result<bool> {
        Ok(self.len()? == 0)
    }
}

/// Notario con persistencia automática
///
/// Extiende el Notario básico con almacenamiento durable.
pub struct NotarioPersistente {
    /// Notario base
    notario: crate::notario::Notario,

    /// Almacén persistente
    almacen: AlmacenSellos,
}

impl NotarioPersistente {
    /// Crea un nuevo notario persistente
    pub fn nuevo(nombre: impl Into<String>, directorio: impl AsRef<Path>) -> Result<Self> {
        let almacen = AlmacenSellos::abrir(directorio)?;
        let notario = crate::notario::Notario::nuevo(nombre);

        Ok(Self { notario, almacen })
    }

    /// Abre un notario existente desde almacenamiento
    ///
    /// # NOTA
    /// Esto requiere la clave privada del notario, que debe
    /// estar almacenada de forma segura (HSM, gestor de secretos, etc.)
    pub fn abrir(
        nombre: impl Into<String>,
        directorio: impl AsRef<Path>,
        clave: crate::crypto::ClavePrivada,
    ) -> Result<Self> {
        let almacen = AlmacenSellos::abrir(directorio)?;
        let notario = crate::notario::Notario::desde_clave(nombre, clave);

        // TODO: Cargar estado previo (vistos, autorizados) desde almacenamiento

        Ok(Self { notario, almacen })
    }

    /// Delega todas las operaciones al notario base
    pub fn notario(&self) -> &crate::notario::Notario {
        &self.notario
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    #[test]
    fn test_almacen_abrir_vacio() {
        let temp = TempDir::new().unwrap();
        let almacen = AlmacenSellos::abrir(temp.path()).unwrap();
        assert!(almacen.is_empty().unwrap());
    }

    #[test]
    fn test_almacen_guardar_cargar() {
        let temp = TempDir::new().unwrap();
        let almacen = AlmacenSellos::abrir(temp.path()).unwrap();

        // Crear un sello de prueba
        let sello = Sello {
            evento_id: "test-1".to_string(),
            aceptado: true,
            razon: "atestado".to_string(),
            timestamp: 1234567890,
            hash_contenido: "abc123".to_string(),
            firmante_pub: "pub456".to_string(),
            sello_anterior: crate::sello::GENESIS_HASH.to_string(),
            cuerpo_hash: "hash789".to_string(),
            firma_notario: "firma012".to_string(),
        };

        almacen.guardar(&sello, 0, crate::sello::GENESIS_HASH).unwrap();

        let cargados = almacen.cargar_todos().unwrap();
        assert_eq!(cargados.len(), 1);
        assert_eq!(cargados[0].evento_id, "test-1");
    }

    #[test]
    fn test_almacen_detecta_alteracion() {
        let temp = TempDir::new().unwrap();
        let almacen = AlmacenSellos::abrir(temp.path()).unwrap();

        let sello = Sello {
            evento_id: "test-1".to_string(),
            aceptado: true,
            razon: "atestado".to_string(),
            timestamp: 1234567890,
            hash_contenido: "abc123".to_string(),
            firmante_pub: "pub456".to_string(),
            sello_anterior: crate::sello::GENESIS_HASH.to_string(),
            cuerpo_hash: "hash789".to_string(),
            firma_notario: "firma012".to_string(),
        };

        almacen.guardar(&sello, 0, crate::sello::GENESIS_HASH).unwrap();

        // Alterar el archivo directamente
        let ruta = temp.path().join("sellos.dat");
        let contenido = std::fs::read_to_string(&ruta).unwrap();
        let alterado = contenido.replace("abc123", "xyz999");
        std::fs::write(&ruta, alterado).unwrap();

        // Debe detectar la alteración
        assert!(almacen.verificar_integridad().is_err());
    }
}
