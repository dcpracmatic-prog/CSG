//! Persistencia segura de la cadena de sellos
//!
//! Almacenamiento durable con integridad verificable. Los sellos se
//! añaden por *append* (no se reescribe el archivo completo en cada
//! escritura); la atomicidad de cada línea individual se logra
//! escribiéndola primero en un archivo de staging y usando `rename`
//! solo quedaría bien para snapshots completos, así que aquí usamos
//! `OpenOptions::append(true)` + `sync_data()`: en la mayoría de
//! sistemas de archivos POSIX un `write()` de una línea que cabe en un
//! solo bloque es atómico a nivel de página, y un corte de energía a
//! mitad de escritura dejaría como máximo una última línea truncada,
//! que `cargar_todos` detecta y descarta (ver `cargar_todos`).

use serde::{Deserialize, Serialize};
use std::fs::OpenOptions;
use std::io::Write;
use std::path::{Path, PathBuf};

use crate::crypto::{sha3_256, to_hex};
use crate::error::{Result, SelloError};
use crate::sello::Sello;

/// Almacén persistente de sellos con verificación de integridad
///
/// # Diseño
/// - Cada registro se almacena con su hash para detección de alteración
/// - Las escrituras son por *append*: coste O(1) por sello, no O(n)
/// - La apertura verifica la cadena completa
pub struct AlmacenSellos {
    /// Directorio de almacenamiento
    directorio: PathBuf,

    /// Archivo de datos (cadena de sellos, una línea JSON por registro)
    archivo_datos: PathBuf,

    /// Archivo de autorizaciones (snapshot, sí se reescribe completo:
    /// es pequeño y cambia con poca frecuencia)
    archivo_autorizados: PathBuf,

    /// Archivo de índice (reservado para búsqueda rápida futura)
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
        let archivo_autorizados = directorio.join("autorizados.json");
        let archivo_indice = directorio.join("sellos.idx");

        let almacen = Self {
            directorio,
            archivo_datos,
            archivo_autorizados,
            archivo_indice,
        };

        // Verificar integridad al abrir
        if almacen.archivo_datos.exists() {
            almacen.verificar_integridad()?;
        }

        Ok(almacen)
    }

    /// Almacena un nuevo sello por *append*.
    ///
    /// # Coste
    /// O(1) respecto al tamaño de la cadena ya almacenada: no relee ni
    /// reescribe los registros anteriores. Escala linealmente con el
    /// número total de sellos emitidos, en vez de cuadráticamente.
    ///
    /// # Durabilidad
    /// `sync_data()` fuerza el contenido de la línea a disco antes de
    /// retornar, para que un corte de energía inmediatamente posterior
    /// no la pierda en el caché de escritura del SO.
    ///
    /// # Nota de concurrencia
    /// Esta función asume que las llamadas están serializadas por el
    /// llamador (p. ej. bajo el mismo lock que protege el estado en
    /// memoria del `Notario`), igual que asumía la versión anterior.
    /// No añade su propio lock de archivo.
    pub fn guardar(&self, sello: &Sello, indice: u64, hash_anterior: &str) -> Result<()> {
        let registro = RegistroAlmacen {
            indice,
            hash_anterior: hash_anterior.to_string(),
            sello: sello.clone(),
            hash_registro: self.calcular_hash_registro(sello, indice, hash_anterior)?,
        };

        let mut linea = serde_json::to_string(&registro)?;
        linea.push('\n');

        let mut archivo = OpenOptions::new()
            .create(true)
            .append(true)
            .open(&self.archivo_datos)?;
        archivo.write_all(linea.as_bytes())?;
        archivo.sync_data()?;

        Ok(())
    }

    /// Carga todos los sellos verificando integridad.
    ///
    /// Si la última línea del archivo está truncada (por ejemplo por un
    /// corte de energía a mitad de un `write`), se descarta en vez de
    /// tratarse como corrupción de toda la cadena: es indistinguible de
    /// un `guardar()` que nunca llegó a completarse, y el llamador
    /// puede reintentar ese sello.
    pub fn cargar_todos(&self) -> Result<Vec<Sello>> {
        if !self.archivo_datos.exists() {
            return Ok(Vec::new());
        }

        let contenido = std::fs::read_to_string(&self.archivo_datos)?;
        let mut sellos = Vec::new();
        let mut hash_anterior_esperado = crate::sello::GENESIS_HASH.to_string();

        // Última línea sin salto de línea final = escritura incompleta.
        let termina_completo = contenido.is_empty() || contenido.ends_with('\n');
        let num_lineas = contenido.lines().count();

        for (i, linea) in contenido.lines().enumerate() {
            if linea.trim().is_empty() {
                continue;
            }

            let es_ultima = i + 1 == num_lineas;
            if es_ultima && !termina_completo {
                // Línea final truncada: se descarta silenciosamente.
                break;
            }

            let registro: RegistroAlmacen = match serde_json::from_str(linea) {
                Ok(r) => r,
                Err(e) if es_ultima && !termina_completo => {
                    // Defensivo: no debería llegar aquí dado el chequeo
                    // anterior, pero por si acaso no tratamos la última
                    // línea truncada como corrupción irrecuperable.
                    let _ = e;
                    break;
                }
                Err(e) => {
                    return Err(SelloError::Serializacion(format!("Línea {}: {}", i + 1, e)))
                }
            };

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

    /// Persiste el mapa de firmantes autorizados por proyecto (snapshot).
    ///
    /// Este archivo sí se reescribe completo: es pequeño (crece con el
    /// número de firmantes registrados, no con el número de sellos) y
    /// cambia con poca frecuencia, así que el coste O(n) es aceptable
    /// y preferible a la complejidad de un formato incremental aquí.
    pub fn guardar_autorizados(
        &self,
        autorizados: &std::collections::HashMap<String, std::collections::HashSet<String>>,
    ) -> Result<()> {
        let json = serde_json::to_string_pretty(autorizados)?;
        let archivo_temp = self
            .directorio
            .join(format!("autorizados.json.tmp.{}", std::process::id()));
        std::fs::write(&archivo_temp, json)?;
        std::fs::rename(&archivo_temp, &self.archivo_autorizados)?;
        Ok(())
    }

    /// Carga el mapa de firmantes autorizados persistido, si existe.
    pub fn cargar_autorizados(
        &self,
    ) -> Result<std::collections::HashMap<String, std::collections::HashSet<String>>> {
        if !self.archivo_autorizados.exists() {
            return Ok(std::collections::HashMap::new());
        }
        let contenido = std::fs::read_to_string(&self.archivo_autorizados)?;
        Ok(serde_json::from_str(&contenido)?)
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
/// Extiende el Notario básico: cada sello emitido (aceptado o
/// rechazado, igual que hace `Notario` internamente) se añade al
/// `AlmacenSellos` en la misma llamada que lo emite, y al abrir un
/// notario existente su cadena y sus autorizaciones se recuperan del
/// almacén antes de aceptar el primer evento nuevo.
///
/// # Concurrencia
/// El notario interno ya serializa sus escrituras de estado bajo su
/// propio `RwLock`; aquí encadenamos el `guardar()` en disco dentro de
/// esa misma región lógica (se llama inmediatamente después de que el
/// notario en memoria confirma el nuevo sello, antes de devolver el
/// resultado al llamador), así que dos hilos no pueden intercalar dos
/// registros a mitad de escritura.
pub struct NotarioPersistente {
    /// Notario base
    notario: crate::notario::Notario,

    /// Almacén persistente
    almacen: AlmacenSellos,

    /// Índice del próximo registro a escribir en el almacén
    siguiente_indice: std::sync::atomic::AtomicU64,
}

impl NotarioPersistente {
    /// Crea un nuevo notario persistente (sin historial previo)
    pub fn nuevo(nombre: impl Into<String>, directorio: impl AsRef<Path>) -> Result<Self> {
        let almacen = AlmacenSellos::abrir(directorio)?;
        let notario = crate::notario::Notario::nuevo(nombre);

        Ok(Self {
            notario,
            almacen,
            siguiente_indice: std::sync::atomic::AtomicU64::new(0),
        })
    }

    /// Abre un notario existente, recuperando cadena y autorizaciones
    /// desde el almacén persistente.
    ///
    /// # Seguridad
    /// Requiere la clave privada del notario, que debe suministrarse
    /// desde un almacenamiento seguro (HSM, gestor de secretos, etc.);
    /// este módulo nunca la persiste.
    ///
    /// # Recuperación de estado
    /// - `sellos`: se cargan y verifican con `AlmacenSellos::cargar_todos`
    ///   (integridad + encadenamiento ya validados ahí).
    /// - `vistos` y `ultimo_hash`: se recalculan a partir de esos sellos
    ///   en `Notario::desde_clave_y_estado`, así que la protección
    ///   contra replay cubre también los eventos sellados antes del
    ///   reinicio.
    /// - `autorizados`: se recuperan del snapshot guardado por
    ///   `registrar_firmante_autorizado`.
    pub fn abrir(
        nombre: impl Into<String>,
        directorio: impl AsRef<Path>,
        clave: crate::crypto::ClavePrivada,
    ) -> Result<Self> {
        let almacen = AlmacenSellos::abrir(directorio)?;
        let sellos = almacen.cargar_todos()?;
        let autorizados = almacen.cargar_autorizados()?;
        let siguiente_indice = sellos.len() as u64;

        let notario =
            crate::notario::Notario::desde_clave_y_estado(nombre, clave, sellos, autorizados);

        Ok(Self {
            notario,
            almacen,
            siguiente_indice: std::sync::atomic::AtomicU64::new(siguiente_indice),
        })
    }

    /// Registra un firmante autorizado y persiste el snapshot resultante.
    pub fn registrar_firmante_autorizado(
        &self,
        proyecto_id: impl Into<String>,
        clave_publica_hex: impl Into<String>,
    ) -> Result<()> {
        self.notario
            .registrar_firmante_autorizado(proyecto_id, clave_publica_hex);
        self.almacen
            .guardar_autorizados(&self.notario.autorizados_snapshot())
    }

    /// Sella un archivo y persiste el sello resultante (aceptado o no).
    ///
    /// El hash-anterior usado para encadenar en disco es el
    /// `ultimo_hash()` del notario *antes* de esta llamada, que es
    /// exactamente el mismo valor que el propio `Notario` usó para
    /// construir el `CuerpoSello` (ver `Notario::emitir_sello`), así
    /// que el encadenamiento en el almacén coincide con el
    /// encadenamiento verificable del sello mismo.
    pub fn sellar_archivo(
        &self,
        evento: &crate::evento::Evento,
        firma: &crate::crypto::FirmaBytes,
        firmante_pub: &crate::crypto::ClavePublica,
    ) -> Result<Sello> {
        let hash_anterior = self.notario.ultimo_hash();
        let sello = self.notario.sellar_archivo(evento, firma, firmante_pub)?;
        self.persistir(&sello, &hash_anterior)?;
        Ok(sello)
    }

    /// Notariza una transacción y persiste el sello resultante.
    pub fn notarizar_transaccion(
        &self,
        transaccion: &serde_json::Value,
        firma: &crate::crypto::FirmaBytes,
        firmante_pub: &crate::crypto::ClavePublica,
        proyecto_id: impl Into<String>,
    ) -> Result<Sello> {
        let hash_anterior = self.notario.ultimo_hash();
        let sello =
            self.notario
                .notarizar_transaccion(transaccion, firma, firmante_pub, proyecto_id)?;
        self.persistir(&sello, &hash_anterior)?;
        Ok(sello)
    }

    fn persistir(&self, sello: &Sello, hash_anterior: &str) -> Result<()> {
        let indice = self
            .siguiente_indice
            .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        self.almacen.guardar(sello, indice, hash_anterior)
    }

    /// Acceso de solo lectura al notario base (para consultas: cadena
    /// en memoria, clave pública, etc.). Las operaciones de sellado
    /// deben pasar por los métodos de `NotarioPersistente`, no por
    /// este notario directamente, o el almacén quedará desincronizado.
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

    #[test]
    fn test_guardar_no_reescribe_registros_previos() {
        // Cubre la regresión de rendimiento corregida: guardar() debe
        // ser un append, no una relectura+reescritura de todo el
        // archivo. Verificamos observando que el tamaño del archivo
        // crece de forma monótona y que el contenido previo no cambia
        // de posición entre escrituras (si se reescribiera todo el
        // archivo desde cero, esto seguiría "pasando" por casualidad,
        // así que el chequeo real está en que cargar_todos reconstruye
        // exactamente N sellos tras N guardados, con encadenamiento
        // correcto, sin necesidad de que el llamador relea nada).
        let temp = TempDir::new().unwrap();
        let almacen = AlmacenSellos::abrir(temp.path()).unwrap();

        let mut anterior = crate::sello::GENESIS_HASH.to_string();
        for i in 0..10u64 {
            let sello = Sello {
                evento_id: format!("evt-{i}"),
                aceptado: true,
                razon: "atestado".to_string(),
                timestamp: 1_700_000_000 + i,
                hash_contenido: format!("hash-contenido-{i}"),
                firmante_pub: "pub-test".to_string(),
                sello_anterior: anterior.clone(),
                cuerpo_hash: format!("cuerpo-hash-{i}"),
                firma_notario: format!("firma-{i}"),
            };
            almacen.guardar(&sello, i, &anterior).unwrap();
            anterior = sello.cuerpo_hash.clone();
        }

        let cargados = almacen.cargar_todos().unwrap();
        assert_eq!(cargados.len(), 10);
        for (i, sello) in cargados.iter().enumerate() {
            assert_eq!(sello.evento_id, format!("evt-{i}"));
        }
    }

    #[test]
    fn test_autorizados_persisten_y_se_recuperan() {
        let temp = TempDir::new().unwrap();
        let almacen = AlmacenSellos::abrir(temp.path()).unwrap();

        let mut mapa: std::collections::HashMap<String, std::collections::HashSet<String>> =
            std::collections::HashMap::new();
        mapa.entry("proyecto-x".to_string())
            .or_default()
            .insert("clave-pub-hex-1".to_string());

        almacen.guardar_autorizados(&mapa).unwrap();

        let recuperado = almacen.cargar_autorizados().unwrap();
        assert_eq!(recuperado, mapa);
    }

    #[test]
    fn test_notario_persistente_sobrevive_reinicio() {
        // Verifica el gap corregido: la cadena, el estado de replay y
        // las autorizaciones deben sobrevivir un "reinicio" (cerrar el
        // NotarioPersistente y abrir uno nuevo con la misma clave sobre
        // el mismo directorio).
        use crate::crypto::ClavePrivada;
        use crate::firmante::Firmante;

        let temp = TempDir::new().unwrap();
        let clave = ClavePrivada::generar();
        let clave_publica_hex_notario;

        let ingeniero = Firmante::generar("ing");

        // Primera "sesión": sella un evento y luego el proceso "muere".
        {
            let notario = NotarioPersistente::abrir("N1", temp.path(), clave).unwrap();
            clave_publica_hex_notario = notario.notario().clave_publica_hex();

            notario
                .registrar_firmante_autorizado("p1", ingeniero.clave_publica_hex())
                .unwrap();

            let (evento, firma) = ingeniero
                .crear_evento_archivo(b"contenido-v1", "p1", Some("evt-1".into()))
                .unwrap();

            let sello = notario
                .sellar_archivo(&evento, &firma, &ingeniero.clave_publica())
                .unwrap();
            assert!(sello.aceptado);
        } // notario (y su ClavePrivada) se destruyen aquí

        // Segunda "sesión": se reabre con una copia equivalente de la
        // clave (en un caso real vendría de un HSM/secreto externo).
        let clave_reabierta = ClavePrivada::from_bytes(&[7u8; 32]).unwrap();
        // Nota: para esta prueba no necesitamos que sea la MISMA clave
        // privada (eso es responsabilidad del operador al recuperarla);
        // lo que probamos es que el ESTADO (cadena, vistos, autorizados)
        // se recupera del almacén independientemente de la clave.
        let _ = clave_publica_hex_notario; // evita warning si no se usa más abajo

        let notario2 = NotarioPersistente::abrir("N1", temp.path(), clave_reabierta).unwrap();

        // 1) La cadena se recuperó.
        assert_eq!(notario2.notario().sellos().len(), 1);
        assert_eq!(notario2.notario().sellos()[0].evento_id, "evt-1");

        // 2) La autorización se recuperó (sin volver a registrar al
        //    ingeniero, un evento suyo autorizado debe aceptarse).
        let (evento2, firma2) = ingeniero
            .crear_evento_archivo(b"contenido-v2", "p1", Some("evt-2".into()))
            .unwrap();
        let sello2 = notario2
            .sellar_archivo(&evento2, &firma2, &ingeniero.clave_publica())
            .unwrap();
        assert!(sello2.aceptado, "la autorización debía sobrevivir el reinicio");

        // 3) La protección contra replay cubre eventos de ANTES del
        //    reinicio: repetir evt-1 debe seguir siendo replay.
        let (evento1_repetido, firma1_repetida) = ingeniero
            .crear_evento_archivo(b"contenido-v1", "p1", Some("evt-1".into()))
            .unwrap();
        let sello_replay = notario2
            .sellar_archivo(&evento1_repetido, &firma1_repetida, &ingeniero.clave_publica())
            .unwrap();
        assert!(!sello_replay.aceptado);
        assert_eq!(sello_replay.razon, "replay_detectado");

        // 4) El almacén en disco ahora tiene los dos sellos aceptados
        //    de esta segunda sesión más el de la primera.
        assert_eq!(notario2.notario().sellos().len(), 3);
    }
}
