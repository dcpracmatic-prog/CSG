# CSG Sello sidecar (Rust)

Sidecar HTTP fino sobre el crate real `sello_integridad`
(`NotarioProtegido` + `Firmante`, Ed25519 + SHA3-256). Es la
implementación en Rust del sidecar que TDCP espera en `CSG_SEAL_URL`
(la referencia en Python vive en
`tdcp/server/csg-sidecar/main.py`); el cliente es
`tdcp/src/protection/csg-client.ts`.

No reimplementa criptografía: el sellado y la verificación los hace el
crate. Este binario solo traduce entre HTTP/JSON y el crate, con HTTP
en std (`TcpListener` + parseo manual, sin dependencias de red).

## Compilar

```bash
cd sidecar
cargo build --release          # o: cargo build (debug)
```

Sin red, con las dependencias ya en la caché local de cargo:

```bash
cargo build --release --offline
```

## Levantar

```bash
# desde sidecar/
CSG_PORT=8010 ./target/release/csg-sidecar
```

Por defecto escucha solo en loopback: `http://127.0.0.1:8010`.
Apunta TDCP a él:

```bash
export CSG_SEAL_URL=http://127.0.0.1:8010
export VITE_CSG_SEAL_URL=http://127.0.0.1:8010
```

Variables de entorno:

| Variable | Defecto | Descripción |
|---|---|---|
| `CSG_HOST` | `127.0.0.1` | Interfaz de escucha |
| `CSG_PORT` | `8010` | Puerto |
| `CSG_NOTARIO_NAME` | `CSG-Notario` | Nombre del notario |
| `CSG_PROJECTS` | `tdcp` | Proyectos autorizados (lista separada por comas) |
| `CSG_UMBRAL_RUPTURA` | `8` | Fallos que rompen la estructura |
| `CSG_FACTOR_ENDURECIMIENTO` | `1.5` | Factor de conatus por fallo |
| `CSG_RETARDO_BASE_MS` | `50` | Retardo base de conatus (ms) |

## Endpoints

| Método | Ruta | Cuerpo / Respuesta |
|---|---|---|
| GET | `/healthz` | `{ ok, service, notario, estructura_rota, version }` |
| GET | `/v1/status` | `{ notario_name, notario_pub, firmante_pub, chain_tip, conatus, estructura_rota, intentos_fallidos, total_sellos }` |
| POST | `/v1/seal` | `{ content_base64, label?, attributes?, proyecto_id?, evento_id? }` → sello `csg.sello.v1` |
| POST | `/v1/verify` | `{ content_base64, sello }` → `{ todo_valido, checks { content_digest_match, cuerpo_no_alterado, firma_notario_valida, aceptado }, hash_contenido, schema }` |

El sello devuelto es el `Sello` del crate más el sobre
(`schema: "csg.sello.v1"`, `label`, `attributes`, `notario_pub`,
`developmentOnly: false`). `label` y `attributes` son campos de sobre:
se devuelven tal cual y **no** forman parte del cuerpo firmado, igual
que en el sidecar de referencia de TDCP.

## Probar a mano

```bash
# salud
curl -s http://127.0.0.1:8010/healthz

# sellar ("aG9sYSBDU0c=" es base64 de "hola CSG")
curl -s -X POST http://127.0.0.1:8010/v1/seal \
  -H 'Content-Type: application/json' \
  -d '{"content_base64":"aG9sYSBDU0c=","label":"demo","proyecto_id":"tdcp"}' \
  | tee /tmp/sello.json

# verificar con el contenido original -> todo_valido: true
curl -s -X POST http://127.0.0.1:8010/v1/verify \
  -H 'Content-Type: application/json' \
  -d "{\"content_base64\":\"aG9sYSBDU0c=\",\"sello\":$(cat /tmp/sello.json)}"

# verificar con contenido alterado ("aG9sYSBDU0ch" es "hola CSG!") -> todo_valido: false
curl -s -X POST http://127.0.0.1:8010/v1/verify \
  -H 'Content-Type: application/json' \
  -d "{\"content_base64\":\"aG9sYSBDU0ch\",\"sello\":$(cat /tmp/sello.json)}"
```

## Tests

```bash
cd sidecar
cargo test --offline
```

El test de integración (`tests/seal_verify.rs`) levanta el binario
real en un puerto libre y comprueba: `/healthz` y `/v1/status`,
`seal` (aceptado, `schema`, `hash_contenido` SHA3-256, `label` /
`attributes` eco), verificación independiente del sello con el crate,
`verify` OK con el contenido original, `verify` NO válido con
contenido alterado y con sello manipulado, `seal` sin contenido → 400,
y replay del mismo `evento_id` → sello rechazado
(`razon: "replay_detectado"`).

## Comportamiento que conviene saber

- **Claves efímeras por proceso.** El notario y el firmante interno se
  generan al arrancar y viven solo en el proceso. Los sellos siguen
  verificándose tras un reinicio porque cada sello lleva su
  `notario_pub` y `/v1/verify` verifica contra el `notario_pub` del
  propio sello (si el sello no lo trae, usa el del notario en curso).
- **Anti-replay.** Reutilizar un `evento_id` ya sellado devuelve un
  sello rechazado (`aceptado: false`, `razon: "replay_detectado"`). Sin
  `evento_id` el sidecar genera uno único por sellado.
- **Proyecto no autorizado.** Un `proyecto_id` fuera de `CSG_PROJECTS`
  devuelve un sello rechazado (`razon: "firmante_no_autorizado"`) y
  cuenta como fallo de conatus; tras `CSG_UMBRAL_RUPTURA` fallos la
  estructura se rompe y `/v1/seal` responde 503 hasta reiniciar el
  proceso (la recuperación es fuera de banda, como en el crate).
- **Cadena.** Cada sello encadena sobre el `cuerpo_hash` anterior
  (`sello_anterior`); la cadena vive en memoria y se pierde al
  reiniciar. `/v1/verify` no exige encadenamiento (igual que la
  referencia de TDCP: verifica contenido, cuerpo y firma).
- **Compatibilidad con la referencia Python.** El `cuerpo_hash` es el
  SHA3-256 del JSON canónico del cuerpo (7 campos, claves ordenadas),
  y la firma es Ed25519 sobre los bytes UTF-8 de ese hash hex: el
  mismo contrato que `sello_integridad::Sello`, así que un sello de
  este sidecar se verifica con el sidecar Python de TDCP y viceversa.
