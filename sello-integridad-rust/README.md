# sello_integridad v1.1.0

Primitiva de attestación criptográfica para activos de ingeniería (planos CAD, firmware, datasets) y transacciones internas.

## Características

- Firmas **Ed25519** (constant-time) con `ed25519-dalek`
- Hash **SHA3-256**
- Claves privadas con **zeroize** y sin `Clone`
- Cadena de sellos verificable de forma independiente
- **NotarioProtegido**: conatus (endurecimiento exponencial), registro de daño cifrado (**AES-256-GCM** + **Argon2id**) y ruptura estructural tras umbral de fallos

## Uso rápido

```rust
use sello_integridad::{Firmante, Notario, verificar_sello};

let ingeniero = Firmante::generar("nombre");
let notario = Notario::nuevo("Mi Empresa");
notario.registrar_firmante_autorizado("proyecto-x", ingeniero.clave_publica_hex());

let (evento, firma) = ingeniero
    .crear_evento_archivo(b"plano.dwg", "proyecto-x", None)
    .unwrap();
let sello = notario
    .sellar_evento(&evento, &firma, &ingeniero.clave_publica())
    .unwrap();
assert!(sello.aceptado);

let reporte = verificar_sello(&sello, &notario.clave_publica_hex(), None).unwrap();
assert!(reporte.todo_valido);
```

### Notario protegido (conatus + ruptura)

```rust
use sello_integridad::{ClaveMaestraDanio, NotarioProtegido, PoliticaConatus};

let politica = PoliticaConatus {
    umbral_ruptura: 5,
    factor_endurecimiento: 1.6,
    retardo_base_ms: 50,
};
let master = ClaveMaestraDanio::generar(); // o secreto externo / HSM
let notario = NotarioProtegido::con_politica("Seguro", politica, Some(master));
```

### Notario persistente (sobrevive reinicios)

`Notario` y `NotarioProtegido` viven solo en memoria: si el proceso
termina, se pierde la cadena, el estado de protección contra replay y
las autorizaciones. `NotarioPersistente` envuelve a `Notario` y
escribe cada sello al abrirlo con `AlmacenSellos` (append en disco,
sin reescribir la cadena completa en cada sello):

```rust
use sello_integridad::{ClavePrivada, Firmante, NotarioPersistente};

let clave = ClavePrivada::generar(); // en producción: HSM / secreto externo
let notario = NotarioPersistente::abrir("Mi Empresa", "./datos-notario", clave)?;
// Si "./datos-notario" ya tenía una cadena, se recupera aquí: la
// protección contra replay cubre también los eventos previos.

let ingeniero = Firmante::generar("Arturo");
notario.registrar_firmante_autorizado("proyecto-x", ingeniero.clave_publica_hex())?;

let (evento, firma) = ingeniero.crear_evento_archivo(b"plano.dwg", "proyecto-x", None)?;
let sello = notario.sellar_archivo(&evento, &firma, &ingeniero.clave_publica())?;
```

## Compilar y probar

```bash
cargo test --lib
cargo run --example demo_api
```

## Módulos

| Módulo | Descripción |
|--------|-------------|
| `crypto` | Ed25519, SHA3, ClavePrivada/Publica, FirmaBytes |
| `firmante` | Autor de eventos firmados |
| `notario` | Emisor de sellos (`Notario`, `NotarioProtegido`) |
| `proteccion` | Conatus, damage_log AES-GCM+Argon2, ruptura |
| `sello` | Estructura de sello y verificación independiente |
| `persistencia` | Almacén durable con integridad |
| `evento` | Eventos y cuerpo canónico |
| `error` | Errores tipados |


## License

Elastic License 2.0 — see [LICENSE](../LICENSE).

