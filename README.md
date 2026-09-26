# CSG — Cerradura de Seguridad Geométrica / Sello de Integridad

Repositorio que combina:

1. **CSG (`csg_lock.py`)** — Experimento de cerradura geométrica ciega (Blind Geometric Lock):
   - La clave es una dirección en un espacio de alta dimensión.
   - El token solo almacena un compromiso hash (nunca la clave en claro).
   - Verificación todo-o-nada (sin feedback de cercanía).
   - Conatus (endurecimiento exponencial) + registro de daño + ruptura estructural.

2. **Sello de Integridad (`sello-integridad-rust/`)** — Crate Rust de attestación criptográfica:
   - Firmas Ed25519, SHA3-256, zeroize de claves privadas.
   - Notario + Firmante + cadena de sellos verificable.
   - **Protección parcial CSG** (`NotarioProtegido`): conatus, damage_log cifrado con **AES-256-GCM** + **Argon2id**, y ruptura estructural tras umbral de intentos fallidos.

## Requisitos

- Python 3.10+ con `numpy` (para el experimento CSG).
- Rust 1.75+ / Cargo (para el crate).

## Uso rápido — experimento CSG

```bash
python3 csg_lock.py
```

## Uso rápido — crate Rust

```bash
cd sello-integridad-rust
cargo test --lib
cargo run --example demo_protegido
```

## API principal (Rust)

```rust
use sello_integridad::{
    Firmante, NotarioProtegido, PoliticaConatus, ClaveMaestraDanio, verificar_sello,
};

let politica = PoliticaConatus {
    umbral_ruptura: 5,
    factor_endurecimiento: 1.6,
    retardo_base_ms: 50,
};
let master = ClaveMaestraDanio::generar(); // o desde secreto externo / HSM
let notario = NotarioProtegido::con_politica("Mi Empresa", politica, Some(master));
let ingeniero = Firmante::generar("Arturo");
notario.registrar_firmante_autorizado("proyecto-x", ingeniero.clave_publica_hex());

let (evento, firma) = ingeniero
    .crear_evento_archivo(b"plano.dwg", "proyecto-x", None)
    .unwrap();
let sello = notario.sellar_evento(&evento, &firma, &ingeniero.clave_publica()).unwrap();
```

Tras N intentos fallidos el notario queda en `estructura_rota` y deja de emitir sellos aceptados hasta una recuperación fuera de banda.

## Licencia

MIT OR Apache-2.0 (crate Rust). El script CSG se ofrece como experimento de investigación.

## Seguridad

- No suba claves maestras ni tokens de acceso a este repositorio.
- La clave maestra del damage_log debe residir fuera del token (HSM o secreto de operador).
