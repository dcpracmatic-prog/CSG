[![CI](https://github.com/dcpracmatic-prog/CSG/actions/workflows/ci.yml/badge.svg)](https://github.com/dcpracmatic-prog/CSG/actions/workflows/ci.yml)

# CSG — Cerradura de Seguridad Geométrica / Sello de Integridad

Repositorio con **dos partes separadas**, que se prueban por separado y no
deben mezclarse: una cerradura experimental en Python y un sello
criptográfico en Rust. La parte Python es un experimento enseñado con sus
límites a la vista; la parte Rust es la pieza seria, usable como biblioteca
de integridad.

> Estado CI (verificado 2026-11-11 en la página de Actions): la última
> corrida en `main` (commit `62df973`, 1 oct 2026, run #12) muestra
> `Status Success` en su cabecera, pero la misma página lista 1 error —
> el job Rust terminó con exit 1. Esa contradicción no se pudo resolver
> desde el sandbox (la página de detalle del job no cargó); la insignia
> de arriba muestra el estado en vivo y la próxima corrida de CI dará el
> veredicto fresco. No se afirma aquí un estado que no se pudo confirmar.

## Parte 1 — Cerradura geométrica ciega (Python, `csg_lock.py`)

Experimento: la clave es una dirección en R⁶⁴; el token guarda solo
`SHA3-256(dirección cuantizada + salt)`; verificación todo-o-nada (sin
feedback de cercanía); conatus ×1.6 por fallo; ruptura a los 5 fallos.

### Qué se probó (Python)

- Experimento del repo: `python3 csg_lock.py` — exit 0. Q1: conatus tras
  5 fallos 1.6 → 2.56 → 4.096 → 6.554 → **10.486** (= 1.6⁵); dueño
  legítimo tras la ruptura denegado. Q2: correlación cercanía vs byte0
  del commit **≈ 0 con n=2000** (mediciones entre −0.007 y +0.021 según
  el salt aleatorio; el número al decimal no es reproducible por diseño).
  Q3: `pickle.dumps(lock)` **no** recupera la dirección (ver abajo).
- Tests: `python3 -m unittest discover -s tests -v` — **11 tests, 0 fallos**
  (~19 s). Incluyen: pickle sin fuga (antes y después de 5 fallos),
  AES-GCM (roundtrip, sin repetición de flujo, alteración de 1 bit
  detectada por el tag), conatus como retardo real medido, y ruptura
  (5 fallos → rota, dueño fuera).
- Fuerza bruta con presupuesto: `tests/test_bruteforce_budget.py` —
  **1 000 000 de direcciones aleatorias en R⁶⁴, 0 aciertos**, en ~13 s
  (~78 000 intentos/s, verificación offline contra el commit). Es una
  medida con presupuesto, no una prueba de imposibilidad.

### Arreglos 2026-11-11 (defectos medidos, hoy corregidos)

1. **Pickle recuperaba la clave.** Antes: `pickle.dumps(lock)` contenía
   `true_direction` (927 B recién enrolado; el test de la aserción
   fallaba con exit 1). Ahora: `enroll()` borra la dirección del objeto
   tras generar commit+payload, y `__getstate__` la excluye del pickle
   aunque llegara a estar asignada. El dueño guarda su dirección fuera
   del token y la pasa a `enroll(payload, direction=...)`. Medido:
   `pickle.dumps(lock)` = 344 B, dirección ausente, `None` tras
   `pickle.loads`; el token recuperado sigue verificando al dueño.
2. **Cifrado XOR repetitivo.** Antes: `xor_encrypt` repetía la clave cada
   32 B, sin autenticación. Ahora: **AES-256-GCM** (`cryptography`,
   clave de 32 B derivada por PBKDF2-SHA3-256, 100 000 iteraciones),
   nonce aleatorio de 12 B por cifrado; cualquier alteración se detecta
   (InvalidTag). Se eligió AES-GCM porque es viable sin romper la demo:
   misma interfaz (clave derivada → cifrar/descifrar payload y huellas
   del damage_log), dependencia estándar instalable por pip y verificada
   en sandbox y en CI. Requiere `pip install -r requirements.txt`.
3. **Conatus sin retardo real.** Antes: solo un número; 3 fallos tardaban
   ~0.23 s (solo el PBKDF2 del damage_log). Ahora: cada fallo espera
   `sleep(0.05 s × conatus)` — 3 fallos tardan ~0.68 s medidos (0.41 s
   de retardo + PBKDF2). El acceso legítimo no espera.

### Límites que siguen (no se prometen como seguridad)

- La tolerancia es frágil: la "exactitud" es caer en la misma celda de
  cuantización (1e-6 por coordenada); una perturbación de 1e-9 ya puede
  fallar. Hace falta el arreglo flotante exacto, no "casi exacto".
- "Sin pista de cercanía" está medido solo como correlación lineal del
  byte 0 (n=2000) más la fuerza bruta de 1M intentos; no es una prueba
  criptográfica ni una auditoría externa.
- La ruptura es destructiva e irreversible por diseño: tras 5 fallos no
  hay vuelta atrás con la clave; el canal de recuperación externo se
  menciona pero no se implementa ni se prueba.
- El `damage_log` se cifra con AES-GCM bajo una clave derivada de una
  clave maestra de demo (`OWNER_MASTER_KEY_DEMO` si no se pasa otra);
  en uso real la clave maestra debe vivir fuera del token (HSM o secreto
  de operador).

## Parte 2 — Sello de Integridad (Rust, `sello-integridad-rust/`)

Crate `sello_integridad` v1.1.0 de attestación criptográfica: firmas
Ed25519, SHA3-256, `zeroize` de claves privadas; Notario + Firmante +
cadena de sellos verificable; `NotarioProtegido` (conatus + damage_log
cifrado con **AES-256-GCM** + **Argon2id** + ruptura) y
`NotarioPersistente`.

### Qué se probó (Rust)

- `cargo test` (suite completa): **42 passed, 0 failed — 35 lib +
  6 integración + 1 doc-test** (medido en sandbox 2026-11-11, antes y
  después de los arreglos Python; la parte Rust no se tocó).
- `cargo run --example demo_protegido`: exit 0. Sello legítimo aceptado,
  conatus 1.00; 3 fallos → rota
  (`Estructura rota: el notario ha sido invalidado por exceso de intentos
  fallidos`); `fallos=3 damage_log_entries=3 conatus=4.10`.
- `cargo run --example demo_api`: exit 0. Flujo clásico + protegido +
  sello legítimo sin subir el conatus.
- Comprobado en el código (no solo en este README): `proteccion.rs` usa
  `Aes256Gcm` + `Argon2id` de verdad; `crypto.rs` usa `zeroize::Zeroize`.
  Umbral configurable: los ejemplos usan `umbral_ruptura: 3`, el ejemplo
  de abajo usa 5 — es un parámetro, no una contradicción.

## Requisitos

- Python 3.10+ con `numpy` y `cryptography` (para la cerradura):
  `pip install -r requirements.txt`.
- Rust 1.75+ / Cargo (para el crate).

## Uso rápido — experimento CSG

```bash
pip install -r requirements.txt
python3 csg_lock.py
python3 -m unittest discover -s tests -v
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

Este repositorio se distribuye bajo la **Elastic License 2.0** (ELv2).
Consulte el archivo [LICENSE](LICENSE) para el texto completo.

Resumen de limitaciones ELv2:
- No ofrecer el software a terceros como servicio alojado/gestionado.
- No eludir funcionalidad de claves de licencia ni ocultar avisos.
- No eliminar avisos de licencia o copyright.

## Seguridad

- No suba claves maestras ni tokens de acceso a este repositorio.
- La clave maestra del damage_log debe residir fuera del token (HSM o secreto de operador).
