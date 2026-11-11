//! Base64 estándar (RFC 4648) con la mínima superficie necesaria.
//!
//! El sidecar solo usa std + el crate `sello_integridad`; no se añade
//! ninguna dependencia de base64. La decodificación es estricta salvo
//! espacios en blanco ASCII, que se ignoran.

#[allow(dead_code)] // `encode` solo lo usa el test de integración.
const ALFABETO: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

fn valor(b: u8) -> Option<u8> {
    match b {
        b'A'..=b'Z' => Some(b - b'A'),
        b'a'..=b'z' => Some(b - b'a' + 26),
        b'0'..=b'9' => Some(b - b'0' + 52),
        b'+' => Some(62),
        b'/' => Some(63),
        _ => None,
    }
}

/// Decodifica base64 estándar. Acepta relleno `=` final (0, 1 o 2).
pub fn decode(input: &str) -> Result<Vec<u8>, String> {
    let limpio: Vec<u8> = input
        .bytes()
        .filter(|b| !matches!(b, b' ' | b'\t' | b'\r' | b'\n'))
        .collect();
    if limpio.is_empty() {
        return Ok(Vec::new());
    }
    if limpio.len() % 4 != 0 {
        return Err("longitud base64 no múltiplo de 4".to_string());
    }
    let mut out = Vec::with_capacity(limpio.len() * 3 / 4);
    for grupo in limpio.chunks_exact(4) {
        let relleno = grupo.iter().filter(|&&b| b == b'=').count();
        if relleno > 2 {
            return Err("relleno base64 inválido".to_string());
        }
        // El relleno solo puede ir al final del último grupo.
        if grupo[0] == b'=' || grupo[1] == b'=' {
            return Err("relleno base64 en posición inválida".to_string());
        }
        let mut n: u32 = 0;
        for (i, &b) in grupo.iter().enumerate() {
            if b == b'=' {
                if i < 2 {
                    return Err("relleno base64 en posición inválida".to_string());
                }
                n <<= 6;
            } else {
                let v = valor(b).ok_or_else(|| format!("carácter base64 inválido: {b}"))?;
                n = (n << 6) | u32::from(v);
            }
        }
        out.push((n >> 16) as u8);
        if relleno < 2 {
            out.push((n >> 8) as u8);
        }
        if relleno < 1 {
            out.push(n as u8);
        }
    }
    Ok(out)
}

/// Codifica a base64 estándar con relleno `=`.
#[allow(dead_code)] // Solo lo usa el test de integración.
pub fn encode(data: &[u8]) -> String {
    let mut out = String::with_capacity(data.len().div_ceil(3) * 4);
    for grupo in data.chunks(3) {
        let b0 = u32::from(grupo[0]);
        let b1 = u32::from(*grupo.get(1).unwrap_or(&0));
        let b2 = u32::from(*grupo.get(2).unwrap_or(&0));
        let n = (b0 << 16) | (b1 << 8) | b2;
        out.push(ALFABETO[(n >> 18 & 63) as usize] as char);
        out.push(ALFABETO[(n >> 12 & 63) as usize] as char);
        out.push(if grupo.len() > 1 {
            ALFABETO[(n >> 6 & 63) as usize] as char
        } else {
            '='
        });
        out.push(if grupo.len() > 2 {
            ALFABETO[(n & 63) as usize] as char
        } else {
            '='
        });
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip() {
        for datos in [&b""[..], b"f", b"fo", b"foo", b"foob", b"fooba", b"foobar", b"\x00\xff\x10\x80"] {
            let cod = encode(datos);
            assert_eq!(decode(&cod).unwrap(), datos, "roundtrip de {datos:?}");
        }
        assert_eq!(encode(b"hola CSG"), "aG9sYSBDU0c=");
        assert_eq!(decode("aG9sYSBDU0c=").unwrap(), b"hola CSG");
    }

    #[test]
    fn rechaza_invalido() {
        assert!(decode("abc").is_err()); // longitud no múltiplo de 4
        assert!(decode("a=== ").is_err());
        assert!(decode("a!b=").is_err());
    }
}
