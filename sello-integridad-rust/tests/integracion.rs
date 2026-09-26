//! Tests de integración del Sello de Integridad Técnica
//!
//! Estas pruebas verifican el comportamiento completo del sistema
//! en escenarios realistas de uso.

use sello_integridad::*;

#[test]
fn test_flujo_completo_ingenieria() {
    // Simula el escenario del ejemplo Python: ingeniero sellando versiones de planos

    let ingeniero = Firmante::generar("Arturo (diseñador)");
    let notario = Notario::nuevo("ATL Edge - Sello de Integridad");

    let proyecto = "smart-token-prod-planos";
    notario.registrar_firmante_autorizado(proyecto, ingeniero.clave_publica_hex());

    // Versión 1 del plano
    let version_1 = b"PLANO_v1.dwg :: geometria original, revision A";
    let (evento1, firma1) = ingeniero
        .crear_evento_archivo(version_1, proyecto, Some("plano-v1".to_string()))
        .unwrap();

    let sello1 = notario
        .notarizar_transaccion(
            &serde_json::to_value(&evento1).unwrap(),
            &firma1,
            &ingeniero.clave_publica(),
            proyecto,
        )
        .unwrap();

    assert!(sello1.aceptado);
    assert_eq!(sello1.razon, "atestado");

    // Versión 2
    let version_2 = b"PLANO_v2.dwg :: geometria original, revision B - ajuste tolerancia";
    let (evento2, firma2) = ingeniero
        .crear_evento_archivo(version_2, proyecto, Some("plano-v2".to_string()))
        .unwrap();

    let sello2 = notario
        .notarizar_transaccion(
            &serde_json::to_value(&evento2).unwrap(),
            &firma2,
            &ingeniero.clave_publica(),
            proyecto,
        )
        .unwrap();

    assert!(sello2.aceptado);

    // Verificación de encadenamiento
    assert!(sello2.verificar_encadenamiento(&sello1.cuerpo_hash));

    // Verificación independiente (simulando perito externo)
    let reporte1 = verificar_sello(&sello1, &notario.clave_publica_hex(), None).unwrap();
    let reporte2 = verificar_sello(
        &sello2,
        &notario.clave_publica_hex(),
        Some(&sello1.cuerpo_hash),
    )
    .unwrap();

    assert!(reporte1.todo_valido);
    assert!(reporte2.todo_valido);
}

#[test]
fn test_ataque_suplantacion_fallido() {
    let notario = Notario::nuevo("Test");
    let ingeniero = Firmante::generar("Legítimo");
    let atacante = Firmante::generar("Atacante");

    let proyecto = "p1";
    notario.registrar_firmante_autorizado(proyecto, ingeniero.clave_publica_hex());

    // El atacante intenta sellar con SU propia clave (no registrada)
    let contenido = b"contenido del plano";
    let (evento_malicioso, firma_atacante) = atacante
        .crear_evento_archivo(contenido, proyecto, Some("fraude-1".to_string()))
        .unwrap();

    let sello_fraude = notario
        .notarizar_transaccion(
            &serde_json::to_value(&evento_malicioso).unwrap(),
            &firma_atacante,
            &atacante.clave_publica(),
            proyecto,
        )
        .unwrap();

    // Debe ser rechazado
    assert!(!sello_fraude.aceptado);
    assert_eq!(sello_fraude.razon, "firmante_no_autorizado");

    // El sistema sigue funcionando para el legítimo
    let (evento_legit, firma_legit) = ingeniero
        .crear_evento_archivo(contenido, proyecto, Some("legit-1".to_string()))
        .unwrap();

    let sello_legit = notario
        .notarizar_transaccion(
            &serde_json::to_value(&evento_legit).unwrap(),
            &firma_legit,
            &ingeniero.clave_publica(),
            proyecto,
        )
        .unwrap();

    assert!(sello_legit.aceptado);
}

#[test]
fn test_propiedad_no_bloqueo() {
    // Verifica la propiedad central: N ataques no bloquean eventos legítimos

    let notario = Notario::nuevo("Test");
    let ingeniero = Firmante::generar("Ingeniero");

    notario.registrar_firmante_autorizado("p1", ingeniero.clave_publica_hex());

    // 100 ataques consecutivos
    for i in 0..100 {
        let atacante = Firmante::generar(format!("atacante-{}", i));
        let (evento, firma) = atacante
            .crear_evento_archivo(
                format!("fraude-{}", i).as_bytes(),
                "p1",
                Some(format!("ataque-{}", i)),
            )
            .unwrap();

        let sello = notario
            .notarizar_transaccion(
                &serde_json::to_value(&evento).unwrap(),
                &firma,
                &atacante.clave_publica(),
                "p1",
            )
            .unwrap();

        assert!(!sello.aceptado);
    }

    // Evento legítimo inmediatamente después
    let (evento_legit, firma_legit) = ingeniero
        .crear_evento_archivo(b"contenido legitimo", "p1", Some("evt-final".to_string()))
        .unwrap();

    let sello_legit = notario
        .notarizar_transaccion(
            &serde_json::to_value(&evento_legit).unwrap(),
            &firma_legit,
            &ingeniero.clave_publica(),
            "p1",
        )
        .unwrap();

    assert!(sello_legit.aceptado);
}

#[test]
fn test_deteccion_alteracion_posterior() {
    let notario = Notario::nuevo("Test");
    let ingeniero = Firmante::generar("Test");

    notario.registrar_firmante_autorizado("p1", ingeniero.clave_publica_hex());

    let contenido_original = b"contenido original del plano";
    let (evento, firma) = ingeniero
        .crear_evento_archivo(contenido_original, "p1", Some("e1".to_string()))
        .unwrap();

    let sello = notario
        .notarizar_transaccion(
            &serde_json::to_value(&evento).unwrap(),
            &firma,
            &ingeniero.clave_publica(),
            "p1",
        )
        .unwrap();

    // Verificar que el contenido no fue alterado
    let hash_actual = sello_integridad::crypto::to_hex(&sello_integridad::crypto::sha3_256(contenido_original));
    assert_eq!(hash_actual, sello.hash_contenido);

    // Si el contenido cambia, el hash no coincide
    let contenido_modificado = b"contenido modificado del plano";
    let hash_modificado = sello_integridad::crypto::to_hex(&sello_integridad::crypto::sha3_256(contenido_modificado));
    assert_ne!(hash_modificado, sello.hash_contenido);
}

#[test]
fn test_verificacion_independiente_sin_software_original() {
    // Simula verificación por un tercero que NO tiene acceso al notario

    let notario = Notario::nuevo("Test");
    let ingeniero = Firmante::generar("Test");

    notario.registrar_firmante_autorizado("p1", ingeniero.clave_publica_hex());

    let contenido = b"documento importante";
    let (evento, firma) = ingeniero
        .crear_evento_archivo(contenido, "p1", Some("doc-1".to_string()))
        .unwrap();

    let sello = notario
        .notarizar_transaccion(
            &serde_json::to_value(&evento).unwrap(),
            &firma,
            &ingeniero.clave_publica(),
            "p1",
        )
        .unwrap();

    // Exportar la clave pública del notario (publicación)
    let notario_pub_hex = notario.clave_publica_hex();

    // Serializar el sello (para enviarlo al verificador)
    let sello_json = sello.a_json().unwrap();

    // El verificador (que no tiene el notario) puede verificar:
    let sello_recibido = Sello::desde_json(&sello_json).unwrap();
    let reporte = verificar_sello(&sello_recibido, &notario_pub_hex, None).unwrap();

    assert!(reporte.todo_valido);
    assert!(reporte.checks.cuerpo_no_alterado);
    assert!(reporte.checks.firma_notario_valida);
}

#[test]
fn test_exportar_cadena() {
    let notario = Notario::nuevo("Test Export");
    let ingeniero = Firmante::generar("Test");

    notario.registrar_firmante_autorizado("p1", ingeniero.clave_publica_hex());

    // Emitir varios sellos
    for i in 0..5 {
        let (evento, firma) = ingeniero
            .crear_evento_archivo(format!("content-{}", i).as_bytes(), "p1", Some(format!("e{}", i)))
            .unwrap();

        notario
            .notarizar_transaccion(
                &serde_json::to_value(&evento).unwrap(),
                &firma,
                &ingeniero.clave_publica(),
                "p1",
            )
            .unwrap();
    }

    // Exportar y verificar estructura
    let cadena_json = notario.exportar_cadena().unwrap();
    let parsed: serde_json::Value = serde_json::from_str(&cadena_json).unwrap();

    assert_eq!(parsed["notario"], "Test Export");
    assert_eq!(parsed["total_sellos"], 5);
    assert!(parsed["sellos"].is_array());
}
