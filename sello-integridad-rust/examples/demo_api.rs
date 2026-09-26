//! Demostración de la API pública de sello_integridad v1.1
use sello_integridad::{
    verificar_sello, ClaveMaestraDanio, Firmante, Notario, NotarioProtegido, PoliticaConatus,
    SelloError,
};

fn main() {
    println!("=== Demo API sello_integridad v{} ===\n", sello_integridad::VERSION);

    // 1. Flujo clásico (Notario sin protección)
    println!("[1] Flujo clásico Notario + Firmante");
    let ingeniero = Firmante::generar("Arturo");
    let notario = Notario::nuevo("Empresa Demo");
    notario.registrar_firmante_autorizado("proyecto-x", ingeniero.clave_publica_hex());

    let contenido = b"plano_v1.dwg";
    let (evento, firma) = ingeniero
        .crear_evento_archivo(contenido, "proyecto-x", Some("evt-1".into()))
        .expect("crear evento");
    let sello = notario
        .sellar_evento(&evento, &firma, &ingeniero.clave_publica())
        .expect("sellar");
    assert!(sello.aceptado);
    println!("  Sello aceptado: evento_id={}, cuerpo_hash={}...", sello.evento_id, &sello.cuerpo_hash[..16]);

    let reporte = verificar_sello(&sello, &notario.clave_publica_hex(), None).expect("verificar");
    assert!(reporte.todo_valido);
    println!("  Verificación independiente: OK\n");

    // 2. NotarioProtegido con conatus + AES-GCM/Argon2
    println!("[2] NotarioProtegido (conatus + ruptura)");
    let politica = PoliticaConatus {
        umbral_ruptura: 3,
        factor_endurecimiento: 1.6,
        retardo_base_ms: 0,
    };
    let master = ClaveMaestraDanio::generar();
    let np = NotarioProtegido::con_politica("Notario Protegido", politica, Some(master));
    let atacante = Firmante::generar("Atacante");
    // No se registra -> cada intento falla

    for i in 1..=3 {
        let (ev, fi) = atacante
            .crear_evento_archivo(b"ataque", "p1", Some(format!("atk-{i}")))
            .unwrap();
        let s = np.sellar_evento(&ev, &fi, &atacante.clave_publica()).unwrap();
        assert!(!s.aceptado);
        println!(
            "  Intento fallido {i}: razon={}, conatus={:.3}, rota={}",
            s.razon,
            np.conatus(),
            np.estructura_rota()
        );
    }
    assert!(np.estructura_rota());

    // Tras ruptura
    let (ev, fi) = atacante
        .crear_evento_archivo(b"mas", "p1", Some("atk-4".into()))
        .unwrap();
    match np.sellar_evento(&ev, &fi, &atacante.clave_publica()) {
        Err(SelloError::EstructuraRota) => println!("  Tras umbral: EstructuraRota (esperado)\n"),
        other => panic!("esperado EstructuraRota, got {:?}", other),
    }

    // 3. Éxito no sube conatus
    println!("[3] Sellado legítimo no altera conatus");
    let np2 = NotarioProtegido::con_politica(
        "OK",
        PoliticaConatus {
            umbral_ruptura: 10,
            factor_endurecimiento: 1.6,
            retardo_base_ms: 0,
        },
        None,
    );
    let leg = Firmante::generar("Legit");
    np2.registrar_firmante_autorizado("p1", leg.clave_publica_hex());
    let (ev, fi) = leg
        .crear_evento_archivo(b"ok", "p1", Some("ok-1".into()))
        .unwrap();
    let s = np2.sellar_evento(&ev, &fi, &leg.clave_publica()).unwrap();
    assert!(s.aceptado);
    assert!((np2.conatus() - 1.0).abs() < 1e-9);
    println!("  Sello legítimo OK, conatus permanece en {:.1}\n", np2.conatus());

    println!("=== API verificada correctamente ===");
}
