//! Demostración de la API pública: Firmante + NotarioProtegido
//! con conatus, AES-GCM y Argon2.

use sello_integridad::{
    verificar_sello, ClaveMaestraDanio, Firmante, NotarioProtegido, PoliticaConatus,
};

fn main() {
    println!("=== Demo Sello de Integridad + Protección CSG ===\n");

    let politica = PoliticaConatus {
        umbral_ruptura: 3,
        factor_endurecimiento: 1.6,
        retardo_base_ms: 0,
    };
    let master = ClaveMaestraDanio::generar();
    let notario = NotarioProtegido::con_politica("Empresa Demo", politica, Some(master));
    let ingeniero = Firmante::generar("Arturo");

    notario.registrar_firmante_autorizado("proyecto-x", ingeniero.clave_publica_hex());
    println!("Notario: {}", notario.nombre());
    println!("Firmante: {} ({})", ingeniero.nombre(), &ingeniero.clave_publica_hex()[..16]);
    println!("Conatus inicial: {:.2}\n", notario.conatus());

    // 1) Sellado legítimo
    let contenido = b"plano_v1.dwg - datos sensibles de ingenieria";
    let (evento, firma) = ingeniero
        .crear_evento_archivo(contenido, "proyecto-x", Some("evt-legit".into()))
        .expect("crear evento");
    let sello = notario
        .sellar_evento(&evento, &firma, &ingeniero.clave_publica())
        .expect("sellar");
    assert!(sello.aceptado);
    println!("[OK] Sello legítimo aceptado (evento_id={})", sello.evento_id);
    println!("     conatus tras éxito: {:.2}", notario.conatus());

    // 2) Verificación independiente
    let reporte = verificar_sello(&sello, &notario.clave_publica_hex(), None).expect("verificar");
    assert!(reporte.todo_valido);
    println!("[OK] Verificación independiente: todo_valido={}\n", reporte.todo_valido);

    // 3) Intentos fallidos hasta ruptura
    let atacante = Firmante::generar("Atacante");
    for i in 1..=3 {
        let (ev, sig) = atacante
            .crear_evento_archivo(b"basura", "proyecto-x", Some(format!("atk-{i}")))
            .unwrap();
        let s = notario
            .sellar_evento(&ev, &sig, &atacante.clave_publica())
            .unwrap();
        println!(
            "[FALLIDO {i}] aceptado={} razon={} conatus={:.2} rota={}",
            s.aceptado,
            s.razon,
            notario.conatus(),
            notario.estructura_rota()
        );
    }

    assert!(notario.estructura_rota());
    println!("\n[OK] Estructura rota tras umbral");

    // 4) Tras ruptura incluso el legítimo es rechazado
    let (ev2, sig2) = ingeniero
        .crear_evento_archivo(b"otro plano", "proyecto-x", Some("evt-post".into()))
        .unwrap();
    match notario.sellar_evento(&ev2, &sig2, &ingeniero.clave_publica()) {
        Err(e) => println!("[OK] Post-ruptura: error esperado -> {e}"),
        Ok(_) => panic!("no debería aceptar tras ruptura"),
    }

    let estado = notario.estado_proteccion();
    println!(
        "\nEstado protección: fallos={} damage_log_entries={} conatus={:.2}",
        estado.intentos_fallidos,
        estado.damage_log.len(),
        estado.conatus
    );
    println!("\n=== Demo finalizada correctamente ===");
}
