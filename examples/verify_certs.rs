/// Demonstrates end-to-end certificate verification in dev mode.
///
/// 1. Simulates a chain with space "rad" and handles "user", "other"
/// 2. Commits and finalizes handles, then exports certs as JSON to data/certs/
/// 3. Exports anchors + message to data/
/// 4. Reads everything back from disk and verifies independently
///
/// Run: cargo run --release --bin verify-certs

use base64::engine::general_purpose::STANDARD as BASE64;
use base64::Engine;
use libveritas::cert::Certificate;
use libveritas::msg::QueryContext;
use libveritas::Veritas;
use libveritas_testutil::fixture::{ChainState, Fixture, FixtureRunner};
use std::fs;
use std::path::Path;

fn main() {
    let certs_dir = Path::new("data/certs");
    fs::create_dir_all(certs_dir).unwrap();

    // ── Step 1: Build simulated chain ──────────────────────────────────
    println!("=== Generating scenario: @rad with user, other ===\n");

    let mut state = ChainState::new();
    let fixture = Fixture::new("@rad")
        .stage(&["user", "other"])
        .commit()
        .finalize();

    let mut runner = FixtureRunner::new(&mut state, fixture);
    runner.run(&mut state);
    state.anchors.push(state.chain.current_root_anchor());

    let bundle = runner.build_bundle();
    let msg = state.message(vec![bundle]);

    // ── Step 2: Verify to obtain zones and certificates ────────────────
    let veritas = state.veritas();
    let ctx = QueryContext::new();
    let result = veritas
        .verify_with_options(&ctx, msg, libveritas::VERIFY_DEV_MODE)
        .expect("fixture verification failed");

    println!("Verified {} zones:", result.zones.len());
    for z in &result.zones {
        println!("  {} -> {}", z.handle, z.sovereignty);
    }

    // ── Step 3: Export certs, anchors, message to data/ ────────────────
    let certs: Vec<Certificate> = result.certificates().collect();
    let root_cert = certs.iter().find(|c| !c.is_leaf()).expect("root cert");
    let root_b64 = BASE64.encode(root_cert.to_bytes());

    for cert in certs.iter().filter(|c| c.is_leaf()) {
        let cert_json = serde_json::json!({
            "root_cert": root_b64,
            "handle_cert": BASE64.encode(cert.to_bytes()),
        });
        let filename = format!("{}.cert.json", cert.subject);
        let path = certs_dir.join(&filename);
        fs::write(&path, serde_json::to_string_pretty(&cert_json).unwrap()).unwrap();
        println!("\nWrote {}", path.display());
    }

    let mut anchors = state.anchors.clone();
    anchors.reverse();
    fs::write("data/anchors.json", serde_json::to_string_pretty(&anchors).unwrap()).unwrap();
    println!("Wrote data/anchors.json");

    let msg_bytes = result.message.to_bytes();
    fs::write("data/message.bin", &msg_bytes).unwrap();
    println!("Wrote data/message.bin ({} bytes)", msg_bytes.len());

    // ── Step 4: Read everything back from disk and re-verify ───────────
    println!("\n=== Reading back from disk and verifying ===\n");

    let anchors_json = fs::read_to_string("data/anchors.json").unwrap();
    let anchors = serde_json::from_str(&anchors_json).unwrap();
    let veritas = Veritas::new().with_anchors(anchors).expect("valid anchors");
    println!(
        "Loaded anchors (range {} .. {})",
        veritas.oldest_anchor(),
        veritas.newest_anchor()
    );

    let msg_bytes = fs::read("data/message.bin").unwrap();
    let msg = libveritas::msg::Message::from_slice(&msg_bytes).unwrap();
    println!("Loaded message.bin ({} bytes)", msg_bytes.len());

    let ctx = QueryContext::new();
    let result = veritas
        .verify_with_options(&ctx, msg, libveritas::VERIFY_DEV_MODE)
        .expect("re-verification failed");

    println!("\nRe-verified {} zones:", result.zones.len());
    for z in &result.zones {
        println!("  {} -> {}", z.handle, z.sovereignty);
    }

    // ── Step 5: Inspect cert files ─────────────────────────────────────
    println!("\n=== Inspecting cert files ===\n");

    for entry in fs::read_dir(certs_dir).unwrap() {
        let entry = entry.unwrap();
        let path = entry.path();
        if path.extension().map_or(true, |e| e != "json") {
            continue;
        }

        let content: serde_json::Value =
            serde_json::from_str(&fs::read_to_string(&path).unwrap()).unwrap();
        let root_bytes = BASE64
            .decode(content["root_cert"].as_str().unwrap())
            .unwrap();
        let handle_bytes = BASE64
            .decode(content["handle_cert"].as_str().unwrap())
            .unwrap();

        let root = Certificate::from_slice(&root_bytes).unwrap();
        let handle = Certificate::from_slice(&handle_bytes).unwrap();

        println!("{}:", path.file_name().unwrap().to_string_lossy());
        println!(
            "  root cert:   subject={}, leaf={}, temporary={}",
            root.subject,
            root.is_leaf(),
            root.is_temporary()
        );
        println!(
            "  handle cert: subject={}, leaf={}, temporary={}, final={}",
            handle.subject,
            handle.is_leaf(),
            handle.is_temporary(),
            handle.is_final()
        );
    }

    println!("\nDone.");
}
