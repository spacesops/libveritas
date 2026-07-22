//! Dump the JSON proof inspection of a real-fixture message.
//!
//! Usage (from repo root):
//!   cargo run --example inspect_real -p libveritas
//!
//! Pipe to a file:
//!   cargo run -q --example inspect_real -p libveritas > /tmp/inspect.json

use std::fs;

use libveritas::Veritas;
use libveritas::inspect::{ZoneKind, inspect};
use libveritas::msg::Message;
use spaces_nums::RootAnchor;

fn main() {
    let anchors_json =
        fs::read_to_string("examples/fixture/anchors-real.json").expect("anchors-real.json");
    let anchors: Vec<RootAnchor> = serde_json::from_str(&anchors_json).expect("parse anchors");
    let msg_bytes = fs::read("examples/fixture/message-real.bin").expect("message-real.bin");
    let msg = Message::from_slice(&msg_bytes).expect("parse message");
    let veritas = Veritas::new()
        .with_anchors(anchors)
        .expect("anchors sorted");

    let report = inspect(&veritas, &msg).expect("inspect");
    let json = serde_json::to_string_pretty(&report).expect("serialize");
    println!("{json}");

    eprintln!(
        "\n-- summary -- {} bytes, {} zones",
        json.len(),
        report.zones.len()
    );
    for z in &report.zones {
        let kind = match z.kind {
            ZoneKind::Space => "Space",
            ZoneKind::Numeric => "Numeric",
            ZoneKind::Handle => "Handle",
        };
        eprintln!("  {} [{}] paths={}", z.handle, kind, z.paths.len());
        for p in &z.paths {
            eprintln!(
                "    {:?}/{:?} steps={} matched={}",
                p.tree,
                p.purpose,
                p.steps.len(),
                p.leaf.as_ref().map(|l| l.matched).unwrap_or(false)
            );
        }
    }
}
