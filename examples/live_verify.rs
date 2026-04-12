/// Live verification of certs in data/certs/ against a running spaced instance.
///
/// 1. Fetches root anchors from the local spaced
/// 2. Reads certificate JSON files from data/certs/
/// 3. Requests on-chain proofs via the buildchainproof RPC
/// 4. Builds and verifies a Message
///
/// Run: cargo run --release --bin live-verify

use base64::engine::general_purpose::STANDARD as BASE64;
use base64::Engine;
use libveritas::builder::MessageBuilder;
use libveritas::cert::{Certificate, NumsSubtree, SpacesSubtree};
use libveritas::msg::{ChainProof, QueryContext};
use libveritas::Veritas;
use serde::Deserialize;
use spacedb::subtree::SubTree;
use spacedb::Sha256Hasher;
use spaces_nums::RootAnchor;
use spaces_protocol::constants::ChainAnchor;
use std::fs;

const SPACED_URL: &str = "http://127.0.0.1:7224";
const SPACED_CREDS: &str = "testuser:SomeRisk84";

fn auth_header() -> String {
    format!("Basic {}", BASE64.encode(SPACED_CREDS))
}

#[derive(Deserialize)]
struct RpcResponse<T> {
    result: Option<T>,
    error: Option<serde_json::Value>,
}

#[derive(Deserialize)]
struct ChainProofResult {
    block: ChainAnchor,
    #[serde(deserialize_with = "deser_b64")]
    spaces_proof: Vec<u8>,
    #[serde(deserialize_with = "deser_b64")]
    ptrs_proof: Vec<u8>,
}

fn deser_b64<'de, D: serde::Deserializer<'de>>(d: D) -> Result<Vec<u8>, D::Error> {
    let s = String::deserialize(d)?;
    BASE64.decode(&s).map_err(serde::de::Error::custom)
}

fn main() {
    // ── 1. Fetch anchors ───────────────────────────────────────────────
    println!("Fetching anchors from {}/root-anchors.json ...", SPACED_URL);
    let anchors: Vec<RootAnchor> = ureq::get(&format!("{}/root-anchors.json", SPACED_URL))
        .set("Authorization", &auth_header())
        .call()
        .expect("failed to fetch anchors")
        .into_json()
        .expect("failed to parse anchors");

    println!(
        "  {} anchors (height {} .. {})",
        anchors.len(),
        anchors.last().map(|a| a.block.height).unwrap_or(0),
        anchors.first().map(|a| a.block.height).unwrap_or(0),
    );

    fs::write(
        "data/anchors.json",
        serde_json::to_string(&anchors).unwrap(),
    )
    .unwrap();
    println!("  Saved to data/anchors.json");

    // ── 2. Read certs ──────────────────────────────────────────────────
    println!("\nReading certs from data/certs/ ...");
    let mut builder = MessageBuilder::new();

    for entry in fs::read_dir("data/certs").expect("data/certs not found") {
        let path = entry.unwrap().path();
        if path.extension().map_or(true, |e| e != "json") {
            continue;
        }

        let content: serde_json::Value =
            serde_json::from_str(&fs::read_to_string(&path).unwrap()).unwrap();

        let root = Certificate::from_slice(
            &BASE64
                .decode(content["root_cert"].as_str().unwrap())
                .unwrap(),
        )
        .unwrap();
        let handle = Certificate::from_slice(
            &BASE64
                .decode(content["handle_cert"].as_str().unwrap())
                .unwrap(),
        )
        .unwrap();

        println!(
            "  {} : root={}, handle={} (leaf={}, temp={})",
            path.file_name().unwrap().to_string_lossy(),
            root.subject,
            handle.subject,
            handle.is_leaf(),
            handle.is_temporary(),
        );

        builder.add_cert(root);
        builder.add_cert(handle);
    }

    // ── 3. Build chain proof via RPC ───────────────────────────────────
    let request = builder.chain_proof_request();
    println!(
        "\nRequesting chain proof ({} space keys, {} num keys) ...",
        request.spaces.len(),
        request.nums.len()
    );

    let rpc_body = serde_json::json!({
        "jsonrpc": "2.0",
        "method": "buildchainproof",
        "params": [request, true],
        "id": 1
    });

    let resp: RpcResponse<ChainProofResult> = ureq::post(SPACED_URL)
        .set("Content-Type", "application/json")
        .set("Authorization", &auth_header())
        .send_json(&rpc_body)
        .expect("failed to call buildchainproof")
        .into_json()
        .expect("failed to parse chain proof result");

    if let Some(err) = &resp.error {
        eprintln!("RPC error: {}", err);
        std::process::exit(1);
    }

    let proof = resp.result.expect("missing result in RPC response");
    println!(
        "  Chain proof at height {} (hash {}...)",
        proof.block.height,
        &hex::encode(proof.block.hash)[..16],
    );

    // ── 4. Build and verify message ────────────────────────────────────
    let chain = ChainProof {
        anchor: proof.block,
        spaces: SpacesSubtree(SubTree::<Sha256Hasher>::from_slice(&proof.spaces_proof).unwrap()),
        nums: NumsSubtree(SubTree::<Sha256Hasher>::from_slice(&proof.ptrs_proof).unwrap()),
    };

    let msg = builder.build(chain).expect("failed to build message");

    println!("\nVerifying ...");
    let veritas = Veritas::new()
        .with_anchors(anchors)
        .expect("invalid anchors");

    let ctx = QueryContext::new();
    let result = veritas.verify(&ctx, msg).expect("verification failed");

    println!("\nVerified {} zones:", result.zones.len());
    for z in &result.zones {
        println!("  {} -> {} (anchor height {})", z.handle, z.sovereignty, z.anchor);

        if let libveritas::ProvableOption::Exists { value } = &z.commitment {
            println!(
                "    commitment: block {}, root {}",
                value.onchain.block_height,
                hex::encode(value.onchain.state_root),
            );
        }
        if let libveritas::ProvableOption::Exists { value } = &z.delegate {
            println!(
                "    delegate: spk {}...",
                hex::encode(&value.script_pubkey.as_bytes()[..8]),
            );
        }
    }

    // ── 5. Save message for offline replay ─────────────────────────────
    let msg_bytes = result.message.to_bytes();
    fs::write("data/message.bin", &msg_bytes).unwrap();
    println!("\nSaved message.bin ({} bytes)", msg_bytes.len());

    println!("\nDone.");
}
