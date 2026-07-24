//! Dump the JSON proof inspection of the kitchen-sink fixture.
//!
//! Unlike `inspect_real` (a single real STARK proof, one handle), this
//! exercises the full report surface: a delegated space, multiple handles,
//! temporary (dependent) handles, and a ZK receipt — useful for developing
//! the visualizer against every field.
//!
//! Usage (from repo root):
//!   cargo run -q --example inspect_kitchen -p libveritas --features inspect \
//!     > examples/js-visualizer/sample-kitchen.json

use libveritas::inspect::inspect;
use libveritas_testutil::fixture::{ChainState, FixtureRunner, kitchen_sink};

fn main() {
    let mut state = ChainState::new();
    let fixture = kitchen_sink();
    let mut runner = FixtureRunner::new(&mut state, fixture);
    runner.run(&mut state);

    let bundle = runner.build_bundle();
    let msg = state.message(vec![bundle]);
    let veritas = state.veritas();

    let report = inspect(&veritas, &msg).expect("inspect");
    println!(
        "{}",
        serde_json::to_string_pretty(&report).expect("serialize report")
    );
}
