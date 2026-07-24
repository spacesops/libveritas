# libveritas Trust Graph

A small JS visualizer for the `InspectReport` produced by
`Veritas.inspectProof()` (wasm) or `libveritas::inspect::inspect()` (Rust,
behind the `inspect` feature).

Enter a zone (e.g. `alice@bitcoin`) and it draws that handle's authentication
chain as a **vertical, DNSViz-style trust graph** — grouped into zone boxes,
flowing from the Bitcoin anchor down to the handle:

```
   Bitcoin anchor        (spaces_root · nums_root)
        │ commits
   @bitcoin  space        (SpaceOut · commitment · ZK receipt · delegate)
        │ commits handles tree
   alice@bitcoin handle   (HandleOut · key rotation)
```

The thick teal spine is the chain of trust; thin edges are supporting proofs.
Each epoch's ZK status is explicit: a **genesis** (first) epoch commits its
handles with **no ZK required**, while later epochs show the `fold`/`step`
receipt that proves the transition. Handle nodes are colored by sovereignty
(sovereign = solid spine, pending = dashed spine); a temporary handle is drawn
as a dashed **HandleOut absent** node with the delegate signing it and a ∅ on
the epoch edge that excludes it.

Click any proof node to drill into its **binary-radix path**: root → branch
bits → the leaf, with each pruned sibling shown as a *hash node* (the same
shape as the trie figure in the spaces paper). An inclusion lands on the
target key; an exclusion lands on a different key (or an empty slot), proving
absence.

The trie also renders the **key in binary**: a `key bits` line spells out the
queried key's discriminating prefix, with each node's branch bit highlighted
and its compressed-prefix bits muted. A node that **compresses a path** (a
radix-tree prefix of more than the single branch bit) is drawn with a dashed
ring and a `⊐ <bits>` chip showing exactly which bits it consumes — so you can
see where the trie collapses long single-child runs. Structural only — the
verifier is authoritative.

No build step. Pure ESM. Drop the two files into a page and call one function.

## Usage

```html
<link rel="stylesheet" href="./style.css" />
<div id="trust"></div>
<script type="module">
  import { renderInspectReport } from './visualizer.js';
  const report = await fetch('./inspect.json').then((r) => r.json());
  renderInspectReport(document.getElementById('trust'), report);
</script>
```

Generate the JSON from a Spaces message and anchors (the wasm build must enable
the `inspect` feature):

```js
import init, { Veritas, Anchors, Message } from '@spacesprotocol/libveritas';

await init();
const veritas = new Veritas(new Anchors(anchorsJson));
const msg = new Message(messageBytes);
const report = veritas.inspectProof(msg); // plain JS object
renderInspectReport(document.getElementById('trust'), report);
```

Or in Rust:

```rust
use libveritas::{Veritas, inspect::inspect, msg::Message};

let report = inspect(&veritas, &msg)?;
let json = serde_json::to_string(&report)?;
```

## Demo

```sh
cd examples/js-visualizer
python3 -m http.server 8123
# open http://localhost:8123/
```

Two fixtures ship with the demo:

- **kitchen-sink** (`sample-kitchen.json`) — a delegated space with nine zones
  across three epochs: a genesis batch (no ZK), a mid epoch (covered
  recursively by the tip receipt), and the tip epoch (receipt in message).
  Exercises sovereign / pending / dependent handles, inclusion and exclusion
  proofs, delegate lookups, key rotation, and a `fold` receipt.
- **real STARK** (`sample-inspect.json`) — a single real proof
  (`sunny@test10000`) with a `step` receipt.

Regenerate them (requires the `inspect` feature):

```sh
cargo run -q --example inspect_kitchen -p libveritas --features inspect \
  > examples/js-visualizer/sample-kitchen.json
cargo run -q --example inspect_real -p libveritas --features inspect \
  > examples/js-visualizer/sample-inspect.json
```

## Report shape

```ts
type InspectReport = {
  anchor: {
    block_height: number;
    block_hash: string; // hex
    spaces_root: string;
    nums_root: string | null;
    anchor_hash: string;
  };
  zones: Array<Zone>;
};

type Zone = {
  handle: string; // "alice@bitcoin", "@bitcoin", "#222-2-2"
  kind: 'space' | 'numeric' | 'handle';
  parent?: string; // for handles, the parent space
  sovereignty?: 'sovereign' | 'pending' | 'dependent';
  receipt?: ReceiptInfo; // decoded (not verified) ZK receipt, parent zones
  records?: { owner?: RecordSummary; delegate?: RecordSummary };
  paths: Array<ProofPath>;
};

type ReceiptInfo = {
  kind: 'fold' | 'step';
  initial_root: string; // hex — the transition's starting state root
  final_root: string; // hex — the committed state root
  rolling_hash: string;
  policy_ok: boolean; // journal policy IDs match this build's FOLD/STEP image IDs
};

type RecordSummary = { seq: number; flags: number; canonical: string; handle: string };

type ProofPath = {
  tree: 'spaces_root' | 'nums_root' | 'handles_root';
  purpose:
    | 'space_utxo'
    | 'numeric_utxo'
    | 'commitment_tip'
    | 'commitment'
    | 'delegate_lookup' // parent's num_id → NumOut (may a delegate sign?)
    | 'key_rotation' // handle's genesis num_id → current key
    | 'handle_inclusion'
    | 'handle_exclusion';
  root: string; // hex
  key: string;
  resolution: 'included' | 'provably_excluded' | 'incomplete';
  provides_root?: 'handles_root'; // chains commitment → handles tree
  commitment?: CommitmentMeta; // present on commitment paths
  leaf?: {
    key: string;
    value_hash: string;
    value_kind: 'SpaceOut' | 'NumOut' | 'Commitment' | 'CommitmentTip' | 'HandleOut' | 'Unknown';
    spent?: boolean; // for a NumOut leaf: dormant (rebindable) — still resolves
    matched: boolean;
  };
  steps: Array<{
    depth: number;
    prefix_bit_len: number;
    prefix: string; // hex of compressed prefix bytes
    direction: 'left' | 'right';
    sibling_hash: string;
  }>;
};

type CommitmentMeta = {
  block_height: number;
  state_root: string; // hex — the committed handles-tree root for this epoch
  prev_root?: string; // hex — omitted for a genesis (first) commitment
  genesis: boolean; // true → committed with NO ZK receipt required
  directly_proven: boolean; // the message receipt's final_root equals state_root
};
```

Notes:

- `provably_excluded` is a **valid** verdict — a temporary-cert exclusion proof
  resolves this way, so it is styled as informational, not an error. Only
  `incomplete` (the proof is pruned where the walk needed to continue) reads as
  a problem.
- ZK usage is derivable from `CommitmentMeta`: `genesis` epochs need no proof;
  a non-genesis epoch is proven directly when `directly_proven`, otherwise a
  `fold` receipt at a newer epoch covers it recursively.

`inspectProof` does **not** verify ZK or signatures — pair with
`veritas.verify(msg)` if validation matters. The inspector is structural; the
verifier is authoritative.
