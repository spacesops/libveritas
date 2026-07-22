// libveritas InspectReport visualizer — DNSViz-style trust graph
//
// Enter a zone (e.g. "alice@bitcoin") and see how trust flows from the Bitcoin
// anchor down to that handle, drawn as a vertical node-link graph grouped into
// zone boxes — the same shape DNSViz uses for a DNSSEC authentication chain.
//
//   Bitcoin anchor  (spaces_root, nums_root)
//        │ commits
//   @bitcoin space  (SpaceOut · commitment · ZK receipt · delegate)
//        │ commits handles tree
//   alice@bitcoin   (HandleOut · key rotation)
//
// The thick teal spine is the chain of trust; thin edges are supporting
// proofs. A genesis epoch is marked "no ZK". Click any node for its merkle
// walk. Structural only — the verifier is authoritative.
//
// Usage:
//   import { renderInspectReport } from './visualizer.js';
//   const report = await fetch('./sample-inspect.json').then(r => r.json());
//   renderInspectReport(document.getElementById('root'), report);

const NS = 'http://www.w3.org/2000/svg';

// ── dom helpers ─────────────────────────────────────────────────────

function el(tag, attrs = {}, ...children) {
  const node = document.createElement(tag);
  applyAttrs(node, attrs);
  append(node, children);
  return node;
}

function s(tag, attrs = {}, ...children) {
  const node = document.createElementNS(NS, tag);
  for (const [k, v] of Object.entries(attrs)) {
    if (v == null || v === false) continue;
    if (k.startsWith('on') && typeof v === 'function') node.addEventListener(k.slice(2), v);
    else node.setAttribute(k, v);
  }
  append(node, children);
  return node;
}

function applyAttrs(node, attrs) {
  for (const [k, v] of Object.entries(attrs)) {
    if (k === 'class') node.className = v;
    else if (k === 'html') node.innerHTML = v;
    else if (k.startsWith('on') && typeof v === 'function') node.addEventListener(k.slice(2), v);
    else if (v !== false && v != null) node.setAttribute(k, v);
  }
}

function append(node, children) {
  for (const c of children) {
    if (c == null || c === false) continue;
    node.appendChild(typeof c === 'string' ? document.createTextNode(c) : c);
  }
}

function trunc(hex, head = 6, tail = 6) {
  if (!hex) return '';
  if (hex.length <= head + tail + 1) return hex;
  return `${hex.slice(0, head)}…${hex.slice(-tail)}`;
}

const ICON = {
  check:
    '<svg viewBox="0 0 16 16" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M3 8.5l3.2 3.2L13 5"/></svg>',
  absent:
    '<svg viewBox="0 0 16 16" fill="none" stroke="currentColor" stroke-width="1.6"><circle cx="8" cy="8" r="5.2"/><path d="M4.5 11.5l7-7" stroke-linecap="round"/></svg>',
  warn:
    '<svg viewBox="0 0 16 16" fill="none" stroke="currentColor" stroke-width="1.7" stroke-linecap="round" stroke-linejoin="round"><path d="M8 2.5L14.5 13.5H1.5z"/><path d="M8 6.5v3"/><circle cx="8" cy="11.6" r="0.4" fill="currentColor"/></svg>',
  chevron:
    '<svg viewBox="0 0 16 16" width="13" height="13" fill="none" stroke="currentColor" stroke-width="1.6" stroke-linecap="round" stroke-linejoin="round"><path d="M6 4l4 4-4 4"/></svg>',
};
function icon(name) {
  return el('span', { class: 'lvi-ico', html: ICON[name] || '' });
}

// ── label maps ──────────────────────────────────────────────────────

const TREE = {
  spaces_root: { label: 'spaces', swatch: 'lvi-swatch-spaces' },
  nums_root: { label: 'nums', swatch: 'lvi-swatch-nums' },
  handles_root: { label: 'handles', swatch: 'lvi-swatch-handles' },
};
const PURPOSE = {
  space_utxo: 'Space ownership',
  numeric_utxo: 'Numeric ownership',
  commitment_tip: 'Commitment tip',
  commitment: 'Epoch commitment',
  delegate_lookup: 'Delegate lookup',
  key_rotation: 'Key rotation',
  handle_inclusion: 'Handle inclusion',
  handle_exclusion: 'Handle exclusion',
};
const PURPOSE_HINT = {
  space_utxo: 'who controls this space on-chain',
  numeric_utxo: 'who controls this numeric on-chain',
  commitment_tip: 'the latest committed handles-tree root',
  commitment: 'dates this epoch and anchors its handles tree',
  delegate_lookup: 'whether a delegate may sign for this space',
  key_rotation: 'the handle’s current key (may differ from genesis)',
  handle_inclusion: 'the handle is committed in the operator tree',
  handle_exclusion: 'the handle is provably absent (temporary cert)',
};
const VERDICT = {
  included: { label: 'included', cls: 'included', ico: 'check' },
  provably_excluded: { label: 'excluded', cls: 'excluded', ico: 'absent' },
  incomplete: { label: 'incomplete', cls: 'incomplete', ico: 'warn' },
};
const SOV = {
  sovereign: { label: 'sovereign', cls: 'sovereign' },
  pending: { label: 'pending', cls: 'pending' },
  dependent: { label: 'dependent', cls: 'dependent' },
};

function renderHandle(name, cls = 'lvi-handle') {
  const wrap = el('span', { class: cls });
  if (name.startsWith('@')) {
    wrap.appendChild(el('span', { class: 'lvi-handle-at' }, '@'));
    wrap.appendChild(el('span', { class: 'lvi-handle-space' }, name.slice(1)));
  } else if (name.startsWith('#')) {
    wrap.appendChild(el('span', { class: 'lvi-handle-space' }, name));
  } else if (name.includes('@')) {
    const [p, x] = name.split('@');
    wrap.appendChild(el('span', {}, p));
    wrap.appendChild(el('span', { class: 'lvi-handle-at' }, '@'));
    wrap.appendChild(el('span', { class: 'lvi-handle-suffix' }, x));
  } else wrap.appendChild(document.createTextNode(name));
  return wrap;
}
function sovDot(sov) {
  return el('span', { class: `lvi-sov-dot lvi-sov-${sov || 'none'}`, title: sov || 'unknown' });
}

// ═══════════════════════════════════════════════════════════════════
// GRAPH — vertical authentication chain for one zone
// ═══════════════════════════════════════════════════════════════════

// layout grid (COL values are the left edge x of each node box)
const COL = { left: 34, mid: 322, right: 610 };
const NODE_W = 182;
const NODE_H = 54;
const BOX_PAD = 22;

// Build the node/edge spec for a selected zone.
function graphSpec(zone, parentZone, anchor) {
  const byPurpose = {};
  for (const p of zone.paths) byPurpose[p.purpose] = p;

  const isHandle = !!zone.parent;
  // A temporary handle is proven ABSENT from the epoch and authorized by the
  // delegate's signature (it is never committed).
  const handleP = byPurpose.handle_inclusion || byPurpose.handle_exclusion;
  const excluded = !!handleP && handleP.resolution !== 'included';
  // A final handle whose epoch is not yet finalized is "pending" — its chain
  // of trust is tentative, drawn with dashed spine edges.
  const pending = zone.sovereignty === 'pending';
  const receipt = parentZone ? parentZone.receipt : zone.receipt;
  const commitPath = byPurpose.commitment;
  const commitMeta = commitPath ? commitPath.commitment : null;
  const genesis = commitMeta && commitMeta.genesis;

  const nodes = [];
  const edges = [];
  const add = (n) => (nodes.push(n), n);

  // rows (generous vertical gaps so edges + labels have room)
  const yAnchor = 46;
  const ySpace = 224;
  const yZk = 344;
  const yHandle = isHandle ? 520 : ySpace;

  // ── anchor box ──
  const spacesRoot = add({
    id: 'spaces_root', col: 'left', y: yAnchor, box: 'anchor',
    label: 'spaces root', value: trunc(anchor.spaces_root), full: anchor.spaces_root, kind: 'root',
  });
  const numsRoot = anchor.nums_root
    ? add({
        id: 'nums_root', col: 'mid', y: yAnchor, box: 'anchor',
        label: 'nums root', value: trunc(anchor.nums_root), full: anchor.nums_root, kind: 'root',
      })
    : null;

  // ── space box ──
  const ownerPath = byPurpose.space_utxo || byPurpose.numeric_utxo;
  const spaceOut = add({
    id: 'space_out', col: 'left', y: ySpace, box: 'space',
    label: byPurpose.numeric_utxo ? 'numeric UTXO' : 'space UTXO',
    value: 'owner', kind: 'utxo', path: ownerPath,
  });
  edges.push({ from: 'spaces_root', to: 'space_out', kind: 'thin' });

  let commitNode = null;
  if (commitPath) {
    commitNode = add({
      id: 'commitment', col: 'mid', y: ySpace, box: 'space',
      label: 'commitment',
      value: commitMeta ? `epoch #${Number(commitMeta.block_height).toLocaleString()}` : 'epoch',
      kind: 'commitment', path: commitPath, genesis, pending,
    });
    if (numsRoot)
      edges.push({ from: 'nums_root', to: 'commitment', kind: pending ? 'pending' : 'thick', label: 'commits' });
  }

  // delegate (space-level)
  const delPath = byPurpose.delegate_lookup;
  let signerId = 'space_out'; // owner signs temporary handles unless a delegate exists
  if (delPath && delPath.resolution === 'included') {
    add({
      id: 'delegate', col: 'right', y: ySpace, box: 'space',
      label: 'delegate',
      // The delegate only authorizes temporary handles — never committed ones.
      value: excluded ? 'signs this handle' : 'signs temp handles',
      kind: 'delegate', path: delPath,
    });
    if (numsRoot) edges.push({ from: 'nums_root', to: 'delegate', kind: 'thin' });
    signerId = 'delegate';
  }

  // ZK receipt / genesis marker (proves the commitment transition)
  if (commitNode) {
    // Placed in the left column so it never sits on the commitment→handle
    // spine (which must stay clear for the exclusion badge).
    if (genesis) {
      add({
        id: 'zk', col: 'left', y: yZk, box: 'space',
        label: 'genesis epoch', value: 'no ZK required', kind: 'genesis',
      });
      edges.push({ from: 'zk', to: 'commitment', kind: 'proof', label: 'direct' });
    } else if (receipt) {
      const direct = commitMeta && commitMeta.directly_proven;
      add({
        id: 'zk', col: 'left', y: yZk, box: 'space',
        label: `${receipt.kind} receipt`,
        value: direct ? 'proves this epoch' : 'covers recursively',
        kind: 'zk', receipt,
      });
      edges.push({ from: 'zk', to: 'commitment', kind: 'proof', label: 'proves' });
    }
  }

  // ── handle box ──
  if (isHandle) {
    add({
      id: 'handle_out', col: 'mid', y: yHandle, box: 'handle',
      label: excluded ? 'handle absent' : 'HandleOut',
      value: zone.handle.split('@')[0],
      kind: 'handle', path: handleP, sov: zone.sovereignty, excluded,
    });

    if (excluded) {
      // Temporary handle: proven ABSENT from the latest epoch, and authorized
      // by the delegate's (or owner's) signature — draw both relationships.
      if (commitNode)
        edges.push({ from: 'commitment', to: 'handle_out', kind: 'excluded', label: 'excluded from' });
      edges.push({ from: signerId, to: 'handle_out', kind: 'sign', label: 'signs' });
    } else {
      // Committed handle: flows through the epoch's handles tree. Dashed when
      // the epoch is not yet finalized (pending).
      if (commitNode)
        edges.push({ from: 'commitment', to: 'handle_out', kind: pending ? 'pending' : 'thick', label: 'handles root' });

      const krPath = byPurpose.key_rotation;
      if (krPath) {
        add({
          id: 'key_rotation', col: 'right', y: yHandle, box: 'handle',
          label: 'key rotation', value: 'current key', kind: 'utxo', path: krPath,
        });
        edges.push({ from: 'handle_out', to: 'key_rotation', kind: 'thin', label: 'current key' });
      }
    }
  }

  // boxes (grouping rectangles)
  const boxes = [
    { id: 'anchor', label: `Bitcoin anchor · block #${Number(anchor.block_height).toLocaleString()}`, tone: 'anchor' },
    { id: 'space', label: `${parentZone ? parentZone.handle : zone.handle}  ·  space`, tone: 'space' },
  ];
  if (isHandle) boxes.push({ id: 'handle', label: `${zone.handle}  ·  handle`, tone: 'handle' });

  return { nodes, edges, boxes, isHandle };
}

function nodeXY(node) {
  return { x: COL[node.col] + NODE_W / 2, y: node.y + NODE_H / 2 };
}

function renderGraphSVG(zone, parentZone, anchor, onSelect, selectedNodeId) {
  const spec = graphSpec(zone, parentZone, anchor);
  const byId = Object.fromEntries(spec.nodes.map((n) => [n.id, n]));

  const width = COL.right + NODE_W + BOX_PAD;
  const maxY = Math.max(...spec.nodes.map((n) => n.y)) + NODE_H;
  const height = maxY + BOX_PAD;

  const svg = s('svg', {
    class: 'lvi-graph-svg',
    viewBox: `0 0 ${width} ${height}`,
    width: '100%',
    preserveAspectRatio: 'xMidYMin meet',
  });

  // arrowhead markers
  const defs = s('defs');
  for (const [id, color] of [
    ['ah-thick', 'var(--tree-nums)'],
    ['ah-thin', 'var(--border-strong)'],
    ['ah-proof', 'var(--ok)'],
    ['ah-absent', 'var(--absent)'],
    ['ah-sign', 'var(--accent)'],
  ]) {
    defs.appendChild(
      s('marker', { id, viewBox: '0 0 10 10', refX: 8, refY: 5, markerWidth: 7, markerHeight: 7, orient: 'auto-start-reverse' },
        s('path', { d: 'M0 0L10 5L0 10z', fill: color })),
    );
  }
  svg.appendChild(defs);

  // ── grouping boxes (behind everything) ──
  const boxG = s('g', { class: 'lvi-gbox-layer' });
  for (const box of spec.boxes) {
    const members = spec.nodes.filter((n) => n.box === box.id);
    if (!members.length) continue;
    const xs = members.map((n) => COL[n.col]);
    const ys = members.map((n) => n.y);
    const x0 = Math.min(...xs) - BOX_PAD;
    const y0 = Math.min(...ys) - BOX_PAD - 14;
    const x1 = Math.max(...xs) + NODE_W + BOX_PAD;
    const y1 = Math.max(...ys) + NODE_H + BOX_PAD;
    boxG.appendChild(
      s('rect', { class: `lvi-gbox lvi-gbox-${box.tone}`, x: x0, y: y0, width: x1 - x0, height: y1 - y0, rx: 12 }),
    );
    boxG.appendChild(s('text', { class: 'lvi-gbox-label', x: x0 + 12, y: y0 + 4 }, box.label));
  }
  svg.appendChild(boxG);

  // ── edges (paths only; labels go on the top layer) ──
  const edgeG = s('g', { class: 'lvi-edge-layer' });
  const labelG = s('g', { class: 'lvi-label-layer' }); // appended last, above nodes
  for (const e of spec.edges) {
    const a = byId[e.from];
    const b = byId[e.to];
    if (!a || !b) continue;
    const pa = nodeXY(a);
    const pb = nodeXY(b);
    const sameRow = Math.abs(a.y - b.y) < 4;
    let x1 = pa.x, y1 = pa.y, x2 = pb.x, y2 = pb.y;
    if (sameRow) {
      const dir = pb.x > pa.x ? 1 : -1;
      x1 = pa.x + dir * (NODE_W / 2);
      x2 = pb.x - dir * (NODE_W / 2);
    } else {
      y1 = a.y < b.y ? a.y + NODE_H : a.y;
      y2 = a.y < b.y ? b.y : b.y + NODE_H;
    }
    const cls =
      e.kind === 'thick' ? 'lvi-edge-thick'
      : e.kind === 'pending' ? 'lvi-edge-pending'
      : e.kind === 'excluded' ? 'lvi-edge-excluded'
      : e.kind === 'sign' ? 'lvi-edge-sign'
      : e.kind === 'proof' ? 'lvi-edge-proof'
      : e.kind === 'ghost' ? 'lvi-edge-ghost'
      : 'lvi-edge-thin';
    const marker =
      e.kind === 'thick' || e.kind === 'pending' ? 'url(#ah-thick)'
      : e.kind === 'excluded' ? 'url(#ah-absent)'
      : e.kind === 'sign' ? 'url(#ah-sign)'
      : e.kind === 'proof' ? 'url(#ah-proof)'
      : e.kind === 'ghost' ? null
      : 'url(#ah-thin)';
    const midY = (y1 + y2) / 2;
    const midX = (x1 + x2) / 2;
    const d = sameRow
      ? `M${x1} ${y1} L${x2} ${y2}`
      : `M${x1} ${y1} C${x1} ${midY} ${x2} ${midY} ${x2} ${y2}`;
    edgeG.appendChild(s('path', { class: `lvi-edge ${cls}`, d, 'marker-end': marker }));

    // label with a pill background so it stays readable over lines
    const addLabel = (lx, ly, text, anchor) => {
      const approxW = text.length * 6.1 + 12;
      const ax = anchor === 'end' ? lx - approxW : anchor === 'middle' ? lx - approxW / 2 : lx;
      labelG.appendChild(s('rect', { class: 'lvi-edge-label-bg', x: ax, y: ly - 9, width: approxW, height: 17, rx: 8 }));
      labelG.appendChild(s('text', { class: 'lvi-edge-label', x: lx, y: ly + 1, 'text-anchor': anchor === 'middle' ? 'middle' : anchor, 'dominant-baseline': 'middle' }, text));
    };

    if (e.kind === 'excluded') {
      // Exclusion badge on the epoch→handle arrow; label to its left.
      labelG.appendChild(s('circle', { class: 'lvi-excl-bg', cx: midX, cy: midY, r: 12 }));
      labelG.appendChild(
        s('text', { class: 'lvi-excl-mark', x: midX, y: midY + 1, 'text-anchor': 'middle', 'dominant-baseline': 'middle' }, '∅'),
      );
      if (e.label) addLabel(midX - 18, midY, e.label, 'end');
    } else if (e.label) {
      if (sameRow) addLabel(midX, y1 - 12, e.label, 'middle');
      else addLabel(midX + 10, midY, e.label, 'start');
    }
  }
  svg.appendChild(edgeG);

  // ── nodes ──
  const nodeG = s('g', { class: 'lvi-node-layer' });
  for (const n of spec.nodes) {
    const x = COL[n.col];
    const g = s('g', {
      class: `lvi-gnode lvi-gnode-${n.kind}${n.excluded ? ' excluded' : ''}${n.pending ? ' pending' : ''}${n.id === selectedNodeId ? ' active' : ''}${n.path ? ' clickable' : ''}`,
      transform: `translate(${x} ${n.y})`,
      onclick: n.path ? () => onSelect(n.id) : null,
    });
    g.appendChild(s('rect', { class: 'lvi-gnode-rect', width: NODE_W, height: NODE_H, rx: 9 }));
    // sovereignty stripe for handle node
    if (n.sov) {
      g.appendChild(s('circle', { class: `lvi-gnode-dot lvi-sov-fill-${n.sov}`, cx: 15, cy: NODE_H / 2, r: 4 }));
    }
    const tx = n.sov ? 28 : 14;
    g.appendChild(s('text', { class: 'lvi-gnode-label', x: tx, y: 20 }, n.label));
    g.appendChild(s('text', { class: 'lvi-gnode-value', x: tx, y: 37 }, n.value));
    // verdict tick for proof nodes
    if (n.path) {
      const v = VERDICT[n.path.resolution];
      if (v) {
        g.appendChild(
          s('text', { class: `lvi-gnode-verdict v-${v.cls}`, x: NODE_W - 12, y: 30, 'text-anchor': 'end' },
            v.cls === 'included' ? '✓' : v.cls === 'excluded' ? '∅' : '!'),
        );
      }
    }
    nodeG.appendChild(g);
  }
  svg.appendChild(nodeG);
  svg.appendChild(labelG); // labels + exclusion badge on top, never occluded

  return { svg, spec };
}

// ═══════════════════════════════════════════════════════════════════
// DETAIL — the merkle walk for a selected proof node
// ═══════════════════════════════════════════════════════════════════

function kv(label, value, cls) {
  return el('div', { class: 'lvi-kv' }, el('span', { class: 'k' }, label), el('span', { class: `v ${cls || ''}`, title: value }, trunc(value, 12, 12)));
}

// Extract the first `bitLen` bits (MSB-first) from a hex string.
function bitsFromHex(hex, bitLen) {
  if (!hex || !bitLen) return '';
  const clean = hex.replace(/[^0-9a-fA-F]/g, '');
  let out = '';
  for (let i = 0; i < bitLen; i++) {
    const byte = parseInt(clean.substr(Math.floor(i / 8) * 2, 2) || '0', 16);
    out += (byte >> (7 - (i % 8))) & 1;
  }
  return out;
}

// Draw the merkle proof as the binary-radix path it actually is: root → branch
// bits → the leaf, with each pruned sibling shown as a "hash node" (cf. the
// spaces-paper trie figure).
function renderTrie(path) {
  const steps = path.steps || [];
  const n = steps.length;
  const DY = 68, XM = 118, XS = 302, R = 14, RR = 19, LW = 122, LH = 34;
  const width = 448;
  const height = 34 + (n + 1) * DY + 18;
  const svg = s('svg', { class: 'lvi-trie', viewBox: `0 0 ${width} ${height}`, width: '100%' });
  const eG = s('g'), nG = s('g'), lG = s('g');
  const yOf = (i) => 34 + i * DY;

  const edge = (x1, y1, x2, y2, cls) =>
    s('path', { class: `lvi-trie-edge ${cls || ''}`, fill: 'none', d: `M${x1} ${y1} C${x1} ${(y1 + y2) / 2} ${x2} ${(y1 + y2) / 2} ${x2} ${y2}` });
  // two-tone bit label: compressed-prefix bits muted, the branch bit highlighted
  const bitLabel = (x, y, pbits, bit, sib) => {
    const txt = pbits + bit;
    const w = txt.length * 6 + 10;
    lG.appendChild(s('rect', { class: 'lvi-trie-lbl-bg', x: x - w / 2, y: y - 8, width: w, height: 15, rx: 7 }));
    const t = s('text', { class: 'lvi-trie-lbl', x, y: y + 1, 'text-anchor': 'middle', 'dominant-baseline': 'middle' });
    if (pbits) t.appendChild(s('tspan', { class: 'lvi-tb-prefix' }, pbits));
    t.appendChild(s('tspan', { class: sib ? 'lvi-tb-sib' : 'lvi-tb-branch' }, bit));
    lG.appendChild(t);
  };

  for (let i = 0; i < n; i++) {
    const st = steps[i];
    const Li = yOf(i), Ln = yOf(i + 1);
    const isLeafNext = i === n - 1;
    const dirBit = st.direction === 'left' ? '0' : '1';
    const sibBit = st.direction === 'left' ? '1' : '0';
    const pbits = bitsFromHex(st.prefix, st.prefix_bit_len);
    // on-path edge (straight down) + its bit-path label
    eG.appendChild(edge(XM, Li + (i === 0 ? RR : R), XM, Ln - (isLeafNext ? LH / 2 : R), 'onpath'));
    bitLabel(XM - 22, (Li + Ln) / 2, pbits, dirBit, false);
    // sibling edge (down-right) → pruned hash node
    eG.appendChild(edge(XM + 6, Li + (i === 0 ? RR - 4 : R - 2), XS - 44, Ln, 'sib'));
    bitLabel((XM + XS) / 2 + 10, (Li + Ln) / 2 - 8, pbits, sibBit, true);
    nG.appendChild(s('ellipse', { class: 'lvi-trie-hash', cx: XS, cy: Ln, rx: 44, ry: 19 }));
    nG.appendChild(s('text', { class: 'lvi-trie-hash-t', x: XS, y: Ln - 3, 'text-anchor': 'middle' }, 'hash node'));
    const ht = s('text', { class: 'lvi-trie-hash-h', x: XS, y: Ln + 9, 'text-anchor': 'middle' }, trunc(st.sibling_hash, 4, 4));
    ht.appendChild(s('title', {}, st.sibling_hash));
    nG.appendChild(ht);
  }

  // internal nodes (root + intermediate). A node with a compressed path gets a
  // dashed accent ring + a chip showing the prefix bits it consumes.
  for (let i = 0; i < n; i++) {
    const y = yOf(i);
    const st = steps[i];
    const r = i === 0 ? RR : R;
    if (st.prefix_bit_len > 0) {
      const pbits = bitsFromHex(st.prefix, st.prefix_bit_len);
      const ring = s('circle', { class: 'lvi-trie-comp', cx: XM, cy: y, r: r + 4 });
      ring.appendChild(s('title', {}, `compressed path · ${st.prefix_bit_len} bit${st.prefix_bit_len === 1 ? '' : 's'} (${pbits})`));
      nG.appendChild(ring);
      // prefix chip to the left of the node
      const cw = pbits.length * 6 + 14;
      lG.appendChild(s('rect', { class: 'lvi-trie-comp-bg', x: XM - r - 12 - cw, y: y - 8, width: cw, height: 16, rx: 8 }));
      const ct = s('text', { class: 'lvi-trie-comp-t', x: XM - r - 12 - cw / 2, y: y + 1, 'text-anchor': 'middle', 'dominant-baseline': 'middle' });
      ct.appendChild(s('tspan', { class: 'lvi-trie-comp-pre' }, '⊐ '));
      ct.appendChild(s('tspan', {}, pbits));
      lG.appendChild(ct);
    }
    if (i === 0) {
      nG.appendChild(s('circle', { class: 'lvi-trie-root', cx: XM, cy: y, r: RR }));
      nG.appendChild(s('text', { class: 'lvi-trie-root-t', x: XM, y: y + 1, 'text-anchor': 'middle', 'dominant-baseline': 'middle' }, 'root'));
    } else {
      nG.appendChild(s('circle', { class: 'lvi-trie-inner', cx: XM, cy: y, r: R }));
    }
  }

  // leaf (or divergence terminal)
  const yl = yOf(n);
  if (n === 0) {
    // root is the leaf
    nG.appendChild(s('circle', { class: 'lvi-trie-root', cx: XM, cy: yl, r: RR }));
    nG.appendChild(s('text', { class: 'lvi-trie-root-t', x: XM, y: yl + 1, 'text-anchor': 'middle', 'dominant-baseline': 'middle' }, 'root'));
  } else if (path.leaf) {
    const matched = path.leaf.matched;
    const rect = s('rect', { class: `lvi-trie-leaf${matched ? '' : ' miss'}`, x: XM - LW / 2, y: yl - LH / 2, width: LW, height: LH, rx: 7 });
    rect.appendChild(s('title', {}, path.leaf.key));
    nG.appendChild(rect);
    const kindT = path.leaf.value_kind && path.leaf.value_kind !== 'Unknown' ? path.leaf.value_kind : trunc(path.leaf.key, 4, 4);
    nG.appendChild(s('text', { class: 'lvi-trie-leaf-t', x: XM, y: yl - 2, 'text-anchor': 'middle' }, kindT));
    nG.appendChild(s('text', { class: 'lvi-trie-leaf-h', x: XM, y: yl + 10, 'text-anchor': 'middle' }, matched ? 'target key' : 'different key → absent'));
  } else {
    nG.appendChild(s('circle', { class: 'lvi-trie-absent', cx: XM, cy: yl, r: R }));
    nG.appendChild(s('text', { class: 'lvi-trie-absent-t', x: XM, y: yl + 1, 'text-anchor': 'middle', 'dominant-baseline': 'middle' }, '∅'));
  }

  svg.appendChild(eG);
  svg.appendChild(nG);
  svg.appendChild(lG);
  return el('div', { class: 'lvi-trie-wrap' }, svg);
}

// The queried key's leading bits, segmented per trie node: compressed-prefix
// bits are muted, the branch bit at each node is highlighted. Reading it left
// to right spells the discriminating prefix of the key.
function renderKeyBits(path) {
  const steps = path.steps || [];
  if (!steps.length) return null;
  const bits = el('span', { class: 'kb-bits' });
  let total = 0;
  let comp = 0;
  for (const st of steps) {
    const pb = bitsFromHex(st.prefix, st.prefix_bit_len);
    const br = st.direction === 'left' ? '0' : '1';
    const seg = el('span', { class: 'kb-seg' });
    if (pb) {
      seg.appendChild(el('span', { class: 'kb-prefix', title: `compressed prefix · ${st.prefix_bit_len} bits` }, pb));
      total += pb.length;
      comp += 1;
    }
    seg.appendChild(el('span', { class: 'kb-branch', title: 'branch bit' }, br));
    total += 1;
    bits.appendChild(seg);
  }
  return el(
    'div',
    { class: 'lvi-keybits' },
    el('span', { class: 'kb-label' }, 'key bits'),
    bits,
    el('span', { class: 'kb-count' }, `${total} of 256 · ${comp} compressed`),
  );
}

function renderWalk(path) {
  const walk = el('div', { class: 'lvi-walk lvi-walk-open' });
  walk.appendChild(kv('root', path.root));
  walk.appendChild(kv('key', path.key));
  if (path.leaf) {
    walk.appendChild(kv('leaf key', path.leaf.key, path.leaf.matched ? 'match' : ''));
    walk.appendChild(kv('value', path.leaf.value_hash));
  }
  const steps = path.steps || [];
  walk.appendChild(
    el('div', { class: 'lvi-steps-label' }, `binary trie · ${steps.length} branch${steps.length === 1 ? '' : 'es'} to leaf`),
  );
  const kb = renderKeyBits(path);
  if (kb) walk.appendChild(kb);
  walk.appendChild(renderTrie(path));
  return walk;
}

function renderNodeDetail(node) {
  if (node && node.kind === 'zk' && node.receipt) return renderReceipt(node.receipt);
  if (!node || !node.path) {
    return el('div', { class: 'lvi-note' }, 'Select a node in the graph to inspect its proof.');
  }
  const path = node.path;
  const v = VERDICT[path.resolution] || { label: path.resolution, cls: 'excluded', ico: 'absent' };
  const tree = TREE[path.tree] || { label: path.tree, swatch: '' };

  const head = el('div', { class: 'lvi-nd-head' },
    el('div', { class: 'lvi-nd-title' }, PURPOSE[path.purpose] || path.purpose),
    el('span', { class: `lvi-verdict lvi-verdict-${v.cls}` }, icon(v.ico), v.label),
  );
  const sub = el('div', { class: 'lvi-nd-sub' },
    el('span', { class: 'lvi-tree-tag' }, el('span', { class: `lvi-swatch ${tree.swatch}` }), `${tree.label} tree`),
    PURPOSE_HINT[path.purpose] ? el('span', {}, `· ${PURPOSE_HINT[path.purpose]}`) : null,
    path.leaf && path.leaf.value_kind !== 'Unknown' ? el('span', { class: 'lvi-leaf-kind' }, path.leaf.value_kind) : null,
    path.leaf && path.leaf.spent === true ? el('span', { class: 'lvi-dormant' }, 'dormant') : null,
    path.commitment && path.commitment.genesis ? el('span', { class: 'lvi-dormant', style: 'color:var(--ok)' }, 'genesis · no ZK') : null,
  );
  return el('div', { class: 'lvi-panel' },
    el('div', { class: 'lvi-nd-body' }, head, sub, renderWalk(path)));
}

function renderReceipt(r) {
  const flow = el('div', { class: 'lvi-receipt-flow' },
    el('div', { class: 'lvi-root-node' }, el('span', { class: 'rn-label' }, 'initial root'), el('span', { class: 'rn-hash', title: r.initial_root }, trunc(r.initial_root))),
    el('span', { class: 'lvi-flow-arrow' }, '→'),
    el('span', { class: 'lvi-flow-kind' }, `${r.kind} proof`),
    el('span', { class: 'lvi-flow-arrow' }, '→'),
    el('div', { class: 'lvi-root-node' }, el('span', { class: 'rn-label' }, 'final root'), el('span', { class: 'rn-hash', title: r.final_root }, trunc(r.final_root))),
  );
  const meta = el('div', { class: 'lvi-receipt-flow' },
    el('span', { class: `lvi-policy ${r.policy_ok ? 'ok' : 'bad'}` }, icon(r.policy_ok ? 'check' : 'warn'), r.policy_ok ? 'policy IDs match this build' : 'policy IDs mismatch'),
    el('span', { class: 'lvi-meta-chip' }, 'rolling', el('b', { title: r.rolling_hash }, trunc(r.rolling_hash, 6, 6))),
  );
  return el('div', { class: 'lvi-panel' },
    el('div', { class: 'lvi-panel-head' }, el('span', { class: 'lvi-eyebrow' }, 'ZK receipt'), el('span', { class: 'lvi-leaf-kind' }, 'decoded, not verified')),
    el('div', { class: 'lvi-receipt-body' }, flow, meta));
}

function recordRow(who, rec) {
  return el('div', { class: 'lvi-record-row' },
    el('span', { class: 'lvi-record-who' }, who),
    el('span', { class: 'lvi-record-seq' }, `seq ${rec.seq}`),
    el('span', { class: 'lvi-record-signer', title: rec.canonical }, rec.canonical),
    rec.flags ? el('span', { class: 'lvi-meta-chip' }, 'flags', el('b', {}, `0x${rec.flags.toString(16)}`)) : null);
}

// ═══════════════════════════════════════════════════════════════════
// PUBLIC ENTRY
// ═══════════════════════════════════════════════════════════════════

export function renderInspectReport(container, report, opts = {}) {
  container.classList.add('libveritas-inspector');
  container.innerHTML = '';
  const root = el('div', { class: 'lvi-root' });

  if (!report || !report.anchor) {
    root.appendChild(el('div', { class: 'lvi-empty' }, 'No inspect report provided.'));
    container.appendChild(root);
    return;
  }
  const zones = report.zones || [];
  if (!zones.length) {
    root.appendChild(el('div', { class: 'lvi-empty' }, 'Report contains no zones.'));
    container.appendChild(root);
    return;
  }

  const spaceZones = zones.filter((z) => !z.parent);
  const parentOf = (z) => (z.parent ? zones.find((p) => p.handle === z.parent) : null);

  // default: first handle if any, else the space
  const firstHandle = zones.find((z) => z.parent);
  const state = { zone: opts.focus || (firstHandle ? firstHandle.handle : zones[0].handle), node: null };

  // ── zone picker (enter a zone) ──
  const nav = el('nav', { class: 'lvi-nav' });
  for (const sp of spaceZones) {
    const group = el('div', { class: 'lvi-nav-group' });
    group.appendChild(
      el('button', { class: 'lvi-nav-space', type: 'button', 'data-zone': sp.handle, onclick: () => select(sp.handle) },
        sovDot(sp.sovereignty), renderHandle(sp.handle, 'lvi-nav-name')),
    );
    for (const h of zones.filter((z) => z.parent === sp.handle)) {
      group.appendChild(
        el('button', { class: 'lvi-nav-handle', type: 'button', 'data-zone': h.handle, onclick: () => select(h.handle) },
          sovDot(h.sovereignty), renderHandle(h.handle, 'lvi-nav-name')),
      );
    }
    nav.appendChild(group);
  }

  const graphHost = el('div', { class: 'lvi-graph-host' });
  const detailHost = el('div', { class: 'lvi-detail-host' });

  function renderDetail() {
    const zone = zones.find((z) => z.handle === state.zone);
    const parentZone = zone ? parentOf(zone) : null;
    const { spec } = renderGraphSVG(zone, parentZone, report.anchor, () => {}, null);
    const node = spec.nodes.find((n) => n.id === state.node);
    detailHost.innerHTML = '';
    detailHost.appendChild(
      el('div', { class: 'lvi-eyebrow', style: 'margin-bottom:10px' },
        state.node ? 'Node proof' : 'Click a graph node to inspect its proof'),
    );
    detailHost.appendChild(renderNodeDetail(node));

    // records for the zone (below node detail)
    const rec = (zone && zone.records) || {};
    if (rec.owner || rec.delegate) {
      const body = el('div', { class: 'lvi-records-body' });
      if (rec.owner) body.appendChild(recordRow('owner', rec.owner));
      if (rec.delegate) body.appendChild(recordRow('delegate', rec.delegate));
      detailHost.appendChild(
        el('div', { class: 'lvi-panel', style: 'margin-top:16px' },
          el('div', { class: 'lvi-panel-head' }, el('span', { class: 'lvi-eyebrow' }, 'Signed records')), body),
      );
    }
  }

  function renderGraph() {
    const zone = zones.find((z) => z.handle === state.zone);
    const parentZone = zone ? parentOf(zone) : null;
    graphHost.innerHTML = '';

    // header: which zone we entered + its status
    const s2 = SOV[zone.sovereignty];
    graphHost.appendChild(
      el('div', { class: 'lvi-graph-head' },
        renderHandle(zone.handle),
        el('span', { class: 'lvi-kind-chip' }, zone.kind),
        s2 ? el('span', { class: `lvi-sov-badge lvi-badge-${s2.cls}` }, sovDot(zone.sovereignty), s2.label) : null,
        zone.receipt ? el('span', { class: 'lvi-meta-chip' }, 'receipt', el('b', {}, zone.receipt.kind)) : null,
      ),
    );

    const { svg } = renderGraphSVG(zone, parentZone, report.anchor, (nodeId) => {
      state.node = state.node === nodeId ? null : nodeId;
      renderGraph();
      renderDetail();
    }, state.node);
    graphHost.appendChild(el('div', { class: 'lvi-graph-scroll' }, svg));

    for (const b of nav.querySelectorAll('[data-zone]'))
      b.classList.toggle('active', b.getAttribute('data-zone') === state.zone);
  }

  function select(handle) {
    state.zone = handle;
    state.node = null;
    renderGraph();
    renderDetail();
  }

  const workspace = el('div', { class: 'lvi-workspace' }, nav,
    el('div', { class: 'lvi-main' }, graphHost, detailHost));
  root.appendChild(workspace);
  container.appendChild(root);

  select(state.zone);
}

export default { renderInspectReport };
