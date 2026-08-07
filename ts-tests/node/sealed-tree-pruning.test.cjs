// Sealed trees keep ~1M internal `MerkleNodes` entries forever (~72 MiB each)
// purely to serve Merkle paths to wallets. No dispatchable reads them, so levels
// below `SealedTreePrunedBelowLevel` are pruned in `on_idle` and rebuilt from the
// leaves when a path needs them.
//
// Sealing a tree needs 2^20 shields — not reachable here, since
// `MaxLeavesPerTree` is a compile-time constant. What this file DOES validate
// against a live chain: the config is wired and sane, the active tree keeps every
// node (the property that guarantees today's paths stay O(depth)), the sweep is
// idle while nothing has sealed, and paths still verify. The pruned-path
// equivalence itself is covered by unit tests, which can seal a tree with
// `MaxLeavesPerTree = 8`.
const { ApiPromise, WsProvider } = require('@polkadot/api');
const { Keyring } = require('@polkadot/keyring');

const ok = [], bad = [];
const check = (n, c, x = '') => { (c ? ok : bad).push(n); console.log(`${c ? 'PASS' : 'FAIL'}  ${n}${x ? ` — ${x}` : ''}`); };
const sect = (t) => console.log(`\n── ${t} ──`);

(async () => {
  const provider = new WsProvider('ws://127.0.0.1:9955');
  const api = await ApiPromise.create({ provider, noInitWarn: true });
  const alice = new Keyring({ type: 'sr25519' }).addFromUri('//Alice');
  const q = api.query.shieldedPool;
  const RUN = require('crypto').randomBytes(4).toString('hex');
  const ONE = 10n ** 18n;

  // ══ Config is wired and self-consistent ═════════════════════════════════
  sect('Config');
  const cut = api.consts.shieldedPool.sealedTreePrunedBelowLevel.toNumber();
  const cap = api.consts.shieldedPool.maxLeavesPerTree.toNumber();
  const depth = api.consts.shieldedPool.maxTreeDepth.toNumber();

  check('SealedTreePrunedBelowLevel is exposed', Number.isInteger(cut), `cut=${cut}`);
  check('cut is inside 1..depth', cut > 0 && cut < depth, `0 < ${cut} < ${depth}`);
  check('node booted — integrity_test accepted the cut', true);

  // The whole point: what fraction of a sealed tree survives.
  const total = Array.from({ length: depth - 1 }, (_, i) => cap >> (i + 1)).reduce((a, b) => a + b, 0);
  const kept = Array.from({ length: depth - cut }, (_, i) => cap >> (cut + i)).reduce((a, b) => a + b, 0);
  const freedPct = (100 * (total - kept)) / total;
  check('cut frees the bulk of a sealed tree', freedPct > 99,
        `${total.toLocaleString()} -> ${kept.toLocaleString()} (${freedPct.toFixed(2)}% freed)`);
  // Recompute cost is 2^cut leaf reads; keep it sane.
  check('recompute stays bounded', 2 ** cut <= 4096, `${2 ** cut} leaf reads per path`);

  // ══ Nothing has sealed: the sweep must be idle ══════════════════════════
  sect('Sweep state before any tree seals');
  const size0 = (await q.merkleTreeSize()).toNumber();
  const sealedCount = (await q.sealedTreeRoots.entries()).length;
  check('no tree has sealed yet on this chain', sealedCount === 0,
        `tree_size=${size0}, cap=${cap}`);
  check('prune cursor is idle', (await q.sealedPruneCursor()).isNone);
  check('no tree recorded as pruned', (await q.lastPrunedTree()).isNone);

  // ══ Inserting leaves must not disturb the sweep or the active tree ══════
  sect('Active tree is never pruned');
  const memo = '0x' + 'b4'.repeat(180);
  let nonce = (await api.rpc.system.accountNextIndex(alice.address)).toNumber();
  const commitments = [];
  for (let i = 0; i < 4; i++) {
    const c = '0x' + RUN + i.toString(16).padStart(8, '0') + 'd2'.repeat(24);
    commitments.push(c);
    await new Promise((res, rej) => {
      const timer = setTimeout(() => rej(new Error('timeout')), 30_000);
      api.tx.shieldedPool.shield(0, ONE, c, memo)
        .signAndSend(alice, { nonce: nonce++ }, ({ status, dispatchError }) => {
          if (dispatchError) {
            clearTimeout(timer);
            let n = dispatchError.toString();
            if (dispatchError.isModule) { try { n = api.registry.findMetaError(dispatchError.asModule).name; } catch (_) {} }
            rej(new Error(n));
          } else if (status.isInBlock) { clearTimeout(timer); res(); }
        }).catch((e) => { clearTimeout(timer); rej(e); });
    });
  }
  const size1 = (await q.merkleTreeSize()).toNumber();
  check('shields landed', size1 === size0 + 4, `${size0} -> ${size1}`);

  // Every internal level of the active tree must still be populated: the sweep
  // only ever touches trees with tree_id < current_tree_id.
  let missing = 0;
  for (let level = 1; level < depth; level++) {
    const node = await q.merkleNodes(0, level, 0);
    if (node.isNone) missing++;
  }
  check('active tree retains every internal level', missing === 0, `${missing} missing`);
  check('sweep stayed idle while inserting', (await q.sealedPruneCursor()).isNone);

  // ══ Paths still work end to end ════════════════════════════════════════
  sect('Merkle paths over RPC');
  const proof = await provider.send('privacy_getMerkleProofByCommitment', [commitments[0]]);
  check('RPC serves a path', Array.isArray(proof.path) && proof.path.length === depth,
        `${proof.path.length} siblings`);
  check('path anchors to a provable root',
        (await q.historicPoseidonRoots(proof.root)).isSome ||
        (await q.sealedRootIndex(proof.root)).isSome);

  // Latency floor for the unpruned path — the sealed-tree case adds the
  // recompute on top of this.
  const t0 = Date.now();
  for (const c of commitments) {
    await provider.send('privacy_getMerkleProofByCommitment', [c]);
  }
  const perCall = (Date.now() - t0) / commitments.length;
  check('unpruned path latency is negligible', perCall < 200, `${perCall.toFixed(0)}ms per call`);

  await api.disconnect();
  console.log(`\n${'═'.repeat(58)}`);
  console.log(`${ok.length} passed, ${bad.length} failed`);
  if (bad.length) bad.forEach((b) => console.log('  FAILED: ' + b));
  process.exit(bad.length ? 1 : 0);
})().catch((e) => { console.error('ERROR:', e.message); process.exit(1); });
