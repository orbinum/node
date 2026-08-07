// Adversarial probe of the Merkle surfaces, against a live node.
//
// The other Merkle test is confirmatory: it checks the zero-hash ladder did not
// move. This one tries to break the node instead.
//
// What is being attacked: `zero_hash_at_level` used to recurse one stack frame
// per level, and the runtime's Wasm stack is a fixed 1 MB. A stack overflow
// there aborts the whole runtime rather than failing one call, so any input
// that reaches the ladder with a large level was a node-kill primitive. The
// function is now a loop, and `IncrementalMerkleTree` rejects depths past 31 at
// compile time.
//
// Every case below is expected to be REJECTED, not to succeed. The failure this
// is looking for is the node dying, hanging, or stopping block production —
// which is why block height is checked after every batch.
//
//   ./target/release/orbinum-node --dev --tmp --rpc-port 9955 --sealing=instant
//   node ts-tests/node/merkle-adversarial.test.cjs
const { ApiPromise, WsProvider } = require('@polkadot/api');
const { Keyring } = require('@polkadot/keyring');

const ok = [], bad = [];
const check = (n, c, x = '') => { (c ? ok : bad).push(n); console.log(`${c ? 'PASS' : 'FAIL'}  ${n}${x ? ` — ${x}` : ''}`); };
const sect = (t) => console.log(`\n── ${t} ──`);

const RPC_TIMEOUT_MS = 15_000;

/** Send an RPC and classify the outcome. A timeout is the interesting failure. */
async function probe(provider, method, params) {
  const started = Date.now();
  try {
    const result = await Promise.race([
      provider.send(method, params),
      new Promise((_, rej) => setTimeout(() => rej(new Error('TIMEOUT')), RPC_TIMEOUT_MS)),
    ]);
    return { outcome: 'ok', ms: Date.now() - started, result };
  } catch (e) {
    if (e.message === 'TIMEOUT') return { outcome: 'timeout', ms: Date.now() - started };
    return { outcome: 'error', ms: Date.now() - started, message: e.message };
  }
}

const memo = () => '0x' + 'ab'.repeat(180);

function submit(tx, signer, nonce) {
  return new Promise((resolve, reject) => {
    const timer = setTimeout(() => reject(new Error('tx timed out')), 30_000);
    tx.signAndSend(signer, { nonce }, ({ status, dispatchError }) => {
      if (dispatchError) { clearTimeout(timer); return reject(new Error(dispatchError.toString())); }
      if (status.isInBlock) { clearTimeout(timer); resolve(); }
    }).catch(reject);
  });
}

(async () => {
  const provider = new WsProvider('ws://127.0.0.1:9955');
  const api = await ApiPromise.create({ provider, noInitWarn: true });
  const alice = new Keyring({ type: 'sr25519' }).addFromUri('//Alice');
  let nonce = (await api.rpc.system.accountNextIndex(alice.address)).toNumber();

  const height = async () => (await api.rpc.chain.getHeader()).number.toNumber();
  const stillAlive = async (label) => {
    const before = await height();
    await submit(api.tx.system.remark('0x00'), alice, nonce++);
    const after = await height();
    check(`node still producing blocks after ${label}`, after > before, `${before} -> ${after}`);
  };

  // Give the tree a leaf so the proof paths have something to resolve.
  const RUN = require('crypto').randomBytes(4).toString('hex');
  await submit(
    api.tx.shieldedPool.shield(0, 10n ** 18n, '0x' + RUN + 'aa'.repeat(28), memo()),
    alice, nonce++);

  sect('Extreme leaf indices');

  // The ladder is indexed by tree level, not by leaf index — but leaf_index is
  // the only Merkle input a stranger controls, and it feeds index arithmetic
  // that derives levels. u32::MAX is the largest value the codec will carry.
  const extremes = [
    ['u32::MAX', 4294967295],
    ['u32::MAX - 1', 4294967294],
    ['2^31 (sign boundary)', 2147483648],
    ['2^20 (one tree)', 1048576],
    ['2^20 - 1', 1048575],
  ];

  for (const [label, idx] of extremes) {
    const r = await probe(provider, 'privacy_getMerkleProof', [idx]);
    // Rejection is the correct answer: these are past tree_size.
    check(`leaf_index ${label} is refused, not hung`, r.outcome === 'error',
      `${r.outcome}${r.ms > 1000 ? ` in ${r.ms}ms` : ''}`);
  }

  await stillAlive('extreme leaf indices');

  sect('Malformed commitments');

  // getMerkleProofByCommitment parses a hex string, so it takes attacker bytes
  // of attacker-chosen length.
  const malformed = [
    ['empty', '0x'],
    ['one byte', '0xff'],
    ['31 bytes', '0x' + 'ff'.repeat(31)],
    ['33 bytes', '0x' + 'ff'.repeat(33)],
    ['1 KiB', '0x' + 'ff'.repeat(1024)],
    ['64 KiB', '0x' + 'ff'.repeat(65536)],
    ['no 0x prefix', 'ff'.repeat(32)],
    ['not hex', '0xzzzz'],
  ];

  for (const [label, c] of malformed) {
    const r = await probe(provider, 'privacy_getMerkleProofByCommitment', [c]);
    check(`commitment ${label} is refused, not hung`, r.outcome === 'error',
      `${r.outcome}${r.ms > 1000 ? ` in ${r.ms}ms` : ''}`);
  }

  await stillAlive('malformed commitments');

  sect('Repeated pressure');

  // A single rejection is cheap. The concern is whether repeated rejections
  // accumulate — a leak, a runtime instance that never resets, a queue that
  // grows. Fire a burst and check the node is unchanged.
  const burst = [];
  for (let i = 0; i < 50; i++) {
    burst.push(probe(provider, 'privacy_getMerkleProof', [4294967295 - i]));
  }
  const results = await Promise.all(burst);
  const hung = results.filter((r) => r.outcome === 'timeout').length;
  const slowest = Math.max(...results.map((r) => r.ms));
  check('50 rejected proof requests, none hung', hung === 0, `slowest ${slowest}ms`);

  await stillAlive('a 50-request burst');

  sect('Storage query surfaces');

  // merkleNodes is a three-key map; the level key is a u8, so 255 is the
  // largest a caller can name. Before the rewrite, a level past the 21-entry
  // cache fell through to the recursive ladder.
  for (const level of [20, 21, 31, 32, 100, 255]) {
    try {
      const v = await api.query.shieldedPool.merkleNodes(0, level, 0);
      check(`merkleNodes at level ${level} answers`, v.isNone || v.isSome,
        v.isSome ? 'stored' : 'empty');
    } catch (e) {
      check(`merkleNodes at level ${level} answers`, false, e.message.slice(0, 60));
    }
  }

  await stillAlive('high-level node queries');

  sect('Runtime API surface');

  // get_root_for_leaf takes a raw leaf index straight into tree arithmetic.
  for (const [label, idx] of extremes) {
    try {
      const r = await api.call.shieldedPoolRuntimeApi.getRootForLeaf(idx);
      check(`getRootForLeaf ${label} answers without trapping`, r.isNone || r.isSome,
        r.isSome ? 'root' : 'none');
    } catch (e) {
      // A clean error is fine. A trap would have downed the runtime instance.
      check(`getRootForLeaf ${label} answers without trapping`,
        !/unreachable|trap/i.test(e.message), e.message.slice(0, 60));
    }
  }

  await stillAlive('runtime API probing');

  await api.disconnect();
  console.log(`\n${ok.length} passed, ${bad.length} failed`);
  if (bad.length) console.log('Failed: ' + bad.join(', '));
  process.exit(bad.length ? 1 : 0);
})().catch((e) => { console.error('ERROR:', e.message); process.exit(1); });
