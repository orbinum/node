// Adversarial probe of the shielded-pool precompile's ABI decoder.
//
// Everything the decoder reads is attacker-chosen calldata. Two bug classes were
// fixed and are attacked here:
//
//   * Truncation. Offsets and lengths are `uint256`, but they were narrowed with
//     `low_u32()`, which keeps the bottom 32 bits and discards the rest. A word
//     of `2^32 + 8` read back as `8`, so the bounds check validated a value the
//     sender never wrote and the decoder indexed somewhere else entirely.
//   * Overflow. `data_start + length > params.len()` wraps on a huge length, and
//     a wrapped sum passes the very check meant to reject it. Release builds do
//     not enable overflow-checks, so it wrapped silently.
//
// Calldata is hand-built rather than encoded by a library: the point is to send
// shapes no encoder would produce. Every call must be refused without the node
// hanging, trapping, or stalling block production — so block height is checked
// after each batch.
//
//   ./target/release/orbinum-node --dev --tmp --rpc-port 9955 --sealing=instant
//   node ts-tests/node/abi-decoder-bounds.test.cjs
const { ApiPromise, WsProvider } = require('@polkadot/api');
const { Keyring } = require('@polkadot/keyring');

const ok = [], bad = [];
const check = (n, c, x = '') => { (c ? ok : bad).push(n); console.log(`${c ? 'PASS' : 'FAIL'}  ${n}${x ? ` — ${x}` : ''}`); };
const sect = (t) => console.log(`\n── ${t} ──`);

// Precompile index 2049.
const PRECOMPILE = '0x0000000000000000000000000000000000000801';
const SHIELD_SELECTOR = '9feb22ea'; // shield(uint32,bytes32,bytes)
const RPC_TIMEOUT_MS = 15_000;

/** 32-byte big-endian word from a BigInt. */
const word = (v) => v.toString(16).padStart(64, '0');

/** eth_call against the precompile; classify the outcome. */
async function ethCall(provider, data) {
  const started = Date.now();
  try {
    const result = await Promise.race([
      provider.send('eth_call', [{ to: PRECOMPILE, data: '0x' + data, gas: '0x100000' }, 'latest']),
      new Promise((_, rej) => setTimeout(() => rej(new Error('TIMEOUT')), RPC_TIMEOUT_MS)),
    ]);
    return { outcome: 'ok', ms: Date.now() - started, result };
  } catch (e) {
    if (e.message === 'TIMEOUT') return { outcome: 'timeout', ms: Date.now() - started };
    return { outcome: 'error', ms: Date.now() - started, message: e.message };
  }
}

(async () => {
  const provider = new WsProvider('ws://127.0.0.1:9955');
  const api = await ApiPromise.create({ provider, noInitWarn: true });
  const alice = new Keyring({ type: 'sr25519' }).addFromUri('//Alice');
  let nonce = (await api.rpc.system.accountNextIndex(alice.address)).toNumber();

  const height = async () => (await api.rpc.chain.getHeader()).number.toNumber();
  const stillAlive = async (label) => {
    const before = await height();
    await new Promise((res, rej) => {
      const t = setTimeout(() => rej(new Error('timeout')), 30_000);
      api.tx.system.remark('0x00').signAndSend(alice, { nonce: nonce++ }, ({ status }) => {
        if (status.isInBlock) { clearTimeout(t); res(); }
      }).catch(rej);
    });
    check(`node still producing blocks after ${label}`, (await height()) > before);
  };

  sect('Truncated offsets');

  // shield(uint32 asset_id, bytes32 commitment, bytes memo)
  // Head: [asset_id][commitment][memo offset]. The memo offset is the word the
  // decoder used to narrow with low_u32.
  const head = (memoOffset) =>
    SHIELD_SELECTOR + word(0n) + 'aa'.repeat(32) + word(memoOffset);

  const truncating = [
    ['2^32 + 96 (low bits look like a valid offset)', (1n << 32n) + 96n],
    ['2^32 exactly (truncates to 0)', 1n << 32n],
    ['2^64 + 96', (1n << 64n) + 96n],
    ['2^255 (top bit set)', 1n << 255n],
    ['uint256 max', (1n << 256n) - 1n],
  ];

  for (const [label, offset] of truncating) {
    // Pad out so a *truncated* offset would land inside the buffer — that is
    // what made the old code accept these.
    const data = head(offset) + word(4n) + 'ab'.repeat(4).padEnd(64, '0');
    const r = await ethCall(provider, data);
    check(`memo offset ${label} is refused`, r.outcome === 'error',
      `${r.outcome}${r.ms > 1000 ? ` in ${r.ms}ms` : ''}`);
  }

  await stillAlive('truncated offsets');

  sect('Overflowing lengths');

  // A valid offset pointing at a length word that would wrap the bounds check.
  const overflowing = [
    ['usize::MAX', (1n << 64n) - 1n],
    ['2^63 (wraps a 64-bit add)', 1n << 63n],
    ['2^32 (wraps a 32-bit usize under Wasm)', 1n << 32n],
    ['uint256 max', (1n << 256n) - 1n],
  ];

  for (const [label, length] of overflowing) {
    const data = head(96n) + word(length) + '00'.repeat(32);
    const r = await ethCall(provider, data);
    check(`memo length ${label} is refused`, r.outcome === 'error',
      `${r.outcome}${r.ms > 1000 ? ` in ${r.ms}ms` : ''}`);
  }

  await stillAlive('overflowing lengths');

  sect('Truncated uint32');

  // asset_id is declared uint32. A wider word used to keep its low bits, turning
  // a malformed call into a plausible one naming a different asset.
  for (const [label, assetId] of [
    ['2^32 + 0 (low bits = asset 0)', 1n << 32n],
    ['2^32 + 1', (1n << 32n) + 1n],
    ['uint256 max', (1n << 256n) - 1n],
  ]) {
    const data = SHIELD_SELECTOR + word(assetId) + 'aa'.repeat(32) + word(96n) +
      word(4n) + 'ab'.repeat(4).padEnd(64, '0');
    const r = await ethCall(provider, data);
    check(`asset_id ${label} is refused`, r.outcome === 'error',
      `${r.outcome}${r.ms > 1000 ? ` in ${r.ms}ms` : ''}`);
  }

  await stillAlive('truncated uint32');

  sect('Malformed shapes');

  for (const [label, data] of [
    ['selector only', SHIELD_SELECTOR],
    ['one byte short of a head', SHIELD_SELECTOR + '00'.repeat(95)],
    ['offset pointing past the buffer', head(1_000_000n)],
    ['offset pointing at itself', head(64n) + word(4n)],
    ['empty calldata', ''],
  ]) {
    const r = await ethCall(provider, data);
    check(`${label} is refused`, r.outcome === 'error',
      `${r.outcome}${r.ms > 1000 ? ` in ${r.ms}ms` : ''}`);
  }

  await stillAlive('malformed shapes');

  sect('Sustained pressure');

  // Repeated rejections must not accumulate anywhere: the guards run before any
  // allocation sized from calldata.
  const burst = [];
  for (let i = 0n; i < 40n; i++) {
    burst.push(ethCall(provider, head((1n << 32n) + i) + word((1n << 63n) + i)));
  }
  const results = await Promise.all(burst);
  const hung = results.filter((r) => r.outcome === 'timeout').length;
  const accepted = results.filter((r) => r.outcome === 'ok').length;
  const slowest = Math.max(...results.map((r) => r.ms));
  check('40 hostile calls, none hung', hung === 0, `slowest ${slowest}ms`);
  check('40 hostile calls, none accepted', accepted === 0, `${accepted} returned ok`);

  await stillAlive('a 40-call burst');

  sect('Well-formed calldata still works');

  // The guards must not reject real calls, or they trade one bug for a worse one.
  // A 180-byte memo is what the pallet requires.
  const goodMemo = 'ab'.repeat(180).padEnd(384, '0'); // 180 bytes padded to 32-byte boundary
  const good = SHIELD_SELECTOR + word(0n) + 'c1'.repeat(32) + word(96n) +
    word(180n) + goodMemo;
  const r = await ethCall(provider, good);
  // eth_call with no value fails at the pallet's zero-amount check, not in the
  // decoder — an ABI error would mean the guards broke valid encoding.
  // "amount must be non-zero" comes from the precompile's own msg.value guard,
  // which runs AFTER decoding — reaching it means the calldata decoded fine.
  // An ABI-layer message here would mean the guards broke valid encoding.
  const decoderRejected = r.outcome === 'error' &&
    /input too short|out of bounds|overflow|does not fit|exceeds u32|slot/i.test(r.message || '');
  check('well-formed calldata clears the decoder and reaches the pallet',
    !decoderRejected, r.message ? r.message.slice(0, 70) : r.outcome);

  await stillAlive('a well-formed call');

  await api.disconnect();
  console.log(`\n${ok.length} passed, ${bad.length} failed`);
  if (bad.length) console.log('Failed: ' + bad.join(', '));
  process.exit(bad.length ? 1 : 0);
})().catch((e) => { console.error('ERROR:', e.message); process.exit(1); });
