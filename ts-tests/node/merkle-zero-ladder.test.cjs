// The zero-hash ladder must not have moved.
//
// `zero_hash_at_level` was recursive — one stack frame per level, against the
// runtime's fixed 1 MB Wasm stack, where an overflow downs the node instead of
// failing a call. It is now a loop. Unreachable either way today, since every
// caller passes level < 21 and integrity_test pins MaxTreeDepth at 20, but the
// ladder is `pub` and the bound lived elsewhere.
//
// What has to hold: the digests are identical. These hashes stand in for empty
// subtrees inside every Merkle path the chain serves, so a divergence at any
// level would invalidate proofs against notes already on chain — including
// notes that exist now.
//
// Unit tests compare the loop against a recursive reference in isolation. Only
// a running node shows the ladder inside real roots and real paths, computed by
// the Wasm runtime rather than natively.
//
//   ./target/release/orbinum-node --dev --tmp --rpc-port 9955 --sealing=instant
//   node ts-tests/node/merkle-zero-ladder.test.cjs
const { ApiPromise, WsProvider } = require('@polkadot/api');
const { Keyring } = require('@polkadot/keyring');

const ok = [], bad = [];
const check = (n, c, x = '') => { (c ? ok : bad).push(n); console.log(`${c ? 'PASS' : 'FAIL'}  ${n}${x ? ` — ${x}` : ''}`); };
const sect = (t) => console.log(`\n── ${t} ──`);

const TX_TIMEOUT_MS = 30_000;

function submit(tx, signer, nonce) {
  return new Promise((resolve, reject) => {
    const timer = setTimeout(() => reject(new Error('tx timed out')), TX_TIMEOUT_MS);
    tx.signAndSend(signer, { nonce }, ({ status, dispatchError }) => {
      if (dispatchError) {
        clearTimeout(timer);
        const msg = dispatchError.isModule
          ? (() => { const d = dispatchError.registry.findMetaError(dispatchError.asModule); return `${d.section}.${d.name}`; })()
          : dispatchError.toString();
        return reject(new Error(msg));
      }
      if (status.isInBlock) { clearTimeout(timer); resolve(); }
    }).catch(reject);
  });
}

const memo = () => '0x' + 'ab'.repeat(180);

// The zero-hash ladder as the pallet computes it: level 0 is the zero digest,
// each level above is hash_pair(prev, prev).
//
// Pinned rather than recomputed here. These are the digests a chain that already
// exists built its Merkle paths from, so a mismatch means the rewrite moved the
// ladder and every proof against an existing note is void. Deriving them in the
// test would only prove the test agrees with itself.
const ZERO_LADDER = [
  '0x0000000000000000000000000000000000000000000000000000000000000000',
  '0x6448b64684ee39a823d5fe5fd52431dc81e4817bf2c3ea3cab9e239efbf59820',
  '0xe1f1b1604477a467f08dc69dcb441a26eca784f56f1a30df6322b1cd3d676910',
  '0x38d256b8b27ed528d51d3750ea6e7c460621f7508d753d2eafe27e533133f418',
  '0x2a95bc9d5597acca6582561a5728b7f14523a53be9ff2063d3b017cb37d8f907',
  '0x553f183916ec5c7b4dadb2948cc599a60729f35d4c1f63c9f5b346875ecf942b',
  '0x789da02ea3dd111d6153b951691ed7febce1a9cc227dea46964566a6c593ee2d',
  '0x9d34873cbeaaa4a87facb58ca815058b7b5939b61e60cf82e9842ba2e5958207',
  '0x61ccf3993abe4c441a21414a272e6b612a47644586ec1b50a627608ff1e5a52f',
  '0x47d7fc14a656213eab28e2e3cc7a5ee4661f949e3880b7ec21fdd8d07643880e',
  '0xf20a19dae57561de33357157f99258f969b42ea5d17a71281e4f4972da01721b',
  '0x36767dcefa6bbcbeb5080865e4e1e6a619982401b2c0005238365e7222888d1f',
  '0x5af8b571049a87d0a888cf2aa1b06261fbfc8cba891570b9af4b916cf6825d2c',
  '0xd0bfbfe070f2586464f413a1aac4f54e13a13fdf5a7f9520b80b94a04841c514',
  '0x0ce8ebf44b8e1116d489ad8c5825be11afb9d844eec0101e966f982fb1330d19',
  '0x926ce0259364b3a50a51af9665ae6711ed73ad14493517ac524170cea98af922',
  '0x2373ba8bd353b7f8eecc6ec6296f525a576abf728d226f9f0b88e56c9b7c7c2a',
  '0x92b9363f64dd754d958b98c2c9430047fc3f464dc1f97ac6c18e6958e586812e',
  '0x0ff11f1c9d24463527927364ad6eef8a94ae0d05cfc8e249ab4e9a1e57c5570f',
  '0xca2cf73461e39c3ce4467d6910e378fe1c0e8088433df6d54a55fbb567ee3018',
];

(async () => {
  const provider = new WsProvider('ws://127.0.0.1:9955');
  const api = await ApiPromise.create({ provider, noInitWarn: true });
  const alice = new Keyring({ type: 'sr25519' }).addFromUri('//Alice');
  const q = api.query.shieldedPool;
  let nonce = (await api.rpc.system.accountNextIndex(alice.address)).toNumber();

  sect('Connected');

  // The ladder is only visible in a path when the levels above the leaf are
  // genuinely empty. On a tree that already holds leaves those siblings are
  // real subtrees, and comparing them against the ladder reports a divergence
  // that is not one — so require a fresh chain rather than assume it.
  const size = (await q.merkleTreeSize()).toNumber();
  check('tree is empty — the ladder is only readable from a fresh chain',
    size === 0, `size=${size}${size ? ' — restart the node with --tmp' : ''}`);
  if (size !== 0) {
    console.log('\nAborting: this test needs an empty tree.');
    await api.disconnect();
    process.exit(1);
  }

  sect('The ladder inside real Merkle paths');

  // A path for a lone leaf is all zero-hashes above level 0: every sibling is an
  // empty subtree, so the path is the ladder read back one level at a time.
  const RUN = require('crypto').randomBytes(4).toString('hex');
  const commitment = '0x' + RUN + 'ce'.repeat(28);
  await submit(api.tx.shieldedPool.shield(0, 10n ** 18n, commitment, memo()), alice, nonce++);

  const leafIndex = (await q.commitmentToLeafIndex(commitment)).unwrap().toNumber();
  const proof = await provider.send('privacy_getMerkleProof', [leafIndex]);

  check('path has one sibling per level', proof.path.length === 20,
    `${proof.path.length} siblings`);

  // Levels 1..19 of a single-leaf tree are empty subtrees, so each sibling must
  // equal the ladder entry for its level. Level 0's sibling is the empty leaf
  // slot, which is the zero digest itself.
  const distinct = new Set(proof.path);
  check('every level contributes a distinct zero digest', distinct.size === proof.path.length,
    `${distinct.size} distinct of ${proof.path.length} — a collapsed ladder would repeat`);

  check('level 0 sibling is the zero digest', proof.path[0] === '0x' + '00'.repeat(32),
    proof.path[0].slice(0, 20) + '…');

  sect('Paths still verify against the root');

  // The end that matters: whatever the ladder produces, a proof built from it
  // has to anchor to the root the chain reports.
  const rootAfter = (await q.poseidonRoot()).toHex();
  check('proof anchors to the current root', proof.root === rootAfter,
    `${proof.root.slice(0, 20)}…`);

  // A second leaf makes level 0 a real sibling while levels 1+ stay empty, so
  // the ladder is still doing the work above it.
  const c2 = '0x' + RUN + 'df'.repeat(28);
  await submit(api.tx.shieldedPool.shield(0, 10n ** 18n, c2, memo()), alice, nonce++);
  const idx2 = (await q.commitmentToLeafIndex(c2)).unwrap().toNumber();
  const proof2 = await provider.send('privacy_getMerkleProof', [idx2]);

  check('second leaf pairs with the first at level 0', proof2.path[0] === commitment,
    `${proof2.path[0].slice(0, 20)}…`);
  check('levels above stay on the ladder',
    proof2.path.slice(1).every((h, i) => h === proof.path[i + 1]),
    'siblings above level 0 unchanged');
  check('second proof anchors to the new root',
    proof2.root === (await q.poseidonRoot()).toHex());

  // The check this file exists for. With two leaves, levels 1..19 are still
  // empty subtrees, so those siblings ARE the ladder — computed by the Wasm
  // runtime, not by a native unit test. Any level that moved shows up here.
  const moved = [];
  for (let level = 1; level < 20; level++) {
    if (proof2.path[level] !== ZERO_LADDER[level]) {
      moved.push(`level ${level}: ${proof2.path[level].slice(0, 18)}… != ${ZERO_LADDER[level].slice(0, 18)}…`);
    }
  }
  check('every ladder level matches the pinned digest', moved.length === 0,
    moved.length ? moved.join('; ') : 'levels 1-19 unchanged');

  sect('Chain is healthy');

  const before = (await api.rpc.chain.getHeader()).number.toNumber();
  await submit(api.tx.system.remark('0x00'), alice, nonce++);
  const after = (await api.rpc.chain.getHeader()).number.toNumber();
  check('blocks still advance', after > before, `${before} -> ${after}`);

  await api.disconnect();
  console.log(`\n${ok.length} passed, ${bad.length} failed`);
  if (bad.length) console.log('Failed: ' + bad.join(', '));
  process.exit(bad.length ? 1 : 0);
})().catch((e) => { console.error('ERROR:', e.message); process.exit(1); });
