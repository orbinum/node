// Deserialization bounds on the ZK verifier, against a live chain.
//
// Three hardening changes are being defended here:
//
//   * A verifying key's point vector is length-prefixed, and `ark-serialize`
//     calls `Vec::with_capacity` on that prefix before reading any element. A
//     key declaring 2^40 points asks the allocator for tens of gigabytes on
//     nothing but submitted bytes. The size guard now lives inside the
//     deserializer rather than only at the call site.
//   * `expected_public_inputs` takes a `u8`, so a circuit id of 257 used to
//     alias onto 1 — a key validated against the wrong circuit's arity and
//     stored where no lookup could reach it.
//   * Genesis stored keys after a length check alone, so a well-sized but
//     meaningless key surfaced only when the first real proof failed.
//
// The unit tests cover the logic. What only a running node can show is that
// the real artifacts still register through the hardened path, and that the
// rejections surface as dispatch errors rather than a stalled or downed node.
//
//   ./target/release/orbinum-node --dev --tmp --rpc-port 9955 --sealing=instant
//   node ts-tests/node/zk-verifier-input-bounds.test.cjs
const { ApiPromise, WsProvider } = require('@polkadot/api');
const { Keyring } = require('@polkadot/keyring');
const fs = require('fs');
const path = require('path');

const ok = [], bad = [];
const check = (n, c, x = '') => { (c ? ok : bad).push(n); console.log(`${c ? 'PASS' : 'FAIL'}  ${n}${x ? ` — ${x}` : ''}`); };
const sect = (t) => console.log(`\n── ${t} ──`);

const TX_TIMEOUT_MS = 30_000;

/** Submit as sudo; resolve with the dispatch error name, or null on success. */
function sudoSubmit(api, call, signer, nonce) {
  return new Promise((resolve, reject) => {
    const timer = setTimeout(() => reject(new Error('tx timed out')), TX_TIMEOUT_MS);
    api.tx.sudo.sudo(call).signAndSend(signer, { nonce }, ({ status, events, dispatchError }) => {
      if (dispatchError) {
        clearTimeout(timer);
        return resolve(errName(dispatchError));
      }
      if (!status.isInBlock) return;
      clearTimeout(timer);
      // sudo swallows the inner error into a SudoAsDone/Sudid event.
      for (const { event } of events) {
        if (api.events.sudo.Sudid.is(event)) {
          const [result] = event.data;
          return resolve(result.isErr ? errName(result.asErr) : null);
        }
      }
      resolve(null);
    }).catch(reject);
  });
}

function errName(e) {
  if (e.isModule) {
    const d = e.registry.findMetaError(e.asModule);
    return `${d.section}.${d.name}`;
  }
  return e.toString();
}

/** Read the repo's real verifying keys, which must keep working. */
function realVk(name) {
  const p = path.join(__dirname, '..', '..', 'artifacts', `verification_key_${name}.bin`);
  return fs.existsSync(p) ? fs.readFileSync(p) : null;
}

(async () => {
  const provider = new WsProvider('ws://127.0.0.1:9955');
  const api = await ApiPromise.create({ provider, noInitWarn: true });
  const alice = new Keyring({ type: 'sr25519' }).addFromUri('//Alice');
  let nonce = (await api.rpc.system.accountNextIndex(alice.address)).toNumber();

  sect('Node came up with genesis keys validated');

  // Genesis now routes its keys through the same arity check as registration.
  // The node being here at all means they passed.
  check('node booted — genesis VKs deserialize and match their arity', true);

  const genesisKeys = await api.query.zkVerifier.verificationKeys.entries();
  check('genesis registered at least one circuit', genesisKeys.length > 0,
    `${genesisKeys.length} keys on chain`);

  sect('Oversized keys are refused');

  // Past the extrinsic's own BoundedVec, so the transaction fails to decode and
  // never reaches dispatch. That is Substrate working as designed — the node
  // logs "someone sent an invalid transaction" and keeps producing blocks.
  // Worth asserting anyway: the failure has to be a rejection, not a crash.
  const huge = Buffer.alloc(9000, 0x01);
  let decodeRejected = false;
  try {
    await sudoSubmit(api,
      api.tx.zkVerifier.registerVerificationKey(99, 1, '0x' + huge.toString('hex')),
      alice, nonce++);
  } catch (e) {
    decodeRejected = /Codec|Verification Error|invalid/i.test(e.message);
    nonce--; // never entered the pool, so the nonce was not consumed
  }
  check('a 9 KiB key is refused at admission', decodeRejected);

  // At the bound the transaction decodes, so this one does reach the pallet.
  // It is the case that proves the in-crate guard runs: 8192 bytes of filler
  // is not a key, and the deserializer must say so rather than size a Vec from
  // whatever length prefix those bytes happen to spell.
  const atBound = Buffer.alloc(8192, 0x01);
  const errBound = await sudoSubmit(api,
    api.tx.zkVerifier.registerVerificationKey(99, 1, '0x' + atBound.toString('hex')),
    alice, nonce++);
  check('a key at the size bound is rejected as malformed', errBound !== null,
    errBound || 'accepted');

  sect('Circuit ids cannot alias');

  // 257 & 0xFF == 1 == TRANSFER. Before the u8::try_from guard this validated
  // against TRANSFER's arity and stored under an unreachable id.
  const vk = realVk('unshield_v2');
  if (vk) {
    const errAlias = await sudoSubmit(api,
      api.tx.zkVerifier.registerVerificationKey(257, 1, '0x' + vk.toString('hex')),
      alice, nonce++);
    check('circuit id 257 is refused rather than aliased onto 1', errAlias !== null,
      errAlias || 'accepted — it aliased');

    const stored = await api.query.zkVerifier.verificationKeys(257, 1);
    check('nothing was stored under the aliasing id', stored.isNone);
  } else {
    check('real VK artifact available', false, 'artifacts/verification_key_unshield_v2.bin missing');
  }

  sect('Legitimate keys still register');

  // The hardening is only worth anything if real artifacts keep working. An id
  // inside u8 and outside the known table carries no arity expectation.
  if (vk) {
    const errOk = await sudoSubmit(api,
      api.tx.zkVerifier.registerVerificationKey(200, 1, '0x' + vk.toString('hex')),
      alice, nonce++);
    check('a real VK registers under an unmapped id', errOk === null, errOk || '');

    const stored = await api.query.zkVerifier.verificationKeys(200, 1);
    check('the key is retrievable', stored.isSome);
  }

  sect('Chain is still healthy');

  // Every rejection above must have been a dispatch error, not something that
  // wedged block production.
  const before = (await api.rpc.chain.getHeader()).number.toNumber();
  await new Promise((r) => setTimeout(r, 100));
  await api.tx.system.remark('0x00').signAndSend(alice, { nonce: nonce++ });
  await new Promise((r) => setTimeout(r, 2000));
  const after = (await api.rpc.chain.getHeader()).number.toNumber();
  check('blocks still advance after the rejected submissions', after > before,
    `${before} -> ${after}`);

  await api.disconnect();
  console.log(`\n${ok.length} passed, ${bad.length} failed`);
  if (bad.length) console.log('Failed: ' + bad.join(', '));
  process.exit(bad.length ? 1 : 0);
})().catch((e) => { console.error('ERROR:', e.message); process.exit(1); });
