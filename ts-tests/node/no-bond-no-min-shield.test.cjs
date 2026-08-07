/**
 * E2E: validator registration takes no bond, and shield takes no minimum.
 *
 * Both features were removed from the runtime, so the checks here are mostly
 * negative: the metadata must not advertise the constants any more, and the
 * calls that the constants used to gate must now go through.
 *
 * Run against a dev node on ws://127.0.0.1:9955.
 */
const { ApiPromise, WsProvider, Keyring } = require('@polkadot/api');
const assert = require('assert');

const WS = process.env.WS || 'ws://127.0.0.1:9955';
const TX_TIMEOUT_MS = 30_000;

let passed = 0;
let failed = 0;

async function test(name, fn) {
  try {
    await fn();
    console.log(`  ok    ${name}`);
    passed++;
  } catch (e) {
    console.log(`  FAIL  ${name}`);
    console.log(`        ${e.message}`);
    failed++;
  }
}

/** Submit and wait for inclusion, rejecting on dispatch error or timeout. */
function submit(tx, signer) {
  return new Promise((resolve, reject) => {
    const timer = setTimeout(() => reject(new Error('tx timed out')), TX_TIMEOUT_MS);
    tx.signAndSend(signer, ({ status, dispatchError }) => {
      if (dispatchError) {
        clearTimeout(timer);
        let msg = dispatchError.toString();
        if (dispatchError.isModule) {
          const d = dispatchError.registry.findMetaError(dispatchError.asModule);
          msg = `${d.section}.${d.name}`;
        }
        reject(new Error(msg));
      } else if (status.isInBlock) {
        clearTimeout(timer);
        resolve(status.asInBlock.toString());
      }
    }).catch(reject);
  });
}

/** 180-byte memo: nonce(12) + data(120) + MAC(16) + ephPk(32). */
function memo() {
  return '0x' + 'ab'.repeat(180);
}

// Commitments are unique per note on-chain, so a rerun against a node that
// already has the previous run's leaves would fail on CommitmentAlreadyExists.
// Seed from the clock so each run gets its own.
const RUN_SEED = Date.now().toString(16).padStart(12, '0').slice(-12);
let commitmentCounter = 0;

function freshCommitment() {
  commitmentCounter++;
  const tail = commitmentCounter.toString(16).padStart(4, '0');
  return '0x' + RUN_SEED.repeat(6).slice(0, 60) + tail;
}

(async () => {
  const api = await ApiPromise.create({ provider: new WsProvider(WS), noInitWarn: true });
  const keyring = new Keyring({ type: 'sr25519' });
  const alice = keyring.addFromUri('//Alice');

  console.log(`\nConnected to ${WS} — ${(await api.rpc.system.chain()).toString()}\n`);

  // ── metadata: the removed constants must be gone ──────────────────────────

  await test('validatorSet does not expose a ValidatorBond constant', async () => {
    assert.strictEqual(api.consts.validatorSet.validatorBond, undefined);
  });

  await test('shieldedPool does not expose a MinShieldAmount constant', async () => {
    assert.strictEqual(api.consts.shieldedPool.minShieldAmount, undefined);
  });

  await test('ValidatorBondOf storage is gone', async () => {
    assert.strictEqual(api.query.validatorSet.validatorBondOf, undefined);
  });

  await test('AmountTooSmall error is gone from shieldedPool metadata', async () => {
    const names = Object.keys(api.errors.shieldedPool);
    assert.ok(!names.includes('AmountTooSmall'), `found: ${names.join(', ')}`);
  });

  await test('InsufficientBond error is gone from validatorSet metadata', async () => {
    const names = Object.keys(api.errors.validatorSet);
    assert.ok(!names.includes('InsufficientBond'), `found: ${names.join(', ')}`);
  });

  await test('bond events are gone from validatorSet metadata', async () => {
    const names = Object.keys(api.events.validatorSet);
    assert.ok(!names.includes('ValidatorBondReserved'), 'ValidatorBondReserved still present');
    assert.ok(!names.includes('ValidatorBondReleased'), 'ValidatorBondReleased still present');
  });

  // ── shield: no minimum, but zero still rejected ───────────────────────────

  const assetId = 0;

  await test('shield of 1 planck is accepted', async () => {
    const commitment = freshCommitment();
    await submit(api.tx.shieldedPool.shield(assetId, 1, commitment, memo()), alice);
  });

  await test('shield of zero is rejected with InvalidAmount', async () => {
    const commitment = freshCommitment();
    await assert.rejects(
      () => submit(api.tx.shieldedPool.shield(assetId, 0, commitment, memo()), alice),
      (e) => e.message === 'shieldedPool.InvalidAmount',
      'expected shieldedPool.InvalidAmount',
    );
  });

  await test('a 1-planck shield actually lands in the pool balance', async () => {
    const before = (await api.query.shieldedPool.poolBalancePerAsset(assetId)).toBigInt();
    const commitment = freshCommitment();
    await submit(api.tx.shieldedPool.shield(assetId, 1, commitment, memo()), alice);
    const after = (await api.query.shieldedPool.poolBalancePerAsset(assetId)).toBigInt();
    assert.strictEqual(after - before, 1n, `pool moved by ${after - before}, expected 1`);
  });

  // ── register_validator: no funds reserved ─────────────────────────────────
  //
  // Alice already validates in dev, so she cannot re-register. Use a fresh
  // account funded with far less than the old 1 000 ORB bond: enough to pay the
  // fee, nowhere near enough to have posted a bond. Under the old rule this was
  // a guaranteed InsufficientBond. It must now reach the prerequisite gate,
  // which is the only thing left standing between an applicant and the queue.

  const POOR = 10n ** 18n; // 1 ORB — 1/1000th of the bond that used to be required

  await test('an account holding far less than the old bond reaches the prerequisite gate', async () => {
    const poor = keyring.addFromUri('//PoorValidator');
    await submit(api.tx.balances.transferKeepAlive(poor.address, POOR), alice);

    const free = (await api.query.system.account(poor.address)).data.free.toBigInt();
    assert.ok(free > 0n && free < 1000n * 10n ** 18n, `unexpected balance ${free}`);

    await assert.rejects(
      () => submit(api.tx.validatorSet.registerValidator(), poor),
      (e) => e.message === 'validatorSet.NoSessionKeys' || e.message === 'validatorSet.NoRelayer',
      'expected a prerequisite failure — a funding failure would mean the bond survived',
    );

    // The failed attempt must not have reserved anything.
    const after = (await api.query.system.account(poor.address)).data;
    assert.strictEqual(after.reserved.toBigInt(), 0n, 'registration reserved funds');
  });

  await test('no account on chain holds a reserved validator bond', async () => {
    const entries = await api.query.system.account.entries();
    const reserved = entries.filter(([, v]) => v.data.reserved.toBigInt() > 0n);
    assert.strictEqual(reserved.length, 0, `${reserved.length} accounts still hold reserves`);
  });

  await api.disconnect();

  console.log(`\n${passed} passed, ${failed} failed\n`);
  process.exit(failed === 0 ? 0 : 1);
})().catch((e) => {
  console.error('fatal:', e.message);
  process.exit(1);
});
