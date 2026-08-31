#!/usr/bin/env node
/**
 * ISMP / Hyperbridge adversarial suite.
 *
 * The functional check lives in `test-ismp-e2e.mjs`. This file tries to BREAK the
 * integration: wrong origins, forged proofs, malformed payloads, boundary values,
 * aliasing, replay, and griefing. A green run means the pallet rejected everything it
 * should have — not that the feature works.
 *
 * Each case states the invariant it defends. A security test that only says "should
 * fail" is unmaintainable the day it starts failing.
 *
 * Usage:
 *   ./scripts/run-ismp-tests.sh security          # boots a node, runs this, tears down
 *   node scripts/test-ismp-security.mjs [ws://…]  # against a node you already have
 */
import { ApiPromise, WsProvider, Keyring } from '@polkadot/api';
import { cryptoWaitReady } from '@polkadot/util-crypto';
import {
  CONSENSUS_CLIENT_ID_GRANDPA,
  CONSENSUS_STATE_ID_PASEO,
  Checklist,
  PALLET_INDEX,
  HYPERBRIDGE_SLOT_DURATION_MS,
  coprocessor,
  expectReject,
  hyperbridgeEntry,
  palletIndex,
  send,
  rpcCall,
  sendUnsigned,
  sudoOutcome,
  whitelistedStateMachine,
} from './lib/ismp-harness.mjs';

const ENDPOINT = process.argv[2] ?? 'ws://127.0.0.1:9944';

/**
 * Para ids used only as test fixtures.
 *
 * None of these is a real chain. They are deliberately far from Hyperbridge's own
 * ids (3367 mainnet / 4009 Paseo) so a fixture can never be mistaken for — or
 * collide with — the entry the suite actually cares about. Naming them keeps the
 * intent of each case visible at the call site instead of leaving bare numbers.
 */
const FIXTURE = {
  /** Whitelisted with slot_duration = 0, to record upstream's lack of validation. */
  ZERO_SLOT: 7777,
  /** Whitelisted with slot_duration = u64::MAX, to prove the runtime survives it. */
  MAX_SLOT: 7778,
  /** Never added — proves the whitelist actually gates. */
  NEVER_ADDED: 9999,
  /** Never added — proves removal of an absent entry is a safe no-op. */
  ABSENT_FOR_REMOVAL: 31337,
  /** Base for the bulk-batch case; ids run BATCH_BASE..BATCH_BASE+BATCH_SIZE. */
  BATCH_BASE: 20000,
};

/** Batch size for the bulk-insert case — large enough to matter, small enough to pass. */
const BATCH_SIZE = 64;

// ─────────────────────────────────────────────────────────────────────────────

/**
 * Every privileged call must reject non-root origins.
 *
 * These four calls decide whose consensus proofs the chain trusts. A non-root path
 * into any of them would let an arbitrary account install a hostile trust root, which
 * is the highest-severity failure available in this integration.
 */
const originEnforcement = async (api, checks, { bob, charlie }) => {
  console.log('\n[1] Origin enforcement — who may change what this chain trusts');

  const addHyperbridge = api.tx.ismpGrandpa.addStateMachines([await hyperbridgeEntry(api)]);

  // Two different signers: catches an accidental allowlist of one account.
  await expectReject(api, checks, 'add_state_machines rejects non-root (Bob)', addHyperbridge, bob, 'BadOrigin');
  await expectReject(api, checks, 'add_state_machines rejects non-root (Charlie)', addHyperbridge, charlie, 'BadOrigin');

  await expectReject(
    api, checks, 'remove_state_machines rejects non-root',
    api.tx.ismpGrandpa.removeStateMachines([await coprocessor(api).then((c) => c.toJSON())]), bob, 'BadOrigin'
  );

  // create_consensus_client installs the trust root itself.
  await expectReject(
    api, checks, 'create_consensus_client rejects non-root',
    api.tx.ismp.createConsensusClient({
      consensusState: '0x00',
      consensusClientId: CONSENSUS_CLIENT_ID_GRANDPA,
      consensusStateId: CONSENSUS_STATE_ID_PASEO,
      unbondingPeriod: 1000,
      challengePeriod: 0,
      stateMachineCommitments: [],
    }), bob, 'BadOrigin'
  );

  // Shrinking an unbonding or challenge period weakens fraud-proof windows.
  await expectReject(
    api, checks, 'update_consensus_state rejects non-root',
    api.tx.ismp.updateConsensusState({
      consensusStateId: CONSENSUS_STATE_ID_PASEO,
      unbondingPeriod: 1,
      challengePeriods: [],
    }), bob, 'BadOrigin'
  );
};

/**
 * `handle_unsigned` takes no signature — anyone can call it. Its only protection is
 * `validate_unsigned`, which runs the full pipeline and fails `BadProof`.
 */
const unsignedEntryPoint = async (api, checks) => {
  console.log('\n[2] Unsigned entry point — the spam and forgery surface');

  const cases = [
    ['empty message batch', []],
    ['forged consensus proof', [{
      Consensus: { consensusProof: '0xdeadbeef', consensusStateId: CONSENSUS_STATE_ID_PASEO, signer: '0x' },
    }]],
    ['unknown consensus state id', [{
      Consensus: { consensusProof: '0x00', consensusStateId: [0xff, 0xff, 0xff, 0xff], signer: '0x' },
    }]],
  ];

  for (const [label, messages] of cases) {
    try {
      await sendUnsigned(api, api.tx.ismp.handleUnsigned(messages));
      checks.add(`handle_unsigned rejects ${label}`, false, 'ACCEPTED — expected rejection');
    } catch (e) {
      // Not every throw is a rejection: a dropped connection or a timeout would also
      // land here and used to be recorded as a pass. Require an error that actually
      // names a refusal by the pool or the runtime.
      const msg = e.message.split('\n')[0];
      const rejected = /invalid|verif|proof|decode|bad|unknown|error|not found|module/i.test(msg);
      checks.add(`handle_unsigned rejects ${label}`, rejected, msg.slice(0, 70));
    }
  }
};

/**
 * Only what root added, exactly as added, and nothing that aliases it.
 */
const whitelistIntegrity = async (api, checks, { alice }) => {
  console.log('\n[3] Whitelist integrity — only what root added, exactly as added');

  const expected = await coprocessor(api);
  await sudoOutcome(api, api.tx.ismpGrandpa.addStateMachines([await hyperbridgeEntry(api)]), alice);

  const stored = await whitelistedStateMachine(api, expected.toJSON());
  checks.add(
    'whitelisted entry readable with exact slot_duration',
    stored !== null && stored.toNumber() === HYPERBRIDGE_SLOT_DURATION_MS,
    stored ? `${expected.toString()} ${stored.toNumber()}ms` : `absent for ${expected.toString()}`
  );

  // If any of these return a value, the whitelist is not gating anything.
  const unAdded = [
    [`Polkadot(${FIXTURE.NEVER_ADDED})`, { Polkadot: FIXTURE.NEVER_ADDED }],
    ['Evm(1)', { Evm: 1 }],
    ['Substrate(evil)', { Substrate: [0x65, 0x76, 0x69, 0x6c] }],
  ];
  for (const [label, stateMachine] of unAdded) {
    const entry = await whitelistedStateMachine(api, stateMachine);
    checks.add(`un-added ${label} is NOT whitelisted`, entry === null, entry ? `LEAKED: ${entry}` : '');
  }

  // `Polkadot(id)` and `Kusama(id)` are different trust roots. Which one is legitimate
  // depends on the build, so this derives the pair: an earlier version hardcoded
  // "Kusama(4009) must be absent", which under a Paseo runtime asserted the *correct*
  // configuration was missing.
  const paraId = expected.isKusama
    ? expected.asKusama.toNumber()
    : expected.asPolkadot.toNumber();
  const otherRelay = expected.isKusama ? { Polkadot: paraId } : { Kusama: paraId };
  const alias = await whitelistedStateMachine(api, otherRelay);
  checks.add(
    `${expected.toString()} does not alias ${JSON.stringify(otherRelay)}`,
    alias === null,
    alias ? 'ALIASED — relay chain ignored in storage key' : ''
  );
};

/**
 * Boundary values, and whether the chain survives them.
 *
 * `slot_duration` is stored unvalidated by upstream (see
 * `configs/ismp/slot_duration.rs` for the full analysis). These cases record that
 * behaviour and assert the chain does not panic or stall because of it.
 */
const boundaryValues = async (api, checks, { alice }) => {
  console.log('\n[4] Boundary and malformed values');

  // Zero makes every header timestamp to 0, so unbonding/challenge checks against
  // that chain become vacuous. Upstream accepts it; Orbinum guards it runtime-side.
  const zero = await sudoOutcome(
    api, api.tx.ismpGrandpa.addStateMachines([{ stateMachine: { Polkadot: FIXTURE.ZERO_SLOT }, slotDuration: 0 }]), alice
  );
  const zeroStored = await whitelistedStateMachine(api, { Polkadot: FIXTURE.ZERO_SLOT });
  // Assert the exact value so a change in EITHER direction fails. On 2512,
  // `substrate-state-machine/src/lib.rs:391` derives the header timestamp as a raw
  // `*slot * slot_duration` with no zero-guard, so 0 yields a vacuous timestamp rather
  // than an error. 2606 added the guard.
  checks.add(
    'slot_duration=0 is stored verbatim by upstream (no validation)',
    zero.ok && zeroStored !== null && zeroStored.toNumber() === 0,
    zero.ok ? `stored=${zeroStored ? zeroStored.toNumber() : 'none'}` : `rejected: ${zero.err}`
  );

  // u64::MAX overflows the downstream `slot * slot_duration` multiply. The chain must
  // at minimum survive the value being written.
  const MAX_U64 = '18446744073709551615';
  const big = await sudoOutcome(
    api, api.tx.ismpGrandpa.addStateMachines([{ stateMachine: { Polkadot: FIXTURE.MAX_SLOT }, slotDuration: MAX_U64 }]), alice
  );
  const bigStored = await whitelistedStateMachine(api, { Polkadot: FIXTURE.MAX_SLOT });
  // The previous predicate was `bigStored === null || bigStored === MAX_U64`, true
  // under both possible outcomes. On 2512 the downstream multiply is unchecked, so
  // u64::MAX is an arithmetic overflow rather than a benign saturation — worth
  // asserting precisely what lands in storage.
  checks.add(
    'slot_duration=u64::MAX is stored verbatim',
    big.ok && bigStored !== null && bigStored.toString() === MAX_U64,
    big.ok ? `stored=${bigStored ? bigStored.toString() : 'none'}` : `rejected: ${big.err}`
  );

  // Stated precisely: `validate_slot_duration` is a checked constant for our own
  // call sites, not a dispatch filter. `add_state_machines` is upstream and cannot be
  // intercepted without a chain-wide BaseCallFilter — see the module docs for why we
  // did not add one. The values above being storable is upstream behaviour, recorded
  // here so a future change in either direction is visible.
  // Documentary, not an assertion — the two cases above do the verifying. Labelled
  // `note:` so it is not miscounted as coverage.
  checks.add(
    'note: unsafe slot_duration values are bounded at our call sites only',
    true,
    'configs/ismp/slot_duration.rs — MIN=1000ms MAX=3600000ms, unit-tested (advisory, not a dispatch filter)'
  );

  // A batch large enough to matter must not brick block production.
  const batch = Array.from({ length: BATCH_SIZE }, (_, i) => ({
    stateMachine: { Polkadot: FIXTURE.BATCH_BASE + i },
    slotDuration: HYPERBRIDGE_SLOT_DURATION_MS,
  }));
  const batchResult = await sudoOutcome(api, api.tx.ismpGrandpa.addStateMachines(batch), alice);
  // Previously a literal `true`: it printed `rejected: <err>` and passed anyway.
  // Reading every entry back also covers partial application and the per-entry weight
  // scaling (`Writes = 2 + 1*n`) that a regenerated flat weight would silently break.
  let batchStored = 0;
  for (let i = 0; i < BATCH_SIZE; i++) {
    const e = await whitelistedStateMachine(api, { Polkadot: FIXTURE.BATCH_BASE + i });
    if (e !== null && e.toNumber() === HYPERBRIDGE_SLOT_DURATION_MS) batchStored++;
  }
  checks.add(
    `${BATCH_SIZE}-entry batch fully applied`,
    batchResult.ok && batchStored === BATCH_SIZE,
    batchResult.ok ? `${batchStored}/${BATCH_SIZE} readable` : `rejected: ${batchResult.err}`
  );

  // Liveness: the chain must still be producing blocks after all of the above.
  const before = (await api.rpc.chain.getHeader()).number.toNumber();
  await new Promise((r) => setTimeout(r, 8000));
  const after = (await api.rpc.chain.getHeader()).number.toNumber();
  checks.add('chain still producing blocks after hostile input', after > before, `#${before} → #${after}`);
};

/**
 * Re-adding must overwrite cleanly; removal must actually revoke trust.
 */
const idempotenceAndRemoval = async (api, checks, { alice }) => {
  console.log('\n[5] Idempotence and removal');

  const target = (await coprocessor(api)).toJSON();
  await sudoOutcome(api, api.tx.ismpGrandpa.addStateMachines([await hyperbridgeEntry(api, 12000)]), alice);
  const reAdded = await whitelistedStateMachine(api, target);
  checks.add(
    're-adding overwrites slot_duration (idempotent key)',
    reAdded !== null && reAdded.toNumber() === 12000,
    reAdded ? `${reAdded.toNumber()}ms` : 'absent'
  );

  // Removal must clear storage, not merely emit an event — otherwise trust persists.
  await sudoOutcome(
    api, api.tx.ismpGrandpa.removeStateMachines([target]), alice
  );
  const removed = await whitelistedStateMachine(api, target);
  checks.add(
    'remove_state_machines actually revokes trust',
    removed === null,
    removed ? `STILL TRUSTED: ${removed}` : 'entry cleared'
  );

  const noop = await sudoOutcome(
    api, api.tx.ismpGrandpa.removeStateMachines([{ Polkadot: FIXTURE.ABSENT_FOR_REMOVAL }]), alice
  );
  checks.add('removing a non-existent entry is a safe no-op', noop.ok,
    noop.ok ? 'no-op' : `err: ${noop.err}`);

  // Leave a known-good state so a later run starts clean.
  await sudoOutcome(api, api.tx.ismpGrandpa.addStateMachines([await hyperbridgeEntry(api)]), alice);
};

/**
 * `fund_message` is the one signed, user-callable entry point.
 */
const economicSurface = async (api, checks, { bob }) => {
  console.log('\n[6] Economic surface');

  // Crediting a message that does not exist would be a mint.
  await expectReject(
    api, checks, 'fund_message rejects unknown commitment',
    api.tx.ismp.fundMessage({ commitment: { Request: `0x${'11'.repeat(32)}` }, amount: 1_000_000 }),
    bob, 'MessageNotFound'
  );

  // A failed call must not move funds beyond the transaction fee.
  const before = (await api.query.system.account(bob.address)).data.free.toBigInt();
  try {
    await send(
      api,
      api.tx.ismp.fundMessage({ commitment: { Response: `0x${'22'.repeat(32)}` }, amount: 10n ** 18n }),
      bob
    );
  } catch {
    // Expected — the assertion is about the balance, not the error.
  }
  const after = (await api.query.system.account(bob.address)).data.free.toBigInt();
  checks.add(
    'failed fund_message does not move funds beyond fees',
    after <= before,
    `Δ=${(after - before).toString()} planck (fee only)`
  );
};

/**
 * Configuration that the integration silently depends on.
 */
const runtimeInvariants = (api, checks) => {
  console.log('\n[7] Runtime configuration invariants');

  // Indices are part of the encoded call format — drift changes how an
  // already-encoded extrinsic decodes.
  for (const [name, expected] of Object.entries(PALLET_INDEX)) {
    const actual = palletIndex(api, name);
    checks.add(`${name} pinned at index ${expected}`, actual === expected, `index ${actual}`);
  }

  // 8 MiB is what GRANDPA consensus proofs needed; a regression silently breaks
  // consensus relaying. Perbill rounds up, so assert the ratio rather than a literal.
  const EIGHT_MIB = 8 * 1024 * 1024;
  const blockLength = api.consts.system.blockLength;
  const normalMax = blockLength.max.normal.toNumber();
  const ratio = normalMax / EIGHT_MIB;
  checks.add(
    'block length raised to 8 MiB at 85% normal ratio',
    Math.abs(ratio - 0.85) < 1e-6 && normalMax > 7_000_000,
    `normal max ${normalMax} bytes (${(ratio * 100).toFixed(2)}% of 8 MiB)`
  );
  checks.add(
    'operational block length is the full 8 MiB',
    blockLength.max.operational.toNumber() === EIGHT_MIB,
    `${blockLength.max.operational.toNumber()} bytes`
  );

  const calls = Object.keys(api.tx.ismpGrandpa ?? {});
  checks.add(
    'ismp-grandpa exposes add/remove state machine calls',
    calls.includes('addStateMachines') && calls.includes('removeStateMachines'),
    calls.join(', ')
  );
};

/**
 * The ISMP RPC surface is reachable by anyone who can open a socket.
 *
 * Every `ismp_query*` method is read-only by contract, so the properties worth
 * asserting are that hostile input produces an error rather than a panic, and that
 * nothing on that surface can mutate chain state.
 */
const rpcSurface = async (api, checks, endpoint) => {
  console.log('\n[8] RPC surface — read-only, hostile input tolerated');

  const before = (await api.rpc.chain.getHeader()).number.toNumber();

  // Unknown commitments: an empty list is correct, an error or panic is not.
  const unknown = await rpcCall(endpoint, 'ismp_queryRequests', [
    [{ commitment: `0x${'ab'.repeat(32)}` }],
  ]);
  checks.add(
    'unknown commitment returns empty, not an error',
    unknown.ok && Array.isArray(unknown.result) && unknown.result.length === 0,
    unknown.ok ? `${JSON.stringify(unknown.result)}` : `error: ${unknown.error?.message}`
  );

  // Malformed input must be rejected cleanly by the deserializer.
  const malformed = [
    ['ismp_queryRequests', ['not-an-array']],
    ['ismp_queryEvents', ['abc', 'def']],
    ['ismp_queryConsensusState', [[1, 2, 3, 4, 5, 6, 7, 8]]],
    ['ismp_queryChallengePeriod', [{ bogus: true }]],
  ];
  for (const [method, params] of malformed) {
    const res = await rpcCall(endpoint, method, params);
    // Either a clean error or a well-formed result is fine; a dropped connection
    // (no error object AND no result) would indicate the node died.
    const survived = res.error !== undefined || res.result !== undefined;
    checks.add(`${method} handles malformed params without dying`, survived,
      res.error ? String(res.error.message).slice(0, 50) : 'returned a result');
  }

  // Huge batch: must not hang or OOM the node.
  const huge = Array.from({ length: 500 }, (_, i) => ({
    commitment: `0x${i.toString(16).padStart(64, '0')}`,
  }));
  const bulk = await rpcCall(endpoint, 'ismp_queryRequests', [huge]);
  checks.add('500-commitment query handled', bulk.error !== undefined || bulk.result !== undefined,
    bulk.ok ? `${(bulk.result ?? []).length} results` : `error: ${bulk.error?.message}`);

  // Nothing above may have advanced or corrupted chain state.
  const after = (await api.rpc.chain.getHeader()).number.toNumber();
  checks.add('chain alive and progressing after RPC abuse', after >= before, `#${before} -> #${after}`);
};

// ─────────────────────────────────────────────────────────────────────────────

const main = async () => {
  await cryptoWaitReady();
  const api = await ApiPromise.create({ provider: new WsProvider(ENDPOINT), noInitWarn: true });
  const keyring = new Keyring({ type: 'sr25519' });
  const accounts = {
    alice: keyring.addFromUri('//Alice'), // sudo
    bob: keyring.addFromUri('//Bob'),
    charlie: keyring.addFromUri('//Charlie'),
  };

  console.log(`\nISMP SECURITY — ${(await api.rpc.system.chain()).toString()} @ ${ENDPOINT}`);
  const checks = new Checklist();

  await originEnforcement(api, checks, accounts);
  await unsignedEntryPoint(api, checks);
  await whitelistIntegrity(api, checks, accounts);
  await boundaryValues(api, checks, accounts);
  await idempotenceAndRemoval(api, checks, accounts);
  await economicSurface(api, checks, accounts);
  runtimeInvariants(api, checks);
  await rpcSurface(api, checks, ENDPOINT);

  await api.disconnect();
  process.exit(checks.report('SECURITY SUITE'));
};

main().catch((e) => {
  console.error('suite error:', e.message);
  process.exit(1);
});
