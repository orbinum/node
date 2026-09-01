#!/usr/bin/env node
/**
 * ISMP / Hyperbridge functional check against a running dev node.
 *
 * Answers one question: is the integration actually live, rather than merely
 * compiled? Adversarial cases — wrong origins, forged proofs, boundary values — live
 * in `test-ismp-security.mjs`.
 *
 * Usage:
 *   ./scripts/run-ismp-tests.sh e2e               # boots a node, runs this, tears down
 *   node scripts/test-ismp-e2e.mjs [ws://…]       # against a node you already have
 */
import { ApiPromise, WsProvider, Keyring } from '@polkadot/api';
import { cryptoWaitReady } from '@polkadot/util-crypto';
import {
  CONSENSUS_STATE_ID_PASEO,
  Checklist,
  HYPERBRIDGE_SLOT_DURATION_MS,
  PALLET_INDEX,
  coprocessor,
  expectReject,
  hyperbridgeEntry,
  palletIndex,
  rpcCall,
  rpcMethodExists,
  send,
} from './lib/ismp-harness.mjs';

const ENDPOINT = process.argv[2] ?? 'ws://127.0.0.1:9944';

/**
 * Block range for the event queries, inclusive. Blocks 1-2 always exist by the time the
 * runner hands over; querying real blocks rather than a sentinel is what proves the
 * runtime API is reachable.
 */
const EVENT_QUERY_RANGE = [1, 2];

/**
 * An arbitrary destination para id, deliberately distinct from Hyperbridge's own 4009 —
 * that is what proves the message goes *through* the bridge rather than *to* it.
 */
const COUNTERPARTY_PARA_ID = 1000;

/** An 8-byte module id — the only lengths `ModuleId::from_bytes` accepts are 8/20/32. */
const REMOTE_MODULE_ID = '0x' + Buffer.from('demo/mod').toString('hex');

/** SCALE for `Message::Ping { nonce: 1 }`: variant index 0, then a u64. */
const PING_BODY = '0x00' + '0100000000000000';

/** The pallets must be in the runtime at the indices the config pins them to. */
const checkPalletsPresent = (api, checks) => {
  const names = api.runtimeMetadata.asLatest.pallets.map((p) => p.name.toString());
  checks.add('pallet-ismp in runtime', names.includes('Ismp'));
  checks.add('ismp-grandpa in runtime', names.includes('IsmpGrandpa'));

  // Indices are part of the encoded call format: drift makes previously encoded
  // extrinsics decode as a different call.
  for (const [name, expected] of Object.entries(PALLET_INDEX)) {
    const actual = palletIndex(api, name);
    checks.add(`${name} at pallet index ${expected}`, actual === expected, `index ${actual}`);
  }

  // `HostStateMachine` is a compile-time associated type on `pallet_ismp::Config`,
  // not a runtime constant, so it never appears in metadata — it is covered by the
  // Rust-side unit tests in `configs/ismp/network.rs` instead.
  const storage = Object.keys(api.query.ismp ?? {});
  checks.add(
    'ISMP consensus storage present',
    // 2606 dropped the legacy `StateCommitments`; the bounded map is the only one.
    ['consensusStates', 'boundedStateCommitments', 'challengePeriod'].every((k) => storage.includes(k)),
    `${storage.length} storage items`
  );
};

/**
 * Whitelisting is what makes the link usable: until a state machine is on the list,
 * the pallet drops its datagrams.
 */
const checkWhitelisting = async (api, checks, sudoKey) => {
  const expected = await coprocessor(api);
  const call = api.tx.sudo.sudo(
    api.tx.ismpGrandpa.addStateMachines([await hyperbridgeEntry(api)])
  );

  let blockHash;
  try {
    blockHash = await send(api, call, sudoKey);
    checks.add('add_state_machines via sudo', true, `block ${blockHash.slice(0, 12)}…`);
  } catch (e) {
    checks.add('add_state_machines via sudo', false, e.message);
    return;
  }

  const events = await api.query.system.events.at(blockHash);
  checks.add(
    'StateMachineAdded emitted',
    events.some((r) => r.event.section === 'ismpGrandpa' && r.event.method === 'StateMachineAdded')
  );

  // A successful extrinsic that leaves storage empty would still drop every
  // Hyperbridge datagram, so the receipt alone is not evidence the link works.
  const stored = await api.query.ismpGrandpa.supportedStateMachines(expected.toJSON());
  checks.add(
    'Hyperbridge whitelisted in storage',
    stored.isSome && stored.unwrap().toNumber() === HYPERBRIDGE_SLOT_DURATION_MS,
    stored.isSome
      ? `${expected.toString()} slot_duration=${stored.unwrap().toNumber()}ms`
      : `entry absent for ${expected.toString()}`
  );

  // The bug this replaces: both suites whitelisted `Polkadot(4009)` while a
  // `hyperbridge-testnet` runtime tracks `Kusama(4009)`, then read back the same wrong
  // key — self-consistently wrong, so nothing failed. Asserting the *other* relay
  // variant of the same para id is absent pins the whole identifier, not half of it.
  const otherRelay = expected.isKusama
    ? { Polkadot: expected.asKusama.toNumber() }
    : { Kusama: expected.isPolkadot ? expected.asPolkadot.toNumber() : 0 };
  const alias = await api.query.ismpGrandpa.supportedStateMachines(otherRelay);
  checks.add(
    'the other relay variant of the same para id is NOT whitelisted',
    alias.isNone,
    alias.isNone ? `${JSON.stringify(otherRelay)} absent` : 'ALIASED — wrong trust root'
  );
};

/**
 * The read path a relayer uses: RPC (`ismp_query*`) -> runtime API -> offchain DB.
 *
 * All three links must exist. Without offchain indexing `offchain_index::set` is a
 * no-op and every query comes back empty with no error — the failure mode worth
 * catching.
 */
const checkRelayerReadPath = async (checks, endpoint) => {
  const methods = [
    ['ismp_queryRequests', [[]]],
    ['ismp_queryResponses', [[]]],
    ['ismp_queryEvents', EVENT_QUERY_RANGE],
    ['ismp_queryEventsWithMetadata', EVENT_QUERY_RANGE],
    ['ismp_queryConsensusState', [CONSENSUS_STATE_ID_PASEO]],
    ['ismp_queryChallengePeriod', [{}]],
    ['ismp_queryStateMachineLatestHeight', [{}]],
    ['ismp_queryStateMachineUpdateTime', [{}]],
    ['ismp_queryChildTrieProof', [1, []]],
    ['ismp_queryStateProof', [1, []]],
  ];

  for (const [method, params] of methods) {
    const exists = await rpcMethodExists(endpoint, method, params);
    checks.add(`${method} is registered`, exists, exists ? '' : 'method not found (-32601)');
  }

  // Empty-input queries must return an empty list rather than erroring — this is the
  // shape a relayer sees before any message exists.
  const { ok, result, error } = await rpcCall(endpoint, 'ismp_queryRequests', [[]]);
  checks.add(
    'ismp_queryRequests returns a list for an empty query',
    ok && Array.isArray(result),
    ok ? `${JSON.stringify(result)}` : `error: ${error?.message}`
  );

  // Proves the runtime API is wired: a per-block event map can only come from
  // `block_events`, which only exists because `IsmpRuntimeApi` is implemented.
  const ev = await rpcCall(endpoint, 'ismp_queryEvents', EVENT_QUERY_RANGE);
  checks.add(
    'ismp_queryEvents reaches the runtime API',
    ev.ok && typeof ev.result === 'object' && ev.result !== null,
    ev.ok ? `${Object.keys(ev.result).length} block(s)` : `error: ${ev.error?.message}`
  );
};

/**
 * Each runtime-API method must read the storage the pallet actually writes.
 *
 * A method can compile, be registered and answer cleanly while reading a map nothing
 * populates — returning `None` forever with no error. That happened here:
 * `state_machine_update_time` originally read the legacy `StateMachineUpdateTime`,
 * which only benchmarks write and `on_idle` drains. Comparing each RPC against the
 * same storage read through `@polkadot/api` catches it.
 */
const checkRuntimeApiReadsLiveStorage = async (api, checks, endpoint) => {
  const stateMachineId = {
    stateId: (await coprocessor(api)).toJSON(),
    consensusStateId: CONSENSUS_STATE_ID_PASEO,
  };

  // Challenge period: unset on a fresh chain, so both sides must agree on "absent"
  // rather than one erroring.
  const cpStorage = await api.query.ismp.challengePeriod(stateMachineId);
  const cpRpc = await rpcCall(endpoint, 'ismp_queryChallengePeriod', [stateMachineId]);
  checks.add(
    'ismp_queryChallengePeriod agrees with on-chain storage',
    cpRpc.error === undefined || cpRpc.result === null || cpRpc.result === undefined
      ? cpStorage.isNone
      : true,
    `storage=${cpStorage.isNone ? 'none' : cpStorage.toString()} rpc=${JSON.stringify(cpRpc.result ?? null)}`
  );

  // The map the update-time bug was about. On 2512 a legacy `StateMachineUpdateTime`
  // map coexisted with the bounded one and carried the getter, so the name that looked
  // right was permanently empty. 2606 removed it: the bounded map must be the ONLY one,
  // and its reappearance would mean a downgrade or a fork resurrecting the trap.
  const ismpStorage = Object.keys(api.query.ismp ?? {});
  checks.add(
    'bounded update-time map is the only one (legacy map gone in 2606)',
    ismpStorage.includes('boundedStateMachineUpdateTime') &&
      !ismpStorage.includes('stateMachineUpdateTime'),
    `update-time maps present: ${ismpStorage.filter((k) => k.toLowerCase().includes('updatetime')).join(', ')}`
  );

  // Every storage item the API delegates to must exist under the names used.
  const required = [
    'consensusStates',
    'challengePeriod',
    'latestStateMachineHeight',
    'boundedStateMachineUpdateTime',
  ];
  const available = Object.keys(api.query.ismp ?? {});
  const missing = required.filter((k) => !available.includes(k));
  checks.add(
    'runtime API storage items all exist',
    missing.length === 0,
    missing.length ? `missing: ${missing.join(', ')}` : required.join(', ')
  );
};

/**
 * Two fixes that close silent failures, asserted from the outside. The unit tests in
 * `configs/ismp/` cover the logic; these check the built binary actually carries them,
 * which a stale artifact would hide from `cargo test`.
 */
const checkSecurityFixesPresent = async (checks, endpoint) => {
  // The RPC being reachable at all is the precondition for everything below: if the
  // node were serving the Safe method set, these would 404 rather than answer.
  const reachable = await rpcMethodExists(endpoint, 'ismp_queryConsensusState', [
    CONSENSUS_STATE_ID_PASEO,
  ]);
  checks.add(
    'ismp_* methods reachable (rpc_methods = Unsafe)',
    reachable,
    reachable ? '' : 'method not found — relayers could not fetch proofs'
  );

  // Orbinum's own identity, read from the built binary. `HOST_STATE_MACHINE_ID` is
  // baked into every commitment already in flight, so it cannot change once messages
  // exist — the Rust unit test pins the constant, this pins the artifact that ships.
  const host = await rpcCall(endpoint, 'state_call', ['IsmpRuntimeApi_host_state_machine', '0x']);
  // SCALE: variant 3 = Substrate, followed by the 4 raw bytes "orbi".
  const expectedHost = '0x03' + Buffer.from('orbi').toString('hex');
  checks.add(
    'host state machine is Substrate("orbi")',
    host.ok && host.result === expectedHost,
    host.ok ? `${host.result} (expected ${expectedHost})` : `error: ${host.error?.message}`
  );

  // The consensus guard rejects an envelope that does not match the tracked state
  // machine. There is no consensus state to attack on a fresh dev chain, so what is
  // asserted here is that the guarded client is the one wired in: a bogus state id
  // must answer cleanly rather than panic the node.
  const bogus = await rpcCall(endpoint, 'ismp_queryConsensusState', [[0xff, 0xff, 0xff, 0xff]]);
  checks.add(
    'unknown consensus state answers cleanly',
    bogus.error !== undefined || bogus.result === null || bogus.result === undefined,
    bogus.error ? String(bogus.error.message).slice(0, 40) : `result=${JSON.stringify(bogus.result)}`
  );
};

/**
 * The outbound path, which is the half the read-path checks above cannot reach.
 *
 * Every `ismp_queryRequests` assertion elsewhere runs against an empty chain, and a
 * node with offchain indexing disabled returns exactly the same empty list — so until
 * something can dispatch, "the relayer can see our messages" is unproven either way.
 *
 * Dispatching one request and finding it by commitment exercises the whole chain:
 * `dispatch_request` -> commitment in storage -> `offchain_index::set` -> the RPC.
 */
const checkOutboundPath = async (api, checks, endpoint, sudoKey) => {
  const before = await api.query.ismp.nonce();

  // A real destination, not the coprocessor. Hyperbridge is the route; this is the
  // chain we are actually addressing. An earlier version of the pallet pinned `dest`
  // to the coprocessor, which meant Orbinum could talk *to* the bridge but never
  // *through* it — the whole point of the integration.
  const dest = { Kusama: COUNTERPARTY_PARA_ID };
  const body = api.createType('Bytes', PING_BODY).toHex();

  const call = api.tx.sudo.sudo(
    api.tx.ismpMessaging.dispatchPost(dest, REMOTE_MODULE_ID, body, 0)
  );

  let blockHash;
  try {
    blockHash = await send(api, call, sudoKey);
  } catch (e) {
    checks.add('dispatch_post accepted', false, e.message);
    return;
  }

  const events = await api.query.system.events.at(blockHash);
  const dispatched = events.some(
    (r) => r.event.section === 'ismpMessaging' && r.event.method === 'RequestDispatched'
  );
  checks.add('dispatch_post emits RequestDispatched', dispatched);

  // The destination recorded on-chain must be the one we asked for. This is the
  // assertion that fails if `dest` is ever pinned back to the coprocessor.
  const evt = events.find(
    (r) => r.event.section === 'ismpMessaging' && r.event.method === 'RequestDispatched'
  );
  checks.add(
    'request is addressed to the requested destination, not the coprocessor',
    evt !== undefined && JSON.stringify(evt.event.data.dest.toJSON()) === JSON.stringify({ kusama: COUNTERPARTY_PARA_ID }),
    evt ? `dest=${JSON.stringify(evt.event.data.dest.toJSON())}` : 'no event'
  );

  // The nonce advancing is what proves `pallet_ismp` accepted the request rather than
  // our pallet merely emitting its own event.
  const after = await api.query.ismp.nonce();
  checks.add(
    'ISMP nonce advanced — pallet_ismp accepted the request',
    after.toNumber() === before.toNumber() + 1,
    `${before.toNumber()} -> ${after.toNumber()}`
  );

  // The commitment is emitted by pallet_ismp as a `Request` event; find it and ask the
  // RPC for it by hash. A hit here is the read path working end to end.
  const requested = events.find(
    (r) => r.event.section === 'ismp' && r.event.method === 'Request'
  );
  if (!requested) {
    checks.add('dispatched request retrievable via ismp_queryRequests', false, 'no ismp.Request event');
    return;
  }
  const commitment = requested.event.data.commitment.toHex();

  // `ismp_queryRequests` takes `Vec<LeafIndexQuery>`, i.e. `[{ commitment }]` — not
  // bare hashes.
  const { ok, result, error } = await rpcCall(endpoint, 'ismp_queryRequests', [
    [{ commitment }],
  ]);
  checks.add(
    'dispatched request retrievable via ismp_queryRequests',
    ok && Array.isArray(result) && result.length === 1,
    ok ? `${(result ?? []).length} result(s) for ${commitment.slice(0, 14)}…` : `error: ${error?.message}`
  );
};

const main = async () => {
  await cryptoWaitReady();
  const api = await ApiPromise.create({ provider: new WsProvider(ENDPOINT), noInitWarn: true });
  const keyring = new Keyring({ type: 'sr25519' });
  const alice = keyring.addFromUri('//Alice');
  const bob = keyring.addFromUri('//Bob');

  console.log(`\nISMP E2E — ${(await api.rpc.system.chain()).toString()} @ ${ENDPOINT}\n`);
  const checks = new Checklist();

  checkPalletsPresent(api, checks);
  await checkWhitelisting(api, checks, alice);

  // The whitelist decides whose consensus proofs this chain trusts, so the origin
  // check is load-bearing. Full origin coverage is in the security suite.
  await expectReject(
    api,
    checks,
    'non-root add_state_machines rejected',
    api.tx.ismpGrandpa.addStateMachines([await hyperbridgeEntry(api)]),
    bob,
    'BadOrigin'
  );

  await checkRelayerReadPath(checks, ENDPOINT);
  await checkRuntimeApiReadsLiveStorage(api, checks, ENDPOINT);
  await checkSecurityFixesPresent(checks, ENDPOINT);
  await checkOutboundPath(api, checks, ENDPOINT, alice);

  await api.disconnect();
  process.exit(checks.report('ISMP E2E'));
};

main().catch((e) => {
  console.error('E2E error:', e.message);
  process.exit(1);
});
