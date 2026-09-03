#!/usr/bin/env node
/**
 * Initialises Hyperbridge's consensus client on a local Orbinum node.
 *
 * This is step 1 of onboarding, run against real Paseo but with the chain on this
 * machine — to confirm `create_consensus_client` accepts the blob Tesseract returns
 * before touching production.
 *
 *   node scripts/setup-paseo-local.mjs <hex> [ws://…]
 *
 * The hex comes from:
 *   docker run --rm --platform linux/amd64 -v /tmp/tess:/data \
 *     polytopelabs/tesseract:latest --config=/data/local.toml --db=/data/relayer.db \
 *     log-consensus-state KUSAMA-4009
 */
import { ApiPromise, WsProvider, Keyring } from '@polkadot/api';
import { cryptoWaitReady } from '@polkadot/util-crypto';
import { Checklist, sudoOutcome, coprocessor } from './lib/ismp-harness.mjs';

const HEX = process.argv[2];
const ENDPOINT = process.argv[3] ?? 'ws://127.0.0.1:9944';

/** The GRANDPA client always identifies itself this way. */
const CONSENSUS_CLIENT_ID = 'GRNP';
/** Hyperbridge's consensus state id on Paseo. */
const CONSENSUS_STATE_ID = 'PAS0';
/** The relay chain's unbonding period, in seconds (Paseo: 7 days). */
const UNBONDING_PERIOD = 7 * 24 * 60 * 60;
/**
 * Zero for Hyperbridge: its economic security comes from the relay chain, so no dispute
 * window is needed. This is what the solochain docs prescribe.
 */
const CHALLENGE_PERIOD = 0;

if (!HEX?.startsWith('0x')) {
  console.error('uso: node scripts/setup-paseo-local.mjs <0xhex> [ws://…]');
  process.exit(2);
}

const main = async () => {
  await cryptoWaitReady();
  const api = await ApiPromise.create({ provider: new WsProvider(ENDPOINT), noInitWarn: true });
  const alice = new Keyring({ type: 'sr25519' }).addFromUri('//Alice');
  const checks = new Checklist();

  console.log(`\nSetup Paseo — ${(await api.rpc.system.chain()).toString()} @ ${ENDPOINT}\n`);

  // The destination must be the one the runtime actually consults. A mainnet binary
  // targets Polkadot(3367) and Paseo's proofs would fail to verify — silently.
  const cop = await coprocessor(api);
  checks.add('node is a Paseo build', cop.isKusama, cop.toString());
  if (!cop.isKusama) {
    console.error('\nRebuild with --features hyperbridge-testnet');
    process.exit(1);
  }

  // `challenge_periods` is a MAP keyed by state machine, not a scalar — the docs do not
  // show it that way. `state_machine_commitments` stays empty: the client starts with no
  // commitments and receives them from the relayer.
  const message = {
    consensusState: HEX,
    consensusClientId: Array.from(Buffer.from(CONSENSUS_CLIENT_ID)),
    consensusStateId: Array.from(Buffer.from(CONSENSUS_STATE_ID)),
    unbondingPeriod: UNBONDING_PERIOD,
    challengePeriods: new Map([[cop.toJSON(), CHALLENGE_PERIOD]]),
    stateMachineCommitments: [],
  };

  const created = await sudoOutcome(api, api.tx.ismp.createConsensusClient(message), alice);
  checks.add('create_consensus_client accepted', created.ok, created.err ?? '');

  if (created.ok) {
    // The extrinsic can report success and leave no state behind; reading storage is
    // what proves the client was actually installed.
    const stored = await api.query.ismp.consensusStates(Array.from(Buffer.from(CONSENSUS_STATE_ID)));
    checks.add(
      'consensus state persisted',
      stored.isSome,
      stored.isSome ? `${stored.unwrap().length} bytes` : 'absent'
    );

    const cp = await api.query.ismp.challengePeriod({
      stateId: cop.toJSON(),
      consensusStateId: Array.from(Buffer.from(CONSENSUS_STATE_ID)),
    });
    checks.add('challenge period recorded', cp.isSome, cp.isSome ? `${cp.unwrap()}s` : 'absent');
  }

  // Whitelist Hyperbridge: until it is on the list, the pallet drops its datagrams.
  const wl = await sudoOutcome(
    api,
    api.tx.ismpGrandpa.addStateMachines([{ stateMachine: cop.toJSON(), slotDuration: 6000 }]),
    alice
  );
  checks.add('Hyperbridge whitelisted', wl.ok, wl.err ?? '');

  await api.disconnect();
  process.exit(checks.report('Setup Paseo'));
};

main().catch((e) => {
  console.error('error:', e.message);
  process.exit(1);
});
