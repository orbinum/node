#!/usr/bin/env node
/**
 * Verifies that every `ismpMessaging` event carries the commitment it should, against a
 * running dev node.
 *
 *   ./target/release/orbinum-node --dev --tmp
 *   node scripts/hyperbridge/verify-commitments.mjs [ws://127.0.0.1:9944]
 *
 * Runtime spec 12 added `commitment` to `MessageReceived`, `MessageRejected`,
 * `RequestTimedOut` and `GetResponseReceived`. Before it, those four were anonymous: an
 * arrival could not be attributed to a message and a timeout could not be matched to what
 * expired. The pallet derives the value with the protocol's own `hash_request`, so the
 * claim under test is not merely "a hash is present" but "it is the SAME hash the sender
 * committed to".
 *
 * The unit tests already assert that equality in Rust. What only a real node can show is
 * that the field survives into the runtime's metadata and out through the RPC decoders an
 * indexer actually uses — a `#[pallet::event]` change is invisible to those until the
 * runtime is built.
 *
 * Inbound events are NOT reachable from here: they need a counterparty and a membership
 * proof. So this checks the metadata contract for all four and exercises the one path a
 * single chain can drive on its own, the dispatch.
 */
import { ApiPromise, WsProvider, Keyring } from '@polkadot/api';
import { cryptoWaitReady } from '@polkadot/util-crypto';
import { Checklist, sudoOutcome } from '../lib/ismp-harness.mjs';

const ENDPOINT = process.argv[2] ?? 'ws://127.0.0.1:9944';

/** Every event that must carry a commitment, and the other fields it must keep. */
const EXPECTED = {
  RequestDispatched: ['dest', 'to', 'commitment'],
  MessageReceived: ['source', 'from', 'body_len', 'commitment'],
  MessageRejected: ['source', 'reason', 'commitment'],
  GetResponseReceived: ['keys', 'found', 'commitment'],
  RequestTimedOut: ['dest', 'commitment'],
};

const main = async () => {
  await cryptoWaitReady();
  const api = await ApiPromise.create({ provider: new WsProvider(ENDPOINT), noInitWarn: true });
  const checks = new Checklist();

  const version = api.runtimeVersion.specVersion.toNumber();
  console.log(`\nVerify commitments — ${(await api.rpc.system.chain()).toString()} @ ${ENDPOINT}`);
  console.log(`  spec_version: ${version}\n`);
  checks.add('runtime carries the commitment change', version >= 12, `spec ${version}`);

  // The metadata is the contract an indexer decodes against. A field added to the Rust
  // enum but missing here would mean the runtime was not rebuilt.
  const meta = api.events.ismpMessaging;
  for (const [name, fields] of Object.entries(EXPECTED)) {
    const event = meta?.[name];
    if (!event) {
      checks.add(`${name} exists`, false, 'absent from metadata');
      continue;
    }
    const actual = event.meta.fields.map((f) => f.name.toString());
    const missing = fields.filter((f) => !actual.includes(f));
    checks.add(
      `${name} fields`,
      missing.length === 0,
      missing.length ? `missing ${missing.join(', ')}` : actual.join(', '),
    );
  }

  // Now the live path. Dispatch a message and read the commitment back out of the event —
  // this is what proves the value reaches a client, not just the runtime.
  const sudo = new Keyring({ type: 'sr25519' }).addFromUri('//Alice');
  const dest = { Kusama: 1000 };
  const outcome = await sudoOutcome(
    api,
    api.tx.ismpMessaging.dispatchPost(dest, '0x' + Buffer.from('probe/mo').toString('hex'), '0x00', 0),
    sudo,
  );
  checks.add('dispatch_post accepted', outcome.ok, outcome.err ?? '');

  if (outcome.ok) {
    const events = await api.query.system.events.at(outcome.blockHash);

    const dispatched = events.find(
      (r) => r.event.section === 'ismpMessaging' && r.event.method === 'RequestDispatched',
    );
    const ours = dispatched?.event.data.commitment?.toHex();
    checks.add('RequestDispatched carries a commitment', Boolean(ours), ours ?? 'none');

    // `pallet-ismp` hashes the same request independently for its own event. If the two
    // disagree, our derivation is wrong and nothing would ever join.
    const protocolRequest = events.find(
      (r) => r.event.section === 'ismp' && r.event.method === 'Request',
    );
    const theirs = protocolRequest?.event.data.commitment?.toHex();
    checks.add(
      'our commitment matches the protocol pallet',
      Boolean(ours) && ours === theirs,
      theirs ? `${ours} vs ${theirs}` : 'ismp.Request not emitted',
    );
  }

  await api.disconnect();
  process.exit(checks.report('Verify commitments'));
};

main().catch((e) => {
  console.error('error:', e.message);
  process.exit(1);
});
