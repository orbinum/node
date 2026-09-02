/**
 * Shared harness for the ISMP test suites.
 *
 * Both `test-ismp-e2e.mjs` (functional) and `test-ismp-security.mjs` (adversarial)
 * need the same three things: a way to record a check, a way to submit an extrinsic
 * and get a usable error back, and a way to read the outcome of a sudo-wrapped call.
 * Keeping them here means a fix to error decoding lands in both suites at once.
 */

/** Hyperbridge's parachain id on the Paseo testnet. */
export const HYPERBRIDGE_TESTNET_PARA_ID = 4009;

/** Hyperbridge's parachain id on Polkadot — the mainnet deployment. */
export const HYPERBRIDGE_MAINNET_PARA_ID = 3367;

/**
 * The slot duration of the chain being whitelisted — Hyperbridge, not Orbinum.
 *
 * They are different chains' block times, coinciding at 6000 ms today. Prefer
 * {@link hyperbridgeSlotDuration}, which reads the runtime's own constant; this fallback
 * exists only for callers without an api handle.
 */
export const HYPERBRIDGE_SLOT_DURATION_MS = 6000;

/** Back-compat alias. Prefer {@link HYPERBRIDGE_SLOT_DURATION_MS}. */
export const SLOT_DURATION_MS = HYPERBRIDGE_SLOT_DURATION_MS;

/** Pallet indices are part of the encoded call format — see the runtime config. */
export const PALLET_INDEX = { Ismp: 19, IsmpGrandpa: 20, IsmpMessaging: 21 };

/**
 * Hyperbridge's consensus state id on Paseo: ASCII "PAS0" as the 4 bytes the chain
 * stores. Defined once because it was previously spelled two different ways across
 * suites, with nothing tying them together.
 */
export const CONSENSUS_STATE_ID_PASEO = [...'PAS0'].map((c) => c.charCodeAt(0));

/** GRANDPA's consensus client id — always "GRNP" per the Hyperbridge docs. */
export const CONSENSUS_CLIENT_ID_GRANDPA = [...'GRNP'].map((c) => c.charCodeAt(0));

/** Collects check results, printing as they happen so a hang shows which case it was. */
export class Checklist {
  constructor() {
    this.results = [];
  }

  /** Records one check. `detail` is shown inline and should carry the observed value. */
  add(name, ok, detail = '') {
    this.results.push({ name, ok, detail });
    console.log(`  ${ok ? 'ok  ' : 'FAIL'} ${name}${detail ? ` — ${detail}` : ''}`);
    return ok;
  }

  get passed() {
    return this.results.filter((r) => r.ok).length;
  }

  get failed() {
    return this.results.filter((r) => !r.ok).length;
  }

  /** Prints the summary and returns the process exit code. */
  report(title) {
    console.log(`\n${'─'.repeat(64)}`);
    console.log(`${this.passed} passed, ${this.failed} failed`);
    if (this.failed) {
      console.log('\nFailures:');
      for (const r of this.results.filter((x) => !x.ok)) {
        console.log(`  · ${r.name} — ${r.detail}`);
      }
    }
    console.log(this.failed === 0 ? `\n${title} PASS\n` : `\n${title} FAIL\n`);
    return this.failed === 0 ? 0 : 1;
  }
}

/** Turns a `DispatchError` into a readable `section.Name`, falling back to its raw form. */
export const describeDispatchError = (api, dispatchError) => {
  if (dispatchError.isModule) {
    const decoded = api.registry.findMetaError(dispatchError.asModule);
    return `${decoded.section}.${decoded.name}`;
  }
  return dispatchError.toString();
};

/**
 * Signs and submits `call`, resolving with the block hash once included.
 *
 * Rejects with a decoded dispatch error, so assertions can match on
 * `ismp.MessageNotFound` rather than a raw index pair.
 */
export const send = (api, call, signer) =>
  new Promise((resolve, reject) => {
    call
      .signAndSend(signer, ({ status, dispatchError }) => {
        if (dispatchError) reject(new Error(describeDispatchError(api, dispatchError)));
        else if (status.isInBlock) resolve(status.asInBlock.toHex());
      })
      .catch(reject);
  });

/**
 * Runs `call` through sudo and reports what the *inner* call did.
 *
 * Sudo succeeds even when the call it wraps fails — the inner result arrives as a
 * `Sudid` event. Without unwrapping that, a failed privileged call looks like a
 * success, which would make every root-path assertion meaningless.
 */
export const sudoOutcome = (api, call, signer) =>
  new Promise((resolve, reject) => {
    api.tx.sudo
      .sudo(call)
      .signAndSend(signer, ({ status, events, dispatchError }) => {
        if (dispatchError) return reject(new Error(describeDispatchError(api, dispatchError)));
        if (!status.isInBlock) return;

        const sudid = events.find(
          (r) => r.event.section === 'sudo' && r.event.method === 'Sudid'
        );
        if (!sudid) return resolve({ ok: true, err: null, blockHash: status.asInBlock.toHex() });

        const result = sudid.event.data[0];
        if (result.isErr) {
          const err = result.asErr;
          return resolve({
            ok: false,
            err: err.isModule ? describeDispatchError(api, err) : err.toString(),
            blockHash: status.asInBlock.toHex(),
          });
        }
        resolve({ ok: true, err: null, blockHash: status.asInBlock.toHex() });
      })
      .catch(reject);
  });

/**
 * Asserts a call is REJECTED, recording the outcome on `checks`.
 *
 * A call that succeeds when it should not is the failure mode worth catching here, so
 * success is recorded as an explicit FAIL rather than an absent result.
 *
 * @param expect substring the error must contain, e.g. `'BadOrigin'`. Matching on the
 *   specific error matters: rejected-for-the-wrong-reason is not a passing test.
 */
export const expectReject = async (api, checks, label, call, signer, expect = '') => {
  try {
    await send(api, call, signer);
    checks.add(label, false, 'call SUCCEEDED — expected rejection');
  } catch (e) {
    const msg = e.message.split('\n')[0];
    const matched = !expect || msg.toLowerCase().includes(expect.toLowerCase());
    checks.add(label, matched, matched ? msg : `rejected as "${msg}", expected "${expect}"`);
  }
};

/** Submits an unsigned extrinsic — the `handle_unsigned` path, which takes no signer. */
export const sendUnsigned = (api, call) =>
  new Promise((resolve, reject) => {
    call
      .send(({ status, dispatchError }) => {
        if (dispatchError) reject(new Error(describeDispatchError(api, dispatchError)));
        else if (status.isInBlock) resolve(status.asInBlock.toHex());
      })
      .catch(reject);
  });

/** Looks up a pallet's runtime index from metadata. */
export const palletIndex = (api, name) =>
  api.runtimeMetadata.asLatest.pallets
    .find((p) => p.name.toString() === name)
    ?.index.toNumber();

/**
 * Reads a state machine's whitelist entry, or `null` when absent. Unwrapping the raw
 * `Option` at each call site invites a mistake that reads as a passing test.
 */
export const whitelistedStateMachine = async (api, stateMachine) => {
  const entry = await api.query.ismpGrandpa.supportedStateMachines(stateMachine);
  return entry.isSome ? entry.unwrap() : null;
};

/**
 * The coprocessor this node was built against, read from the runtime.
 *
 * `Polkadot(4009)` and `Kusama(4009)` are distinct SCALE variants, and the coprocessor
 * — not the whitelist — is what decides the identity our state commitments are
 * recorded under (`ismp-grandpa/src/consensus.rs`, the `T::Coprocessor::get()` match).
 * Both suites previously hardcoded `Polkadot(4009)`, so under a `hyperbridge-testnet`
 * build they whitelisted a state machine the runtime would never consult — and read
 * back the same wrong key, so every assertion passed.
 *
 * Reading it off the node is the only form that cannot be self-consistently wrong.
 * Neither `Coprocessor` nor `HostStateMachine` reaches metadata (they are plain
 * associated types, not `#[pallet::constant]`), hence the dedicated runtime API.
 *
 * Throws rather than defaulting: a default is precisely how the original bug survived.
 */
export const coprocessor = async (api) => {
  const raw = await api.rpc.state.call('OrbinumIsmpApi_coprocessor', '0x');
  const decoded = api.createType('Option<IsmpHostStateMachine>', raw);
  if (decoded.isNone) {
    throw new Error('runtime reports no coprocessor — ISMP proxying is disabled');
  }
  return decoded.unwrap();
};

/**
 * The slot duration this runtime whitelists the coprocessor with, read from the node.
 *
 * The runtime enforces its own bounds on this value at compile time, so reading it here
 * means the suites cannot whitelist something the runtime would have rejected.
 */
export const hyperbridgeSlotDuration = async (api) => {
  const raw = await api.rpc.state.call('OrbinumIsmpApi_hyperbridge_slot_duration', '0x');
  return api.createType('u64', raw).toNumber();
};

/**
 * The Hyperbridge whitelist entry for the network this node was built against.
 *
 * Both halves come from the runtime, never hardcoded — see {@link coprocessor}.
 */
export const hyperbridgeEntry = async (api, slotDuration) => ({
  stateMachine: (await coprocessor(api)).toJSON(),
  slotDuration: slotDuration ?? (await hyperbridgeSlotDuration(api)),
});

/**
 * Calls a raw JSON-RPC method by name. `@polkadot/api` only surfaces methods it knows
 * from metadata, and the ISMP RPC is a node-side extension that never appears there.
 *
 * Returns `{ ok, result, error }` rather than throwing: "responds with a protocol
 * error" and "is not registered" are different outcomes, and a throw collapses them.
 */
export const rpcCall = async (endpoint, method, params = []) => {
  const httpUrl = endpoint.replace(/^ws/, 'http');
  try {
    const res = await fetch(httpUrl, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ jsonrpc: '2.0', id: 1, method, params }),
    });
    const json = await res.json();
    return { ok: !json.error, result: json.result, error: json.error };
  } catch (e) {
    return { ok: false, result: undefined, error: { message: e.message } };
  }
};

/**
 * True when the node recognises `method` at all. JSON-RPC reports an unknown method as
 * -32601; anything else means it is registered and reachable.
 */
export const rpcMethodExists = async (endpoint, method, params = []) => {
  const { error } = await rpcCall(endpoint, method, params);
  return !error || error.code !== -32601;
};
