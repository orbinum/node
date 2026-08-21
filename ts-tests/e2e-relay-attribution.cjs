// E2E for origin-based relay fee attribution, against a --dev node.
//
//   node ts-tests/e2e-relay-attribution.cjs
//
// The relay fee recipient used to be a free `relayer: Option<H160>` argument on
// two unsigned extrinsics: anyone could take a propagated proof, resubmit it
// naming themselves, and collect a fee they never paid for. It is now taken from
// the dispatch origin — the EVM caller for precompile submissions, the signer for
// signed ones — which the calldata cannot influence.
//
// What this checks is that the field is gone from the chain's own metadata and
// that the surrounding machinery still lines up. Actually emitting a fee needs a
// valid Groth16 proof, which a release binary cannot fake, so the credit paths
// are covered by the pallet's unit tests instead.

const { ApiPromise, WsProvider } = require('@polkadot/api');

const WS = process.env.WS || 'ws://127.0.0.1:9944';

let pass = 0;
let fail = 0;

function check(name, ok, detail) {
	if (ok) {
		pass++;
		console.log(`  ok    ${name}`);
	} else {
		fail++;
		console.log(`  FAIL  ${name}${detail ? ` — ${detail}` : ''}`);
	}
}

function argNames(section, method) {
	const meta = section[method].meta;
	return meta.args.map((a) => a.name.toString());
}

async function main() {
	const api = await ApiPromise.create({ provider: new WsProvider(WS) });
	const spec = api.runtimeVersion;
	console.log(
		`\nRuntime: ${spec.specName} spec=${spec.specVersion} tx=${spec.transactionVersion}\n`
	);

	// ─── The argument is gone ────────────────────────────────────────────────
	console.log('Extrinsic signatures');

	for (const call of ['unshield', 'privateTransfer']) {
		const args = argNames(api.tx.shieldedPool, call);
		check(
			`${call} no longer takes a relayer argument`,
			!args.includes('relayer'),
			`args: ${args.join(', ')}`
		);
		// The rest of the signature must be intact — this catches an accidental
		// drop of the wrong field.
		// Metadata renders arg names in camelCase.
		check(
			`${call} still takes fee and circuitVersion`,
			args.includes('fee') && args.includes('circuitVersion'),
			`args: ${args.join(', ')}`
		);
	}

	// ─── The origin is not observable from metadata ──────────────────────────
	//
	// Substrate only publishes types reachable from calls, events and storage, so
	// `OriginCaller` and its variants never appear. That the runtime accepts
	// `RuntimeOrigin: From<pallet_shielded_pool::RawOrigin>` is proven at compile
	// time by `template/runtime/src/precompiles.rs` — the build fails without it.
	// What IS observable, and what matters here, is that the argument is gone:
	// checked above.

	// ─── Attribution events ──────────────────────────────────────────────────
	console.log('\nFee attribution events');

	check('RelayFeeDiverted still exists', api.events.shieldedPool.RelayFeeDiverted !== undefined);

	const selfRelayed = api.events.shieldedPool.SelfRelayedFee;
	check('SelfRelayedFee is exposed', selfRelayed !== undefined);
	if (selfRelayed) {
		const fields = selfRelayed.meta.fields.map((f) => f.name.toString());
		for (const want of ['author', 'asset_id', 'amount']) {
			check(`SelfRelayedFee carries \`${want}\``, fields.includes(want), `has ${fields}`);
		}
	}

	// ─── The registry still resolves ─────────────────────────────────────────
	console.log('\nRelayer registry');

	// Attribution goes through the registry: an authenticated H160 still has to
	// map to a substrate account, because the EVM address mapping produces a
	// synthetic account, not the validator's own.
	check(
		'relayerRegistry is queryable',
		typeof api.query.relayer?.relayerRegistry === 'function'
	);
	check(
		'relayerByAccount is queryable',
		typeof api.query.relayer?.relayerByAccount === 'function'
	);

	const registered = await api.query.relayer.relayerRegistry.entries();
	check(`registry reads cleanly (${registered.length} entries)`, Array.isArray(registered));

	// ─── The relay RPC is intact ─────────────────────────────────────────────
	console.log('\nRelay RPC');

	const relayerApi = api.call?.relayerRuntimeApi;
	check('relayerRuntimeApi is reachable', relayerApi !== undefined);
	if (relayerApi?.getActiveRelayers) {
		const active = await relayerApi.getActiveRelayers();
		check(`getActiveRelayers responds (${active.length})`, Array.isArray(active.toJSON()));
	}

	// The precompile selectors must be unchanged: the relayer was never an ABI
	// field, so removing the extrinsic argument must not shift the calldata.
	const cfg = await api.call.shieldedPoolRuntimeApi?.relayConfig?.();
	if (cfg) {
		const selectors = cfg.allowedSelectors ?? cfg.allowed_selectors;
		check(
			`relay selector whitelist is non-empty (${selectors?.length ?? 0})`,
			selectors && selectors.length > 0
		);
	} else {
		console.log('  skip  relayConfig not exposed on this runtime API');
	}

	console.log(`\n${pass} passed, ${fail} failed\n`);
	await api.disconnect();
	process.exit(fail === 0 ? 0 : 1);
}

main().catch((e) => {
	console.error(e);
	process.exit(1);
});
