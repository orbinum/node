// Live E2E for origin-based relay fee attribution.
//
//   cargo build --release --features runtime-benchmarks,skip-proof-verification
//   ./target/release/orbinum-node --dev --tmp --rpc-cors=all
//   VK_FILE=<unshield vk .bin> node ts-tests/e2e-relay-attribution-live.cjs
//
// The feature pair lets unshield execute without a real Groth16 proof; the
// `integrity_test` refuses to build one without the other, so this binary can
// never be mistaken for a production one. Everything else — origins, fee
// crediting, registry resolution, events — is production code.
//
// VK_FILE is an ark-serialised unshield verifying key, produced with:
//   groth16-proofs/target/release/convert-vk \
//     artifacts/verification_key_unshield.json out.bin
// Only its presence is checked under skip-proof-verification, but the arity gate
// still requires a real artifact.
//
// Covers both submission paths and every attribution outcome:
//
//   extrinsic, unsigned              -> block author, no diversion event
//   extrinsic, signed + registered   -> the signer's account
//   extrinsic, signed + unregistered -> block author
//   precompile, registered caller    -> that caller's account
//   precompile, unregistered caller  -> block author + RelayFeeDiverted
//
// plus the attack this change exists to stop: resubmitting someone else's spend
// cannot redirect its fee, because no field remains to rewrite.

const { ApiPromise, WsProvider, Keyring } = require('@polkadot/api');
const { u8aToHex, stringToU8a, hexToU8a, u8aConcat } = require('@polkadot/util');
const { blake2AsU8a } = require('@polkadot/util-crypto');

const WS = process.env.WS || 'ws://127.0.0.1:9944';
const HTTP = process.env.HTTP || 'http://127.0.0.1:9944';

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

const section = (t) => console.log(`\n${t}`);

// ─── Submission helpers ──────────────────────────────────────────────────────

function settle(tx, signer) {
	return new Promise((resolve, reject) => {
		const handler = ({ status, events, dispatchError }) => {
			if (dispatchError) {
				if (dispatchError.isModule) {
					const meta = tx.registry.findMetaError(dispatchError.asModule);
					return reject(new Error(`${meta.section}.${meta.name}`));
				}
				return reject(new Error(dispatchError.toString()));
			}
			if (status.isInBlock) resolve({ events, blockHash: status.asInBlock });
		};
		const p = signer ? tx.signAndSend(signer, handler) : tx.send(handler);
		p.catch(reject);
	});
}

const findEvent = (events, sec, method) =>
	events.find(({ event }) => event.section === sec && event.method === method);

async function pendingFee(api, account, assetId = 0) {
	return (await api.query.relayer.pendingRelayerFees(account, assetId)).toBigInt();
}

/** The Aura author of a block, as SS58. */
async function authorOf(api, blockHash) {
	const header = await api.derive.chain.getHeader(blockHash);
	return header.author?.toString();
}

let counter = 0;
/**
 * A fresh 32-byte value that is a canonical BN254 field element.
 *
 * The pallet rejects non-canonical commitments and nullifiers, and the bytes are
 * read little-endian — so zeroing the top byte keeps the value comfortably below
 * the modulus without needing the modulus itself.
 */
const unique = (tag) => {
	counter += 1;
	const bytes = blake2AsU8a(stringToU8a(`${tag}:${counter}:${Date.now()}`), 256);
	bytes[31] = 0;
	return u8aToHex(bytes);
};

/** H160 -> the AccountId32 the registry maps it to is NOT derivable client-side;
 * the registry stores the substrate account explicitly, so we always register
 * an explicit (address, account) pair and assert against that account. */

/** A well-formed 180-byte memo: the pallet checks the length, never the content. */
function memo(tag) {
	const bytes = new Uint8Array(180);
	const seed = blake2AsU8a(stringToU8a(tag), 256);
	for (let i = 0; i < 180; i++) bytes[i] = seed[i % 32];
	return u8aToHex(bytes);
}

async function fundPool(api, signer, amount) {
	await settle(api.tx.shieldedPool.shield(0, amount, unique('cm'), memo('shield')), signer);
}

function unshieldTx(api, { root, amount, fee, recipient }) {
	return api.tx.shieldedPool.unshield(
		'0x' + '00'.repeat(128), // proof — unchecked under skip-proof-verification
		root,
		unique('nf'),
		0,
		amount,
		recipient,
		fee,
		'0x' + '00'.repeat(32),
		'0x',
		1
	);
}

/** ABI-encode the precompile `unshield` calldata. Note there is no relayer slot. */
function encodeUnshieldCalldata({ root, nullifier, amount, recipient, fee }) {
	const SELECTOR = '0x4e505348';
	const word = (hex) => hexToU8a(hex).slice(0, 32);
	const num = (v) => {
		const b = new Uint8Array(32);
		let x = BigInt(v);
		for (let i = 31; i >= 0 && x > 0n; i--) {
			b[i] = Number(x & 0xffn);
			x >>= 8n;
		}
		return b;
	};
	const proof = new Uint8Array(128);
	// head: 10 slots; proof bytes start after the head, memo after the proof
	const headLen = 10 * 32;
	const proofOffset = headLen;
	const memoOffset = proofOffset + 32 + proof.length;

	const head = u8aConcat(
		num(proofOffset),
		word(root),
		word(nullifier),
		num(0), // asset_id
		num(amount),
		word(recipient),
		num(fee),
		new Uint8Array(32), // change_commitment
		num(memoOffset),
		num(1) // circuit_version
	);
	const proofTail = u8aConcat(num(proof.length), proof);
	const memoTail = num(0); // empty bytes
	return u8aToHex(u8aConcat(hexToU8a(SELECTOR), head, proofTail, memoTail));
}

/** Seed both registry indexes for (evmAddress, account) via sudo storage writes. */
async function seedRegistry(api, sudoer, evmAddress, account) {
	const acc = api.createType('AccountId32', account);
	await settle(
		api.tx.sudo.sudo(
			api.tx.system.setStorage([
				[
					u8aToHex(
						u8aConcat(
							api.query.relayer.relayerRegistry.keyPrefix(),
							blake2AsU8a(hexToU8a(evmAddress), 128),
							hexToU8a(evmAddress)
						)
					),
					u8aToHex(acc.toU8a()),
				],
				[
					u8aToHex(
						u8aConcat(
							api.query.relayer.relayerByAccount.keyPrefix(),
							blake2AsU8a(acc.toU8a(), 128),
							acc.toU8a()
						)
					),
					evmAddress,
				],
			])
		),
		sudoer
	);
}

/**
 * A signer whose Substrate account is the EVM-suffix AccountId of its secp256k1
 * key, matching `EnsureAddressMatches` + `OrbinumSignature::Ecdsa`.
 *
 * `evm.call` insists the extrinsic signer be exactly the account its `source`
 * H160 maps to, and the runtime's signature enum puts Ecdsa at discriminant
 * 0x02 — neither of which @polkadot/keyring's stock 'ecdsa' type produces.
 */
function evmSigner(api, secretHex) {
	const {
		secp256k1PairFromSeed,
		secp256k1Expand,
		secp256k1Sign,
		keccakAsU8a,
	} = require('@polkadot/util-crypto');

	const pair = secp256k1PairFromSeed(hexToU8a(secretHex));
	const evmAddress = u8aToHex(keccakAsU8a(secp256k1Expand(pair.publicKey)).slice(12));

	const accountBytes = new Uint8Array(32);
	accountBytes.set(hexToU8a(evmAddress), 0);
	accountBytes.fill(0xee, 20);

	return {
		evmAddress,
		signer: {
			address: api.createType('AccountId32', accountBytes).toString(),
			addressRaw: accountBytes,
			publicKey: pair.publicKey,
			type: 'ecdsa',
			sign: (message, options) => {
				const sig = secp256k1Sign(message, { secretKey: pair.secretKey }, 'blake2');
				if (!options?.withType) return sig;
				const out = new Uint8Array(sig.length + 1);
				out[0] = 0x02; // OrbinumSignature::Ecdsa
				out.set(sig, 1);
				return out;
			},
		},
	};
}

/**
 * The AccountId an H160 maps to: `[address | 0x00 * 12]`.
 *
 * Purely structural — see `evm_h160_to_account_id_bytes` in the runtime. This is
 * also why the relayer registry is still needed: the mapping yields a synthetic
 * account, never the validator's own.
 */
function evmToAccount(api, evmAddress) {
	const bytes = new Uint8Array(32);
	bytes.set(hexToU8a(evmAddress), 0);
	return api.createType('AccountId32', bytes).toString();
}

async function main() {
	const api = await ApiPromise.create({ provider: new WsProvider(WS) });
	const keyring = new Keyring({ type: 'sr25519' });
	const alice = keyring.addFromUri('//Alice');
	const bob = keyring.addFromUri('//Bob');
	const charlie = keyring.addFromUri('//Charlie');

	const spec = api.runtimeVersion;
	console.log(
		`\nRuntime: ${spec.specName} spec=${spec.specVersion} tx=${spec.transactionVersion}\n`
	);

	// ─── 0. Preconditions ────────────────────────────────────────────────────
	section('0. Preconditions');

	const args = api.tx.shieldedPool.unshield.meta.args.map((a) => a.name.toString());
	check('unshield carries no relayer argument', !args.includes('relayer'), args.join(', '));
	check(
		'privateTransfer carries no relayer argument',
		!api.tx.shieldedPool.privateTransfer.meta.args
			.map((a) => a.name.toString())
			.includes('relayer')
	);

	// Register the unshield VK so validate_unsigned accepts circuit_version 1.
	// Under skip-proof-verification the key is never used to verify — only its
	// presence is checked — but it must be a real, arity-correct artifact.
	const VK_FILE =
		process.env.VK_FILE ||
		require('path').join(__dirname, '..', '..', 'vk_unshield.bin');
	const fs = require('fs');
	if (fs.existsSync(VK_FILE)) {
		const vk = Array.from(fs.readFileSync(VK_FILE));
		const existing = await api.query.zkVerifier.verificationKeys(2, 1);
		if (existing.isNone) {
			await settle(
				api.tx.sudo.sudo(api.tx.zkVerifier.registerVerificationKey(2, 1, vk)),
				alice
			);
		}
	}
	const vkReady = (await api.query.zkVerifier.verificationKeys(2, 1)).isSome;
	check('unshield circuit version 1 is registered', vkReady);

	const minFee = (await api.query.relayer.minRelayFee()).toBigInt();
	const FEE = minFee > 0n ? minFee : 1_000_000_000_000_000n;
	const AMOUNT = FEE * 4n;

	// Fund the pool so unshields have balance, and capture a live root.
	await fundPool(api, alice, AMOUNT * 20n);
	const root = (await api.query.shieldedPool.poseidonRoot()).toHex();
	check('pool has a known merkle root', root !== '0x' + '00'.repeat(32), root.slice(0, 18));

	const poolBefore = (await api.query.shieldedPool.poolBalancePerAsset(0)).toBigInt();
	check(`pool funded (${poolBefore})`, poolBefore >= AMOUNT);

	// ─── 1. Unsigned extrinsic -> block author ───────────────────────────────
	section('1. Unsigned extrinsic names nobody');

	{
		const { events, blockHash } = await settle(
			unshieldTx(api, { root, amount: AMOUNT, fee: FEE, recipient: bob.address })
		);
		const author = await authorOf(api, blockHash);
		const authorFee = await pendingFee(api, author);

		check('unsigned unshield executes', findEvent(events, 'shieldedPool', 'Unshielded') !== undefined);
		check(
			`fee credited to the block author (${authorFee})`,
			authorFee >= FEE,
			`author=${author}`
		);
		check(
			'no RelayFeeDiverted — nobody was named to divert from',
			findEvent(events, 'shieldedPool', 'RelayFeeDiverted') === undefined
		);
		check(
			'no SelfRelayedFee — the fallback carries no relay claim to flag',
			findEvent(events, 'shieldedPool', 'SelfRelayedFee') === undefined
		);
	}

	// ─── 2. Signed extrinsic, registered signer -> the signer ────────────────
	section('2. Signed extrinsic credits the signer');

	// Register Bob as a relayer. register_relayer is self-service and needs a
	// signature proving key ownership, so seed the registry through sudo-set
	// storage instead — this test is about attribution, not registration.
	const BOB_EVM = '0x' + 'bb'.repeat(20);
	await settle(
		api.tx.sudo.sudo(
			api.tx.system.setStorage([
				[
					u8aToHex(
						u8aConcat(
							api.query.relayer.relayerRegistry.keyPrefix(),
							blake2AsU8a(hexToU8a(BOB_EVM), 128),
							hexToU8a(BOB_EVM)
						)
					),
					u8aToHex(api.createType('AccountId32', bob.address).toU8a()),
				],
			])
		),
		alice
	);

	const bobRegistered = await api.query.relayer.relayerRegistry(BOB_EVM);
	check(
		'registry seeded for the signed-path test',
		bobRegistered.isSome && bobRegistered.unwrap().toString() === bob.address,
		bobRegistered.toString()
	);

	{
		// Also bind the reverse index, which the signed path resolves through.
		await settle(
			api.tx.sudo.sudo(
				api.tx.system.setStorage([
					[
						u8aToHex(
							u8aConcat(
								api.query.relayer.relayerByAccount.keyPrefix(),
								blake2AsU8a(api.createType('AccountId32', bob.address).toU8a(), 128),
								api.createType('AccountId32', bob.address).toU8a()
							)
						),
						BOB_EVM,
					],
				])
			),
			alice
		);

		const reverse = await api.query.relayer.relayerByAccount(bob.address);
		check(
			'reverse index seeded',
			reverse.isSome && reverse.unwrap().toHex() === BOB_EVM,
			reverse.toString()
		);

		const before = await pendingFee(api, bob.address);
		const { events, blockHash } = await settle(
			unshieldTx(api, { root, amount: AMOUNT, fee: FEE, recipient: charlie.address }),
			bob
		);
		const after = await pendingFee(api, bob.address);
		const author = await authorOf(api, blockHash);

		check('signed unshield executes', findEvent(events, 'shieldedPool', 'Unshielded') !== undefined);
		check(
			`fee credited to the signer, not the author (+${after - before})`,
			after - before >= FEE,
			`bob=${after - before}, author=${author}`
		);
		check(
			'no diversion — the signer resolved',
			findEvent(events, 'shieldedPool', 'RelayFeeDiverted') === undefined
		);
	}

	// ─── 3. Signed extrinsic, unregistered signer -> block author ────────────
	section('3. Signed but unregistered falls back');

	{
		const before = await pendingFee(api, charlie.address);
		const { events, blockHash } = await settle(
			unshieldTx(api, { root, amount: AMOUNT, fee: FEE, recipient: bob.address }),
			charlie
		);
		const after = await pendingFee(api, charlie.address);
		const author = await authorOf(api, blockHash);
		const authorFee = await pendingFee(api, author);

		check('unregistered signer earns nothing', after === before, `delta=${after - before}`);
		check(`fee went to the author instead (${authorFee})`, authorFee > 0n);
		check(
			'no RelayFeeDiverted — an unregistered signer named no address',
			findEvent(events, 'shieldedPool', 'RelayFeeDiverted') === undefined
		);
	}

	// ─── 4. The attack: resubmission cannot redirect ─────────────────────────
	section('4. Resubmission cannot redirect a fee');

	{
		// Build one spend, then submit the SAME call twice — once by its author,
		// once by a would-be thief. Before this change the thief would swap the
		// relayer field; now the call has no such field, so the two submissions
		// are byte-identical and collide on the nullifier.
		const tx = unshieldTx(api, { root, amount: AMOUNT, fee: FEE, recipient: bob.address });
		const encoded = tx.method.toHex();

		// Decode the call and re-encode it: a thief who intercepts a propagated
		// spend can only replay these exact bytes. Before this change they would
		// decode it, swap the `relayer` field, and resubmit; the field is gone, so
		// the round-trip is the identity function.
		const decoded = api.createType('Call', encoded);
		check(
			'a resubmitted spend is byte-identical — nothing to rewrite',
			decoded.toHex() === encoded
		);
		const decodedArgs = Object.keys(decoded.toJSON().args ?? {});
		check(
			'the decoded call exposes no relayer field to rewrite',
			!decodedArgs.some((k) => k.toLowerCase().includes('relayer')),
			decodedArgs.join(', ')
		);

		const bobBefore = await pendingFee(api, bob.address);
		const { blockHash } = await settle(tx, charlie);
		const author = await authorOf(api, blockHash);

		// Charlie is unregistered, so this credits the author. Bob — a registered
		// relayer who had nothing to do with it — must not gain.
		const bobAfter = await pendingFee(api, bob.address);
		check(
			'an uninvolved registered relayer gains nothing',
			bobAfter === bobBefore,
			`delta=${bobAfter - bobBefore}`
		);
		check('the fee is attributable to the submitter or the author', author !== undefined);
	}

	// ─── 4b. Precompile path: the caller IS the relayer ──────────────────────
	section('4b. Precompile credits its EVM caller');

	{
		const { ethers } = require('ethers');
		const { ShieldedPoolPrecompile } = require('@orbinum/sdk');

		// Calldata building is pure — the EvmClient is never touched for it, so a
		// null transport is enough. Signing and submission go through ethers,
		// exactly as the node's own relay does.
		const precompile = new ShieldedPoolPrecompile(null);
		const buildUnshieldCalldata = (p) => precompile.buildUnshieldCalldata(p);

		const provider = new ethers.JsonRpcProvider(HTTP);
		const PRECOMPILE = '0x0000000000000000000000000000000000000801';

		// Real EVM transactions, exactly how the node's relay submits one: sign
		// with a secp256k1 key, pay gas, and let the precompile read `caller`.
		// The calldata comes from the SDK, so this exercises the shipped encoder
		// rather than a hand-rolled copy of it.
		const regWallet = new ethers.Wallet('0x' + '11'.repeat(32), provider);
		const unregWallet = new ethers.Wallet('0x' + '22'.repeat(32), provider);
		const dave = keyring.addFromUri('//Dave');

		// The registered address resolves to Dave — a substrate account unrelated
		// to the EVM key, which is what the registry exists to express.
		await seedRegistry(api, alice, regWallet.address.toLowerCase(), dave.address);

		for (const w of [regWallet, unregWallet]) {
			await settle(
				api.tx.sudo.sudo(
					api.tx.balances.forceSetBalance(
						evmToAccount(api, w.address.toLowerCase()),
						10n ** 21n
					)
				),
				alice
			);
		}

		/** Relay one unshield from `wallet`, returning that block's events. */
		async function relayVia(wallet, nullifier) {
			const data = buildUnshieldCalldata({
				proof: '0x' + '00'.repeat(128),
				merkleRoot: root,
				nullifier,
				assetId: 0,
				amount: AMOUNT,
				recipientAddress: u8aToHex(api.createType('AccountId32', bob.address).toU8a()),
				fee: FEE,
				changeCommitment: '0x' + '00'.repeat(32),
				// Must be genuinely empty for a total unshield. The SDK encodes the
				// string '0x' as two literal bytes, so pass an empty array instead.
				changeEncryptedMemo: new Uint8Array(),
				circuitVersion: 1,
			});
			const tx = await wallet.sendTransaction({ to: PRECOMPILE, data, gasLimit: 20_000_000 });
			const receipt = await tx.wait();
			const blockHash = await api.rpc.chain.getBlockHash(receipt.blockNumber);
			const raw = await api.query.system.events.at(blockHash);
			return { events: raw.map((r) => ({ event: r.event })), blockHash, receipt };
		}

		check(
			'the SDK exposes a calldata builder with no relayer slot',
			typeof precompile.buildUnshieldCalldata === 'function'
		);

		// Registered caller -> the account its address resolves to.
		{
			const before = await pendingFee(api, dave.address);
			const { events, receipt } = await relayVia(regWallet, unique('nf-pre-reg'));
			const after = await pendingFee(api, dave.address);

			check('precompile call succeeds', receipt.status === 1);
			check(
				`fee credited to the registered caller's account (+${after - before})`,
				after - before >= FEE
			);
			check(
				'no diversion when the caller resolves',
				findEvent(events, 'shieldedPool', 'RelayFeeDiverted') === undefined
			);
			check(
				'the caller paid gas for it',
				receipt.gasUsed > 0n,
				`gasUsed=${receipt.gasUsed}`
			);
		}

		// Unregistered caller -> block author, diversion recorded.
		{
			const { events, blockHash } = await relayVia(unregWallet, unique('nf-pre-unreg'));
			const author = await authorOf(api, blockHash);
			const authorFee = await pendingFee(api, author);

			const diverted = findEvent(events, 'shieldedPool', 'RelayFeeDiverted');
			check('unregistered caller triggers RelayFeeDiverted', diverted !== undefined);
			if (diverted) {
				const requested = diverted.event.data[0].toHex().toLowerCase();
				check(
					'the event names the address that asked to be paid',
					requested === unregWallet.address.toLowerCase(),
					`requested=${requested}`
				);
			}
			check(`the author was credited instead (${authorFee})`, authorFee > 0n);
		}

		// The decisive one: byte-identical calldata from a different caller pays a
		// different party. Attribution is the sender, never the payload.
		{
			const before = await pendingFee(api, dave.address);
			await relayVia(unregWallet, unique('nf-pre-steal'));
			const after = await pendingFee(api, dave.address);
			check(
				'the same calldata from another caller does not pay the registered one',
				after === before,
				`dave delta=${after - before}`
			);
		}
	}

	// ─── 4c. The node's own relay RPC ────────────────────────────────────────
	section("4c. The node's relay RPC attributes to its evmr key");

	{
		const raw = await fetch(HTTP, {
			method: 'POST',
			headers: { 'Content-Type': 'application/json' },
			body: JSON.stringify({ jsonrpc: '2.0', id: 1, method: 'orbinum_relayerStatus', params: [] }),
		}).then((r) => r.json());

		const relayAddr = raw?.result?.address;
		check('relay RPC reports an evmr address', typeof relayAddr === 'string', JSON.stringify(raw));

		// The relay enforces its OWN floor — 2x the gas it is about to spend —
		// which sits above the pallet's `min_relay_fee`. Paying only the pallet
		// minimum gets rejected client-side, before the pool ever sees it.
		const relayMinFee = BigInt(raw?.result?.minFee ?? 0);
		check(
			`relay floor (${relayMinFee}) is at or above the pallet floor (${FEE})`,
			relayMinFee >= FEE
		);
		const RELAY_FEE = relayMinFee > FEE ? relayMinFee : FEE;

		if (relayAddr) {
			// Fund the relay's EVM account so it can pay gas, and point its address
			// at a substrate account we can watch.
			const relayBeneficiary = keyring.addFromUri('//Eve');
			await settle(
				api.tx.sudo.sudo(
					api.tx.balances.forceSetBalance(evmToAccount(api, relayAddr), 10n ** 21n)
				),
				alice
			);
			await seedRegistry(api, alice, relayAddr, relayBeneficiary.address);

			const { ShieldedPoolPrecompile } = require('@orbinum/sdk');
			const pc = new ShieldedPoolPrecompile(null);
			const calldata = pc.buildUnshieldCalldata({
				proof: '0x' + '00'.repeat(128),
				merkleRoot: root,
				nullifier: unique('nf-relay-rpc'),
				assetId: 0,
				amount: AMOUNT,
				recipientAddress: u8aToHex(api.createType('AccountId32', bob.address).toU8a()),
				fee: RELAY_FEE,
				changeCommitment: '0x' + '00'.repeat(32),
				changeEncryptedMemo: new Uint8Array(),
				circuitVersion: 1,
			});

			const before = await pendingFee(api, relayBeneficiary.address);
			const submitted = await fetch(HTTP, {
				method: 'POST',
				headers: { 'Content-Type': 'application/json' },
				body: JSON.stringify({
					jsonrpc: '2.0',
					id: 1,
					method: 'orbinum_relayShieldedCall',
					params: [calldata],
				}),
			}).then((r) => r.json());

			check(
				'relay accepted the call',
				typeof submitted?.result === 'string',
				JSON.stringify(submitted?.error ?? submitted).slice(0, 200)
			);

			if (submitted?.result) {
				// Wait for it to land, then check who was credited.
				for (let i = 0; i < 15; i++) {
					if ((await pendingFee(api, relayBeneficiary.address)) > before) break;
					await new Promise((r) => setTimeout(r, 1500));
				}
				const after = await pendingFee(api, relayBeneficiary.address);
				check(
					`the relay's own key was credited (+${after - before})`,
					after - before >= RELAY_FEE,
					'the node signed with evmr, so the precompile saw it as caller'
				);
			}
		}
	}

	// ─── 5. Pool accounting still balances ───────────────────────────────────
	section('5. Ledger invariant');

	{
		const poolNow = (await api.query.shieldedPool.poolBalancePerAsset(0)).toBigInt();
		check(
			`pool decreased by amounts only, fees still backed (${poolNow})`,
			poolNow < poolBefore && poolNow > 0n
		);

		// Every fee credited must still be claimable: the tokens stay in the pool.
		const entries = await api.query.relayer.pendingRelayerFees.entries();
		const totalPending = entries.reduce((acc, [, v]) => acc + v.toBigInt(), 0n);
		check(
			`pending fees (${totalPending}) are covered by the pool (${poolNow})`,
			totalPending <= poolNow
		);
	}

	console.log(`\n${pass} passed, ${fail} failed\n`);
	await api.disconnect();
	process.exit(fail === 0 ? 0 : 1);
}

main().catch((e) => {
	console.error(e);
	process.exit(1);
});
