import { assert } from "chai";
import { ethers } from "ethers";

import { createAndFinalizeBlock, customRequest, describeWithFrontier } from "./util";

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// The relay identity `evm_relay_key::resolve` injects on dev chains: Alice's
/// ECDSA key. It is endowed in the development genesis so relaying can pay gas.
const RELAYER_ADDRESS = "0xe04cc55ebee1cbce552f250e85c57b70b2e2625b";

/// Minimum relay fee, read from the node at suite start.
///
/// The effective floor is derived from the current base fee, so it is not a
/// constant: hardcoding one makes every "just below the minimum" case either
/// vacuous or wrong the moment fees move.
let MIN_RELAY_FEE: bigint;

/// Function selectors, derived below from the ABI signatures rather than
/// hardcoded. A stale copy here fails silently: the tests keep passing because
/// a wrong selector still produces "unsupported selector", so the negative
/// cases go green while the positive ones silently test nothing.
const SIG_UNSHIELD = "unshield(bytes,bytes32,bytes32,uint32,uint256,bytes32,uint256,bytes32,bytes,uint32)";
const SIG_PRIVATE_TRANSFER = "privateTransfer(bytes,bytes32,bytes32[],bytes32[],bytes[],uint32,uint256,uint32)";

const SEL_UNSHIELD = ethers.id(SIG_UNSHIELD).slice(2, 10);
const SEL_PRIVATE_TRANSFER = ethers.id(SIG_PRIVATE_TRANSFER).slice(2, 10);

// ---------------------------------------------------------------------------
// Calldata builders
// ---------------------------------------------------------------------------

const abiCoder = ethers.AbiCoder.defaultAbiCoder();

/**
 * Build ABI-encoded calldata for `unshield(...)` with the given relay fee.
 *
 * The argument list mirrors SIG_UNSHIELD exactly — the head is 10 slots, and the
 * relay's `min_calldata_len` (324 = 4 + 10×32) is derived from that. Encoding a
 * shorter argument list here would build calldata the relay rightly refuses.
 *
 * ABI head layout after prepending the selector:
 *   data[196..228] = slot 6 = uint256 fee  ← the value relay.rs reads
 */
function buildUnshieldCalldata(fee: bigint): string {
	const encoded = abiCoder.encode(
		["bytes", "bytes32", "bytes32", "uint32", "uint256", "bytes32", "uint256", "bytes32", "bytes", "uint32"],
		[
			"0x" + "aa".repeat(32), // proof (32 dummy bytes)
			"0x" + "bb".repeat(32), // merkle root
			"0x" + "cc".repeat(32), // nullifier
			0, // assetId
			ethers.parseEther("1"), // amount
			"0x" + "11".repeat(32), // recipient (AccountId32; must not be zero)
			fee, // relay fee
			"0x" + "00".repeat(32), // change commitment (total unshield → zero)
			"0x", // change encrypted memo (empty for total unshield)
			1, // circuit version
		]
	);
	return "0x" + SEL_UNSHIELD + encoded.slice(2);
}

/**
 * Build ABI-encoded calldata for `privateTransfer(...)` with the given relay fee.
 *
 * Mirrors SIG_PRIVATE_TRANSFER: 8 head slots, so `min_calldata_len` is
 * 260 = 4 + 8×32.
 *
 * ABI head layout: data[196..228] = slot 6 = uint256 fee
 */
function buildPrivateTransferCalldata(fee: bigint): string {
	const encoded = abiCoder.encode(
		["bytes", "bytes32", "bytes32[]", "bytes32[]", "bytes[]", "uint32", "uint256", "uint32"],
		[
			"0x" + "aa".repeat(32), // proof
			"0x" + "bb".repeat(32), // merkle root
			["0x" + "cc".repeat(32)], // nullifiers[]
			["0x" + "dd".repeat(32)], // output commitments[]
			["0x" + "ee".repeat(180)], // encrypted memos[] (must be exactly 180 bytes)
			0, // assetId
			fee, // relay fee
			1, // circuit version
		]
	);
	return "0x" + SEL_PRIVATE_TRANSFER + encoded.slice(2);
}

// ---------------------------------------------------------------------------
// Relay RPC
//
// Dev chains get a relay key injected automatically, so there is no "relay
// disabled" case to cover here — that only happens on a non-dev chain with no
// `evmr` key in its keystore.
// ---------------------------------------------------------------------------

describeWithFrontier("Frontier RPC (Relay)", (context) => {
	before("read the effective minimum relay fee", async () => {
		const result = await customRequest(context.web3, "orbinum_relayerStatus", []);
		assert.notExists(result.error, `unexpected RPC error: ${JSON.stringify(result.error)}`);
		MIN_RELAY_FEE = BigInt(result.result.minFee);
	});

	// ── orbinum_relayerStatus ──────────────────────────────────────────

	it("orbinum_relayerStatus: enabled, correct address, positive minFee", async () => {
		const result = await customRequest(context.web3, "orbinum_relayerStatus", []);
		assert.notExists(result.error, `unexpected RPC error: ${JSON.stringify(result.error)}`);

		const status = result.result;
		assert.equal(status.address.toLowerCase(), RELAYER_ADDRESS, "relayer address should be the dev relay identity");
		// enabled tracks whether the relay can cover a transaction, so it doubles
		// as the check that the dev genesis actually endowed the relay account.
		assert.isTrue(
			BigInt(status.balanceWei) > BigInt(0),
			"relay account must be endowed in the development genesis"
		);
		assert.isTrue(status.enabled, "relayer should report enabled=true");
		assert.isTrue(BigInt(status.minFee) > BigInt(0), "minFee must be positive");
	});

	// ── Validation errors ──────────────────────────────────────────────

	it("rejects empty calldata (too short)", async () => {
		const result = await customRequest(context.web3, "orbinum_relayShieldedCall", ["0x"]);
		assert.exists(result.error, "expected error for empty calldata");
		assert.include(JSON.stringify(result.error), "calldata too short");
	});

	it("rejects calldata shorter than 228 bytes", async () => {
		const short = "0x" + "00".repeat(100);
		const result = await customRequest(context.web3, "orbinum_relayShieldedCall", [short]);
		assert.exists(result.error, "expected error for short calldata");
		assert.include(JSON.stringify(result.error), "calldata too short");
	});

	it("rejects calldata of exactly 227 bytes (one byte short of 228)", async () => {
		const data = "0x" + "00".repeat(227);
		const result = await customRequest(context.web3, "orbinum_relayShieldedCall", [data]);
		assert.exists(result.error, "expected error for 227-byte calldata");
		assert.include(JSON.stringify(result.error), "calldata too short");
	});

	it("rejects unknown function selector", async () => {
		// 0xdeadbeef is not in the relay whitelist
		const data = "0xdeadbeef" + "00".repeat(224);
		const result = await customRequest(context.web3, "orbinum_relayShieldedCall", [data]);
		assert.exists(result.error, "expected error for unknown selector");
		assert.include(JSON.stringify(result.error), "unsupported selector");
	});

	it("rejects fee = 0 (slot 6 is zero)", async () => {
		const data = buildUnshieldCalldata(BigInt(0));
		const result = await customRequest(context.web3, "orbinum_relayShieldedCall", [data]);
		assert.exists(result.error, "expected error for zero fee");
		assert.include(JSON.stringify(result.error), "fee below minimum");
	});

	it("rejects fee 1 wei below the minimum", async () => {
		const data = buildUnshieldCalldata(MIN_RELAY_FEE - BigInt(1));
		const result = await customRequest(context.web3, "orbinum_relayShieldedCall", [data]);
		assert.exists(result.error, "expected error for sub-minimum fee");
		assert.include(JSON.stringify(result.error), "fee below minimum");
	});

	it("rejects privateTransfer with fee 1 wei below the minimum", async () => {
		const data = buildPrivateTransferCalldata(MIN_RELAY_FEE - BigInt(1));
		const result = await customRequest(context.web3, "orbinum_relayShieldedCall", [data]);
		assert.exists(result.error, "expected error for sub-minimum fee");
		assert.include(JSON.stringify(result.error), "fee below minimum");
	});

	// ── Fee is read from slot 6 (data[196..228]), NOT slot 5 (data[164..196]) ──

	it("does NOT read fee from slot 5 (regression: old wrong position)", async () => {
		// Build calldata with exact min fee in the correct position (slot 6)
		// but verify we're not fooled by a large value in slot 5 (recipient).
		// If relay incorrectly read slot 5, it would accept zero-fee calldata
		// where slot 5 happened to be large.
		const data = buildUnshieldCalldata(BigInt(0)); // fee = 0 at slot 6
		// Overwrite slot 5 (data[164..196]) with a large value
		const dataBytes = Buffer.from(data.slice(2), "hex");
		const largeFee = ethers.toBeHex(MIN_RELAY_FEE, 32).slice(2);
		dataBytes.set(Buffer.from(largeFee, "hex"), 164);
		const tampered = "0x" + dataBytes.toString("hex");
		// Slot 6 is still zero → relay must reject as "fee below minimum"
		const result = await customRequest(context.web3, "orbinum_relayShieldedCall", [tampered]);
		assert.exists(result.error, "relay must not accept zero-fee calldata");
		assert.include(
			JSON.stringify(result.error),
			"fee below minimum",
			"fee regression: relay must read from slot 6, not slot 5"
		);
	});

	// ── Happy path ─────────────────────────────────────────────────────
	//
	// Skipped, not broken. The relay dry-runs the call against the EVM before it
	// will sign anything, so accepting calldata means the whole shielded operation
	// must succeed: a merkle root the pool knows, an unspent nullifier, and a
	// proof that verifies. Dummy calldata cannot clear that, and these cases have
	// never been able to pass. Covering them needs a funded pool with a real note,
	// which is what ts-tests/e2e-relay-*.cjs does against a seeded chain.

	it.skip("accepts valid unshield calldata with exact minimum fee → returns H256 txHash", async () => {
		const data = buildUnshieldCalldata(MIN_RELAY_FEE);
		const result = await customRequest(context.web3, "orbinum_relayShieldedCall", [data]);
		assert.notExists(result.error, `unexpected error: ${JSON.stringify(result.error)}`);
		assert.match(result.result, /^0x[0-9a-fA-F]{64}$/, "result must be a 0x-prefixed 32-byte hex hash");
		await createAndFinalizeBlock(context.web3); // mine to advance relayer nonce
	});

	it.skip("accepts valid privateTransfer calldata with minimum fee → returns H256 txHash", async () => {
		const data = buildPrivateTransferCalldata(MIN_RELAY_FEE);
		const result = await customRequest(context.web3, "orbinum_relayShieldedCall", [data]);
		assert.notExists(result.error, `unexpected error: ${JSON.stringify(result.error)}`);
		assert.match(result.result, /^0x[0-9a-fA-F]{64}$/, "result must be a 0x-prefixed 32-byte hex hash");
		await createAndFinalizeBlock(context.web3);
	});

	it.skip("accepts fee larger than minimum → returns H256 txHash", async () => {
		const data = buildUnshieldCalldata(MIN_RELAY_FEE * BigInt(10));
		const result = await customRequest(context.web3, "orbinum_relayShieldedCall", [data]);
		assert.notExists(result.error, `unexpected error: ${JSON.stringify(result.error)}`);
		assert.match(result.result, /^0x[0-9a-fA-F]{64}$/);
		await createAndFinalizeBlock(context.web3);
	});

	// ── Tx lifecycle ───────────────────────────────────────────────────

	it.skip("relayed tx is visible in pending pool before block is mined", async () => {
		const data = buildUnshieldCalldata(MIN_RELAY_FEE);
		const relayResult = await customRequest(context.web3, "orbinum_relayShieldedCall", [data]);
		assert.notExists(relayResult.error, `unexpected error: ${JSON.stringify(relayResult.error)}`);
		const txHash: string = relayResult.result;

		const pending = await customRequest(context.web3, "eth_getTransactionByHash", [txHash]);
		assert.isNotNull(pending.result, "relayed tx should be in pending pool immediately");
		assert.equal(pending.result.hash.toLowerCase(), txHash.toLowerCase(), "hash in pool must match returned hash");

		await createAndFinalizeBlock(context.web3); // clean up pool
	});

	it.skip("relayed tx has a receipt after block is finalized", async () => {
		const data = buildUnshieldCalldata(MIN_RELAY_FEE);
		const relayResult = await customRequest(context.web3, "orbinum_relayShieldedCall", [data]);
		assert.notExists(relayResult.error, `unexpected error: ${JSON.stringify(relayResult.error)}`);
		const txHash: string = relayResult.result;

		await createAndFinalizeBlock(context.web3);

		const receipt = await context.web3.eth.getTransactionReceipt(txHash);
		assert.isNotNull(receipt, "receipt must exist after block is finalized");
		assert.equal(receipt.transactionHash.toLowerCase(), txHash.toLowerCase(), "receipt txHash must match");
	});
});
