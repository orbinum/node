import { assert } from "chai";
import { ethers } from "ethers";

import { GENESIS_ACCOUNT_PRIVATE_KEY } from "./config";
import { createAndFinalizeBlock, customRequest, describeWithFrontier } from "./util";

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Minimum relay fee: 0.001 ORB (1e15 wei), mirrors MIN_RELAY_FEE_WEI in relay.rs
const MIN_RELAY_FEE = ethers.parseUnits("0.001", 18);

/// EVM address derived from GENESIS_ACCOUNT_PRIVATE_KEY (lower‑case, with 0x)
const RELAYER_ADDRESS = "0x6be02d1d3665660d22ff9624b7be0551ee1ac91b";

/// Verified function selectors (keccak256 of ABI signature, first 4 bytes)
const SEL_UNSHIELD = "47fc44a2";
const SEL_PRIVATE_TRANSFER = "8c0f5d24";

// ---------------------------------------------------------------------------
// Calldata builders
// ---------------------------------------------------------------------------

const abiCoder = ethers.AbiCoder.defaultAbiCoder();

/**
 * Build ABI-encoded calldata for `unshield(bytes,bytes32,bytes32,uint32,uint256,bytes32,uint256)`
 * with the given relay fee inserted as the 7th argument.
 *
 * ABI head layout after prepending the selector:
 *   data[196..228] = slot 6 = uint256 fee  ← the value relay.rs reads
 */
function buildUnshieldCalldata(fee: bigint): string {
	const encoded = abiCoder.encode(
		["bytes", "bytes32", "bytes32", "uint32", "uint256", "bytes32", "uint256"],
		[
			"0x" + "aa".repeat(32), // proof (32 dummy bytes)
			"0x" + "bb".repeat(32), // merkle root
			"0x" + "cc".repeat(32), // nullifier
			0, // assetId
			ethers.parseEther("1"), // amount
			"0x" + "00".repeat(32), // recipient (AccountId32 as bytes32)
			fee, // relay fee
		]
	);
	return "0x" + SEL_UNSHIELD + encoded.slice(2);
}

/**
 * Build ABI-encoded calldata for
 * `privateTransfer(bytes,bytes32,bytes32[],bytes32[],bytes[],uint32,uint256)`
 * with the given relay fee as the 7th argument.
 *
 * ABI head layout: data[196..228] = slot 6 = uint256 fee
 */
function buildPrivateTransferCalldata(fee: bigint): string {
	const encoded = abiCoder.encode(
		["bytes", "bytes32", "bytes32[]", "bytes32[]", "bytes[]", "uint32", "uint256"],
		[
			"0x" + "aa".repeat(32), // proof
			"0x" + "bb".repeat(32), // merkle root
			["0x" + "cc".repeat(32)], // nullifiers[]
			["0x" + "dd".repeat(32)], // output commitments[]
			["0x" + "ee".repeat(104)], // encrypted memos[]
			0, // assetId
			fee, // relay fee
		]
	);
	return "0x" + SEL_PRIVATE_TRANSFER + encoded.slice(2);
}

// ---------------------------------------------------------------------------
// Suite 1 — relay is NOT configured (no --evm-relayer-key)
// ---------------------------------------------------------------------------

describeWithFrontier("Frontier RPC (Relay – disabled)", (context) => {
	it("orbinum_relayerStatus returns method-not-found when disabled", async () => {
		const result = await customRequest(context.web3, "orbinum_relayerStatus", []);
		assert.exists(result.error, "expected JSON-RPC error but got none");
		const errStr = JSON.stringify(result.error).toLowerCase();
		assert.isTrue(
			errStr.includes("not found") || errStr.includes("-32601"),
			`unexpected error: ${errStr}`
		);
	});

	it("orbinum_relayShieldedCall returns method-not-found when disabled", async () => {
		const result = await customRequest(context.web3, "orbinum_relayShieldedCall", [
			"0x" + "00".repeat(228),
		]);
		assert.exists(result.error, "expected JSON-RPC error but got none");
		const errStr = JSON.stringify(result.error).toLowerCase();
		assert.isTrue(
			errStr.includes("not found") || errStr.includes("-32601"),
			`unexpected error: ${errStr}`
		);
	});
});

// ---------------------------------------------------------------------------
// Suite 2 — relay IS configured with the genesis test key
// ---------------------------------------------------------------------------

describeWithFrontier(
	"Frontier RPC (Relay – enabled)",
	(context) => {
		// ── orbinum_relayerStatus ──────────────────────────────────────────

		it("orbinum_relayerStatus: enabled, correct address, correct minFee", async () => {
			const result = await customRequest(context.web3, "orbinum_relayerStatus", []);
			assert.notExists(result.error, `unexpected RPC error: ${JSON.stringify(result.error)}`);

			const status = result.result;
			assert.isTrue(status.enabled, "relayer should report enabled=true");
			assert.equal(status.minFee, "1000000000000000", "minFee mismatch (expected 0.001 ORB)");
			assert.equal(
				status.address.toLowerCase(),
				RELAYER_ADDRESS,
				"relayer address should match key derived from GENESIS_ACCOUNT_PRIVATE_KEY"
			);
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

		// ── Happy path: valid calldata is accepted and tx hash is returned ─

		it("accepts valid unshield calldata with exact minimum fee → returns H256 txHash", async () => {
			const data = buildUnshieldCalldata(MIN_RELAY_FEE);
			const result = await customRequest(context.web3, "orbinum_relayShieldedCall", [data]);
			assert.notExists(result.error, `unexpected error: ${JSON.stringify(result.error)}`);
			assert.match(
				result.result,
				/^0x[0-9a-fA-F]{64}$/,
				"result must be a 0x-prefixed 32-byte hex hash"
			);
			await createAndFinalizeBlock(context.web3); // mine to advance relayer nonce
		});

		it("accepts valid privateTransfer calldata with minimum fee → returns H256 txHash", async () => {
			const data = buildPrivateTransferCalldata(MIN_RELAY_FEE);
			const result = await customRequest(context.web3, "orbinum_relayShieldedCall", [data]);
			assert.notExists(result.error, `unexpected error: ${JSON.stringify(result.error)}`);
			assert.match(
				result.result,
				/^0x[0-9a-fA-F]{64}$/,
				"result must be a 0x-prefixed 32-byte hex hash"
			);
			await createAndFinalizeBlock(context.web3);
		});

		it("accepts fee larger than minimum → returns H256 txHash", async () => {
			const data = buildUnshieldCalldata(MIN_RELAY_FEE * BigInt(10));
			const result = await customRequest(context.web3, "orbinum_relayShieldedCall", [data]);
			assert.notExists(result.error, `unexpected error: ${JSON.stringify(result.error)}`);
			assert.match(result.result, /^0x[0-9a-fA-F]{64}$/);
			await createAndFinalizeBlock(context.web3);
		});

		// ── Tx lifecycle ───────────────────────────────────────────────────

		it("relayed tx is visible in pending pool before block is mined", async () => {
			const data = buildUnshieldCalldata(MIN_RELAY_FEE);
			const relayResult = await customRequest(context.web3, "orbinum_relayShieldedCall", [data]);
			assert.notExists(relayResult.error, `unexpected error: ${JSON.stringify(relayResult.error)}`);
			const txHash: string = relayResult.result;

			const pending = await customRequest(context.web3, "eth_getTransactionByHash", [txHash]);
			assert.isNotNull(pending.result, "relayed tx should be in pending pool immediately");
			assert.equal(
				pending.result.hash.toLowerCase(),
				txHash.toLowerCase(),
				"hash in pool must match returned hash"
			);

			await createAndFinalizeBlock(context.web3); // clean up pool
		});

		it("relayed tx has a receipt after block is finalized", async () => {
			const data = buildUnshieldCalldata(MIN_RELAY_FEE);
			const relayResult = await customRequest(context.web3, "orbinum_relayShieldedCall", [data]);
			assert.notExists(relayResult.error, `unexpected error: ${JSON.stringify(relayResult.error)}`);
			const txHash: string = relayResult.result;

			await createAndFinalizeBlock(context.web3);

			const receipt = await context.web3.eth.getTransactionReceipt(txHash);
			assert.isNotNull(receipt, "receipt must exist after block is finalized");
			assert.equal(
				receipt.transactionHash.toLowerCase(),
				txHash.toLowerCase(),
				"receipt txHash must match"
			);
		});
	},
	undefined, // provider (default = http)
	["--evm-relayer-key", GENESIS_ACCOUNT_PRIVATE_KEY]
);
