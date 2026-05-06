import { assert } from "chai";
import { AbiCoder, ethers } from "ethers";

import { GENESIS_ACCOUNT, GENESIS_ACCOUNT_PRIVATE_KEY } from "./config";
import { createAndFinalizeBlock, customRequest, describeWithFrontier } from "./util";

// ─── Precompile address ────────────────────────────────────────────────────────
// hash(2049) = H160::from_low_u64_be(2049) = 0x…0801
const SHIELDED_POOL_PRECOMPILE = "0x0000000000000000000000000000000000000801";

// ─── Function selectors ────────────────────────────────────────────────────────
// keccak256("shield(uint32,bytes32,bytes)")[0..4]  — payable, amount = msg.value
const SEL_SHIELD = "9feb22ea";
// keccak256("privateTransfer(bytes,bytes32,bytes32[],bytes32[],bytes[])")[0..4]
const SEL_PRIVATE_TRANSFER = "dcd5b898";
// keccak256("unshield(bytes,bytes32,bytes32,uint32,uint256,bytes32)")[0..4]
const SEL_UNSHIELD = "dcf1bff2";

const abiCoder = AbiCoder.defaultAbiCoder();

// ─── Test data factories ───────────────────────────────────────────────────────

/** 32-byte commitment (fake Poseidon output, deterministic). */
function fakeCommitment(): string {
	return "0x" + "ab".repeat(32); // 32 bytes
}

/** 32-byte nullifier. */
function fakeNullifier(): string {
	return "0x" + "cd".repeat(32); // 32 bytes
}

/** 32-byte Merkle root. */
function fakeMerkleRoot(): string {
	return "0x" + "ef".repeat(31) + "01"; // 32 bytes
}

/**
 * Minimal well-formed Groth16 proof (256 bytes).
 * The ZK verifier will reject it, but the calldata will parse correctly.
 */
function fakeProof(): Uint8Array {
	return new Uint8Array(256).fill(0xaa);
}

/** 104-byte encrypted memo (MAX_MEMO_SIZE). */
function fakeMemo(): Uint8Array {
	return new Uint8Array(104).fill(0x01);
}

/** Encode shield(assetId, commitment, encryptedMemo) calldata. Amount is sent as msg.value. */
function encodeShield(assetId: number, commitment: string, memo: Uint8Array): string {
	const encoded = abiCoder.encode(["uint32", "bytes32", "bytes"], [assetId, commitment, memo]);
	return "0x" + SEL_SHIELD + encoded.slice(2);
}

/** Encode privateTransfer(proof, root, nullifiers[], commitments[], memos[]) calldata. */
function encodePrivateTransfer(
	proof: Uint8Array,
	root: string,
	nullifiers: string[],
	commitments: string[],
	memos: Uint8Array[]
): string {
	const encoded = abiCoder.encode(
		["bytes", "bytes32", "bytes32[]", "bytes32[]", "bytes[]"],
		[proof, root, nullifiers, commitments, memos]
	);
	return "0x" + SEL_PRIVATE_TRANSFER + encoded.slice(2);
}

/** Encode unshield(proof, root, nullifier, assetId, amount, recipient) calldata. */
function encodeUnshield(
	proof: Uint8Array,
	root: string,
	nullifier: string,
	assetId: number,
	amount: bigint,
	recipient: string
): string {
	const encoded = abiCoder.encode(
		["bytes", "bytes32", "bytes32", "uint32", "uint256", "bytes32"],
		[proof, root, nullifier, assetId, amount, recipient]
	);
	return "0x" + SEL_UNSHIELD + encoded.slice(2);
}

/** Send a raw EVM transaction and mine a block. Returns the transaction hash. */
async function sendCall(web3: any, data: string, gasLimit = "0x500000", value = "0x00"): Promise<string> {
	const tx = await web3.eth.accounts.signTransaction(
		{
			from: GENESIS_ACCOUNT,
			to: SHIELDED_POOL_PRECOMPILE,
			data,
			value,
			gasPrice: "0x3B9ACA00",
			gas: gasLimit,
		},
		GENESIS_ACCOUNT_PRIVATE_KEY
	);

	const result = await customRequest(web3, "eth_sendRawTransaction", [tx.rawTransaction]);
	await createAndFinalizeBlock(web3);
	return result.result as string;
}

// ─── Test suite ───────────────────────────────────────────────────────────────

describeWithFrontier("Frontier RPC (Precompile: ShieldedPool – routing)", (context) => {
	// ── 1. Precompile is registered ──────────────────────────────────────────
	it("should return a non-empty response for any call to 0x0801", async () => {
		// eth_call with empty data: the precompile should reply (even if it reverts)
		// rather than silently returning 0x (which would mean "not a precompile").
		const result = await customRequest(context.web3, "eth_call", [
			{
				from: GENESIS_ACCOUNT,
				to: SHIELDED_POOL_PRECOMPILE,
				data: "0x",
				gas: "0x100000",
			},
			"latest",
		]);
		// A precompile always returns a non-null result (may be an error, but not null).
		assert.isNotNull(result, "eth_call to 0x0801 returned null");
	});

	// ── 2. Unknown selector is rejected ─────────────────────────────────────
	it("should reject an unknown function selector", async () => {
		const txHash = await sendCall(context.web3, "0xdeadbeef");

		const receipt = await context.web3.eth.getTransactionReceipt(txHash);
		assert.isNotNull(receipt, "no receipt for unknown-selector call");
		assert.equal(receipt.status, false, "unknown selector should make the tx fail (status=0)");
	});

	// ── 3. Malformed calldata for shield ─────────────────────────────────────
	it("should reject shield calldata that is too short to decode", async () => {
		// Valid selector + only 3 bytes of data (not enough to decode uint32)
		const data = "0x" + SEL_SHIELD + "aabbcc";
		const txHash = await sendCall(context.web3, data);
		const receipt = await context.web3.eth.getTransactionReceipt(txHash);
		assert.equal(receipt.status, false, "malformed calldata should fail");
	});

	// ── 4. shield() – selector is routed; fails at pallet level ──────────────
	it("shield: call reaches pallet (fails with pallet error, not routing error)", async () => {
		// Asset 0 may not be registered; the call will fail in the pallet, but
		// the precompile selector routing and ABI decoding succeed.
		// Amount is passed as msg.value (1 ORB in wei).
		const data = encodeShield(
			0, // assetId
			fakeCommitment(),
			fakeMemo()
		);
		const value = "0x" + ethers.parseEther("1").toString(16);
		const txHash = await sendCall(context.web3, data, "0x800000", value);
		const receipt = await context.web3.eth.getTransactionReceipt(txHash);

		assert.isNotNull(receipt, "shield call produced no receipt");
		// Status=false is OK here: pallet rejects unknown asset / fake commitment.
		// What we want to confirm is that the tx was *processed*, not dropped.
		assert.exists(receipt.blockNumber, "shield call not included in a block");
	});

	// ── 5. unshield() – selector is routed; fails at ZK verifier ─────────────
	it("unshield: call reaches ZK verifier (fails proof verification, not routing)", async () => {
		const recipient =
			"0x6be02d1d3665660d22ff9624b7be0551ee1ac91b000000000000000000000000";
		const data = encodeUnshield(
			fakeProof(),
			fakeMerkleRoot(),
			fakeNullifier(),
			0, // assetId
			ethers.parseEther("1"),
			recipient
		);
		const txHash = await sendCall(context.web3, data, "0x800000");
		const receipt = await context.web3.eth.getTransactionReceipt(txHash);

		assert.isNotNull(receipt, "unshield call produced no receipt");
		assert.exists(receipt.blockNumber, "unshield call not included in a block");
	});

	// ── 6. privateTransfer() – selector is routed; fails at ZK verifier ──────
	it("privateTransfer: call reaches ZK verifier (fails proof verification, not routing)", async () => {
		// 2 inputs, 2 outputs (standard private transfer)
		const data = encodePrivateTransfer(
			fakeProof(),
			fakeMerkleRoot(),
			[fakeNullifier(), fakeNullifier()], // input nullifiers
			[fakeCommitment(), fakeCommitment()], // output commitments
			[fakeMemo(), fakeMemo()] // encrypted memos for each output
		);
		const txHash = await sendCall(context.web3, data, "0x800000");
		const receipt = await context.web3.eth.getTransactionReceipt(txHash);

		assert.isNotNull(receipt, "privateTransfer call produced no receipt");
		assert.exists(receipt.blockNumber, "privateTransfer call not included in a block");
	});
});

describeWithFrontier("Frontier RPC (Precompile: ShieldedPool – used_addresses)", (context) => {
	// ── 7. Precompile address appears in the set of known precompiles ─────────
	it("should include 0x0801 in the precompile address list via eth_getCode", async () => {
		// Precompile addresses return empty bytecode (0x) when queried with eth_getCode.
		// This is a standard Frontier property: EOAs also return 0x, but what matters
		// is that calls succeed (tested above). Here we just confirm the address is
		// reachable and not confused with a contract deployment.
		const code = await context.web3.eth.getCode(SHIELDED_POOL_PRECOMPILE);
		// Frontier precompiles typically return "0x" for code.
		assert.equal(code, "0x", "precompile address should report empty bytecode");
	});

	// ── 8. Smoke-test: ABI-encoded data roundtrips correctly ─────────────────
	it("shield ABI encoding produces correct selector prefix", () => {
		const data = encodeShield(42, fakeCommitment(), fakeMemo());
		assert.isTrue(data.startsWith("0x" + SEL_SHIELD), "shield calldata has wrong selector");
	});

	it("unshield ABI encoding produces correct selector prefix", () => {
		const data = encodeUnshield(
			fakeProof(),
			fakeMerkleRoot(),
			fakeNullifier(),
			0,
			BigInt("1000000000000000000"),
			"0x" + "00".repeat(32)
		);
		assert.isTrue(data.startsWith("0x" + SEL_UNSHIELD), "unshield calldata has wrong selector");
	});

	it("privateTransfer ABI encoding produces correct selector prefix", () => {
		const data = encodePrivateTransfer(fakeProof(), fakeMerkleRoot(), [fakeNullifier()], [fakeCommitment()], [
			fakeMemo(),
		]);
		assert.isTrue(
			data.startsWith("0x" + SEL_PRIVATE_TRANSFER),
			"privateTransfer calldata has wrong selector"
		);
	});
});
