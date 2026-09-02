import { expect } from "chai";
import { ethers } from "ethers";
import { step } from "mocha-steps";

import { CHAIN_ID, GENESIS_ACCOUNT_PRIVATE_KEY } from "./config";
import { describeWithFrontier, customRequest } from "./util";

describeWithFrontier("Frontier RPC (Transaction cost)", (context) => {
	// Signed here rather than pasted as a raw hex blob: a hardcoded transaction
	// carries its own chain id and signature, so it silently stops testing what it
	// claims the moment either changes. Signing with a chain id keeps it EIP-155
	// protected — unprotected legacy transactions are refused by RPC policy before
	// they reach the pool, and the rejection under test would never be reached.
	//
	// ethers signs a zero gas limit; web3 rejects it client-side.
	step("should take transaction cost into account and not submit it to the pool", async function () {
		const wallet = new ethers.Wallet(GENESIS_ACCOUNT_PRIVATE_KEY);
		const rawTransaction = await wallet.signTransaction({
			to: "0x12cb274aad8251c875c0bf6872b67d9983e53fdd",
			value: 1,
			gasPrice: "0x3B9ACA00",
			gasLimit: 0, // below the 21000 intrinsic minimum
			nonce: 0,
			chainId: CHAIN_ID,
		});

		const tx = await customRequest(context.web3, "eth_sendRawTransaction", [rawTransaction]);

		expect(tx.error).to.include({
			message: "intrinsic gas too low",
		});
	});
});
