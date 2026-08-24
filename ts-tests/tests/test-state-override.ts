import { expect, use as chaiUse } from "chai";
import chaiAsPromised from "chai-as-promised";
import Web3 from "web3";
import { AbiItem } from "web3-utils";

import StateOverrideTest from "../build/contracts/StateOverrideTest.json";
import Test from "../build/contracts/Test.json";
import { GENESIS_ACCOUNT, GENESIS_ACCOUNT_BALANCE, GENESIS_ACCOUNT_PRIVATE_KEY } from "./config";
import { createAndFinalizeBlock, customRequest, describeWithFrontier } from "./util";

chaiUse(chaiAsPromised);

describeWithFrontier("Frontier RPC (StateOverride)", (context) => {
	const STATE_OVERRIDE_TEST_CONTRACT_BYTECODE = StateOverrideTest.bytecode;
	const otherAddress = "0xd43593c715fdd31c61141abd04a99fd6822c8558";

	let contract;
	let contractAddress;
	before("create the contract", async function () {
		this.timeout(15000);
		contract = new context.web3.eth.Contract(StateOverrideTest.abi as AbiItem[]);
		const data = contract
			.deploy({
				data: STATE_OVERRIDE_TEST_CONTRACT_BYTECODE,
				arguments: [100],
			})
			.encodeABI();
		const tx = await context.web3.eth.accounts.signTransaction(
			{
				from: GENESIS_ACCOUNT,
				data,
				value: Web3.utils.numberToHex(Web3.utils.toWei("1", "ether")),
				gas: "0x100000",
			},
			GENESIS_ACCOUNT_PRIVATE_KEY
		);
		const { result } = await customRequest(context.web3, "eth_sendRawTransaction", [tx.rawTransaction]);
		await createAndFinalizeBlock(context.web3);
		const receipt = await context.web3.eth.getTransactionReceipt(result);
		contractAddress = receipt.contractAddress;

		const txSetAllowance = await context.web3.eth.accounts.signTransaction(
			{
				from: GENESIS_ACCOUNT,
				to: contractAddress,
				data: contract.methods.setAllowance(otherAddress, 10).encodeABI(),
				gas: "0x100000",
				gasPrice: "0x3B9ACA00",
				value: "0x0",
			},
			GENESIS_ACCOUNT_PRIVATE_KEY
		);
		await customRequest(context.web3, "eth_sendRawTransaction", [txSetAllowance.rawTransaction]);
		await createAndFinalizeBlock(context.web3);
	});

	// The genesis account is endowed DEV_BALANCE (10_000 ORB), minus whatever the
	// deploy in `before` spent on gas.
	it("should report the real sender balance without state override", async function () {
		const { result } = await customRequest(context.web3, "eth_call", [
			{
				from: GENESIS_ACCOUNT,
				to: contractAddress,
				data: contract.methods.getSenderBalance().encodeABI(),
			},
		]);
		const balance = Web3.utils.toBN(Web3.utils.hexToNumberString(result));
		const endowment = Web3.utils.toBN(GENESIS_ACCOUNT_BALANCE);

		expect(balance.lte(endowment), "balance exceeded the genesis endowment").to.be.true;
		// A tenth of the endowment is far more than the deploy costs; anything
		// below it would mean the account is not the endowed one.
		expect(balance.gte(endowment.divn(10)), "balance was implausibly low").to.be.true;
	});

	// Balance and nonce overrides are the only ones that go through the runtime's
	// RuntimeStorageOverride, which has to rebuild the System::Account key itself.
	// Get the address derivation wrong and the key does not exist, so the override
	// is dropped and the call silently returns real chain state.
	it("should have a balance of 5000 with state override", async function () {
		const { result } = await customRequest(context.web3, "eth_call", [
			{
				from: GENESIS_ACCOUNT,
				to: contractAddress,
				data: contract.methods.getBalance().encodeABI(),
			},
			"latest",
			{
				[contractAddress]: {
					balance: Web3.utils.numberToHex(5000),
				},
			},
		]);
		expect(Web3.utils.hexToNumberString(result)).to.equal("5000");
	});

	it("should override the sender balance", async function () {
		const { result: real } = await customRequest(context.web3, "eth_call", [
			{
				from: GENESIS_ACCOUNT,
				to: contractAddress,
				data: contract.methods.getSenderBalance().encodeABI(),
			},
		]);
		expect(Web3.utils.hexToNumberString(real)).to.not.equal("1234");

		const { result } = await customRequest(context.web3, "eth_call", [
			{
				from: GENESIS_ACCOUNT,
				to: contractAddress,
				data: contract.methods.getSenderBalance().encodeABI(),
			},
			"latest",
			{
				[GENESIS_ACCOUNT]: {
					balance: Web3.utils.numberToHex(1234),
				},
			},
		]);
		expect(Web3.utils.hexToNumberString(result)).to.equal("1234");
	});

	it("should have availableFunds of 100 without state override", async function () {
		const { result } = await customRequest(context.web3, "eth_call", [
			{
				from: GENESIS_ACCOUNT,
				to: contractAddress,
				data: contract.methods.availableFunds().encodeABI(),
			},
		]);
		expect(Web3.utils.hexToNumberString(result)).to.equal("100");
	});

	it("should have availableFunds of 500 with state override", async function () {
		const availableFundsKey = Web3.utils.padLeft(Web3.utils.numberToHex(1), 64); // slot 1
		const newValue = Web3.utils.padLeft(Web3.utils.numberToHex(500), 64);

		const { result } = await customRequest(context.web3, "eth_call", [
			{
				from: GENESIS_ACCOUNT,
				to: contractAddress,
				data: contract.methods.availableFunds().encodeABI(),
			},
			"latest",
			{
				[contractAddress]: {
					stateDiff: {
						[availableFundsKey]: newValue,
					},
				},
			},
		]);
		expect(Web3.utils.hexToNumberString(result)).to.equal("500");
	});

	it("should have allowance of 10 without state override", async function () {
		const { result } = await customRequest(context.web3, "eth_call", [
			{
				from: GENESIS_ACCOUNT,
				to: contractAddress,
				data: contract.methods.allowance(GENESIS_ACCOUNT, otherAddress).encodeABI(),
			},
		]);
		expect(Web3.utils.hexToNumberString(result)).to.equal("10");
	});

	it("should have allowance of 50 with state override", async function () {
		const allowanceKey = Web3.utils.soliditySha3(
			{
				type: "uint256",
				value: otherAddress,
			},
			{
				type: "uint256",
				value: Web3.utils.soliditySha3(
					{
						type: "uint256",
						value: GENESIS_ACCOUNT,
					},
					{
						type: "uint256",
						value: "2", // slot 2
					}
				),
			}
		);
		const newValue = Web3.utils.padLeft(Web3.utils.numberToHex(50), 64);

		const { result } = await customRequest(context.web3, "eth_call", [
			{
				from: GENESIS_ACCOUNT,
				to: contractAddress,
				data: contract.methods.allowance(GENESIS_ACCOUNT, otherAddress).encodeABI(),
			},
			"latest",
			{
				[contractAddress]: {
					stateDiff: {
						[allowanceKey]: newValue,
					},
				},
			},
		]);
		expect(Web3.utils.hexToNumberString(result)).to.equal("50");
	});

	it("should have allowance of 50 but availableFunds 0 with full state override", async function () {
		const allowanceKey = Web3.utils.soliditySha3(
			{
				type: "uint256",
				value: otherAddress,
			},
			{
				type: "uint256",
				value: Web3.utils.soliditySha3(
					{
						type: "uint256",
						value: GENESIS_ACCOUNT,
					},
					{
						type: "uint256",
						value: "2", // slot 2
					}
				),
			}
		);
		const newValue = Web3.utils.padLeft(Web3.utils.numberToHex(50), 64);

		const { result } = await customRequest(context.web3, "eth_call", [
			{
				from: GENESIS_ACCOUNT,
				to: contractAddress,
				data: contract.methods.allowance(GENESIS_ACCOUNT, otherAddress).encodeABI(),
			},
			"latest",
			{
				[contractAddress]: {
					state: {
						[allowanceKey]: newValue,
					},
				},
			},
		]);
		expect(Web3.utils.hexToNumberString(result)).to.equal("50");

		const { result: result2 } = await customRequest(context.web3, "eth_call", [
			{
				from: GENESIS_ACCOUNT,
				to: contractAddress,
				data: contract.methods.availableFunds().encodeABI(),
			},
			"latest",
			{
				[contractAddress]: {
					state: {
						[allowanceKey]: newValue,
					},
				},
			},
		]);
		expect(Web3.utils.hexToNumberString(result2)).to.equal("0");
	});

	it("should set MultiplyBy7 deployedBytecode with state override", async function () {
		const testContract = new context.web3.eth.Contract(Test.abi as AbiItem[]);
		const { result } = await customRequest(context.web3, "eth_call", [
			{
				from: GENESIS_ACCOUNT,
				to: contractAddress,
				data: testContract.methods.multiply(5).encodeABI(), // multiplies by 7
			},
			"latest",
			{
				[contractAddress]: {
					code: Test.deployedBytecode,
				},
			},
		]);
		expect(Web3.utils.hexToNumberString(result)).to.equal("35");
	});
});
