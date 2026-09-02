import { expect } from "chai";
import { step } from "mocha-steps";

import { RUNTIME_SPEC_NAME } from "./config";
import { describeWithFrontier, customRequest } from "./util";

describeWithFrontier("Frontier RPC (Web3Api)", (context) => {
	// The client version embeds the runtime's spec/impl version, so hardcoding it
	// here would break on every runtime upgrade. Read the live version instead and
	// assert the shape.
	step("should get client version", async function () {
		const runtime = await customRequest(context.web3, "state_getRuntimeVersion", []);
		const { specName, specVersion, implVersion } = runtime.result;

		expect(specName).to.be.equal(RUNTIME_SPEC_NAME);

		const version = await context.web3.eth.getNodeInfo();
		expect(version).to.be.equal(`${specName}/v${specVersion}.${implVersion}/fc-rpc-2.0.0-dev`);
	});

	step("should remote sha3", async function () {
		const data = context.web3.utils.stringToHex("hello");
		const hash = await customRequest(context.web3, "web3_sha3", [data]);
		const localHash = context.web3.utils.sha3("hello");
		expect(hash.result).to.be.equal(localHash);
	});
});
