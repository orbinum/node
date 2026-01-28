import { groth16 } from "snarkjs";
import * as path from "path";
import * as fs from "fs";

/**
 * Generate ZK proof for disclosure circuit
 * Uses pre-generated input from build/disclosure_input_*.json
 */
async function main() {
  console.log("\n=== Disclosure Circuit - Proof Generation ===\n");

  // Paths relative to circuits/ directory
  const buildDir = path.join(__dirname, "..", "..", "build");
  const keysDir = path.join(__dirname, "..", "..", "keys");

  // Input scenarios
  const scenarios = [
    "reveal_nothing",
    "reveal_value_only",
    "reveal_value_and_asset",
    "reveal_all",
  ];

  // Default to reveal_value_only, or use environment variable
  const scenario = process.env.DISCLOSURE_SCENARIO || "reveal_value_only";

  if (!scenarios.includes(scenario)) {
    console.error(
      `❌ Invalid scenario: ${scenario}. Must be one of: ${scenarios.join(", ")}`
    );
    process.exit(1);
  }

  const inputFile = path.join(
    buildDir,
    `disclosure_input_${scenario}.json`
  );
  const wasmFile = path.join(buildDir, "disclosure_js", "disclosure.wasm");
  const zkeyFile = path.join(keysDir, "disclosure_pk.zkey");

  console.log("1. Loading inputs...");
  console.log(`   Scenario: ${scenario}`);
  console.log(`   Input file: ${inputFile}`);

  if (!fs.existsSync(inputFile)) {
    console.error(`❌ Input file not found: ${inputFile}`);
    console.log("\n💡 Generate inputs first:");
    console.log("   npm run gen-input:disclosure");
    process.exit(1);
  }

  if (!fs.existsSync(wasmFile)) {
    console.error(`❌ WASM file not found: ${wasmFile}`);
    console.log("\n💡 Compile circuit first:");
    console.log("   npm run full-build:disclosure");
    process.exit(1);
  }

  if (!fs.existsSync(zkeyFile)) {
    console.error(`❌ Proving key not found: ${zkeyFile}`);
    console.log("\n💡 Generate keys first:");
    console.log("   npm run setup:disclosure");
    process.exit(1);
  }

  const input = JSON.parse(fs.readFileSync(inputFile, "utf-8"));

  console.log("\n2. Generating witness and proof...");
  console.log(
    `   Circuit: disclosure (${Object.keys(input).length} signals)`
  );

  const { proof, publicSignals } = await groth16.fullProve(
    input,
    wasmFile,
    zkeyFile
  );

  console.log("\n3. Saving proof and public signals...");
  const proofPath = path.join(buildDir, `proof_disclosure_${scenario}.json`);
  const publicPath = path.join(buildDir, `public_disclosure_${scenario}.json`);

  fs.writeFileSync(proofPath, JSON.stringify(proof, null, 2));
  fs.writeFileSync(publicPath, JSON.stringify(publicSignals, null, 2));

  console.log(`   ✓ Proof saved: ${proofPath}`);
  console.log(`   ✓ Public signals saved: ${publicPath}`);

  console.log("\n4. Verifying proof...");
  const vkeyPath = path.join(buildDir, "verification_key_disclosure.json");

  if (!fs.existsSync(vkeyPath)) {
    console.error(`❌ Verification key not found: ${vkeyPath}`);
    process.exit(1);
  }

  const vkey = JSON.parse(fs.readFileSync(vkeyPath, "utf-8"));
  const isValid = await groth16.verify(vkey, publicSignals, proof);

  if (isValid) {
    console.log("   ✅ Proof verified successfully!");
  } else {
    console.error("   ❌ Proof verification failed!");
    process.exit(1);
  }

  console.log("\n✅ Proof generation complete!\n");
  console.log("Generated files:");
  console.log(`  • ${proofPath}`);
  console.log(`  • ${publicPath}`);
  console.log("\nPublic signals (revealed data):");
  console.log(JSON.stringify(publicSignals, null, 2));
  console.log("\n");
}

main()
  .then(() => process.exit(0))
  .catch((error) => {
    console.error("\n❌ Error:", error.message);
    if (error.stack) {
      console.error("\nStack trace:");
      console.error(error.stack);
    }
    process.exit(1);
  });
