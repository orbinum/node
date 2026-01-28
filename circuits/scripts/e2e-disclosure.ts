import { execSync } from "child_process";

/**
 * End-to-End workflow for disclosure circuit
 * Executes: compile → setup → gen-input → prove
 */

const CIRCUITS_DIR = "/Users/nolascomedina/Documents/Dev/orb/node/circuits";

function run(command: string, description: string) {
  console.log(`\n${"=".repeat(70)}`);
  console.log(`  ${description}`);
  console.log(`${"=".repeat(70)}\n`);

  try {
    execSync(`cd ${CIRCUITS_DIR} && ${command}`, {
      stdio: "inherit",
      encoding: "utf-8",
    });
  } catch (error) {
    console.error(`\n❌ Error executing: ${command}`);
    process.exit(1);
  }
}

function main() {
  console.log("\n");
  console.log("╔" + "═".repeat(68) + "╗");
  console.log("║" + " ".repeat(68) + "║");
  console.log(
    "║" +
      " ".repeat(15) +
      "DISCLOSURE CIRCUIT - E2E WORKFLOW" +
      " ".repeat(20) +
      "║"
  );
  console.log("║" + " ".repeat(68) + "║");
  console.log("╚" + "═".repeat(68) + "╝");
  console.log("\n");

  // Step 1: Compile circuit
  run("npm run compile:disclosure", "Step 1/5: Compile Circuit");

  // Step 2: Generate proving/verification keys
  run("npm run setup:disclosure", "Step 2/5: Setup Keys");

  // Step 3: Convert keys (optional)
  run("npm run convert:disclosure", "Step 3/5: Convert Keys");

  // Step 4: Generate test inputs (all scenarios)
  run("npm run gen-input:disclosure", "Step 4/5: Generate Test Inputs");

  // Step 5: Generate proofs for all scenarios
  console.log(`\n${"=".repeat(70)}`);
  console.log(`  Step 5/5: Generate Proofs (All Scenarios)`);
  console.log(`${"=".repeat(70)}\n`);

  const scenarios = [
    "reveal_nothing",
    "reveal_value_only",
    "reveal_value_and_asset",
    "reveal_all",
  ];

  for (const scenario of scenarios) {
    console.log(`\n📋 Generating proof for: ${scenario}...`);
    try {
      execSync(
        `cd ${CIRCUITS_DIR} && DISCLOSURE_SCENARIO=${scenario} npm run prove:disclosure`,
        {
          stdio: "inherit",
          encoding: "utf-8",
        }
      );
    } catch (error) {
      console.error(`\n❌ Error generating proof for ${scenario}`);
      process.exit(1);
    }
  }

  console.log("\n");
  console.log("╔" + "═".repeat(68) + "╗");
  console.log("║" + " ".repeat(68) + "║");
  console.log(
    "║" +
      " ".repeat(20) +
      "✅ E2E WORKFLOW COMPLETE!" +
      " ".repeat(21) +
      "║"
  );
  console.log("║" + " ".repeat(68) + "║");
  console.log("╚" + "═".repeat(68) + "╝");
  console.log("\n");

  console.log("Generated artifacts in circuits/build/:");
  console.log("  • disclosure.r1cs");
  console.log("  • disclosure.wasm");
  console.log("  • verification_key_disclosure.json");
  console.log("  • 4 input files (disclosure_input_*.json)");
  console.log("  • 4 proof files (proof_disclosure_*.json)");
  console.log("  • 4 public signal files (public_disclosure_*.json)");
  console.log("\nNext steps:");
  console.log("  • Run benchmarks: npm run bench:disclosure");
  console.log("  • View results: cat build/benchmark_results_disclosure.json");
  console.log("\n");
}

main();
process.exit(0);
