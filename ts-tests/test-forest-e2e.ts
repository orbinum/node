/**
 * Multi-tree forest E2E against a local dev node built with
 * MaxLeavesPerTree = 8 (local-only runtime tweak).
 *
 * Shields 10 notes to cross the first seal, then asserts:
 *  - TreeSealed { tree_id: 0 } fired with the expected final root
 *  - leaves 0..7 anchor to the sealed root (tree_id 0) via privacy RPC
 *  - leaves 8..9 anchor to the live root (tree_id 1)
 *  - privacy_getMerkleRoot equals the active-tree root
 *
 * Run: npx ts-node test-forest-e2e.ts [ws://127.0.0.1:9944]
 */
import { ApiPromise, WsProvider } from "@polkadot/api";
import { Keyring } from "@polkadot/keyring";
import { cryptoWaitReady } from "@polkadot/util-crypto";
import assert from "assert";

const WS_URL = process.argv[2] ?? "ws://127.0.0.1:9944";
const MEMO_SIZE = 180;
const AMOUNT = 10n ** 18n; // MinShieldAmount

function commitment(i: number): string {
    const b = Buffer.alloc(32);
    b.writeUInt32LE(i + 1, 0);
    b[31] = 0x42;
    return "0x" + b.toString("hex");
}

function memo(i: number): string {
    // EncryptedMemo is a newtype over BoundedVec<u8, 180>; pass exact-length hex.
    return "0x" + (i + 1).toString(16).padStart(2, "0") + "00".repeat(MEMO_SIZE - 1);
}

let provider: WsProvider;

async function rpc(_api: ApiPromise, method: string, params: unknown[]): Promise<any> {
    return provider.send(method, params);
}

async function main() {
    await cryptoWaitReady();
    provider = new WsProvider(WS_URL);
    const api = await ApiPromise.create({ provider, noInitWarn: true });
    const alice = new Keyring({ type: "sr25519" }).addFromUri("//Alice");

    let sealedEvent: { treeId: number; finalRoot: string } | null = null;

    let nonce = (await api.rpc.system.accountNextIndex(alice.address)).toNumber();
    for (let i = 0; i < 10; i++) {
        await new Promise<void>((resolve, reject) => {
            api.tx.shieldedPool
                .shield(0, AMOUNT, commitment(i), memo(i))
                .signAndSend(alice, { nonce: nonce++ }, ({ status, events, dispatchError }) => {
                    if (dispatchError) {
                        reject(new Error(`shield ${i}: ${dispatchError.toString()}`));
                    } else if (status.isInBlock) {
                        for (const { event } of events) {
                            if (event.section === "shieldedPool" && event.method === "TreeSealed") {
                                const d = event.data.toJSON() as any[];
                                sealedEvent = { treeId: d[0], finalRoot: d[1] };
                            }
                        }
                        resolve();
                    }
                })
                .catch(reject);
        });
        console.log(`shield ${i} in block`);
    }

    assert(sealedEvent, "TreeSealed event must fire on the 8th insert");
    assert.strictEqual(sealedEvent!.treeId, 0, "first sealed tree is 0");
    console.log(`TreeSealed: tree 0, final_root ${sealedEvent!.finalRoot}`);

    const activeRoot: string = await rpc(api, "privacy_getMerkleRoot", []);
    const proof0 = await rpc(api, "privacy_getMerkleProof", [0]);
    const proof7 = await rpc(api, "privacy_getMerkleProof", [7]);
    const proof8 = await rpc(api, "privacy_getMerkleProof", [8]);
    const proof9 = await rpc(api, "privacy_getMerkleProof", [9]);

    // Sealed tree: permanent anchor, not the live root.
    for (const p of [proof0, proof7]) {
        assert.strictEqual(p.tree_id, 0);
        assert.strictEqual(p.root, sealedEvent!.finalRoot, "sealed leaves anchor to the final root");
        assert.notStrictEqual(p.root, activeRoot);
        assert.strictEqual(p.path.length, 20);
    }
    // Active tree.
    for (const p of [proof8, proof9]) {
        assert.strictEqual(p.tree_id, 1);
        assert.strictEqual(p.root, activeRoot, "active leaves anchor to the live root");
    }
    // Same-block consistency of the by-commitment variant.
    const byCommit = await rpc(api, "privacy_getMerkleProofByCommitment", [commitment(3)]);
    assert.strictEqual(byCommit.leaf_index, 3);
    assert.strictEqual(byCommit.tree_id, 0);
    assert.strictEqual(byCommit.root, sealedEvent!.finalRoot);

    console.log("FOREST E2E OK: seal fired, sealed leaves anchor to permanent root, active tree serves live root");
    await api.disconnect();
}

main().catch((e) => {
    console.error(e);
    process.exit(1);
});
