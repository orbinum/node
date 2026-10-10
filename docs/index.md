---
# https://vitepress.dev/reference/default-theme-home-page
layout: home

hero:
  name: "Orbinum"
  text: "Private transactions on Substrate"
  tagline: A privacy-focused network combining a Groth16 shielded pool with full EVM compatibility.
  actions:
    - theme: brand
      text: Overview
      link: /overview

features:
- title: Shielded pool
  details: A UTXO-model privacy layer where value lives as Poseidon commitments in a Merkle forest. Shield, transfer, and unshield, each backed by a Groth16 proof verified on-chain.
- title: EVM compatibility
  details: Built on Frontier, so Solidity contracts, MetaMask, and the standard Ethereum RPC surface work unmodified. EVM and Substrate accounts share one balance.
- title: Gasless privacy
  details: Private transfers and withdrawals are unsigned and carry their fee inside the proof, so a relayer can pay gas without learning who is transacting.
- title: Selective disclosure
  details: Encrypted memos let an owner recover their notes by scanning, and value proofs let them prove what a commitment encodes without revealing the blinding factor.
---
