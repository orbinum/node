# Security policy

Orbinum Technologies maintains this repository. Thank you for helping keep Orbinum and its users safe.

## Reporting a vulnerability

**Do not open a public issue, pull request or discussion for a security problem.**

Email **security@orbinum.com** with:

- what is affected: the component (runtime pallet, node, RPC, precompile) and the version or commit;
- what an attacker can do, and under which conditions;
- steps or a proof of concept to reproduce it, ideally on a local `--dev` chain;
- any fix or mitigation you suggest.

We will acknowledge the report, keep you informed while we assess and fix it, and agree with you on when to disclose it. We credit reporters in the advisory unless they prefer otherwise.

## Supported versions

| Version | Supported |
|---|---|
| The latest node release (`vX.Y.Z` tag) and the runtime running on testnet | Yes |
| `main` | Yes, fixes land here first |
| Older releases | No: upgrade to the latest |

Mainnet has not launched. Releases are listed on [GitHub](https://github.com/orbinum/node/releases) and the runtime history in [`template/runtime/RUNTIME_VERSIONS.md`](template/runtime/RUNTIME_VERSIONS.md).

## Scope

In scope: the code in this repository, including the runtime and its pallets (shielded pool, zero-knowledge verification, staking, validator admission, text signatures, EVM precompiles), the node and its RPC.

Out of scope:

- vulnerabilities in upstream dependencies (Substrate/polkadot-sdk, Frontier, Hyperbridge): report them upstream, and tell us if Orbinum is affected;
- denial of service against public testnet infrastructure, and spam;
- social engineering and physical attacks.

The Hub app, the indexer and the SDKs live in their own repositories; report their vulnerabilities to the same address.

## Testing guidelines

- Test on a local chain or your own testnet node, not against other users' accounts or funds.
- Do not degrade public testnet services for others.
- Give us reasonable time to fix the issue before disclosing it.

## Advisories

Security fixes are published in the release notes and, for significant issues, as GitHub security advisories on this repository.
