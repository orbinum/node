# Security policy

## Supported versions

Only the latest commit on `main` is supported. Support will be extended back to
tagged releases once the release pipeline is stable.

## Reporting a vulnerability

Report suspected vulnerabilities privately by email to **security@orbinum.net**.

Please do not open a public issue, pull request, or discussion thread for a
security report. Orbinum holds user funds in a shielded pool, so a public report
is a disclosure.

Useful things to include, as far as you have them:

- the affected component and the commit you tested against
- what an attacker gains, and what they need in order to get it
- reproduction steps, or a proof-of-concept if you have one
- whether you have shared the report with anyone else

We will acknowledge receipt and let you know whether we are treating the report
as a vulnerability. If you would like a coordinated disclosure date, say so and
we will agree one with you.

There is currently no bug bounty program. Reports are welcome regardless.

## Scope

This policy covers the Orbinum node and runtime in this repository, the
zero-knowledge circuits in [orbinum/circuits](https://github.com/orbinum/circuits),
and the client SDKs published under the [orbinum](https://github.com/orbinum)
organization.

Orbinum builds on [Frontier](https://github.com/polkadot-evm/frontier). A
vulnerability in unmodified upstream Frontier or Polkadot SDK code should be
reported to those projects. If you are unsure which applies, send it to us and
we will route it.
