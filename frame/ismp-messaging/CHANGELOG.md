# Changelog — pallet-ismp-messaging

All notable changes to this pallet are documented here.
Format follows [Keep a Changelog](https://keepachangelog.com/en/1.0.0/).

---

## [Unreleased]

---

## [0.2.0] — 2026-11-08

Ships with runtime spec 21.

### Changed

- **`Config::AdminOrigin`** (breaking): `accept_source`, `remove_source`,
  `set_message_fee` and `set_outbound_paused` check it instead of root in code, so
  the chain's cross-chain trust can move to a multisig or council by changing a
  type. The Orbinum runtime sets it to `CrossChainAdmin` (root for now). Root's
  free dispatch is unchanged. Benchmarks take the admin's successful origin.

---

## [0.1.0] — 2026-09-15

First release: Orbinum's ISMP application. Signed and root dispatch of POST and GET
requests with an anti-spam fee paid to the treasury (`MessageFee`,
`MessageByteFee`, capped by `MaxMessageFee`), accepted sources for inbound
messages, an outbound pause, timeouts bounded for signed dispatch, and delivery
receipts.
