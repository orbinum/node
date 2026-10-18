# Changelog

All notable changes to `pallet-evm-precompile-balances` will be documented in this file.

## [Unreleased]

## [0.2.0] - 2026-10-16

**Breaking** — gas is charged by dispatch weight and every failure reverts with
a reason. Requires the next runtime `spec_version`.

### Security

- Static calls, delegated calls (DELEGATECALL, CALLCODE) and calls carrying
  value are refused. A transfer debits `context.caller`, which under
  DELEGATECALL is the delegating contract's caller: any contract a user called
  could move that user's ORB through `0x…0802`. Value sent to the precompile
  was stranded in its account.

### Changed

- **Gas follows the dispatch weight.** A call is charged the weight of
  `transfer_allow_death` or `transfer_keep_alive`, its proof size and the
  storage a new account takes, before the transfer runs, so a failing transfer
  costs the same as a successful one. The flat 5,000 gas, which metered neither
  proof size nor storage, is gone. On Orbinum the proof size dominates: a
  direct transfer transaction uses about 60,000 gas.
- **Failures revert with a reason.** Every failure reverts with
  `Error(string)` and returns the unused gas, instead of an exceptional halt
  that consumed all of it. A failed transfer reverts with
  `transfer failed: <DispatchError>`.
- **Calldata length is exact.** Input must be the selector plus one `bytes32`
  and one `uint256` (68 bytes); shorter or longer input reverts.
- The precompile is split into `abi` (decoding), `guard` (caller rules) and
  `dispatch` (charging and the transfer).

## [0.1.0] - 2026-05-29

### Added

- Native `pallet_balances` transfers to any `AccountId32` from EVM contracts and
  wallets, at `0x…0802`: `transfer(bytes32,uint256)` (`0x6a467394`) and
  `transferKeepAlive(bytes32,uint256)` (`0xac6ac4c4`). The `bytes32` is the
  recipient's raw `AccountId32`; a `uint256` above `u128::MAX` is rejected.
- A flat 5,000 gas per call.
