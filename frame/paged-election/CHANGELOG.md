# Changelog — pallet-paged-election

All notable changes to this pallet are documented here.
Format follows [Keep a Changelog](https://keepachangelog.com/en/1.0.0/).

---

## [Unreleased]

---

## [0.1.0] — 2026-11-08

First release. Staking's election computed on-chain: sequential Phragmén over a
paged snapshot, spread across blocks within a weight budget, with no off-chain
miner. Implements `ElectionProvider` for `pallet-staking-async`.

### Added

- **Snapshot** (`engine/snapshot.rs`). Targets and seats in one step, then one
  voter page per step from the most significant page down to 0, as staking
  pages its voters. Votes become 16-bit candidate indices; votes for
  non-candidates, repeated votes, repeated targets and voters without stake or
  valid votes are dropped. Each page records its voters and how many of them
  approve each candidate (`PageInfos`). A page with more voters than
  `VoterSnapshotPerBlock` fails the election (`DataProvider`) instead of being
  cut. Each snapshot step is charged its worst case, whatever staking returns
  (it walks past voters without stake, up to twice a page).
- **Rounds** (`engine/rounds.rs`). Each round elects the lowest score (the first
  target on ties), then passes over the pages applying the winner's score as
  the load of the voters approving it. No per-voter state: a voter's load is
  the score of the last winner it approves. Per candidate only its approval and
  an exact 192-bit sum of contributions persist, so a load change moves a
  contribution instead of recomputing the round. A page none of whose voters
  approve the winner is skipped unread.
- **Exact arithmetic** (`engine/phragmen.rs`, public as `phragmen`). Scores, loads, contributions, edge
  weights and normalisation are upstream's integers step for step:
  `DEN / approval` starts, `⌊load · stake / approval⌋` contributions with
  256-bit intermediates, saturation at `u128::MAX` where upstream saturates
  (reported with `ScoreSaturated`), and upstream's `normalize`; a voter whose
  edges cannot be normalised (upstream would fail) backs nobody, so no voter
  backs more than its stake. Winners, their
  order and each winner's total stake equal `sp_npos_elections::seq_phragmen`
  (without balancing) exactly.
- **Export** (`engine/export.rs`). `elect(page)` rebuilds the page's supports
  from the winners' scores; a stored page that is missing or no longer decodes
  errors (`Failed(Inconsistent)`) instead of exporting as empty. `elect(0)`
  clears every trace of the election, pages beyond `Pages` included. Supports
  respect `MaxWinnersPerPage` and `MaxBackersPerWinner` by construction
  (`integrity_test`).
- **`ElectionProvider`** (`engine/provider.rs`). `start` refuses while an election runs
  or waits to be fetched; `status` is `Err` when idle, `Ok(None)` while
  computing and `Ok(Some(weight of a page fetch))` when done or failed;
  `elect` errors with `NotReady` while computing and changes nothing;
  `duration` is derived from the step prices (`Pallet::duration_bound`);
  `asap` finishes the election regardless of weight.
- **Failures** (`FailReason`): staking's data unavailable, more seats than
  `MaxWinnersPerPage`, broken internal state, or governance. A failed election
  makes every page fetch error, so staking collects no winners and keeps its
  validators; page 0 clears it.
- **Weight discipline.** All work happens in `on_poll`, within
  `RoundBudget` of the block and what the block has left; every step is priced
  with `WeightInfo` before it runs and runs only if it fits. Benchmarks for the
  target snapshot, a voter page snapshot, a selection, an apply pass over a
  page, staking's page fetch (through `ElectionDataProvider::fetch_page`) and
  `abort`. `weights.rs` holds conservative placeholders until the reference
  hardware run.
- **Governance** (`AdminOrigin`): `abort` (call index 0) fails an election
  still computing or done, and clears a failed one, until staking fetches a
  page (`ElectionMeta::fetched`); then it errors with `AlreadyFetching`, since
  aborting would seat the winners of the pages already fetched and clearing
  would leave staking waiting for the rest.
- **Events:** `ElectionStarted`, `SnapshotTaken`, `ElectionDone`,
  `PageExported`, `ElectionFailed`, `ScoreSaturated`, `Cleared`, and
  `EraPlanReset`, which the runtime emits when it resets a staking era plan
  that a failed election left unable to start.
- **Checks.** `integrity_test` checks the parameters, that the heaviest step
  fits the budget and that a page fetch fits a block. `pre_upgrade` refuses an
  upgrade while an election runs or waits to be fetched. `try_state` checks the
  phase against the storage, the snapshot (approvals, page counts, unique
  targets and votes), the winners (bounded, unique, every seat filled when
  done) and that every unelected candidate's sum matches the loads applied.
- **Layout.** Only `lib.rs` at the root. `types/` the snapshot (`snapshot.rs`)
  and the election's progress (`phase.rs`); `engine/` the hooks' work, one
  module per concern: `snapshot`, `rounds`, `export`, `invariants`, the
  arithmetic (`phragmen`), the `ElectionProvider` interface (`provider`), and
  the step loop and cost model in `mod.rs`; `benchmarking/` the benchmarks and
  `weights.rs`; `tests/` the mock runtime and the tests.

### Weights

- Measured on reference hardware (Hetzner CPX62, AMD EPYC-Genoa; 50 steps, 20 repeats, 2026-11-09),
  replacing the provisional weights; the voter snapshot and page export are the
  heaviest steps.
