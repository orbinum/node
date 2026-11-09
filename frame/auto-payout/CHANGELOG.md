# Changelog — pallet-auto-payout

All notable changes to this pallet are documented here.
Format follows [Keep a Changelog](https://keepachangelog.com/en/1.0.0/).

---

## [Unreleased]

---

## [0.1.0] — 2026-11-08

First release. Pays staking rewards automatically each era, so no staker has to
claim them. Ships with runtime spec 21.

### Security

- **Each page is charged its estimate**, not the weight staking reports: staking's
  refund counts only the nominators it paid, so a page of nominators with payee
  `None` reported almost nothing and a block paid many more pages than its budget.
  A call the runtime's filter stopped is charged what it reports (no work).
- **An era still being paid past its window is behind**, whatever its progress:
  progress is priced with the weights of the block that paid each page, so a
  weight rise mid-era could otherwise leave its last pages for the next era.
- **`pause` is refused within `ExpiryMargin`** of the oldest unpaid era leaving
  staking's history (`ExpiryNear`), so the watchdog's resume cannot be undone by
  pausing again.
- **`try_state`** checks the limits' caps and order only (a floor stored before a
  weight rise is tolerated by the hooks), and also that the era being paid is
  closed and never stored done, that its validators all have pages, and that no
  more eras are queued than staking keeps.

### Added

- **Era queue.** When staking's active era moves on, the eras that closed are
  queued (`Queue`, oldest first). Eras that leave staking's history unpaid
  expire (`EraExpired`). The history counts from staking's planned era
  (`EraPayouts::planned_era`, its `CurrentEra`), as staking does: once the next
  era is planned the oldest queued era is dropped before it starts, without a
  refused call.
- **Payment by page.** Each page is paid through the runtime's
  `EraPayouts::pay`, the same `payout_stakers_by_page` a manual claim makes, to
  each staker's own reward destination. Pages someone claimed first are skipped
  silently.
- **Refusals by reach** (`PayoutOutcome`). A page staking refuses is skipped
  with `PayoutSkipped`; a refusal that holds for the rest of a validator's pages
  (`ValidatorUnpayable`) skips them all under that one event; one that holds for
  the era (`EraUnpayable`) drops it with `EraExpired`. None spends a block's
  budget on calls staking will refuse.
- **Filtered calls wait** (`PayoutOutcome::Blocked`). When the runtime filters
  the call (a call filter or safe mode), nothing more is paid that block and the
  page stays next, neither skipped nor dropped; payment resumes once the call is
  allowed again.
- **Pacing.** An era's pages are priced with staking's weights and spread over
  `PaymentWindow` blocks:
  - `on_idle` pays from the weight transactions left, up to `idle` of the block;
  - `on_initialize` pays only when the era is behind schedule (`floor`) or more
    than one era waits (`catch_up`);
  - neither pays on the runtime's heavy blocks (`EraPayouts::is_heavy_block`).

  Starting an era is charged its reads and 1 µs of CPU per validator
  (`MaxValidators`) to price its pages: a validator's pages cost at most three
  `page_weight` calls (`ValidatorPages::work`), however many there are, and so
  does skipping its remaining pages. The 1 µs is an estimate until a benchmark
  of starting the largest era replaces it.
- **Governance** (`AdminOrigin`): `set_limits` (call index 0), within hard caps
  in code (`floor` ≤ 10 %, `catch_up` ≤ 10 %, `idle` ≤ 25 %, exported as
  `MAX_FLOOR`, `MAX_CATCH_UP`, `MAX_IDLE`), with `floor` checked to fit the
  largest step. A share stored before a weight change that no longer fits a step
  is raised to the largest step, so a behind era always moves. `pause` and
  `resume` (call indices 1 and 2): while paused, eras keep queueing and manual
  claims keep working.
- **Expiry watchdog** (`Config::ExpiryMargin`, the runtime sets 14 eras). At
  each era change, an unpaid era within the margin of leaving staking's history
  is reported with `ExpiryAtRisk { era, eras_left }`, whatever holds it, and a
  pause is lifted with `ResumedToAvoidExpiry { era }`: a forgotten `pause` cannot
  cost rewards. Only a call filter, a deliberate chain-wide control, can hold an
  era to expiry, and it is warned each era before. `eras_left` counts from the
  planned era.
- **Checks.** `integrity_test` checks the defaults, the window, the queue bound
  and the expiry margin. `try_state` checks the queue order, the cursor and the
  limits, and that every stored value decodes: one that no longer does (e.g.
  after `MaxQueuedEras` or `MaxValidators` is lowered) reads as an empty queue
  or no era being paid, which would drop eras silently.
- **Layout.** Only `lib.rs` at the root. `types/` holds the interface to
  staking (`staking.rs`), the era being paid (`era.rs`) and the limits
  (`limits.rs`); `engine/` the hooks' work, one module per concern: `queue`,
  `expiry`, `hooks` (each block's budget), `payment`, `invariants`, and the pure
  budget rules (`pacing`, public as `pacing`); `benchmarking/` the benchmarks and
  `weights.rs`; `tests/` the mock runtime and the tests.
- **Runtime adapter** (`template/runtime/src/staking/eras/payouts.rs`): pays
  through the runtime's call filter, as a manual claim would. `CallFiltered` is
  `Blocked`; `InvalidEraToReward` is era-level when the era is out of staking's
  history or has no reward, and validator-level otherwise (staking returns it
  too for a validator without an exposure); `NotStash`, `NotController` and
  `InvalidPage` are validator-level; `AlreadyClaimed` is `AlreadyPaid`; anything
  else is page-level.
