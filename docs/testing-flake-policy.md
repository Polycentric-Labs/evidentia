# Testing flake policy

A flaky test — one that passes or fails on identical code depending on timing,
ordering, or environment — is worse than no test: it trains maintainers to
ignore red, and a chronically-red gate masks real regressions. This policy
codifies the rules that keep Evidentia's suite deterministic, so a red result
always means a real problem.

## The rule: tests must not depend on wall-clock timing

Three flake classes have appeared and been eliminated; all were timing-dependent
assertions in CI, where shared runners + JIT/import warmup + load make
wall-clock behaviour non-deterministic.

1. **No wall-clock *deadlines*.** Hypothesis property tests run under
   `deadline=None` in the CI profiles (`tests/property/conftest.py`,
   `tests/fuzz/conftest.py`). A per-example timing deadline flakes: a test that
   normally runs in <50 ms occasionally crosses 200 ms under load and Hypothesis
   reports `FlakyFailure`. A true hang or quadratic blow-up is still caught by
   the pytest + CI job timeouts; genuine performance regressions belong in
   *explicit* benchmarks, never a timing-sensitive test assertion.

2. **Anchor timestamps; never compare two `utc_now()` calls for strict
   ordering.** When a test needs "this value was refreshed", anchor the baseline
   clearly in the past (e.g. `utc_now() - timedelta(days=10)`) rather than
   comparing the construction time to the refresh time. On a coarse-resolution
   clock (Windows resolves to ~16 ms) two `utc_now()` calls in the same tick
   return an identical value, so a strict `>` flakes. The vendor / challenge /
   POA&M store tests all anchor their baseline in the past.

3. **No product wall-clock budget inside a capacity test.** The SCAP import
   carries a 60 s processing budget (`WALL_SECONDS`). The capacity tests import
   exact-limit documents (10,000 outcomes, 5 MiB native, 2 MiB assessment),
   which take about 17 s uninstrumented and 2.5x longer under coverage, so the
   budget expired on a loaded Linux coverage runner (the v0.13.0 review PR,
   CI round 4). A capacity test proves a size property: it injects a budget
   that cannot expire (`monkeypatch.setattr(_limits, "WALL_SECONDS", 3600.0)`)
   and asserts no elapsed time. The budget keeps its own deterministic tests,
   which patch `start_budget` to an already-expired deadline (`test_scap_io.py`,
   `test_collectors_scap_stream.py`); import speed belongs in a benchmark.


## General determinism rules

- **Freeze or inject the clock** for time-dependent logic rather than reading the
  real clock in an assertion.
- **No order dependence** between tests; each test sets up and tears down its own
  fixtures (the suite uses `tmp_path` + isolated stores).
- **No network in unit/property tests**; the SSRF-guard tests use a mock driver,
  and the live-SQL / collector tests are isolated and opt-in.
- **Derandomize Hypothesis in CI** (`derandomize=True`) so a failing example is
  reproducible across machines.
- **A skipped gate is a failure, not a pass.** A check that cannot run (a build
  that never reaches its assertions, a harness that crashes at startup) must fail
  loudly — it must never report green-by-omission. The container smoke test was
  silently dead for several releases and masked a real base-image regression;
  the lesson is that every gate self-tests.

## If you hit a flake

1. Reproduce it — re-run the exact seed / example (Hypothesis prints it).
2. Find the non-determinism (timing, ordering, environment) — do **not** just
   add a retry or bump a timeout to paper over it.
3. Make the test deterministic (anchor the clock, isolate the fixture, mock the
   boundary), then add a one-line comment explaining the flake class so it does
   not regress.
4. If the flake reveals a real product bug (a genuine race, a real hang),
   fix the product, not the test.
