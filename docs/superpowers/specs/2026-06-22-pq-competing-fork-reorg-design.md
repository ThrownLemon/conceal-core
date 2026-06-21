# PQ Competing-Fork Reorg Test Design

## Purpose

Add a chain-level test that exercises the production alternative-chain switch
path with branch-conflicting post-quantum transactions. The test must prove that
PQ database state, nullifier handling, output indexing, disconnected
transactions, and MDBX persistence remain correct when a heavier fork replaces
the active chain.

This complements `TestPqChainState.cpp`, which already covers direct
connect/disconnect/reconnect and restart behavior. The new test targets
`switch_to_alternative_blockchain()` and the state transitions around a real
competing fork.

## Scope

The implementation will:

- use two real `cn::core` instances with separate temporary MDBX databases;
- build and replay an identical common prefix through the configured checkpoint
  range;
- create divergent, internally valid branches using normal block-template,
  transaction-validation, and block-submission APIs;
- force core A to switch to core B's branch only when B has greater cumulative
  difficulty;
- inspect state through public blockchain/PQ query APIs;
- restart core A from its MDBX database and repeat the final state checks.

The implementation will not add production hooks, modify consensus behavior,
or attempt to manufacture a failure after the active chain has already been
popped. Failed-switch rollback is a separate test because it requires a
different adversarial construction.

## Architecture

The test will extend `tests/UnitTests/TestPqChainState.cpp` so it can reuse the
existing currency configuration, temporary-directory management, PQ
transaction builders, and query helpers without duplicating consensus-sensitive
test setup.

Two cores avoid manually reproducing block-template accounting:

- **Core A** constructs the initial active branch.
- **Core B** receives the same common-prefix blocks, then constructs the
  competing branch from the shared tip.
- Core B's branch transactions and blocks are submitted to core A using normal
  incoming transaction and block APIs.

Transactions needed by alternative blocks will be submitted to core A with
`keptByBlock=true`. This models block-sourced transactions and permits the
alternative-chain verifier to obtain complete transaction coverage without
weakening normal mempool policy.

## Fork Topology

Both cores share the same chain through height 12. Exact checkpoint hashes may
be used only for these deterministic empty setup blocks, matching the existing
chain-state fixture. All PQ-bearing blocks use real cryptographic verification.

Core A then builds:

1. a deposit that spends PQ funding output zero;
2. empty blocks until the deposit reaches its configured term;
3. a withdrawal that consumes that deposit.

At A's branch tip, the deposit cell is used, the withdrawal payout exists, and
the funding nullifier is spent.

Core B builds from the common height-12 tip:

1. a different valid deposit that spends the same funding output and therefore
   has the same funding nullifier, but uses distinct deposit payload data;
2. empty descendants until the branch cumulative difficulty exceeds core A's
   recorded active-branch cumulative difficulty.

Core B's deposit remains unspent. Its branch is submitted to core A in order.
The test first proves that the shorter/equal branch remains alternative, then
proves that the final descendant triggers a switch.

## Required Assertions

Before the switch:

- core A's active tip is unchanged while B is not heavier;
- A's deposit is present and marked used;
- A's withdrawal payout is present;
- B's deposit is absent from active-chain PQ projections.

After the switch:

- core A's active tip equals core B's heavier tip;
- A's deposit and withdrawal payout are absent from active-chain projections;
- B's deposit exists and is marked unused;
- PQ coinbase/output indices contain the entries expected from B's branch and no
  stale entries unique to A's disconnected branch;
- a third validly formed transaction spending the shared funding output is
  rejected because B now owns the nullifier;
- disconnected A transactions are not accepted as relayable transactions on
  the new active chain. If the implementation retains block-kept conflicts
  internally, the test must distinguish that storage detail from relayability
  and report any unsafe behavior as an audit finding.

After restarting core A against the same MDBX directory:

- the active tip remains B's tip;
- B's deposit and its unused state are reproduced;
- A's deposit and payout remain absent;
- PQ output-index projections match the pre-restart result;
- the shared nullifier still prevents a third spend.

## Error Handling and Diagnostics

Test helpers will fail with the transaction or block validation context and the
expected height/hash when setup or submission fails. State assertions will
include branch-specific labels so a failure identifies whether stale A state,
missing B state, nullifier drift, output-index drift, or restart persistence is
responsible.

Any discovered production defect will be recorded separately from fixture or
test-environment failures. The test must not encode a known-bad outcome merely
to pass.

## Verification

Run the focused competing-fork test first, then the existing PQ chain-state and
adversarial suites. The final verification set must include:

- the new competing-fork test;
- `PqChainState.*`;
- `PqAdversarialParser.*`;
- PQ deposit serialization, primitive, transaction, output-validation, and
  spend-gate tests already used by the post-remediation audit.

The test must pass on the authorized WSL environment with the repository's
normal build and GTest runner. `git diff --check` must also pass.

## Acceptance Criteria

The work is complete when a production-path heavier-fork switch with
branch-conflicting PQ spends is reproducibly tested, all post-switch and
post-restart invariants pass, and any unsafe mempool or state behavior found by
the test is reported with exact code and test evidence.
