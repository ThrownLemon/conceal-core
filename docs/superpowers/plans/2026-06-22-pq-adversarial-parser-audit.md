# PQ Adversarial Parser Audit Checklist

**Goal:** Continue the quantum-resistance audit by trying to uncover new concrete bugs in C++ parser, transaction serialization, and adversarial PQ wire inputs rather than re-reporting evidence gaps already under remediation.

**Scope:** Current worktree at `/Users/travis/Projects/conceal-core-mdbx-merge`. Avoid modifying Claude/model remediation files unless a failing test requires it. Prefer isolated unit tests and documented findings.

## Tasks

- [x] Map parser/serialization entrypoints and existing test wiring.
- [x] Add isolated adversarial tests for malformed PQ tx-extra and transaction serialization inputs.
- [x] Run targeted WSL tests against the current checkout.
- [x] Investigate any failing cases to source-level root cause.
- [x] Record confirmed new findings or clean results in the audit report.

## Result

Added `tests/UnitTests/TestPqAdversarialParser.cpp` and documented `M-new-6`, `M-new-7`, and
`M-new-8` in `docs/reviews/quantum-resistance-research/10-adversarial-parser-audit.md`: residual PQ
multisig blob materialization, oversized PQ ring-index array materialization, and malformed PQ multisig
output-key validation. WSL targeted runs passed `PqAdversarialParser.*` 11/11 and the adjacent
parser/address/deposit/golden slice 70/70.

## Initial Focus

- `parseTransactionExtra` for malformed 0x06/0x07 length and trailing-field cases.
- `fromBinaryArray(TransactionInput/TransactionOutputTarget/Transaction)` for unknown tags, oversized PQ arrays, and malformed PQ blobs.
- Address parsing and PQ scheme/version boundary checks where not already covered.
