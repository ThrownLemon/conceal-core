---
description: Run the multi-agent collaborative workflow (spec → design → implement → review → verify → PR) on a conceal-core feature/fix.
argument-hint: <describe the feature/fix/backlog item>
---

Run our multi-agent collaborative workflow on this repo (conceal-core — the C++ CryptoNote daemon/wallet core).

TASK: $ARGUMENTS

This is consensus/crypto/money-critical C++ — a bug can lose funds or fork the chain. Match the existing code style; do **NOT** modernize legacy code unless asked. See `CLAUDE.md` for the consensus surfaces (`CryptoNoteConfig.h`, `CryptoNoteCore`, `Serialization`, `CryptoNoteProtocol`/`P2p`, `Checkpoints`) and the build (`-DBUILD_TESTS=ON` is required to compile/run the gtest suite).

## Co-agents

Run headless. Each writes ONLY its own findings file, read-only everywhere else. **Never edit source in parallel — I (Claude) drive all source edits.**

- **Codex (gpt-5.5):** `codex exec --dangerously-bypass-approvals-and-sandbox -m gpt-5.5 "<prompt>"`
- **Antigravity (Gemini 3.1 Pro):** `agy -p "<prompt>" --model "Gemini 3.1 Pro (High)" --dangerously-skip-permissions --print-timeout 20m`
- **GLM-5.2:** `opencode run --dangerously-skip-permissions -m zai/glm-5.2 "<prompt>"`
- **Opus 4.8 subagent:** Task tool, `model: opus`

**First confirm each CLI is installed here; skip any that aren't and say so.** (As of setup: `codex`, `agy`, `opencode`, `coderabbit` are present. `clang-tidy`/`cppcheck`/`clang-format` are NOT installed — install them or skip those review gates and note it.)

## Phases

1. **SPEC (parallel).** Write a shared `docs/specs/<feature>/BRIEF.md` (the task + real file pointers + constraints: build system, consensus/serialization/RPC/ABI impact, compat). Get 4 independent specs (Codex, Gemini, GLM, Opus subagent) → synthesize the best ideas into `spec-merged.md` with provenance; resolve forks explicitly.

2. **DESIGN / ARCHITECTURE** (adapt — there's no UI). For anything non-trivial, produce a design doc covering: data structures, protocol/serialization format changes, consensus impact (hard-fork? height-gated behind a new `UPGRADE_HEIGHT_*` + block major version?), RPC/API surface, ABI/wire compatibility, threading (the `System` dispatcher), and 2–3 alternatives with tradeoffs. **STOP and wait for my approval of the design before implementing.** Skip only for trivial mechanical changes.

3. **IMPLEMENT.** I drive the edits (TDD via gtest/ctest where the harness allows — build with `-DBUILD_TESTS=ON`); co-agents advise only. Honor existing C++11 legacy style; flag anything touching consensus/serialization/networking as needing extra scrutiny.

4. **REVIEW (parallel).** Codex + Gemini + GLM each review the diff (read-only, write findings files under `docs/reviews/<feature>/`) PLUS CodeRabbit (`coderabbit review --plain -t all`) + clang-tidy/cppcheck/clang-format (if installed). Add an adversarial pass focused on: memory safety / UB, integer overflow, consensus divergence, crypto misuse, and serialization compat. Address CRITICAL/HIGH; document deferrals.

5. **VERIFY.** `cmake` configure (`-DCMAKE_BUILD_TYPE=Release -DBUILD_TESTS=ON`) + build + `ctest --output-on-failure`; run sanitizers (ASan/UBSan) if the build supports them. **Gate = clean build + green tests.**

6. **DOCUMENT.** Update affected docs (README / CMake notes / protocol docs) and fold in learnings — commit on the branch so it ships IN the PR, not after.

7. **PR.** Branch off the appropriate base (`<id-3letter>/<topic>`; PRs target the `development` branch per `CONTRIBUTING.md`); Conventional Commits; PR body with multi-agent provenance + test plan + review response + an explicit **consensus/compat impact statement**.

Keep me in the loop at the **spec-merge** and **design-approval** gates. Put artifacts under `docs/{specs,design,reviews}/<feature>/`.
