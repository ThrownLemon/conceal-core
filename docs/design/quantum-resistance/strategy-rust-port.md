# Strategy Q1 — Port conceal-core to Rust?

Status: analysis only (no code changes). Author: Claude (Opus) subagent, 2026-06-18.
Scope: whether/how to move conceal-core from C++11 to Rust, in the context of the
ongoing post-quantum work on `pqc/testnet-poc`.

Bottom line up front: **Do NOT rewrite the daemon. Keep the C++11 consensus core and
grow the existing Rust island (`pqc/ccx-pqc`) behind the C-ABI FFI.** A full rewrite is a
multi-year, multi-engineer effort with catastrophic fork risk and near-zero PQ payoff;
the island model already gives us the memory-safety win exactly where new, attacker-facing,
parsing-heavy crypto code lives. This is the same architecture Zcash (librustzcash) and
Monero (FCMP++/Carrot Rust libs over C++) chose, and for the same reasons.

---

## 0. The facts on the ground (measured, not assumed)

| Thing | Measurement |
|---|---|
| Total C++ source | **~92,400 LOC** across `src/` (`.cpp`+`.h`), 19+ libs |
| `crypto/` (CN primitives, PoW, keccak, ed25519 ops) | 13,580 LOC / 19 files |
| `CryptoNoteCore` (blockchain, validation, mempool, difficulty) | 16,953 LOC / 69 files |
| `Serialization` (KV-binary wire/disk format) | 2,169 LOC / 23 files |
| `P2p` + `CryptoNoteProtocol` | 6,489 LOC / 34 files |
| Existing Rust island `pqc/ccx-pqc` | **1,022 LOC** (`lib.rs` 712 + `ringsig.rs` 310) |
| FFI entry points (`pub extern "C"`) already live | **33** |

So the Rust footprint we already maintain is ~1k LOC behind 33 C-ABI functions, against a
92k-LOC C++ daemon. That ratio is the whole argument in one line: the new, dangerous,
quantum-relevant code is tiny and isolated; the legacy mass is large, battle-tested, and
consensus-load-bearing.

---

## (a) The Rust-island-via-C-ABI model vs. a full daemon rewrite

### What the island already buys us

We are *already running* the island pattern. `pqc/ccx-pqc` is a `crate-type = ["staticlib"]`
linked into `conceald`, exposing 33 `#[no_mangle] extern "C"` functions: ML-KEM-768
keygen/encap/decap and KEM-stealth (`ccx_pq_kem_*`), ML-DSA-65 deposits/multisig
(`ccx_pq_multisig_*`), ChaCha20-Poly1305 AEAD message seal/open (`ccx_pq_msg_*`), and the
experimental lattice ring signature (`ccx_pqr_*`). Every entry point is wrapped in
`catch_unwind` (with `panic = "unwind"` pinned in `Cargo.toml`) so a Rust panic becomes a
C error code instead of UB across the FFI boundary. This is a textbook, correctly-built
FFI island.

This is precisely the model used in production by the projects the user named:

- **librustzcash** — Zcash's `zcashd` (C++) called into Rust (`librustzcash`) for all the
  new, security-critical Sapling/Orchard cryptography (Halo2 proving/verifying, note
  encryption, commitment trees) over an FFI boundary, for *years*, while the C++ node kept
  driving consensus. The Rust island carried the hard crypto; the C++ shell carried the
  chain. (`zcash.readthedocs.io/.../librustzcash_arch.html`.)
- **Monero FCMP++/Carrot** — the new full-chain-membership-proof crypto and the Carrot
  addressing protocol are **Rust libraries** integrated into the **C++** Monero daemon via
  FFI; 2025 dev updates explicitly describe "cleaning up the FFI (removing asserts/unwraps,
  returning errors correctly)" — i.e. the same boundary-hardening we did with `catch_unwind`.
  Monero did *not* rewrite `monerod`; it bolted a Rust crypto island onto it.
  (CCS jeffro256/j-berman 2025 proposals; Monero Observer Jul 2025.)

So our instinct is already aligned with the two most relevant precedents on the planet:
privacy-coin C++ daemons adopt Rust *as a crypto island*, not as a rewrite.

### What the island does NOT buy us

- **No memory safety for the 92k LOC of C++** that does block validation, mempool, P2P
  parsing, RPC, serialization. The CVE-relevant attack surface (untrusted P2P/RPC bytes
  hitting C++ parsers) stays in C++.
- **No help for the consensus byte-format**, which must remain bit-exact (see (e)).
- **FFI has its own footguns**: pointer/length contracts, ownership, the panic boundary.
  We have already hit and fixed several (struct-of-pointers vs flat-stride ABI mismatch on
  the ring-sig keys; the `catch_unwind` requirement). Every new island function adds a
  hand-audited `unsafe` boundary. The island is safer *inside*, but the seam is not free.

### A full daemon rewrite — what it would actually mean

"Port conceal-core to Rust" in the maximal sense = reimplement `CryptoNoteCore` +
`Serialization` + `P2p`/`CryptoNoteProtocol` + `Rpc` + `Wallet` in Rust such that it
produces and accepts **byte-identical** blocks, transactions, P2P messages and disk format.
That is not a translation; it is a **consensus-compatible re-implementation** — the hardest
class of blockchain engineering there is, because every off-by-one in the homemade
KV-binary serializer, every quirk of CryptoNight, every difficulty-LWMA edge case, every
hard-fork height gate in `CryptoNoteConfig.h` must be reproduced exactly or the Rust node
forks off the network. (See (c) for the cost.)

---

## (b) Memory-safety value-for-money on money/consensus code

The case for Rust on *new* crypto code is genuinely strong, and we should keep banking it.
The case for *retroactively* rewriting the existing C++ for safety is weak on ROI. Both are
true at once.

### Why the CryptoNote/Bytecoin lineage is a real memory-safety liability

conceal-core is a fork of the CryptoNote/Bytecoin codebase. That lineage has a documented
history of memory-safety and parsing bugs in exactly the surfaces a rewrite would target:

- **CVE-2017-12564 (Monero/CryptoNote lineage)** — heap corruption / DoS via crafted P2P
  data in the `cryptonote` deserialization path. Untrusted bytes → C++ parser → memory bug.
  This is the canonical CryptoNote-family memory-safety CVE and it lives in the
  serialization/protocol layer we still run.
- **The "burning bug" / amount-aliasing and key-image classes** — logic, not memory, but
  they show that the *validation* surface is where money is lost, and that surface is dense
  C++.
- Our own PQ review found **C/C++-class hazards** even in the new path: a pre-existing
  **null-deref in `gettransactions` on a malformed hash**, an **output-sum overflow bypass**
  in the v3 money-conservation check, and a heap/uninit crash when serializing a reloaded PQ
  block (masked under gdb, needs ASAN). These are precisely the bug classes Rust's type
  system (no null, checked arithmetic in debug / explicit `checked_*`, ownership) tends to
  eliminate by construction.

So: the C++ surface *does* leak memory-safety and integer-overflow bugs, and on
money-critical paths. The value of memory safety here is real, not theoretical.

### But: value-for-money is about *where* you spend the rewrite

- **Highest ROI:** new code that parses untrusted bytes and does crypto — i.e. exactly the
  PQ island. Already in Rust. Done.
- **Medium ROI:** the serialization parsers and P2P message decoders (untrusted-input
  parsing) — these *could* move to Rust behind FFI and would meaningfully shrink the
  memory-unsafe attack surface. But they are also the **consensus byte-format**, so a port
  must be byte-exact and is risk-heavy (see (e)).
- **Low ROI:** difficulty math, block-template assembly, RPC business logic, wallet
  bookkeeping. Rewriting these in Rust buys little safety (they're not the classic
  memory-corruption surface) and re-introduces consensus risk for no PQ benefit.
- **Negative ROI:** CryptoNight PoW and the ed25519/`crypto-ops` primitives. These are
  performance-tuned, well-exercised, and a rewrite invites subtle divergence with zero
  upside (the hash layer is already Grover-adequate; nothing here is quantum-relevant).

Memory safety is worth paying for **at the boundary where untrusted bytes first meet
parsing logic** and **in new crypto**. It is *not* worth a from-scratch reimplementation of
16k LOC of consensus validation whose bugs are mostly logic bugs a rewrite would have to
re-derive (and could get newly wrong).

---

## (c) Realistic cost of a full rewrite

The empirical precedents are unambiguous and they are large.

- **Zebra (Zcash, Rust)** — a *consensus-compatible* Zcash node written from scratch in
  Rust by the **Zcash Foundation**. It took **~3+ years** of work by a **funded, dedicated
  team** to reach production-readiness, and the goal was explicitly "reimplement the
  consensus rules in a modular Rust architecture," with multiple external audits along the
  way and a long testnet/mainnet shadowing period before it could be trusted. Even with a
  foundation behind it, this was a multi-year program, not a port.
- **Grin / Beam (Mimblewimble)** — these are sometimes cited as "Rust privacy coins," but
  they were **greenfield** (Grin in Rust, Beam in C++) — designed from day one with a clean
  protocol. They had **no legacy byte-format to stay compatible with**, which is the single
  biggest cost driver we *do* have. They are evidence that *new* chains can be built in Rust
  efficiently, not that *existing* chains can be ported cheaply.
- **Monero** chose **not** to rewrite `monerod`; after years and a large contributor base it
  still adds Rust as crypto libraries over the C++ core. If the Monero project, with its
  resources, won't rewrite its daemon, a fork the size of conceal-core should not either.

### Concrete estimate for conceal-core

A faithful, byte-compatible Rust reimplementation of the consensus-bearing subset
(`crypto` + `CryptoNoteCore` + `Serialization` + `P2p`/`CryptoNoteProtocol`, ~37k LOC)
plus parity testing against the existing chain:

- **Effort:** order of **15–40 engineer-months** for an experienced Rust+blockchain team
  *just to reach byte-parity and pass a long shadow-sync against mainnet*; more to also
  port `Rpc` + `Wallet`/`WalletLegacy` (~14k LOC) for feature parity. Realistically a
  **2–4 year calendar program** at the staffing levels this project actually has (a small
  volunteer/contributor team), if it ever finishes.
- **Risk:** **chain-fork risk is the dominant cost, not LOC.** Any divergence in the
  homemade KV-binary serializer, CryptoNight, LWMA difficulty, or a hard-fork height gate
  makes the Rust node reject/produce blocks the C++ network doesn't agree with — a
  consensus split. This must be caught by exhaustive differential testing (replay the entire
  historical chain through both implementations and assert identical accept/reject + hashes)
  before the Rust node touches mainnet. That test harness is itself a major deliverable.
- **Opportunity cost:** every month on a rewrite is a month not spent on the *actual* PQ
  blocker — a production-grade, audited, constant-time PQ linkable ring signature (the one
  thing no rewrite gives you, because it doesn't exist in any language yet).

The rewrite's cost is enormous and its PQ payoff is **zero**: Rust does not solve the
quantum problem. The quantum problem is a *cryptography* problem (no mature small-proof
audited PQ ring sig / PQ zk-proof), and that is language-independent.

---

## (d) Incremental roadmap — what to move to Rust, in order

Principle: **move into Rust only code that is (1) new, or (2) a pure, byte-defined function
that can be differentially tested to bit-exactness against the C++, and never move the code
that *defines* consensus byte-format unless you can prove byte-parity.** Each step is behind
the existing C-ABI and leaves the C++ daemon driving consensus.

**Phase 0 — Harden the island we have (now).**
- This is the realistic "Rust port": keep going on `ccx-pqc`. It already holds all the
  PQ-relevant, attacker-facing crypto.
- Finish the boundary hygiene: confirm every `extern "C"` validates pointer/length, returns
  error codes (not panics), and has a fuzz/property test. Treat the FFI seam as a security
  boundary, document the ownership contract per function.
- Make the ring sig production-grade *in Rust* (constant-time, calibrated params, NTT,
  audit) — this is CIP-0001 C1 and is the single highest-value Rust work available.

**Phase 1 — PQ crypto consolidation (next, low risk).**
- Move any remaining hand-rolled PQ glue (e.g. deterministic ML-KEM `KeyGen(d,z)` for the
  wallet, currently blocked on an RNG-based `keypair()`) into the island. New code, no
  legacy byte-format constraint, pure win.
- Add deterministic test vectors (FIPS 203/204/205 KATs) inside the crate so the island is
  self-verifying.

**Phase 2 — Optional: untrusted-input parsers behind FFI (medium risk, real safety ROI).**
- Candidate: a Rust **decoder** for the PQ-extended transaction/`tx-extra` fields and the
  new `PqKeyInput`/`PqKeyOutput` variants — the *parsing* of untrusted bytes for the new
  types, where a malformed P2P/RPC payload could currently hit a C++ bug (we already found
  one uninit/heap issue on the reloaded-PQ-block serialize path).
- **Hard rule:** the Rust decoder must produce byte-identical output to the C++ KV-binary
  serializer for the same struct, verified by a round-trip differential test on a large
  corpus, *before* it is allowed on the validation path. If it can't be proven byte-exact,
  it does not ship — it stays a defense-in-depth pre-validator, not the source of truth.

**Phase 3 — Optional, much later: networking I/O (high effort, low PQ relevance).**
- P2P transport *could* move to a Rust async stack, but conceal-core's networking is written
  against the custom `src/System` dispatcher (green-thread runtime), not asio. Replacing that
  is a large, invasive change with no PQ payoff. **Defer indefinitely** unless a separate
  networking-rewrite project is funded.

**Never in scope for the PQ effort:** `crypto/` PoW + ed25519 ops (Grover-adequate, no
quantum relevance, high divergence risk), difficulty math, RPC business logic, wallet
bookkeeping. Leave them in C++.

This roadmap is strictly additive: at every phase the C++ daemon remains the consensus
authority and the network stays compatible. There is no flag day, no fork.

---

## (e) Where C++ must stay — the consensus byte-format

Some code cannot move without becoming a consensus change, and these are exactly the parts a
naive "rewrite in Rust" would touch first:

1. **`src/Serialization` (KV-binary + the `ISerializer` overloads).** This *is* the wire and
   on-disk format. The byte layout of blocks, transactions, P2P messages, and the
   blockchain/wallet DB is *defined by this code's behavior*, quirks included. Rust may
   *mirror* it (Phase 2, byte-exact, differentially tested) but the C++ remains the canonical
   definition; you cannot "improve" it without a hard fork.
2. **`CryptoNoteConfig.h` + the validation in `CryptoNoteCore`.** Hard-fork heights
   (`UPGRADE_HEIGHT_V3..V9`), block major versions, `MONEY_SUPPLY`, `DIFFICULTY_TARGET`,
   LWMA difficulty, money-conservation checks. These define *what blocks the network accepts*.
   They stay in C++ (the running network's reference) until and unless a fully differential-
   tested Rust validator is proven identical over the entire historical chain — a Zebra-scale
   undertaking, out of scope for PQ.
3. **`crypto/` CryptoNight PoW + `crypto-ops` (ed25519 group ops, key images, ring math).**
   The PoW hash and the legacy signature/key-image math are consensus-defining and
   performance-tuned. The hash layer is already Grover-adequate; there is zero quantum reason
   to touch it and every reason (divergence risk) not to.
4. **`CryptoNoteProtocol`/`P2p` handshake + message framing.** Changing these breaks wire
   compatibility with the existing network. Mirror, don't move.

Rule of thumb: **if changing the code's output by one byte would fork the chain, the C++ is
the source of truth.** Rust may stand beside it as a byte-exact mirror or a defense-in-depth
validator, but the C++ keeps defining consensus until a funded, audited, differentially-
tested reimplementation exists — which is a separate strategic project, not a PQ task.

---

## Recommendation

1. **Reject the full rewrite.** Multi-year, fork-risk-dominated, and it delivers *no* quantum
   resistance (the PQ blocker is cryptographic, not linguistic). Zebra (~3 yr, funded
   foundation) and Monero's refusal to rewrite `monerod` are the proof.
2. **Double down on the Rust island we already run.** It is the correct, precedented
   architecture (librustzcash, Monero FCMP++/Carrot). Keep all *new* PQ crypto in
   `ccx-pqc`, harden the FFI seam, and spend the engineering budget on the one thing that
   actually matters: a constant-time, calibrated-parameter, **audited** PQ ring signature.
3. **Allow Rust to grow only by the byte-exact rule.** New PQ code → Rust freely. Existing
   consensus byte-format code → stays C++ as the source of truth; Rust may mirror it only
   under exhaustive differential testing, and only as defense-in-depth, never as a silent
   replacement.
4. **Keep C++ as the consensus authority** for serialization, validation, PoW, and P2P
   framing indefinitely, absent a separately-funded Zebra-style reimplementation program.

The honest framing for the partner: "porting to Rust" is two different questions wearing one
name. *Growing the Rust crypto island* is already happening, is correct, and is cheap. *A full
daemon rewrite* is a 2–4-year, fork-risk-heavy program that does not solve the quantum problem
and that even Monero won't undertake. Do the first; don't do the second.

---

### Sources / precedents

- Zebra (Zcash Foundation, Rust consensus-compatible node, ~3+ yr funded build):
  https://github.com/ZcashFoundation/zebra , https://zfnd.org/zebra/
- librustzcash architecture (Rust crypto island behind C++ `zcashd` via FFI):
  https://zcash.readthedocs.io/en/master/rtd_pages/librustzcash_arch.html
- Monero FCMP++/Carrot Rust libraries over C++ daemon, FFI cleanup (2025):
  https://ccs.getmonero.org/proposals/jeffro256-full-time-2025Q4.html ,
  https://monero.observer/jeffro256-posts-july-2025-monero-carrot-dev-update/
- Grin (Rust) / Beam (C++) — greenfield Mimblewimble, no legacy byte-format (contrast case).
- CVE-2017-12564 — CryptoNote/Monero lineage P2P deserialization heap corruption (memory-
  safety precedent in the surface a rewrite would target).
- Internal: `pqc/POC-RESULTS.md`, `docs/reviews/pq-security-review.md`,
  `docs/design/quantum-resistance/REMAINING-WORK.md`; measured LOC from `src/`.
