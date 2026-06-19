# Gao et al. RingCT vs MatRiCT-Au — measured benchmark (WSL host 100.100.90.103)

Read-only research + benchmark. NO conceal-core / matrict-lib / pqc-bench changes.
Host: AMD Ryzen 9 5950X 16-core, Ubuntu 24.04 x86_64. RDTSC/effective clock = 3.494 GHz
(calibrated against CLOCK_MONOTONIC; validated vs selftest wall-clock).
Mac-side mirror of ~/gao-bench-notes.md on the WSL host.

================================================================================
PART A — THE PAPER (Gao, Zhao, Gu et al., FC/PKC 2025)
================================================================================
PDF: ~/gao-paper.pdf -> ~/gao-paper.txt (33 pp). Eprint mirror blocked; PolyU copy OK.

**CRITICAL: the paper has NO numeric tables.** All comparisons are Figures 1-4
(matlab plots) reported in TEXT only as PERCENTAGES + qualitative statements.
There are NO absolute KB / ms figures to extract. The "absolute KB" the task asked
for do not exist in the paper text — only relative %.

Paper hardware: Intel i7-8750H @ 2.20 GHz, 8 GB RAM. Impl: Golang + LaGo ring lib.
Reference repo = github.com/GoldSaintEagle/RingCT_Implementation (the ~/gao-ringct clone).

Paper params (ring-sig, "under MatRiCT"): (d,w,p)=(64,56,8), q=2^49-2^18+2^9+1,
(n,m)=(29,60); qb=2^31-2^18+2^3+1, (nb,mb)=(18,38). MatRiCT+ variant: (d,w)=(256,56),
q=167770241(~2^27), (n,kappa)=(4,4), qb=2^34-2^26-2^7+1, (nb,kb)=(5,5).
128-bit PQ security only when #outputs S<=2.

Quoted improvements (vs MatRiCT / vs MatRiCT+):
- Abstract: "up to 50% and 20% proof size, 30% and 20% proving time, 20% and 20%
  verification time of MatRiCT and MatRiCT+, respectively."
- Ring-signature size (Fig 2, k=1, beta=N, N=2..10): ~50% smaller vs MatRiCT;
  ~15% smaller vs MatRiCT+. (This is THE "~50% smaller" claim. It is the ring-sig
  COMPONENT, not a full RingCT tx.)
- Balance-proof size (Fig 1, 64-bit amounts, S=1): 15% at M=1, >50% other M vs
  MatRiCT(w/ range proof); ~20% vs MatRiCT+.
- Time (Fig 3, balance): ~30% prove / ~20% verify vs MatRiCT; ~20%/~20% vs MatRiCT+.
- Ring-sig time (Fig 4, N=10/20/50): ~15% prove reduction at N=50; less at small N;
  "outperform in all settings" but margin small at N~10.
- WHY smaller: Gao removes the binary proof => runs under a SMALLER parameter set.

================================================================================
PART B — GO REFERENCE, MEASURED (ring sig: Gao LinearSum vs MatRiCT OneOutOfMany)
================================================================================
~/gao-ringct, Go 1.22.2, GOPATH mode (GO111MODULE=off), LaGo vendored at
~/go/src/github.com/dedis/lago. README: "toy implementation ... do NOT use in
production." No serializer in repo => proof size computed structurally:
  size = (#ring-elements) * d coeffs * ceil(bitlen(q)/8) bytes.
Both LinearSumProof (Gao) and OneOutOfManyProof (MatRiCT) share setTestSettings:
d=64, q=65537 (3 B/coeff), n=32, m=64 — i.e. IDENTICAL params for both, which the
paper's whole thesis says should DIFFER. So the Go harness CANNOT reproduce the
size gap (which comes from Gao's smaller param set). Element counts measured instead.

** CORRECTNESS OF THE REFERENCE CODE (run on this host): **
  - Gao TestLinearSumProof  ......... PASS  (ring signature, "this work")
  - MatRiCT TestOneOutOfManyProof ... FAIL  (fails at very first case k=1,beta=2)
  - MatRiCT TestBalanceProof ........ FAIL
  - Gao TestLinearEquationArgument_plus FAIL (early-return / >2-out unsupported)
  => Only Gao's ring signature verifies. The MatRiCT baseline DOES NOT verify in
     this published checkout (clean master, single commit, no local edits).

Measured (custom zz_bench_n10_test.go, 20 reps, mean ms; size structural):
scheme         N   valid  proof_elems  size(KB,noX)  prove_ms  verify_ms
Gao-LinearSum   8  true       232        43.50         1168      718
Gao-LinearSum  10  true       234        43.88         1204      724
Gao-LinearSum  16  true       240        45.00         1281      779
MatRiCT-OOOM    8  FALSE      224        42.00         1180      723
MatRiCT-OOOM   10  FALSE      224        42.00         1210      721
MatRiCT-OOOM   16  FALSE      224        42.00         1257      785

Gao N10 prover memory: live HeapAlloc ~18 MB; process peak RSS ~95 MB (Go runtime+GC).
NOTE: under identical params the element counts are ~equal (Gao slightly LARGER),
so the Go harness does NOT show the paper's 50% size win — that win lives entirely
in the parameter-set choice, which this toy ties together. Times here (~0.7-1.3 s)
are LaGo-on-Go and not comparable to the C MatRiCT-Au below.

This is PARTIAL RingCT: it benchmarks the ring-signature (one-out-of-many / linear-
sum) COMPONENT only. No confidential-amount commitments, no balance proof wired in,
no linkability/nullifier end-to-end. Balance proof exists separately but FAILS.

================================================================================
PART C — MatRiCT-Au IN-REPO BASELINE, MEASURED (~/matrict-lib, NOT modified)
================================================================================
n10m1 = ring size 10, 1 input. AMD Ryzen 9 5950X. Full keygen->CRS->spend->verify->audit.
- serialize_test_n10m1 30: PACKED proof+cn+s = 109,936 B (107.4 KB); RAW = 292.5 KB.
- selftest_n10m1 30: 30/30 correct, PASS. Cycles->ms @ 3.494 GHz:
    Verify : median 11.95 ms (11.82-12.32, very stable)   mean 11.97 ms
    Spend  : median 63.0 ms  (15.5-418.9, rejection-sampling tail) mean 98.4 ms
    SamMat(CRS) ~4.1 ms, TdRowGen ~1.9 ms, Audit ~0.005 ms
- Peak prover RSS (whole selftest): 31,204 KB (~30.5 MB).

================================================================================
HEAD-TO-HEAD (ring size ~10, this WSL host)
================================================================================
                         | Gao LinearSum (Go, N=10) | MatRiCT-Au n10m1 (C)
proof size               | 43.9 KB (struct, no ser) | 107.4 KB packed / 292.5 KB raw
verify                   | ~724 ms (LaGo/Go)        | ~12.0 ms (C)
prove                    | ~1204 ms (LaGo/Go)       | ~63 ms median (C)
prover mem               | ~18 MB heap / ~95 MB RSS | ~30.5 MB RSS
verifies?                | YES                      | YES (30/30)
scope                    | ring-sig component only  | full RingCT (ring+amount+audit)
language                 | Go (toy, unaudited)      | C (MatRiCT-Au ref, unaudited)

These are NOT comparable cross-impl (Go/LaGo vs hand-tuned C; different param sets;
component vs full tx). The size numbers are different objects: Gao 43.9 KB is the
ring-sig proof under q=65537/d=64 toy params; MatRiCT-Au 107.4 KB is a full packed
spend proof (ring sig + amount commitments + serialized). NOT apples-to-apples.

CONFIRM/CORRECT the "~50% smaller / ~20% faster" claim:
- "~50% smaller": this is the PAPER's claim for the ring-signature COMPONENT vs the
  ORIGINAL MatRiCT (2019), measured in Gao's own Go impl under DIFFERENT param sets.
  It is NOT a measured 50% vs MatRiCT-Au, and NOT vs MatRiCT+ (only ~15-20% there).
  We could NOT reproduce a 50% size win on this host: the Go toy ties both schemes to
  one param set (=> ~equal sizes), and a Go-vs-C cross-impl size compare is meaningless.
- "~20% faster": paper = ~20% verify / 20-30% prove vs MatRiCT, ~20% vs MatRiCT+, in
  Gao's Go impl. Again relative within Go, not vs MatRiCT-Au C. NOT reproduced as an
  absolute speed win over MatRiCT-Au (the C verify is ~60x faster simply by language).
- MatRiCT-Au is the SUCCESSOR of MatRiCT/MatRiCT+ (the auditable 2022/24 line); the
  paper compares against MatRiCT (2019) and MatRiCT+ (2022), NOT MatRiCT-Au. So the
  50%/20% figures do NOT describe a Gao-vs-MatRiCT-Au gap at all.
