# Raptor Exact-Scheme and Proof Analysis

Status: In progress; current worktree closes the pre-fix programmed-key forgery but no reviewed reduction exists  
Original audit snapshot: `1d5cda1483c70f51b081c9513b9497ec602ddb16`  
Current recheck HEAD: `411c848f7276ae5099b7e5c7e0fd01977f6ae243` plus dirty remediation/audit files  
Paper: Lu, Au, Zhang, *Raptor: A Practical Lattice-Based (Linkable) Ring Signature*, ePrint 2018/857

## Current verdict

The implementation is recognizably derived from the linkable Raptor construction in paper Section 5.4,
but the current worktree intentionally changes the challenge oracle to bind the ring public keys
directly. That change closes the adaptive programmed-key forgery found during reduction work, but the
paper's published proofs still do not directly establish security for this exact code. The remaining
obligations are:

1. adapt the generic proof to the instantiated transcript and exact bounded relation;
2. quantify Falcon preimage output independence from the trapdoor/public key;
3. prove the multi-sample case when all decoys share one hidden throwaway key;
4. define the exact R-SIS/R-ISIS bounds induced by verification;
5. independently review any completed reduction.

## Exact implemented scheme

Let `R_q = Z_q[x]/(x^512 + 1)`, `q = 12289`. Canonical ring elements use Falcon's
14-bit `modq` encoding. Let:

- `H1(aots) = HashToRq("RAPTOR-CCX-H1-mask", modq(aots))`;
- `h = HashToRq("RAPTOR-CCX-paramch-h", "conceal-raptor-paramch-v0")`;
- current worktree:
  `H0(mu, a0[1..L], c[1..L]) = SHAKE256_256("RAPTOR-CCX-H-transcript" ||
  LE64(|mu|) || mu || LE64(L) || modq(a0_1) || ... || modq(a0_L) ||
  modq(c1) || ... || modq(cL))`;
- original audited snapshot:
  `H0(mu, c[1..L]) = SHAKE256_256("RAPTOR-CCX-H-transcript" || LE64(|mu|) || mu ||
  modq(c1) || ... || modq(cL))`;
- `N(aots) = SHAKE256_256("RAPTOR-CCX-nullifier" || modq(aots))`;
- `T(members, ring, aots)` be the length-prefixed OTS transcript at
  `raptor.rs:264-291`;
- `HT(T) = HashToRq("RAPTOR-CCX-ots-target", T)`.

### Key generation

From a 48-byte wallet seed, derive independent deterministic Falcon-512 keypairs:

```text
(a, td)       <- Falcon.KeyGen(SHAKE256("RAPTOR-CCX-key-main" || seed))
(aots, tdots) <- Falcon.KeyGen(SHAKE256("RAPTOR-CCX-key-ots"  || seed))
mask           = H1(aots)
a0             = a + mask mod q
public output  = a0
secret         = (td, tdots, a, aots, mask)
```

The on-chain public output contains `a0`, not `aots`. `aots` is revealed by a spend signature and its
hash is the nullifier.

### Signing

For signer position `pi` and ring `a0[1..L]`:

```text
ai = a0i - H1(aots)
```

For every `i != pi`, choose uniform `bi` in `{0,1}^256`. The implementation creates one fresh hidden
Falcon throwaway key per signature, then for each decoy chooses a fresh uniform target `ui` and
samples:

```text
(r0i, r1i) <- Falcon.Inv(throwaway_td, ui)
ci          = r0i + ai*r1i + h*bi
```

For the signer, repeatedly sample uniform `cpi`, set:

```text
bpi          = H0(mu, a0[1..L], c[1..L]) XOR XOR(i != pi, bi)
upi          = cpi - h*bpi
(r0pi,r1pi) <- Falcon.Inv(td, upi)
```

All response pairs must satisfy the Falcon-512 joint squared-norm ceiling `34,034,726` and both
polynomials must be Falcon-compressible.

Finally:

```text
(s0,s1) <- Falcon.Inv(tdots, HT(T(members, ring, aots)))
```

The signature is `members || aots || (s0,s1)`.

### Verification and linking

Verification checks canonical decoding, response and OTS joint norm ceilings, explicit
`bi in {0,1}^256`, recomputes every `ci`, verifies the XOR relation, and verifies:

```text
s0 + aots*s1 = HT(T(members, ring, aots))
```

The consensus nullifier is `N(aots)`. Two accepted spends link when their nullifier hashes are equal.

## Paper-to-code mapping

| Paper Section 5.4 operation | Implementation | Assessment |
|---|---|---|
| Two Falcon keypairs | `raptor.rs:118-135` | Matches, with deterministic domain-separated seeds. |
| `a0 = a + H1(aots)` | `raptor.rs:127-131` | Matches addition-over-`R_q` instantiation. |
| `ai = a0i - H1(aots)` | `raptor.rs:400-405`, `531` | Matches. |
| Decoy `bi <- {0,1}^256` | `raptor.rs:417-432` | Matches. |
| Decoy `(r0,r1) <- D_r` | `raptor.rs:315-365` | Changed to Falcon inversion under one shared hidden key. Requires a quantified equivalence lemma. |
| `ci = r0 + ai*r1 + h*bi` | `raptor.rs:422-430`, `531-539` | Matches. |
| Uniform `cpi <- R_q` | `raptor.rs:454-462` | Matches. |
| XOR challenge | `raptor.rs:241-254`, `464-466` | Current worktree binds `ring` into `H`; this deliberately differs from Section 5.4 and is load-bearing for the programmed-key forgery fix. |
| Falcon inversion for signer | `raptor.rs:468-480` | Matches algebraically; adds norm/compression rejection. |
| Falcon signature over members, ring, `aots` | `raptor.rs:256-291`, `489-505` | Matches Section 5.4 semantically via a domain-separated `HashToRq`. |
| Link tag `aots` | `raptor.rs:199-212`, `560-563` | Code exposes `SHAKE256(aots)` to consensus rather than raw `aots`. |

## Important corrections to the initial audit

### Current challenge binding differs from the original paper instantiation

The original audited snapshot followed the paper's full Raptor descriptions in Sections 5.3 and 5.4,
which use `H(mu,c1,...,cL)` and bind the ring only through the Falcon OTS transcript. During reduction
work, that proved insufficient for adaptive-ring/key-programming resistance: an attacker could choose a
ring key after seeing a challenge in the pre-fix construction.

The current worktree now absorbs the ring public-key list into `H0`, closer to the generic proof's
`Lpk` binding. The regression
`raptor::adaptive_ring_forgery::programmed_key_forgery_is_rejected` passes. This is a security
improvement, not a complete proof: the exact modified scheme still needs a reviewed reduction.

### The paper does not define the audit brief's named `B1`

The reviewed ePrint text specifies membership in distributions `D x D x Db` and gives no named `B1`
or formula `nu * eta * sqrt(n)`. The implementation turns that distribution-membership requirement
into Falcon's standard joint squared-norm ceiling plus compressibility. Task 2 must derive the exact
bounded relation needed for R-SIS/R-ISIS and honest-distribution acceptance; it cannot merely
"correct the paper's B1."

## Proof ledgers

### Unforgeability

The intended route is:

1. a successful new ring transcript gives a collision or inversion in
   `Hash_a(r0,r1,b) = r0 + a*r1 + h*b`;
2. differences of two accepted openings produce an R-SIS solution for `(1,a,h)`;
3. a forged transcript under an already revealed `aots` alternatively gives a Falcon OTS forgery;
4. NTRU pseudorandomness hides which transformed `ai` has a trapdoor.

This route is not yet a reduction for the implementation:

- the exact R-SIS norm is determined by differences of two jointly bounded Falcon responses and
  binary `b` values, but has not been calculated;
- the generic forking proof hashes `Lpk` in `H0`, while Section 5.4 and the code bind `Lpk` in the OTS;
- the implementation hashes the OTS transcript to an arbitrary ring target and verifies only the
  preimage relation and Falcon norm, so the required Falcon unforgeability statement must be stated
  for this raw target-driven interface;
- the security game must enforce one honest signature per output/OTS key. Consensus spends an output
  once, but the cryptographic statement must not silently assume unrestricted many-time OTS security.

**Current status:** plausible proof route, incomplete.

### Anonymity

The paper's argument requires:

```text
Inv(a, td, u, b) is statistically close to the public decoy distribution D_r,
independently of the trapdoor-bearing key.
```

The code does not sample decoys directly from the stated product Gaussian `D_R,eta^2`. It invokes the
same Falcon preimage sampler on random targets under a fresh hidden throwaway key. This is a sensible
engineering attempt to match implementations, but it creates two obligations:

1. **single-sample key independence:** quantify statistical distance between Falcon inversion outputs
   for independently generated Falcon keys at the exact Falcon-512 sampler width;
2. **multi-sample shared-key independence:** bound the joint distribution of `L-1` outputs produced
   under one hidden throwaway key against independent samples from the signer distribution.

Conditional independence given the throwaway key is insufficient if the output distribution has any
key-dependent feature. The source comment's reference to a `stats` harness is unsupported in the
reviewed tree.

The OTS response is generated under the disclosed `aots` but is not associated with a ring position.
No direct position leak was identified there.

**Current status:** unproven pending sampler theorem and classifier testing.

### Linkability, false linking, and nonslanderability

For an honestly derived output, `aots` is deterministic from the stored seed, the OTS authenticates
`aots` and the complete ring transcript, and consensus checks the declared nullifier against
`N(aots)`. A second accepted spend with the same `aots` therefore has the same nullifier.

The remaining statements require separate assumptions:

- different `aots` values collide as nullifiers only by finding a 256-bit SHAKE collision;
- producing a second valid `aots' != aots` for the same public `a0` requires finding another
  trapdoor-bearing `a' = a0 - H1(aots')` plus an OTS trapdoor, or breaking the ring/OTS relation;
- framing an honest output with its `aots` requires forging the target-driven Falcon OTS after at
  most one honest signature.

The paper links by raw `aots` equality; the implementation links by a hash. This is a conventional
change, but collision resistance of the nullifier hash is an additional explicit assumption.

**Current status:** plausible under NTRU sparsity, R-SIS/R-ISIS, one-signature Falcon
unforgeability, and SHAKE collision resistance; reduction incomplete.

## Required next evidence

- Calculate the exact R-SIS/R-ISIS norm bounds induced by verifier acceptance.
- Locate or derive the applicable Falcon/GPV statistical-distance theorem with exact parameters.
- Implement the pre-registered signer/decoy classifier in Task 4.
- Write the composition reduction that moves `Lpk` binding from `H0` to the Falcon OTS target.
- Obtain independent cryptographic review before changing the status from "unproven."
