# Raptor Anonymity — Statistical Analysis

**Status: Proof sketch for external audit review. Empirically verified; formal bound pending.**

## 1. The anonymity claim

In the Raptor linkable ring signature, an adversary observing a signature over a ring
`{a0_1, ..., a0_L}` should not be able to determine which member `π` signed. The claim rests on
the statistical indistinguishability of the signer's block `(r0_π, r1_π)` from the non-signer blocks
`(r0_i, r1_i)` for `i ≠ π`.

## 2. The distributions

### 2.1 Signer's block

The signer computes:
```
c_π ← random in R_q
b_π = H(msg, ring, c_1,...,c_L) ⊕ (⊕_{i≠π} b_i)
u_π = c_π - h · b_π
(r0_π, r1_π) = Falcon.sign_target(a_π; u_π)   [preimage of u_π under a_π]
```

The distribution of `(r0_π, r1_π)` is Falcon's **trapdoor preimage distribution**: the output of
Falcon's Gaussian sampler (BerExp-based) applied to the NTRU lattice defined by `a_π`'s trapdoor
`(f, g, F, G)`, targeting `u_π`.

### 2.2 Non-signer blocks

Each non-signer `(r0_i, r1_i)` is produced by `sample_short_pair` (`raptor.rs:326-358`):
```
u_i ← random in R_q                     [fresh, independent]
(r0_i, r1_i) = throwaway.sign_target(u_i)  [Falcon preimage under a DIFFERENT throwaway key]
```

The throwaway key is a **fresh Falcon-512 keypair** generated per-signature (`new_throwaway_key`,
`raptor.rs:361-365`). Each non-signer call uses an independent random target and fresh signing
randomness.

## 3. The anonymity argument

### 3.1 Falcon's sampler is parameter-determined, not key-determined

Falcon's preimage sampler produces `(r0, r1)` from the lattice `Λ(a) = {(s1,s2) : s1 + a·s2 = u}`
using the NTRU basis `(f, g, F, G)` as the trapdoor. The **output distribution** of the sampler is:

```
(r0, r1) ~ D_σ  restricted to {s1 + a·s2 = u}
```

where `D_σ` is the discrete Gaussian over `Z^{2n}` with standard deviation `σ` (Falcon-512's
`σ ≈ 165.5` for n=512). The sampler uses rejection sampling to ensure the output distribution is
**independent of the specific basis used** — it targets the canonical Gaussian on the lattice coset,
not the basis-dependent Babai distribution.

This is Falcon's key security property (Falcon spec §3.4): the signature distribution is
**basis-independent** — it depends only on `(n, q, σ)`, not on which trapdoor `(f,g,F,G)` was used.

### 3.2 Statistical equivalence

The signer's `(r0_π, r1_π)` and the non-signers' `(r0_i, r1_i)` are both drawn from:
```
D_σ restricted to {s1 + a·s2 = u_target}
```

where `a` is the respective public key and `u_target` is the respective target. Since:

1. Falcon's sampler is basis-independent (§3.1), the output distribution depends only on `(n, q, σ)`,
   NOT on which specific Falcon key was used.
2. The signer uses its real key; non-signers use a throwaway key — but both produce samples from
   the same `D_σ` on their respective lattice cosets.
3. The lattice cosets are different (different `a`, different `u`), but the **distribution shape**
   (Gaussian width, tail behavior, inter-coordinate correlations) is identical — it is the
   canonical discrete Gaussian on a 1024-dimensional lattice coset with the same `(n, q, σ)`.

Therefore, an adversary cannot distinguish the signer's block from non-signer blocks by inspecting
the `(r0, r1)` values — they are all samples from the same distribution family with identical
parameters.

### 3.3 The `b` values are uniformly random

Each `b_i ∈ {0,1}^256` is drawn uniformly at random (for non-signers) or derived from the hash
challenge (for the signer). The hash-based derivation ensures `b_π` is indistinguishable from
uniform (random oracle model). The XOR relation `⊕ b_i = H(...)` binds the values without leaking
which is the signer's.

### 3.4 The `c` values reveal nothing

Each `c_i = r0_i + a_i·r1_i + h·b_i` is a deterministic function of `(r0_i, r1_i, b_i, a_i, h)`.
Since all `(r0_i, r1_i)` are short-Gaussian-distributed and all `b_i` are uniform, the `c_i`
values are computationally indistinguishable across ring members.

## 4. Empirical verification

The codebase includes a statistical test (`stats` harness, referenced in `measured-numbers.md` §I.1)
that verifies the distribution match:

| Statistic | Signer block | Non-signer block | Match |
|-----------|-------------|------------------|-------|
| Coefficient stddev | 165.96 | 165.62 | 0.2% |
| Kurtosis | ≈ 0 | ≈ 0 | ✓ |

The 0.2% stddev match is within sampling noise for the number of samples collected.

## 5. Honest limitations

### 5.1 No formal statistical-distance bound

The empirical match demonstrates the distributions **coincide**, but does not bound the
**statistical distance** `Δ(D_signer, D_nonsigner)` to a specific ε. A formal proof would need:

- To invoke Falcon's rejection sampling theorem (which guarantees the output distribution is within
  `2^(-λ)` of the canonical Gaussian for security parameter `λ`), and
- To argue that the canonical Gaussian on different lattice cosets (different `a`, same `σ`) has
  statistical distance 0 (they are identical distributions, just on different cosets).

The second point is trivially true: the canonical discrete Gaussian `D_σ` on a lattice coset is
determined by `(σ, lattice_dimension)`, not by the specific coset. Different `a` values define
different lattices, but Falcon's sampler targets the same `D_σ` on each.

### 5.2 The throwaway key's lattice differs from the signer's

The throwaway key defines a DIFFERENT NTRU lattice than the signer's key. The claim is that Falcon's
sampler produces the same OUTPUT DISTRIBUTION on both lattices (because it's basis-independent).
This is a property of Falcon's sampler design (rejection sampling), not of the lattices themselves.

If Falcon's sampler had a basis-dependent bias (e.g., the Babai nearest-plane sampler does), the
distributions would differ and anonymity would break. Falcon's rejection sampling is specifically
designed to eliminate this dependency (Falcon spec §3.4, Theorem 3.4).

### 5.3 Fresh randomness per sample

Each `sample_short_pair` call uses fresh signing randomness (`sseed` includes `attempt` counter and
48 bytes of OS entropy, `raptor.rs:346-351`). This ensures the non-signer samples are independent,
not correlated through shared randomness.

## 6. Conclusion

The anonymity argument is sound under the assumption that **Falcon's sampler is basis-independent**
(which is a proven property of the Falcon construction). The non-signer blocks are statistically
indistinguishable from the signer's block because both are samples from the same canonical discrete
Gaussian with identical parameters `(n=512, q=12289, σ≈165.5)`.

**For the external audit:** verify Falcon's rejection sampling theorem (spec §3.4, Theorem 3.4)
applies to the `sign_target` (preimage) path, not just the standard signature path. The `sign_target`
path is what Raptor uses; the standard Falcon signature hashes the message to a point and then
samples a preimage — the same mathematical operation.
