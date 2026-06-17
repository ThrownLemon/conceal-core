#!/usr/bin/env python3
# Level-1 wire-size aggregation: Conceal's OWN tx-size structure
# (Currency::getApproximateMaximumInputCount) with PQ object sizes substituted.
# Validated: Ed25519 avg tx reproduces Conceal's ~1.2 KB.

MIXIN = 5                      # MINIMUM_MIXIN -> ring 6
RING = MIXIN + 1
ZONE = 100000                  # CRYPTONOTE_BLOCK_GRANTED_FULL_REWARD_ZONE
HEADER = 1 + 8 + 1 + 32        # version + unlock + extra-tag + tx pubkey = 42
KEM = 1088                     # ML-KEM-768 ciphertext per output (PQ stealth)

# object sizes (bytes), measured where possible
SCHEMES = {
    # name: (arch, sig_per_member|proof, nullifier, out_key, needs_kem, verify_ms_per_input)
    "Ed25519 ring (today)":      ("ring", 64,    32,  32,   False, 0.95),
    "Raptor ring (linear)":      ("ring", 2520,  897, 897,  True,  0.80),
    "MatRiCT-Au ring (log)":     ("logring", 19000, 248, 4360, True, 19.0),
    "Falafl ring (log)":         ("logring", 35000, 0,  4096, True, 32.0),
    "Falcon NO-RING (dev idea)": ("noring", 752,  32,  897,  True,  0.10),
    "SPHINCS+128f NO-RING":      ("noring", 17088,32,  32,   True,  0.50),
    "SPHINCS+128s NO-RING":      ("noring", 7856, 32,  32,   True,  1.50),
}

def input_bytes(arch, sig, nul):
    base = 1 + 10 + nul + 1 + 4          # tag + amount + nullifier + idx-vec + idx-init
    if arch == "ring":                   # one sig per ring member (linear)
        return base + MIXIN*4 + RING*sig
    if arch == "logring":                # one proof blob covers the ring
        return base + MIXIN*4 + sig
    if arch == "noring":                 # transparent input: reference 1 output + 1 witness sig
        return 1 + 10 + nul + 4 + sig    # no decoy indexes
    raise ValueError(arch)

def output_bytes(out_key, kem):
    return 1 + out_key + 10 + (kem if kem else 0)

PROFILES = [("median",1,1), ("average",2.39,2.22), ("p90",4,7), ("fusion",45,2)]

print(f"{'scheme':<28} {'med':>8} {'avg':>9} {'p90':>9} {'fusion':>10}   {'avg verify':>10}  {'txs/block':>9}")
for name,(arch,sig,nul,ok,needkem,vms) in SCHEMES.items():
    kem = KEM if needkem else 0
    ib = input_bytes(arch, sig, nul); ob = output_bytes(ok, kem)
    def tx(ins,outs): return HEADER + outs*ob + ins*ib
    sizes = {p: tx(i,o) for p,i,o in PROFILES}
    avg = sizes["average"]; avgv = 2.39*vms
    per_block = max(1, int(ZONE/avg)) if avg < ZONE else 0
    def kb(x): return f"{x/1000:.1f}K" if x>=1000 else f"{x:.0f}"
    note = "" if per_block>0 else " (>block!)"
    print(f"{name:<28} {kb(sizes['median']):>8} {kb(avg):>9} {kb(sizes['p90']):>9} {kb(sizes['fusion']):>10}   {avgv:>8.1f}ms  {str(per_block)+note:>9}")

print(f"\n(ring={RING}, mixin={MIXIN}; avg tx = 2.39 inputs / 2.22 outputs from 468 live txs;")
print(f" block reward zone = {ZONE//1000} KB; txs/block = how many average txs fit before the size penalty.)")
