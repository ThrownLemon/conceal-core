# v2 Consensus Parameters — proposal (D8 draft)

> Grounded in the **measured** v2 serialized sizes (`spike/pqc` round-trip + `wire-size-calc.py`), at ring 6 / ML-KEM-768 stealth. Current values are PQ-incompatible (every PQ ring tx exceeds them). These are **proposals for the team** — `[DECISION]`.

## Measured v2 tx sizes (serialization round-trip, real bytes)
| Profile (in/out) | MatRiCT-Au | Raptor | Falafl |
|---|---|---|---|
| median 1/1 | 25 KB | 19 KB | 40 KB |
| avg 2/2 | 50 KB | 38 KB | 81 KB |
| p90 4/7 | 115 KB | 82 KB | 177 KB |
| fusion 45/2 | 878 KB | 768 KB | 1.59 MB |

## The three caps that must change
| Param | Today | Why it breaks | Proposal `[DECISION]` |
|---|---|---|---|
| `CRYPTONOTE_MAX_TX_SIZE_LIMIT` | ~99 KB | p90 + fusion txs exceed it → rejected | **≥ p90 with headroom.** If fusion stays unbounded: ~2 MB. If fusion is capped (below): ~256 KB covers p90. |
| `FUSION_TX_MAX_SIZE` | 30 KB | every PQ fusion tx exceeds → fusion impossible | **Redesign:** cap fusion *input count* so a fusion tx ≤ MAX_TX (e.g. ≤8–12 PQ inputs/tx), or use MatRiCT input-amortization. Raise the byte cap to match. |
| `CRYPTONOTE_BLOCK_GRANTED_FULL_REWARD_ZONE` | 100 KB | normal PQ tx (38–81 KB) ≈ a whole zone → reward-penalized | **~1 MB** so several PQ txs fit the free zone (block size stays dynamic = 2× median). |

## Recommended starting point (MatRiCT-Au, ring 6)
- `MAX_TX_SIZE_LIMIT` = **512 KB** (covers p90 115 KB with large headroom; forces fusion to be bounded — see below).
- **Fusion redesign:** cap inputs/fusion-tx so it stays < MAX_TX (MatRiCT amortization makes multi-input cheap); raise `FUSION_TX_MAX_SIZE` to ~256 KB.
- `BLOCK_GRANTED_FULL_REWARD_ZONE` = **1 MB** (~13–20 normal PQ txs in the free zone; dynamic max = 2 MB+).
- Storage at current demand (~1.16 tx/blk): MatRiCT ≈ **18 GB/yr** (see comparison-chart). Mitigate with signature pruning (E2).

## Open
- Final values depend on ring size (D7) and scheme (D1). The 45-input fusion outlier (878 KB–1.6 MB) is the forcing case — **decide whether to bound fusion inputs or raise MAX_TX to multi-MB.** Bounding is cleaner (keeps per-tx + block sizes sane).
