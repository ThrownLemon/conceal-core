#!/usr/bin/env bash
# LIVE end-to-end demo of the "Option 3" classical-deposit CREATION FREEZE (CIP-0001, UPGRADE_HEIGHT_V9).
#
# Consensus rule under test (testnet TESTNET_UPGRADE_HEIGHT_V9 = 80):
#   At/after the V9 activation height, CREATION of a NEW classical (Ed25519) deposit output
#   (a MultisignatureOutput with term != 0) is REJECTED. CREATION-side only — withdrawing an
#   ALREADY-EXISTING classical deposit stays valid. Enforced at three sites:
#     * Blockchain::pushBlock per-tx gate + coinbase guard (authoritative consensus),
#     * tx_memory_pool::add_tx loose-tx reject (mempool policy: logs
#       "classical deposit creation is frozen at/after height ..." and fails sendrawtransaction).
#
# Proves THREE behaviors on a LIVE, ISOLATED 2-node testnet (node1 mines; nodes exclusive-peer only
# each other, never touch the real testnet):
#   #1  PRE-V9  (height < 80): create a classical deposit            => ACCEPTED (confirms into a block).
#   #2  POST-V9 (height >= 80): withdraw that pre-V9 deposit (matured) => ACCEPTED (existing deposits
#                                                                          stay spendable — Option-3 guarantee).
#   #3  POST-V9 (height >= 80): create a NEW classical deposit        => REJECTED by the freeze (daemon
#                                                                          logs the freeze line; tx never confirms).
#
# ── FUNDING NOTE (why this harness uses classical_deposit_injector, not `concealwallet deposit`) ──
# On this PoC branch the testnet coinbase (Currency::constructMinerTx, m_testnet branch) emits a PQ
# stealth output at index 0 PLUS a classical "remainder" KeyOutput at index 1 to the miner. The
# remainder's one-time key is derived at output-position index 1, but every wallet scanner
# (TransfersConsumer::findMyOutputs / lookup_acc_outs) walks a keyIndex counter that does NOT advance
# over the leading PQ output, so it tries index 0 and never recognises the remainder — a mined wallet
# shows 0 classical balance. (Confirmed empirically + by code; it is a pre-existing wallet/coinbase
# index quirk, NOT the freeze.) So to OWN a spendable classical input we spend that coinbase remainder
# directly with pqc/tools/classical_deposit_injector — a standalone harness tool (the classical twin of
# pq_injector) that re-derives the one-time key at the correct index via the project's own
# cn::createTransaction builder. NO consensus/crypto source is modified. The injected deposit tx (a
# normal v2 tx with no leading PQ output) IS scannable, so the miner wallet recognises the deposit and
# `withdraw 0` works for behavior #2.
#
# Engineering discipline mirrors pqc/verify-wallet-w2w.sh: isolated nodes, explicit poll-gates on
# daemon RPC + wallet transcript (never a fixed sleep as the only sync), concealwallet teardown-crash
# tolerance, clear PASS/FAIL assertions, cleanup trap.
#
# Usage:  pqc/verify-deposit-freeze.sh /path/to/build/src      (e.g. ~/conceal-core/build/src on WSL)
set -uo pipefail

BIN="${1:-build/src}"
CONCEALD="$BIN/conceald"
WALLET="$BIN/concealwallet"
INJECTOR="$BIN/classical_deposit_injector"

V9=80                          # TESTNET_UPGRADE_HEIGHT_V9 — the freeze activation height
DEP_AMOUNT=2000000             # 2 CCX deposit (>= depositMinAmount 1 CCX; fits one 4.9-CCX coinbase remainder)
DEP_TERM=30                    # testnet min deposit term (= depositMinTermV3); unlock = create_height + 30
DEP_FEE=1000
PREV9_COINBASE_HEIGHT=3        # coinbase whose remainder funds the PRE-V9 deposit (unlocks at h=13)
POSTV9_COINBASE_HEIGHT=6       # a DIFFERENT coinbase remainder for the POST-V9 (rejected) attempt
CREATE_GATE=15                 # create the pre-V9 deposit once height reaches this (coinbase unlocked, < 80)
MINE_BUF=4                     # mine this many blocks past V9 before the post-V9 reject attempt

RPC1=16600
RPC2=16601
N1=/tmp/ccx-df1                # node1 data dir (miner; --log-level 3 so the freeze INFO line is captured)
N2=/tmp/ccx-df2                # node2 data dir (peer)
WAL=/tmp/ccx-df-wallet         # wallet file base ($WAL.wallet); mined-to + withdraw driver
WFIFO=/tmp/ccx-df.fifo         # command channel that keeps the wallet session open
WOUT=/tmp/ccx-df-wallet.out    # wallet session transcript (verdict surface for #2)
GENOUT=/tmp/ccx-df-gen.out     # wallet generation transcript (captures ccx7 address + secret keys)
D1LOG="$N1/d.log"              # node1 daemon log (carries the freeze log line for behavior #3)

WALPID=""

height() { curl -s "http://127.0.0.1:$RPC1/getinfo" 2>/dev/null | grep -oE '"height":[0-9]+' | grep -oE '[0-9]+'; }
pool()   { curl -s "http://127.0.0.1:$RPC1/getinfo" 2>/dev/null | grep -oE '"tx_pool_size":[0-9]+' | grep -oE '[0-9]+'; }
jrpc()   { curl -s -X POST "http://127.0.0.1:$RPC1/json_rpc" -H 'Content-Type: application/json' -d "$1" 2>/dev/null; }

cleanup() {
  exec 9>&- 2>/dev/null || true
  [ -n "$WALPID" ] && kill -9 "$WALPID" 2>/dev/null || true
  pkill -x concealwallet 2>/dev/null || true
  pkill -x conceald 2>/dev/null || true
  rm -f "$WFIFO" 2>/dev/null || true
}
trap cleanup EXIT

fail() { echo; echo "######## RESULT: FAIL ########"; echo "   $*"; exit 1; }

wait_for() { # <file> <regex> <max_seconds>
  local f="$1" re="$2" max="$3" i=0
  while [ "$i" -lt "$max" ]; do
    grep -qE "$re" "$f" 2>/dev/null && return 0
    sleep 1; i=$((i+1))
  done
  return 1
}

wait_height() { # <target> <max_seconds>
  local target="$1" max="$2" i=0 H
  while [ "$i" -lt "$max" ]; do
    H=$(height || true)
    [ "${H:-0}" -ge "$target" ] 2>/dev/null && return 0
    sleep 2; i=$((i+2))
  done
  return 1
}

# Fetch the classical coinbase-remainder spend material for a given block height:
#   echoes "<coinbaseHex> <remainderGlobalIndex>" or empty on failure.
# The remainder is output index 1; its global index is the 2nd entry of the coinbase's output_indexes.
fetch_remainder() { # <blockHeight>
  local hgt="$1" raw cbhash gidx cbhex
  raw=$(jrpc "{\"jsonrpc\":\"2.0\",\"id\":\"0\",\"method\":\"getrawtransactionsbyheights\",\"params\":{\"heights\":[$hgt],\"include_miner_txs\":true,\"range\":false}}")
  cbhash=$(echo "$raw" | grep -oE '"hash":"[0-9a-f]{64}"' | head -1 | grep -oE '[0-9a-f]{64}')
  gidx=$(echo "$raw" | grep -oE '"output_indexes":\[[0-9,]+\]' | head -1 | grep -oE '[0-9]+' | sed -n '2p')
  [ -n "$cbhash" ] && [ -n "$gidx" ] || return 1
  cbhex=$(curl -s -X POST "http://127.0.0.1:$RPC1/gettransactions" -H 'Content-Type: application/json' \
            -d "{\"txs_hashes\":[\"$cbhash\"]}" 2>/dev/null \
          | grep -oE '"txs_as_hex":\["[0-9a-f]+' | grep -oE '[0-9a-f]{40,}' | head -1)
  [ -n "$cbhex" ] || return 1
  echo "$cbhex $gidx"
}

submit() { # <txHex> -> echoes daemon JSON
  curl -s -X POST "http://127.0.0.1:$RPC1/sendrawtransaction" -H 'Content-Type: application/json' \
    -d "{\"tx_as_hex\":\"$1\"}" 2>/dev/null
}

echo ">> cleanup any stragglers"
pkill -x conceald 2>/dev/null || true; pkill -x concealwallet 2>/dev/null || true; sleep 2
rm -rf "$N1" "$N2" "$WAL"* "$WFIFO" "$WOUT" "$GENOUT"; mkdir -p "$N1" "$N2"

[ -x "$INJECTOR" ] || fail "classical_deposit_injector not found at $INJECTOR (build it: make ClassicalDepositInjector)"

# ── Step 0: generate the wallet we mine to; capture its ccx7 address + secret keys. ─────────────────
echo ">> [wallet] generate driver wallet; capture ccx7 mining address + secret keys"
printf 'export_keys\nexit\n' | "$WALLET" --testnet --generate-new-wallet "$WAL" --password x >"$GENOUT" 2>&1 || true
MINE_ADDR=$(grep -oE 'ccx7[0-9A-Za-z]{90,}' "$GENOUT" | head -1)
SPEND_KEY=$(grep -oE 'Private spend key: [0-9a-f]{64}' "$GENOUT" | grep -oE '[0-9a-f]{64}' | head -1)
VIEW_KEY=$(grep -oE 'Private view key: [0-9a-f]{64}' "$GENOUT" | grep -oE '[0-9a-f]{64}' | head -1)
echo "   mining address = ${MINE_ADDR:-<none>}"
[ -n "${MINE_ADDR:-}" ] && [ -n "${SPEND_KEY:-}" ] && [ -n "${VIEW_KEY:-}" ] \
  || fail "could not capture address + secret keys from wallet generation ($GENOUT)"

# ── Step 1: launch two isolated testnet nodes; node1 mines to our address at log-level 3 (INFO). ────
echo ">> launch 2 isolated testnet nodes (node1 mines to our address, --log-level 3 to capture freeze line)"
setsid "$CONCEALD" --testnet --data-dir "$N1" --no-console --hide-my-port --p2p-bind-ip 127.0.0.1 \
  --add-exclusive-node 127.0.0.1:15600 --rpc-bind-port "$RPC1" --p2p-bind-port 15500 \
  --log-level 3 --log-file "$D1LOG" --start-mining "$MINE_ADDR" --mining-threads 4 \
  >/tmp/ccx-df1.out 2>&1 </dev/null &
setsid "$CONCEALD" --testnet --data-dir "$N2" --no-console --hide-my-port --p2p-bind-ip 127.0.0.1 \
  --add-exclusive-node 127.0.0.1:15500 --rpc-bind-port "$RPC2" --p2p-bind-port 15600 \
  --log-level 0 --log-file "$N2/d.log" >/tmp/ccx-df2.out 2>&1 </dev/null &

echo ">> wait for chain to reach height $CREATE_GATE (coinbase remainder at h$PREV9_COINBASE_HEIGHT unlocks at +10)"
wait_height "$CREATE_GATE" 240 || fail "chain did not reach height $CREATE_GATE in time"
echo "   height=$(height)"

# ===================================================================================================
# BEHAVIOR #1 — PRE-V9: create a classical deposit  => EXPECT ACCEPTED (confirms into a block)
# ===================================================================================================
echo
echo "==================== BEHAVIOR #1: PRE-V9 deposit creation (expect ACCEPTED) ===================="
H1=$(height)
[ "${H1:-0}" -lt "$V9" ] 2>/dev/null || fail "chain already at/after V9 ($H1 >= $V9) before behavior #1 — window blown"
echo ">> build a classical deposit ($((DEP_AMOUNT/1000000)) CCX, term $DEP_TERM) from coinbase remainder at h$PREV9_COINBASE_HEIGHT; submit at height $H1 (< $V9)"
RM1=$(fetch_remainder "$PREV9_COINBASE_HEIGHT") || fail "could not fetch coinbase remainder at h$PREV9_COINBASE_HEIGHT"
CBHEX1=${RM1% *}; GIDX1=${RM1##* }
DTX1=$("$INJECTOR" "$SPEND_KEY" "$VIEW_KEY" "$CBHEX1" "$GIDX1" "$DEP_AMOUNT" "$DEP_TERM" "$DEP_FEE" 2>/tmp/ccx-df-inj1.err)
[ -n "$DTX1" ] || fail "injector did not produce a pre-V9 deposit tx: $(cat /tmp/ccx-df-inj1.err)"
DTX1_HASH=$(grep -oE 'hash=[0-9a-f]{64}' /tmp/ccx-df-inj1.err | grep -oE '[0-9a-f]{64}')
SUB1=$(submit "$DTX1")
echo "   injector: $(cat /tmp/ccx-df-inj1.err)"
echo "   submit -> $SUB1"
echo "$SUB1" | grep -q '"status":"OK"' || fail "behavior #1: pre-V9 deposit was REJECTED by the daemon ($SUB1) — expected OK"

echo ">> wait for the pre-V9 deposit to CONFIRM (pool drains + a block is mined)"
S1=$(height); DEP1_CONFIRM_HEIGHT=""
for _ in $(seq 1 40); do
  P=$(pool); NH=$(height)
  if [ "${P:-1}" = 0 ] && [ "${NH:-0}" -gt "${S1:-0}" ]; then DEP1_CONFIRM_HEIGHT="$NH"; break; fi
  sleep 3
done
[ -n "$DEP1_CONFIRM_HEIGHT" ] || fail "behavior #1: pre-V9 deposit did not confirm (pool never drained)"
# Confirm it is really on-chain (not missed).
MISS=$(curl -s -X POST "http://127.0.0.1:$RPC1/gettransactions" -H 'Content-Type: application/json' \
        -d "{\"txs_hashes\":[\"$DTX1_HASH\"]}" 2>/dev/null | grep -oE '"missed_tx":\[[^]]*\]')
echo "$MISS" | grep -q '"missed_tx":\[\]' || fail "behavior #1: deposit tx $DTX1_HASH reported missing after mine ($MISS)"
B1_CREATE_HEIGHT="$S1"
echo "   BEHAVIOR #1 PASS: classical deposit ACCEPTED + confirmed (tx $DTX1_HASH, mined by height $DEP1_CONFIRM_HEIGHT)."

# ── Open the miner wallet (kept open via FIFO), reset/sync, and read the deposit it now owns. ───────
echo ">> [wallet] open miner wallet (FIFO-kept-open), reset to scan the deposit, read its unlock height"
mkfifo "$WFIFO"
exec 9<>"$WFIFO"
setsid "$WALLET" --testnet --daemon-host 127.0.0.1 --daemon-port "$RPC1" \
  --wallet-file "$WAL.wallet" --password x <"$WFIFO" >"$WOUT" 2>&1 &
WALPID=$!
printf 'reset\n' >&9
wait_for "$WOUT" 'Wallet reset was successful' 90 || fail "wallet did not finish reset/sync"
printf 'list_deposits\n' >&9
wait_for "$WOUT" '\|[[:space:]]*Locked[[:space:]]*' 30 \
  || fail "wallet did not list the confirmed (Locked) deposit. Transcript tail:
$(tail -20 "$WOUT")"
printf 'deposit_info 0\n' >&9
wait_for "$WOUT" 'Unlock Height:' 30 || true
UNLOCK_HEIGHT=$(grep -E 'Unlock Height:' "$WOUT" | grep -oE '[0-9]+' | tail -1)
echo "   wallet sees deposit id 0 (Locked); unlock height = ${UNLOCK_HEIGHT:-?}"

# ===================================================================================================
# Mine the chain past V9 AND past the deposit's unlock height, then confirm the wallet sees it matured.
# ===================================================================================================
TARGET=$((V9 + MINE_BUF))
[ "${UNLOCK_HEIGHT:-0}" -gt "$TARGET" ] 2>/dev/null && TARGET="$UNLOCK_HEIGHT"
echo
echo ">> mine past V9 and past unlock: wait for height >= $TARGET"
wait_height "$TARGET" 600 || fail "chain did not reach height $TARGET in time"
echo "   height=$(height) (>= V9=$V9, >= unlock=${UNLOCK_HEIGHT:-?})"

echo ">> [wallet] wait for deposit 0 to mature (status Unlocked) in the wallet view"
DEP_MATURE=0
for _ in $(seq 1 60); do
  printf 'deposit_info 0\n' >&9
  sleep 2
  if grep -qE 'Status:[[:space:]]*Unlocked' "$WOUT" 2>/dev/null; then DEP_MATURE=1; break; fi
done
[ "$DEP_MATURE" = 1 ] || fail "behavior #2 precondition: deposit 0 never reached Unlocked. Transcript tail:
$(tail -25 "$WOUT")"
echo "   deposit 0 is Unlocked (matured)"

# ===================================================================================================
# BEHAVIOR #2 — POST-V9: withdraw the pre-V9 deposit  => EXPECT ACCEPTED (existing deposit spendable)
# ===================================================================================================
echo
echo "================ BEHAVIOR #2: POST-V9 withdraw of pre-V9 deposit (expect ACCEPTED) ================"
HW=$(height)
echo ">> [wallet] withdraw deposit 0 at height $HW (>= $V9). The withdraw tx makes only term==0 outputs,"
echo "            so the CREATION freeze does NOT catch it — this is the Option-3 guarantee."
printf 'withdraw 0\n' >&9
wait_for "$WOUT" 'Money successfully sent, transaction hash: [0-9a-f]{64}' 60 \
  || fail "behavior #2: POST-V9 withdraw was NOT accepted by the wallet. Transcript tail:
$(tail -25 "$WOUT")"
WD_TXH=$(grep -oE 'Money successfully sent, transaction hash: [0-9a-f]{64}' "$WOUT" | tail -1 | grep -oE '[0-9a-f]{64}')
echo "   withdraw tx built+relayed: $WD_TXH"

echo ">> wait for the withdraw to CONFIRM (deposit 0 status becomes Withdrawn)"
WD_CONFIRMED=0
for _ in $(seq 1 60); do
  printf 'list_deposits\n' >&9
  sleep 2
  if grep -qE '\|[[:space:]]*Withdrawn[[:space:]]*' "$WOUT" 2>/dev/null; then WD_CONFIRMED=1; break; fi
done
[ "$WD_CONFIRMED" = 1 ] || fail "behavior #2: withdraw never confirmed (deposit 0 never became Withdrawn). Transcript tail:
$(tail -25 "$WOUT")"
B2_WITHDRAW_HEIGHT=$(height)
echo "   BEHAVIOR #2 PASS: POST-V9 withdraw of the pre-V9 deposit ACCEPTED + confirmed (status Withdrawn)."

# ===================================================================================================
# BEHAVIOR #3 — POST-V9: create a NEW classical deposit  => EXPECT REJECTED by the freeze
# ===================================================================================================
echo
echo "================= BEHAVIOR #3: POST-V9 NEW classical deposit creation (expect REJECTED) ================="
HR=$(height)
LOG_LINES_BEFORE=$(wc -l < "$D1LOG" 2>/dev/null | tr -d ' '); LOG_LINES_BEFORE=${LOG_LINES_BEFORE:-0}
echo ">> build a NEW classical deposit from coinbase remainder at h$POSTV9_COINBASE_HEIGHT; submit at height $HR (>= $V9)"
RM3=$(fetch_remainder "$POSTV9_COINBASE_HEIGHT") || fail "could not fetch coinbase remainder at h$POSTV9_COINBASE_HEIGHT"
CBHEX3=${RM3% *}; GIDX3=${RM3##* }
DTX3=$("$INJECTOR" "$SPEND_KEY" "$VIEW_KEY" "$CBHEX3" "$GIDX3" "$DEP_AMOUNT" "$DEP_TERM" "$DEP_FEE" 2>/tmp/ccx-df-inj3.err)
[ -n "$DTX3" ] || fail "injector did not produce a post-V9 deposit tx: $(cat /tmp/ccx-df-inj3.err)"
DTX3_HASH=$(grep -oE 'hash=[0-9a-f]{64}' /tmp/ccx-df-inj3.err | grep -oE '[0-9a-f]{64}')
SUB3=$(submit "$DTX3")
echo "   injector: $(cat /tmp/ccx-df-inj3.err)"
echo "   submit -> $SUB3  (expect NOT OK)"

# Assertion A: the daemon must NOT accept the relay.
echo "$SUB3" | grep -q '"status":"OK"' && fail "behavior #3: post-V9 classical deposit was ACCEPTED ($SUB3) — the freeze LEAKED!"

# Assertion B: the daemon must log the authoritative freeze line.
echo ">> wait for node1 to log 'classical deposit creation is frozen' (authoritative proof)"
FREEZE_LOGGED=0
for _ in $(seq 1 30); do
  if grep -qE 'classical deposit creation is frozen' "$D1LOG" 2>/dev/null; then FREEZE_LOGGED=1; break; fi
  sleep 1
done
[ "$FREEZE_LOGGED" = 1 ] || fail "behavior #3: node1 never logged the freeze line. Node1 log tail:
$(tail -20 "$D1LOG" 2>/dev/null)"
FREEZE_LINE=$(grep -E 'classical deposit creation is frozen' "$D1LOG" | tail -1)

# Assertion C: the rejected deposit must NOT confirm (it never entered the pool).
echo ">> verify the rejected deposit did NOT confirm (still missing after a few blocks)"
HSNAP=$(height); wait_height $((HSNAP + 2)) 90 || true
STILL_MISSING=$(curl -s -X POST "http://127.0.0.1:$RPC1/gettransactions" -H 'Content-Type: application/json' \
        -d "{\"txs_hashes\":[\"$DTX3_HASH\"]}" 2>/dev/null | grep -oE "\"missed_tx\":\[\"$DTX3_HASH\"\]")
[ -n "$STILL_MISSING" ] || fail "behavior #3: rejected deposit tx $DTX3_HASH unexpectedly appeared on-chain (freeze leaked!)"
B3_REJECT_HEIGHT="$HR"
echo "   BEHAVIOR #3 PASS: POST-V9 classical deposit creation REJECTED (daemon status not OK, freeze logged, tx never confirmed)."
echo "      daemon log: $FREEZE_LINE"

# ── Tear down the wallet session without blocking on its (possibly crashing) teardown. ─────────────
echo
echo ">> tear down wallet session (tolerate teardown segfault — verdicts already captured)"
printf 'exit\n' >&9
exec 9>&- 2>/dev/null || true
for _ in $(seq 1 5); do kill -0 "$WALPID" 2>/dev/null || break; sleep 1; done
kill -9 "$WALPID" 2>/dev/null || true
WALPID=""
echo ">> stop nodes"; pkill -x conceald 2>/dev/null || true

# ===================================================================================================
# SUMMARY
# ===================================================================================================
echo
echo "######## RESULT: PASS — all three behaviors verified ########"
echo "   V9 activation height (TESTNET_UPGRADE_HEIGHT_V9) : $V9"
echo "   #1 PRE-V9  create classical deposit  : ACCEPTED  (submitted height $B1_CREATE_HEIGHT, mined by $DEP1_CONFIRM_HEIGHT, unlock $UNLOCK_HEIGHT, term $DEP_TERM)"
echo "   #2 POST-V9 withdraw pre-V9 deposit   : ACCEPTED  (confirmed ~height $B2_WITHDRAW_HEIGHT, status Withdrawn)"
echo "   #3 POST-V9 create NEW classical dep. : REJECTED  (submitted height $B3_REJECT_HEIGHT)"
echo "       proof: $FREEZE_LINE"
echo ">> done"
exit 0
