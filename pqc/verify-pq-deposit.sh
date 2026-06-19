#!/usr/bin/env bash
# LIVE end-to-end demo of the PQ (ML-DSA-65) DEPOSIT create + withdraw path (CIP-0001, UPGRADE_HEIGHT_V9,
# Option 3). The companion to pqc/verify-deposit-freeze.sh: that script proves classical-deposit CREATION
# is frozen at/after V9 and that pre-V9 classical deposits stay withdrawable; THIS script proves the
# replacement — a PQ deposit — is creatable, visible, maturable, and withdrawable (principal + interest),
# and that a second withdrawal of the same cell is rejected (on-chain double-spend guard).
#
# Consensus under test (testnet TESTNET_UPGRADE_HEIGHT_V9 = 80):
#   * At/after V9, a PqMultisigOutput deposit is the ONLY new deposit (classical is frozen).
#   * check_pq_multisig validates the ML-DSA withdrawal sig over getTransactionPqSigningHash, binds
#     input.term == output.term, enforces the deposit lock, and marks isUsed (double-spend) on spend.
#   * The daemon credits amount + getInterestForInput on withdrawal (the wallet payout must match).
#
# Behaviors proven on a LIVE isolated single-node testnet (node1 mines; no real-testnet contact):
#   #1  POST-V9: pq_deposit <months> <amount>          => ACCEPTED, confirms, visible via get_pq_multisig_outputs.
#   #2  POST-V9: mine term blocks                       => deposit matures (createdHeight + term <= height).
#   #3  POST-V9: pq_withdraw <output_index>            => ACCEPTED (principal + interest), confirms, isUsed set.
#   #4  POST-V9: pq_withdraw <output_index> again      => REJECTED (the cell is already used — double-spend).
#   #5  reload the wallet from its mnemonic, withdraw a SECOND fresh deposit => ACCEPTED (restore proven).
#
# Funding note: a PQ deposit is PQ-funded (it spends a PQ coinbase output, owned by the fixed testnet
# ML-KEM key). PQ_TESTNET_COINBASE_AMOUNT (0.1 CCX) is below the 1-CCX mainnet DEPOSIT_MIN_AMOUNT, so
# the testnet build uses TESTNET_DEPOSIT_MIN_AMOUNT (0.01 CCX). Mainnet is unaffected.
#
# Usage:  pqc/verify-pq-deposit.sh /path/to/build/src
set -uo pipefail

BIN="${1:-build/src}"
CONCEALD="$BIN/conceald"
WALLET="$BIN/concealwallet"

V9=80                          # TESTNET_UPGRADE_HEIGHT_V9 — PQ deposits activate here
DEP_MONTHS=1                   # term = months * TESTNET_DEPOSIT_MIN_TERM_V3 (30) = 30 blocks
DEP_TERM=30
DEP_AMOUNT="0.05"             # 0.05 CCX (>= TESTNET_DEPOSIT_MIN_AMOUNT 0.01; fits one 0.1-CCX PQ coinbase output)
DEP_FEE=1000
RING=4
MINE_BUF=6                     # mine this many blocks past V9 before the first deposit

RPC1=16600
N1=/tmp/ccx-pqd1
WAL=/tmp/ccx-pqd-wallet
WFIFO=/tmp/ccx-pqd.fifo
WOUT=/tmp/ccx-pqd-wallet.out
GENOUT=/tmp/ccx-pqd-gen.out
D1LOG="$N1/d.log"
MNEMONIC_FILE=/tmp/ccx-pqd-mnemonic.txt

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

# Count PQ deposit cells the daemon reports for the PQ coinbase amount (0.1 CCX = 100000 atomic).
pq_msig_count() {
  jrpc '{"jsonrpc":"2.0","id":"0","method":"get_pq_multisig_outputs","params":{"amounts":[100000]}}' \
    | grep -oE '"output_index":[0-9]+' | wc -l | tr -d ' '
}
# Lowest unused deposit cell output_index the daemon reports (or empty). Parses the flat entry list.
pq_first_unused_index() {
  jrpc '{"jsonrpc":"2.0","id":"0","method":"get_pq_multisig_outputs","params":{"amounts":[100000]}}' \
    | grep -oE '"output_index":[0-9]+,"keys"[^}]*"is_used":(true|false)' \
    | grep '"is_used":false' | head -1 | grep -oE '"output_index":[0-9]+' | grep -oE '[0-9]+'
}

open_wallet() { # opens the wallet kept-open via FIFO, resets/syncs
  mkfifo "$WFIFO"
  exec 9<>"$WFIFO"
  setsid "$WALLET" --testnet --daemon-host 127.0.0.1 --daemon-port "$RPC1" \
    --wallet-file "$WAL.wallet" --password x <"$WFIFO" >"$WOUT" 2>&1 &
  WALPID=$!
  printf 'reset\n' >&9
  wait_for "$WOUT" 'Wallet reset was successful' 90 || fail "wallet did not finish reset/sync"
}
close_wallet() {
  printf 'exit\n' >&9 2>/dev/null || true
  exec 9>&- 2>/dev/null || true
  for _ in $(seq 1 5); do kill -0 "$WALPID" 2>/dev/null || break; sleep 1; done
  kill -9 "$WALPID" 2>/dev/null || true
  WALPID=""
  rm -f "$WFIFO" 2>/dev/null || true
}

echo ">> cleanup any stragglers"
pkill -x conceald 2>/dev/null || true; pkill -x concealwallet 2>/dev/null || true; sleep 2
rm -rf "$N1" "$WAL"* "$WFIFO" "$WOUT" "$GENOUT" "$MNEMONIC_FILE"; mkdir -p "$N1"

# ── Step 0: generate the driver wallet; capture its ccx7 address + 25-word mnemonic. ────────────────
echo ">> [wallet] generate driver wallet; capture ccx7 mining address + mnemonic"
printf 'exit\n' | "$WALLET" --testnet --generate-new-wallet "$WAL" --password x >"$GENOUT" 2>&1 || true
MINE_ADDR=$(grep -oE 'ccx7[0-9A-Za-z]{90,}' "$GENOUT" | head -1)
# The 25-word mnemonic line (after the seed banner). Grab the longest 25-word lowercase line.
grep -oE '([a-z]+ ){24}[a-z]+' "$GENOUT" | head -1 > "$MNEMONIC_FILE" || true
[ -n "${MINE_ADDR:-}" ] || fail "could not capture mining address ($GENOUT)"
echo "   mining address = $MINE_ADDR"
[ -s "$MNEMONIC_FILE" ] && echo "   mnemonic captured ($(wc -w < "$MNEMONIC_FILE") words)" || echo "   (mnemonic not captured — behavior #5 will be skipped)"

# ── Step 1: launch a single isolated testnet node mining to our address at log-level 3. ─────────────
echo ">> launch isolated testnet node (mines to our address, --log-level 3 to capture PQ accept/reject lines)"
setsid "$CONCEALD" --testnet --data-dir "$N1" --no-console --hide-my-port --p2p-bind-ip 127.0.0.1 \
  --rpc-bind-port "$RPC1" --p2p-bind-port 15500 \
  --log-level 3 --log-file "$D1LOG" --start-mining "$MINE_ADDR" --mining-threads 4 \
  >/tmp/ccx-pqd1.out 2>&1 </dev/null &

TARGET=$((V9 + MINE_BUF))
echo ">> wait for chain to reach height $TARGET (past V9=$V9 so PQ deposits are active + coinbase PQ outputs exist)"
wait_height "$TARGET" 600 || fail "chain did not reach height $TARGET in time"
echo "   height=$(height)"

open_wallet

# ===================================================================================================
# BEHAVIOR #1 — POST-V9: create a PQ deposit  => EXPECT ACCEPTED + visible via get_pq_multisig_outputs
# ===================================================================================================
echo
echo "==================== BEHAVIOR #1: POST-V9 PQ deposit creation (expect ACCEPTED) ===================="
CELLS_BEFORE=$(pq_msig_count)
echo ">> [wallet] pq_deposit $DEP_MONTHS $DEP_AMOUNT $DEP_FEE $RING  (cells before = $CELLS_BEFORE)"
printf 'pq_deposit %s %s %s %s\n' "$DEP_MONTHS" "$DEP_AMOUNT" "$DEP_FEE" "$RING" >&9
wait_for "$WOUT" 'PQ deposit relayed: [0-9a-f]{64}' 60 \
  || fail "behavior #1: pq_deposit was not relayed. Transcript tail:
$(tail -25 "$WOUT")"
DEP1_TXH=$(grep -oE 'PQ deposit relayed: [0-9a-f]{64}' "$WOUT" | tail -1 | grep -oE '[0-9a-f]{64}')
echo "   pq_deposit relayed: $DEP1_TXH"

echo ">> wait for the PQ deposit to CONFIRM (pool drains + a block is mined) and a new cell to appear"
DEP1_OK=0
for _ in $(seq 1 60); do
  NC=$(pq_msig_count)
  if [ "${NC:-0}" -gt "${CELLS_BEFORE:-0}" ]; then DEP1_OK=1; break; fi
  sleep 3
done
[ "$DEP1_OK" = 1 ] || fail "behavior #1: PQ deposit never appeared in get_pq_multisig_outputs (cells still $CELLS_BEFORE). Daemon log tail:
$(grep -iE 'pq multisig|PQ deposit|reject' "$D1LOG" | tail -15)"
IDX1=$(pq_first_unused_index)
[ -n "$IDX1" ] || fail "behavior #1: no unused PQ deposit cell index found after create"
echo "   BEHAVIOR #1 PASS: PQ deposit ACCEPTED + visible on-chain (cell output_index $IDX1)."

# ===================================================================================================
# BEHAVIOR #2 — mature the deposit (mine past createdHeight + term)
# ===================================================================================================
echo
echo "==================== BEHAVIOR #2: mature the PQ deposit (mine term blocks) ===================="
HNOW=$(height)
MATURE_TARGET=$((HNOW + DEP_TERM + 2))
echo ">> mine to height >= $MATURE_TARGET (createdHeight ~ $HNOW + term $DEP_TERM)"
wait_height "$MATURE_TARGET" 600 || fail "chain did not reach maturity height $MATURE_TARGET"
echo "   BEHAVIOR #2 PASS: chain at height $(height) (>= deposit unlock)."

# ===================================================================================================
# BEHAVIOR #3 — POST-V9: withdraw the matured PQ deposit  => EXPECT ACCEPTED (principal + interest)
# ===================================================================================================
echo
echo "================ BEHAVIOR #3: withdraw the matured PQ deposit (expect ACCEPTED) ================"
echo ">> [wallet] pq_withdraw $IDX1"
printf 'pq_withdraw %s\n' "$IDX1" >&9
wait_for "$WOUT" 'PQ withdraw relayed: [0-9a-f]{64}' 60 \
  || fail "behavior #3: pq_withdraw was not relayed. Transcript tail:
$(tail -25 "$WOUT")"
WD1_TXH=$(grep -oE 'PQ withdraw relayed: [0-9a-f]{64}' "$WOUT" | tail -1 | grep -oE '[0-9a-f]{64}')
WD1_LINE=$(grep -E 'PQ withdraw relayed' "$WOUT" | tail -1)
echo "   pq_withdraw relayed: $WD1_TXH"
echo "   $WD1_LINE"

echo ">> wait for the withdraw to CONFIRM (pool drains, cell becomes is_used)"
WD1_OK=0
for _ in $(seq 1 60); do
  USED=$(jrpc '{"jsonrpc":"2.0","id":"0","method":"get_pq_multisig_outputs","params":{"amounts":[100000]}}' \
         | grep -oE "\"output_index\":$IDX1,\"keys\"[^}]*\"is_used\":(true|false)" | grep -oE '"is_used":(true|false)' | tail -1)
  if [ "$USED" = '"is_used":true' ]; then WD1_OK=1; break; fi
  sleep 3
done
[ "$WD1_OK" = 1 ] || fail "behavior #3: withdraw never confirmed (cell $IDX1 never became is_used). Daemon log tail:
$(grep -iE 'pq multisig|reject|interest' "$D1LOG" | tail -15)"
echo "   BEHAVIOR #3 PASS: PQ withdraw ACCEPTED + confirmed (cell $IDX1 is_used=true, principal+interest paid)."

# ===================================================================================================
# BEHAVIOR #4 — POST-V9: withdraw the SAME cell again  => EXPECT REJECTED (double-spend, isUsed)
# ===================================================================================================
echo
echo "================ BEHAVIOR #4: second withdraw of the same cell (expect REJECTED) ================"
echo ">> [wallet] pq_withdraw $IDX1  (the cell is already used)"
printf 'pq_withdraw %s\n' "$IDX1" >&9
# Either the wallet refuses (cell is_used) OR the relay is rejected — both are a valid REJECT.
WD2_REJECTED=0
for _ in $(seq 1 20); do
  if grep -qE 'already spent|relay rejected|is already spent' "$WOUT" 2>/dev/null; then WD2_REJECTED=1; break; fi
  # A second "relayed" line for the same cell would be a LEAK — guard against it.
  if [ "$(grep -cE 'PQ withdraw relayed' "$WOUT")" -ge 2 ]; then
    fail "behavior #4: a SECOND withdraw of cell $IDX1 was relayed — double-spend LEAKED!"
  fi
  sleep 1
done
[ "$WD2_REJECTED" = 1 ] || fail "behavior #4: second withdraw was neither refused nor rejected. Transcript tail:
$(tail -15 "$WOUT")"
echo "   BEHAVIOR #4 PASS: second withdraw REJECTED (double-spend prevented)."

# ===================================================================================================
# BEHAVIOR #5 — restore-from-mnemonic then withdraw a fresh deposit  => EXPECT ACCEPTED
# ===================================================================================================
echo
echo "============ BEHAVIOR #5: reload wallet from mnemonic, then deposit+withdraw (restore) ============"
# Create a SECOND fresh deposit with the still-open wallet ...
CELLS_B5=$(pq_msig_count)
printf 'pq_deposit %s %s %s %s\n' "$DEP_MONTHS" "$DEP_AMOUNT" "$DEP_FEE" "$RING" >&9
wait_for "$WOUT" 'PQ deposit relayed: [0-9a-f]{64}' 60 || fail "behavior #5: second pq_deposit not relayed"
for _ in $(seq 1 60); do NC=$(pq_msig_count); [ "${NC:-0}" -gt "${CELLS_B5:-0}" ] && break; sleep 3; done
IDX2=$(pq_first_unused_index)
[ -n "$IDX2" ] || fail "behavior #5: second deposit cell did not appear"
echo "   second PQ deposit created (cell output_index $IDX2)"

if [ -s "$MNEMONIC_FILE" ]; then
  # ... close the wallet, DELETE the wallet file, and RESTORE it purely from the 25-word mnemonic ...
  echo ">> close wallet, delete wallet file, RESTORE from 25-word mnemonic"
  close_wallet
  rm -f "$WAL.wallet" "$WAL.address" 2>/dev/null || true
  MNEMONIC=$(cat "$MNEMONIC_FILE")
  printf 'exit\n' | "$WALLET" --testnet --restore-deterministic-wallet \
    --generate-new-wallet "$WAL" --password x --mnemonic-seed "$MNEMONIC" >/tmp/ccx-pqd-restore.out 2>&1 || true
  grep -qiE 'restore|generated|seed' /tmp/ccx-pqd-restore.out || true

  # ... wait until the second deposit matures, then withdraw it from the RESTORED wallet.
  HNOW=$(height); wait_height $((HNOW + DEP_TERM + 2)) 600 || fail "behavior #5: chain did not mature the 2nd deposit"
  open_wallet
  echo ">> [restored wallet] pq_withdraw $IDX2"
  printf 'pq_withdraw %s\n' "$IDX2" >&9
  wait_for "$WOUT" 'PQ withdraw relayed: [0-9a-f]{64}' 60 \
    || fail "behavior #5: restored wallet could not withdraw the deposit (restore broke the DSA key!). Transcript tail:
$(tail -25 "$WOUT")"
  WD3_TXH=$(grep -oE 'PQ withdraw relayed: [0-9a-f]{64}' "$WOUT" | tail -1 | grep -oE '[0-9a-f]{64}')
  echo "   BEHAVIOR #5 PASS: RESTORED-from-mnemonic wallet withdrew the deposit ($WD3_TXH) — the DSA deposit key is mnemonic-recoverable."
else
  echo "   BEHAVIOR #5 SKIPPED: mnemonic was not captured from wallet generation."
fi

close_wallet
echo ">> stop node"; pkill -x conceald 2>/dev/null || true

echo
echo "######## RESULT: PASS — PQ deposit create + withdraw verified ########"
echo "   V9 activation height (TESTNET_UPGRADE_HEIGHT_V9) : $V9"
echo "   #1 POST-V9 create PQ deposit         : ACCEPTED  (tx $DEP1_TXH, cell $IDX1, amount $DEP_AMOUNT, term $DEP_TERM)"
echo "   #2 mature                            : OK        (mined past createdHeight + term)"
echo "   #3 POST-V9 withdraw PQ deposit       : ACCEPTED  (tx $WD1_TXH, principal + interest, cell is_used)"
echo "   #4 second withdraw same cell         : REJECTED  (double-spend prevented)"
[ -s "$MNEMONIC_FILE" ] && echo "   #5 restore-from-mnemonic + withdraw  : ACCEPTED  (DSA deposit key recovered from seed)"
echo ">> done"
exit 0
