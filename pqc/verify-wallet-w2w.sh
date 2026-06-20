#!/usr/bin/env bash
# A/B verification for WALLET↔WALLET post-quantum transfers (CIP-0001).
#
# Two separate concealwallet wallets on the isolated 2-node testnet:
#   [B] pq_address            -> B publishes its deterministic PQ receive address (ctp…)
#   [A] pq_transfer <B-addr>  -> A (holding the bootstrap coinbase PQ outputs) BUILDS+RELAYS a v3 PQ
#                                tx whose output is KEM-encapsulated to B's address      => accepted
#   (wait for the spend to be mined so the daemon indexes B's new output)
#   [B] pq_receive            -> B SCANS with its OWN seed-derived KEM secret and SEES the output
# Proves real wallet→wallet PQ value transfer + recipient-side scanning (not just self-spend).
#
# Determinism design — B is opened EXACTLY ONCE and kept open the whole time (no fragile reopen):
#   * Earlier versions generated B, exited, then RE-OPENED B for pq_receive. That reopen was doubly
#     fragile: (1) "--generate-new-wallet $WB" writes "$WB.wallet" but "--wallet-file $WB" passed the
#     bare path straight to WalletGreen::load, which read EOF and threw "Failed to read wallet version:
#     Wrong version"; and (2) even with the path fixed, WalletGreen::load runs a full sync-on-open whose
#     latency grows with chain height — on a tall/long-running chain the reopened session can hang before
#     it ever accepts pq_receive. We sidestep BOTH by driving B's single session through a FIFO: open B
#     once at low height (fast sync), publish its address, keep it open while A sends + the spend mines,
#     then feed pq_receive into the SAME live session.
#   * pq_receive is sync-INDEPENDENT: it scans the daemon's get_pq_outputs RPC with B's seed-derived KEM
#     secret, so once A's output is mined B sees it immediately regardless of B's own sync position.
#   * A's pq_transfer relays BEFORE its session teardown. A pre-existing System/WalletLegacy teardown
#     flake can segfault concealwallet during "exit"; that is AFTER "PQ tx relayed: ... status=OK" is
#     printed and AFTER the tx is in the pool, so we gate on status=OK from A's captured output and
#     tolerate a non-zero/crashing A exit (the relayed tx still mines).
#   * The wait for B's output is an EXPLICIT poll of get_pq_outputs at the post-fee amount, so the
#     receive step never races ahead of the mine.
#
# Usage:  pqc/verify-wallet-w2w.sh /path/to/build/src
set -uo pipefail

BIN="${1:-build/src}"
CONCEALD="$BIN/conceald"
WALLET="$BIN/concealwallet"
ADDR="ccx7VAySMmU88LY8VZESSbQe7FLH7xsD1WtGXdiZCPaqNxp8Y1uQW4rJ8UCtPjyKeGKUdiyiG2CbUZoybVMUxmh47ckXGxYBFw"
RPC1=16600
N1=/tmp/ccx-w1
N2=/tmp/ccx-w2
WA=/tmp/ccx-wa
WB=/tmp/ccx-wb
BFIFO=/tmp/ccx-wb.fifo       # command channel that keeps B's single session open
AOUT=/tmp/ccx-w2w-a.out      # A's pq_transfer transcript (segfault-safe relay check)
BOUT=/tmp/ccx-w2w-b.out      # B's session transcript (address + pass/fail assertion)
# A spends one PQ_TESTNET_COINBASE_AMOUNT (100000) output with fee 1000, so the output A sends to B is
# 99000 atomic units = "0.099000" at 6 display decimals. Coinbase outputs (0.100000) are visible to ANY
# wallet via the shared fixed testnet KEM key, so we assert specifically on the post-fee amount: only an
# output KEM-encapsulated to B's OWN seed-derived key (i.e. the one A actually sent to B) carries it.
RECV_AMOUNT="0.099000"

WALPID=""

wal() { "$WALLET" --testnet --daemon-host 127.0.0.1 --daemon-port "$RPC1" "$@" 2>&1; }
height() { curl -s "http://127.0.0.1:$RPC1/getinfo" | grep -oE '"height":[0-9]+' | grep -oE '[0-9]+'; }
clean() { grep -vE 'Height [0-9]|loading|synchroniz|Wallet sync|Mnemonic|Container|Closing|Wallet closed|Saving|generated\.|wallet again|^\s*$|ConcealWallet is an|/!\\|Conceal Wallet v|testnet mode|Wallet Address|Private |New wallet added|Use .help|Always use|\*\*\*|Connected'; }
# Count PQ outputs the daemon indexes at the POST-FEE amount (99000 = A's A->B output denomination).
# get_pq_outputs enumerates per requested amount, so we ask only for 99000 — this gates specifically on
# A's spend being mined (coinbase outputs are a different amount and never satisfy this gate).
pq_out_count() {
  curl -s -X POST "http://127.0.0.1:$RPC1/json_rpc" \
    -H 'Content-Type: application/json' \
    -d '{"jsonrpc":"2.0","id":"0","method":"get_pq_outputs","params":{"amounts":[99000]}}' 2>/dev/null \
    | grep -oE '"global_index"' | wc -l | tr -d ' '
}

cleanup() {
  # Close B's session if still open, then nodes. exec 9>&- closes the FIFO writer so B's stdin sees EOF.
  exec 9>&- 2>/dev/null || true
  [ -n "$WALPID" ] && kill "$WALPID" 2>/dev/null || true
  pkill -x conceald 2>/dev/null || true
  rm -f "$BFIFO" 2>/dev/null || true
}
trap cleanup EXIT

fail() { echo "   FAIL: $*"; exit 1; }

# Block until a regex appears in a file (bounded), so we never feed the next command before the prompt
# has consumed the previous one's output.
wait_for() { # <file> <regex> <max_seconds>
  local f="$1" re="$2" max="$3" i=0
  while [ "$i" -lt "$max" ]; do
    grep -qE "$re" "$f" 2>/dev/null && return 0
    sleep 1; i=$((i+1))
  done
  return 1
}

echo ">> cleanup"; pkill -x conceald 2>/dev/null || true; sleep 2
rm -rf "$N1" "$N2" "$WA"* "$WB"* "$AOUT" "$BOUT" "$BFIFO"; mkdir -p "$N1" "$N2"

echo ">> launch 2 isolated testnet nodes (node1 mines)"
setsid "$CONCEALD" --testnet --data-dir "$N1" --no-console --hide-my-port --p2p-bind-ip 127.0.0.1 \
  --add-exclusive-node 127.0.0.1:15600 --rpc-bind-port "$RPC1" --p2p-bind-port 15500 \
  --log-level 1 --log-file "$N1/d.log" --start-mining "$ADDR" --mining-threads 4 \
  >/tmp/ccx-w1.out 2>&1 </dev/null &
setsid "$CONCEALD" --testnet --data-dir "$N2" --no-console --hide-my-port --p2p-bind-ip 127.0.0.1 \
  --add-exclusive-node 127.0.0.1:15500 --rpc-bind-port 16601 --p2p-bind-port 15600 \
  --log-level 0 --log-file "$N2/d.log" >/tmp/ccx-w2.out 2>&1 </dev/null &

echo ">> wait for PQ coinbase to unlock (height >= 17)"
while true; do H=$(height || true); [ "${H:-0}" -ge 17 ] 2>/dev/null && break; sleep 3; done
echo "   height=$H"

echo ">> [B] open wallet B ONCE (kept open via FIFO) and read its PQ address"
mkfifo "$BFIFO"
# Keep the FIFO open for writing on fd 9 so B's stdin does not see EOF between commands.
exec 9<>"$BFIFO"
setsid "$WALLET" --testnet --daemon-host 127.0.0.1 --daemon-port "$RPC1" \
  --generate-new-wallet "$WB" --password x <"$BFIFO" >"$BOUT" 2>&1 &
WALPID=$!

# Ask B for its PQ address and wait for it to appear.
printf 'pq_address\n' >&9
wait_for "$BOUT" 'ctp[0-9A-Za-z]{20,}' 60 || fail "B did not print a PQ address (session did not come up)"
B_ADDR=$(grep -oE 'ctp[0-9A-Za-z]{20,}' "$BOUT" | head -1)
echo "   B PQ address = ${B_ADDR:-<none>}"
[ -n "${B_ADDR:-}" ] || fail "no PQ address from B"

echo ">> record PQ-output count before A spends (deterministic mine gate)"
PRE=$(pq_out_count); echo "   pq_outputs(99000) before = $PRE"

echo ">> [A] generate wallet A + pq_transfer to B's PQ address (ring 4, fee 1000)"
# Capture A's transcript so the relay is confirmed from status=OK even if A segfaults on exit teardown.
# A's concealwallet process can also hit the pre-existing System dispatcher flake
# ("Dispatcher::dispatch, read(remoteSpawnEvent) failed, result=11") and abort BEFORE relaying. That
# abort is non-deterministic, so retry on a fresh A wallet until the relay is confirmed (status=OK). Each
# attempt spends a distinct coinbase PQ output, so a retry does not double-send the same output.
A_RELAYED=0
for attempt in 1 2 3 4 5; do
  rm -rf "$WA"*
  printf "pq_transfer %s 4 1000\nexit\n" "$B_ADDR" | wal --generate-new-wallet "$WA" --password x >"$AOUT" 2>&1 || true
  if grep -q 'PQ tx relayed: .* status=OK' "$AOUT"; then A_RELAYED=1; break; fi
  echo "   attempt $attempt: A did not relay (dispatcher/teardown flake); retrying"
  sleep 2
done
clean <"$AOUT" || true
[ "$A_RELAYED" = 1 ] || fail "A did not relay the PQ tx after retries (no 'status=OK')"
echo "   A relay confirmed (status=OK)"

echo ">> wait for the A->B spend to be mined (poll get_pq_outputs until it grows)"
S=$(height)
for _ in $(seq 1 60); do
  NOW=$(pq_out_count)
  H=$(height)
  { [ "${NOW:-0}" -gt "${PRE:-0}" ] && [ "${H:-0}" -ge $((S+1)) ]; } 2>/dev/null && break
  sleep 3
done
echo "   height=$H  pq_outputs(99000) now=$NOW (was $PRE)"
[ "${NOW:-0}" -gt "${PRE:-0}" ] || fail "A's PQ output never appeared in get_pq_outputs (not mined)"

echo ">> [B] pq_receive in the SAME still-open session (scan with B's own KEM secret)"
printf 'pq_receive\npq_balance mine\n' >&9
# Wait for B to list the post-fee output. The transcript ($BOUT) IS the verdict — it is complete the
# moment this line appears, independent of whether B's session then shuts down cleanly.
wait_for "$BOUT" "global_index=[0-9]+ amount=$RECV_AMOUNT " 60 || true

# Close B's session, but NEVER block on its teardown: B can hit the pre-existing System dispatcher flake
# ("read(remoteSpawnEvent) failed") during "exit" and hang. We already have the receipt, so give exit a
# short grace period then SIGKILL — a blocking `wait` here would otherwise hang the whole verification.
printf 'exit\n' >&9
exec 9>&- 2>/dev/null || true
for _ in $(seq 1 5); do kill -0 "$WALPID" 2>/dev/null || break; sleep 1; done
kill -9 "$WALPID" 2>/dev/null || true
WALPID=""

# Fallback: if B's live session aborted on the dispatcher flake BEFORE printing the receipt, do ONE
# short fresh pq_receive. pq_receive is a pure get_pq_outputs RPC scan, so a brief fresh B session
# (opened at the still-low chain height — sync-on-open is fast here) reproduces it deterministically.
# We reopen with the explicit ".wallet" path B was generated under (belt-and-suspenders vs the bare-arg
# load regression the C++ fix also addresses).
if ! grep -qE "global_index=[0-9]+ amount=$RECV_AMOUNT " "$BOUT"; then
  echo "   B's live pq_receive did not show the output (session flake?); one fresh-session fallback scan"
  printf 'pq_receive\nexit\n' | wal --wallet-file "$WB.wallet" --password x >>"$BOUT" 2>&1 || true
fi

echo ">> stop nodes"; pkill -x conceald 2>/dev/null || true

# B's seed-derived scan also sees the shared testnet coinbase key (amount 0.100000), so a generic
# "received some output" check would pass even with NO transfer. Assert specifically on the post-fee
# amount 0.099000 — an output only B's OWN seed-derived key can decapsulate, i.e. the one A sent to B.
if grep -qE "global_index=[0-9]+ amount=$RECV_AMOUNT " "$BOUT"; then
  echo ">> PASS: B received the PQ output A sent (post-fee amount $RECV_AMOUNT):"
  grep -E "global_index=[0-9]+ amount=$RECV_AMOUNT |Received PQ outputs:" "$BOUT" | sed 's/^/     /'
  echo ">> done"
  exit 0
else
  echo ">> B session transcript (cleaned):"; clean <"$BOUT" | sed 's/^/     /'
  fail "B did not list the received PQ output at the post-fee amount $RECV_AMOUNT"
fi
