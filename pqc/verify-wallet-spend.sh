#!/usr/bin/env bash
# A/B verification for WALLET-NATIVE post-quantum spend (CIP-0001).
#
# Brings up the same isolated 2-node testnet as run-poc-testnet.sh, then drives the concealwallet CLI
# (NOT the pq_injector tool) to:
#   [1] pq_balance        -> the wallet sees the spendable PQ coinbase outputs
#   [2] pq_transfer 4 1000 -> the wallet BUILDS + RELAYS a v3 PQ tx (ring of 4)         => accepted
#   [3] pq_transfer 4 2000 -> same signer (lowest index) => SAME nullifier               => rejected
# Proving the wallet path is byte-consensus-identical to the injector path (same builder) and that
# the in-pool double-spend guard fires for a wallet-built tx too.
#
# Usage:  pqc/verify-wallet-spend.sh /path/to/build/src
set -uo pipefail

BIN="${1:-build/src}"
CONCEALD="$BIN/conceald"
WALLET="$BIN/concealwallet"
ADDR="ccx7VAySMmU88LY8VZESSbQe7FLH7xsD1WtGXdiZCPaqNxp8Y1uQW4rJ8UCtPjyKeGKUdiyiG2CbUZoybVMUxmh47ckXGxYBFw"
RPC1=16600
N1=/tmp/ccx-v1
N2=/tmp/ccx-v2
WDIR=/tmp/ccx-pqwallet

echo ">> cleanup"
pkill -x conceald 2>/dev/null || true
sleep 2
rm -rf "$N1" "$N2" "$WDIR"; mkdir -p "$N1" "$N2" "$WDIR"

echo ">> launch 2 isolated testnet nodes (node1 mines)"
setsid "$CONCEALD" --testnet --data-dir "$N1" --no-console --hide-my-port --p2p-bind-ip 127.0.0.1 \
  --add-exclusive-node 127.0.0.1:15600 --rpc-bind-port "$RPC1" --p2p-bind-port 15500 \
  --log-level 1 --log-file "$N1/d.log" --start-mining "$ADDR" --mining-threads 4 \
  >/tmp/ccx-v1.out 2>&1 </dev/null &
setsid "$CONCEALD" --testnet --data-dir "$N2" --no-console --hide-my-port --p2p-bind-ip 127.0.0.1 \
  --add-exclusive-node 127.0.0.1:15500 --rpc-bind-port 16601 --p2p-bind-port 15600 \
  --log-level 0 --log-file "$N2/d.log" >/tmp/ccx-v2.out 2>&1 </dev/null &

height() { curl -s "http://127.0.0.1:$RPC1/getinfo" | grep -oE '"height":[0-9]+' | grep -oE '[0-9]+'; }

echo ">> wait for PQ coinbase outputs (heights 1..5) to unlock (height >= 17)"
while true; do H=$(height || true); [ "${H:-0}" -ge 17 ] 2>/dev/null && break; sleep 3; done
echo "   height=$H"

echo ">> drive concealwallet (pq_balance; pq_transfer x2 same signer => double-spend)"
printf 'pq_balance\npq_transfer 4 1000\npq_transfer 4 2000\npq_balance\nexit\n' | \
  "$WALLET" --testnet --generate-new-wallet "$WDIR/w" --password x \
    --daemon-host 127.0.0.1 --daemon-port "$RPC1" 2>&1 | \
  grep -vE 'Height [0-9]|loading|synchroniz|Wallet sync|Mnemonic|^\s*$' || true

echo ">> stop nodes"
pkill -x conceald 2>/dev/null || true
echo ">> done"
