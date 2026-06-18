#!/usr/bin/env bash
# Post-quantum testnet PoC runner (CIP-0001).
#
# Brings up an ISOLATED two-node testnet, mines blocks whose coinbase carries a post-quantum
# output, spends one such output with a version-3 PQ transaction via the pq_injector tool, and
# demonstrates that a same-nullifier double-spend is rejected.
#
# Why two nodes: the miner only starts after on_connection_synchronized(), which needs a peer
# whose top block we already have. Two nodes that peer ONLY with each other (exclusive) sync
# trivially at genesis, start mining, and never touch the real Conceal testnet.
#
# Prereqs: build conceald + pq_injector first (Release, -DBUILD_TESTS optional):
#   mkdir -p build && cd build && cmake .. -DCMAKE_BUILD_TYPE=Release && make -j conceald PqInjector
#
# Usage:  pqc/run-poc-testnet.sh /path/to/build/src
set -euo pipefail

BIN="${1:-build/src}"
CONCEALD="$BIN/conceald"
INJECTOR="$BIN/pq_injector"
ADDR="ccx7VAySMmU88LY8VZESSbQe7FLH7xsD1WtGXdiZCPaqNxp8Y1uQW4rJ8UCtPjyKeGKUdiyiG2CbUZoybVMUxmh47ckXGxYBFw"
RPC1=16600
N1=/tmp/ccx-n1
N2=/tmp/ccx-n2

rpc()  { curl -s -X POST "http://127.0.0.1:$RPC1/json_rpc" -H 'Content-Type: application/json' -d "$1"; }
info() { curl -s "http://127.0.0.1:$RPC1/getinfo"; }
height() { info | grep -oE '"height":[0-9]+' | grep -oE '[0-9]+'; }
hdr()  { rpc "{\"jsonrpc\":\"2.0\",\"id\":\"0\",\"method\":\"getblockheaderbyheight\",\"params\":{\"height\":$1}}"; }

echo ">> cleaning up any previous run"
pkill -x conceald 2>/dev/null || true
sleep 2
rm -rf "$N1" "$N2"; mkdir -p "$N1" "$N2"

echo ">> launching node 1 (miner) and node 2 (peer), isolated"
setsid "$CONCEALD" --testnet --data-dir "$N1" --no-console --hide-my-port --p2p-bind-ip 127.0.0.1 \
  --add-exclusive-node 127.0.0.1:15600 --rpc-bind-port "$RPC1" --p2p-bind-port 15500 \
  --log-level 2 --log-file "$N1/d.log" --start-mining "$ADDR" --mining-threads 4 \
  >/tmp/ccx-n1.out 2>&1 </dev/null &
setsid "$CONCEALD" --testnet --data-dir "$N2" --no-console --hide-my-port --p2p-bind-ip 127.0.0.1 \
  --add-exclusive-node 127.0.0.1:15500 --rpc-bind-port 16601 --p2p-bind-port 15600 \
  --log-level 0 --log-file "$N2/d.log" >/tmp/ccx-n2.out 2>&1 </dev/null &

echo ">> waiting for the coinbase of block 1 to unlock (height >= 13)"
while true; do H=$(height || true); [ "${H:-0}" -ge 13 ] 2>/dev/null && break; sleep 3; done
echo "   height=$H"

AMT=$(hdr 1 | grep -oE '"reward":[0-9]+' | grep -oE '[0-9]+')
echo ">> block 1 PQ coinbase amount = $AMT"

echo ">> [1] spend block 1's PQ output (fee 1000000)"
HEX=$("$INJECTOR" "$AMT" 1000000 0)
echo "   submit: $(curl -s -X POST http://127.0.0.1:$RPC1/sendrawtransaction \
  -H 'Content-Type: application/json' -d "{\"tx_as_hex\":\"$HEX\"}")"

echo ">> waiting for the PQ tx to be mined"
S=$(height); while true; do P=$(info | grep -oE '"tx_pool_size":[0-9]+' | grep -oE '[0-9]+'); H=$(height); \
  { [ "${P:-1}" = 0 ] && [ "${H:-0}" -gt "${S:-0}" ]; } && break; sleep 2; done
echo "   mined; tx_count=$(info | grep -oE '"tx_count":[0-9]+' | grep -oE '[0-9]+')"

echo ">> [2] DOUBLE-SPEND: distinct tx (fee 2000000), SAME nullifier -> must be rejected"
HEX2=$("$INJECTOR" "$AMT" 2000000 0)
echo "   submit: $(curl -s -X POST http://127.0.0.1:$RPC1/sendrawtransaction \
  -H 'Content-Type: application/json' -d "{\"tx_as_hex\":\"$HEX2\"}")"
echo "   tx_pool_size=$(info | grep -oE '"tx_pool_size":[0-9]+' | grep -oE '[0-9]+') (expect 0)"
echo "   tx_count=$(info | grep -oE '"tx_count":[0-9]+' | grep -oE '[0-9]+') (expect 1 — double-spend not mined)"

echo ">> done. Stop with: pkill -x conceald"
