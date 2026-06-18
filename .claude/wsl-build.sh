#!/usr/bin/env bash
# Sync the local (Mac) conceal-core working tree to the WSL build host and build/test there.
# The Mac is Apple Silicon and cannot build this repo (arm64 portability gaps); WSL = x86_64 Ubuntu.
#
# Usage:
#   .claude/wsl-build.sh            # sync + build (incremental)
#   .claude/wsl-build.sh test       # sync + build + ctest
#   .claude/wsl-build.sh clean      # sync + wipe build/ + configure + build
#   .claude/wsl-build.sh shell      # ssh into the host at the repo
set -euo pipefail

HOST="${CCX_WSL_HOST:-100.100.90.103}"
REMOTE_DIR="${CCX_WSL_DIR:-conceal-core}"
JOBS="${CCX_JOBS:-16}"
LOCAL_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)/"
CMD="${1:-build}"

sync() {
  echo ">> sync $LOCAL_DIR -> $HOST:$REMOTE_DIR"
  rsync -az --delete --exclude 'build/' --exclude '.DS_Store' --exclude 'pqc/ccx-pqc/target/' "$LOCAL_DIR" "$HOST:$REMOTE_DIR/"
}

case "$CMD" in
  shell) exec ssh -t "$HOST" "cd ~/$REMOTE_DIR && exec \$SHELL" ;;
  clean)
    sync
    ssh "$HOST" "cd ~/$REMOTE_DIR && rm -rf build && mkdir build && cd build && \
      cmake .. -DCMAKE_BUILD_TYPE=Release -DBUILD_TESTS=ON && make -j$JOBS"
    ;;
  test)
    sync
    ssh "$HOST" "cd ~/$REMOTE_DIR/build && cmake .. -DCMAKE_BUILD_TYPE=Release -DBUILD_TESTS=ON >/dev/null && \
      make -j$JOBS && ctest --output-on-failure --timeout 900"
    ;;
  build|*)
    sync
    ssh "$HOST" "cd ~/$REMOTE_DIR/build && cmake .. -DCMAKE_BUILD_TYPE=Release -DBUILD_TESTS=ON >/dev/null && \
      make -j$JOBS"
    ;;
esac
