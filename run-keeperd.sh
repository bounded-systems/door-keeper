#!/usr/bin/env bash
# run-keeperd.sh — start keeperd for claude-box
#
# keeperd listens on TCP; boxes connect via host.containers.internal (the
# podman-machine gateway to the host). Unix sockets can't cross the macOS→VM
# boundary, so we use TCP and set KEEPERD_HOST for the in-box client.
#
# Usage:
#   ./run-keeperd.sh up       # start keeperd on TCP
#   ./run-keeperd.sh test     # verify keeperd responds
#   ./run-keeperd.sh down     # stop keeperd
#
# Then: claude-box work --repo . --net-open  # needs network to reach keeperd
#       (inside box) echo '{"id":"1","method":"status"}' | nc host.containers.internal 9999
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PORT="${KEEPERD_PORT:-9999}"

die() { printf '\033[31mkeepered: %s\033[0m\n' "$*" >&2; exit 1; }

up() {
  # Kill any existing keeperd
  pkill -f "keeperd.ts serve" 2>/dev/null || true
  pkill -f "keeperd.*--port" 2>/dev/null || true

  # Start keeperd on TCP (use nix run if available, else bun)
  echo "keeperd: starting on TCP port ${PORT}..."
  if command -v nix >/dev/null && [[ -f "$SCRIPT_DIR/flake.nix" ]]; then
    nix run "$SCRIPT_DIR#keeperd" -- serve --port "$PORT" &
  elif command -v bun >/dev/null; then
    bun run "$SCRIPT_DIR/keeperd.ts" serve --port "$PORT" &
  else
    die "neither nix nor bun found"
  fi
  KEEPERD_PID=$!
  sleep 0.5

  # Verify it's running
  if ! kill -0 "$KEEPERD_PID" 2>/dev/null; then
    die "keeperd failed to start"
  fi

  echo "keeperd: running on port ${PORT} (pid ${KEEPERD_PID})"
  echo ""
  echo "Test with:"
  echo "  { echo '{\"id\":\"1\",\"method\":\"status\"}'; sleep 0.1; } | nc localhost ${PORT}"
  echo ""
  echo "From inside a box (needs --net-open for now):"
  echo "  { echo '{\"id\":\"1\",\"method\":\"status\"}'; sleep 0.1; } | nc host.containers.internal ${PORT}"
}

test_() {
  echo "keeperd: testing status..."
  response=$({ echo '{"id":"1","method":"status"}'; sleep 0.2; } | nc localhost "$PORT" 2>/dev/null || true)
  if [[ "$response" == *'"ok":true'* ]]; then
    echo "keeperd: responding ✓"
    echo "$response" | head -1
  else
    die "keeperd not responding (got: $response)"
  fi
}

down() {
  echo "keeperd: stopping..."
  pkill -f "keeperd.ts serve" 2>/dev/null || true
  pkill -f "keeperd.*--port" 2>/dev/null || true
  echo "keeperd: stopped"
}

case "${1:-up}" in
  up)   up ;;
  test) test_ ;;
  down) down ;;
  *)    die "usage: run-keeperd.sh {up|test|down}" ;;
esac
