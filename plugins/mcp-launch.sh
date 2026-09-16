#!/bin/sh
set -eu

FLOWAUDIT_ROOT="${FLOWAUDIT_ROOT:-${SECURITY_SCAN_ROOT:-}}"
FLOWAUDIT_RUNTIME="${FLOWAUDIT_RUNTIME:-${SECURITY_SCAN_RUNTIME:-docker}}"
export FLOWAUDIT_ROOT FLOWAUDIT_RUNTIME

if [ -z "${FLOWAUDIT_ROOT:-}" ]; then
  echo 'Set FLOWAUDIT_ROOT to the absolute flowaudit project directory before launching your client.' >&2
  exit 64
fi
case "$FLOWAUDIT_ROOT" in
  /*) ;;
  *) echo 'FLOWAUDIT_ROOT must be an absolute path.' >&2; exit 64 ;;
esac
if [ ! -f "$FLOWAUDIT_ROOT/package.json" ]; then
  echo 'FLOWAUDIT_ROOT does not contain the flowaudit project.' >&2
  exit 66
fi

case "${FLOWAUDIT_RUNTIME:-docker}" in
  docker)
    if ! command -v docker >/dev/null 2>&1; then
      echo 'Docker is unavailable. Install/start Docker, or use FLOWAUDIT_RUNTIME=local after npm install and npm run build.' >&2
      exit 69
    fi
    exec docker compose --project-directory "$FLOWAUDIT_ROOT" exec -T scanner node dist/src/mcp.js
    ;;
  local)
    if [ ! -f "$FLOWAUDIT_ROOT/dist/src/mcp.js" ]; then
      echo 'Build the scanner first: run npm install and npm run build in FLOWAUDIT_ROOT.' >&2
      exit 66
    fi
    cd "$FLOWAUDIT_ROOT"
    exec node dist/src/mcp.js
    ;;
  *) echo 'FLOWAUDIT_RUNTIME must be docker (default) or local.' >&2; exit 64 ;;
esac
