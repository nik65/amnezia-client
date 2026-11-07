#!/usr/bin/env bash
set -Eeuo pipefail
# Thin WSL entrypoint; plan-only unless --execute is passed through.
exec python3 "$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)/bootstrap_guest.py" "$@"
