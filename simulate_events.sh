#!/usr/bin/env bash
# ==============================================================================
# Vigil — Interactive Security Event Simulator & Demonstration Runner
# ==============================================================================
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "${SCRIPT_DIR}"

chmod +x "${SCRIPT_DIR}/simulate_events.py"
exec "${SCRIPT_DIR}/simulate_events.py" "$@"

