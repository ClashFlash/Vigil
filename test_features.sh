#!/usr/bin/env bash
# ==============================================================================
# Vigil — Non-Resource Security Features Showcase & Verification Runner
# ==============================================================================
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "${SCRIPT_DIR}"

# Ensure python script is executable
chmod +x "${SCRIPT_DIR}/test_features.py"

# Execute test suite passing all arguments
exec "${SCRIPT_DIR}/test_features.py" "$@"

