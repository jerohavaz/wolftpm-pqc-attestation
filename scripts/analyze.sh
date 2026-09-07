#!/usr/bin/env bash
set -euo pipefail
root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
"${root}/analysis/.venv/bin/python" "${root}/analysis/analyze.py" --results "${root}/results"
