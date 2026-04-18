#!/usr/bin/env bash
# PostToolUse hook: run type/lint check after every file write or edit.
# Exit 2 so Claude self-corrects on failure.
set -euo pipefail

input=$(cat)
file=$(printf '%s' "$input" | python3 -c \
  "import sys,json; d=json.load(sys.stdin); print(d.get('tool_input',{}).get('file_path',''))" \
  2>/dev/null || echo "")

[ -z "$file" ] && exit 0

root=$(git -C "$(dirname "$file")" rev-parse --show-toplevel 2>/dev/null) || exit 0

case "$file" in
  *.rs)
    echo "rust: cargo clippy" >&2
    cd "$root"
    cargo clippy --quiet -- -D warnings 2>&1 || exit 2
    ;;
  *.py)
    echo "python: ruff check" >&2
    ruff check "$file" 2>&1 || exit 2
    ;;
  *.ts|*.svelte)
    echo "svelte/ts: npm run check" >&2
    cd "$root/frontend"
    npm run check --silent 2>&1 || exit 2
    ;;
esac
