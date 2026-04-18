#!/usr/bin/env bash
# PreToolUse (Bash) gate: intercept "git push" calls from Claude and run pre-push checks.
# Exit 2 so Claude self-corrects on failure.
input=$(cat)
cmd=$(printf '%s' "$input" | python3 -c \
  "import sys,json; d=json.load(sys.stdin); print(d.get('tool_input',{}).get('command',''))" \
  2>/dev/null || echo "")

[[ "$cmd" == *"git push"* ]] || exit 0

bash "$(dirname "$0")/pre-push" || exit 2
