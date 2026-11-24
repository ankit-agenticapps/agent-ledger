#!/bin/sh
# 15-second demo: build a ledger, verify, tamper with one line, verify again.
set -u
HERE=$(cd "$(dirname "$0")/.." && pwd)
TMP=$(mktemp -d)
trap 'rm -rf "$TMP"' EXIT
export AGENT_LEDGER="$TMP/ledger.jsonl"
export PYTHONPATH="$HERE"
AL="python3 -m agent_ledger"
pause() { [ -n "${DEMO_FAST:-}" ] || sleep "$1"; }

echo "\$ agent-ledger log  (5 entries, 3 agents)"
$AL log --agent claude-code --action "edited auth.py" --cost 0.42 --files auth.py >/dev/null
$AL log --agent codex --action "ran test suite" --cost 0.18 >/dev/null
$AL log --agent claude-code --action "refactored db layer" --cost 0.91 --files db.py >/dev/null
$AL log --agent gemini --action "wrote docs" --cost 0.07 --files README.md >/dev/null
$AL log --agent codex --action "fixed flaky test" --cost 0.25 --files t.py >/dev/null
pause 1
echo "\$ agent-ledger verify"
$AL verify
pause 2
echo
echo "\$ sed -i 's/ran test suite/deleted prod db/' ledger.jsonl   # someone edits history"
sed 's/ran test suite/deleted prod db/' "$AGENT_LEDGER" > "$TMP/x" && mv "$TMP/x" "$AGENT_LEDGER"
pause 2
echo "\$ agent-ledger verify"
$AL verify
code=$?
echo "exit code: $code"
[ "$code" -eq 1 ]
