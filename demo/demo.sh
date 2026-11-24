#!/bin/sh
# 15-second demo: agent reads .env -> BLOCKED (recorded), history edit -> VERIFY FAIL,
# then a self-contained HTML report. Set DEMO_FAST=1 to skip pauses, DEMO_OPEN=1 to open the report.
set -u
HERE=$(cd "$(dirname "$0")/.." && pwd)
TMP=$(mktemp -d)
trap 'rm -rf "$TMP"' EXIT
export AGENT_LEDGER="$TMP/ledger.jsonl"
export AGENT_LEDGER_POLICY="$TMP/policy.json"   # missing file = built-in default policy
export PYTHONPATH="$HERE"
AL="python3 -m agent_ledger"
OUT="${DEMO_OUT:-$HERE/demo/out}"
mkdir -p "$OUT"
pause() { [ -n "${DEMO_FAST:-}" ] || sleep "$1"; }

echo "\$ agent-ledger log  (3 agents)"
$AL log --agent claude-code --action "edited auth.py" --cost 0.42 --files auth.py >/dev/null
$AL log --agent codex --action "ran test suite" --cost 0.18 >/dev/null
$AL log --agent gemini --action "wrote docs" --cost 0.07 --files README.md >/dev/null
pause 1
echo
echo "# agent tries to read .env (Claude Code PreToolUse hook -> policy-check)"
echo '{"tool_name":"Read","tool_input":{"file_path":".env"}}' | $AL policy-check
pcode=$?
[ "$pcode" -eq 2 ] && echo "BLOCKED (exit $pcode) - decision recorded in the chain"
pause 2
echo "\$ agent-ledger verify"
$AL verify || exit 1
pause 1
echo
echo "\$ sed -i 's/policy:DENY/policy:ALLOW/' ledger.jsonl   # agent rewrites its own denial"
sed 's/policy:DENY/policy:ALLOW/' "$AGENT_LEDGER" > "$TMP/x" && mv "$TMP/x" "$AGENT_LEDGER"
pause 1
echo "\$ agent-ledger verify"
$AL verify
code=$?
echo "exit code: $code"
pause 1
echo
echo "\$ agent-ledger report --html report.html"
$AL report --html "$OUT/report.html"
[ -n "${DEMO_OPEN:-}" ] && { open "$OUT/report.html" 2>/dev/null || xdg-open "$OUT/report.html" 2>/dev/null; }
[ "$pcode" -eq 2 ] && [ "$code" -eq 1 ]
