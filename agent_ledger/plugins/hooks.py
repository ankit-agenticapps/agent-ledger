"""hooks plugin: print ready-to-paste Claude Code hook JSON and a Codex wrapper."""
import json


def run(args):
    cmd = args.cmd_name
    hook = {"hooks": {"PostToolUse": [{
        "matcher": "Edit|Write|MultiEdit|Bash",
        "hooks": [{"type": "command",
                   "command": "%s log --agent claude-code --hook-stdin" % cmd}]}]}}
    print("# Claude Code: merge into ~/.claude/settings.json")
    print(json.dumps(hook, indent=2))
    print()
    print("# Codex: wrap each run (logs start and finish)")
    print('codex() { %s log --agent codex --action "run: $*"; '
          'command codex "$@"; s=$?; %s log --agent codex '
          '--action "finished (exit $s)"; return $s; }' % (cmd, cmd))
    return 0


def register(subparsers):
    p = subparsers.add_parser("hooks", help="print Claude Code / Codex hook setup")
    p.add_argument("--cmd-name", default="agent-ledger",
                   help="how to invoke the tool (default: agent-ledger; "
                        "or 'python3 -m agent_ledger')")
    p.set_defaults(func=run)
