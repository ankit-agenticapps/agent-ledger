"""policy plugin: hard-block risky tool calls (Claude Code PreToolUse hook).

Exit 2 + reason on stderr blocks the call; exit 0 allows it. Every decision is
appended to the signed ledger chain. Shell-command parsing is HEURISTIC: it
catches common forms, not every obfuscation (see README).
"""
import fnmatch
import json
import os
import re
import shlex
import sys

from .. import core

DEFAULT_POLICY = {
    "version": 1,
    "block_paths": [".env", ".env.*", "*.pem", "id_rsa", "id_ed25519",
                    "~/.ssh", "~/.aws"],
    "allow_paths": [".env.example", ".env.sample"],
    "block_rm_outside_project": True,
    "block_force_push_branches": ["main", "master"],
    "block_pipe_to_shell": True,
    "block_secret_patterns": True,
    "max_cost_usd": 5.0,
}

PATH_KEYS = ("file_path", "path", "notebook_path")
PATH_TOOLS = {"Read", "Write", "Edit", "MultiEdit", "NotebookEdit", "NotebookRead",
              "Glob", "Grep"}
SECRET_EXTRA = re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----")
PIPE_SHELL = re.compile(
    r"\b(curl|wget)\b[^|;&\n]*\|\s*(sudo\s+)?(env\s+)?(ba|z|da|k)?sh\b"
    r"|\b(curl|wget)\b[^|;&\n]*\|\s*(sudo\s+)?python3?\b"
    r"|\b(ba|z|da)?sh\s+-c\s+[\"']?\$\(\s*(curl|wget)\b")


def policy_path(path=None):
    return os.path.abspath(os.path.expanduser(
        path or os.environ.get("AGENT_LEDGER_POLICY")
        or "~/.agent-ledger/policy.json"))


def load_policy(path=None):
    """Policy file merged over defaults; missing file -> defaults."""
    pol = dict(DEFAULT_POLICY)
    p = policy_path(path)
    if os.path.exists(p):
        with open(p) as f:
            data = json.load(f)
        if not isinstance(data, dict):
            raise ValueError("policy must be a JSON object")
        pol.update(data)
    return pol


def _home():
    return os.path.expanduser("~")


def _expand(s, cwd):
    """Expand ~, $HOME, ${HOME}; None if other variables remain."""
    s = s.replace("${HOME}", _home()).replace("$HOME", _home())
    s = os.path.expanduser(s)
    if "$" in s or "`" in s:
        return None
    return os.path.normpath(os.path.join(cwd, s))


def path_blocked(raw, pol, cwd):
    """Return the matching rule if this path is blocked, else None."""
    if not raw or not isinstance(raw, str):
        return None
    p = _expand(raw, cwd)
    if p is None:
        return None
    base = os.path.basename(p)
    for pat in pol.get("allow_paths", []):
        if "/" not in pat and fnmatch.fnmatch(base, pat):
            return None
    for pat in pol.get("block_paths", []):
        if "/" in pat or pat.startswith("~"):
            root = os.path.normpath(os.path.expanduser(pat))
            if p == root or p.startswith(root + os.sep):
                return pat
        elif any(fnmatch.fnmatch(part, pat) for part in p.split(os.sep) if part):
            return pat
    return None


def _segments(cmd):
    parts = re.split(r"&&|\|\||[;|\n]", cmd)
    out = []
    for seg in parts:
        try:
            out.append(shlex.split(seg))
        except ValueError:
            out.append(seg.split())
    return [t for t in out if t]


def _strip_prefix(tokens):
    while tokens and (tokens[0] in ("sudo", "command", "env", "nohup", "time")
                      or re.match(r"^\w+=", tokens[0])):
        tokens = tokens[1:]
    return tokens


def check_rm(tokens, cwd, project):
    if not tokens or os.path.basename(tokens[0]) != "rm":
        return None
    flags = [t for t in tokens[1:] if t.startswith("-")]
    recursive = any(t == "--recursive" or (not t.startswith("--") and
                    ("r" in t or "R" in t)) for t in flags)
    if not recursive:
        return None
    targets = [t for t in tokens[1:] if not t.startswith("-")]
    proj = os.path.normpath(project)
    for t in targets:
        p = _expand(t, cwd)
        if p is None:
            return "rm -rf target '%s' uses an unresolved variable" % t
        if p == os.sep or p == os.path.normpath(_home()):
            return "rm -rf on '%s' (root or home)" % t
        if not (p == proj or p.startswith(proj + os.sep)):
            return "rm -rf target '%s' is outside the project dir" % t
    return None


def check_push(tokens, pol):
    if len(tokens) < 2 or tokens[0] != "git" or "push" not in tokens:
        return None
    rest = tokens[tokens.index("push") + 1:]
    force = any(t in ("--force", "-f", "--force-with-lease") or
                t.startswith("--force-with-lease=") or
                (t.startswith("-") and not t.startswith("--") and "f" in t)
                for t in rest)
    pos = [t for t in rest if not t.startswith("-")]
    forced_ref = any(t.startswith("+") for t in pos)
    if not (force or forced_ref):
        return None
    branches = pol.get("block_force_push_branches") or []
    refs = pos[1:]
    if not refs:
        return "force push without an explicit branch (could be %s)" % "/".join(branches)
    for r in refs:
        dst = r.split(":")[-1].lstrip("+")
        dst = dst[len("refs/heads/"):] if dst.startswith("refs/heads/") else dst
        if dst in branches:
            return "force push to protected branch '%s'" % dst
    return None


def check_tool(tool, ti, pol, cwd, project):
    """Rule checks (no budget). Returns (reason_or_None, files_list)."""
    ti = ti if isinstance(ti, dict) else {}
    files = []
    if tool in PATH_TOOLS or any(k in ti for k in PATH_KEYS):
        for k in PATH_KEYS:
            v = ti.get(k)
            if isinstance(v, str):
                files.append(v)
                rule = path_blocked(v, pol, cwd)
                if rule:
                    return "%s of '%s' blocked by path rule '%s'" % (tool, v, rule), files
    cmd = ti.get("command") if isinstance(ti.get("command"), str) else ""
    if cmd:
        if pol.get("block_pipe_to_shell", True) and PIPE_SHELL.search(cmd):
            return "piping a download into a shell (curl|sh) is blocked", files
        for seg in _segments(cmd):
            seg = _strip_prefix(seg)
            if pol.get("block_rm_outside_project", True):
                r = check_rm(seg, cwd, project)
                if r:
                    return r, files
            if pol.get("block_force_push_branches"):
                r = check_push(seg, pol)
                if r:
                    return r, files
            for tok in seg[1:]:
                t = tok.split("=", 1)[-1].lstrip("<>")
                rule = path_blocked(t, pol, cwd)
                if rule:
                    return "command touches '%s' (path rule '%s')" % (t, rule), files
    if pol.get("block_secret_patterns", True):
        blob = json.dumps(ti, ensure_ascii=True)
        if SECRET_EXTRA.search(blob) or any(p.search(blob) for p in core._PATTERNS):
            return "tool input contains a known secret pattern", files
    return None, files


def decide(payload, pol, ledger):
    """Return (allowed, reason). Does not write the ledger."""
    tool = str(payload.get("tool_name", "unknown"))
    ti = payload.get("tool_input")
    cwd = payload.get("cwd") or os.getcwd()
    project = os.environ.get("CLAUDE_PROJECT_DIR") or cwd
    reason, files = check_tool(tool, ti, pol, cwd, project)
    if reason is None and pol.get("max_cost_usd") is not None:
        sid = payload.get("session_id")
        if sid:
            spent = core.session_cost(ledger, sid)
            if spent > float(pol["max_cost_usd"]):
                reason = "session budget exceeded: $%.4f spent > cap $%.4f" % (
                    spent, float(pol["max_cost_usd"]))
    return reason is None, reason, files


def cmd_check(args):
    ledger = core.default_path(args.ledger)
    try:
        payload = json.loads(sys.stdin.read() or "{}")
        if not isinstance(payload, dict):
            raise ValueError
    except ValueError:
        print("policy-check: unparseable input, allowing", file=sys.stderr)
        _record(ledger, args.agent, "ALLOW", "unparseable input", {}, [])
        return 0
    try:
        pol = load_policy(args.policy)
    except (ValueError, OSError) as ex:
        reason = "policy file unreadable (%s); failing closed" % ex
        _record(ledger, args.agent, "DENY", reason, payload, [])
        print("BLOCKED: " + reason, file=sys.stderr)
        return 2
    allowed, reason, files = decide(payload, pol, ledger)
    _record(ledger, args.agent, "ALLOW" if allowed else "DENY", reason, payload, files)
    if allowed:
        return 0
    print("BLOCKED by agent-ledger policy: %s" % reason, file=sys.stderr)
    return 2


def _record(ledger, agent, verdict, reason, payload, files):
    ti = payload.get("tool_input") if isinstance(payload.get("tool_input"), dict) else {}
    what = ti.get("command") or ti.get("file_path") or ti.get("path") or ""
    action = "policy:%s %s %s" % (verdict, payload.get("tool_name", "unknown"),
                                  str(what)[:100])
    if reason:
        action += " -- " + reason
    if payload.get("session_id"):
        action += core.session_tag(payload["session_id"])
    try:
        core.append(ledger, agent, action, 0.0, files[:5])
    except (ValueError, OSError) as ex:
        print("policy-check: could not write ledger: %s" % ex, file=sys.stderr)


def cmd_policy(args):
    p = policy_path(args.policy)
    if args.action == "show":
        print(json.dumps(load_policy(args.policy), indent=2))
        return 0
    if os.path.exists(p) and not args.force:
        print("error: %s exists (use --force to overwrite)" % p)
        return 1
    os.makedirs(os.path.dirname(p), exist_ok=True)
    with open(p, "w") as f:
        json.dump(DEFAULT_POLICY, f, indent=2)
        f.write("\n")
    print("wrote default policy: %s" % p)
    return 0


def register(subparsers):
    p = subparsers.add_parser("policy-check",
                              help="PreToolUse hook: read tool call JSON on stdin, exit 2 to block")
    p.add_argument("--agent", default="claude-code")
    p.add_argument("--policy", help="policy.json (default: env AGENT_LEDGER_POLICY "
                   "or ~/.agent-ledger/policy.json; built-in defaults if absent)")
    p.set_defaults(func=cmd_check)
    p = subparsers.add_parser("policy", help="policy init | show")
    p.add_argument("action", choices=["init", "show"])
    p.add_argument("--policy")
    p.add_argument("--force", action="store_true")
    p.set_defaults(func=cmd_policy)
