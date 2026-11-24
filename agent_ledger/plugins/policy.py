"""policy plugin: per-rule deny / ask / allow for tool calls (Claude Code PreToolUse hook).

Each rule has an `action`:
  deny  - exit 2 + reason on stderr (the call is blocked)
  ask   - exit 0 + PreToolUse JSON on stdout (Claude Code prompts the human)
  allow - exit 0, logged only
Rules may carry exceptions (`allow_paths`, `allow_agents`, `allow_commands`, or an
`allow` list of {paths, agents, commands} objects whose keys must ALL match) and a
`redact_output_note` that is appended to the reason shown to the human/agent.
Every decision is appended to the signed ledger chain. Shell parsing is
HEURISTIC: it catches common forms, not every obfuscation (see README).
A policy file without a "rules" list uses the legacy flat keys, all as deny.
"""
import fnmatch
import json
import os
import re
import shlex
import sys

from .. import core

SECRET_PATHS = [".env", ".env.*", "*.pem", "id_rsa", "id_ed25519", "~/.ssh", "~/.aws"]
SAFE_EXAMPLES = [".env.example", ".env.sample"]

# Used when no policy file exists: strict legacy hard-block (every rule = deny).
DEFAULT_POLICY = {
    "version": 1,
    "block_paths": list(SECRET_PATHS),
    "allow_paths": list(SAFE_EXAMPLES),
    "block_rm_outside_project": True,
    "block_force_push_branches": ["main", "master"],
    "block_pipe_to_shell": True,
    "block_secret_patterns": True,
    "max_cost_usd": 5.0,
}

# Written by `policy init`: ask for secret reads, deny for the dangerous things.
INIT_POLICY = {
    "version": 2,
    "rules": [
        {"id": "secret-read", "kind": "path_read", "action": "ask",
         "paths": list(SECRET_PATHS), "allow_paths": list(SAFE_EXAMPLES),
         "redact_output_note": "Output may contain secrets; do not repeat values in replies or logs."},
        {"id": "ssh-aws-write", "kind": "path_write", "action": "deny",
         "paths": ["~/.ssh", "~/.aws"]},
        {"id": "secret-write", "kind": "path_write", "action": "ask",
         "paths": [".env", ".env.*", "*.pem", "id_rsa", "id_ed25519"],
         "allow_paths": list(SAFE_EXAMPLES)},
        {"id": "secret-exfil", "kind": "net_exfil", "action": "deny",
         "paths": list(SECRET_PATHS), "allow_paths": list(SAFE_EXAMPLES)},
        {"id": "rm-outside-project", "kind": "rm_outside_project", "action": "deny"},
        {"id": "force-push-main", "kind": "force_push", "action": "deny",
         "branches": ["main", "master"]},
        {"id": "pipe-to-shell", "kind": "pipe_to_shell", "action": "deny"},
    ],
    "safe_env_read": True,
    "block_secret_patterns": True,
    "max_cost_usd": 5.0,
}

SEVERITY = {"allow": 0, "ask": 1, "deny": 2}
KINDS = {"path_read", "path_write", "path_any", "net_exfil",
         "rm_outside_project", "force_push", "pipe_to_shell"}
PATH_KEYS = ("file_path", "path", "notebook_path")
READ_TOOLS = {"Read", "Grep", "Glob", "NotebookRead"}
WRITE_TOOLS = {"Write", "Edit", "MultiEdit", "NotebookEdit"}
NET_CMDS = {"curl", "wget", "nc", "ncat", "netcat", "scp", "sftp", "rsync", "ftp", "socat"}
WRITE_CMDS = {"rm", "mv", "tee", "touch", "chmod", "chown", "dd", "ln", "truncate",
              "install", "shred", "rmdir"}
SECRET_EXTRA = re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----")
PIPE_SHELL = re.compile(
    r"\b(curl|wget)\b[^|;&\n]*\|\s*(sudo\s+)?(env\s+)?(ba|z|da|k)?sh\b"
    r"|\b(curl|wget)\b[^|;&\n]*\|\s*(sudo\s+)?python3?\b"
    r"|\b(ba|z|da)?sh\s+-c\s+[\"']?\$\(\s*(curl|wget)\b")
# '^[A-Z_]*=' style: anchored character classes ending in '=' (names only).
NAME_PAT = re.compile(r"^\^?(\[[A-Za-z0-9_-]+\][*+]?)+=?$")
AWK_PROG = re.compile(r"^\{\s*print\s+\$1\s*\}$")
SED_PROG = re.compile(r"^s/=\.\*\$?//p?$")


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
    build_rules(pol)  # validate now so a bad file fails closed
    return pol


def build_rules(pol):
    """Rule list: explicit `rules`, else legacy flat keys converted (all deny)."""
    if "rules" in pol:
        rules = pol["rules"]
        if not isinstance(rules, list):
            raise ValueError("'rules' must be a list")
        for i, r in enumerate(rules):
            if not isinstance(r, dict):
                raise ValueError("rule %d must be an object" % i)
            r.setdefault("id", "rule-%d" % (i + 1))
            if r.get("action") not in SEVERITY:
                raise ValueError("rule '%s': action must be deny, ask or allow" % r["id"])
            if r.get("kind") not in KINDS:
                raise ValueError("rule '%s': unknown kind '%s'" % (r["id"], r.get("kind")))
        return rules
    rules = [{"id": "path-block", "kind": "path_any", "action": "deny",
              "paths": pol.get("block_paths", []), "allow_paths": pol.get("allow_paths", [])}]
    if pol.get("block_rm_outside_project", True):
        rules.append({"id": "rm-outside-project", "kind": "rm_outside_project", "action": "deny"})
    if pol.get("block_force_push_branches"):
        rules.append({"id": "force-push", "kind": "force_push", "action": "deny",
                      "branches": pol["block_force_push_branches"]})
    if pol.get("block_pipe_to_shell", True):
        rules.append({"id": "pipe-to-shell", "kind": "pipe_to_shell", "action": "deny"})
    return rules


def _home():
    return os.path.expanduser("~")


def _expand(s, cwd):
    """Expand ~, $HOME, ${HOME}; None if other variables remain."""
    s = s.replace("${HOME}", _home()).replace("$HOME", _home())
    s = os.path.expanduser(s)
    if "$" in s or "`" in s:
        return None
    return os.path.normpath(os.path.join(cwd, s))


def match_path(raw, patterns, cwd, project=None):
    """Return the first pattern matching this path, else None.
    Patterns: 'name' globs match any path component; '~/x', '/abs' and
    '{project}/x' are anchored (prefix match, or glob if they contain * ? [)."""
    if not raw or not isinstance(raw, str):
        return None
    p = _expand(raw, cwd)
    if p is None:
        return None
    for pat in patterns or []:
        if "{project}" in pat:
            pat = pat.replace("{project}", project or cwd)
        if "/" in pat or pat.startswith("~"):
            root = os.path.normpath(os.path.expanduser(pat))
            if p == root or p.startswith(root + os.sep) or fnmatch.fnmatch(p, root):
                return pat
        elif any(fnmatch.fnmatch(part, pat) for part in p.split(os.sep) if part):
            return pat
    return None


def path_blocked(raw, pol, cwd):
    """Legacy helper: matching block rule if this path is blocked, else None."""
    p = _expand(raw, cwd) if isinstance(raw, str) and raw else None
    if p is None:
        return None
    if match_path(raw, pol.get("allow_paths", []), cwd):
        return None
    return match_path(raw, pol.get("block_paths", []), cwd)


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


def check_push(tokens, branches):
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
    branches = branches or []
    refs = pos[1:]
    if not refs:
        return "force push without an explicit branch (could be %s)" % "/".join(branches)
    for r in refs:
        dst = r.split(":")[-1].lstrip("+")
        dst = dst[len("refs/heads/"):] if dst.startswith("refs/heads/") else dst
        if dst in branches:
            return "force push to protected branch '%s'" % dst
    return None


def safe_env_names(seg):
    """True if this command segment only prints variable NAMES from env files
    (grep -o '^[A-Z_]*=' .env, cut -d= -f1 .env, awk -F= '{print $1}', sed 's/=.*//')."""
    if not seg or any(">" in t or "`" in t or "$(" in t or re.search(r"\$[A-Za-z_{]", t)
                      for t in seg):
        return False
    base, args = os.path.basename(seg[0]), seg[1:]
    files = []
    if base in ("grep", "egrep"):
        pos, only = [], False
        for t in args:
            if t.startswith("-") and len(t) > 1:
                if not re.match(r"^-[oEhHiwP]+$", t):
                    return False
                only = only or "o" in t
            else:
                pos.append(t)
        if not only or len(pos) < 2 or not NAME_PAT.match(pos[0]):
            return False
        files = pos[1:]
    elif base == "cut":
        delim = field = False
        i = 0
        while i < len(args):
            t = args[i]
            if t == "-d" and i + 1 < len(args) and args[i + 1] == "=":
                delim, i = True, i + 2
            elif t == "-d=":
                delim, i = True, i + 1
            elif t == "-f" and i + 1 < len(args) and args[i + 1] == "1":
                field, i = True, i + 2
            elif t == "-f1":
                field, i = True, i + 1
            elif t.startswith("-"):
                return False
            else:
                files.append(t)
                i += 1
        if not (delim and field):
            return False
    elif base == "awk":
        sep, prog, i = False, None, 0
        while i < len(args):
            t = args[i]
            if t == "-F=":
                sep, i = True, i + 1
            elif t == "-F" and i + 1 < len(args) and args[i + 1] == "=":
                sep, i = True, i + 2
            elif t.startswith("-"):
                return False
            elif prog is None:
                prog, i = t, i + 1
            else:
                files.append(t)
                i += 1
        if not (sep and prog and AWK_PROG.match(prog)):
            return False
    elif base == "sed":
        pos = [t for t in args if not (t.startswith("-") and t in ("-n", "-E", "-r"))]
        if any(t.startswith("-") for t in pos) or len(pos) < 2 or not SED_PROG.match(pos[0]):
            return False
        files = pos[1:]
    else:
        return False
    return bool(files) and all(os.path.basename(f).startswith(".env") for f in files)


def _tool_mode(tool):
    return "write" if tool in WRITE_TOOLS else "read"


def _seg_info(seg, cwd):
    """Describe one shell segment: base command and [(raw_path, mode)]."""
    base = os.path.basename(seg[0])
    wmode = base in WRITE_CMDS or (base == "sed" and any(
        t == "--in-place" or (t.startswith("-i") and not t.startswith("--")) for t in seg[1:]))
    paths, prev = [], ""
    pos = [i for i, t in enumerate(seg[1:], 1) if not t.startswith("-")]
    for i, tok in enumerate(seg[1:], 1):
        redirect = prev.startswith(">") or tok.startswith(">")
        t = tok.split("=", 1)[-1].lstrip("<>@")
        prev = tok
        if not t:
            continue
        mode = "write" if (wmode or redirect) else "read"
        if base in ("cp", "install") and pos and i == pos[-1] and not wmode:
            mode = "write"
        paths.append((t, mode))
    return {"base": base, "paths": paths}


class Ctx(object):
    pass


def build_ctx(payload, pol, rules, agent):
    c = Ctx()
    c.tool = str(payload.get("tool_name", "unknown"))
    ti = payload.get("tool_input")
    c.ti = ti if isinstance(ti, dict) else {}
    c.cwd = payload.get("cwd") or os.getcwd()
    c.project = os.environ.get("CLAUDE_PROJECT_DIR") or c.cwd
    c.agent = agent
    c.files, c.tool_paths, c.segs, c.safe = [], [], [], []
    if c.tool in READ_TOOLS | WRITE_TOOLS or any(k in c.ti for k in PATH_KEYS):
        for k in PATH_KEYS:
            v = c.ti.get(k)
            if isinstance(v, str):
                c.files.append(v)
                c.tool_paths.append((v, _tool_mode(c.tool)))
    c.cmd = c.ti.get("command") if isinstance(c.ti.get("command"), str) else ""
    all_pats = [p for r in rules if r["kind"].startswith("path_") or r["kind"] == "net_exfil"
                for p in r.get("paths", [])]
    inner = [a or b for a, b in re.findall(r"\$\(([^()]*)\)|`([^`]*)`", c.cmd)]
    segs = []
    for text in ([c.cmd] + inner) if c.cmd else []:
        segs.extend(_segments(text))
    for seg in segs:
        seg = _strip_prefix(seg)
        if not seg:
            continue
        if pol.get("safe_env_read", False) and safe_env_names(seg):
            files = [t for t in seg[1:] if not t.startswith("-")]
            hit = [f for f in files if match_path(f, all_pats, c.cwd, c.project)]
            if hit:
                c.safe.append(hit[0])
                continue
        info = _seg_info(seg, c.cwd)
        info["tokens"] = seg
        c.segs.append(info)
    return c


def _waived(rule, ctx, raw=None):
    """Return a description of the exception that waives this rule, else None."""
    cmd = ctx.cmd
    pats = rule.get("allow_paths")
    if pats and raw and match_path(raw, pats, ctx.cwd, ctx.project):
        return "allow_paths"
    ag = rule.get("allow_agents")
    if ag and any(fnmatch.fnmatch(ctx.agent, a) for a in ag):
        return "allow_agents '%s'" % ctx.agent
    cm = rule.get("allow_commands")
    if cm and cmd and any(fnmatch.fnmatch(cmd, c) for c in cm):
        return "allow_commands"
    for ex in rule.get("allow") or []:
        ok = bool(ex)
        if "paths" in ex:
            ok = ok and bool(raw and match_path(raw, ex["paths"], ctx.cwd, ctx.project))
        if "agents" in ex:
            ok = ok and any(fnmatch.fnmatch(ctx.agent, a) for a in ex["agents"])
        if "commands" in ex:
            ok = ok and bool(cmd and any(fnmatch.fnmatch(cmd, c) for c in ex["commands"]))
        if ok:
            return "allow entry"
    return None


def _hit(rule, reason, ctx, raw=None):
    wv = _waived(rule, ctx, raw)
    if wv:
        return {"action": "allow", "rule": rule["id"],
                "reason": "exception (%s) waives rule: %s" % (wv, reason)}
    return {"action": rule["action"], "rule": rule["id"],
            "reason": rule.get("reason") or reason,
            "note": rule.get("redact_output_note")}


def eval_rules(rules, ctx, pol):
    hits = []
    for f in ctx.safe:
        hits.append({"action": "allow", "rule": "safe-env-read",
                     "reason": "names-only read of '%s' (no values printed)" % f})
    for rule in rules:
        kind = rule["kind"]
        if kind in ("path_read", "path_write", "path_any"):
            want = {"path_read": "read", "path_write": "write"}.get(kind)
            for raw, mode in ctx.tool_paths:
                if want in (None, mode) and match_path(raw, rule.get("paths"), ctx.cwd, ctx.project):
                    pat = match_path(raw, rule.get("paths"), ctx.cwd, ctx.project)
                    hits.append(_hit(rule, "%s of '%s' blocked by path rule '%s'" % (
                        ctx.tool, raw, pat), ctx, raw))
            for seg in ctx.segs:
                for raw, mode in seg["paths"]:
                    pat = match_path(raw, rule.get("paths"), ctx.cwd, ctx.project)
                    if pat and want in (None, mode):
                        hits.append(_hit(rule, "command touches '%s' (path rule '%s')" % (
                            raw, pat), ctx, raw))
        elif kind == "net_exfil":
            if any(s["base"] in NET_CMDS for s in ctx.segs):
                for seg in ctx.segs:
                    for raw, _ in seg["paths"]:
                        pat = match_path(raw, rule.get("paths"), ctx.cwd, ctx.project)
                        if pat:
                            hits.append(_hit(rule, "command sends secret file '%s' over the "
                                             "network (path rule '%s')" % (raw, pat), ctx, raw))
        elif kind == "rm_outside_project":
            for seg in ctx.segs:
                r = check_rm(seg["tokens"], ctx.cwd, ctx.project)
                if r:
                    hits.append(_hit(rule, r, ctx))
        elif kind == "force_push":
            for seg in ctx.segs:
                r = check_push(seg["tokens"], rule.get("branches") or ["main", "master"])
                if r:
                    hits.append(_hit(rule, r, ctx))
        elif kind == "pipe_to_shell":
            if ctx.cmd and PIPE_SHELL.search(ctx.cmd):
                hits.append(_hit(rule, "piping a download into a shell (curl|sh) is blocked", ctx))
    if pol.get("block_secret_patterns", True):
        blob = json.dumps(ctx.ti, ensure_ascii=True)
        if SECRET_EXTRA.search(blob) or any(p.search(blob) for p in core._PATTERNS):
            hits.append({"action": "deny", "rule": "secret-patterns",
                         "reason": "tool input contains a known secret pattern"})
    return hits


def decide(payload, pol, ledger, agent="claude-code"):
    """Return a decision dict (action, reason, rule, note, files, hits).
    Does not write the ledger. Severity: deny > ask > allow."""
    rules = build_rules(pol)
    ctx = build_ctx(payload, pol, rules, agent)
    hits = eval_rules(rules, ctx, pol)
    if pol.get("max_cost_usd") is not None and payload.get("session_id"):
        spent = core.session_cost(ledger, payload["session_id"])
        if spent > float(pol["max_cost_usd"]):
            hits.append({"action": "deny", "rule": "budget",
                         "reason": "session budget exceeded: $%.4f spent > cap $%.4f" % (
                             spent, float(pol["max_cost_usd"]))})
    best = {"action": "allow", "reason": None, "rule": None}
    for h in hits:
        if SEVERITY[h["action"]] > SEVERITY[best["action"]] or best["rule"] is None:
            best = h
    d = dict(best)
    d.setdefault("note", None)
    d["files"], d["hits"] = ctx.files, hits
    return d


def full_reason(d):
    r = d.get("reason")
    if r and d.get("rule"):
        r += " (rule: %s)" % d["rule"]
    if r and d.get("note") and d["action"] != "allow":
        r += " Note: " + d["note"]
    return r


def _read_payload():
    payload = json.loads(sys.stdin.read() or "{}")
    if not isinstance(payload, dict):
        raise ValueError
    return payload


def cmd_check(args):
    ledger = core.default_path(args.ledger)
    try:
        payload = _read_payload()
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
    d = decide(payload, pol, ledger, args.agent)
    reason = full_reason(d)
    _record(ledger, args.agent, d["action"].upper(), reason, payload, d["files"])
    if d["action"] == "deny":
        print("BLOCKED by agent-ledger policy: %s" % reason, file=sys.stderr)
        return 2
    if d["action"] == "ask":
        print(json.dumps({"hookSpecificOutput": {
            "hookEventName": "PreToolUse", "permissionDecision": "ask",
            "permissionDecisionReason": "agent-ledger policy: %s" % reason}}))
    return 0


def cmd_explain(args):
    """Read a payload from stdin, print the matching rule and why. No side effects."""
    try:
        payload = _read_payload()
    except ValueError:
        print("explain: stdin is not a JSON object")
        return 1
    try:
        pol = load_policy(args.policy)
    except (ValueError, OSError) as ex:
        print("DENY  rule=policy-file  policy file unreadable (%s); would fail closed" % ex)
        return 0
    d = decide(payload, pol, core.default_path(args.ledger), args.agent)
    print("%s  rule=%s  agent=%s" % (d["action"].upper(), d["rule"] or "none", args.agent))
    print("why: %s" % (d["reason"] or "no rule matched; allowed by default"))
    if d.get("note") and d["action"] != "allow":
        print("note: %s" % d["note"])
    others = [h for h in d["hits"] if h is not d and h["rule"] != d["rule"]]
    for h in others:
        print("also: %s rule=%s  %s" % (h["action"].upper(), h["rule"], h["reason"]))
    return 0


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
    if args.action == "explain":
        return cmd_explain(args)
    if os.path.exists(p) and not args.force:
        print("error: %s exists (use --force to overwrite)" % p)
        return 1
    os.makedirs(os.path.dirname(p), exist_ok=True)
    with open(p, "w") as f:
        json.dump(INIT_POLICY, f, indent=2)
        f.write("\n")
    print("wrote default policy: %s" % p)
    return 0


def register(subparsers):
    p = subparsers.add_parser("policy-check",
                              help="PreToolUse hook: tool call JSON on stdin; exit 2 = deny, "
                                   "exit 0 + JSON = ask, exit 0 = allow")
    p.add_argument("--agent", default="claude-code")
    p.add_argument("--policy", help="policy.json (default: env AGENT_LEDGER_POLICY "
                   "or ~/.agent-ledger/policy.json; built-in defaults if absent)")
    p.set_defaults(func=cmd_check)
    p = subparsers.add_parser("policy", help="policy init | show | explain (payload on stdin)")
    p.add_argument("action", choices=["init", "show", "explain"])
    p.add_argument("--policy")
    p.add_argument("--agent", default="claude-code", help="agent name for explain")
    p.add_argument("--force", action="store_true")
    p.set_defaults(func=cmd_policy)
