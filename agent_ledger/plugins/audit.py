"""audit plugin: read-only power check of your agent configs (logic copied from
agent-audit), recorded as a ledger entry."""
import argparse, json, os, re, sys

try:
    import tomllib
except ImportError:  # Python < 3.11: Codex config is skipped
    tomllib = None

W = {"high": 25, "medium": 10, "low": 4}
RISKY = {"rm", "curl", "wget", "sudo", "sh", "bash", "zsh", "eval", "ssh", "scp",
         "chmod", "chown", "dd", "kill", "python", "python3", "node", "git push", "docker"}
SECRET = re.compile(r"(KEY|TOKEN|SECRET|PASSWORD|PASSWD|CREDENTIAL)", re.I)
SHELLY = re.compile(r"(shell|terminal|bash|exec|command-runner|run[-_]command)", re.I)
LAUNCHERS = {"npx", "bunx", "uvx", "pipx"}


def load(path):
    """Return parsed JSON/TOML dict, or None if missing/unreadable."""
    try:
        with open(path, "rb") as f:
            raw = f.read()
        if path.endswith(".toml"):
            return tomllib.loads(raw.decode("utf-8")) if tomllib else None
        data = json.loads(raw.decode("utf-8"))
        return data if isinstance(data, dict) else None
    except Exception:
        return None


def add(out, sev, msg, where):
    f = {"severity": sev, "reason": msg, "where": where}
    if f not in out:
        out.append(f)


def check_allow(rule, where, out):
    if not isinstance(rule, str):
        return
    m = re.match(r"^([\w.\-]+)(?:\((.*)\))?$", rule.strip())
    if not m:
        return
    tool, arg = m.group(1), (m.group(2) or "").strip()
    wild = arg in ("", "*", ":*", "**")
    if tool == "*" or (tool == "Bash" and wild):
        add(out, "high", "Allow rule '%s' lets the agent run any command without asking." % rule, where)
    elif tool == "Bash" and arg.endswith(":*"):
        cmd = arg[:-2].strip()
        if cmd.split(" ")[0] in RISKY or cmd in RISKY:
            add(out, "high", "Allow rule '%s' lets the agent run a risky command with any input." % rule, where)
    elif tool in ("Write", "Edit", "MultiEdit", "WebFetch") and wild:
        add(out, "medium", "Allow rule '%s' lets the agent change or fetch anything unprompted." % rule, where)
    elif tool == "Read" and arg in ("*", "**", "/**", "~/**"):
        add(out, "low", "Allow rule '%s' lets the agent read any file it can reach." % rule, where)


def check_settings(d, where, out):
    perms = d.get("permissions") if isinstance(d.get("permissions"), dict) else {}
    for r in perms.get("allow") or []:
        check_allow(r, where, out)
    if perms.get("defaultMode") == "bypassPermissions" or d.get("defaultMode") == "bypassPermissions":
        add(out, "high", "Permission checks are switched off (bypassPermissions mode).", where)
    if d.get("skipDangerousModePermissionPrompt") is True:
        add(out, "high", "The warning before dangerous mode is skipped.", where)
    hooks = d.get("hooks")
    for event, groups in (hooks.items() if isinstance(hooks, dict) else []):
        for g in groups if isinstance(groups, list) else []:
            for h in (g.get("hooks") or []) if isinstance(g, dict) else []:
                if isinstance(h, dict) and h.get("command"):
                    add(out, "medium", "A '%s' hook runs a shell command automatically." % event, where)


def check_codex(d, where, out):
    if d.get("sandbox_mode") == "danger-full-access":
        add(out, "high", "Codex sandbox is off (danger-full-access).", where)
    if d.get("approval_policy") == "never":
        add(out, "medium", "Codex never asks before acting (approval_policy = never).", where)
    if d.get("approval_policy") == "never" and d.get("sandbox_mode") == "danger-full-access":
        add(out, "high", "Codex has no sandbox and no approval prompts at all.", where)


def check_server(name, s, home, where, out):
    if not isinstance(s, dict):
        return
    cmd = os.path.basename(str(s.get("command", "")))
    args = [str(a) for a in (s.get("args") or [])]
    label = "MCP server '%s'" % name
    roots = {"/", "~", "~/", home, home + "/", "$HOME", "${HOME}"}
    if any(a in roots for a in args) or (re.search(r"filesystem", name + " ".join(args), re.I)
                                         and any(a in roots for a in args)):
        add(out, "high", "%s can read and write your whole home folder or disk." % label, where)
    if SHELLY.search(name) or any(SHELLY.search(a) for a in args):
        add(out, "high", "%s gives the agent a shell or command runner." % label, where)
    env = s.get("env") if isinstance(s.get("env"), dict) else {}
    for k, v in env.items():
        if SECRET.search(str(k)) and v and not str(v).startswith("${"):
            add(out, "medium", "%s has a secret in its config (key: %s)." % (label, k), where)
    if cmd in LAUNCHERS or (cmd in ("pnpm", "yarn") and "dlx" in args):
        if any(a.endswith("@latest") for a in args):
            add(out, "medium", "%s downloads the newest version every launch (@latest)." % label, where)
        else:
            pk = [a for a in args if not a.startswith("-") and a != "dlx"]
            if pk and not re.search(r"@\d", pk[0]) and not re.search(r"==\d", pk[0]):
                add(out, "low", "%s runs '%s' with no pinned version." % (label, pk[0]), where)


def scan(home, cwd):
    out, scanned = [], []
    jfiles = [os.path.join(home, ".claude", "settings.json"),
              os.path.join(cwd, ".claude", "settings.json"),
              os.path.join(cwd, ".claude", "settings.local.json")]
    for p in jfiles:
        d = load(p)
        if d is not None:
            scanned.append(p)
            check_settings(d, p, out)
            for n, s in (d.get("mcpServers") or {}).items():
                check_server(n, s, home, p, out)
    for p in [os.path.join(cwd, ".mcp.json"), os.path.join(home, ".claude.json")]:
        d = load(p)
        if d is None:
            continue
        scanned.append(p)
        groups = [d.get("mcpServers")]
        groups += [v.get("mcpServers") for v in (d.get("projects") or {}).values() if isinstance(v, dict)]
        for g in groups:
            for n, s in (g.items() if isinstance(g, dict) else []):
                check_server(n, s, home, p, out)
    p = os.path.join(home, ".codex", "config.toml")
    d = load(p)
    if d is not None:
        scanned.append(p)
        check_codex(d, p, out)
        for n, s in (d.get("mcp_servers") or {}).items():
            check_server(n, s, home, p, out)
    out.sort(key=lambda f: -W[f["severity"]])
    return out, scanned


def score(findings):
    return min(100, sum(W[f["severity"]] for f in findings))


def label(n):
    return "LOW" if n < 25 else "MODERATE" if n < 50 else "HIGH" if n < 75 else "EXTREME"


def render(findings, scanned, color):
    paint = (lambda t, c: "\033[%sm%s\033[0m" % (c, t)) if color else (lambda t, c: t)
    col = {"high": "31", "medium": "33", "low": "36"}
    n = score(findings)
    bar = "#" * (n // 5) + "." * (20 - n // 5)
    lines = ["", paint("AGENT POWER SCORE: %d/100 (%s)" % (n, label(n)), "1"), "[%s]" % bar, ""]
    lines.append("Scanned %d config file(s). Findings, most serious first:" % len(scanned))
    if not findings:
        lines.append("  None found. Your agents look tightly scoped.")
    for f in findings[:12]:
        lines.append("  %s %s" % (paint("[%s]" % f["severity"].upper().ljust(6), col[f["severity"]]), f["reason"]))
        lines.append("           in %s" % f["where"])
    if len(findings) > 12:
        lines.append("  ... and %d more (use --json for all)" % (len(findings) - 12))
    lines += ["", "Read-only: nothing was changed and no secret values were printed.", ""]
    return "\n".join(lines)


def run(args):
    from .. import core
    findings, scanned = scan(os.path.abspath(args.home), os.path.abspath(args.dir))
    n = score(findings)
    if args.json:
        print(json.dumps({"score": n, "level": label(n), "scanned": scanned,
                          "findings": findings}, indent=2))
    else:
        print(render(findings, scanned, False))
    if not args.no_record:  # the audit itself never writes outside the ledger
        core.append(core.default_path(args.ledger), "agent-ledger",
                    "audit: power score %d/100 (%s), %d findings, %d files scanned"
                    % (n, label(n), len(findings), len(scanned)),
                    0.0, [])
    return 0


def register(subparsers):
    p = subparsers.add_parser("audit", help="read-only check of agent permissions")
    p.add_argument("--json", action="store_true")
    p.add_argument("--home", default=os.path.expanduser("~"))
    p.add_argument("--dir", default=os.getcwd())
    p.add_argument("--no-record", action="store_true",
                   help="do not write the result to the ledger")
    p.set_defaults(func=run)
