"""policy plugin: per-rule deny / ask / allow for tool calls (Claude Code PreToolUse hook).

Each rule has an `action`:
  deny  - exit 2 + reason on stderr (the call is blocked)
  ask   - exit 0 + PreToolUse JSON on stdout (Claude Code prompts the human)
  allow - exit 0, logged only
Rules may carry exceptions (`allow_paths`, `allow_agents`, `allow_commands`, or an
`allow` list of {paths, agents, commands} objects whose keys must ALL match) and a
`redact_output_note` that is appended to the reason shown to the human/agent.
Every decision is appended to the signed ledger chain.

Fail-closed: bad/oversized/non-JSON input, wrong types, a broken policy file or
any internal error -> exit 2 (blocked), logged when possible. `--fail-open`
restores the old "allow on error" behaviour.

Self-protection (hard-coded, not overridable by policy.json): the tool refuses
writes to its own control files (policy, ledger, sigs, state, keys,
allowed_signers, ~/.agent-ledger, Claude Code settings and hooks) and asks
before reads. Shell parsing is HEURISTIC (see SECURITY.md): it catches common
forms and asks a human when a command is too complex to judge.
A policy file without a "rules" list uses the legacy flat keys, all as deny.
"""
import fnmatch
import glob as _glob
import json
import os
import re
import subprocess
import sys

from .. import core, shellparse
from . import signing

MAX_INPUT = 1024 * 1024          # hook payloads above this are denied unread
MAX_CMD_PARSE = 20000            # longer commands are not parsed: ask a human

SECRET_PATHS = [".env", ".env.*", "*.env", "*.pem", "*.key", "*.p12", "*.pfx",
                "id_rsa", "id_ed25519", "id_ecdsa", "id_dsa", "credentials",
                "credentials.json", ".git-credentials", ".npmrc", ".netrc",
                "~/.ssh", "~/.aws", "~/.kube", "~/.gnupg", "~/.config/gh",
                "/proc/*/environ"]
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
READ_TOOLS = {"Read", "Grep", "Glob", "NotebookRead", "LS"}
WRITE_TOOLS = {"Write", "Edit", "MultiEdit", "NotebookEdit"}
KNOWN_TOOLS = READ_TOOLS | WRITE_TOOLS | {"Bash", "BashOutput", "KillShell", "TodoWrite"}
NET_CMDS = {"curl", "wget", "nc", "ncat", "netcat", "scp", "sftp", "rsync", "ftp", "socat"}
WRITE_CMDS = {"rm", "mv", "tee", "touch", "chmod", "chown", "dd", "ln", "truncate",
              "install", "shred", "rmdir", "unlink"}
READ_ONLY_CMDS = {"cat", "less", "more", "head", "tail", "ls", "stat", "file", "wc",
                  "grep", "egrep", "fgrep", "rg", "ag", "diff", "cmp", "jq", "nl",
                  "tac", "od", "xxd", "hexdump", "strings", "md5sum", "shasum",
                  "sha256sum", "cksum", "realpath", "readlink", "du", "bat", "view",
                  "sort", "uniq", "cut", "sed", "echo", "printf", "test", "["}
RECURSIVE_READERS = {"rg", "ag", "ack", "tar", "zip", "7z", "7za"}
DELETERS = {"rm", "shred", "unlink", "rmdir"}
ENV_DUMPERS = {"printenv"}
SECRET_EXTRA = re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----")
# '^[A-Z_]*=' style: anchored character classes ending in '=' (names only).
NAME_PAT = re.compile(r"^\^?(\[[A-Za-z0-9_-]+\][*+]?)+=?$")
AWK_PROG = re.compile(r"^\{\s*print\s+\$1\s*\}$")
SED_PROG = re.compile(r"^s/=\.\*\$?//p?$")
WRITE_NAME = re.compile(r"(write|edit|delete|remove|create|move|rename|update|put|patch|"
                        r"append|mkdir|exec|run|shell|command|upload|save|copy)", re.I)
TOP_DIRS = {"/", "/users", "/home", "/etc", "/usr", "/var", "/tmp", "/private", "/bin",
            "/sbin", "/lib", "/lib64", "/opt", "/system", "/library", "/applications",
            "/volumes", "/root", "/boot", "/dev", "/proc", "/srv", "/mnt", "/media",
            "/private/var", "/private/tmp", "/private/etc"}
CRITICAL_PREFIXES = ("/etc", "/usr", "/bin", "/sbin", "/lib", "/boot", "/system",
                     "/library", "/applications", "/private/etc", "/root", "/dev",
                     "/opt")
BLOB_SKIP = {".git", "node_modules", ".venv", "venv", "__pycache__"}
INLINE_FLAGS = {"-c", "-e", "-r", "-E", "--eval", "-p", "-pe", "-ne"}
CODE_FETCH = re.compile(r"urlopen|urllib|requests\.|http\.client|socket|curl|wget|fetch\(")
CODE_EXEC = re.compile(r"\bexec\b|\beval\b|\bsystem\b|popen|subprocess|child_process")
CODE_DELETE = re.compile(r"rmtree|unlink|\.remove\(|rmdir|os\.system|subprocess|child_process|"
                         r"\brm\s+-|shutil|File\.delete|FileUtils|exec\(")


def policy_path(path=None):
    return os.path.abspath(os.path.expanduser(
        path or os.environ.get("AGENT_LEDGER_POLICY")
        or "~/.agent-ledger/policy.json"))


_NUM = (int, float)
_TOP_TYPES = {
    "version": ((int,), False), "rules": ((list,), False),
    "safe_env_read": ((bool,), False), "block_secret_patterns": ((bool,), False),
    "block_rm_outside_project": ((bool,), False), "block_pipe_to_shell": ((bool,), False),
    "require_session": ((bool,), False), "max_cost_usd": (_NUM, True),
    "max_cost_usd_per_day": (_NUM, True), "block_paths": ((list,), False),
    "allow_paths": ((list,), False), "block_force_push_branches": ((list,), False),
    "comment": ((str,), False), "$comment": ((str,), False),
}
_RULE_LISTS = ("paths", "allow_paths", "allow_agents", "allow_commands", "branches")
_RULE_KEYS = set(_RULE_LISTS) | {"id", "kind", "action", "allow", "reason",
                                 "redact_output_note", "comment", "$comment"}


def _strlist(v, what):
    if not isinstance(v, list) or not all(isinstance(x, str) for x in v):
        raise ValueError("%s must be a list of strings" % what)


def validate_policy(pol):
    """Raise ValueError on unknown keys or wrong types (caller fails closed)."""
    for k, v in pol.items():
        if k not in _TOP_TYPES:
            raise ValueError("unknown policy key '%s'" % k)
        types, nullable = _TOP_TYPES[k]
        if v is None and nullable:
            continue
        if isinstance(v, bool) and bool not in types:
            raise ValueError("policy key '%s' has the wrong type" % k)
        if not isinstance(v, types):
            raise ValueError("policy key '%s' has the wrong type" % k)
        if isinstance(v, float) and v != v:
            raise ValueError("policy key '%s' is not a number" % k)
        if isinstance(v, _NUM) and not isinstance(v, bool) and v < 0:
            raise ValueError("policy key '%s' must not be negative" % k)
    for k in ("block_paths", "allow_paths", "block_force_push_branches"):
        if k in pol:
            _strlist(pol[k], k)


def load_policy(path=None):
    """Policy file merged over defaults; missing file -> defaults."""
    pol = dict(DEFAULT_POLICY)
    p = policy_path(path)
    if os.path.exists(p):
        if os.path.getsize(p) > MAX_INPUT:
            raise ValueError("policy file is larger than 1 MB")
        with open(p) as f:
            data = json.load(f)
        if not isinstance(data, dict):
            raise ValueError("policy must be a JSON object")
        pol.update(data)
    validate_policy(pol)
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
            if not isinstance(r["id"], str):
                raise ValueError("rule %d: id must be a string" % i)
            if r.get("action") not in SEVERITY:
                raise ValueError("rule '%s': action must be deny, ask or allow" % r["id"])
            if r.get("kind") not in KINDS:
                raise ValueError("rule '%s': unknown kind '%s'" % (r["id"], r.get("kind")))
            for k in r:
                if k not in _RULE_KEYS:
                    raise ValueError("rule '%s': unknown key '%s'" % (r["id"], k))
            for k in _RULE_LISTS:
                if k in r:
                    _strlist(r[k], "rule '%s' %s" % (r["id"], k))
            for k in ("reason", "redact_output_note"):
                if k in r and not isinstance(r[k], str):
                    raise ValueError("rule '%s': %s must be a string" % (r["id"], k))
            al = r.get("allow", [])
            if not isinstance(al, list) or not all(isinstance(x, dict) for x in al):
                raise ValueError("rule '%s': allow must be a list of objects" % r["id"])
            for x in al:
                for k, v in x.items():
                    if k not in ("paths", "agents", "commands"):
                        raise ValueError("rule '%s': unknown allow key '%s'" % (r["id"], k))
                    _strlist(v, "rule '%s' allow.%s" % (r["id"], k))
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


# ---- path handling ---------------------------------------------------------

def _home():
    return os.path.expanduser("~")


def _canon(p):
    """Absolute, symlink-resolved, alias-stripped, case-folded path."""
    try:
        p = os.path.realpath(p)
    except (OSError, ValueError):
        p = os.path.abspath(p)
    p = re.sub(r"^/System/Volumes/Data(?=/|$)", "", p) or "/"
    return p.casefold()


_VAR = re.compile(r"\$\{(\w+)\}|\$(\w+)")


def _expand(s, cwd, env=None):
    """Expand ~, $HOME, $PWD, $(pwd) and tracked variables. None if anything
    unresolved ($VAR, `cmd`, $(cmd)) remains."""
    env = env or {}
    s = s.replace(shellparse.SUB_OPEN + "pwd" + shellparse.SUB_CLOSE, cwd)

    def rep(m):
        name = m.group(1) or m.group(2)
        if name == "HOME":
            return _home()
        if name == "PWD":
            return cwd
        return env.get(name, m.group(0))
    s = _VAR.sub(rep, s)
    s = os.path.expanduser(s)
    if "$" in s or "`" in s or shellparse.SUB_OPEN in s:
        return None
    return os.path.normpath(os.path.join(cwd, s))


def _is_glob(s):
    return any(c in s for c in "*?[")


def _name_match(part, pat):
    return fnmatch.fnmatch(part.casefold(), pat.casefold())


def match_path(raw, patterns, cwd, project=None, env=None):
    """Return the first pattern matching this path, else None.
    Patterns: 'name' globs match any path component (case-insensitive);
    '~/x', '/abs' and '{project}/x' are anchored (prefix match, or glob if they
    contain * ? [). Paths are symlink-resolved; globs in the path are expanded
    against the filesystem and also compared by name."""
    if not raw or not isinstance(raw, str):
        return None
    if raw.startswith("file://"):
        raw = raw[7:]
    p = _expand(raw, cwd, env)
    if p is None:
        return None
    cands = [p]
    if _is_glob(p):
        cands += _glob.glob(p)[:200]
    info = []
    for c in cands:
        cc = _canon(c)
        info.append((cc, [x for x in c.split(os.sep) if x] + [x for x in cc.split(os.sep) if x]))
    for pat in patterns or []:
        if "{project}" in pat:
            pat = pat.replace("{project}", project or cwd)
        anchored = "/" in pat or pat.startswith("~")
        root = _canon(os.path.expanduser(pat)) if anchored else None
        for cc, parts in info:
            if anchored:
                if cc == root or cc.startswith(root.rstrip("/") + "/") or fnmatch.fnmatch(cc, root):
                    return pat
            elif any(_name_match(part, pat) for part in parts):
                return pat
        if not anchored and _is_glob(p) and not _is_glob(pat):
            if _name_match(pat, os.path.basename(p)):  # '.e*' can name '.env'
                return pat
    return None


def allow_match(raw, patterns, cwd, project=None, env=None):
    """Like match_path for allow-lists, but a glob (.env*) is waived only if every
    file it expands to is allowed (so '.env*' cannot hide behind '.env.example')."""
    p = _expand(raw, cwd, env) if isinstance(raw, str) and raw else None
    if p is not None and _is_glob(p):
        hits = _glob.glob(p)[:200]
        if not hits or not all(match_path(h, patterns, cwd, project) for h in hits):
            return None
        return patterns[0] if patterns else None
    return match_path(raw, patterns, cwd, project, env)


def path_blocked(raw, pol, cwd):
    """Legacy helper: matching block rule if this path is blocked, else None."""
    p = _expand(raw, cwd) if isinstance(raw, str) and raw else None
    if p is None:
        return None
    if allow_match(raw, pol.get("allow_paths", []), cwd):
        return None
    return match_path(raw, pol.get("block_paths", []), cwd)


def _dir_has_secret(d, patterns, allow, cwd, project):
    """First secret-looking file name below directory d (bounded walk), else None."""
    seen = 0
    base_depth = d.rstrip(os.sep).count(os.sep)
    try:
        for root, dirs, files in os.walk(d):
            dirs[:] = [x for x in dirs if x not in BLOB_SKIP]
            if root.count(os.sep) - base_depth >= 4:
                dirs[:] = []
            for name in files + dirs:
                seen += 1
                if seen > 3000:
                    return None
                full = os.path.join(root, name)
                if match_path(full, patterns, cwd, project) and not (
                        allow and match_path(full, allow, cwd, project)):
                    return full
    except OSError:
        return None
    return None


# ---- self protection -------------------------------------------------------

_PROT_SUFFIX = re.compile(r"/\.claude/settings[^/]*\.json$|/\.claude/hooks(/|$)|"
                          r"/allowed_signers$")
NEEDLES = [".agent-ledger", ".claude/settings", ".claude/hooks", "allowed_signers"]


def protected_set(ledger, policy_file):
    """(roots, needles): control files the agent may not modify."""
    roots = [os.path.join(_home(), ".agent-ledger"), ledger, ledger + ".sigs",
             ledger + ".state", policy_file, signing.keys_dir()]
    needles = list(NEEDLES) + [x.casefold() for x in roots]
    return [_canon(r) for r in roots], needles


def protected_hit(raw, cwd, roots, env=None):
    """Label of the control file this path points at, else None."""
    if not raw or not isinstance(raw, str):
        return None
    if raw.startswith("file://"):
        raw = raw[7:]
    p = _expand(raw, cwd, env)
    if p is None:
        return None
    for c in [p] + (_glob.glob(p)[:200] if _is_glob(p) else []):
        cc = _canon(c)
        for r in roots:
            if cc == r or cc.startswith(r.rstrip("/") + "/"):
                return r
        if _PROT_SUFFIX.search(cc):
            return "agent-ledger/Claude Code control file"
    return None


# ---- command analysis ------------------------------------------------------

def _safe_root(project, cwd):
    """Canonical project root, or None when it is too broad to trust
    (/, $HOME, /Users, /etc ...). Falls back to cwd if that is usable."""
    home = _canon(_home())
    for cand in (project, cwd):
        r = _canon(cand) if cand else None
        if r and r != home and r not in TOP_DIRS:
            return r
    return None


def _inside(p, root):
    return p == root or p.startswith(root.rstrip("/") + "/")


def _targets(args):
    out, after = [], False
    for t in args:
        if after or not t.startswith("-"):
            out.append(t)
        elif t == "--":
            after = True
    return out


def _critical(p):
    home = _canon(_home())
    if _inside(p, home):
        rel = p[len(home):].lstrip("/")
        return rel.startswith(".")
    return any(_inside(p, c) for c in CRITICAL_PREFIXES)


def _delete_reason(targets, recursive, cwd, project, what="rm -rf", env=None):
    root = _safe_root(project, cwd)
    home = _canon(_home())
    for t in targets:
        p = _expand(t, cwd, env)
        if p is None:
            return "%s target '%s' uses an unresolved variable" % (what, t)
        cp = _canon(p)
        if cp == "/" or cp == home:
            return "%s on '%s' (root or home)" % (what, t)
        in_proj = root is not None and _inside(cp, root)
        if recursive and not in_proj:
            return "%s target '%s' is outside the project dir" % (what, t)
        if not recursive and not in_proj and _critical(cp):
            return "%s deletes critical file '%s' outside the project dir" % (what, t)
    return None


def check_rm(tokens, cwd, project, env=None):
    """tokens: an argv. Handles rm, shred, unlink, find -delete/-exec rm,
    rsync --delete, git clean, mv X /dev/null."""
    if not tokens:
        return None
    b = shellparse.base(tokens[0])
    args = tokens[1:]
    if b in DELETERS:
        flags = [t for t in args if t.startswith("-") and t != "--"]
        recursive = b == "shred" or b == "rm" and any(
            t == "--recursive" or (not t.startswith("--") and ("r" in t or "R" in t))
            for t in flags)
        return _delete_reason(_targets(args), recursive, cwd, project,
                              "rm -rf" if recursive else b, env)
    if b == "mv":
        pos = _targets(args)
        if len(pos) >= 2 and pos[-1] == "/dev/null":
            return _delete_reason(pos[:-1], True, cwd, project, "mv to /dev/null", env)
        return None
    if b == "find":
        starts = []
        for a in args:
            if a.startswith("-") or a in ("(", "!", ")"):
                break
            starts.append(a)
        starts = starts or ["."]
        bad = "-delete" in args
        for k, a in enumerate(args):
            if a in ("-exec", "-execdir", "-ok", "-okdir"):
                inner = args[k + 1:k + 2]
                if inner and shellparse.base(inner[0]) in DELETERS:
                    bad = True
        return _delete_reason(starts, True, cwd, project, "find -delete/-exec rm", env) if bad else None
    if b == "rsync":
        if any(a.startswith("--delete") or a == "--remove-source-files" for a in args):
            pos = _targets(args)
            if pos:
                return _delete_reason([pos[-1]], True, cwd, project, "rsync --delete", env)
        return None
    if b == "git":
        sub, rest, _alias, cdir = _git_parse(args)
        if sub == "clean":
            flags = "".join(a[1:] for a in rest if a.startswith("-") and not a.startswith("--"))
            if "f" in flags or "--force" in rest:
                if "x" in flags or "X" in flags:
                    return "git clean -x deletes ignored files such as .env"
                if "d" in flags:
                    return _delete_reason([cdir or "."], True, cwd, project, "git clean -fd", env)
    return None


_GIT_ARG_OPTS = {"-C", "-c", "--git-dir", "--work-tree", "--namespace", "--exec-path",
                 "--super-prefix", "--config-env"}


def _git_parse(args):
    """-> (subcommand, rest_args, alias_flag, -C dir)"""
    i, alias, cdir = 0, False, None
    while i < len(args):
        a = args[i]
        if a in _GIT_ARG_OPTS and i + 1 < len(args):
            if a == "-c" and args[i + 1].lower().startswith("alias."):
                alias = True
            if a == "-C":
                cdir = args[i + 1]
            i += 2
        elif a.startswith("-"):
            i += 1
        else:
            break
    sub = args[i] if i < len(args) else ""
    rest = args[i + 1:]
    if sub == "config" and any(x.lower().startswith("alias.") for x in rest):
        alias = True
    return sub, rest, alias, cdir


def _current_branch(cwd):
    try:
        r = subprocess.run(["git", "symbolic-ref", "--short", "-q", "HEAD"], cwd=cwd,
                           stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, timeout=2)
        out = r.stdout.decode("utf-8", "replace").strip()
        return out or None
    except (OSError, subprocess.SubprocessError, ValueError):
        return None


def check_push(tokens, branches, cwd=None):
    if len(tokens) < 2 or shellparse.base(tokens[0]) != "git":
        return None
    sub, rest, alias, _ = _git_parse(tokens[1:])
    branches = branches or []
    if alias:
        return "git alias definition could hide a force push"
    if sub != "push":
        return None
    force = any(t in ("--force", "-f") or t.startswith("--force") or
                (t.startswith("-") and not t.startswith("--") and "f" in t)
                for t in rest)
    if "--mirror" in rest:
        return "git push --mirror overwrites remote branches"
    pos = [t for t in rest if not t.startswith("-")]
    delete = "--delete" in rest or "-d" in rest
    refs = pos[1:]
    if not (force or delete or any(r.startswith("+") or r.startswith(":") for r in refs)):
        return None
    if force and not refs:
        return "force push without an explicit branch (could be %s)" % "/".join(branches)
    for r in refs:
        forced = force or r.startswith("+")
        dst = r.lstrip("+").split(":")[-1]
        deleting = delete or (r.lstrip("+").startswith(":"))
        if not (forced or deleting):
            continue
        dst = dst[len("refs/heads/"):] if dst.startswith("refs/heads/") else dst
        if dst in ("HEAD", "@"):
            cur = _current_branch(cwd or os.getcwd())
            if cur is None or cur in branches:
                return "force push of HEAD (current branch %s) to a protected branch" % (cur or "unknown")
            continue
        if any(fnmatch.fnmatch(b, dst) for b in branches):
            return "%s protected branch '%s'" % ("delete of" if deleting and not forced else "force push to", dst)
    return None


def _fetcher_in(cmds):
    for c in cmds:
        inner, strings, _ = shellparse.unwrap(c.words)
        if inner and shellparse.base(inner[0]) in shellparse.FETCH:
            return True
    return False


def _exec_target(seg):
    """True if this command would execute what it is fed / given."""
    b = seg["base"]
    if shellparse.is_interp(b):
        args = seg["inner"][1:]
        if shellparse.is_python(b) and args[:2] == ["-m", "json.tool"]:
            return False
        return True
    first = seg["inner"][0] if seg["inner"] else ""
    return first.startswith("$") or shellparse.SUB_OPEN in first


def pipe_to_shell_reason(ctx):
    """Why this command downloads and executes, else None."""
    segmap = ctx.segmap
    for pl in ctx.parsed.pipelines:
        for k, cmd in enumerate(pl):
            sg = segmap.get(id(cmd))
            if sg and sg["base"] in shellparse.FETCH:
                for later in pl[k + 1:]:
                    lg = segmap.get(id(later))
                    if lg and _exec_target(lg):
                        return "piping a download into a shell (curl|sh) is blocked"
    outs = set()
    for sg in ctx.segs:
        cmd, b, w = sg["cmd"], sg["base"], sg["inner"]
        if _exec_target(sg) and cmd.sub_cmds and _fetcher_in(cmd.sub_cmds):
            return "executing a downloaded script (shell fed by a download) is blocked"
        if b in shellparse.FETCH:
            for k, a in enumerate(w):
                if a in ("-o", "--output") and k + 1 < len(w):
                    outs.add(w[k + 1])
                elif a == "-O" and b == "wget" and k + 1 < len(w):
                    outs.add(w[k + 1])
                elif a == "-O" and b == "curl":
                    outs.update(os.path.basename(x) for x in w if "/" in x and not x.startswith("-"))
                elif a.startswith("-o") and len(a) > 2 and not a.startswith("--"):
                    outs.add(a[2:])
            for op, tgt in sg["redirs"]:
                if op in (">", ">>", ">|"):
                    outs.add(tgt)
        elif outs and w and (_exec_target(sg) or w[0] in outs):
            if any(a in outs or os.path.basename(a) in outs or os.path.normpath(a) in outs
                   for a in w):
                return "executing a file downloaded earlier in the same command is blocked"
        if shellparse.is_python(b) or b in ("perl", "ruby", "node", "nodejs", "php", "lua"):
            code = " ".join(w[1:])
            if any(f in w[1:] for f in INLINE_FLAGS) and CODE_FETCH.search(code) \
                    and CODE_EXEC.search(code):
                return "inline code downloads and executes (blocked)"
    return None


def _cands(word):
    """Strings inside one shell word that may be file paths (-d@f, f=@f, h:p)."""
    out = [word]
    if word.startswith("-") and word != "-":
        if word.startswith("--"):
            if "=" in word:
                out.append(word.split("=", 1)[1])
        elif len(word) > 2:
            out.append(word[2:])
    for x in list(out):
        for sep in ("=", ":", "@"):
            if sep in x:
                out.append(x.split(sep, 1)[1])
    res = []
    for x in out:
        x = x.lstrip("@<>")
        if x and not x.startswith("-") and x not in res:
            res.append(x)
    return res


def _seg_paths(seg, base_b):
    """[(candidate_path, mode)] for one simple command."""
    words, inner = seg["words"], seg["inner"]
    sed_i = base_b == "sed" and any(
        t == "--in-place" or (t.startswith("-i") and not t.startswith("--")) for t in inner[1:])
    wmode = base_b in WRITE_CMDS or sed_i
    pos = [i for i, t in enumerate(words) if not t.startswith("-")]
    paths = []
    for i, tok in enumerate(words):
        mode = "write" if wmode else "read"
        if base_b in ("cp", "install") and pos and i == pos[-1]:
            mode = "write"
        for c in _cands(tok):
            paths.append((c, mode))
    for op, tgt in seg["redirs"]:
        if op in ("<<<", "<<", "<<-"):
            continue
        if op in (">&", "<&") and (tgt.isdigit() or tgt == "-"):
            continue
        for c in _cands(tgt):
            paths.append((c, "read" if op == "<" else "write"))
    return paths


def _tool_mode(tool):
    return "write" if tool in WRITE_TOOLS else "read"


def _leaves(obj, out, depth=0):
    if len(out) > 500 or depth > 6:
        return
    if isinstance(obj, str):
        out.append(obj)
    elif isinstance(obj, dict):
        for v in obj.values():
            _leaves(v, out, depth + 1)
    elif isinstance(obj, (list, tuple)):
        for v in obj:
            _leaves(v, out, depth + 1)


class Ctx(object):
    pass


def _track_env(seg_words, env, cwd):
    """Update simple VAR=literal tracking; True if these words were only assignments."""
    ws = list(seg_words)
    if ws and shellparse.base(ws[0]) in ("export", "local", "declare", "readonly", "typeset"):
        ws = ws[1:]
    if not ws or not all(shellparse.ASSIGN.match(w) for w in ws):
        return False
    for w in ws:
        k, v = w.split("=", 1)
        v2 = _expand_vars(v, env, cwd)
        if shellparse.SUB_OPEN not in v2 and "$" not in v2:
            env[k] = v2
    return True


def _expand_vars(w, env, cwd):
    w = w.replace(shellparse.SUB_OPEN + "pwd" + shellparse.SUB_CLOSE, cwd)

    def rep(m):
        name = m.group(1) or m.group(2)
        if name == "HOME":
            return _home()
        if name == "PWD":
            return cwd
        return env.get(name, m.group(0))
    return _VAR.sub(rep, w)


def build_ctx(payload, pol, rules, agent, ledger=None, policy_file=None):
    c = Ctx()
    c.tool = str(payload.get("tool_name", "unknown"))
    ti = payload.get("tool_input")
    c.ti = ti if isinstance(ti, dict) else {}
    cwd = payload.get("cwd")
    c.cwd = cwd if isinstance(cwd, str) and cwd else os.getcwd()
    c.project = os.environ.get("CLAUDE_PROJECT_DIR") or c.cwd
    c.agent = agent
    c.ledger = ledger or core.default_path()
    c.roots, c.needles = protected_set(c.ledger, policy_file or policy_path())
    c.files, c.tool_paths, c.segs, c.safe, c.complex = [], [], [], [], []
    c.segmap, c.parsed, c.extra_hits, c.unresolved = {}, None, [], []
    c.search_dirs, c.glob_names = [], []
    c.generic = c.tool not in KNOWN_TOOLS
    if not c.generic:
        for k in PATH_KEYS:
            v = c.ti.get(k)
            if isinstance(v, str):
                c.files.append(v)
                c.tool_paths.append((v, _tool_mode(c.tool)))
        if c.tool in ("Grep", "Glob"):
            for k in ("glob", "pattern"):
                v = c.ti.get(k)
                if isinstance(v, str) and (k == "glob" or c.tool == "Glob"):
                    c.glob_names.append(v)
            base_dir = c.ti.get("path") if isinstance(c.ti.get("path"), str) else c.cwd
            if c.tool == "Grep" and not c.glob_names:
                c.search_dirs.append(base_dir)
    else:
        leaves = []
        _leaves(c.ti, leaves)
        mode = "write" if WRITE_NAME.search(c.tool) else "read"
        for s_ in leaves:
            if "\n" not in s_ and len(s_) < 2048 and s_.strip():
                c.files.append(s_)
                c.tool_paths.append((s_.strip(), mode))
            if len(s_) < 20000 and ("secret" in c.tool.lower() or c.tool == "Task"):
                c.tool_paths.extend((tok, "read") for tok in _inline_tokens(s_))
    c.cmd = c.ti.get("command") if isinstance(c.ti.get("command"), str) else ""
    all_pats = [p for r in rules if r["kind"].startswith("path_") or r["kind"] == "net_exfil"
                for p in r.get("paths", [])]
    c.all_pats = all_pats
    if not c.cmd:
        return c
    if len(c.cmd) > MAX_CMD_PARSE:
        c.complex.append("command is too long to analyze (%d chars)" % len(c.cmd))
        return c
    parsed = shellparse.parse(c.cmd)
    c.parsed = parsed
    c.complex.extend(parsed.complex)
    env, i = {}, 0
    while i < len(parsed.cmds):
        cmd = parsed.cmds[i]
        i += 1
        words = [_expand_vars(w, env, c.cwd) for w in cmd.words]
        redirs = [(op, _expand_vars(w, env, c.cwd)) for op, w in cmd.redirs]
        if _track_env(words, env, c.cwd):
            continue
        inner, strings, wrappers = shellparse.unwrap(words)
        for s_ in strings:
            sub = shellparse.parse(s_, cmd.depth + 1)
            parsed.merge(sub, cmd.depth + 1)
        b = shellparse.base(inner[0]) if inner else ""
        if shellparse.is_shell(b) and cmd.heredocs:
            for body in cmd.heredocs:
                parsed.merge(shellparse.parse(body, cmd.depth + 1), cmd.depth + 1)
        if inner and (inner[0].startswith("$") or shellparse.SUB_OPEN in inner[0]):
            c.complex.append("command name '%s' is not a literal" % inner[0].replace(
                shellparse.SUB_OPEN, "$(").replace(shellparse.SUB_CLOSE, ")"))
        seg = {"cmd": cmd, "words": words, "redirs": redirs, "inner": inner,
               "base": b, "wrappers": wrappers, "heredocs": cmd.heredocs}
        if not inner and "env" in wrappers:
            c.extra_hits.append({"action": "ask", "rule": "env-dump",
                                 "reason": "dumps the environment (may contain secrets)"})
        if b in ENV_DUMPERS or (b in ("set", "export", "declare") and len(inner) <= 2
                                and not any(shellparse.ASSIGN.match(a) for a in inner[1:])
                                and (b == "set" and len(inner) == 1 or "-p" in inner[1:])):
            c.extra_hits.append({"action": "ask", "rule": "env-dump",
                                 "reason": "dumps the environment (may contain secrets)"})
        if pol.get("safe_env_read", False) and inner and safe_env_names(inner):
            files = [t for t in inner[1:] if not t.startswith("-")]
            hit = [f for f in files if match_path(f, all_pats, c.cwd, c.project, env)]
            if hit:
                c.safe.append(hit[0])
                continue
        seg["paths"] = _seg_paths(seg, b)
        seg["env"] = dict(env)
        c.segs.append(seg)
        c.segmap[id(cmd)] = seg
    # decode-and-run obfuscation, and un-analyzable inline code
    for pl in parsed.pipelines:
        names = []
        for cmd in pl:
            sg = c.segmap.get(id(cmd))
            if sg:
                names.append(sg["base"])
                if sg["base"] == "base64" and any(a in ("-d", "-D", "--decode") for a in sg["inner"]):
                    c.complex.append("decodes data in a pipeline (obfuscation cannot be analyzed)")
                if sg["base"] == "xxd" and "-r" in sg["inner"]:
                    c.complex.append("decodes data in a pipeline (obfuscation cannot be analyzed)")
    for sg in c.segs:
        b = sg["base"]
        args = sg["inner"][1:]
        if (shellparse.is_python(b) or b in ("perl", "ruby", "node", "nodejs", "php", "lua")) \
                and any(a in INLINE_FLAGS or (a.startswith("-") and a[1:2] in ("c", "e") and len(a) > 2)
                        for a in args):
            code = " ".join(args)
            for tok in _inline_tokens(code):
                sg["paths"].append((tok, "read"))
            if CODE_DELETE.search(code):
                c.complex.append("inline %s code may delete files (cannot be analyzed)" % b)
        if b in RECURSIVE_READERS or (b in ("grep", "egrep", "fgrep") and any(
                a in ("-r", "-R", "--recursive") or (a.startswith("-") and not a.startswith("--")
                                                     and ("r" in a or "R" in a)) for a in args)) or (
                b in ("cp", "scp", "rsync") and any(
                a.startswith("-") and not a.startswith("--") and any(x in a for x in "rRa")
                or a in ("--recursive", "--archive") for a in args)):
            dirs = [a for a in _targets(args) if os.path.isdir(_expand(a, c.cwd, sg["env"]) or "/nonexistent")]
            if not dirs and b in ("rg", "ag", "ack", "grep", "egrep", "fgrep") and not [
                    a for a in _targets(args)][1:]:
                dirs = ["."]
            for d in dirs:
                p = _expand(d, c.cwd, sg["env"])
                if p:
                    c.search_dirs.append(p)
    return c


def _inline_tokens(code):
    return [t for t in re.split(r"[\s'\"()\[\],;=<>|&{}`]+", code) if t and len(t) < 512][:400]


# ---- env-file "names only" reads -------------------------------------------

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



def _waived(rule, ctx, raw=None):
    """Return a description of the exception that waives this rule, else None."""
    cmd = ctx.cmd
    pats = rule.get("allow_paths")
    if pats and raw and allow_match(raw, pats, ctx.cwd, ctx.project):
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
            ok = ok and bool(raw and allow_match(raw, ex["paths"], ctx.cwd, ctx.project))
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


READERS_FILE = (READ_ONLY_CMDS - {"echo", "printf", "test", "["}) | {
    "cp", "mv", "tar", "base64", "xxd", "source", ".", "open", "scp", "rsync", "xargs",
    "zip", "unzip", "tee", "vim", "nano", "code"}
PATHISH = re.compile(r"^[~/.$\x01]|/")


def _rel_names(ctx):
    names = {os.path.basename(r) for r in ctx.roots if "." in os.path.basename(r)}
    names |= {"policy.json", "ledger.jsonl", "allowed_signers", "id_ed25519"}
    return names


def protect_hits(ctx):
    """Hard-coded self-protection of the tool's own control files."""
    hits = []

    def add(action, what, how):
        hits.append({"action": action, "rule": "self-protect",
                     "reason": "%s of control file '%s' is blocked: agent-ledger protects "
                               "its own policy, ledger, keys and the Claude Code hook "
                               "settings (%s)" % (how, what, "writes denied, reads ask")})
    for raw, mode in ctx.tool_paths:
        if protected_hit(raw, ctx.cwd, ctx.roots):
            add("deny" if mode == "write" else "ask", raw, "write" if mode == "write" else "read")
        elif ctx.generic and any(n in raw.casefold() for n in ctx.needles):
            add("deny" if mode == "write" else "ask", raw, "write" if mode == "write" else "read")
    moved = False
    rel = _rel_names(ctx)
    for sg in ctx.segs:
        b = sg["base"]
        text = " ".join(sg["words"] + [t for _, t in sg["redirs"]] + sg["heredocs"]).casefold()
        words = sg["words"]
        for k, w in enumerate(words):
            if shellparse.base(w) in ("agent-ledger", "agent_ledger"):
                rest = [x.lower() for x in words[k + 1:]]
                if "keygen" in rest or "sign" in rest or ("policy" in rest and "init" in rest):
                    hits.append({"action": "deny", "rule": "self-protect",
                                 "reason": "agents may not run agent-ledger key or policy "
                                           "management (keygen, sign, policy init)"})
                break
        pathhit, wmode = None, False
        for cand, mode in sg["paths"]:
            if protected_hit(cand, ctx.cwd, ctx.roots, sg.get("env")):
                pathhit = pathhit or cand
                wmode = wmode or mode == "write"
            elif moved and (fnmatch.fnmatch(os.path.basename(cand).casefold(), "settings*.json")
                            or os.path.basename(cand) in rel or cand in ("hooks", "keys")):
                pathhit = pathhit or cand
                wmode = wmode or mode == "write"
        readish = b in READ_ONLY_CMDS
        if pathhit:
            add("ask" if (readish and not wmode) else "deny", pathhit,
                "read" if (readish and not wmode) else "change")
        elif any(n in text for n in ctx.needles):
            if shellparse.is_interp(b) or b in WRITE_CMDS or b in ("cp", "rsync", "awk", "perl"):
                add("deny", "(command text)", "change")
            elif readish:
                add("ask", "(command text)", "read")
        if b in ("cd", "pushd") and any(n in text for n in ctx.needles + [".claude"]):
            moved = True
    return hits


def eval_rules(rules, ctx, pol):
    hits = []
    for f in ctx.safe:
        hits.append({"action": "allow", "rule": "safe-env-read",
                     "reason": "names-only read of '%s' (no values printed)" % f})
    hits.extend(ctx.extra_hits)
    hits.extend(protect_hits(ctx))
    for r in dict.fromkeys(ctx.complex):
        hits.append({"action": "ask", "rule": "complex-command",
                     "reason": "unparseable or too complex to judge safely (%s); a human "
                               "should look at this command" % r})
    for sg in ctx.segs:
        if sg["base"] in READERS_FILE:
            for t in sg["words"][1:]:
                if t.startswith("-"):
                    continue
                if (("$" in t or shellparse.SUB_OPEN in t) and PATHISH.search(t)
                        and _expand(t, ctx.cwd, sg.get("env")) is None):
                    hits.append({"action": "ask", "rule": "unresolved-path",
                                 "reason": "path argument '%s' uses a variable or command "
                                           "substitution that cannot be resolved" % t.replace(
                                               shellparse.SUB_OPEN, "$(").replace(
                                               shellparse.SUB_CLOSE, ")")})
                    break
    for rule in rules:
        kind = rule["kind"]
        if kind in ("path_read", "path_write", "path_any"):
            want = {"path_read": "read", "path_write": "write"}.get(kind)
            pats = rule.get("paths")
            for raw, mode in ctx.tool_paths:
                pat = match_path(raw, pats, ctx.cwd, ctx.project)
                if pat and want in (None, mode):
                    hits.append(_hit(rule, "%s of '%s' blocked by path rule '%s'" % (
                        ctx.tool, raw, pat), ctx, raw))
            for seg in ctx.segs:
                for raw, mode in seg["paths"]:
                    pat = match_path(raw, pats, ctx.cwd, ctx.project, seg.get("env"))
                    if pat and want in (None, mode):
                        hits.append(_hit(rule, "command touches '%s' (path rule '%s')" % (
                            raw, pat), ctx, raw))
            if want in (None, "read"):
                for g in ctx.glob_names:
                    gb = os.path.basename(g)
                    for pat in pats or []:
                        if "/" in pat or pat.startswith("~"):
                            continue
                        if _name_match(pat, gb) or (not _is_glob(pat) and _name_match(gb, pat)) \
                                or fnmatch.fnmatch(pat.casefold(), gb.casefold()):
                            hits.append(_hit(rule, "%s glob '%s' can reach secret files "
                                             "(path rule '%s')" % (ctx.tool, g, pat), ctx, pat))
                            break
                for d in ctx.search_dirs:
                    found = _dir_has_secret(d, pats, rule.get("allow_paths"), ctx.cwd, ctx.project)
                    if found:
                        hits.append(_hit(rule, "recursive read of '%s' would reach secret "
                                         "file '%s'" % (d, found), ctx, found))
        elif kind == "net_exfil":
            if any(s["base"] in NET_CMDS for s in ctx.segs):
                for seg in ctx.segs:
                    for raw, _ in seg["paths"]:
                        pat = match_path(raw, rule.get("paths"), ctx.cwd, ctx.project, seg.get("env"))
                        if pat:
                            hits.append(_hit(rule, "command sends secret file '%s' over the "
                                             "network (path rule '%s')" % (raw, pat), ctx, raw))
        elif kind == "rm_outside_project":
            for seg in ctx.segs:
                r = check_rm(seg["inner"], ctx.cwd, ctx.project, seg.get("env"))
                if not r and "xargs" in seg["wrappers"] and seg["base"] in DELETERS \
                        and not _targets(seg["inner"][1:]):
                    r = "%s with targets read from stdin (xargs) cannot be checked" % seg["base"]
                if r:
                    hits.append(_hit(rule, r, ctx))
        elif kind == "force_push":
            for seg in ctx.segs:
                r = check_push(seg["inner"], rule.get("branches") or ["main", "master"], ctx.cwd)
                if r:
                    hits.append(_hit(rule, r, ctx))
        elif kind == "pipe_to_shell":
            r = pipe_to_shell_reason(ctx) if ctx.parsed is not None else None
            if r:
                hits.append(_hit(rule, r, ctx))
    if pol.get("block_secret_patterns", True):
        blob = json.dumps(ctx.ti, ensure_ascii=True)
        if (SECRET_EXTRA.search(blob) or any(p.search(blob) for p in core._PATTERNS)
                or any(p.search(blob) for p in core._EXTRA[:6])):
            hits.append({"action": "deny", "rule": "secret-patterns",
                         "reason": "tool input contains a known secret pattern"})
    return hits


def decide(payload, pol, ledger, agent="claude-code", policy_file=None):
    """Return a decision dict (action, reason, rule, note, files, hits).
    Does not write the ledger. Severity: deny > ask > allow."""
    rules = build_rules(pol)
    ctx = build_ctx(payload, pol, rules, agent, ledger, policy_file)
    hits = eval_rules(rules, ctx, pol)
    cap = pol.get("max_cost_usd")
    sid = payload.get("session_id")
    if cap is not None:
        if sid:
            spent = core.session_cost(ledger, sid)
            if spent > float(cap):
                hits.append({"action": "deny", "rule": "budget",
                             "reason": "session budget exceeded: $%.4f spent > cap $%.4f" % (
                                 spent, float(cap))})
        elif pol.get("require_session"):
            hits.append({"action": "deny", "rule": "budget",
                         "reason": "no session_id in the hook payload, so the cost cap cannot "
                                   "be applied (require_session is on)"})
    dcap = pol.get("max_cost_usd_per_day")
    if dcap is not None:
        spent = core.session_cost_day(ledger)
        if spent > float(dcap):
            hits.append({"action": "deny", "rule": "budget-day",
                         "reason": "daily budget exceeded: $%.4f spent today > cap $%.4f" % (
                             spent, float(dcap))})
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


class _BadInput(Exception):
    pass


def _read_payload(limit=MAX_INPUT):
    """Parse the hook JSON from stdin. Raises _BadInput (caller fails closed)."""
    stream = getattr(sys.stdin, "buffer", sys.stdin)
    raw = stream.read(limit + 1)
    if len(raw) > limit:
        raise _BadInput("input is larger than %d bytes" % limit)
    if isinstance(raw, bytes):
        try:
            raw = raw.decode("utf-8")
        except UnicodeDecodeError:
            raise _BadInput("input is not valid UTF-8")
    if not raw.strip():
        raise _BadInput("empty input")
    try:
        payload = json.loads(raw)
    except (ValueError, RecursionError):
        raise _BadInput("input is not valid JSON")
    if not isinstance(payload, dict):
        raise _BadInput("input is not a JSON object")
    for k, t in (("tool_name", str), ("tool_input", dict), ("cwd", str), ("session_id", str)):
        if k in payload and payload[k] is not None and not isinstance(payload[k], t):
            raise _BadInput("field '%s' has the wrong type" % k)
    return payload


def _fail(args, ledger, reason, payload=None):
    _record(ledger, args.agent, "DENY" if not args.fail_open else "ALLOW",
            reason, payload or {}, [])
    if args.fail_open:
        print("policy-check: %s; allowing because --fail-open is set" % reason, file=sys.stderr)
        return 0
    print("BLOCKED by agent-ledger policy: %s (failing closed; --fail-open turns this "
          "off)" % reason, file=sys.stderr)
    return 2


def cmd_check(args):
    ledger = core.default_path(args.ledger)
    try:
        return _check(args, ledger)
    except BaseException as ex:  # noqa: B902 - fail closed on anything at all
        try:
            return _fail(args, ledger, "internal error (%s: %s)" % (
                type(ex).__name__, str(ex)[:200]))
        except BaseException:
            print("BLOCKED by agent-ledger policy: internal error (failing closed)",
                  file=sys.stderr)
            return 0 if args.fail_open else 2


def _check(args, ledger):
    try:
        payload = _read_payload()
    except _BadInput as ex:
        return _fail(args, ledger, "unusable hook input: %s" % ex)
    try:
        pol = load_policy(args.policy)
    except (ValueError, OSError, RecursionError) as ex:
        reason = "policy file unreadable (%s); failing closed" % ex
        _record(ledger, args.agent, "DENY", reason, payload, [])
        print("BLOCKED: " + reason, file=sys.stderr)
        return 2
    d = decide(payload, pol, ledger, args.agent, policy_path(args.policy))
    reason = full_reason(d)
    wrote = _record(ledger, args.agent, d["action"].upper(), reason, payload, d["files"])
    if d["action"] != "deny" and not wrote and not args.fail_open:
        print("BLOCKED by agent-ledger policy: the audit ledger cannot be written "
              "(corrupt, replaced or unwritable); failing closed so auditing cannot "
              "be silently disabled. Run `agent-ledger verify`. (--fail-open turns "
              "this off)", file=sys.stderr)
        return 2
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
    except _BadInput as ex:
        print("explain: %s" % ex)
        return 1
    try:
        pol = load_policy(args.policy)
    except (ValueError, OSError) as ex:
        print("DENY  rule=policy-file  policy file unreadable (%s); would fail closed" % ex)
        return 0
    d = decide(payload, pol, core.default_path(args.ledger), args.agent, policy_path(args.policy))
    print("%s  rule=%s  agent=%s" % (d["action"].upper(), d["rule"] or "none", args.agent))
    print("why: %s" % (d["reason"] or "no rule matched; allowed by default"))
    if d.get("note") and d["action"] != "allow":
        print("note: %s" % d["note"])
    others = [h for h in d["hits"] if h is not d and h["rule"] != d["rule"]]
    for h in others:
        print("also: %s rule=%s  %s" % (h["action"].upper(), h["rule"], h["reason"]))
    return 0


def _record(ledger, agent, verdict, reason, payload, files):
    """Append the decision to the ledger. Returns False if it could not be written."""
    ti = payload.get("tool_input") if isinstance(payload.get("tool_input"), dict) else {}
    what = ti.get("command") or ti.get("file_path") or ti.get("path") or ""
    # redact BEFORE truncating so a secret straddling the cut is not logged as a prefix
    what = core.neutralize_tags(core.redact(str(what)[:4000]))[:100]
    tool = core.redact(str(payload.get("tool_name", "unknown"))[:80])
    action = "policy:%s %s %s" % (verdict, tool, what)
    if reason:
        action += " -- " + core.neutralize_tags(core.redact(str(reason)[:1500]))
    sid = payload.get("session_id") if isinstance(payload.get("session_id"), str) else None
    if sid:
        action += core.session_tag(sid)
    try:
        core.append(ledger, agent, action, 0.0, [str(x)[:200] for x in files[:5]], session=sid)
        return True
    except (ValueError, OSError) as ex:
        print("policy-check: could not write ledger: %s" % ex, file=sys.stderr)
        return False


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
    p.add_argument("--fail-open", action="store_true",
                   help="UNSAFE opt-out: allow (exit 0) when input is unusable or an "
                        "internal error happens. Default is to block (exit 2).")
    p.set_defaults(func=cmd_check)
    p = subparsers.add_parser("policy", help="policy init | show | explain (payload on stdin)")
    p.add_argument("action", choices=["init", "show", "explain"])
    p.add_argument("--policy")
    p.add_argument("--agent", default="claude-code", help="agent name for explain")
    p.add_argument("--force", action="store_true")
    p.set_defaults(func=cmd_policy)
