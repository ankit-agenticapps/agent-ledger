"""Small, defensive shell lexer used by policy-check. Standard library only.

It is NOT a full shell. It turns a command string into simple commands
(argv words + redirections), following quotes, `$()`, backticks, `<()`,
subshell parens, heredocs and line continuations, so the policy rules can
look at what is really being run. Anything it cannot parse is reported in
`Parsed.complex` so the caller can ask a human instead of guessing.
"""
import os
import re

SUB_OPEN, SUB_CLOSE = "\x01", "\x02"
MAX_DEPTH = 6
MAX_CMDS = 400

KEYWORDS = {"if", "then", "else", "elif", "fi", "while", "until", "do", "done",
            "!", "{", "}", "esac", "function"}
HEADERS = {"for", "select", "case"}
ASSIGN = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*=")
SHELLS = {"sh", "bash", "zsh", "dash", "ksh", "fish", "csh", "tcsh", "ash", "rbash"}
OTHER_INTERP = {"perl", "ruby", "node", "nodejs", "php", "lua", "pwsh", "osascript",
                "deno", "bun", "tclsh", "source", ".", "eval"}
FETCH = {"curl", "wget", "fetch", "nc", "ncat", "netcat", "socat", "lwp-download",
         "aria2c", "http", "https", "xh"}

# wrapper -> (options that take an argument, number of positional args to skip)
WRAPPERS = {
    "sudo": ({"-u", "-g", "-h", "-p", "-C", "-D", "-R", "-T", "-U", "-r", "-t",
              "--user", "--group", "--host", "--prompt", "--chdir", "--chroot"}, 0),
    "doas": ({"-u", "-C"}, 0),
    "env": ({"-u", "-C", "-S", "--unset", "--chdir"}, 0),
    "nice": ({"-n", "--adjustment"}, 0),
    "ionice": ({"-c", "-n", "-p", "-P", "-t"}, 0),
    "timeout": ({"-s", "-k", "--signal", "--kill-after"}, 1),
    "stdbuf": ({"-i", "-o", "-e"}, 0),
    "xargs": ({"-n", "-I", "-P", "-a", "-d", "-L", "-s", "-E", "-l", "-i"}, 0),
    "nohup": (set(), 0), "time": (set(), 0), "command": (set(), 0),
    "exec": ({"-a"}, 0), "builtin": (set(), 0), "setsid": (set(), 0),
    "watch": ({"-n", "-d"}, 0), "busybox": (set(), 0), "unbuffer": (set(), 0),
    "caffeinate": ({"-t", "-w"}, 0), "chronic": (set(), 0),
}


def base(word):
    return os.path.basename(str(word)).lower()


def is_shell(b):
    return b in SHELLS


def is_python(b):
    return re.match(r"^python[0-9.]*$", b) is not None


def is_interp(b):
    return b in SHELLS or b in OTHER_INTERP or is_python(b)


class Cmd(object):
    def __init__(self):
        self.words, self.redirs, self.subs = [], [], []
        self.heredocs, self.sub_cmds = [], []
        self.pipe_next = False
        self.depth = 0


class Parsed(object):
    def __init__(self):
        self.cmds, self.pipelines, self.complex = [], [], []

    def merge(self, other, depth):
        for c in other.cmds:
            c.depth += depth
        self.cmds.extend(other.cmds)
        self.pipelines.extend(other.pipelines)
        for r in other.complex:
            if r not in self.complex:
                self.complex.append(r)


def _skip_dq(t, i):
    """t[i] is an opening double quote; return index after the closing one."""
    n = len(t)
    i += 1
    while i < n:
        c = t[i]
        if c == "\\":
            i += 2
            continue
        if c == '"':
            return i + 1
        if c == "$" and t.startswith("$(", i):
            j = _match_paren(t, i + 2)
            if j < 0:
                return -1
            i = j + 1
            continue
        if c == "`":
            j = _match_bt(t, i + 1)
            if j < 0:
                return -1
            i = j + 1
            continue
        i += 1
    return -1


def _match_paren(t, i):
    """i is just after '('; return index of the matching ')' or -1."""
    depth, n = 1, len(t)
    while i < n:
        c = t[i]
        if c == "\\":
            i += 2
            continue
        if c == "'":
            j = t.find("'", i + 1)
            if j < 0:
                return -1
            i = j + 1
            continue
        if c == '"':
            i = _skip_dq(t, i)
            if i < 0:
                return -1
            continue
        if c == "(":
            depth += 1
        elif c == ")":
            depth -= 1
            if depth == 0:
                return i
        i += 1
    return -1


def _match_bt(t, i):
    n = len(t)
    while i < n:
        if t[i] == "\\":
            i += 2
            continue
        if t[i] == "`":
            return i
        i += 1
    return -1


REDIR_OPS = ("<<<", "<<-", "&>>", "&>", "<<", ">>", ">|", ">&", "<&", "<>", "<", ">")


def _lex(text, parsed):
    t = text.replace(SUB_OPEN, " ").replace(SUB_CLOSE, " ")
    n, i = len(t), 0
    cmds, pipeline, pend = [], [], []
    st = {"cur": Cmd(), "buf": [], "inword": False, "redir": None}

    def flush_word():
        if not st["inword"]:
            return
        w = "".join(st["buf"])
        st["buf"], st["inword"] = [], False
        cur = st["cur"]
        if st["redir"] is not None:
            cur.redirs.append((st["redir"], w))
            if st["redir"] in ("<<", "<<-"):
                pend.append((cur, w, st["redir"] == "<<-"))
            st["redir"] = None
        else:
            cur.words.append(w)

    def end_cmd(pipe=False):
        flush_word()
        cur = st["cur"]
        if cur.words or cur.redirs:
            cmds.append(cur)
            pipeline.append(cur)
            cur.pipe_next = pipe
        if not pipe and pipeline:
            parsed.pipelines.append(list(pipeline))
            del pipeline[:]
        st["cur"] = Cmd()

    def add_sub(inner):
        st["cur"].subs.append(inner)
        st["buf"].append(SUB_OPEN + inner + SUB_CLOSE)
        st["inword"] = True

    while i < n:
        c = t[i]
        if c in " \t\r":
            flush_word()
            i += 1
        elif c == "\n":
            end_cmd()
            i += 1
            for cur, delim, strip in pend:
                body = []
                while i < n:
                    j = t.find("\n", i)
                    line = t[i:] if j < 0 else t[i:j]
                    i = n if j < 0 else j + 1
                    cmp_line = line.lstrip("\t") if strip else line
                    if cmp_line == delim:
                        break
                    body.append(line)
                cur.heredocs.append("\n".join(body))
            del pend[:]
        elif c == "\\":
            if i + 1 < n and t[i + 1] == "\n":
                i += 2
            elif i + 1 < n:
                st["buf"].append(t[i + 1])
                st["inword"] = True
                i += 2
            else:
                i += 1
        elif c == "#" and not st["inword"]:
            j = t.find("\n", i)
            i = n if j < 0 else j
        elif c == "'":
            j = t.find("'", i + 1)
            if j < 0:
                parsed.complex.append("unterminated quote")
                j = n
            st["buf"].append(t[i + 1:j])
            st["inword"] = True
            i = j + 1
        elif c == '"':
            st["inword"] = True
            i += 1
            closed = False
            while i < n:
                ch = t[i]
                if ch == '"':
                    closed = True
                    i += 1
                    break
                if ch == "\\" and i + 1 < n:
                    if t[i + 1] in '"\\$`':
                        st["buf"].append(t[i + 1])
                        i += 2
                    elif t[i + 1] == "\n":
                        i += 2
                    else:
                        st["buf"].append(ch)
                        i += 1
                    continue
                if ch == "$" and t.startswith("$(", i):
                    j = _match_paren(t, i + 2)
                    if j < 0:
                        parsed.complex.append("unterminated $(")
                        j = n
                    add_sub(t[i + 2:j])
                    i = j + 1
                    continue
                if ch == "`":
                    j = _match_bt(t, i + 1)
                    if j < 0:
                        parsed.complex.append("unterminated backtick")
                        j = n
                    add_sub(t[i + 1:j])
                    i = j + 1
                    continue
                st["buf"].append(ch)
                i += 1
            if not closed:
                parsed.complex.append("unterminated quote")
        elif c == "$":
            if t.startswith("$(", i):
                j = _match_paren(t, i + 2)
                if j < 0:
                    parsed.complex.append("unterminated $(")
                    j = n
                add_sub(t[i + 2:j])
                i = j + 1
            elif t.startswith("${", i):
                j = t.find("}", i)
                if j < 0:
                    j = n - 1
                st["buf"].append(t[i:j + 1])
                st["inword"] = True
                i = j + 1
            elif t.startswith("$'", i):
                j = t.find("'", i + 2)
                if j < 0:
                    j = n
                st["buf"].append(t[i + 2:j])
                st["inword"] = True
                i = j + 1
            else:
                st["buf"].append("$")
                st["inword"] = True
                i += 1
        elif c == "`":
            j = _match_bt(t, i + 1)
            if j < 0:
                parsed.complex.append("unterminated backtick")
                j = n
            add_sub(t[i + 1:j])
            i = j + 1
        elif c in "<>" and t.startswith("(", i + 1):
            j = _match_paren(t, i + 2)
            if j < 0:
                parsed.complex.append("unterminated process substitution")
                j = n
            add_sub(t[i + 2:j])
            i = j + 1
        elif c in "<>" or t.startswith("&>", i):
            op = next(o for o in REDIR_OPS if t.startswith(o, i))
            if st["inword"] and "".join(st["buf"]).isdigit():
                st["buf"], st["inword"] = [], False
            else:
                flush_word()
            if st["redir"] is None:
                st["redir"] = op
            i += len(op)
        elif c == ";":
            end_cmd()
            i += 1
        elif c == "&":
            end_cmd()
            i += 2 if t.startswith("&&", i) else 1
        elif c == "|":
            if t.startswith("||", i):
                end_cmd()
                i += 2
            elif t.startswith("|&", i):
                end_cmd(pipe=True)
                i += 2
            else:
                end_cmd(pipe=True)
                i += 1
        elif c in "()":
            end_cmd()
            i += 1
        else:
            st["buf"].append(c)
            st["inword"] = True
            i += 1
    end_cmd()
    return cmds


def parse(text, depth=0):
    """Parse a command string into a Parsed (flat command list + pipelines)."""
    parsed = Parsed()
    if depth > MAX_DEPTH:
        parsed.complex.append("command substitutions nested too deeply")
        return parsed
    cmds = _lex(text, parsed)
    parsed.cmds.extend(cmds)
    for c in cmds:
        c.depth = depth
        for inner in c.subs:
            sub = parse(inner, depth + 1)
            c.sub_cmds.extend(sub.cmds)
            parsed.merge(sub, 0)
    if len(parsed.cmds) > MAX_CMDS:
        parsed.complex.append("too many commands to analyze")
    return parsed


def _skip_opts(args, opts, npos):
    i = 0
    while i < len(args):
        a = args[i]
        if a == "--":
            i += 1
            break
        if a.startswith("-") and len(a) > 1:
            i += 2 if a in opts else 1
            continue
        break
    return args[i + npos:] if npos else args[i:]


def unwrap(words):
    """Strip keywords, VAR=x prefixes and wrapper commands (sudo, env, timeout,
    xargs, nohup...). Returns (inner_argv, shell_strings, wrapper_names).
    shell_strings are scripts to re-parse (bash -c STR, eval ARGS, su -c STR)."""
    w, wrappers = list(words), []
    for _ in range(16):
        while w and (w[0] in KEYWORDS or ASSIGN.match(w[0])):
            w = w[1:]
        if not w:
            break
        b = base(w[0])
        if b in HEADERS:
            return [], [], wrappers
        spec = WRAPPERS.get(b)
        if spec is None:
            break
        wrappers.append(b)
        w = _skip_opts(w[1:], spec[0], spec[1])
    strings = []
    if w:
        b = base(w[0])
        args = w[1:]
        if is_shell(b) or b == "su":
            for k, a in enumerate(args):
                if a == "--command" or (a.startswith("-") and not a.startswith("--")
                                        and "c" in a[1:]):
                    rest = [x for x in args[k + 1:] if not x.startswith("-")]
                    if rest:
                        strings.append(rest[0])
                    break
        elif b == "eval" and args:
            strings.append(" ".join(args))
    return w, strings, wrappers
