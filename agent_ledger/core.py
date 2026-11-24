"""Core ledger: append, read, verify. Standard library only."""
import datetime
import hashlib
import json
import os
import re
import stat
import tempfile

try:
    import fcntl
except ImportError:  # non-POSIX: no locking available
    fcntl = None

GENESIS = "0" * 64
FIELDS = ("ts", "agent", "action", "cost", "files", "prev_hash", "hash")

_PATTERNS = [
    re.compile(r"sk-[A-Za-z0-9_\-]{16,}"),
    re.compile(r"gh[pousr]_[A-Za-z0-9]{20,}"),
    re.compile(r"github_pat_[A-Za-z0-9_]{20,}"),
    re.compile(r"(?:AKIA|ASIA)[0-9A-Z]{16}"),
    re.compile(r"xox[abprs]-[A-Za-z0-9\-]{10,}"),
]
# Extra shapes redacted in the ledger (and caught by policy-check).
_EXTRA = [
    re.compile(r"npm_[A-Za-z0-9]{20,}"),
    re.compile(r"glpat-[A-Za-z0-9_\-]{16,}"),
    re.compile(r"AIza[0-9A-Za-z_\-]{30,}"),
    re.compile(r"(?:sk|rk|pk)_(?:live|test)_[A-Za-z0-9]{10,}"),
    re.compile(r"SG\.[A-Za-z0-9_\-]{16,}\.[A-Za-z0-9_\-]{16,}"),
    re.compile(r"hooks\.slack\.com/services/[A-Za-z0-9/]+"),
    re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----[\s\S]*?(?:-----END [A-Z ]*PRIVATE KEY-----|$)"),
    re.compile(r"(?i)\bBearer\s+[A-Za-z0-9._~+/=\-]{8,}"),
    re.compile(r"(?i)\b(password|passwd|secret|token|api[_-]?key|apikey|auth)"
               r"(\s*[=:]\s*)(?!\[redacted\])[^\s&\"']+"),
    re.compile(r"(?<=://)[^/\s:@]+:[^/\s@]+(?=@)"),
    re.compile(r"\b[0-9a-fA-F]{40}\b|\b[0-9a-fA-F]{64}\b"),
]
_LONG = re.compile(r"[A-Za-z0-9+/=_\-]{32,}")


def _entropy(s):
    import math
    n = float(len(s))
    return -sum(c / n * math.log(c / n, 2)
                for c in (s.count(x) for x in set(s)))


def _tokenish(m):
    s = m.group(0)
    mixed = (any(c.isdigit() for c in s) and any(c.islower() for c in s)
             and any(c.isupper() for c in s))
    # high-entropy strings with a digit and a letter (e.g. all-lowercase keys)
    rand = (any(c.isdigit() for c in s) and any(c.isalpha() for c in s)
            and _entropy(s) >= 3.6)
    return "[redacted]" if (mixed or rand) else s


def _sub_extra(m):
    if m.re.groups >= 2:
        return m.group(1) + m.group(2) + "[redacted]"
    return "[redacted]"


_FP = re.compile(r"(SHA256:[A-Za-z0-9+/]{43})")


def redact(text):
    """Replace anything that looks like a secret with [redacted].
    SSH key fingerprints (public identifiers) are kept."""
    parts = _FP.split(str(text))
    return "".join(p if i % 2 else _redact(p) for i, p in enumerate(parts))


def _redact(text):
    for p in _PATTERNS:
        text = p.sub("[redacted]", text)
    for p in _EXTRA:
        text = p.sub(_sub_extra, text)
    return _LONG.sub(_tokenish, text)


def default_path(path=None):
    return os.path.abspath(os.path.expanduser(
        path or os.environ.get("AGENT_LEDGER")
        or "~/.agent-ledger/ledger.jsonl"))


def compute_hash(entry):
    body = {k: v for k, v in entry.items() if k != "hash"}
    blob = json.dumps(body, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=True)
    return hashlib.sha256(blob.encode("ascii")).hexdigest()


def canonical_line(entry):
    return json.dumps(entry, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=True)


TS_RE = re.compile(r"^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d\.\d{6}Z$")
MAX_FUTURE_SECONDS = 300


def _now_ts():
    return datetime.datetime.now(datetime.timezone.utc).strftime(
        "%Y-%m-%dT%H:%M:%S.%fZ")


def _ts_in_future(ts):
    try:
        t = datetime.datetime.strptime(ts, "%Y-%m-%dT%H:%M:%S.%fZ").replace(
            tzinfo=datetime.timezone.utc)
    except ValueError:
        return True
    delta = t - datetime.datetime.now(datetime.timezone.utc)
    return delta.total_seconds() > MAX_FUTURE_SECONDS


def check_regular(path):
    """Refuse symlinks and non-regular files (e.g. /dev/null) as a ledger."""
    try:
        st = os.lstat(path)
    except FileNotFoundError:
        return
    if stat.S_ISLNK(st.st_mode):
        raise ValueError("ledger path is a symlink; refusing to follow it: %s" % path)
    if not stat.S_ISREG(st.st_mode):
        raise ValueError("ledger path is not a regular file: %s" % path)


def _last_entry(f):
    """Parsed last line of an open binary file (None if empty)."""
    size = f.seek(0, os.SEEK_END)
    if size == 0:
        return None
    f.seek(size - 1)
    if f.read(1) != b"\n":
        raise ValueError("ledger is corrupt: last line is not newline-terminated; run verify")
    chunk = 4096
    while True:
        start = max(0, size - chunk)
        f.seek(start)
        data = f.read(size - start)
        lines = data.rstrip(b"\n").split(b"\n")
        if len(lines) > 1 or start == 0:
            break
        chunk *= 2
    try:
        e = json.loads(lines[-1].decode("utf-8"))
        e["hash"]
        return e
    except Exception:
        raise ValueError("ledger is corrupt at its last line; run verify")


# ---- state file: high-water mark (count, head) + signing facts -------------

def state_path(path):
    return path + ".state"


def read_state(path):
    try:
        with open(state_path(path), "r") as f:
            d = json.load(f)
        return d if isinstance(d, dict) else {}
    except (OSError, ValueError):
        return {}


def update_state(path, **kw):
    """Merge keys into the state file (atomic replace). Best effort."""
    d = read_state(path)
    d.update(kw)
    sp = state_path(path)
    try:
        fd, tmp = tempfile.mkstemp(dir=os.path.dirname(sp) or ".", prefix=".state-")
        with os.fdopen(fd, "w") as f:
            json.dump(d, f, sort_keys=True)
        os.replace(tmp, sp)
    except OSError:
        pass


def _count_lines(f):
    f.seek(0)
    return sum(1 for _ in f)


def append(path, agent, action, cost=0.0, files=None, session=None):
    """Append one entry under an exclusive lock. Returns the entry dict."""
    path = default_path(path)
    cost = float(cost or 0.0)
    if cost < 0 or cost != cost or cost == float("inf"):
        raise ValueError("cost must be a non-negative number")
    if not str(agent).strip() or not str(action).strip():
        raise ValueError("agent and action are required")
    if isinstance(files, str):
        files = [x.strip() for x in files.split(",") if x.strip()]
    os.makedirs(os.path.dirname(path), exist_ok=True)
    check_regular(path)
    flags = os.O_RDWR | os.O_APPEND | os.O_CREAT | getattr(os, "O_NOFOLLOW", 0)
    fd = os.open(path, flags, 0o600)
    f = os.fdopen(fd, "a+b")
    with f:
        if not stat.S_ISREG(os.fstat(f.fileno()).st_mode):
            raise ValueError("ledger path is not a regular file: %s" % path)
        if fcntl:
            fcntl.flock(f, fcntl.LOCK_EX)
        try:
            last = _last_entry(f)
            prev = last["hash"] if last else GENESIS
            ts = _now_ts()
            if last and isinstance(last.get("ts"), str) and ts < last["ts"]:
                ts = last["ts"]  # keep timestamps monotonic if the clock stepped back
            entry = {
                "ts": ts,
                "agent": redact(agent).strip(),
                "action": redact(action).strip(),
                "cost": round(cost, 6),
                "files": [redact(x) for x in (files or [])],
                "prev_hash": prev,
            }
            if session:
                entry["session"] = clean_session(session)
            entry["hash"] = compute_hash(entry)
            line = canonical_line(entry) + "\n"
            f.seek(0, os.SEEK_END)
            f.write(line.encode("ascii"))
            f.flush()
            os.fsync(f.fileno())
            st = read_state(path)
            if last and st.get("head") == prev and isinstance(st.get("count"), int):
                count = st["count"] + 1
            else:
                count = _count_lines(f)
            update_state(path, count=count, head=entry["hash"])
        finally:
            if fcntl:
                fcntl.flock(f, fcntl.LOCK_UN)
    return entry


def read(path=None):
    """Return a list of entry dicts (no verification). Missing file -> []."""
    path = default_path(path)
    out = []
    if not os.path.exists(path):
        return out
    check_regular(path)
    with open(path, "rb") as f:
        for raw in f:
            try:
                e = json.loads(raw.decode("utf-8"))
                out.append(e if isinstance(e, dict) else {"_corrupt": True})
            except Exception:
                out.append({"_corrupt": True})
    return out


def verify(path=None, anchor_hash=None, min_entries=None, check_state=False):
    """Check the whole chain.

    Returns (ok, line_number_or_None, reason, count).
    min_entries: fail if fewer entries. check_state: also compare with the
    high-water mark file (detects truncation/rollback unless it was deleted too).
    """
    path = default_path(path)
    if not os.path.exists(path):
        return False, None, "ledger file not found: %s" % path, 0
    try:
        check_regular(path)
    except ValueError as ex:
        return False, None, str(ex), 0
    prev, n, hashes, prev_ts = GENESIS, 0, [], ""
    with open(path, "rb") as f:
        for raw in f:
            n += 1
            try:
                e = json.loads(raw.decode("utf-8"))
                if not isinstance(e, dict):
                    raise ValueError
            except Exception:
                return False, n, "line is not valid JSON", n - 1
            missing = [k for k in FIELDS if k not in e]
            if missing:
                return False, n, "missing field(s): " + ", ".join(missing), n - 1
            if e["prev_hash"] != prev:
                return (False, n, "prev_hash does not match the previous "
                        "entry (line removed, added or reordered)", n - 1)
            try:
                good = compute_hash(e) == e["hash"]
            except (TypeError, ValueError):
                good = False
            if not good:
                return (False, n, "entry content does not match its hash "
                        "(line was edited)", n - 1)
            if raw != (canonical_line(e) + "\n").encode("ascii"):
                return (False, n, "line is not in canonical form (missing "
                        "newline, pretty-printed or duplicate keys)", n - 1)
            ts = e["ts"]
            if not isinstance(ts, str) or not TS_RE.match(ts):
                return False, n, "timestamp is malformed", n - 1
            if ts < prev_ts:
                return (False, n, "timestamp goes backwards (entry back-dated "
                        "or reordered)", n - 1)
            if _ts_in_future(ts):
                return False, n, "timestamp is in the future", n - 1
            prev_ts = ts
            prev = e["hash"]
            hashes.append(prev)
    if anchor_hash and anchor_hash not in hashes:
        return (False, None, "anchor hash not found in the chain (entries "
                "removed or ledger replaced)", n)
    if min_entries is not None and n < min_entries:
        return (False, None, "only %d entries, expected at least %d (ledger "
                "truncated or replaced)" % (n, min_entries), n)
    if check_state:
        st = read_state(path)
        c = st.get("count")
        if isinstance(c, int) and c > 0:
            if n == 0:
                return (False, None, "ledger is empty but %d entries were "
                        "recorded earlier (emptied)" % c, 0)
            if n < c:
                return (False, None, "ledger has %d entries but %d were "
                        "recorded earlier (truncated or rolled back)" % (n, c), n)
            if hashes[c - 1] != st.get("head"):
                return (False, None, "entry %d differs from the head recorded "
                        "earlier (history was rewritten)" % c, n)
    return True, None, "ok", n


def anchor(path=None):
    """Return (latest_hash, count). Empty ledger -> (GENESIS, 0)."""
    es = read(path)
    return (es[-1]["hash"] if es and "hash" in es[-1] else GENESIS), len(es)


def clean_session(session_id):
    return re.sub(r"[^A-Za-z0-9_.\-]", "_", str(session_id))[:64]


def session_tag(session_id):
    """Marker appended to an action so entries can be tied to one session."""
    return " [session=%s]" % clean_session(session_id)


def neutralize_tags(text):
    """Defang session tags inside agent-controlled text (budget spoofing)."""
    return str(text).replace("[session=", "[session:")


def session_cost(path, session_id):
    """Total cost of entries tied to this session id (structured field, or the
    legacy tag at the very end of the action)."""
    tag = session_tag(session_id)
    sid = clean_session(session_id)
    total = 0.0
    for e in read(path):
        if e.get("session") == sid or (
                "session" not in e and str(e.get("action", "")).endswith(tag)):
            try:
                total += float(e.get("cost") or 0)
            except (TypeError, ValueError):
                pass
    return total


def session_cost_day(path):
    """Total cost of all entries stamped with today's (UTC) date."""
    today = datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%d")
    total = 0.0
    for e in read(path):
        if str(e.get("ts", "")).startswith(today):
            try:
                total += float(e.get("cost") or 0)
            except (TypeError, ValueError):
                pass
    return total
