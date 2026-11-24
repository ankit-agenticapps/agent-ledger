"""Core ledger: append, read, verify. Standard library only."""
import datetime
import hashlib
import json
import os
import re

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
    re.compile(r"AKIA[0-9A-Z]{16}"),
    re.compile(r"xox[abprs]-[A-Za-z0-9\-]{10,}"),
]
_LONG = re.compile(r"[A-Za-z0-9+/=_\-]{32,}")


def _tokenish(m):
    s = m.group(0)
    ok = (any(c.isdigit() for c in s) and any(c.islower() for c in s)
          and any(c.isupper() for c in s))
    return "[redacted]" if ok else s


def redact(text):
    """Replace anything that looks like a secret with [redacted]."""
    text = str(text)
    for p in _PATTERNS:
        text = p.sub("[redacted]", text)
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


def _last_hash(f):
    """Hash of the last line of an open binary file (GENESIS if empty)."""
    size = f.seek(0, os.SEEK_END)
    if size == 0:
        return GENESIS
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
        return json.loads(lines[-1].decode("utf-8"))["hash"]
    except Exception:
        raise ValueError("ledger is corrupt at its last line; run verify")


def append(path, agent, action, cost=0.0, files=None):
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
    with open(path, "a+b") as f:
        if fcntl:
            fcntl.flock(f, fcntl.LOCK_EX)
        try:
            entry = {
                "ts": datetime.datetime.now(datetime.timezone.utc)
                .strftime("%Y-%m-%dT%H:%M:%S.%fZ"),
                "agent": redact(agent).strip(),
                "action": redact(action).strip(),
                "cost": round(cost, 6),
                "files": [redact(x) for x in (files or [])],
                "prev_hash": _last_hash(f),
            }
            entry["hash"] = compute_hash(entry)
            line = json.dumps(entry, sort_keys=True, separators=(",", ":"),
                              ensure_ascii=True) + "\n"
            f.seek(0, os.SEEK_END)
            f.write(line.encode("ascii"))
            f.flush()
            os.fsync(f.fileno())
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
    with open(path, "rb") as f:
        for raw in f:
            try:
                out.append(json.loads(raw.decode("utf-8")))
            except Exception:
                out.append({"_corrupt": True})
    return out


def verify(path=None, anchor_hash=None):
    """Check the whole chain.

    Returns (ok, line_number_or_None, reason, count).
    """
    path = default_path(path)
    if not os.path.exists(path):
        return False, None, "ledger file not found: %s" % path, 0
    prev, n, seen = GENESIS, 0, set()
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
            if compute_hash(e) != e["hash"]:
                return (False, n, "entry content does not match its hash "
                        "(line was edited)", n - 1)
            prev = e["hash"]
            seen.add(prev)
    if anchor_hash and anchor_hash not in seen:
        return (False, None, "anchor hash not found in the chain (entries "
                "removed or ledger replaced)", n)
    return True, None, "ok", n


def anchor(path=None):
    """Return (latest_hash, count). Empty ledger -> (GENESIS, 0)."""
    es = read(path)
    return (es[-1]["hash"] if es else GENESIS), len(es)


def session_tag(session_id):
    """Marker appended to an action so entries can be tied to one session."""
    return " [session=%s]" % re.sub(r"[^A-Za-z0-9_.\-]", "_", str(session_id))[:64]


def session_cost(path, session_id):
    """Total cost of entries tagged with this session id."""
    tag = session_tag(session_id)
    total = 0.0
    for e in read(path):
        if tag in str(e.get("action", "")):
            try:
                total += float(e.get("cost") or 0)
            except (TypeError, ValueError):
                pass
    return total
