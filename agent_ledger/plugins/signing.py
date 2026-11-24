"""signing plugin: signed head hash (ssh-keygen -Y), sidecar .sigs file, git anchor.

Honest limit: an attacker running as the same user can delete the key or the
sidecar. Keep the private key somewhere the agent cannot reach.
"""
import datetime
import json
import os
import shutil
import subprocess
import tempfile

from .. import core

NAMESPACE = "agent-ledger"
PRINCIPAL = "agent-ledger"
MISSING = ("ssh-keygen not found on PATH: install OpenSSH to use signatures "
           "(skipping).")


def keys_dir():
    return os.path.abspath(os.path.expanduser(
        os.environ.get("AGENT_LEDGER_KEYS") or "~/.agent-ledger/keys"))


def sigs_path(ledger):
    return ledger + ".sigs"


def have_ssh_keygen():
    return shutil.which("ssh-keygen") is not None


def message(head, count, ts):
    return "agent-ledger/v1 head=%s count=%d ts=%s" % (head, count, ts)


def _run(cmd, data=None):
    return subprocess.run(cmd, input=data, stdout=subprocess.PIPE,
                          stderr=subprocess.PIPE)


def cmd_keygen(args):
    if not have_ssh_keygen():
        print(MISSING)
        return 1
    d = os.path.abspath(os.path.expanduser(args.dir)) if args.dir else keys_dir()
    os.makedirs(d, exist_ok=True)
    try:
        os.chmod(d, 0o700)
    except OSError:
        pass
    key = os.path.join(d, "id_ed25519")
    if os.path.exists(key) and not args.force:
        print("error: %s already exists (use --force to replace)" % key)
        return 1
    for p in (key, key + ".pub"):
        if os.path.exists(p):
            os.remove(p)
    r = _run(["ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-C", PRINCIPAL,
              "-f", key])
    if r.returncode != 0:
        print("error: ssh-keygen failed: %s" % r.stderr.decode("utf-8", "replace").strip())
        return 1
    os.chmod(key, 0o600)
    with open(key + ".pub") as f:
        parts = f.read().split()
    allowed = os.path.join(d, "allowed_signers")
    with open(allowed, "w") as f:
        f.write('%s namespaces="%s" %s %s\n' % (PRINCIPAL, NAMESPACE, parts[0], parts[1]))
    print("private key:     %s (mode 0600)" % key)
    print("public key:      %s.pub" % key)
    print("allowed_signers: %s" % allowed)
    print()
    print("IMPORTANT: move the PRIVATE key off the agent's reach (another user,")
    print("another machine, or a hardware key). Agents running as you can read,")
    print("use or delete anything in your home directory. Keep only the .pub and")
    print("allowed_signers here, and sign from the safe place with")
    print("`agent-ledger sign --key PATH`.")
    return 0


def sign(ledger, key=None):
    """Sign the current head. Returns (ok, message)."""
    if not have_ssh_keygen():
        return False, MISSING
    key = os.path.abspath(os.path.expanduser(key)) if key else os.path.join(keys_dir(), "id_ed25519")
    if not os.path.exists(key):
        return False, "key not found: %s (run `agent-ledger keygen`)" % key
    ok, line, why, n = core.verify(ledger)
    if not ok:
        return False, "refusing to sign a broken chain (%s)" % why
    head, count = core.anchor(ledger)
    if count == 0:
        return False, "ledger is empty; nothing to sign"
    ts = datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    r = _run(["ssh-keygen", "-Y", "sign", "-f", key, "-n", NAMESPACE],
             message(head, count, ts).encode("ascii"))
    if r.returncode != 0:
        return False, "ssh-keygen sign failed: %s" % r.stderr.decode("utf-8", "replace").strip()
    rec = {"head": head, "count": count, "ts": ts,
           "signature": r.stdout.decode("ascii", "replace")}
    with open(sigs_path(ledger), "a") as f:
        f.write(json.dumps(rec, sort_keys=True, separators=(",", ":")) + "\n")
    return True, "signed head %s (%d entries)" % (head[:12], count)


def cmd_sign(args):
    ok, msg = sign(core.default_path(args.ledger), args.key)
    print(msg if ok else "error: " + msg)
    return 0 if ok else 1


def read_sigs(ledger):
    out = []
    p = sigs_path(ledger)
    if os.path.exists(p):
        with open(p) as f:
            for raw in f:
                if raw.strip():
                    try:
                        out.append(json.loads(raw))
                    except ValueError:
                        out.append({"_corrupt": True})
    return out


def check_signature(rec, allowed):
    """Return True if the signature record is cryptographically valid."""
    try:
        msg = message(rec["head"], int(rec["count"]), rec["ts"]).encode("ascii")
        sig = rec["signature"]
    except (KeyError, TypeError, ValueError):
        return False
    with tempfile.TemporaryDirectory() as td:
        sp = os.path.join(td, "s.sig")
        with open(sp, "w") as f:
            f.write(sig)
        if allowed and os.path.exists(allowed):
            cmd = ["ssh-keygen", "-Y", "verify", "-f", allowed, "-I", PRINCIPAL,
                   "-n", NAMESPACE, "-s", sp]
        else:
            cmd = ["ssh-keygen", "-Y", "check-novalidate", "-n", NAMESPACE, "-s", sp]
        return _run(cmd, msg).returncode == 0


def signature_status(ledger, allowed=None):
    """Evaluate all signatures. Returns dict with per-record results."""
    entries = core.read(ledger)
    recs = read_sigs(ledger)
    allowed = allowed or os.path.join(keys_dir(), "allowed_signers")
    results, last = [], None
    for i, rec in enumerate(recs):
        if rec.get("_corrupt"):
            results.append((rec, "unreadable record"))
            continue
        if not check_signature(rec, allowed):
            results.append((rec, "BAD signature"))
            continue
        try:
            c = int(rec["count"])
            matches = 0 < c <= len(entries) and entries[c - 1].get("hash") == rec["head"]
        except (KeyError, TypeError, ValueError):
            matches = False
        if not matches:
            results.append((rec, "signed head not in chain at its position "
                            "(entries removed or rewritten)"))
            continue
        results.append((rec, "ok"))
        if last is None or int(rec["count"]) > int(last["count"]):
            last = rec
    return {"results": results, "last": last, "total": len(entries),
            "pinned": bool(os.path.exists(allowed)),
            "bad": sum(1 for _, s in results if s != "ok")}


def report_signatures(ledger, allowed=None):
    """Print signature check. Returns exit code (1 if any signature is bad)."""
    if not have_ssh_keygen():
        print("signatures: SKIPPED. " + MISSING)
        return 0
    st = signature_status(ledger, allowed)
    n = len(st["results"])
    if n == 0:
        print("signatures: none found (%s)" % sigs_path(ledger))
    else:
        print("signatures: %d checked, %d valid, %d bad%s" % (
            n, n - st["bad"], st["bad"],
            "" if st["pinned"] else " (no allowed_signers: key identity NOT pinned)"))
        for rec, status in st["results"]:
            if status != "ok":
                print("  SIGNATURE FAIL (count=%s ts=%s): %s" % (
                    rec.get("count"), rec.get("ts"), status))
    last = st["last"]
    if last:
        print("last signed point: entry %d at %s (head %s)" % (
            int(last["count"]), last["ts"], last["head"][:12]))
        tail = st["total"] - int(last["count"])
    else:
        tail = st["total"]
    print("unsigned tail: %d entries" % tail)
    return 1 if st["bad"] else 0


def _git(args, cwd=None):
    return subprocess.run(["git"] + args, cwd=cwd, stdout=subprocess.PIPE,
                          stderr=subprocess.PIPE)


def anchor_git(ledger, cwd=None):
    """Write the head hash into a local annotated git tag. Returns (ok, msg)."""
    if shutil.which("git") is None:
        return False, "git not found on PATH (skipping)"
    if _git(["rev-parse", "--is-inside-work-tree"], cwd).returncode != 0:
        return False, "not inside a git repository (skipping)"
    head, count = core.anchor(ledger)
    if count == 0:
        return False, "ledger is empty; nothing to anchor"
    tag = "agent-ledger-%d-%s" % (count, head[:12])
    msg = "agent-ledger anchor\nhead=%s\ncount=%d" % (head, count)
    r = _git(["tag", "-a", tag, "-m", msg], cwd)
    if r.returncode != 0:
        return False, "git tag failed: %s" % r.stderr.decode("utf-8", "replace").strip()
    return True, "git tag %s created (local only, not pushed)" % tag


def register(subparsers):
    p = subparsers.add_parser("keygen", help="create an ed25519 signing key")
    p.add_argument("--dir", help="key folder (default ~/.agent-ledger/keys)")
    p.add_argument("--force", action="store_true", help="replace existing key")
    p.set_defaults(func=cmd_keygen)
    p = subparsers.add_parser("sign", help="sign the current head hash")
    p.add_argument("--key", help="private key path (default: keys/id_ed25519)")
    p.set_defaults(func=cmd_sign)
