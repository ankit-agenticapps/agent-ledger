"""signing plugin: signed head hash (ssh-keygen -Y), sidecar .sigs file, git anchor.

Honest limit: an attacker running as the same user can delete the key or the
sidecar. Keep the private key somewhere the agent cannot reach.
"""
import datetime
import json
import os
import re
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
    allowed = os.path.join(d, "allowed_signers")
    if os.path.exists(allowed) and not args.force:
        print("error: %s already exists (use --force to replace; this changes "
              "who may sign)" % allowed)
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
    with open(allowed, "w") as f:
        f.write('%s namespaces="%s" %s %s\n' % (PRINCIPAL, NAMESPACE, parts[0], parts[1]))
    fp = key_fingerprint(key + ".pub")
    if fp:
        try:  # record the signer identity in the chain itself
            core.append(core.default_path(getattr(args, "ledger", None)), "agent-ledger",
                        "keygen: public key fingerprint=%s" % fp)
        except (ValueError, OSError) as ex:
            print("warning: could not record the fingerprint in the ledger: %s" % ex)
    print("private key:     %s (mode 0600)" % key)
    print("public key:      %s.pub" % key)
    if fp:
        print("fingerprint:     %s (recorded in the ledger chain)" % fp)
    print("allowed_signers: %s" % allowed)
    print()
    print("IMPORTANT: move the PRIVATE key off the agent's reach (another user,")
    print("another machine, or a hardware key). Agents running as you can read,")
    print("use or delete anything in your home directory. Keep only the .pub and")
    print("allowed_signers here, and sign from the safe place with")
    print("`agent-ledger sign --key PATH`.")
    return 0


def key_fingerprint(path):
    """SHA256:... fingerprint of a key file, or None."""
    try:
        r = _run(["ssh-keygen", "-l", "-f", path])
    except OSError:
        return None
    parts = r.stdout.decode("utf-8", "replace").split()
    return parts[1] if r.returncode == 0 and len(parts) > 1 and parts[1].startswith("SHA256:") else None


def allowed_fingerprints(allowed):
    """Fingerprints of every key listed in an allowed_signers file."""
    out = []
    try:
        lines = open(allowed).read().splitlines()
    except OSError:
        return out
    for ln in lines:
        m = re.search(r"((?:ssh|ecdsa|sk)-[A-Za-z0-9@.\-]+)\s+([A-Za-z0-9+/=]+)", ln)
        if not m or ln.lstrip().startswith("#"):
            continue
        with tempfile.TemporaryDirectory() as td:
            tp = os.path.join(td, "k.pub")
            with open(tp, "w") as f:
                f.write("%s %s\n" % (m.group(1), m.group(2)))
            fp = key_fingerprint(tp)
        if fp:
            out.append(fp)
    return out


FP_RE = re.compile(r"fingerprint=(SHA256:[A-Za-z0-9+/=]+)")


def chain_pin(entries):
    """(pinned_fp, all_fps_in_order, signing_enabled) from marker entries."""
    fps, enabled = [], False
    for e in entries:
        act = str(e.get("action", ""))
        if e.get("agent") != "agent-ledger":
            continue
        if act.startswith("signing:enabled") or act.startswith("keygen:"):
            m = FP_RE.search(act)
            if m:
                fps.append(m.group(1))
            enabled = True  # a recorded keygen or first signature means signatures are expected
    return (fps[0] if fps else None), fps, enabled


def is_marker(e):
    return e.get("agent") == "agent-ledger" and str(e.get("action", "")).startswith("signing:enabled")


def sign(ledger, key=None):
    """Sign the current head. Returns (ok, message)."""
    if not have_ssh_keygen():
        return False, MISSING
    key = os.path.abspath(os.path.expanduser(key)) if key else os.path.join(keys_dir(), "id_ed25519")
    if not os.path.exists(key):
        return False, "key not found: %s (run `agent-ledger keygen`)" % key
    ok, line, why, n = core.verify(ledger, check_state=True)
    if not ok:
        return False, "refusing to sign a broken chain (%s)" % why
    head, count = core.anchor(ledger)
    if count == 0:
        return False, "ledger is empty; nothing to sign"
    fp = key_fingerprint(key)
    pin, _, enabled = chain_pin(core.read(ledger))
    st = core.read_state(ledger)
    pin = pin or st.get("fingerprint")
    if pin and fp and fp != pin:
        return False, ("signing key fingerprint %s differs from the one pinned in "
                       "the chain (%s); refusing" % (fp, pin))
    ts = datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    r = _run(["ssh-keygen", "-Y", "sign", "-f", key, "-n", NAMESPACE],
             message(head, count, ts).encode("ascii"))
    if r.returncode != 0:
        return False, "ssh-keygen sign failed: %s" % r.stderr.decode("utf-8", "replace").strip()
    rec = {"head": head, "count": count, "ts": ts,
           "signature": r.stdout.decode("ascii", "replace")}
    with open(sigs_path(ledger), "a") as f:
        f.write(json.dumps(rec, sort_keys=True, separators=(",", ":")) + "\n")
    core.update_state(ledger, signing=True, fingerprint=pin or fp,
                      max_signed_count=max(count, int(st.get("max_signed_count") or 0)))
    if not enabled:  # first signature: record in the chain that signing is on
        try:
            core.append(ledger, "agent-ledger",
                        "signing:enabled fingerprint=%s first_signed_count=%d" % (fp, count))
        except (ValueError, OSError):
            pass
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
                        rec = json.loads(raw)
                    except ValueError:
                        rec = None
                    out.append(rec if isinstance(rec, dict) else {"_corrupt": True})
    return out


FPOUT_RE = re.compile(r"key (SHA256:\S+)")


def check_signature_fp(rec, allowed):
    """Return (valid, signer_fingerprint_or_None)."""
    try:
        msg = message(rec["head"], int(rec["count"]), rec["ts"]).encode("ascii")
        sig = rec["signature"]
        if not isinstance(sig, str):
            return False, None
    except (KeyError, TypeError, ValueError, UnicodeError):
        return False, None
    with tempfile.TemporaryDirectory() as td:
        sp = os.path.join(td, "s.sig")
        with open(sp, "w") as f:
            f.write(sig)
        if allowed and os.path.exists(allowed):
            cmd = ["ssh-keygen", "-Y", "verify", "-f", allowed, "-I", PRINCIPAL,
                   "-n", NAMESPACE, "-s", sp]
        else:
            cmd = ["ssh-keygen", "-Y", "check-novalidate", "-n", NAMESPACE, "-s", sp]
        r = _run(cmd, msg)
    m = FPOUT_RE.search(r.stdout.decode("utf-8", "replace"))
    return r.returncode == 0, (m.group(1) if m else None)


def check_signature(rec, allowed):
    """Return True if the signature record is cryptographically valid."""
    return check_signature_fp(rec, allowed)[0]


def signature_status(ledger, allowed=None, allow_rotation=False):
    """Evaluate all signatures. Returns dict with per-record results and
    chain-level `problems` (missing sigs file, swapped signer, rollback)."""
    entries = core.read(ledger)
    recs = read_sigs(ledger)
    allowed = allowed or os.path.join(keys_dir(), "allowed_signers")
    state = core.read_state(ledger)
    pin, fps, enabled = chain_pin(entries)
    pin = pin or state.get("fingerprint")
    enabled = enabled or bool(state.get("signing"))
    problems = []
    if len(set(fps)) > 1 and not allow_rotation:
        problems.append("the chain records more than one signer fingerprint "
                        "(%s); pass --allow-rotation if you rotated the key on purpose"
                        % ", ".join(sorted(set(fps))))
    if pin and os.path.exists(allowed):
        have = allowed_fingerprints(allowed)
        if pin not in have:
            problems.append("allowed_signers does not contain the signer fingerprint "
                            "recorded in the chain (%s): file swapped?" % pin)
    if enabled and not recs:
        problems.append("signing was set up but the signature file is missing or "
                        "empty (%s): deleted or rolled back?" % sigs_path(ledger))
    results, last = [], None
    for i, rec in enumerate(recs):
        if rec.get("_corrupt"):
            results.append((rec, "unreadable record"))
            continue
        good, fp = check_signature_fp(rec, allowed)
        if not good:
            results.append((rec, "BAD signature"))
            continue
        if pin and fp and fp != pin:
            results.append((rec, "BAD signature: signed by a key that is not the "
                            "signer pinned in the chain"))
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
    seen = int(last["count"]) if last else 0
    if (isinstance(state.get("max_signed_count"), int)
            and state["max_signed_count"] > seen and recs):
        problems.append("newest valid signature covers %d entries but %d were "
                        "signed earlier (signature records removed: rollback)"
                        % (seen, state["max_signed_count"]))
    if enabled and recs and last is None:
        problems.append("signing is set up but no signature in the file is valid")
    tail = sum(1 for e in entries[seen:] if not is_marker(e))
    return {"results": results, "last": last, "total": len(entries),
            "tail": tail, "problems": problems, "enabled": enabled, "pin": pin,
            "pinned": bool(os.path.exists(allowed)),
            "bad": sum(1 for _, s in results if s != "ok")}


def report_signatures(ledger, allowed=None, allow_rotation=False):
    """Print signature check. Returns exit code (1 if anything is wrong)."""
    st0 = core.read_state(ledger)
    if not have_ssh_keygen():
        print("signatures: SKIPPED. " + MISSING)
        return 1 if (st0.get("signing") or chain_pin(core.read(ledger))[2]) else 0
    st = signature_status(ledger, allowed, allow_rotation)
    n = len(st["results"])
    if n == 0:
        print("signatures: none found (%s)%s" % (
            sigs_path(ledger), "" if st["enabled"] else
            " - signing was never set up, so nothing stops a full rewrite"))
    else:
        print("signatures: %d checked, %d valid, %d bad%s" % (
            n, n - st["bad"], st["bad"],
            "" if st["pinned"] else " (no allowed_signers: key identity NOT pinned by "
            "file%s)" % (", pinned by chain fingerprint" if st["pin"] else "")))
        for rec, status in st["results"]:
            if status != "ok":
                print("  SIGNATURE FAIL (count=%s ts=%s): %s" % (
                    rec.get("count"), rec.get("ts"), status))
    for pr in st["problems"]:
        print("  SIGNATURE PROBLEM: %s" % pr)
    last = st["last"]
    if last:
        print("last signed point: entry %d at %s (head %s)" % (
            int(last["count"]), last["ts"], last["head"][:12]))
    print("unsigned tail: %d entries" % st["tail"])
    return 1 if (st["bad"] or st["problems"]) else 0


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
