"""Command line interface. Plugins in plugins/ add their own commands."""
import argparse
import importlib
import importlib.util
import os
import pkgutil
import sys

from . import core
from .plugins import __path__ as _PLUGIN_PATH


def ascii_safe(s):
    """ASCII only, control characters (newline, ESC...) shown escaped."""
    s = str(s).encode("ascii", "replace").decode("ascii")
    return "".join(c if 32 <= ord(c) < 127 else "\\x%02x" % ord(c) for c in s)


def _ledger(args):
    return core.default_path(args.ledger)


def cmd_log(args):
    action = args.action
    files = args.files
    if args.hook_stdin:  # Claude Code hook: JSON on stdin; never block the agent
        try:
            import json
            d = json.loads(sys.stdin.read() or "{}")
            ti = d.get("tool_input") or {}
            action = "tool: %s" % d.get("tool_name", "unknown")
            if ti.get("command"):
                action += " " + str(ti["command"])[:120]
            files = ti.get("file_path") or files
            if d.get("session_id") and not args.session:
                args.session = d["session_id"]
        except Exception:
            action = action or "tool call"
    if not action:
        print("error: --action is required", file=sys.stderr)
        return 2
    action = core.neutralize_tags(action)
    if action.lstrip().lower().startswith(("keygen:", "signing:")):
        print("error: action prefixes 'keygen:' and 'signing:' are reserved", file=sys.stderr)
        return 0 if args.hook_stdin else 2
    if args.session:
        action += core.session_tag(args.session)
    try:
        e = core.append(_ledger(args), args.agent, action, args.cost, files,
                        session=args.session)
    except (ValueError, OSError) as ex:
        print("error: %s" % ex, file=sys.stderr)
        return 0 if args.hook_stdin else 2
    print("logged %s %s" % (e["agent"], e["hash"][:12]))
    return 0


def cmd_verify(args):
    ok, line, why, n = core.verify(_ledger(args), args.anchor, args.min_entries,
                                   check_state=not args.no_state)
    if ok:
        print("VERIFY OK: %d entries, chain intact%s" % (
            n, ", anchor found" if args.anchor else ""))
    elif line:
        print("VERIFY FAIL at line %d: %s" % (line, why))
    else:
        print("VERIFY FAIL: %s" % why)
    code = 0 if ok else 1
    if args.signatures:
        from .plugins import signing
        code = max(code, signing.report_signatures(
            _ledger(args), args.allowed_signers, args.allow_rotation))
    return code


def cmd_anchor(args):
    h, n = core.anchor(_ledger(args))
    print("anchor: %s" % h)
    print("entries: %d" % n)
    if args.git:
        from .plugins import signing
        ok, msg = signing.anchor_git(_ledger(args))
        print(msg if ok else "git anchor skipped: " + msg)
        return 0 if ok else 1
    return 0


def cmd_report(args):
    if args.html:
        from .plugins import htmlreport
        try:
            htmlreport.write(_ledger(args), args.html)
        except OSError as ex:
            print("error: %s" % ex, file=sys.stderr)
            return 2
        print("wrote %s" % args.html)
        return 0
    es = [e for e in core.read(_ledger(args)) if "agent" in e]
    if not es:
        print("Ledger is empty.")
        return 0
    per = {}
    for e in es:
        a = per.setdefault(e["agent"], [0, 0.0, ""])
        a[0] += 1
        a[1] += float(e.get("cost") or 0)
        a[2] = max(a[2], e.get("ts", ""))
    print("%-16s %7s %10s  %s" % ("AGENT", "ENTRIES", "COST USD", "LAST SEEN"))
    for name, (c, cost, last) in sorted(per.items()):
        print("%-16s %7d %10.4f  %s" % (ascii_safe(name)[:16], c, cost, last))
    print("%-16s %7d %10.4f" % ("TOTAL", len(es), sum(v[1] for v in per.values())))
    print("\nLast 10 actions:")
    for e in es[-10:]:
        print("  %s  %-12s %s" % (e.get("ts", "")[:19], ascii_safe(e["agent"])[:12],
                                  ascii_safe(e.get("action", ""))[:80]))
    return 0


def _load_file(path):
    name = "agent_ledger_ext_" + os.path.splitext(os.path.basename(path))[0]
    spec = importlib.util.spec_from_file_location(name, path)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def load_plugins(subparsers):
    """Load every module exposing register(subparsers). Returns loaded names.

    Sources: the built-in plugins/ package, plus .py files in the folders
    listed in env AGENT_LEDGER_PLUGINS (os.pathsep separated).
    """
    mods = []
    for m in pkgutil.iter_modules(_PLUGIN_PATH):
        mods.append((m.name, importlib.import_module(
            "agent_ledger.plugins." + m.name)))
    for d in filter(None, os.environ.get("AGENT_LEDGER_PLUGINS", "").split(os.pathsep)):
        if os.path.isdir(d):
            for fn in sorted(os.listdir(d)):
                if fn.endswith(".py") and not fn.startswith("_"):
                    try:
                        mods.append((fn[:-3], _load_file(os.path.join(d, fn))))
                    except Exception as ex:
                        print("warning: plugin %s failed: %s" % (fn, ex), file=sys.stderr)
    loaded = []
    for name, mod in mods:
        if hasattr(mod, "register"):
            mod.register(subparsers)
            loaded.append(name)
    return loaded


def build_parser():
    ap = argparse.ArgumentParser(
        prog="agent-ledger",
        description="Tamper-evident shared activity ledger for coding agents.")
    ap.add_argument("--ledger", help="ledger file (default: env AGENT_LEDGER "
                    "or ~/.agent-ledger/ledger.jsonl)")
    sub = ap.add_subparsers(dest="cmd", metavar="<command>")
    sub.required = True

    p = sub.add_parser("log", help="append an entry")
    p.add_argument("--agent", required=True)
    p.add_argument("--action", help="what the agent did")
    p.add_argument("--cost", type=float, default=0.0, help="cost in USD")
    p.add_argument("--files", help="comma-separated file list")
    p.add_argument("--session", help="session id (enables per-session budgets)")
    p.add_argument("--hook-stdin", action="store_true",
                   help="read a Claude Code hook JSON payload from stdin")
    p.set_defaults(func=cmd_log)

    p = sub.add_parser("verify", help="check the chain (exit 1 if broken)")
    p.add_argument("--anchor", help="also require this hash to be in the chain")
    p.add_argument("--signatures", action="store_true",
                   help="also check signed heads and report the unsigned tail")
    p.add_argument("--min-entries", type=int, metavar="N",
                   help="fail if the ledger has fewer than N entries (rollback guard)")
    p.add_argument("--allow-rotation", action="store_true",
                   help="accept more than one signer fingerprint in the chain")
    p.add_argument("--no-state", action="store_true",
                   help="skip the high-water-mark file check (.state next to the ledger)")
    p.add_argument("--allowed-signers", help="allowed_signers file (default: "
                   "~/.agent-ledger/keys/allowed_signers)")
    p.set_defaults(func=cmd_verify)

    p = sub.add_parser("report", help="per-agent summary and recent actions")
    p.add_argument("--html", metavar="OUT", help="write one self-contained HTML report")
    p.set_defaults(func=cmd_report)

    p = sub.add_parser("anchor", help="print latest hash to store elsewhere")
    p.add_argument("--git", action="store_true",
                   help="also write it into a local annotated git tag (no push)")
    p.set_defaults(func=cmd_anchor)

    load_plugins(sub)
    return ap


def main(argv=None):
    args = build_parser().parse_args(argv)
    return args.func(args)
