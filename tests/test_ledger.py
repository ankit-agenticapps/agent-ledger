import argparse
import io
import json
import os
import subprocess
import sys
import tempfile
import unittest
from contextlib import redirect_stdout

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)
from agent_ledger import core, cli  # noqa: E402


def run_cli(*argv):
    buf = io.StringIO()
    with redirect_stdout(buf):
        code = cli.main(list(argv))
    return code, buf.getvalue()


class Base(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.path = os.path.join(self.tmp.name, "l.jsonl")

    def tearDown(self):
        self.tmp.cleanup()

    def fill(self, n=4):
        for i in range(n):
            core.append(self.path, "a%d" % (i % 2), "did thing %d" % i, 0.5, ["f.py"])

    def lines(self):
        with open(self.path) as f:
            return f.read().splitlines()

    def write(self, lines):
        with open(self.path, "w") as f:
            f.write("\n".join(lines) + "\n")


class TestAppendVerify(Base):
    def test_append_fields_and_chain(self):
        e = core.append(self.path, "claude", "edit", 1.25, "a.py,b.py")
        self.assertEqual(e["prev_hash"], core.GENESIS)
        self.assertEqual(e["files"], ["a.py", "b.py"])
        self.assertEqual(e["cost"], 1.25)
        e2 = core.append(self.path, "codex", "run")
        self.assertEqual(e2["prev_hash"], e["hash"])
        self.assertEqual(len(core.read(self.path)), 2)

    def test_verify_ok(self):
        self.fill()
        ok, line, why, n = core.verify(self.path)
        self.assertTrue(ok)
        self.assertEqual(n, 4)

    def test_tamper_edit(self):
        self.fill()
        ls = self.lines()
        ls[1] = ls[1].replace("did thing 1", "did thing X")
        self.write(ls)
        ok, line, why, _ = core.verify(self.path)
        self.assertFalse(ok)
        self.assertEqual(line, 2)

    def test_tamper_delete(self):
        self.fill()
        ls = self.lines()
        del ls[1]
        self.write(ls)
        ok, line, why, _ = core.verify(self.path)
        self.assertFalse(ok)
        self.assertEqual(line, 2)

    def test_tamper_reorder(self):
        self.fill()
        ls = self.lines()
        ls[1], ls[2] = ls[2], ls[1]
        self.write(ls)
        ok, line, _, _ = core.verify(self.path)
        self.assertFalse(ok)
        self.assertEqual(line, 2)

    def test_cli_verify_exit_codes(self):
        self.fill()
        self.assertEqual(run_cli("--ledger", self.path, "verify")[0], 0)
        ls = self.lines()
        ls[2] = ls[2].replace("0.5", "0.0")
        self.write(ls)
        code, out = run_cli("--ledger", self.path, "verify")
        self.assertEqual(code, 1)
        self.assertIn("line 3", out)

    def test_report(self):
        self.fill()
        code, out = run_cli("--ledger", self.path, "report")
        self.assertEqual(code, 0)
        self.assertIn("a0", out)
        self.assertIn("Last 10 actions", out)


class TestConcurrency(Base):
    def test_concurrent_processes(self):
        code = ("import sys; sys.path.insert(0, %r); from agent_ledger import core\n"
                "for i in range(25): core.append(%r, 'p'+sys.argv[1], 'x'*200+str(i))"
                % (ROOT, self.path))
        ps = [subprocess.Popen([sys.executable, "-c", code, str(i)]) for i in range(6)]
        for p in ps:
            self.assertEqual(p.wait(), 0)
        ok, line, why, n = core.verify(self.path)
        self.assertTrue(ok, why)
        self.assertEqual(n, 150)


class TestRedaction(Base):
    def test_patterns(self):
        for secret in ["sk-abcdefghijklmnop1234", "ghp_" + "a1B2" * 6,
                       "AKIAABCDEFGHIJKLMNOP", "aB3" * 14]:
            self.assertIn("[redacted]", core.redact("use " + secret + " now"))
            self.assertNotIn(secret, core.redact("use " + secret))

    def test_normal_text_kept(self):
        t = "edited /Users/x/project/src/module.py and ran tests"
        self.assertEqual(core.redact(t), t)

    def test_appended_entry_redacted(self):
        e = core.append(self.path, "a", "key sk-abcdefghijklmnop1234 used")
        self.assertIn("[redacted]", e["action"])
        with open(self.path) as f:
            self.assertNotIn("sk-abcdef", f.read())


class TestAnchor(Base):
    def test_anchor_and_verify(self):
        self.fill(3)
        h, n = core.anchor(self.path)
        self.assertEqual(n, 3)
        code, out = run_cli("--ledger", self.path, "anchor")
        self.assertIn(h, out)
        self.assertEqual(run_cli("--ledger", self.path, "verify", "--anchor", h)[0], 0)
        self.assertEqual(run_cli("--ledger", self.path, "verify", "--anchor", "f" * 64)[0], 1)

    def test_anchor_catches_tail_truncation(self):
        self.fill(3)
        h, _ = core.anchor(self.path)
        self.write(self.lines()[:2])
        self.assertTrue(core.verify(self.path)[0])
        self.assertFalse(core.verify(self.path, h)[0])


class TestPlugins(Base):
    def test_builtin_plugins_loaded(self):
        ap = argparse.ArgumentParser()
        sub = ap.add_subparsers()
        loaded = cli.load_plugins(sub)
        self.assertIn("audit", loaded)
        self.assertIn("hooks", loaded)

    def test_external_plugin_dir(self):
        d = os.path.join(self.tmp.name, "plug")
        os.mkdir(d)
        with open(os.path.join(d, "hello.py"), "w") as f:
            f.write("def run(a):\n    print('hi-plugin'); return 0\n"
                    "def register(s):\n    s.add_parser('hello').set_defaults(func=run)\n")
        os.environ["AGENT_LEDGER_PLUGINS"] = d
        try:
            code, out = run_cli("hello")
        finally:
            del os.environ["AGENT_LEDGER_PLUGINS"]
        self.assertEqual((code, out.strip()), (0, "hi-plugin"))

    def test_hooks_output(self):
        code, out = run_cli("hooks")
        self.assertEqual(code, 0)
        self.assertIn("PostToolUse", out)
        self.assertIn("agent-ledger log", out)
        json.loads(out.split("\n\n")[0].split("\n", 1)[1])

    def test_audit_records_entry(self):
        home = os.path.join(self.tmp.name, "home")
        os.makedirs(os.path.join(home, ".claude"))
        with open(os.path.join(home, ".claude", "settings.json"), "w") as f:
            json.dump({"permissions": {"allow": ["Bash(*)"]}}, f)
        code, out = run_cli("--ledger", self.path, "audit", "--home", home, "--dir", home)
        self.assertEqual(code, 0)
        self.assertIn("AGENT POWER SCORE", out)
        es = core.read(self.path)
        self.assertEqual(len(es), 1)
        self.assertTrue(es[0]["action"].startswith("audit:"))
        self.assertTrue(core.verify(self.path)[0])


if __name__ == "__main__":
    unittest.main()
