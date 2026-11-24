# agent-ledger

One shared, tamper-evident diary for every coding agent on your machine.

## The problem

You run Claude Code, Codex and maybe others at the same time. Each one keeps
its own logs, and each one can rewrite them. When something goes wrong, or the
bill is higher than expected, you cannot fully trust the record of who did what
or what it cost.

## The fix

agent-ledger keeps one append-only file. Every entry stores a fingerprint
(SHA-256 hash) of the entry before it, like links in a chain. Change, delete or
reorder any line and the chain breaks, and `verify` tells you which line.
No dependencies, Python 3.9+, plain files.

## 10-second quickstart

```
python3 -m agent_ledger log --agent claude-code --action "edited auth.py" --cost 0.42 --files auth.py
python3 -m agent_ledger verify
python3 -m agent_ledger report
```

Optional: `pip install -e .` gives you the short `agent-ledger` command.
Default file: `~/.agent-ledger/ledger.jsonl` (change with `--ledger PATH` or
the `AGENT_LEDGER` environment variable).

## Example output

```
$ agent-ledger verify
VERIFY OK: 5 entries, chain intact

$ agent-ledger report
AGENT            ENTRIES   COST USD  LAST SEEN
claude-code            2     1.3300  2026-11-24T09:15:02.113201Z
codex                  2     0.4300  2026-11-24T09:15:02.201554Z
gemini                 1     0.0700  2026-11-24T09:15:02.178003Z

(someone edits a line)
$ agent-ledger verify
VERIFY FAIL at line 2: entry content does not match its hash (line was edited)
```

## Commands

- `log --agent NAME --action TEXT [--cost USD] [--files a,b]` add an entry
- `verify [--anchor HASH]` exit 0 if fine, exit 1 and the first bad line if not
- `report` per-agent totals and the last 10 actions
- `anchor` print the newest hash and entry count
- `audit` read-only check of your agent permissions, result saved as an entry
- `hooks` print ready-to-paste setup for Claude Code and Codex

Secrets are never stored: text that looks like an API key (`sk-...`, `ghp_...`,
`AKIA...`, long random-looking tokens) is replaced with `[redacted]`.

## Have your own agent install it

Paste this to Claude Code or Codex:

> Set up agent-ledger from this folder: run `python3 -m agent_ledger hooks`,
> add the Claude Code hook JSON to my settings.json and the Codex wrapper to my
> shell profile, then run `python3 -m agent_ledger log --agent setup --action
> "installed agent-ledger"` and `python3 -m agent_ledger verify`.

## Extending

Drop a module with `register(subparsers)` into `agent_ledger/plugins/`. See
`docs/EXTENDING.md`. Ideas are in `ROADMAP.md`.

## Honest limits

- The chain detects edits, deletions in the middle, and reordering. It does
  not stop them.
- Someone with write access who rewrites the whole file from the first line
  can build a new, valid-looking chain. A forged file passes `verify`.
- Removing the last entries also leaves a valid chain, unless you have an anchor.
- Mitigation: run `agent-ledger anchor` and copy the hash somewhere an agent
  cannot edit (a git commit, a post, a note on another device). Later,
  `agent-ledger verify --anchor HASH` fails if that point is gone from the chain.
- Costs and actions are whatever the caller reports; the ledger proves they
  were not changed afterwards, not that they were true.
- Redaction is pattern-based and can miss unusual secrets.

## Tests and demo

```
python3 -m unittest discover -s tests
demo/demo.sh
```

MIT licensed.
