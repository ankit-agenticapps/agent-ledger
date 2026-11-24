# agent-ledger

**A flight recorder that agents cannot quietly edit.**

One shared, hash-chained, optionally signed record of what every coding agent
on your machine did, what it was allowed to do, and what it cost. Zero
third-party dependencies, Python 3.9+, plain files, no network calls.

## The problem

You run Claude Code, Codex and maybe others at once. Each keeps its own logs,
and each can rewrite them. Plain logging also has two well-known gaps: "logging
is not enforcement" (it records the bad thing after it happened) and "an
unsigned chain can be rewritten by the agent itself". agent-ledger addresses
both, and records every allow/deny decision in the same chain as the actions.

## Three features

1. **Signed head + anchor.** `agent-ledger sign` signs the current head hash
   (plus entry count and timestamp) with an ed25519 key via `ssh-keygen -Y`.
   `verify --signatures` checks every signature and reports the last signed
   point and the `unsigned tail: N entries`. `anchor --git` writes the head hash
   into a local annotated git tag.
2. **Policy hard-block.** `agent-ledger policy-check` is a Claude Code
   PreToolUse hook: it exits 2 with a reason when a rule blocks the call (secret
   files, `rm -rf` outside the project, force-push to main, `curl | sh`, known
   secret patterns, per-session budget cap). Every decision, allow or deny, is
   appended to the chain.
3. **HTML report.** `report --html out.html` writes one self-contained file
   (no external requests): timeline grouped by agent, denials highlighted, cost
   totals, signature status, and the chain is re-verified in your browser with
   SHA-256, showing "chain intact" or "broken at line N". Dark/light, phone
   friendly.

## 10-second quickstart

```
python3 -m agent_ledger log --agent claude-code --action "edited auth.py" --cost 0.42 --files auth.py
python3 -m agent_ledger verify
python3 -m agent_ledger report --html report.html
```

Optional: `pip install -e .` gives the short `agent-ledger` command. Default
file: `~/.agent-ledger/ledger.jsonl` (change with `--ledger PATH` or the
`AGENT_LEDGER` environment variable).

Wire it into Claude Code:

```
agent-ledger policy init     # writes ~/.agent-ledger/policy.json (editable)
agent-ledger hooks           # prints settings JSON: PreToolUse -> policy-check, PostToolUse -> log
```

## Signing

```
agent-ledger keygen          # key in ~/.agent-ledger/keys/ (0600) + allowed_signers
agent-ledger sign [--key PATH]
agent-ledger verify --signatures
agent-ledger anchor --git    # local annotated tag, never pushed
```

```
$ agent-ledger verify --signatures
VERIFY OK: 6 entries, chain intact
signatures: 1 checked, 1 valid, 0 bad
last signed point: entry 5 at 2026-11-24T09:20:00Z (head 3fa9c01b22de)
unsigned tail: 1 entries
```

Signatures live in `ledger.jsonl.sigs` (one JSON per line: head, count, ts,
signature). If the ledger is truncated or rewritten below a signed point, the
signed head no longer matches and `verify --signatures` exits 1. If
`ssh-keygen` is missing, signature commands print a clear message and skip.

**Honest limit:** an attacker running as your user can delete the key and the
`.sigs` file, or sign a forged chain with a key they generate. Signatures only
help if the private key lives where the agent cannot reach: another OS user,
another machine, or a hardware key. `keygen` prints this advice; keep only the
`.pub` and `allowed_signers` next to the agent.

## Policy

`policy.json` (written by `policy init`; built-in defaults apply if absent):

```
{"block_paths": [".env", ".env.*", "*.pem", "id_rsa", "id_ed25519", "~/.ssh", "~/.aws"],
 "allow_paths": [".env.example", ".env.sample"],
 "block_rm_outside_project": true,
 "block_force_push_branches": ["main", "master"],
 "block_pipe_to_shell": true,
 "block_secret_patterns": true,
 "max_cost_usd": 5.0}
```

Budget: costs come from ledger entries tagged with the session id
(`log --session ID --cost X`; the PostToolUse hook tags automatically). The
call is blocked when the session total is greater than `max_cost_usd`.

Decisions look like `policy:DENY Read .env -- Read of '.env' blocked by path
rule '.env' [session=abc]`. A malformed policy file fails closed (blocks).
Unparseable hook input is allowed and recorded.

**Heuristic, not a sandbox.** Shell parsing is best-effort: it splits on
`; && || |`, resolves `~`, `$HOME` and relative paths, and pattern-matches
`curl|sh`. It will miss obfuscation (`eval`, base64, a script that does the
bad thing internally, variables other than `$HOME`, which it treats as
unresolvable and blocks for `rm -rf`). Treat it as a strong guard rail against
mistakes and casual misuse, and pair it with OS-level permissions for real
isolation.

## Commands

- `log --agent NAME --action TEXT [--cost USD] [--files a,b] [--session ID]`
- `verify [--anchor HASH] [--signatures] [--allowed-signers FILE]` exit 0 fine, 1 broken
- `report [--html OUT]` per-agent totals, or the HTML report
- `anchor [--git]` print newest hash and count; optionally tag it in git
- `keygen`, `sign [--key PATH]`
- `policy-check [--policy FILE]` hook entry point; `policy init|show`
- `audit` read-only check of your agent permissions, saved as an entry
- `hooks` print ready-to-paste setup for Claude Code and Codex

Secrets are never stored: text that looks like an API key (`sk-...`, `ghp_...`,
`AKIA...`, long random-looking tokens) is replaced with `[redacted]`.

## How it compares

| | Plain agent logs | Hook + SQLite + YAML policy tools (e.g. Gryph) | agent-ledger |
|---|---|---|---|
| Records actions | per agent, own format | yes | yes, one file for all agents |
| Edit/delete detectable | no | depends on store | yes, hash chain, names the line |
| Survives the agent rewriting history | no | not by itself | detectable with signed heads kept off-box |
| Blocks risky calls | no | yes, policy file | yes, policy.json |
| Blocking decisions recorded | n/a | in the tool's store | in the same signed chain as the actions |
| Storage / deps | text files | SQLite + YAML | one JSONL file, standard library only |

Tools in the hooks-plus-policy family do real, useful work and solve the
"enforce" half well. What we do differently: the allow/deny decisions live in
the same tamper-evident chain as everything else, across many agents at once,
and the chain can be anchored by a signature or a git tag so rewriting it
requires something the agent should not have. Use them together if you like.

## Have your own agent install it

> Set up agent-ledger from this folder: run `python3 -m agent_ledger policy init`,
> then `python3 -m agent_ledger hooks`, add the Claude Code hook JSON to my
> settings.json and the Codex wrapper to my shell profile, then run
> `python3 -m agent_ledger log --agent setup --action "installed agent-ledger"`
> and `python3 -m agent_ledger verify`.

## Extending

Drop a module with `register(subparsers)` into `agent_ledger/plugins/`. See
`docs/EXTENDING.md`. Ideas are in `ROADMAP.md`.

## Honest limits

- The chain detects edits, deletions in the middle, and reordering. It does
  not stop them; the policy hook stops only what its heuristics recognize.
- Without a signature or anchor kept elsewhere, someone with write access can
  rebuild the whole file from line one and it passes `verify`.
- Removing the last entries leaves a valid chain; signed heads, `--anchor` and
  git tags are what reveal it (and only for points you signed or anchored).
- Same-user attackers can delete the signing key. Keep the private key
  elsewhere.
- The browser check re-computes hashes; it proves internal consistency of the
  file you opened, not that the file is the original.

Run tests: `python3 -m unittest discover -s tests`. Demo: `sh demo/demo.sh`.
