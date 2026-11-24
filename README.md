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
2. **Policy: deny / ask / allow.** `agent-ledger policy-check` is a Claude Code
   PreToolUse hook. Each rule has an action: `deny` blocks (exit 2), `ask`
   makes Claude Code prompt you (exit 0 + PreToolUse JSON), `allow` just logs.
   Secret files ask; `rm -rf` outside the project, force-push to main,
   `curl | sh` and sending a secret file over the network deny. Every
   decision (ALLOW, ASK, DENY, with rule and reason) is appended to the chain.
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
agent-ledger hooks           # prints settings JSON: PreToolUse -> policy-check (deny/ask/allow), PostToolUse -> log
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

`policy init` writes `~/.agent-ledger/policy.json`; `policy explain` shows what
a call would do; `policy show` prints the active policy.

```
agent-ledger policy init
echo '{"tool_name":"Read","tool_input":{"file_path":".env"}}' | agent-ledger policy explain
# ASK  rule=secret-read  agent=claude-code
# why: Read of '.env' blocked by path rule '.env'
```

`explain` reads a hook payload on stdin and writes nothing (no ledger entry).

Each rule has an `id`, a `kind`, an `action` and optional exceptions:

```
{"rules": [
  {"id": "secret-read", "kind": "path_read", "action": "ask",
   "paths": [".env", ".env.*", "*.pem", "id_rsa", "id_ed25519", "~/.ssh", "~/.aws"],
   "allow_paths": [".env.example", ".env.sample"],
   "allow": [{"paths": ["{project}/.env"], "agents": ["deploy-bot"]}],
   "redact_output_note": "Do not repeat secret values in replies."},
  {"id": "ssh-aws-write", "kind": "path_write", "action": "deny", "paths": ["~/.ssh", "~/.aws"]},
  {"id": "secret-exfil", "kind": "net_exfil", "action": "deny", "paths": [".env", "~/.ssh"]},
  {"id": "rm-outside-project", "kind": "rm_outside_project", "action": "deny"},
  {"id": "force-push-main", "kind": "force_push", "action": "deny", "branches": ["main", "master"]},
  {"id": "pipe-to-shell", "kind": "pipe_to_shell", "action": "deny"}],
 "safe_env_read": true, "block_secret_patterns": true, "max_cost_usd": 5.0}
```

- Kinds: `path_read` (Read/Grep/Glob and read-style shell commands), `path_write`
  (Write/Edit, redirects, rm/mv/tee/cp destination), `path_any`, `net_exfil`
  (curl/wget/nc/scp with a secret file, `@file`, or `base64 .env | curl`),
  `rm_outside_project`, `force_push`, `pipe_to_shell`.
- Actions: `deny` -> stderr reason, exit 2 (shown as BLOCKED). `ask` -> stdout
  `{"hookSpecificOutput":{"hookEventName":"PreToolUse","permissionDecision":"ask",
  "permissionDecisionReason":"..."}}`, exit 0, you get the prompt. `allow` -> log only.
  If several rules match, deny beats ask beats allow.
- Exceptions: `allow_paths`, `allow_agents` (agent name globs, from
  `policy-check --agent NAME`) and `allow_commands` (globs on the full command)
  each waive the rule on their own. An `allow` entry with several keys needs all
  of them (e.g. `.env` in the project dir AND agent `deploy-bot`). `{project}`
  means `$CLAUDE_PROJECT_DIR`. A waived call is logged as ALLOW with the rule.
- `redact_output_note` is appended to the reason for ask/deny.
- Safe `.env` reads: commands that only print variable names are allowed and
  logged (`grep -o '^[A-Z_]*=' .env`, `cut -d= -f1 .env`,
  `awk -F= '{print $1}' .env`, `sed 's/=.*//' .env`). Disable with
  `"safe_env_read": false`.
- Budget: `max_cost_usd` stays a deny. Costs come from ledger entries tagged
  with the session id (`log --session ID --cost X`; the PostToolUse hook tags
  automatically); blocked when the session total is greater than the cap.
- No policy file: built-in strict defaults deny every secret-file touch. A
  policy file without `rules` (the old `block_paths` keys) also keeps the
  all-deny behavior.

Decisions look like `policy:ASK Read .env -- Read of '.env' blocked by path
rule '.env' (rule: secret-read) [session=abc]`.

**Fail-closed.** A malformed policy file, unusable hook input (empty, not JSON,
wrong types, invalid UTF-8, over 1 MB) or any internal error blocks the call
(exit 2) and is logged when the ledger can be written. If the ledger itself is
corrupt, replaced or unwritable the call is also blocked, so auditing cannot be
silently switched off. `policy-check --fail-open` restores the old "allow on
error" behaviour (unsafe; documented opt-out).

**Self-protection (not overridable by policy.json).** Writes to the policy file,
the ledger, `.sigs`, `.state`, the keys folder and `allowed_signers`,
`~/.agent-ledger`, `~/.claude/settings*.json`, `.claude/settings*.json` and
`~/.claude/hooks` are denied for every tool and for shell commands; reads ask.
Agents may not run `keygen`, `sign` or `policy init`.

**Shell parsing is heuristic, not a sandbox.** It tokenises quotes, `$()`,
backticks, `<()`, subshells, heredocs and wrappers (`sudo -u`, `env`, `timeout`,
`xargs`, `bash -c`, `eval`), resolves `~`, `$HOME`, `$PWD`, simple variables and
symlinks (realpath, case-insensitive), expands globs, and knows `rm`, `find
-delete`, `rsync --delete`, `git clean`, `git push` force/mirror/delete forms and
download-then-execute patterns. Anything it cannot parse or that is too long is
reported as `complex-command` and asks a human. It still cannot see what a
script does internally. See SECURITY.md.

## Commands

- `log --agent NAME --action TEXT [--cost USD] [--files a,b] [--session ID]`
- `verify [--anchor HASH] [--min-entries N] [--signatures] [--allow-rotation] [--no-state] [--allowed-signers FILE]`
  exit 0 fine, 1 broken. Also fails on truncation/rollback against the high-water
  mark (`<ledger>.state`), back-dated or non-canonical lines, and with
  `--signatures` on a missing sigs file after signing was set up, a swapped signer
  (fingerprint is recorded in the chain by `keygen`/`sign`), or removed signatures
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

Read SECURITY.md for the threat model. In short:

- The chain detects edits, deletions, reordering, back-dating and (via the
  `.state` high-water mark, `--min-entries`, `--anchor` and signed heads) most
  truncation and rollback. It does not stop any of it.
- **An attacker running as the same user can rewrite everything**: ledger, sigs,
  `.state`, allowed_signers, policy and the Claude Code hook settings. The hook
  refuses to help, but a process outside the hook (or a tool the hook does not
  see) is not stopped. Only an external anchor (a head hash kept off-box, a git
  tag pushed by another identity, a remote witness) or a signing key held by
  another user or machine closes this.
- A chain rebuilt from line one with the attacker's own key looks self-consistent;
  the fingerprint pin only helps while the original `keygen`/`sign` entries are
  still in the chain.
- **Shell parsing is heuristic.** Obfuscation, scripts that do the bad thing
  internally, `python script.py`, aliases and anything the lexer cannot judge
  (it asks) can slip through. There is **no OS-level sandbox**: use OS
  permissions, a separate user, containers or managed settings for real isolation.
- The budget cap counts only costs that something reports; the shipped
  PostToolUse hook logs cost 0.
- The browser check proves internal consistency of the file you opened, not that
  it is the original; compare the printed head hash with a trusted copy.

Run tests: `python3 -m unittest discover -s tests`. Demo: `sh demo/demo.sh`.
