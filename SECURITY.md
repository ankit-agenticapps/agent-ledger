# Security model

agent-ledger is a tamper-evident log plus a guard rail for coding agents. It is
not a sandbox. This file says what it defends against and what it does not.

## What it does

- **Hash chain** over every entry; canonical line format, monotonic timestamps,
  symlink and non-regular-file refusal. `verify` names the first bad line.
- **High-water mark** (`<ledger>.state`: count + head) catches truncation, an
  emptied ledger and rewritten history until that file is also changed.
- **Signed heads** (`sign`, ssh-keygen) with the signer fingerprint recorded in
  the chain by `keygen` and `sign`. `verify --signatures` fails on a missing sigs
  file once signing was set up, a swapped `allowed_signers`, a different signer,
  removed newer signatures, or a signed head that is not in the chain.
  `verify --min-entries N` and `--anchor HASH` check against values you kept.
- **policy-check** (Claude Code PreToolUse hook): deny / ask / allow per rule,
  fail-closed on any error, hard-coded self-protection of its own control files,
  every decision recorded in the chain.

## What it cannot do

1. **Same-user attacker.** Anything running as you can rewrite the ledger, the
   sigs, `.state`, `allowed_signers`, the policy file and `~/.claude/settings.json`
   by a route the hook does not see (another process, a tool not hooked, a
   script run outside the agent). A chain rebuilt from genesis with the attacker's
   own key verifies. Defences that work: keep the private signing key off-box or
   under another user; record the head hash somewhere the agent cannot write
   (separate git identity, remote, paper) and check it with `verify --anchor` /
   `--min-entries`; run the agent as a different OS user with a read-only policy
   and managed (root-owned) Claude Code settings.
2. **Heuristic shell parsing.** The lexer handles common shapes and asks a human
   when a command is unparseable, over 20,000 characters or uses an unresolvable
   command name or path variable. It cannot see inside scripts, aliases,
   `python script.py`, encoded payloads it does not recognise, or what a binary
   does. Treat a pass as "no known bad pattern", not "safe".
3. **No OS-level sandbox.** There is no seccomp, chroot, container or user
   separation. Use those for real isolation.
4. **Budget is advisory.** Only reported costs count; sessions are keyed by the
   hook's session id; a new session id starts a new budget unless
   `max_cost_usd_per_day` is set.
5. **Redaction is pattern-based.** Split or encoded secrets can survive.
6. **Hook coverage depends on configuration.** Use the matcher printed by
   `agent-ledger hooks` (Bash, file tools, Glob, Grep, LS, WebFetch, Task and
   `mcp__.*`). A tool or agent that does not call the hook is not covered.

## Reporting

Open a private issue with a reproduction (the policy-check payload and expected
rc). No network access is needed to reproduce anything in this tool.
