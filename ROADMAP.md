# Roadmap

Next
- Checkpoint/undo: snapshot touched files (or a git stash ref) before each
  allowed write, record the checkpoint id in the chain, `agent-ledger undo ID`.
- MCP server mode: let an agent query its own ledger (recent actions, its
  budget, why a call was denied) read-only, without being able to write history.
- Cross-agent budgets: one cap across Claude Code, Codex and others, not just
  per session, with the check recorded in the chain.

Later
- Per-entry signatures (so a full-file rewrite also needs the key).
- Cost import from agent logs: plugins that read each agent's usage logs.
- Policy: allowlists, per-agent rules, dry-run mode that only records.
- Log rotation with a chained handoff entry between files.
- More hook recipes for other agents.
