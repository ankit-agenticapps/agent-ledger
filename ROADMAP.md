# Roadmap (extension ideas)

- Signed entries: sign each hash with a local key (e.g. ed25519 via an optional
  plugin) so a full-file rewrite also needs the key.
- Mobile viewer: a read-only page or small app showing the report and verify status.
- Cost import from agent logs: plugins that read each agent's own usage logs and
  log the cost automatically.
- Web dashboard: local read-only page with per-agent charts and a verify badge.
- Auto-anchoring: write the latest hash to a git commit or a remote note on a schedule.
- Log rotation with a chained handoff entry between files.
- More hook recipes for other agents.
