# 15-second video: shot list

Record a terminal, large font, dark theme. Run `demo/demo.sh` (it paces itself;
`DEMO_OPEN=1` opens the HTML report at the end).

| Time | Shot | On-screen text |
|------|------|----------------|
| 0-2s | Black screen, text only | "Your agents keep their own logs. They can rewrite them." |
| 2-5s | `log` lines, then agent reads `.env`: ASK (you get a prompt), then `curl -d @.env`: BLOCKED (exit 2) | "Agent tries to read .env. ASK: needs your OK. Tries to send it out. BLOCKED. Both recorded in the chain." |
| 5-7s | `verify` prints VERIFY OK | "VERIFY OK: 5 entries" |
| 7-10s | The `sed` edit turns DENY into ALLOW | "The agent rewrites its own denial..." |
| 10-12s | `verify` prints VERIFY FAIL at line 5 in red | "Caught. Line 5." |
| 12-14s | Browser: HTML report, red "Chain BROKEN at line 5" banner | "Re-verified in your browser." |
| 14-15s | Title card | "agent-ledger. A flight recorder agents cannot quietly edit. MIT." |

Notes: keep the sed command visible for a full second; zoom on "line 5" and on
the ASK and BLOCKED lines. For the report shot, open the file after the tamper step so
the banner is red. Do not show real paths, usernames or keys.
