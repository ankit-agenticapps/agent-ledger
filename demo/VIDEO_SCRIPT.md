# 15-second video: shot list

Record a terminal, large font, dark theme. Run `demo/demo.sh` (it paces itself).

| Time | Shot | On-screen text |
|------|------|----------------|
| 0-2s | Black screen, text only | "Your agents keep their own logs. They can rewrite them." |
| 2-5s | Terminal: five `log` lines scroll by (3 agents) | "One shared ledger. Each entry locks in the one before." |
| 5-7s | `verify` prints VERIFY OK in green | "VERIFY OK: 5 entries" |
| 7-10s | The `sed` edit runs on one line | "One quiet edit to history..." |
| 10-13s | `verify` prints VERIFY FAIL at line 2 in red | "Caught. Line 2." |
| 13-15s | Title card | "agent-ledger. Zero dependencies. MIT." |

Notes: keep the sed command visible for a full second; zoom on "line 2".
Do not show real paths, usernames or keys.
