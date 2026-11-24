# Extending agent-ledger

Any module in `agent_ledger/plugins/` that defines `register(subparsers)` is
loaded automatically and can add a command. You can also keep plugins outside
the package: put `.py` files in a folder and set
`AGENT_LEDGER_PLUGINS=/path/to/folder` (several folders: separate with `:`).

Set `func` on your parser; it receives the parsed args and returns an exit code.
`args.ledger` is the `--ledger` value (pass it to `core.default_path`).

## Example: a `count` plugin

```python
# agent_ledger/plugins/count.py
from .. import core


def run(args):
    entries = core.read(core.default_path(args.ledger))
    print("%d entries" % len(entries))
    # record your own result in the chain if you want:
    core.append(core.default_path(args.ledger), "count-plugin", "counted ledger")
    return 0


def register(subparsers):
    p = subparsers.add_parser("count", help="count ledger entries")
    p.set_defaults(func=run)
```

Run it: `python3 -m agent_ledger count`

Rules of thumb: use `core.append` for writes (it locks and chains), never write
the file yourself; keep plugins read-only toward the outside world; output ASCII.
