"""agent-ledger: a tamper-evident shared activity ledger for coding agents."""
from .core import (GENESIS, append, anchor, default_path, read, redact,
                   verify)

__version__ = "0.1.0"
__all__ = ["GENESIS", "append", "anchor", "default_path", "read", "redact",
           "verify"]
