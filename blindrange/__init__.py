"""blindrange: range queries over encrypted data on blind, decentralized nodes."""
# Defined before the submodule imports: client and node both read it (for the
# User-Agent and the reported build), and importing it afterwards makes that a
# circular import.
__version__ = "0.7.0"

from .client import Owner        # noqa: E402
from .ring import Ring           # noqa: E402

__all__ = ["Owner", "Ring", "__version__"]
