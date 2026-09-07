"""
BinDiff Python Interface
=========================

A Cython-based Python interface for BinDiff binary diffing engine.

This package provides Python bindings to BinDiff's C++ core, enabling:
- Binary diffing and comparison
- Loading and analyzing BinExport files
- Managing diff results and databases
- Accessing match information and statistics

Example:
    Basic usage for diffing two binaries:

    >>> import bindiff
    >>> # Diff two BinExport files
    >>> bindiff.diff('primary.BinExport', 'secondary.BinExport', 'results.db')
    >>>
    >>> # Load and analyze results
    >>> results = bindiff.Results.load('results.db')
    >>> print(f"Matched functions: {results.num_matches}")
    >>> for match in results.matches:
    ...     print(f"  {match.primary_name} -> {match.secondary_name}")
"""

# The fork's own line. The major tracks the upstream engine generation --
# this is built on google/bindiff v8 -- and the minor is this fork's, so 8.1.0
# is "the v8 engine, first release of this fork". Upstream published v8 and
# never an 8.1, so the two cannot collide; the distribution is named
# bindiff-ng for the same reason, while the import name stays bindiff.
__version__ = "8.1.4"

from .database import (
    BinDiffDatabase,
    DiffMetadata,
    FunctionMatch,
    FileInfo,
    MANUAL_ALGORITHM,
)

__all__ = [
    # Main API
    "diff",
    "Results",

    # Reading and editing a .BinDiff file
    "BinDiffDatabase",
    "FunctionMatch",
    "FileInfo",
    "DiffMetadata",
    "MANUAL_ALGORITHM",


    # Loading functions
    "incremental_diff",
    "load_comments",
    "load_matches",
    "load_statistics",

    # Configuration
    "get_config",
    "get_default_config",
    "set_config",
    "reset_config",

    # Core types
    "CallGraph",
    "FlowGraph",
    "FixedPoint",

    # Data types
    "MatchInfo",
    "StatisticsInfo",
]


# Keep readers and plugin helpers usable without a compiled engine. Native
# imports still fail normally when an engine API is actually requested.
def __getattr__(name):
    if name not in __all__:
        raise AttributeError(f"module {__name__!r} has no attribute {name!r}")
    from importlib import import_module

    module = import_module(".results" if name == "Results" else ".core", __name__)
    value = getattr(module, name)
    globals()[name] = value
    return value


def __dir__():
    return sorted(set(globals()) | set(__all__))
