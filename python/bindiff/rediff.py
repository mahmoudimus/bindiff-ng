"""Comparing again while keeping the matches a person has stood behind.

BinDiff calls this "Diff Database Incrementally". The engine side is
`bindiff.incremental_diff`: every match in a seed `.BinDiff` is re-created as
a fixed point before matching starts, every step skips a function that
already has one, and the propagation through the call graph runs from *all*
fixed points -- so the kept pairs anchor what is found around them, and their
own similarity and confidence are recomputed from the new exports.

What is kept is the caller's decision, and the two choices differ in kind:

* ``KEEP_CONFIRMED`` -- matches verified or paired by hand (stored as the
  manual algorithm at confidence 1.0) and matches something was ported
  through (the ``commentsported`` flag). Upstream's C++ plugin keeps only the
  manual ones; a port is included here because a ported name now exists on
  both sides, and a full re-diff would pair it by name and vouch for it
  whether or not it was right.
* ``KEEP_ALL`` -- every current match. Locks in matches nobody looked at.

The engine writes a fresh result: confidence is recomputed, so a verified
match would no longer read as manual, and the ported flag is not carried.
`carry_marks` puts both back. The seed carries what it needs for that itself,
so nothing here depends on the session that built it.

No IDA and no extension: plain sqlite3, so it is tested anywhere.
"""

from __future__ import annotations

import sqlite3
from typing import Iterable, List, Sequence, Tuple

from bindiff.database import (MANUAL_ALGORITHM, BinDiffDatabase, FunctionMatch,
                              _to_signed, _to_unsigned)

KEEP_CONFIRMED = "confirmed"
KEEP_ALL = "all"
KEEP_MODES = (KEEP_CONFIRMED, KEEP_ALL)


def is_confirmed(match: FunctionMatch) -> bool:
    """Verified, paired by hand, or ported through."""
    return match.manual or bool(match.comments_ported)


def kept_matches(matches: Iterable[FunctionMatch],
                 mode: str = KEEP_CONFIRMED) -> List[FunctionMatch]:
    if mode not in KEEP_MODES:
        raise ValueError(f"unknown keep mode {mode!r}; expected one of "
                         f"{KEEP_MODES}")
    matches = list(matches)
    if mode == KEEP_ALL:
        return matches
    return [match for match in matches if is_confirmed(match)]


def write_seed(matches: Sequence[FunctionMatch], path: str) -> int:
    """Writes the matches to keep as a minimal `.BinDiff` the engine seeds
    from. Returns how many were written.

    Built from the open connection's rows rather than by copying the file:
    edits not yet saved -- a verify, an unmatch -- live in that connection's
    transaction and are not on disk, and they are exactly the ones a person
    re-diffing after an edit means.

    Only what the engine reads (`function.address1/address2/algorithm`
    joined to `functionalgorithm`) plus the two marks `carry_marks` restores.
    """
    connection = sqlite3.connect(path)
    try:
        connection.executescript("""
            DROP TABLE IF EXISTS function;
            DROP TABLE IF EXISTS functionalgorithm;
            CREATE TABLE functionalgorithm (id SMALLINT, name TEXT);
            CREATE TABLE function (id INT, address1 BIGINT, address2 BIGINT,
                algorithm SMALLINT, confidence DOUBLE PRECISION,
                commentsported BOOLEAN);
        """)
        algorithms: dict = {}
        for match in matches:
            if match.algorithm not in algorithms:
                algorithms[match.algorithm] = len(algorithms) + 1
                connection.execute(
                    "INSERT INTO functionalgorithm VALUES (?, ?)",
                    (algorithms[match.algorithm], match.algorithm))
            connection.execute(
                "INSERT INTO function VALUES (?, ?, ?, ?, ?, ?)",
                (match.id, _to_signed(match.address_primary),
                 _to_signed(match.address_secondary),
                 algorithms[match.algorithm], match.confidence,
                 1 if match.comments_ported else 0))
        connection.commit()
        return len(matches)
    finally:
        connection.close()


def _seed_marks(seed_path: str) -> Tuple[set, set]:
    """(pairs that were manual, pairs that were ported), by address pair."""
    connection = sqlite3.connect(seed_path)
    try:
        manual, ported = set(), set()
        for address1, address2, name, confidence, flag in connection.execute("""
                SELECT f.address1, f.address2, COALESCE(a.name, ''),
                       f.confidence, f.commentsported
                FROM function AS f
                LEFT JOIN functionalgorithm AS a ON f.algorithm = a.id"""):
            pair = (_to_unsigned(address1), _to_unsigned(address2))
            if confidence == 1.0 and "manual" in name:
                manual.add(pair)
            if flag:
                ported.add(pair)
        return manual, ported
    finally:
        connection.close()


def carry_marks(seed_path: str, output_path: str) -> dict:
    """Restores "verified" and "ported" on the pairs that kept them.

    By address pair, not id: the engine numbers its output afresh. A pair the
    new exports no longer contain was dropped by the engine and is simply
    absent; it is counted, not an error.
    """
    manual, ported = _seed_marks(seed_path)
    database = BinDiffDatabase.open(output_path, read_only=False)
    try:
        by_pair = {(m.address_primary, m.address_secondary): m
                   for m in database.matches(order_by_similarity=False)}
        # Already manual in the output means the engine kept the algorithm
        # name and the confidence came out 1.0 anyway; confirming again would
        # only count a change that did not happen.
        confirm = [by_pair[p].id for p in manual
                   if p in by_pair and not by_pair[p].manual]
        flag = [by_pair[p].id for p in ported
                if p in by_pair and not by_pair[p].comments_ported]
        if confirm:
            database.confirm_matches(confirm)
        if flag:
            database.set_comments_ported(flag)
        database.commit()
        missing = len((manual | ported) - set(by_pair))
        return {"verified": sum(1 for p in manual if p in by_pair),
                "ported": sum(1 for p in ported if p in by_pair),
                "dropped": missing}
    finally:
        database.close()


__all__ = ["KEEP_ALL", "KEEP_CONFIRMED", "KEEP_MODES", "carry_marks",
           "is_confirmed", "kept_matches", "write_seed", "MANUAL_ALGORITHM"]
