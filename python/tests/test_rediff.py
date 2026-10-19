"""Comparing again while keeping confirmed matches (bindiff.rediff).

The first half needs neither IDA nor the extension: what is kept, and that the
seed answers the engine's own seeding query. The second half runs the engine
end to end, because the claims that matter -- kept pairs survive, their marks
survive, the rest is matched afresh -- are about what the engine writes.
"""

import sqlite3

import pytest

from bindiff.database import MANUAL_ALGORITHM, BinDiffDatabase, FunctionMatch
from bindiff.rediff import (KEEP_ALL, KEEP_CONFIRMED, carry_marks,
                            is_confirmed, kept_matches, write_seed)


def match(id, *, algorithm="function: hash matching", confidence=0.9,
          ported=False, primary=0x401000, secondary=0x501000):
    return FunctionMatch(
        id=id, address_primary=primary + id, name_primary=f"p{id}",
        address_secondary=secondary + id, name_secondary=f"s{id}",
        similarity=0.9, confidence=confidence, flags=0, algorithm=algorithm,
        comments_ported=ported, basic_blocks=1, edges=0, instructions=3)


MATCHES = [
    match(1),                                                  # nobody looked
    match(2, algorithm=MANUAL_ALGORITHM, confidence=1.0),      # verified
    match(3, ported=True),                                     # ported through
    match(4, algorithm=MANUAL_ALGORITHM, confidence=0.7),      # manual name, not confirmed
]

# The query wrappers.cc runs to seed, verbatim. The seed is only useful if
# this answers it.
ENGINE_SEED_QUERY = """
    SELECT f.address1, f.address2, COALESCE(a.name, '')
    FROM function AS f
    LEFT JOIN functionalgorithm AS a ON f.algorithm = a.id
"""


class TestWhatIsKept:
    def test_confirmed_is_verified_by_hand_or_ported(self):
        assert [m.id for m in kept_matches(MATCHES, KEEP_CONFIRMED)] == [2, 3]

    def test_manual_needs_full_confidence(self):
        # The rule FixedPointInfo::IsManual() applies; a manual algorithm
        # name alone is not a confirmation.
        assert not is_confirmed(MATCHES[3])

    def test_all_is_all(self):
        assert kept_matches(MATCHES, KEEP_ALL) == MATCHES

    def test_an_unknown_mode_is_refused(self):
        with pytest.raises(ValueError):
            kept_matches(MATCHES, "most")


class TestSeed:
    def test_the_engine_query_reads_it(self, tmp_path):
        seed = tmp_path / "seed.BinDiff"
        assert write_seed(kept_matches(MATCHES), str(seed)) == 2
        rows = sqlite3.connect(seed).execute(ENGINE_SEED_QUERY).fetchall()
        assert sorted(rows) == [
            (0x401002, 0x501002, MANUAL_ALGORITHM),
            (0x401003, 0x501003, "function: hash matching"),
        ]

    def test_high_addresses_survive(self, tmp_path):
        seed = tmp_path / "seed.BinDiff"
        high = match(9, algorithm=MANUAL_ALGORITHM, confidence=1.0,
                     primary=0xFFFFFFFF00000000, secondary=0x8000000000000000)
        write_seed([high], str(seed))
        address1, address2, _ = sqlite3.connect(seed).execute(
            ENGINE_SEED_QUERY).fetchone()
        # Stored signed, as the engine's own writer does.
        assert address1 & (2**64 - 1) == high.address_primary
        assert address2 & (2**64 - 1) == high.address_secondary

    def test_rewriting_replaces(self, tmp_path):
        seed = tmp_path / "seed.BinDiff"
        write_seed(MATCHES, str(seed))
        write_seed(MATCHES[:1], str(seed))
        assert len(sqlite3.connect(seed).execute(ENGINE_SEED_QUERY).fetchall()) == 1


# -- end to end ----------------------------------------------------------------


@pytest.fixture
def first_result(bindiff_module, insider_pair, tmp_path):
    """A real result with two matches verified and one ported, unsaved --
    the state a person is in when they reach for "Compare again"."""
    primary, secondary = insider_pair
    path = tmp_path / "first.BinDiff"
    assert bindiff_module.diff(str(primary), str(secondary), str(path)) == 0
    database = BinDiffDatabase.open(str(path), read_only=False)
    matches = database.matches()
    # Weakest first, so a confirmation is a real change of state rather than
    # a hash match that was manual-strength anyway.
    weakest = sorted(matches, key=lambda m: m.confidence)
    verified = [weakest[0].id, weakest[1].id]
    database.confirm_matches(verified)
    database.set_comments_ported([weakest[2].id])
    yield database, verified, weakest[2].id
    database.close()


def _pair(m):
    return (m.address_primary, m.address_secondary)


@pytest.mark.requires_extension
@pytest.mark.e2e
class TestCompareAgain:
    def test_unsaved_edits_reach_the_seed(self, first_result, tmp_path):
        database, verified, ported = first_result
        assert database.has_unsaved_changes
        seed = tmp_path / "seed.BinDiff"
        kept = kept_matches(database.matches(), KEEP_CONFIRMED)
        write_seed(kept, str(seed))
        assert {m.id for m in kept} == set(verified) | {ported}

    def test_kept_pairs_survive_with_their_marks(
            self, first_result, insider_pair, tmp_path):
        from bindiff.headless import incremental

        database, verified, ported = first_result
        before = {m.id: m for m in database.matches()}
        seed = tmp_path / "seed.BinDiff"
        write_seed(kept_matches(database.matches(), KEEP_CONFIRMED), str(seed))

        output = tmp_path / "again.BinDiff"
        result = incremental(str(insider_pair[0]), str(insider_pair[1]),
                             str(seed), str(output))
        assert result.ok, result.message
        assert result.details["dropped"] == 0

        with BinDiffDatabase.open(str(output)) as again:
            by_pair = {_pair(m): m for m in again.matches()}
        for match_id in verified:
            kept = by_pair[_pair(before[match_id])]
            # The engine recomputes confidence; carry_marks puts the
            # confirmation back, or the row would stop reading as verified.
            assert kept.manual, kept
        assert by_pair[_pair(before[ported])].comments_ported
        # Nothing else carries a mark it did not earn.
        assert sum(m.manual for m in by_pair.values()) == len(verified)
        assert sum(bool(m.comments_ported) for m in by_pair.values()) == 1

    def test_the_rest_is_matched_afresh(
            self, bindiff_module, first_result, insider_pair, tmp_path):
        """Keeping three pairs must not cost the diff its other matches."""
        from bindiff.headless import incremental

        database, _verified, _ported = first_result
        plain = len(database.matches())
        seed = tmp_path / "seed.BinDiff"
        write_seed(kept_matches(database.matches(), KEEP_CONFIRMED), str(seed))
        output = tmp_path / "again.BinDiff"
        result = incremental(str(insider_pair[0]), str(insider_pair[1]),
                             str(seed), str(output))
        assert result.ok, result.message
        assert result.details["new"] > 0
        assert result.matches >= plain - 1, (result.matches, plain)

    def test_the_worker_takes_a_seed(
            self, first_result, insider_pair, tmp_path, capsys):
        from bindiff.headless import StageResult, main

        database, _verified, _ported = first_result
        seed = tmp_path / "seed.BinDiff"
        write_seed(kept_matches(database.matches(), KEEP_CONFIRMED), str(seed))
        output = tmp_path / "again.BinDiff"
        code = main(["pipeline", str(insider_pair[0]), str(insider_pair[1]),
                     str(output), "--keep", str(seed)])
        line = [l for l in capsys.readouterr().out.splitlines()
                if l.startswith("{") and '"stage"' in l][-1]
        result = StageResult.from_json(line)
        assert code == 0 and result.ok, result.message
        assert result.details["verified"] == 2
        assert result.details["ported"] == 1


def test_carry_marks_counts_a_pair_the_engine_dropped(
        bindiff_module, insider_pair, tmp_path):
    """A kept pair whose functions are gone from the new export is absent
    from the output. Counted, never invented."""
    primary, secondary = insider_pair
    output = tmp_path / "out.BinDiff"
    assert bindiff_module.diff(str(primary), str(secondary), str(output)) == 0
    seed = tmp_path / "seed.BinDiff"
    write_seed([match(1, algorithm=MANUAL_ALGORITHM, confidence=1.0,
                      primary=0x7777000000, secondary=0x7777000000)], str(seed))
    assert carry_marks(str(seed), str(output)) == {
        "verified": 0, "ported": 0, "dropped": 1}


test_carry_marks_counts_a_pair_the_engine_dropped = pytest.mark.requires_extension(
    test_carry_marks_counts_a_pair_the_engine_dropped)
