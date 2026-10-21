import pytest

from taintwatch import Integrity, Label
from taintwatch.spans import FastSpanIndex, TStr


def test_fast_span_index_point_query() -> None:
    u = Label(Integrity.UNTRUSTED, sources=frozenset({"web"}))
    usr = Label(Integrity.USER, sources=frozenset({"user"}))

    # Segment 0-5 (USER), 5-10 (UNTRUSTED), 10-15 (USER)
    s1 = TStr.of("hello", usr)
    s2 = TStr.of("world", u)
    s3 = TStr.of("again", usr)
    t = s1 + s2 + s3

    index = FastSpanIndex.from_tstr(t)
    assert index.size == 3
    assert index.total_length == 15

    assert index.query_point(2).integrity == Integrity.USER
    assert index.query_point(7).integrity == Integrity.UNTRUSTED
    assert index.query_point(12).integrity == Integrity.USER

    with pytest.raises(IndexError):
        index.query_point(15)


def test_fast_span_index_range_query() -> None:
    u = Label(Integrity.UNTRUSTED)
    usr = Label(Integrity.USER)

    t = TStr.of("AAAAA", usr) + TStr.of("BBBBB", u) + TStr.of("CCCCC", usr)
    index = FastSpanIndex.from_tstr(t)

    # Range covering B (5-10) and start of C (10-12)
    segs = index.query_range(7, 12)
    assert len(segs) == 2
    assert segs[0].start == 5 and segs[0].end == 10
    assert segs[1].start == 10 and segs[1].end == 15


def test_fast_span_index_has_taint_pruning() -> None:
    u = Label(Integrity.UNTRUSTED)
    usr = Label(Integrity.USER)

    # Clean prefix, untrusted middle, clean suffix
    t = TStr.of("A" * 100, usr) + TStr.of("B" * 50, u) + TStr.of("C" * 100, usr)
    index = FastSpanIndex.from_tstr(t)

    # Clean prefix has no taint below USER
    assert index.has_taint_below(Integrity.USER, 0, 100) is False

    # Middle section contains UNTRUSTED taint
    assert index.has_taint_below(Integrity.USER, 100, 150) is True

    # Whole text contains UNTRUSTED taint
    assert index.has_taint_below(Integrity.USER, 0, 250) is True

    # Suffix is clean
    assert index.has_taint_below(Integrity.USER, 150, 250) is False


def test_large_interspersed_index_consistency() -> None:
    u = Label(Integrity.UNTRUSTED)
    usr = Label(Integrity.USER)

    # Create 50 alternating chunks
    parts = []
    for i in range(50):
        lbl = u if i % 2 == 0 else usr
        parts.append(TStr.of(f"chunk_{i:03d}_", lbl))

    t = parts[0]
    for p in parts[1:]:
        t = t + p

    index = FastSpanIndex.from_tstr(t)
    assert index.size == 50

    # Verify query_point against tstr.label_at for every 10th index
    for idx in range(0, len(t), 10):
        assert index.query_point(idx) == t.label_at(idx)
