#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 INTERCHAINED LLC
# SPDX-License-Identifier: BUSL-1.1
# NEDB · © 2026 INTERCHAINED LLC × Eth-Interchained × Vex (Claude Opus 5)

"""Cross-language parity for state_root_v1.

The Rust engine and the Python reference must produce byte-identical roots for
every committed vector. This is the test that makes the vectors mean anything:
a format pinned by one implementation is not pinned, and the failure mode it
guards against is the quiet one -- two implementations that agree on every case
anyone happened to try, and differ on the one that ships.
"""
import json
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
sys.path.insert(0, os.path.join(ROOT, "python"))

from nedb.state_root import check_vectors, compute, record_leaf  # noqa: E402

VECTORS = os.path.join(ROOT, "vectors", "state_root_v1.json")


def test_vectors_agree():
    n, failures = check_vectors(VECTORS)
    assert n > 0, "the vector file is empty -- nothing was checked"
    assert not failures, "Rust and Python disagree:\n  " + "\n  ".join(failures)
    print(f"  ok  {n} vectors agree across Rust and Python")


def test_the_vectors_actually_discriminate():
    """Every case must land on a different root.

    Without this, a suite of vectors that all collapsed to the same hash would
    pass parity perfectly while pinning nothing at all.
    """
    with open(VECTORS, encoding="utf-8") as fh:
        cases = json.load(fh)["cases"]
    roots = {}
    for c in cases:
        r = c["expect"]["state_root"]
        assert r not in roots, f"{c['name']} and {roots[r]} share a root"
        roots[r] = c["name"]
    print(f"  ok  {len(cases)} cases, {len(roots)} distinct roots")


def test_an_empty_root_is_not_zero():
    empty = compute([], [])["state_root"]
    assert empty != "0" * 64, "an empty database must not look uninitialised"
    assert len(empty) == 64
    print("  ok  empty root is a constant, not zero")


def test_a_changed_byte_changes_the_root():
    """Sanity: the hash is actually reading the data."""
    a = compute(["c"], [{"coll": "c", "id": "1", "data": {"x": 1}}])["state_root"]
    b = compute(["c"], [{"coll": "c", "id": "1", "data": {"x": 2}}])["state_root"]
    assert a != b
    print("  ok  content changes move the root")


def test_presence_is_distinct_from_emptiness():
    absent = record_leaf("c", "1", {}, None, None)
    empty = record_leaf("c", "1", {}, "", None)
    assert absent != empty, "valid_from=None and valid_from='' are different facts"
    print("  ok  absent is not empty")


if __name__ == "__main__":
    failed = 0
    for name, fn in sorted(globals().items()):
        if name.startswith("test_") and callable(fn):
            try:
                fn()
            except AssertionError as e:
                print(f"  FAIL {name}: {e}")
                failed += 1
    print("state_root vectors:", "FAILED" if failed else "all green")
    sys.exit(1 if failed else 0)
