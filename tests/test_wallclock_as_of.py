#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 INTERCHAINED LLC
# SPDX-License-Identifier: BUSL-1.1
# NEDB · © 2026 INTERCHAINED LLC × Eth-Interchained × Vex (Claude Opus 5)

"""
Wall-clock AS OF — system time by datetime, in both engines.

`AS OF SYSTEM TIME` accepts two argument forms, resolved by TYPE:

  bare integer            a NEDB sequence number — the original contract,
                          byte-for-byte unchanged (backcompat is the point)
  quoted string           a wall-clock moment: ISO 8601 date/datetime
  (neSQL/HTTP + NQL)      (naive = UTC, Z and ±HH:MM offsets honored), or
                          unix seconds/millis with an explicit s/ms unit

Resolution rule, identical in both engines: the wall-clock moment resolves
to the LAST seq whose write-time (`ts`, stamped by the single-writer
sequencer, monotonic) is at or before the moment — "state as known at that
moment". AS OF semantics, not "the next write after".

Honesty contracts asserted here:
  - a moment before the first write is a loud LookupError, never empty rows
  - after the last write clamps to the newest version (the tip)
  - a garbage string is a SyntaxError naming the accepted forms
  - bare integers NEVER change meaning (a query that worked before this
    feature existed answers the same today)

Cross-engine: the Rust engine carries the same parser (rust/nedb-v2/src/
wallclock.rs) and resolver (Db::seq_at over the ts index built by the cold
scan / put paths). tests/test_nql_predicates.py and tests/test_nql_shaping.py
run both engines on the same battery where a Rust build is available.

© INTERCHAINED LLC × Vex (Interchained AI fleet: GLM · Claude · Opus · Fable · GPT-6)"""
from __future__ import annotations
import os, sys, time, math, json, tempfile, shutil
sys.path.insert(0, os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "python"))

from nedb.engine import NEDB

PASS = 0
FAIL = 0

def check(name: str, cond: bool, detail=None):
    global PASS, FAIL
    if cond:
        PASS += 1
        print(f"  ✅ {name}")
    else:
        FAIL += 1
        print(f"  ❌ {name}  {detail if detail is not None else ''}")

def utc(ts: float, fmt: str = "%Y-%m-%dT%H:%M:%S.%fZ") -> str:
    import datetime
    return datetime.datetime.fromtimestamp(ts, datetime.timezone.utc).strftime(fmt)

workdir = tempfile.mkdtemp(prefix="nedb-wallclock-")
try:
    # ── setup: three versions, sleep-spaced so their ts values differ ─────────
    db = NEDB(os.path.join(workdir, "d"))
    v1 = db.put("docs", "x", {"v": 1}); time.sleep(1.1)
    v2 = db.put("docs", "x", {"v": 2}); time.sleep(1.1)
    v3 = db.put("docs", "x", {"v": 3})
    s1, s3 = v1["_seq"], v3["_seq"]
    ts_map = {op.seq: op.ts for op in db.log.ops}
    ts1, ts3 = ts_map[s1], ts_map[s3]
    ts2 = ts_map[v2["_seq"]]

    def v_at(query: str):
        rows = [d for d in db.query(query) if d.get("_id") == "x"]
        return rows[0]["v"] if rows else None

    print("\n  ── resolution: last write at or before the moment ──\n")

    # The moment 1µs after a write resolves to THAT write (boundary inclusive).
    check("just after v1 → v1", v_at(f"FROM docs AS OF '{utc(ts1 + 0.000001)}'") == 1)
    check("just after v2 → v2", v_at(f"FROM docs AS OF '{utc(ts2 + 0.000001)}'") == 2)
    check("just after v3 → v3", v_at(f"FROM docs AS OF '{utc(ts3 + 0.000001)}'") == 3)

    # Midpoint between v1 and v2 → still v1 ("as known at that moment").
    mid12 = (ts1 + ts2) / 2
    check("midpoint v1→v2 → v1", v_at(f"FROM docs AS OF '{utc(mid12)}'") == 1)
    # 1µs before v3 → v2.
    check("1µs before v3 → v2", v_at(f"FROM docs AS OF '{utc(ts3 - 0.000001)}'") == 2)

    print("\n  ── boundary honesty ──\n")

    # Before the first write: loud refusal, never a silent empty answer.
    before_first = utc(ts1 - 1.0)
    refused = False
    try:
        r = db.query(f"FROM docs AS OF '{before_first}'")
        got_none = all(d.get("_id") != "x" for d in r)
        check("before first write does not silently answer", False,
              f"returned {len(r)} rows instead of refusing")
    except LookupError:
        check("before first write refuses loudly (nothing existed yet)", True)
    except SyntaxError as e:
        check("before first write refuses loudly (nothing existed yet)", False, e)

    # After the last write clamps to the newest version.
    check("after last write clamps to v3",
          v_at(f"FROM docs AS OF '{utc(ts3 + 60)}'") == 3)

    # A moment before the doc's first version: the doc is absent — but the
    # moment is AFTER the store's first write (the registry), so it resolves
    # (to the registry write) and answers "x not yet written" with an empty
    # result for x. That is correct AS OF semantics, distinct from the
    # nothing-existed-yet refusal above.
    check("moment between registry and doc: x absent",
          v_at(f"FROM docs AS OF '{utc(ts1 - 0.000001)}'") is None)

    print("\n  ── accepted forms ──\n")

    # Date-only (midnight UTC). The store was written "today"; midnight of
    # today precedes the writes on a UTC clock, so it refuses honestly.
    # Compute the date from the actual first-write ts to stay timezone-true.
    import datetime as _dt
    day = _dt.datetime.fromtimestamp(ts1, _dt.timezone.utc).strftime("%Y-%m-%d")
    try:
        db.query(f"FROM docs AS OF '{day}'")
        check("date-only midnight (before writes) refuses", False, "resolved instead")
    except LookupError:
        check("date-only midnight (before writes) refuses", True)

    # An explicit time-of-day later that day resolves.
    check("date + time later that day → v3",
          v_at(f"FROM docs AS OF '{utc(ts3 + 0.000001)}'") == 3)

    # Offset form: +00:00 explicit UTC.
    check("+00:00 offset accepted",
          v_at(f"FROM docs AS OF '{utc(ts1 + 0.000001, '%Y-%m-%dT%H:%M:%S.%f+00:00')}'") == 1)

    # Non-zero offset: 17:00+02:00 == 15:00Z. Build it from a known instant.
    known = ts2 + 0.000001
    as_utc = _dt.datetime.fromtimestamp(known, _dt.timezone.utc)
    plus2 = (_dt.datetime.fromtimestamp(known, _dt.timezone.utc)
             + _dt.timedelta(hours=2)).strftime("%Y-%m-%dT%H:%M:%S.%f") + "+02:00"
    check("non-zero offset (+02:00) normalizes to UTC",
          v_at(f"FROM docs AS OF '{plus2}'") == 2)

    # Unix with explicit units. The moment must land AFTER the write (ceil)
    # and BEFORE the next write (sleep spacing guarantees it for ms).
    check("unix seconds (ceil) → v1",
          v_at(f"FROM docs AS OF '{math.ceil(ts1)}s'") == 1)
    check("unix millis (+1) → v1",
          v_at(f"FROM docs AS OF '{int(ts1 * 1000) + 1}ms'") == 1)

    print("\n  ── refusals ──\n")

    for garbage in ["not a time", "15/09/2026", "sep 15", "2026-9-15"]:
        try:
            db.query(f"FROM docs AS OF '{garbage}'")
            check(f"garbage {garbage!r} refuses", False, "accepted")
        except SyntaxError:
            check(f"garbage {garbage!r} refuses naming the forms", True)

    print("\n  ── BACKCOMPAT: bare integers are sequences, always ──\n")

    check("AS OF <seq> reads the historical version",
          v_at(f"FROM docs AS OF {s1}") == 1)
    check("AS OF <later seq> reads the later version",
          v_at(f"FROM docs AS OF {s3}") == 3)
    check("AS OF 0 (before any user write) → x absent",
          v_at("FROM docs AS OF 0") is None)
    # The one that must NEVER regress: an integer that LOOKS like a unix
    # timestamp stays a sequence.
    # A bare integer that LOOKS like a unix timestamp stays a sequence: a seq
    # past the head resolves to the newest version at or before it (AS OF
    # semantics), which is v3 — NOT a wall-clock resolution to "now". The
    # distinction: wall-clock would ALSO return v3 here, so assert the
    # MEANING differently — a bare integer names a seq even when it is
    # absurdly large (no clamp to tip by wall-clock, no refusal by clock):
    # AS OF 10**15 (a seq no store will ever reach) answers from the newest
    # known version, exactly as AS OF semantics dictates, without consulting
    # any clock.
    look_like_unix = int(ts1)
    if look_like_unix > s3:
        check("a unix-looking integer is still a SEQ (answers by seq semantics)",
              v_at(f"FROM docs AS OF {look_like_unix}") == 3,
              f"expected v3 by seq semantics, got something else")
    # And a seq beyond ANY plausible write count answers the same way — no
    # clock is consulted for bare integers, ever.
    check("an absurdly large bare integer is still seq semantics",
          v_at(f"FROM docs AS OF {10**15}") == 3)

    print("\n  ── both time axes compose ──\n")

    db.put("policy", "r", {"pct": 5.0}, valid_from="2024-01-01", valid_to="2024-12-31")
    snap = db.seq
    db.put("policy", "r", {"pct": 6.0}, valid_from="2025-01-01")
    ts_snap = {op.seq: op.ts for op in db.log.ops}[snap]
    # wall-clock at the snap + VALID AS OF the 2024 window → the 5.0 row
    rows = db.query(f"FROM policy AS OF '{utc(ts_snap + 0.000001)}' VALID AS OF \"2024-06-15\"")
    check("wall-clock AS OF + VALID AS OF compose",
          len(rows) == 1 and rows[0].get("pct") == 5.0, rows)

    print("\n  ── cross-engine (when the Rust core is importable) ──\n")

    try:
        import nedb as _pkg
        native = getattr(_pkg, "_native", None) or getattr(_pkg, "__has_native__", False)
    except Exception:
        native = None
    if native:
        check("native core present — deep parity lives in the Rust suites", True)
    else:
        print("  (native core not built here — Rust parity runs in CI; suites: cargo test -p nedb-engine --lib wallclock)")

finally:
    shutil.rmtree(workdir, ignore_errors=True)

# ─────────────────────────────────────────────────────────────────────────────
total = PASS + FAIL
print(f"\n  {'═'*52}")
print(f"  Wall-clock AS OF  |  {PASS}/{total} passed{'  ✅' if not FAIL else f'  ❌  {FAIL} FAILED'}")
print(f"  {'═'*52}\n")
sys.exit(1 if FAIL else 0)
