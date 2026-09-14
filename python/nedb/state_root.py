# SPDX-FileCopyrightText: 2026 INTERCHAINED LLC
# SPDX-License-Identifier: BUSL-1.1
# NEDB · © 2026 INTERCHAINED LLC × Eth-Interchained × Vex (Claude Opus 5)

"""state_root_v1 — the Python reference implementation.

This is deliberately a SECOND implementation, written from the format rules
rather than translated from the Rust. Its whole job is to disagree if the
format has a hole in it: a spec that only one program implements is not a
spec, it is that program's behaviour written down.

The rules it implements, in full:

  hash            BLAKE2b-512, first 32 bytes
  domains         every hash input starts with a distinct ASCII tag
  lengths         every variable-length field is preceded by u64 little-endian
  optionals       one presence byte, then the value if present
  ordering        leaves sorted by key BYTES (collection, then id)
  unicode         none applied; names commit as the exact UTF-8 they arrived as
  odd leaf        promoted unchanged, never duplicated (CVE-2012-2459)
  leaf count      committed in the subtree root alongside the fold
  empty           H(tag), a constant, never zero
  field order     documents commit in their own key order, not sorted

Run `python3 -m nedb.state_root` to check against the committed vectors.
"""

from __future__ import annotations

import hashlib
import json
import struct
from typing import Any, Iterable, Mapping, Optional, Sequence

TAG_EMPTY = b"nedb:state_root_v1:empty"
TAG_NODE = b"nedb:state_root_v1:node"
TAG_NS_LEAF = b"nedb:state_root_v1:namespace_leaf"
TAG_NS_ROOT = b"nedb:state_root_v1:namespace_root"
TAG_REC_LEAF = b"nedb:state_root_v1:record_leaf"
TAG_REC_ROOT = b"nedb:state_root_v1:records_root"
TAG_STATE_ROOT = b"nedb:state_root_v1:state_root"

V_NULL, V_FALSE, V_TRUE, V_I64, V_U64, V_F64, V_STR, V_ARR, V_OBJ = range(9)

I64_MIN, I64_MAX = -(2**63), 2**63 - 1
U64_MAX = 2**64 - 1


def _h(*parts: bytes) -> bytes:
    d = hashlib.blake2b()
    for p in parts:
        d.update(p)
    return d.digest()[:32]


def _lp(b: bytearray, raw: bytes) -> None:
    b += struct.pack("<Q", len(raw))
    b += raw


def _lp_opt(b: bytearray, s: Optional[str]) -> None:
    if s is None:
        b.append(0)
    else:
        b.append(1)
        _lp(b, s.encode("utf-8"))


def encode_value(b: bytearray, v: Any) -> None:
    """Canonical encoding of a JSON value.

    Numbers commit by REPRESENTATION, not by mathematical value, so 1 and 1.0
    differ. Python makes that distinction naturally (int vs float); the Rust
    side gets it from serde_json's parsed number type. That the two agree is
    not automatic, which is exactly why it is in the vectors.
    """
    if v is None:
        b.append(V_NULL)
    elif v is True:
        b.append(V_TRUE)
    elif v is False:
        b.append(V_FALSE)
    elif isinstance(v, int):
        # bool is a subclass of int, handled above.
        if I64_MIN <= v <= I64_MAX:
            b.append(V_I64)
            b += struct.pack("<q", v)
        elif 0 <= v <= U64_MAX:
            b.append(V_U64)
            b += struct.pack("<Q", v)
        else:
            raise ValueError(f"integer out of 64-bit range: {v}")
    elif isinstance(v, float):
        if v != v:
            raise ValueError("NaN cannot be committed to a state root")
        b.append(V_F64)
        # -0.0 == 0.0, so they must commit identically.
        b += struct.pack("<d", 0.0 if v == 0.0 else v)
    elif isinstance(v, str):
        b.append(V_STR)
        _lp(b, v.encode("utf-8"))
    elif isinstance(v, (list, tuple)):
        b.append(V_ARR)
        b += struct.pack("<Q", len(v))
        for it in v:
            encode_value(b, it)
    elif isinstance(v, Mapping):
        b.append(V_OBJ)
        b += struct.pack("<Q", len(v))
        # Insertion order, NOT sorted. Python dicts preserve it; the vectors
        # are loaded with object_pairs_hook=dict to keep the file's order.
        for k, val in v.items():
            _lp(b, k.encode("utf-8"))
            encode_value(b, val)
    else:
        raise TypeError(f"not a JSON value: {type(v).__name__}")


def namespace_leaf(name: str) -> bytes:
    b = bytearray()
    _lp(b, name.encode("utf-8"))
    return _h(TAG_NS_LEAF, bytes(b))


def record_leaf(
    coll: str,
    id_: str,
    data: Any,
    valid_from: Optional[str] = None,
    valid_to: Optional[str] = None,
) -> bytes:
    b = bytearray()
    _lp(b, coll.encode("utf-8"))
    _lp(b, id_.encode("utf-8"))
    _lp_opt(b, valid_from)
    _lp_opt(b, valid_to)
    encode_value(b, data)
    return _h(TAG_REC_LEAF, bytes(b))


def _fold(level: list[bytes]) -> bytes:
    if not level:
        return _h(TAG_EMPTY)
    while len(level) > 1:
        nxt = []
        for i in range(0, len(level) - 1, 2):
            nxt.append(_h(TAG_NODE, level[i], level[i + 1]))
        if len(level) % 2:
            nxt.append(level[-1])  # promote; duplicating is CVE-2012-2459
        level = nxt
    return level[0]


def _subtree(tag: bytes, leaves: list[bytes]) -> bytes:
    return _h(tag, struct.pack("<Q", len(leaves)), _fold(leaves))


def namespace_root(collections: Iterable[str]) -> bytes:
    names = sorted(set(collections), key=lambda s: s.encode("utf-8"))
    return _subtree(TAG_NS_ROOT, [namespace_leaf(n) for n in names])


def records_root(records: Sequence[Mapping[str, Any]]) -> bytes:
    ordered = sorted(
        records,
        key=lambda r: (r["coll"].encode("utf-8"), r["id"].encode("utf-8")),
    )
    leaves = [
        record_leaf(
            r["coll"], r["id"], r["data"],
            r.get("valid_from"), r.get("valid_to"),
        )
        for r in ordered
    ]
    return _subtree(TAG_REC_ROOT, leaves)


def compute(collections: Iterable[str], records: Sequence[Mapping[str, Any]]) -> dict:
    colls = list(collections)
    ns = namespace_root(colls)
    rec = records_root(records)
    return {
        "version": "state_root_v1",
        "namespace_root": ns.hex(),
        "records_root": rec.hex(),
        "state_root": _h(TAG_STATE_ROOT, ns, rec).hex(),
        "collection_count": len(set(colls)),
        "record_count": len(records),
    }


# ── Vector check ──────────────────────────────────────────────────────────

def check_vectors(path: str) -> tuple[int, list[str]]:
    """Returns (cases checked, failures). Never raises on a mismatch — the
    caller decides what a mismatch means, and a mismatch is data, not a crash.
    """
    with open(path, encoding="utf-8") as fh:
        doc = json.load(fh)
    failures = []
    for case in doc["cases"]:
        got = compute(case["collections"], case["records"])
        want = case["expect"]
        for field in ("namespace_root", "records_root", "state_root",
                      "collection_count", "record_count"):
            if got[field] != want[field]:
                failures.append(
                    f"{case['name']}.{field}: python={got[field]!r} "
                    f"rust={want[field]!r}"
                )
    return len(doc["cases"]), failures


if __name__ == "__main__":
    import os
    import sys

    here = os.path.dirname(os.path.abspath(__file__))
    default = os.path.join(here, "..", "..", "vectors", "state_root_v1.json")
    target = sys.argv[1] if len(sys.argv) > 1 else default
    n, bad = check_vectors(target)
    for line in bad:
        print("MISMATCH", line)
    print(f"{n - len({b.split('.')[0] for b in bad})}/{n} cases agree with Rust")
    sys.exit(1 if bad else 0)
