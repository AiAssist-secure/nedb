# state_root_v1 Format Specification

A state root is one hash that commits to what a database currently says: which
collections exist and what is in them. It is computable from live state alone,
without replaying history, and it is the same for any two databases that hold
the same data — regardless of how they arrived there.

## What a state root is NOT

A state root does not commit to history. History already has a commitment: the
running Merkle head (`Db::head`), which chains every write by seq and object
hash, and answers "did this database's past change?". The state root answers a
different question — "do these two databases say the same thing right now?" —
and it has to be computable without replaying anything.

Keeping them separate is deliberate. A root that folded in history could not be
compared across two databases that reached the same state by different routes,
and that comparison is most of what a root is for: replica agreement, drift
detection, anchoring, and the "before" and "after" sides of a diff.

## Why leaves are logical content, not object hashes

The obvious construction is a tree over `node.hash`. It is wrong here, and the
reason is worth stating because it is not obvious: with encryption on, a node's
hash is not a function of its content.

`ObjectStore::write` hashes the ciphertext, and `encrypt` draws a fresh random
AES-GCM nonce per call. Measured on the running engine:

```
PLAINTEXT same=true  a=144eb088e2f5 b=144eb088e2f5
ENCRYPTED same=false a=d501c7798dcf b=9af86e8fafec
```

Same logical node, written twice under one data-encryption key, two different
hashes. A root built on object hashes would therefore differ between an
encrypted replica and a plaintext one holding identical data, which destroys the
only property anybody wants from it. So the leaves are built from the logical
content, and the encryption layer never touches the root.

The fields that are deliberately absent from each leaf — `seq`, `ts`, `prev`,
the object hash — describe how and when a state was arrived at. That is
history's job, not the state root's.

## Wire Format

### Hash function

BLAKE2b-512, truncated to the first 32 bytes. This matches the rest of the
engine. The output is 32 bytes, hex-encoded at every boundary where text is
expected.

The hash function is written `H(a, b, ...)` below: concatenate all arguments
and pass to BLAKE2b-512, take the first 32 bytes.

### Domain tags

Every hash input begins with one of these ASCII byte strings. They are spelled
out in full rather than numbered so that a hexdump of a mismatched
implementation says what it was hashing.

| Constant        | Tag bytes                                 |
|-----------------|-------------------------------------------|
| `TAG_EMPTY`     | `nedb:state_root_v1:empty`                |
| `TAG_NODE`      | `nedb:state_root_v1:node`                 |
| `TAG_NS_LEAF`   | `nedb:state_root_v1:namespace_leaf`       |
| `TAG_NS_ROOT`   | `nedb:state_root_v1:namespace_root`       |
| `TAG_REC_LEAF`  | `nedb:state_root_v1:record_leaf`          |
| `TAG_REC_ROOT`  | `nedb:state_root_v1:records_root`         |
| `TAG_STATE_ROOT`| `nedb:state_root_v1:state_root`           |

Domain separation means leaves, internal nodes, subtree roots, and the final
composition cannot be confused for one another. A leaf cannot be presented as
an internal node.

### Length-prefix rule

Every variable-length field is preceded by its length as a u64 little-endian
(8 bytes). This makes concatenation unambiguous: `("ab", "c")` and `("a",
"bc")` produce different byte sequences, so `(coll="ab", id="c")` and
`(coll="a", id="bc")` do not collide in a record leaf. The
`concatenation_ambiguity` vector case pins this.

Write `LP(bytes)` for the 8-byte little-endian length followed by the bytes.

### Optional-presence-byte rule

An optional field is encoded as one presence byte, then the value if present.
`None` is `0x00`. `Some(s)` is `0x01` followed by `LP(s.as_bytes())`. A
present empty string `Some("")` is therefore `0x01 0x00 0x00 0x00 0x00 0x00
0x00 0x00 0x00`, distinct from `None` which is `0x00`. The `bitemporal` vector
case (id `empty_from`) pins this: `valid_from = ""` commits differently from
`valid_from = null`.

### JSON value type tags and their encodings

JSON values are encoded canonically rather than serialized to a JSON string.
Serializing to text and hashing that introduces float formatting, escape
choices, and whitespace as three independent ways for two correct
implementations to disagree.

| Tag | Byte | Encoding                                                      |
|-----|------|---------------------------------------------------------------|
| `V_NULL`  | `0` | Tag byte only                                         |
| `V_FALSE` | `1` | Tag byte only                                         |
| `V_TRUE`  | `2` | Tag byte only                                         |
| `V_I64`   | `3` | Tag byte + i64 little-endian (8 bytes)                |
| `V_U64`   | `4` | Tag byte + u64 little-endian (8 bytes)                |
| `V_F64`   | `5` | Tag byte + f64 bits little-endian (8 bytes)           |
| `V_STR`   | `6` | Tag byte + `LP(utf8_bytes)`                           |
| `V_ARR`   | `7` | Tag byte + u64 element count (LE) + each element      |
| `V_OBJ`   | `8` | Tag byte + u64 field count (LE) + each `LP(key)` + value |

**Integer/float distinction.** A JSON number is committed by its representation
as parsed, not by its mathematical value. The parsed type is checked in order:
try i64 first; if that fails, try u64 (covers numbers in `(i64::MAX,
u64::MAX]`); if that fails, use f64. So the integer `1` encodes as `V_I64 01
00 00 00 00 00 00 00` and the float `1.0` encodes as `V_F64` followed by the
IEEE-754 bits of `1.0`. They are not equal. The `integer_and_float` vector case
pins this. The `negative_and_large_numbers` case covers `i64::MIN`
(`-9223372036854775808`) as V_I64 and `u64::MAX` (`18446744073709551615`) as
V_U64.

**The -0.0 rule.** `-0.0 == 0.0` in IEEE-754, so they must commit identically.
Before taking the bits of an f64, normalize: if `f == 0.0`, use `0.0`. The
`negative_and_large_numbers` case includes id `"3"` with data `-0.0`; its
encoding is identical to `0.0`.

**NaN.** Refused. `NaN != NaN`, so a root containing one would not equal
itself, and the failure would look like corruption. Return an error rather than
produce such a root.

**Objects.** Field order is preserved as written, not sorted. NEDB treats
document key order as meaningful (`serde_json` `preserve_order` is on
crate-wide, so `SELECT *` returns columns in document order). Two documents
whose keys are ordered differently are two databases that answer differently,
and a root that cannot tell them apart is not committing to state. The
`field_order_preserved` vector case carries `{"b":1,"a":2}` — the keys are
committed in that order.

### Namespace leaf construction

A namespace leaf encodes one live collection name:

```
namespace_leaf(name) = H(TAG_NS_LEAF, LP(name.as_utf8_bytes()))
```

### Record leaf construction

A record leaf encodes one live document. Fields that describe the write event
(`seq`, `ts`, `prev`, object hash) are absent.

```
buf  = LP(coll.as_utf8_bytes())
buf += LP(id.as_utf8_bytes())
buf += OPT(valid_from)      # presence byte + LP(value) or 0x00
buf += OPT(valid_to)        # same
buf += encode_value(data)
record_leaf(...) = H(TAG_REC_LEAF, buf)
```

### Fold rule

Given a list of leaves (each 32 bytes):

1. If the list is empty, return `H(TAG_EMPTY)`.
2. While more than one element remains:
   a. Pair adjacent elements: `H(TAG_NODE, left, right)`.
   b. If the count is odd, the final element is **promoted unchanged** to the
      next level. It is NOT duplicated. Duplication is the Bitcoin
      CVE-2012-2459 construction, where two different leaf sets produce the
      same root.
3. Return the single remaining element.

### Subtree root (committed leaf count)

After folding, the result is bound to its tag and its leaf count:

```
subtree(tag, leaves) = H(tag, u64_le(len(leaves)), fold(leaves))
```

Promotion alone leaves the tree shape ambiguous for some leaf counts. Committing
the count removes the question entirely. The `three_records_odd_leaf` and
`four_records_even` vector cases both have different record counts and different
roots, confirming that three promoted leaves do not collide with four leaves.

### Namespace root

1. Deduplicate collection names.
2. Sort by raw UTF-8 bytes.
3. Compute `namespace_leaf(name)` for each.
4. Apply `subtree(TAG_NS_ROOT, leaves)`.

### Records root

1. Sort records by `(coll.as_bytes(), id.as_bytes())` — raw UTF-8, no locale.
2. Compute `record_leaf(...)` for each.
3. Apply `subtree(TAG_REC_ROOT, leaves)`.

The `unsorted_input` vector case feeds records in `z/9, a/1, z/1` order and
expects the same result as if they had been sorted: records root ordering is the
implementation's responsibility, not the caller's.

### Final composition

```
state_root(namespace, records) = H(TAG_STATE_ROOT, namespace, records)
```

The published output is a `StateRoot` struct:

| Field              | Type   | Description                                      |
|--------------------|--------|--------------------------------------------------|
| `version`          | string | `"state_root_v1"`                                |
| `namespace_root`   | string | 64 hex characters (32 bytes)                     |
| `records_root`     | string | 64 hex characters (32 bytes)                     |
| `state_root`       | string | 64 hex characters (32 bytes)                     |
| `collection_count` | u64    | Number of distinct live collections              |
| `record_count`     | u64    | Number of live documents                         |

## Decided Questions

Every row below is a place where two reasonable implementations would disagree.
The cross-language vectors pin them as data.

| Question               | Decision                                                      | Reason                                                                                        |
|------------------------|---------------------------------------------------------------|-----------------------------------------------------------------------------------------------|
| Ordering               | Raw UTF-8 bytes; no locale, no post-normalization code points | Every language agrees on byte order without a library                                         |
| Unicode normalization  | None; names commit as the exact UTF-8 bytes they were created with | Normalizing inside the encoder would make two distinct collections collide in the root    |
| Tombstones             | Absent; a deleted document contributes nothing to the root    | The root commits to current visible state; history carries the tombstone                      |
| Dropped collections    | Absent from the namespace; present in history                 | An emptied-but-live collection IS in the namespace — that distinction requires durable identity |
| Document field order   | Preserved as written, not sorted                              | NEDB returns columns in document order, so two differently-ordered documents behave differently |
| Empty root             | `H(TAG_EMPTY)`, a distinct constant; never zero               | Zero looks like an uninitialized field; "no collections" must not be confused with "nobody computed this" |

## Verifying Against the Cross-Language Vectors

The file `vectors/state_root_v1.json` contains 17 cases. The header says:

> Any implementation of state_root_v1 must reproduce every expect block
> exactly. These pin the decisions prose cannot.

Each case provides `collections`, `records`, and an `expect` block. An
implementation is correct when it produces the same `namespace_root`,
`records_root`, `state_root`, `collection_count`, and `record_count` for every
case.

To run the Python reference implementation against the committed vectors:

```
python3 -m nedb.state_root
```

Run from any directory; the script resolves the vector path relative to its own
location (`python/nedb/state_root.py` → `../../vectors/state_root_v1.json`).
Exit code 0 means every case agreed. The script prints one `MISMATCH` line per
divergence, naming the case and field, so a partial implementation can see
exactly which cases it gets right.

To regenerate the vector file from the Rust implementation (this records a
format change — treat any diff as such):

```
NEDB_WRITE_VECTORS=1 cargo test vectors
```

Every other implementation and every root persisted in the field is downstream
of that file.

## Verification Model

A persisted root (`RootRecord`) and the recomputability of its history are two
independent facts. `verify_root(at_seq)` returns a `RootVerification` with
separate `record` and `recomputation` fields precisely because the two are
independent.

Example output when the database has been compacted past the root's sequence:

```
root_record:   valid
recomputation: unavailable
reason:        HISTORY_PRUNED
```

There are three recomputation outcomes:

| Outcome       | Meaning                                                      |
|---------------|--------------------------------------------------------------|
| `matches`     | A recomputation ran and agreed with the stored root          |
| `differs`     | A recomputation ran and did not agree — something is wrong   |
| `unavailable` | The history needed to recompute is gone (pruned by `compact`)|

Flattening `unavailable` into PASS would claim a verification that never ran.
Flattening it into FAIL would report tampering that never happened. A pruned
database is not a corrupt one, and an operator who cannot tell the two apart
will either ignore real alarms or panic at routine ones.

The process exit codes reflect this:

| `record` status   | `recomputation` outcome     | Exit code |
|-------------------|-----------------------------|-----------|
| `valid`           | `matches`                   | 0         |
| `valid`           | `unavailable`               | 3         |
| `missing`         | (not attempted)             | 4         |
| `unknown_version` | (not attempted)             | 5         |
| `valid`           | `differs`                   | 1         |

`is_verified()` returns true only when `record = valid` AND `recomputation =
matches`. `is_mismatch()` returns true only when `recomputation = differs`.
"Unavailable" is neither. A caller that scripts against this output must be able
to tell "checked and good" from "could not check".

The `history_floor()` value — stored in `_nedb.meta` under the key
`history_floor` — records where `compact` cut. Below that floor, the engine
cannot distinguish "no writes at that sequence" from "writes that were
discarded". Without the floor, a failed recomputation below it could not be
attributed and would have to be reported as PASS or FAIL — both wrong answers.
