# SPDX-FileCopyrightText: 2026 INTERCHAINED LLC
# SPDX-License-Identifier: BUSL-1.1
# NEDB · © 2026 INTERCHAINED LLC × Eth-Interchained × Vex (Claude Opus 5)

"""Collection identity for the Python reference engine.

This mirrors `rust/nedb-v2/src/namespace.rs` rule for rule, and it exists for
the same reason the Rust one does: a collection has to exist because a record
says so, not because storage happens to have something lying around.

# Why the reference engine needs this too

NEDB ships two independent NQL implementations. When the Rust engine started
registering collections, the two stopped agreeing about sequence numbers — the
same writes into a fresh database landed one position apart, because Rust spent
a sequence on the registry record and Python did not. The cross-engine parity
corpus caught it immediately:

    parity after a delete: FROM t AS OF 1
        python [(('_id','a'), ('t','66'))]
        rust   [(('_id','a'), ('t','55'))]

Rust at `AS OF 1` was Python at `AS OF 0`. The correct response was not to move
the test's goalposts. If collection existence is a logical fact in the engine,
it is a logical fact in the reference, and the two agree again because both are
right rather than because one stopped looking.

The Python engine had the same underlying defect in a different shape, too:
collections were derived by splitting live document keys, so a collection whose
last document was deleted simply ceased to exist — indistinguishable from one
that had never been created.
"""

RESERVED_PREFIX = "_nedb"

#: The collection registry. Ids are collection names; the newest version of
#: each says whether that collection is currently live.
COLLECTIONS = "_nedb.collections"

#: Engine metadata that is neither a collection record nor a root.
META = "_nedb.meta"

#: Persisted state roots.
ROOTS = "_nedb.roots"

MAX_NAME_BYTES = 255


class ReservedCollection(ValueError):
    """A write was aimed at the engine's own namespace."""


class InvalidCollectionName(ValueError):
    """A name a collection cannot durably have."""


def is_reserved(coll: str) -> bool:
    """Is this name part of the engine's own namespace?"""
    return coll == RESERVED_PREFIX or coll.startswith(RESERVED_PREFIX + ".")


def refuse_reserved(coll: str) -> None:
    """Refuse a write the caller is not allowed to make."""
    if is_reserved(coll):
        raise ReservedCollection(
            f"collection {coll!r} is reserved: everything under "
            f"{RESERVED_PREFIX!r} is engine-owned, and letting a client write "
            f"there would let it forge the namespace the state root commits to"
        )


def validate_name(coll: str) -> None:
    """Is this a name a collection can durably HAVE?

    Refuses rather than sanitises. A silently rewritten name is a different
    collection than the one the caller asked for, and they would never be told.

    The Python engine keys documents as ``coll:id``, so a colon in a collection
    name would make ``a:b`` and ``a`` + id ``b`` the same key — an aliasing bug
    the Rust engine cannot have, since it keys by a pair. Refused here for the
    same reason a path separator is refused there: the name has to survive its
    own storage layer intact.
    """
    if not isinstance(coll, str):
        raise InvalidCollectionName(
            f"collection name must be a string, got {type(coll).__name__}"
        )
    if coll == "":
        raise InvalidCollectionName("collection name is empty")
    n = len(coll.encode("utf-8"))
    if n > MAX_NAME_BYTES:
        raise InvalidCollectionName(
            f"collection name is {n} bytes; the limit is {MAX_NAME_BYTES}"
        )
    if coll in (".", ".."):
        raise InvalidCollectionName(
            f"collection name {coll!r} is a filesystem path component, not a name"
        )
    if "/" in coll or "\\" in coll:
        raise InvalidCollectionName(
            f"collection name {coll!r} contains a path separator — on disk a "
            f"collection name is a directory name, so this does not name a "
            f"collection, it names a location"
        )
    if ":" in coll:
        raise InvalidCollectionName(
            f"collection name {coll!r} contains a colon, which is the key "
            f"separator — 'a:b' and collection 'a' id 'b' would be one key"
        )
    if "\0" in coll:
        raise InvalidCollectionName("collection name contains a NUL byte")
    if coll != coll.strip():
        raise InvalidCollectionName(
            f"collection name {coll!r} has leading or trailing whitespace"
        )


def validate_writable(coll: str) -> None:
    """A name that may be written to: valid AND not engine-owned."""
    validate_name(coll)
    refuse_reserved(coll)


def seq_id(seq: int) -> str:
    """Zero-padded so lexicographic ordering is numeric ordering."""
    return f"{seq:020d}"
