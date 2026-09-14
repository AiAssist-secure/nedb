# Collection Identity

## The Defect That Motivated This

Before durable collection identity, "which collections exist" was not a fact
about the database. It was a fact about the storage substrate, and the two
substrates disagreed. The `namespace.rs` module documents the exact
measurements:

```
disk, flush between PUT and DELETE : ["orders"]
disk, both inside one flush tick   : []
memory                             : []
```

All three are the same logical history — create a collection, then empty it.

Disk mode answered by listing directories (`IdIndex::collections` did a
`read_dir`). The WAL write buffer is keyed by `(coll, id)`, so a PUT followed
by a DELETE before the 1-second flush ticker fires overwrites the buffered entry
with its own tombstone. No directory is ever created. `PUT, flush, DELETE`
leaves the directory behind forever, because the flush path only ever calls
`remove_file` — it has no `remove_dir` in it at all.

The namespace was therefore decided by a background timer.

That is survivable for a `LIST COLLECTIONS` convenience call: a stale listing
is mildly wrong but not structurally harmful. It is fatal for a state root. A
root commits to a namespace, which is only meaningful if two replicas of the
same history agree on what the namespace IS. A namespace that varies with flush
timing cannot be agreed upon.

## The Design

A collection exists because a record says so, not because a directory is lying
around. Creation is an event; the event is a node; the node lives in the DAG
like everything else.

Emptying a collection does not destroy it. Only an explicit drop does, and a
drop is a tombstone rather than an absence. The registry record gains
`"dropped": true` at the sequence of the drop. The name stays in `_nedb.collections`,
marked dropped, so that `AS OF` before the drop still reports the collection as
having existed, and a root for that earlier sequence can distinguish "dropped"
from "never created".

Documents inside a dropped collection are left where they are. Reclaiming them
is `compact`'s job and an explicit operator decision; quietly destroying history
behind a namespace operation is exactly the behavior the engine refuses to have.

Revival happens automatically: if a write arrives for a dropped collection, the
registration is rewritten with `"dropped": false`. A write is an unambiguous
assertion that the caller means for this collection to exist.

Putting the registry in the DAG rather than in a sidecar file pays three times
without extra work:

- `since()` replicates collection creation to followers for free.
- `collections_as_of(seq)` answers "which collections existed at seq N" for free,
  because the registry documents have version chains like every other document.
- `verify()` covers the registry for free, because it is ordinary data in the
  same object store.

A `COLLECTIONS` file would have needed all three written by hand.

## The Reserved `_nedb.*` Namespace

The registry has to live somewhere, and wherever it lives must not be
user-writable. If a client could write to the registry directly, it could forge
the namespace the state root commits to.

The reservation is expressed through a prefix check: everything under `_nedb`
or matching `_nedb.*` is engine-owned. User writes to any such name are refused
with an explicit error. The prefix is `_nedb` exactly — a collection named
`_private` or `_nedbish` is not reserved; only the engine's own prefix is taken.

Two engine collections currently live under this reservation:

| Name                | Purpose                                                                 |
|---------------------|-------------------------------------------------------------------------|
| `_nedb.collections` | Collection registry. Document ids are collection names; each document records whether the collection is currently live (`"dropped": false/true`) and the sequence at which the status was written. |
| `_nedb.roots`       | Persisted state roots. Document ids are zero-padded sequence numbers so that the id index's lexicographic ordering is also numeric ordering. |
| `_nedb.meta`        | Engine metadata not suited to either above: `history_floor` lives here. |

The `_nedb.roots` reservation exists for a specific reason beyond general
access control: a root record that counted as part of the state it describes
would change that state, so computing one would immediately invalidate it. The
reservation keeps root records out of `collections()` — they are invisible to
the input of the computation that produces them.

## Collection Semantics Table

| Operation              | Effect on namespace                        | Effect on history                          |
|------------------------|--------------------------------------------|--------------------------------------------|
| First write to `x`     | Registers `x` as live in `_nedb.collections` | Node written; collection registered at that seq |
| Further writes to `x`  | No change (registry already says live)     | New nodes written                          |
| Delete all docs in `x` | No change; `x` remains live, with zero records | Tombstones written for each deleted doc |
| `drop_collection("x")` | Registry records `"dropped": true`         | Drop event is a node in `_nedb.collections`; all prior doc history remains |
| Write to dropped `x`   | Registry rewritten with `"dropped": false` | New doc written; collection revived at that seq |
| `collections_as_of(n)` | Returns the set live at seq `n`            | Reads the registry version chains as of that seq |

The difference between "emptied" and "dropped" is what the `an_empty_but_live_collection_changes_the_root` test in `root.rs` exists to enforce:

```
let never   = compute(&[], &[]).unwrap();
let emptied = compute(&["orders".into()], &[]).unwrap();
assert_ne!(never.state_root, emptied.state_root,
    "a database that once had orders is not one that never did");
```

A database where `orders` was created and then emptied is not the same database
as one where `orders` never existed. Without durable collection identity, the
root had no way to tell them apart — the timer made the decision instead.
