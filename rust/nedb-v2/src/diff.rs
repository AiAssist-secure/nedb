// SPDX-FileCopyrightText: 2026 INTERCHAINED LLC
// SPDX-License-Identifier: BUSL-1.1
// NEDB · © 2026 INTERCHAINED LLC × Eth-Interchained × Vex (Claude Opus 5)

//! Logical difference between two points in history.
//!
//! # What this is not
//!
//! It is not a log slice. A log answers "what happened between A and B"; this
//! answers "how does the state at B differ from the state at A", and those are
//! different questions with different answers. A document written five times
//! and then restored to its original contents produces five log entries and
//! zero diff entries. A document created and deleted inside the range produces
//! two log entries and, again, zero diff entries — it is absent on both sides,
//! so the state did not change.
//!
//! It is also not textual. The unit is a document and a collection, not a line.
//!
//! # How a side is materialised
//!
//! Exactly the way [`crate::db::Db::state_root_as_of`] materialises one:
//!
//! ```text
//! state(S) = { (coll, id) -> node
//!              | coll in collections_as_of(S), not reserved,
//!                id  in list_ids_including_deleted(coll),
//!                get_as_of(coll, id, S) == Some(node) }
//! ```
//!
//! Sharing the definition with the state root is deliberate and load-bearing:
//! if `diff(a, b)` were empty, the two roots MUST be equal, and a diff computed
//! from a different notion of "the state at S" could not promise that.
//!
//! One consequence worth stating out loud: dropping a collection removes its
//! documents from the state even though `drop_collection` never tombstones them
//! individually. So a drop shows up twice in a diff — once as a removed
//! collection, once as a removed document per row. That is not double counting,
//! it is the namespace fact and the row facts, and a consumer restoring state
//! from the diff needs both.
//!
//! # Cost
//!
//! Per candidate id, two `get_as_of` calls, and each one walks `prev` backward
//! from the current head until it reaches a version at or before the target
//! sequence. The cost is therefore one object read per version stepped over,
//! not a scan of history: a document untouched since seq 3 costs a single read
//! no matter how far apart `from` and `to` are, and only hot documents cost
//! more. The candidate set itself is the full id list of every collection live
//! at either end, which is the same enumeration an `AS OF` query already pays.

use crate::db::Db;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::BTreeSet;
use std::sync::atomic::Ordering;

/// Which direction a thing moved between the two sequence points.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ChangeKind {
    /// Absent at `from_seq`, present at `to_seq`.
    Added,
    /// Present at `from_seq`, absent at `to_seq`.
    Removed,
    /// Present at both, and not identical.
    Modified,
}

/// Which keys of a document object moved. Only ever describes `data`.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct FieldDelta {
    /// Keys present only on the `to` side.
    pub added: Vec<String>,
    /// Keys present only on the `from` side.
    pub removed: Vec<String>,
    /// Keys present on both sides with different values.
    pub changed: Vec<String>,
}

impl FieldDelta {
    /// True when no key moved. A `Modified` change can legitimately carry an
    /// empty delta: bi-temporal validity is not a field, so a record whose
    /// `valid_from` moved while its payload stood still changes with no key
    /// changing. Reading emptiness as "nothing happened" would lose exactly
    /// that case, which is why `temporal` exists alongside this.
    pub fn is_empty(&self) -> bool {
        self.added.is_empty() && self.removed.is_empty() && self.changed.is_empty()
    }
}

/// The bi-temporal validity window, before and after.
///
/// Present on a `Modified` change only when the window actually moved. The
/// alternative — folding validity into `FieldDelta` under pseudo-keys like
/// `"valid_from"` — would collide with a user document that genuinely has a
/// field by that name, and the collision would be silent.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TemporalDelta {
    pub valid_from_before: Option<String>,
    pub valid_from_after: Option<String>,
    pub valid_to_before: Option<String>,
    pub valid_to_after: Option<String>,
}

/// One document whose visible state differs between the two sequence points.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct DocChange {
    pub coll: String,
    pub id: String,
    pub kind: ChangeKind,
    /// The payload as of `from_seq`. `None` for `Added`.
    pub before: Option<Value>,
    /// The payload as of `to_seq`. `None` for `Removed`.
    pub after: Option<Value>,
    /// Key-level detail, for `Modified` only, and only when BOTH payloads are
    /// JSON objects. A scalar or an array has no keys, and inventing field
    /// names for one (`"0"`, `"1"`, ...) would report a structure the document
    /// does not have — `before`/`after` already say everything true there.
    pub fields: Option<FieldDelta>,
    /// Validity-window movement, for `Modified` only, and only when the window
    /// moved.
    pub temporal: Option<TemporalDelta>,
}

/// One collection that came into or went out of existence.
///
/// `ChangeKind::Modified` never appears here: a collection has no content of
/// its own in the registry beyond whether it is live, so "changed" is not a
/// state it can be in. Its documents are reported as documents.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CollChange {
    pub name: String,
    pub kind: ChangeKind,
}

/// The complete difference in logical state between two sequence points.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct StateDiff {
    pub from_seq: u64,
    pub to_seq: u64,
    /// Sorted by name, byte-wise.
    pub collections: Vec<CollChange>,
    /// Sorted by `(coll, id)`, byte-wise.
    pub documents: Vec<DocChange>,
}

impl StateDiff {
    /// True when the two sequence points describe the same logical state.
    pub fn is_empty(&self) -> bool {
        self.collections.is_empty() && self.documents.is_empty()
    }
}

/// Error prefix for a range that reaches below the history floor. Exposed as a
/// constant because callers (and `nesql diff`) need to branch on the reason
/// without string-matching a sentence that may be reworded.
pub const HISTORY_PRUNED: &str = "HISTORY_PRUNED";

/// Error prefix for `from_seq > to_seq`.
pub const REVERSED_RANGE: &str = "REVERSED_RANGE";

/// Difference in logical state between `from_seq` and `to_seq`.
///
/// # Refusals
///
/// **Below the history floor.** `compact` discards superseded versions, and
/// below [`Db::history_floor`] the `prev` chain no longer reaches. A diff
/// computed there would be indistinguishable from a diff over a range where
/// nothing happened: every pruned document would silently read as unchanged.
/// An empty answer that means "I cannot see" is worse than no answer, so this
/// refuses with [`HISTORY_PRUNED`] rather than returning a partial result.
///
/// **`from_seq > to_seq`.** Refused rather than interpreted as a reverse diff.
/// A reversed range is already expressible — it is `diff(to, from)` — so
/// accepting it here would buy nothing and cost the invariant that
/// `kind == Added` means "exists at `to_seq`". Silently swapping the arguments
/// would invert the meaning of every `kind` in the result relative to the
/// argument order the caller wrote, and nothing in the returned value would
/// tell them that happened.
///
/// A `to_seq` beyond the current tip is NOT refused: sequences are monotonic,
/// so any sequence at or past the tip denotes the current state unambiguously.
/// There is nothing to be wrong about, and refusing would make
/// `diff(x, u64::MAX)` — a reasonable spelling of "up to now" — an error.
pub fn diff(db: &Db, from_seq: u64, to_seq: u64) -> Result<StateDiff, String> {
    if from_seq > to_seq {
        return Err(format!(
            "{}: from_seq {} is after to_seq {}; a diff's argument order fixes the \
             sign of every change in it. Ask for diff({}, {}) if you want the \
             reverse.",
            REVERSED_RANGE, from_seq, to_seq, to_seq, from_seq
        ));
    }

    let floor = db.history_floor();
    if from_seq < floor || to_seq < floor {
        let which = if from_seq < floor { "from_seq" } else { "to_seq" };
        let bad = if from_seq < floor { from_seq } else { to_seq };
        return Err(format!(
            "{}: {} {} is below the history floor {}. compact() discarded the \
             superseded versions needed to reconstruct that state, so a diff there \
             could not distinguish an unchanged document from an unreadable one. \
             The oldest diffable sequence is {}.",
            HISTORY_PRUNED, which, bad, floor, floor
        ));
    }

    // Equal endpoints short-circuit. Not just an optimisation: it makes the
    // empty result a fact about the arguments rather than a claim about
    // storage, which holds even if the engine underneath is mid-write.
    if from_seq == to_seq {
        return Ok(StateDiff { from_seq, to_seq, collections: vec![], documents: vec![] });
    }

    // `BTreeSet` rather than `HashSet` so every set operation below emits
    // byte-wise sorted names with no sort step to forget.
    let before_colls: BTreeSet<String> = live_collections(db, from_seq);
    let after_colls: BTreeSet<String> = live_collections(db, to_seq);

    let mut collections = Vec::new();
    for name in after_colls.difference(&before_colls) {
        collections.push(CollChange { name: name.clone(), kind: ChangeKind::Added });
    }
    for name in before_colls.difference(&after_colls) {
        collections.push(CollChange { name: name.clone(), kind: ChangeKind::Removed });
    }
    // Interleave Added and Removed by name rather than grouping by kind: a
    // reader scanning a diff is looking for a collection, not for a kind.
    collections.sort_by(|a, b| a.name.cmp(&b.name));

    let mut documents = Vec::new();
    // Union, because a document can be added into a collection that is new at
    // `to_seq`, or removed along with one that died before it.
    for coll in before_colls.union(&after_colls) {
        // Collection liveness gates document visibility, and has to be checked
        // per endpoint rather than assumed from membership in the union.
        // `drop_collection` is a namespace tombstone that deliberately leaves
        // the rows alone, so `get_as_of` on a dropped collection still returns
        // documents — they are simply no longer part of the state, exactly as
        // `state_root_as_of` treats them. Without this gate a drop would show
        // up as a removed collection whose rows all read "unchanged", which is
        // not a state any query can return.
        let live_before = before_colls.contains(coll);
        let live_after = after_colls.contains(coll);

        // `list_ids_including_deleted` returns sorted, deduplicated ids, and is
        // the same candidate enumeration `AS OF` uses. It is a superset of what
        // was live at either endpoint — ids that are absent at both are
        // filtered out below, which is also what makes a create-then-delete
        // entirely inside the range correctly produce nothing.
        for id in db.list_ids_including_deleted(coll) {
            let before = live_before.then(|| db.get_as_of(coll, &id, from_seq)).flatten();
            let after = live_after.then(|| db.get_as_of(coll, &id, to_seq)).flatten();
            if let Some(change) = classify(coll, &id, before, after) {
                documents.push(change);
            }
        }
    }
    documents.sort_by(|a, b| a.coll.cmp(&b.coll).then_with(|| a.id.cmp(&b.id)));

    Ok(StateDiff { from_seq, to_seq, collections, documents })
}

/// Collections live at `seq`, with the engine's own namespace removed.
///
/// `_nedb.*` is bookkeeping: the collection registry, persisted state roots,
/// the history floor. Those records change as a consequence of user writes (and
/// of taking a root, which is not a state change at all), so surfacing them
/// would report the engine's own paperwork as part of the user's diff.
fn live_collections(db: &Db, seq: u64) -> BTreeSet<String> {
    db.collections_as_of(seq)
        .into_iter()
        .filter(|c| !crate::namespace::is_reserved(c))
        .collect()
}

/// Turn a pair of visible versions into a change, or `None` when there is none.
fn classify(
    coll: &str,
    id: &str,
    before: Option<crate::store::Node>,
    after: Option<crate::store::Node>,
) -> Option<DocChange> {
    match (before, after) {
        (None, None) => None,
        (None, Some(a)) => Some(DocChange {
            coll: coll.to_string(),
            id: id.to_string(),
            kind: ChangeKind::Added,
            before: None,
            after: Some(a.data),
            fields: None,
            temporal: None,
        }),
        (Some(b), None) => Some(DocChange {
            coll: coll.to_string(),
            id: id.to_string(),
            kind: ChangeKind::Removed,
            before: Some(b.data),
            after: None,
            fields: None,
            temporal: None,
        }),
        (Some(b), Some(a)) => {
            let temporal_moved =
                b.valid_from != a.valid_from || b.valid_to != a.valid_to;
            // Payload equality only — NOT node equality. `seq`, `hash`, `prev`,
            // `ts` and `caused_by` differ on every rewrite, including a rewrite
            // that stored byte-identical content, and reporting that as a state
            // change would make the diff a log again.
            //
            // Bi-temporal validity is the other half: the state root commits to
            // `valid_from`/`valid_to`, so a document whose window moved IS a
            // different logical state even with identical payload, and missing
            // it here would let `diff` say "no change" about two provably
            // different roots.
            if b.data == a.data && !temporal_moved {
                return None;
            }
            let fields = field_delta(&b.data, &a.data);
            Some(DocChange {
                coll: coll.to_string(),
                id: id.to_string(),
                kind: ChangeKind::Modified,
                before: Some(b.data),
                after: Some(a.data),
                fields,
                temporal: temporal_moved.then(|| TemporalDelta {
                    valid_from_before: b.valid_from,
                    valid_from_after: a.valid_from,
                    valid_to_before: b.valid_to,
                    valid_to_after: a.valid_to,
                }),
            })
        }
    }
}

/// Key-level delta, or `None` when either side is not a JSON object.
///
/// Output order is the byte-wise key order, not document order: `serde_json` is
/// built here with `preserve_order`, so a document's key order is whatever the
/// writer happened to use, and inheriting it would make the diff of two
/// equivalent documents depend on how they were typed.
fn field_delta(before: &Value, after: &Value) -> Option<FieldDelta> {
    let (b, a) = match (before.as_object(), after.as_object()) {
        (Some(b), Some(a)) => (b, a),
        _ => return None,
    };
    let mut delta = FieldDelta::default();
    let keys: BTreeSet<&String> = b.keys().chain(a.keys()).collect();
    for k in keys {
        match (b.get(k), a.get(k)) {
            (None, Some(_)) => delta.added.push(k.clone()),
            (Some(_), None) => delta.removed.push(k.clone()),
            (Some(bv), Some(av)) if bv != av => delta.changed.push(k.clone()),
            _ => {}
        }
    }
    Some(delta)
}

/// The last assigned sequence — the newest point `diff` can be asked about and
/// get a full answer for. Convenience for callers that want "since X, up to
/// now" without reaching into `Db::seq` and getting the off-by-one wrong.
pub fn tip(db: &Db) -> u64 {
    db.seq.load(Ordering::SeqCst).saturating_sub(1)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn db() -> Db {
        Db::in_memory()
    }

    fn put(db: &Db, coll: &str, id: &str, data: Value) -> u64 {
        db.put(coll, id, data, vec![], None, None)
            .expect("put should succeed")
            .seq
    }

    fn find<'a>(d: &'a StateDiff, coll: &str, id: &str) -> Option<&'a DocChange> {
        d.documents.iter().find(|c| c.coll == coll && c.id == id)
    }

    #[test]
    fn added_document_is_detected() {
        let db = db();
        let from = put(&db, "users", "a", json!({"n": 1}));
        put(&db, "users", "b", json!({"n": 2}));
        let d = diff(&db, from, tip(&db)).unwrap();
        let c = find(&d, "users", "b").expect("b should appear");
        assert_eq!(c.kind, ChangeKind::Added);
        assert_eq!(c.before, None);
        assert_eq!(c.after, Some(json!({"n": 2})));
        assert!(c.fields.is_none(), "an add has no field delta; `after` is the whole story");
    }

    #[test]
    fn removed_document_is_detected() {
        let db = db();
        put(&db, "users", "a", json!({"n": 1}));
        let from = tip(&db);
        db.delete("users", "a").unwrap();
        let d = diff(&db, from, tip(&db)).unwrap();
        let c = find(&d, "users", "a").expect("a should appear");
        assert_eq!(c.kind, ChangeKind::Removed);
        assert_eq!(c.before, Some(json!({"n": 1})));
        assert_eq!(c.after, None);
    }

    #[test]
    fn modified_document_is_detected() {
        let db = db();
        put(&db, "users", "a", json!({"n": 1}));
        let from = tip(&db);
        put(&db, "users", "a", json!({"n": 2}));
        let d = diff(&db, from, tip(&db)).unwrap();
        let c = find(&d, "users", "a").expect("a should appear");
        assert_eq!(c.kind, ChangeKind::Modified);
        assert_eq!(c.before, Some(json!({"n": 1})));
        assert_eq!(c.after, Some(json!({"n": 2})));
    }

    #[test]
    fn document_created_and_deleted_inside_the_range_does_not_appear() {
        let db = db();
        put(&db, "users", "keep", json!({"n": 0}));
        let from = tip(&db);
        put(&db, "users", "ghost", json!({"n": 1}));
        db.delete("users", "ghost").unwrap();
        let d = diff(&db, from, tip(&db)).unwrap();
        assert!(
            find(&d, "users", "ghost").is_none(),
            "absent on both sides is not a state change: {:?}",
            d.documents
        );
        assert!(d.documents.is_empty(), "{:?}", d.documents);
    }

    #[test]
    fn unchanged_document_does_not_appear() {
        let db = db();
        put(&db, "users", "a", json!({"n": 1}));
        let from = tip(&db);
        put(&db, "users", "b", json!({"n": 2}));
        let d = diff(&db, from, tip(&db)).unwrap();
        assert!(find(&d, "users", "a").is_none());
        assert_eq!(d.documents.len(), 1);
    }

    #[test]
    fn rewriting_identical_content_is_not_a_change() {
        // The line between a diff and a log: five writes, zero state change.
        let db = db();
        put(&db, "users", "a", json!({"n": 1}));
        let from = tip(&db);
        for _ in 0..5 {
            put(&db, "users", "a", json!({"n": 1}));
        }
        let d = diff(&db, from, tip(&db)).unwrap();
        assert!(d.is_empty(), "{:?}", d);
    }

    #[test]
    fn value_restored_to_its_original_is_not_a_change() {
        let db = db();
        put(&db, "users", "a", json!({"n": 1}));
        let from = tip(&db);
        put(&db, "users", "a", json!({"n": 99}));
        put(&db, "users", "a", json!({"n": 1}));
        let d = diff(&db, from, tip(&db)).unwrap();
        assert!(d.is_empty(), "net state is identical: {:?}", d);
    }

    #[test]
    fn created_collection_appears_as_added() {
        let db = db();
        put(&db, "users", "a", json!({"n": 1}));
        let from = tip(&db);
        put(&db, "orders", "o1", json!({"total": 10}));
        let d = diff(&db, from, tip(&db)).unwrap();
        assert_eq!(
            d.collections,
            vec![CollChange { name: "orders".into(), kind: ChangeKind::Added }]
        );
        assert_eq!(find(&d, "orders", "o1").unwrap().kind, ChangeKind::Added);
    }

    #[test]
    fn emptied_but_live_collection_is_not_a_removed_collection() {
        let db = db();
        put(&db, "orders", "o1", json!({"total": 10}));
        let from = tip(&db);
        db.delete("orders", "o1").unwrap();
        let d = diff(&db, from, tip(&db)).unwrap();
        assert!(
            d.collections.is_empty(),
            "an empty collection still exists; only a drop removes it: {:?}",
            d.collections
        );
        assert_eq!(find(&d, "orders", "o1").unwrap().kind, ChangeKind::Removed);
    }

    #[test]
    fn dropped_collection_appears_as_removed_with_its_rows() {
        let db = db();
        put(&db, "orders", "o1", json!({"total": 10}));
        put(&db, "orders", "o2", json!({"total": 20}));
        let from = tip(&db);
        assert!(db.drop_collection("orders").unwrap());
        let d = diff(&db, from, tip(&db)).unwrap();
        assert_eq!(
            d.collections,
            vec![CollChange { name: "orders".into(), kind: ChangeKind::Removed }]
        );
        // The namespace fact AND the row facts: a consumer rebuilding state
        // from this diff needs both.
        assert_eq!(d.documents.len(), 2);
        assert!(d.documents.iter().all(|c| c.kind == ChangeKind::Removed));
    }

    #[test]
    fn reserved_collections_never_appear() {
        let db = db();
        // Seed first: on an empty database `tip` saturates to 0, which is also
        // the sequence the very first registry record gets, so a range starting
        // at the tip of an empty db already contains that record.
        put(&db, "seed", "s", json!({}));
        let from = tip(&db);
        // Every user write touches the registry, and create_root writes a root
        // record — both land in `_nedb.*`.
        put(&db, "users", "a", json!({"n": 1}));
        db.create_root().unwrap();
        let d = diff(&db, from, tip(&db)).unwrap();
        assert!(
            d.collections.iter().all(|c| !c.name.starts_with("_nedb")),
            "{:?}",
            d.collections
        );
        assert!(
            d.documents.iter().all(|c| !c.coll.starts_with("_nedb")),
            "{:?}",
            d.documents
        );
        assert_eq!(
            d.collections,
            vec![CollChange { name: "users".into(), kind: ChangeKind::Added }]
        );
    }

    #[test]
    fn below_the_history_floor_is_refused_not_silently_empty() {
        let db = db();
        put(&db, "users", "a", json!({"n": 1}));
        put(&db, "users", "a", json!({"n": 2}));
        // Set the floor directly rather than via compact(). Compaction only
        // raises it when it ACTUALLY pruned something, and the only substrate
        // that prunes is selected by the process-global NEDB_DAG_V3 — which a
        // threaded test run cannot set without changing the substrate under
        // every other database being opened at that moment.
        db.set_history_floor(tip(&db)).unwrap();
        let floor = db.history_floor();
        assert!(floor > 0, "precondition: the database is in the pruned state");

        let err = diff(&db, 0, tip(&db)).unwrap_err();
        assert!(err.starts_with(HISTORY_PRUNED), "{}", err);
        assert!(err.contains(&floor.to_string()), "the reason must name the floor: {}", err);

        // At or above the floor is still answerable.
        assert!(diff(&db, floor, tip(&db)).is_ok());
    }

    #[test]
    fn history_floor_refusal_also_covers_to_seq() {
        let db = db();
        put(&db, "users", "a", json!({"n": 1}));
        put(&db, "users", "a", json!({"n": 2}));
        db.set_history_floor(tip(&db)).unwrap();
        let floor = db.history_floor();
        // from == to == 0 would short-circuit to empty if the floor check ran
        // second; it must run first.
        let err = diff(&db, 0, 0).unwrap_err();
        assert!(err.starts_with(HISTORY_PRUNED), "{}", err);
        assert!(err.contains("from_seq"), "{}", err);
        let err = diff(&db, floor, floor - 1).unwrap_err();
        assert!(err.starts_with(REVERSED_RANGE), "{}", err);
    }

    #[test]
    fn reversed_range_is_refused() {
        let db = db();
        put(&db, "users", "a", json!({"n": 1}));
        let t = tip(&db);
        let err = diff(&db, t, 0).unwrap_err();
        assert!(err.starts_with(REVERSED_RANGE), "{}", err);
        assert!(err.contains(&format!("diff({}, {})", 0, t)), "must name the fix: {}", err);
    }

    #[test]
    fn field_delta_names_added_removed_and_changed_keys() {
        let db = db();
        put(&db, "users", "a", json!({"keep": 1, "drop": 2, "move": 3}));
        let from = tip(&db);
        put(&db, "users", "a", json!({"keep": 1, "move": 4, "new": 5}));
        let d = diff(&db, from, tip(&db)).unwrap();
        let f = find(&d, "users", "a").unwrap().fields.as_ref().expect("objects get a delta");
        assert_eq!(f.added, vec!["new".to_string()]);
        assert_eq!(f.removed, vec!["drop".to_string()]);
        assert_eq!(f.changed, vec!["move".to_string()]);
    }

    #[test]
    fn no_field_delta_when_either_side_is_not_an_object() {
        let db = db();
        put(&db, "vals", "scalar", json!(1));
        put(&db, "vals", "arr", json!([1, 2]));
        let from = tip(&db);
        put(&db, "vals", "scalar", json!({"n": 1}));
        put(&db, "vals", "arr", json!([1, 2, 3]));
        let d = diff(&db, from, tip(&db)).unwrap();
        assert!(find(&d, "vals", "scalar").unwrap().fields.is_none());
        assert!(find(&d, "vals", "arr").unwrap().fields.is_none());
    }

    #[test]
    fn valid_from_change_alone_counts_as_modified() {
        let db = db();
        db.put("users", "a", json!({"n": 1}), vec![], Some("2020-01-01".into()), None)
            .unwrap();
        let from = tip(&db);
        db.put("users", "a", json!({"n": 1}), vec![], Some("2021-01-01".into()), None)
            .unwrap();
        let d = diff(&db, from, tip(&db)).unwrap();
        let c = find(&d, "users", "a").expect("a temporal move is a state change");
        assert_eq!(c.kind, ChangeKind::Modified);
        assert_eq!(c.before, c.after, "payload identical; only the window moved");
        let t = c.temporal.as_ref().expect("the reason must be reported");
        assert_eq!(t.valid_from_before.as_deref(), Some("2020-01-01"));
        assert_eq!(t.valid_from_after.as_deref(), Some("2021-01-01"));
        assert!(
            c.fields.as_ref().unwrap().is_empty(),
            "validity is not a field, so no key moved"
        );
    }

    #[test]
    fn valid_to_change_alone_counts_as_modified() {
        let db = db();
        db.put("users", "a", json!({"n": 1}), vec![], None, None).unwrap();
        let from = tip(&db);
        db.put("users", "a", json!({"n": 1}), vec![], None, Some("2030-01-01".into()))
            .unwrap();
        let d = diff(&db, from, tip(&db)).unwrap();
        let c = find(&d, "users", "a").unwrap();
        assert_eq!(c.kind, ChangeKind::Modified);
        let t = c.temporal.as_ref().unwrap();
        assert_eq!(t.valid_to_before, None);
        assert_eq!(t.valid_to_after.as_deref(), Some("2030-01-01"));
    }

    #[test]
    fn no_temporal_delta_when_the_window_did_not_move() {
        let db = db();
        db.put("users", "a", json!({"n": 1}), vec![], Some("2020-01-01".into()), None)
            .unwrap();
        let from = tip(&db);
        db.put("users", "a", json!({"n": 2}), vec![], Some("2020-01-01".into()), None)
            .unwrap();
        let d = diff(&db, from, tip(&db)).unwrap();
        assert!(find(&d, "users", "a").unwrap().temporal.is_none());
    }

    #[test]
    fn diff_of_a_point_with_itself_is_empty() {
        let db = db();
        put(&db, "users", "a", json!({"n": 1}));
        put(&db, "orders", "o1", json!({"n": 2}));
        let t = tip(&db);
        let d = diff(&db, t, t).unwrap();
        assert!(d.is_empty(), "{:?}", d);
        assert_eq!((d.from_seq, d.to_seq), (t, t));
        // And at a sequence in the middle of history, not just the tip.
        assert!(diff(&db, 1, 1).unwrap().is_empty());
    }

    #[test]
    fn output_ordering_is_deterministic() {
        let db = db();
        put(&db, "seed", "s", json!({}));
        let from = tip(&db);
        // Insert in an order that is neither sorted nor reverse-sorted, across
        // several collections, so a stable answer cannot be an accident of
        // insertion order.
        for (coll, id) in [
            ("zeta", "m"), ("alpha", "z"), ("zeta", "a"),
            ("alpha", "b"), ("mid", "q"), ("alpha", "a"),
        ] {
            put(&db, coll, id, json!({"v": id}));
        }
        let to = tip(&db);
        let first = diff(&db, from, to).unwrap();
        let second = diff(&db, from, to).unwrap();
        assert_eq!(first, second, "two runs over the same range must agree");

        let colls: Vec<&str> = first.collections.iter().map(|c| c.name.as_str()).collect();
        assert_eq!(colls, vec!["alpha", "mid", "zeta"]);
        let docs: Vec<(&str, &str)> = first
            .documents
            .iter()
            .map(|c| (c.coll.as_str(), c.id.as_str()))
            .collect();
        assert_eq!(
            docs,
            vec![
                ("alpha", "a"), ("alpha", "b"), ("alpha", "z"),
                ("mid", "q"),
                ("zeta", "a"), ("zeta", "m"),
            ]
        );
    }

    #[test]
    fn recreated_document_is_modified_not_added() {
        // Delete then re-put starts a fresh version chain. The endpoints are
        // what matter: present both sides, different content.
        let db = db();
        put(&db, "users", "a", json!({"n": 1}));
        let from = tip(&db);
        db.delete("users", "a").unwrap();
        put(&db, "users", "a", json!({"n": 2}));
        let d = diff(&db, from, tip(&db)).unwrap();
        let c = find(&d, "users", "a").unwrap();
        assert_eq!(c.kind, ChangeKind::Modified);
        assert_eq!(c.before, Some(json!({"n": 1})));
        assert_eq!(c.after, Some(json!({"n": 2})));
    }

    #[test]
    fn an_empty_diff_implies_equal_state_roots() {
        // The contract that ties this module to `root`: if diff says nothing
        // changed, the two roots must agree, and vice versa.
        let db = db();
        put(&db, "users", "a", json!({"n": 1}));
        let from = tip(&db);
        put(&db, "users", "a", json!({"n": 99}));
        put(&db, "users", "a", json!({"n": 1}));
        let to = tip(&db);
        assert!(diff(&db, from, to).unwrap().is_empty());
        assert_eq!(
            db.state_root_as_of(from).unwrap().state_root,
            db.state_root_as_of(to).unwrap().state_root
        );
    }
}
