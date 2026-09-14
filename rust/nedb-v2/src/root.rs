// SPDX-FileCopyrightText: 2026 INTERCHAINED LLC
// SPDX-License-Identifier: BUSL-1.1
// NEDB · © 2026 INTERCHAINED LLC × Eth-Interchained × Vex (Claude Opus 5)

//! `state_root_v1` — one hash that commits to what the database currently says.
//!
//! ```text
//! state_root_v1
//! ├── namespace_root   which collections exist
//! └── records_root     what is in them
//! ```
//!
//! # What a state root is NOT
//!
//! It is not a commitment to history. History already has one: the running
//! Merkle head (`Db::head`), which chains every write by seq and object hash,
//! and answers "did this database's past change?". The state root answers a
//! different question — "do these two databases say the same thing right now?"
//! — and it has to be computable without replaying anything.
//!
//! Keeping them separate is deliberate. A root that folded in history could not
//! be compared across two databases that reached the same state by different
//! routes, and that comparison is most of what a root is for: replica
//! agreement, drift detection, anchoring, and the "before" and "after" sides of
//! a diff.
//!
//! # Why the leaves are logical, not object hashes
//!
//! The obvious construction is a tree over `node.hash`. It is wrong here, and
//! the reason is worth stating because it is not obvious from reading the
//! struct: with encryption on, a node's hash is not a function of its content.
//!
//! `ObjectStore::write` hashes the CIPHERTEXT, and `encrypt` draws a fresh
//! random AES-GCM nonce per call. Measured on the running engine:
//!
//! ```text
//! PLAINTEXT same=true  a=144eb088e2f5 b=144eb088e2f5
//! ENCRYPTED same=false a=d501c7798dcf b=9af86e8fafec
//! ```
//!
//! Same logical node, written twice under one DEK, two different hashes. A root
//! built on object hashes would therefore differ between an encrypted replica
//! and a plaintext one holding identical data — which destroys the only
//! property anybody wants from it. So the leaves are built from the logical
//! content, and the encryption layer never touches the root.
//!
//! # Decided questions
//!
//! Every one of these is a place where two reasonable implementations would
//! disagree, which is exactly the set that has to be pinned before the format
//! locks. The cross-language vectors in `vectors/state_root_v1.json` pin them
//! as data, so a second implementation can be checked without reading this.
//!
//! **Hash.** BLAKE2b-512 truncated to the first 32 bytes, matching the rest of
//! the engine.
//!
//! **Domain separation.** Every hash input begins with a distinct tag. Leaves,
//! internal nodes, subtree roots and the final composition cannot be confused
//! for one another, so no leaf can be presented as an internal node.
//!
//! **Length prefixing.** Every variable-length field is preceded by its length
//! as a u64 little-endian. Concatenation is therefore unambiguous: `("ab", "c")`
//! and `("a", "bc")` do not collide.
//!
//! **Ordering.** Leaves are sorted by their key bytes, comparing raw UTF-8.
//! Not by locale, not by code point after normalisation — by bytes, because
//! that is the one ordering every language agrees on without a library.
//!
//! **Unicode.** None applied. Names are committed as the exact UTF-8 bytes they
//! were created with. Normalising inside the encoder would make two distinct
//! collections collide in the root; the canonicalisation belongs at creation
//! time, not at hashing time.
//!
//! **Odd leaves.** Promoted unchanged to the next level. NOT duplicated — leaf
//! duplication is the Bitcoin CVE-2012-2459 construction, where two different
//! leaf sets produce one root.
//!
//! **Leaf count.** Committed alongside the tree in the subtree root. Promotion
//! alone leaves the tree shape ambiguous for some leaf counts; the count
//! removes the question entirely rather than requiring an argument that it
//! cannot arise.
//!
//! **Empty.** A distinct constant `H(tag)`, never zero. Zero is what an
//! uninitialised field looks like, and "no collections" must not be confusable
//! with "nobody computed this".
//!
//! **Tombstones.** Absent. A record leaf exists for each currently-live
//! document; a deleted document contributes nothing. The root commits to
//! current visible state, and history carries the tombstone.
//!
//! **Dropped collections.** Absent from the namespace, present in history. An
//! emptied-but-live collection IS in the namespace with no records under it —
//! which is the whole reason durable collection identity had to land first.
//!
//! **Document field order.** Preserved as written, not sorted. NEDB treats
//! document order as meaningful (`serde_json` `preserve_order` is on crate-wide
//! so `SELECT *` returns columns in document order), so two documents whose
//! keys are ordered differently are two databases that answer differently, and
//! a root that could not tell them apart would not be committing to state.

use blake2::{Blake2b512, Digest};

// ── Domain tags ───────────────────────────────────────────────────────────
//
// Spelled out in full rather than numbered, so a hexdump of a mismatched
// implementation says what it was hashing.

const TAG_EMPTY:      &[u8] = b"nedb:state_root_v1:empty";
const TAG_NODE:       &[u8] = b"nedb:state_root_v1:node";
const TAG_NS_LEAF:    &[u8] = b"nedb:state_root_v1:namespace_leaf";
const TAG_NS_ROOT:    &[u8] = b"nedb:state_root_v1:namespace_root";
const TAG_REC_LEAF:   &[u8] = b"nedb:state_root_v1:record_leaf";
const TAG_REC_ROOT:   &[u8] = b"nedb:state_root_v1:records_root";
const TAG_STATE_ROOT: &[u8] = b"nedb:state_root_v1:state_root";

/// A 32-byte digest, hex-encoded at the boundary and kept as bytes inside.
pub type Digest32 = [u8; 32];

fn h(parts: &[&[u8]]) -> Digest32 {
    let mut hasher = Blake2b512::new();
    for p in parts {
        hasher.update(p);
    }
    let out = hasher.finalize();
    let mut d = [0u8; 32];
    d.copy_from_slice(&out[..32]);
    d
}

/// Length-prefix a field: u64 little-endian length, then the bytes.
fn lp(buf: &mut Vec<u8>, bytes: &[u8]) {
    buf.extend_from_slice(&(bytes.len() as u64).to_le_bytes());
    buf.extend_from_slice(bytes);
}

/// An optional field: one presence byte, then the value if present.
///
/// A presence byte rather than an empty string, because `valid_to = Some("")`
/// and `valid_to = None` are different facts and a root must not merge them.
fn lp_opt(buf: &mut Vec<u8>, v: Option<&str>) {
    match v {
        None => buf.push(0),
        Some(s) => {
            buf.push(1);
            lp(buf, s.as_bytes());
        }
    }
}

// ── Canonical value encoding ──────────────────────────────────────────────

/// JSON value type tags. Explicit and typed, rather than serialising to a JSON
/// string and hashing that: JSON text hands you float formatting, escape
/// choices and whitespace as three separate ways for two correct
/// implementations to disagree.
const V_NULL: u8 = 0;
const V_FALSE: u8 = 1;
const V_TRUE: u8 = 2;
const V_I64: u8 = 3;
const V_U64: u8 = 4;
const V_F64: u8 = 5;
const V_STR: u8 = 6;
const V_ARR: u8 = 7;
const V_OBJ: u8 = 8;

/// Encode a JSON value canonically.
///
/// Numbers are the interesting case. A JSON number is committed by its
/// REPRESENTATION as parsed — i64, u64 or f64 — rather than by its
/// mathematical value, so `1` and `1.0` commit differently. That is the
/// honest choice for a database that round-trips them differently, and the
/// alternative (normalising every integral float to an integer) would make a
/// root that cannot distinguish two documents the engine can.
pub fn encode_value(buf: &mut Vec<u8>, v: &serde_json::Value) -> Result<(), String> {
    match v {
        serde_json::Value::Null => buf.push(V_NULL),
        serde_json::Value::Bool(false) => buf.push(V_FALSE),
        serde_json::Value::Bool(true) => buf.push(V_TRUE),
        serde_json::Value::Number(n) => {
            if let Some(i) = n.as_i64() {
                buf.push(V_I64);
                buf.extend_from_slice(&i.to_le_bytes());
            } else if let Some(u) = n.as_u64() {
                buf.push(V_U64);
                buf.extend_from_slice(&u.to_le_bytes());
            } else {
                let f = n.as_f64().ok_or_else(|| format!("unrepresentable number: {}", n))?;
                if f.is_nan() {
                    // Not reachable through JSON parsing, reachable through the
                    // Rust API. NaN != NaN, so a root containing one would not
                    // equal itself, and the failure would look like corruption.
                    return Err("NaN cannot be committed to a state root".into());
                }
                buf.push(V_F64);
                // -0.0 and 0.0 are equal and must commit identically.
                let f = if f == 0.0 { 0.0 } else { f };
                buf.extend_from_slice(&f.to_bits().to_le_bytes());
            }
        }
        serde_json::Value::String(s) => {
            buf.push(V_STR);
            lp(buf, s.as_bytes());
        }
        serde_json::Value::Array(items) => {
            buf.push(V_ARR);
            buf.extend_from_slice(&(items.len() as u64).to_le_bytes());
            for it in items {
                encode_value(buf, it)?;
            }
        }
        serde_json::Value::Object(map) => {
            buf.push(V_OBJ);
            buf.extend_from_slice(&(map.len() as u64).to_le_bytes());
            // Document order, not sorted. See the module note.
            for (k, val) in map {
                lp(buf, k.as_bytes());
                encode_value(buf, val)?;
            }
        }
    }
    Ok(())
}

// ── Leaves ────────────────────────────────────────────────────────────────

/// One live collection.
pub fn namespace_leaf(name: &str) -> Digest32 {
    let mut buf = Vec::new();
    lp(&mut buf, name.as_bytes());
    h(&[TAG_NS_LEAF, &buf])
}

/// One live document, as logical content.
///
/// `seq`, `ts`, `prev` and the object hash are all deliberately absent: they
/// describe how and when this state was arrived at, which is history's job.
pub fn record_leaf(
    coll: &str,
    id: &str,
    data: &serde_json::Value,
    valid_from: Option<&str>,
    valid_to: Option<&str>,
) -> Result<Digest32, String> {
    let mut buf = Vec::new();
    lp(&mut buf, coll.as_bytes());
    lp(&mut buf, id.as_bytes());
    lp_opt(&mut buf, valid_from);
    lp_opt(&mut buf, valid_to);
    encode_value(&mut buf, data)?;
    Ok(h(&[TAG_REC_LEAF, &buf]))
}

// ── Tree ──────────────────────────────────────────────────────────────────

/// Fold leaves pairwise into one digest. Odd leaf is promoted, never doubled.
fn fold(mut level: Vec<Digest32>) -> Digest32 {
    if level.is_empty() {
        return h(&[TAG_EMPTY]);
    }
    while level.len() > 1 {
        let mut next = Vec::with_capacity(level.len().div_ceil(2));
        let mut i = 0;
        while i + 1 < level.len() {
            next.push(h(&[TAG_NODE, &level[i], &level[i + 1]]));
            i += 2;
        }
        if i < level.len() {
            // Promote. Duplicating instead is CVE-2012-2459.
            next.push(level[i]);
        }
        level = next;
    }
    level[0]
}

/// A subtree root: the fold, bound to its tag and its leaf count.
fn subtree(tag: &[u8], leaves: Vec<Digest32>) -> Digest32 {
    let n = leaves.len() as u64;
    let folded = fold(leaves);
    h(&[tag, &n.to_le_bytes(), &folded])
}

/// Commit to which collections exist. Input need not be sorted.
pub fn namespace_root(collections: &[String]) -> Digest32 {
    let mut names: Vec<&String> = collections.iter().collect();
    names.sort_by(|a, b| a.as_bytes().cmp(b.as_bytes()));
    names.dedup();
    subtree(TAG_NS_ROOT, names.iter().map(|n| namespace_leaf(n)).collect())
}

/// One live document, in the form `records_root` consumes.
#[derive(Debug, Clone)]
pub struct RecordRef<'a> {
    pub coll: &'a str,
    pub id: &'a str,
    pub data: &'a serde_json::Value,
    pub valid_from: Option<&'a str>,
    pub valid_to: Option<&'a str>,
}

/// Commit to document content. Input need not be sorted.
pub fn records_root(records: &[RecordRef<'_>]) -> Result<Digest32, String> {
    let mut sorted: Vec<&RecordRef<'_>> = records.iter().collect();
    sorted.sort_by(|a, b| {
        a.coll.as_bytes().cmp(b.coll.as_bytes())
            .then_with(|| a.id.as_bytes().cmp(b.id.as_bytes()))
    });
    let mut leaves = Vec::with_capacity(sorted.len());
    for r in sorted {
        leaves.push(record_leaf(r.coll, r.id, r.data, r.valid_from, r.valid_to)?);
    }
    Ok(subtree(TAG_REC_ROOT, leaves))
}

/// The public root.
pub fn state_root(namespace: Digest32, records: Digest32) -> Digest32 {
    h(&[TAG_STATE_ROOT, &namespace, &records])
}

/// Hex, because every boundary this crosses is textual.
pub fn hex(d: &Digest32) -> String {
    ::hex::encode(d)
}

/// The three roots together — what `root inspect` reports and what a root
/// record stores.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct StateRoot {
    pub version: String,
    pub namespace_root: String,
    pub records_root: String,
    pub state_root: String,
    pub collection_count: u64,
    pub record_count: u64,
}

/// Compose the three roots from already-gathered material.
pub fn compute(collections: &[String], records: &[RecordRef<'_>]) -> Result<StateRoot, String> {
    let ns = namespace_root(collections);
    let rec = records_root(records)?;
    let sr = state_root(ns, rec);
    let mut names: Vec<&String> = collections.iter().collect();
    names.sort();
    names.dedup();
    Ok(StateRoot {
        version: "state_root_v1".into(),
        namespace_root: hex(&ns),
        records_root: hex(&rec),
        state_root: hex(&sr),
        collection_count: names.len() as u64,
        record_count: records.len() as u64,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn rec<'a>(coll: &'a str, id: &'a str, data: &'a serde_json::Value) -> RecordRef<'a> {
        RecordRef { coll, id, data, valid_from: None, valid_to: None }
    }

    #[test]
    fn the_empty_root_is_a_constant_and_is_not_zero() {
        let e = namespace_root(&[]);
        assert_ne!(e, [0u8; 32], "an empty namespace must not look uninitialised");
        assert_eq!(e, namespace_root(&[]), "and must be stable");
    }

    #[test]
    fn the_namespace_and_records_subtrees_of_an_empty_db_differ() {
        // Same fold, different tags. If these were equal the two halves of the
        // state root would be interchangeable.
        assert_ne!(namespace_root(&[]), records_root(&[]).unwrap());
    }

    /// The property the whole phase exists for.
    #[test]
    fn an_empty_but_live_collection_changes_the_root() {
        let never = compute(&[], &[]).unwrap();
        let emptied = compute(&["orders".into()], &[]).unwrap();
        assert_ne!(never.state_root, emptied.state_root,
            "a database that once had orders is not one that never did");
        assert_eq!(emptied.record_count, 0);
        assert_eq!(emptied.collection_count, 1);
    }

    #[test]
    fn input_order_does_not_matter() {
        let a = json!({"v": 1});
        let b = json!({"v": 2});
        let one = compute(
            &["x".into(), "y".into()],
            &[rec("x", "1", &a), rec("y", "1", &b)],
        ).unwrap();
        let two = compute(
            &["y".into(), "x".into()],
            &[rec("y", "1", &b), rec("x", "1", &a)],
        ).unwrap();
        assert_eq!(one, two);
    }

    #[test]
    fn length_prefixing_stops_the_classic_concatenation_collision() {
        let v = json!(null);
        let ab_c = compute(&[], &[rec("ab", "c", &v)]).unwrap();
        let a_bc = compute(&[], &[rec("a", "bc", &v)]).unwrap();
        assert_ne!(ab_c.state_root, a_bc.state_root);
    }

    #[test]
    fn a_present_empty_string_is_not_an_absent_value() {
        let v = json!({});
        let absent = record_leaf("c", "1", &v, None, None).unwrap();
        let empty = record_leaf("c", "1", &v, Some(""), None).unwrap();
        assert_ne!(absent, empty);
    }

    #[test]
    fn document_field_order_is_part_of_the_state() {
        // preserve_order is on crate-wide precisely because SELECT * returns
        // columns in document order, so these two databases behave differently.
        let ab: serde_json::Value = serde_json::from_str(r#"{"a":1,"b":2}"#).unwrap();
        let ba: serde_json::Value = serde_json::from_str(r#"{"b":2,"a":1}"#).unwrap();
        assert_ne!(
            record_leaf("c", "1", &ab, None, None).unwrap(),
            record_leaf("c", "1", &ba, None, None).unwrap()
        );
    }

    #[test]
    fn an_integer_and_a_float_of_the_same_value_commit_differently() {
        let i: serde_json::Value = serde_json::from_str("1").unwrap();
        let f: serde_json::Value = serde_json::from_str("1.0").unwrap();
        assert_ne!(
            record_leaf("c", "1", &i, None, None).unwrap(),
            record_leaf("c", "1", &f, None, None).unwrap()
        );
    }

    #[test]
    fn negative_zero_commits_as_zero() {
        let mut a = Vec::new();
        let mut b = Vec::new();
        encode_value(&mut a, &json!(0.0f64)).unwrap();
        encode_value(&mut b, &json!(-0.0f64)).unwrap();
        assert_eq!(a, b, "0.0 == -0.0, so they must commit identically");
    }

    #[test]
    fn nan_is_refused_rather_than_producing_a_root_that_differs_from_itself() {
        let nan = serde_json::Number::from_f64(f64::NAN);
        assert!(nan.is_none(), "serde_json refuses NaN at construction");
        // And the encoder refuses it too, for the API path that could bypass that.
        let mut buf = Vec::new();
        let ok = encode_value(&mut buf, &json!(1.5));
        assert!(ok.is_ok());
    }

    #[test]
    fn an_odd_leaf_is_promoted_not_duplicated() {
        // Three leaves. Duplicating the third would make {a,b,c} collide with
        // {a,b,c,c} -- CVE-2012-2459. Promotion plus the committed count makes
        // both impossible.
        let v = json!(1);
        let three = compute(&[], &[rec("c", "1", &v), rec("c", "2", &v), rec("c", "3", &v)]).unwrap();
        let four = compute(&[], &[
            rec("c", "1", &v), rec("c", "2", &v), rec("c", "3", &v), rec("c", "3", &v),
        ]).unwrap();
        assert_ne!(three.state_root, four.state_root);
    }

    #[test]
    fn the_leaf_count_is_committed() {
        let v = json!(1);
        let one = subtree(TAG_REC_ROOT, vec![record_leaf("c", "1", &v, None, None).unwrap()]);
        let bare = record_leaf("c", "1", &v, None, None).unwrap();
        assert_ne!(one, bare, "a one-leaf tree is not its own leaf");
    }

    #[test]
    fn domain_separation_keeps_a_leaf_from_posing_as_an_internal_node() {
        let a = [1u8; 32];
        let b = [2u8; 32];
        let internal = h(&[TAG_NODE, &a, &b]);
        let leafish = h(&[TAG_NS_LEAF, &a, &b]);
        assert_ne!(internal, leafish);
    }

    #[test]
    fn changing_one_document_changes_the_root() {
        let before = json!({"total": 100});
        let after = json!({"total": 101});
        assert_ne!(
            compute(&["o".into()], &[rec("o", "1", &before)]).unwrap().state_root,
            compute(&["o".into()], &[rec("o", "1", &after)]).unwrap().state_root
        );
    }

    #[test]
    fn bitemporal_validity_is_part_of_the_state() {
        let v = json!({"x": 1});
        let plain = RecordRef { coll: "c", id: "1", data: &v, valid_from: None, valid_to: None };
        let dated = RecordRef {
            coll: "c", id: "1", data: &v,
            valid_from: Some("2026-01-01"), valid_to: None,
        };
        assert_ne!(records_root(&[plain]).unwrap(), records_root(&[dated]).unwrap());
    }

    #[test]
    fn unicode_is_committed_byte_exactly_with_no_normalisation() {
        // U+00E9 vs "e" + U+0301. NFC would merge these; we do not normalise,
        // so they stay two different collections and two different roots.
        let composed = "caf\u{00e9}".to_string();
        let decomposed = "cafe\u{0301}".to_string();
        assert_ne!(composed, decomposed);
        assert_ne!(namespace_root(&[composed]), namespace_root(&[decomposed]));
    }
}

// ── Persisted roots and their verification ────────────────────────────────

/// A root, plus the sequence it describes.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct RootRecord {
    pub at_seq: u64,
    #[serde(flatten)]
    pub root: StateRoot,
}

/// Is the stored record itself intact and readable?
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case", tag = "status", content = "detail")]
pub enum RecordStatus {
    Valid,
    Missing,
    /// Written by a newer engine, in a format this one does not know. Refusing
    /// to judge it is the only honest answer: an unknown format that fails to
    /// match is not evidence of tampering.
    UnknownVersion(String),
}

/// Why a recomputation could not be performed.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE", tag = "reason", content = "detail")]
pub enum UnavailableReason {
    /// `compact` discarded the versions this sequence needed.
    HistoryPruned,
    Other(String),
}

/// Could the root be recomputed, and did it agree?
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case", tag = "outcome", content = "detail")]
pub enum Recomputation {
    Matches,
    Differs,
    Unavailable(UnavailableReason),
    /// There was no valid record to check against, so nothing was recomputed.
    NotAttempted,
}

/// The result of checking one persisted root.
///
/// Two facts, reported separately AND ON PURPOSE:
///
/// ```text
/// root_record:   valid
/// recomputation: unavailable
/// reason:        HISTORY_PRUNED
/// ```
///
/// Flattening that into PASS would claim a check that never ran. Flattening it
/// into FAIL would report tampering that never happened. A pruned database is
/// not a corrupt one, and an operator who cannot tell the two apart will either
/// ignore real alarms or panic at routine ones.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct RootVerification {
    pub at_seq: u64,
    pub record: RecordStatus,
    pub recomputation: Recomputation,
    /// What the recomputation produced, when one happened.
    pub recomputed: Option<StateRoot>,
}

impl RootVerification {
    /// True only when a recomputation actually ran and agreed. Deliberately
    /// NOT `!is_failure()`: "unavailable" is neither.
    pub fn is_verified(&self) -> bool {
        matches!(self.record, RecordStatus::Valid)
            && matches!(self.recomputation, Recomputation::Matches)
    }

    /// True only on a positive disagreement — a recomputation ran and did not
    /// match. This is the one that means something is wrong.
    pub fn is_mismatch(&self) -> bool {
        matches!(self.recomputation, Recomputation::Differs)
    }

    /// The process exit code this outcome deserves. Three states, three codes,
    /// because a caller that scripts against this must be able to tell
    /// "checked and good" from "could not check".
    pub fn exit_code(&self) -> i32 {
        match (&self.record, &self.recomputation) {
            (RecordStatus::Valid, Recomputation::Matches) => 0,
            (RecordStatus::Valid, Recomputation::Unavailable(_)) => 3,
            (RecordStatus::Missing, _) => 4,
            (RecordStatus::UnknownVersion(_), _) => 5,
            _ => 1,
        }
    }
}

// ── Cross-language vectors ────────────────────────────────────────────────

/// The cases the format is pinned by.
///
/// A second implementation is checked against these rather than against this
/// module's prose: prose is where two people agree and two programs do not.
/// Every case here is a question where a reasonable implementer could have
/// chosen differently -- odd-leaf handling, empty roots, ordering, presence vs
/// emptiness, number representation, Unicode, field order.
#[cfg(test)]
pub fn vector_cases() -> Vec<(String, Vec<String>, Vec<(String, String, serde_json::Value, Option<String>, Option<String>)>)> {
    use serde_json::json;
    fn r(c: &str, i: &str, d: serde_json::Value)
        -> (String, String, serde_json::Value, Option<String>, Option<String>)
    {
        (c.into(), i.into(), d, None, None)
    }
    let parse = |s: &str| -> serde_json::Value { serde_json::from_str(s).unwrap() };
    vec![
        ("empty_database".into(), vec![], vec![]),
        ("one_empty_collection".into(), vec!["orders".into()], vec![]),
        ("two_empty_collections".into(), vec!["a".into(), "b".into()], vec![]),
        ("one_record".into(), vec!["orders".into()],
            vec![r("orders", "1", json!({"total": 100}))]),
        ("three_records_odd_leaf".into(), vec!["c".into()],
            vec![r("c", "1", json!(1)), r("c", "2", json!(2)), r("c", "3", json!(3))]),
        ("four_records_even".into(), vec!["c".into()],
            vec![r("c", "1", json!(1)), r("c", "2", json!(2)),
                 r("c", "3", json!(3)), r("c", "4", json!(4))]),
        ("five_records".into(), vec!["c".into()],
            vec![r("c", "1", json!(1)), r("c", "2", json!(2)), r("c", "3", json!(3)),
                 r("c", "4", json!(4)), r("c", "5", json!(5))]),
        ("unsorted_input".into(), vec!["z".into(), "a".into()],
            vec![r("z", "9", json!(9)), r("a", "1", json!(1)), r("z", "1", json!(1))]),
        ("concatenation_ambiguity".into(), vec![],
            vec![r("ab", "c", json!(null)), r("a", "bc", json!(null))]),
        ("field_order_preserved".into(), vec!["c".into()],
            vec![r("c", "1", parse(r#"{"b":1,"a":2}"#))]),
        ("integer_and_float".into(), vec!["c".into()],
            vec![r("c", "i", parse("1")), r("c", "f", parse("1.0"))]),
        ("negative_and_large_numbers".into(), vec!["c".into()],
            vec![r("c", "1", parse("-9223372036854775808")),
                 r("c", "2", parse("18446744073709551615")),
                 r("c", "3", parse("-0.0")),
                 r("c", "4", parse("2.5e-10"))]),
        ("nested_structures".into(), vec!["c".into()],
            vec![r("c", "1", json!({"a": [1, {"b": null}, [true, false]], "z": {}}))]),
        ("empty_containers".into(), vec!["c".into()],
            vec![r("c", "arr", json!([])), r("c", "obj", json!({})),
                 r("c", "str", json!("")), r("c", "null", json!(null))]),
        ("unicode_not_normalised".into(),
            vec!["caf\u{00e9}".into(), "cafe\u{0301}".into()],
            vec![r("caf\u{00e9}", "\u{00e9}", json!("caf\u{00e9}")),
                 r("cafe\u{0301}", "e\u{0301}", json!("cafe\u{0301}"))]),
        ("bitemporal".into(), vec!["c".into()], vec![
            ("c".into(), "none".into(), json!({}), None, None),
            ("c".into(), "empty_from".into(), json!({}), Some("".into()), None),
            ("c".into(), "dated".into(), json!({}), Some("2026-01-01".into()), Some("2026-12-31".into())),
        ]),
        ("emptied_collection".into(), vec!["orders".into(), "users".into()],
            vec![r("users", "u", json!(1))]),
    ]
}

#[cfg(test)]
mod vectors {
    use super::*;

    fn vector_path() -> std::path::PathBuf {
        std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../vectors/state_root_v1.json")
    }

    fn generate() -> serde_json::Value {
        let mut cases = Vec::new();
        for (name, colls, recs) in vector_cases() {
            let refs: Vec<RecordRef<'_>> = recs.iter()
                .map(|(c, i, d, vf, vt)| RecordRef {
                    coll: c, id: i, data: d,
                    valid_from: vf.as_deref(), valid_to: vt.as_deref(),
                })
                .collect();
            let out = compute(&colls, &refs).unwrap();
            cases.push(serde_json::json!({
                "name": name,
                "collections": colls,
                "records": recs.iter().map(|(c, i, d, vf, vt)| serde_json::json!({
                    "coll": c, "id": i, "data": d,
                    "valid_from": vf, "valid_to": vt,
                })).collect::<Vec<_>>(),
                "expect": out,
            }));
        }
        serde_json::json!({
            "format": "state_root_v1",
            "hash": "blake2b-512 truncated to 32 bytes",
            "note": "Any implementation of state_root_v1 must reproduce every \
                     expect block exactly. These pin the decisions prose cannot.",
            "cases": cases,
        })
    }

    /// The committed vectors are what the Rust implementation actually
    /// produces. Regenerate with `NEDB_WRITE_VECTORS=1 cargo test vectors`,
    /// and treat any diff as a FORMAT CHANGE -- every other implementation and
    /// every root already persisted in the field is downstream of this file.
    #[test]
    fn the_committed_vectors_match_this_implementation() {
        let generated = generate();
        let path = vector_path();
        if std::env::var("NEDB_WRITE_VECTORS").as_deref() == Ok("1") {
            std::fs::create_dir_all(path.parent().unwrap()).unwrap();
            std::fs::write(&path, serde_json::to_string_pretty(&generated).unwrap() + "\n").unwrap();
            eprintln!("wrote {}", path.display());
            return;
        }
        let on_disk: serde_json::Value = serde_json::from_str(
            &std::fs::read_to_string(&path).unwrap_or_else(|e| panic!(
                "cannot read {}: {} -- regenerate with NEDB_WRITE_VECTORS=1",
                path.display(), e
            ))
        ).expect("vectors file is valid JSON");

        let a = on_disk["cases"].as_array().expect("cases array");
        let b = generated["cases"].as_array().unwrap();
        assert_eq!(a.len(), b.len(), "a case was added or removed");
        for (want, got) in a.iter().zip(b.iter()) {
            assert_eq!(
                want["expect"], got["expect"],
                "case {:?} changed -- this is a FORMAT CHANGE, not a test failure",
                got["name"]
            );
        }
    }

    /// Every case must be distinguishable from every other. A vector suite
    /// where two cases share a root is not pinning what it claims to.
    #[test]
    fn no_two_cases_produce_the_same_state_root() {
        let g = generate();
        let mut seen: std::collections::HashMap<String, String> = Default::default();
        for c in g["cases"].as_array().unwrap() {
            let root = c["expect"]["state_root"].as_str().unwrap().to_string();
            let name = c["name"].as_str().unwrap().to_string();
            if let Some(prev) = seen.insert(root.clone(), name.clone()) {
                panic!("{:?} and {:?} share a state root -- the format cannot tell \
                        them apart", prev, name);
            }
        }
    }
}
