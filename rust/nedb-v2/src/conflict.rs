// SPDX-FileCopyrightText: 2026 INTERCHAINED LLC
// SPDX-License-Identifier: BUSL-1.1
// NEDB · © 2026 INTERCHAINED LLC × Eth-Interchained × Vex (Claude Opus 5)

//! Merge conflicts, as data.
//!
//! # Why a conflict is a struct and not a string
//!
//! A conflict is not an error message, it is a FACT about three values: what
//! the document was at the fork point, what the destination did to it, and what
//! the branch did to it. Rendering that into `"conflict on orders/42"` throws
//! away the only information a resolver needs and forces every caller —
//! operator, CLI, API client, future automatic resolver — to go back and dig
//! the three sides out again. So the three sides travel with the conflict.
//!
//! # Whose side is whose
//!
//! Consistently, everywhere in this engine:
//!
//!   - **ours** is the DESTINATION — the branch being merged INTO, as it is now
//!   - **theirs** is the BRANCH being merged
//!   - **base** is the common ancestor: the destination as of `base_seq`
//!
//! # Resolution is a write, never a repair
//!
//! [`resolve`] does not patch the conflicting versions and does not reach into
//! history. It writes the chosen value as an ordinary new write at the tip, and
//! records what was chosen and why in [`CONFLICTS`]. Both halves matter: the
//! write keeps the append-only contract, and the record is what lets a later
//! merge know that `TakeOurs` was a DECISION rather than an unresolved
//! difference — without it, choosing the destination's value would leave the
//! two sides still disagreeing and the same conflict would be reported forever.

use std::sync::atomic::Ordering;

use anyhow::Result;
use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::db::Db;

/// The audit log of resolved conflicts. Ids are a hash of (coll, id); the
/// version chain on each record is the history of decisions about that
/// document, newest last.
pub const CONFLICTS: &str = "_nedb.conflicts";

/// The shape of a disagreement.
///
/// Named from the destination's point of view first, so `ModifiedDeleted` reads
/// "ours modified, theirs deleted".
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ConflictKind {
    /// Both sides changed an existing document, to different values.
    BothModified,
    /// The destination changed it; the branch deleted it.
    ModifiedDeleted,
    /// The destination deleted it; the branch changed it.
    DeletedModified,
    /// It did not exist at the fork point and both sides created it, differently.
    BothAdded,
}

/// One document that two lines of history disagree about.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Conflict {
    /// Which branch this disagreement is WITH, and which generation of that
    /// name — see `branch::branch_key`.
    ///
    /// A conflict without it is not identified. Two branches can make the same
    /// claim about the same document for entirely different reasons, and a
    /// human who resolved one has decided nothing at all about the other. The
    /// key that settles a conflict is therefore
    /// `(branch, branch_created_seq, coll, id)`, never `(coll, id)`:
    ///
    /// ```text
    /// base orders/42 = 1     branch X = 7
    /// main           = 8     branch Y = 7
    /// ```
    ///
    /// Resolving X must leave Y unresolved. Keyed only by document, X's
    /// decision would silently authorise Y's merge because the two happen to
    /// agree about the value — which is a human decision about one line of
    /// history being applied to another without anyone being asked.
    pub branch: String,
    pub branch_created_seq: u64,
    pub coll: String,
    pub id: String,
    /// The common ancestor: the destination as of the branch's `base_seq`.
    pub base: Option<Value>,
    /// The destination, now.
    pub ours: Option<Value>,
    /// The branch.
    pub theirs: Option<Value>,
    pub kind: ConflictKind,
}

/// What to do about it.
#[derive(Debug, Clone, PartialEq)]
pub enum Resolution {
    TakeOurs,
    TakeTheirs,
    /// Neither side — a third value the resolver supplies. The common case for
    /// a genuine semantic merge (two edits to different fields of one record),
    /// which no automatic rule can produce correctly.
    TakeValue(Value),
}

/// Which way a conflict went, as recorded. Kept separate from [`Resolution`]
/// so the audit record serialises to something stable and readable rather than
/// to an enum shape that would change if `Resolution` grew a variant.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Choice {
    Ours,
    Theirs,
    Value,
}

/// The durable record that a conflict was settled, and how.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ResolutionRecord {
    pub branch: String,
    pub branch_created_seq: u64,
    pub coll: String,
    pub id: String,
    pub kind: ConflictKind,
    pub base: Option<Value>,
    pub ours: Option<Value>,
    pub theirs: Option<Value>,
    pub choice: Choice,
    /// The value actually written. `None` means the resolution was a delete.
    pub chosen: Option<Value>,
    /// The destination sequence the decision was recorded at.
    pub at_seq: u64,
}

/// Stable id for the (coll, id) slot in the audit log.
///
/// Length-prefixed before hashing for the same reason as in
/// [`crate::branch`]: collection names and document ids are arbitrary user
/// text, so any separator could occur inside either, and a key an attacker can
/// collide by choosing an id is not a key.
fn conflict_key(branch: &str, created_seq: u64, coll: &str, id: &str) -> String {
    use blake2::{Blake2b512, Digest};
    let mut h = Blake2b512::new();
    // Length-prefixed, so no combination of names can be spelled two ways.
    for part in [branch, coll, id] {
        h.update((part.len() as u64).to_be_bytes());
        h.update(part.as_bytes());
    }
    // The generation, so a reused branch name does not inherit the previous
    // branch's decisions. A name is a working label; this pair is the identity.
    h.update(created_seq.to_be_bytes());
    hex::encode(&h.finalize()[..32])
}

/// Settle a conflict by writing the chosen value, append-only, and recording
/// the decision.
///
/// The write goes through the public [`Db::put`] / [`Db::delete`] path, so a
/// resolved value is validated, registers its collection and enters the Merkle
/// chain exactly like any other write. There is no privileged path by which a
/// merge can install a value the engine would otherwise refuse.
pub fn resolve(db: &Db, c: &Conflict, r: Resolution) -> Result<()> {
    let (choice, chosen) = match r {
        Resolution::TakeOurs => (Choice::Ours, c.ours.clone()),
        Resolution::TakeTheirs => (Choice::Theirs, c.theirs.clone()),
        Resolution::TakeValue(v) => (Choice::Value, Some(v)),
    };

    match &chosen {
        Some(v) => {
            db.put(&c.coll, &c.id, v.clone(), vec![], None, None)?;
        }
        None => {
            // `delete` returns false when the document is already absent, which
            // is the normal outcome of resolving a ModifiedDeleted in favour of
            // the delete when the destination had already deleted it too. Not
            // an error: the requested end state is the state.
            db.delete(&c.coll, &c.id)?;
        }
    }

    let at_seq = db.seq.load(Ordering::SeqCst).saturating_sub(1);
    let rec = ResolutionRecord {
        branch: c.branch.clone(),
        branch_created_seq: c.branch_created_seq,
        coll: c.coll.clone(),
        id: c.id.clone(),
        kind: c.kind,
        base: c.base.clone(),
        ours: c.ours.clone(),
        theirs: c.theirs.clone(),
        choice,
        chosen,
        at_seq,
    };
    db.put_unchecked(
        CONFLICTS,
        &conflict_key(&c.branch, c.branch_created_seq, &c.coll, &c.id),
        serde_json::to_value(&rec)?,
        vec![], None, None,
    )?;
    Ok(())
}

/// The most recent decision recorded about a document, if any.
pub fn resolution_for(db: &Db, branch: &str, created_seq: u64, coll: &str, id: &str)
    -> Option<ResolutionRecord>
{
    let n = db.get(CONFLICTS, &conflict_key(branch, created_seq, coll, id))?;
    serde_json::from_value(n.data).ok()
}

/// Every conflict decision currently recorded, sorted by (coll, id).
///
/// Only the latest decision per document; the earlier ones are on each
/// record's `prev` chain and reachable with `AS OF`, the same as any other
/// superseded version in the engine.
pub fn resolutions(db: &Db) -> Vec<ResolutionRecord> {
    let mut out: Vec<ResolutionRecord> = db
        .list_ids_including_deleted(CONFLICTS)
        .into_iter()
        .filter_map(|k| db.get(CONFLICTS, &k))
        .filter_map(|n| serde_json::from_value::<ResolutionRecord>(n.data).ok())
        .collect();
    out.sort_by(|a, b| (&a.coll, &a.id).cmp(&(&b.coll, &b.id)));
    out
}

/// Has this exact disagreement already been decided?
///
/// Matched on the BRANCH side rather than on the whole triple. Once a decision
/// is recorded, `resolve` has written the chosen value to the destination, so
/// the destination side has moved by construction and comparing it would never
/// match. What must not have moved is the branch's claim: if the branch is
/// still saying the same thing it said when the decision was taken, the
/// decision still answers it. If the branch has since written something else,
/// that is a new disagreement and it gets reported.
pub(crate) fn is_settled(db: &Db, c: &Conflict) -> bool {
    match resolution_for(db, &c.branch, c.branch_created_seq, &c.coll, &c.id) {
        // Scoped to the branch GENERATION, then matched on the branch's claim.
        // The generation scoping is what stops one branch's decision settling
        // another's identical claim; the claim match is what makes a branch
        // that has since written something else a new disagreement rather than
        // a settled one.
        Some(rec) => rec.theirs == c.theirs,
        None => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    fn j(v: u64) -> Value { serde_json::json!({ "v": v }) }

    fn a_conflict() -> Conflict {
        Conflict {
            branch: "b".into(),
            branch_created_seq: 0,
            coll: "orders".into(),
            id: "42".into(),
            base: Some(j(1)),
            ours: Some(j(2)),
            theirs: Some(j(3)),
            kind: ConflictKind::BothModified,
        }
    }

    #[test]
    fn taking_theirs_writes_their_value_as_a_new_version() {
        let db = Db::in_memory();
        db.put("orders", "42", j(1), vec![], None, None).unwrap();
        let base_seq = db.seq.load(Ordering::SeqCst) - 1;
        db.put("orders", "42", j(2), vec![], None, None).unwrap();

        resolve(&db, &a_conflict(), Resolution::TakeTheirs).unwrap();
        assert_eq!(db.get("orders", "42").unwrap().data, j(3));
        // Append-only: the versions that disagreed are both still there.
        assert_eq!(db.get_as_of("orders", "42", base_seq).unwrap().data, j(1));
    }

    #[test]
    fn taking_ours_still_writes_a_version_rather_than_doing_nothing() {
        let db = Db::in_memory();
        db.put("orders", "42", j(1), vec![], None, None).unwrap();
        db.put("orders", "42", j(2), vec![], None, None).unwrap();
        let before = db.seq.load(Ordering::SeqCst);

        resolve(&db, &a_conflict(), Resolution::TakeOurs).unwrap();
        assert_eq!(db.get("orders", "42").unwrap().data, j(2));
        assert!(db.seq.load(Ordering::SeqCst) > before,
                "a decision is an event; it has to land in history to be auditable");
    }

    #[test]
    fn a_third_value_can_be_chosen() {
        let db = Db::in_memory();
        db.put("orders", "42", j(2), vec![], None, None).unwrap();
        let merged = serde_json::json!({ "v": 2, "note": "hand-merged" });
        resolve(&db, &a_conflict(), Resolution::TakeValue(merged.clone())).unwrap();
        assert_eq!(db.get("orders", "42").unwrap().data, merged);
    }

    #[test]
    fn resolving_toward_a_delete_removes_the_live_document() {
        let db = Db::in_memory();
        db.put("orders", "42", j(2), vec![], None, None).unwrap();
        let at = db.seq.load(Ordering::SeqCst) - 1;
        let c = Conflict { theirs: None, kind: ConflictKind::ModifiedDeleted, ..a_conflict() };
        resolve(&db, &c, Resolution::TakeTheirs).unwrap();
        assert!(db.get("orders", "42").is_none());
        assert_eq!(db.get_as_of("orders", "42", at).unwrap().data, j(2),
                   "a delete is a tombstone; the value before it is still readable");
    }

    #[test]
    fn resolving_a_delete_that_already_happened_is_not_an_error() {
        let db = Db::in_memory();
        db.put("orders", "42", j(2), vec![], None, None).unwrap();
        db.delete("orders", "42").unwrap();
        let c = Conflict { ours: None, theirs: None, kind: ConflictKind::ModifiedDeleted, ..a_conflict() };
        resolve(&db, &c, Resolution::TakeTheirs).unwrap();
        assert!(db.get("orders", "42").is_none());
        assert_eq!(resolutions(&db).len(), 1, "the decision is still recorded");
    }

    #[test]
    fn every_resolution_leaves_an_audit_record_with_all_three_sides() {
        let db = Db::in_memory();
        db.put("orders", "42", j(2), vec![], None, None).unwrap();
        resolve(&db, &a_conflict(), Resolution::TakeTheirs).unwrap();

        let all = resolutions(&db);
        assert_eq!(all.len(), 1);
        let r = &all[0];
        assert_eq!(r.coll, "orders");
        assert_eq!(r.id, "42");
        assert_eq!(r.kind, ConflictKind::BothModified);
        assert_eq!(r.base, Some(j(1)));
        assert_eq!(r.ours, Some(j(2)));
        assert_eq!(r.theirs, Some(j(3)));
        assert_eq!(r.choice, Choice::Theirs);
        assert_eq!(r.chosen, Some(j(3)));
        assert_eq!(resolution_for(&db, "b", 0, "orders", "42").as_ref(), Some(r));
    }

    #[test]
    fn a_second_decision_supersedes_the_first_without_erasing_it() {
        let db = Db::in_memory();
        db.put("orders", "42", j(2), vec![], None, None).unwrap();
        resolve(&db, &a_conflict(), Resolution::TakeOurs).unwrap();
        let after_first = db.seq.load(Ordering::SeqCst) - 1;
        resolve(&db, &a_conflict(), Resolution::TakeTheirs).unwrap();

        assert_eq!(resolution_for(&db, "b", 0, "orders", "42").unwrap().choice, Choice::Theirs);
        assert_eq!(resolutions(&db).len(), 1, "one live record per document");
        // The earlier decision is still readable through the version chain.
        let old = db.get_as_of(CONFLICTS, &conflict_key("b", 0, "orders", "42"), after_first).unwrap();
        let old: ResolutionRecord = serde_json::from_value(old.data).unwrap();
        assert_eq!(old.choice, Choice::Ours);
    }

    #[test]
    fn a_decision_settles_the_branch_claim_it_was_taken_against_and_no_other() {
        let db = Db::in_memory();
        db.put("orders", "42", j(2), vec![], None, None).unwrap();
        let c = a_conflict();
        assert!(!is_settled(&db, &c), "nothing is settled before it is decided");
        resolve(&db, &c, Resolution::TakeOurs).unwrap();
        assert!(is_settled(&db, &c));

        let moved_on = Conflict { theirs: Some(j(99)), ..c };
        assert!(!is_settled(&db, &moved_on),
                "a new claim from the branch is a new disagreement");
    }

    #[test]
    fn conflict_keys_cannot_be_forged_by_a_clever_id() {
        assert_ne!(conflict_key("br", 0, "a", "b|c"), conflict_key("br", 0, "a|b", "c"));
        assert_ne!(conflict_key("br", 0, "ab", "c"), conflict_key("br", 0, "a", "bc"));
        assert_eq!(conflict_key("br", 0, "a", "b"), conflict_key("br", 0, "a", "b"));
        // The branch name and generation are part of the key, not decoration.
        assert_ne!(conflict_key("x", 0, "a", "b"), conflict_key("y", 0, "a", "b"));
        assert_ne!(conflict_key("x", 0, "a", "b"), conflict_key("x", 1, "a", "b"));
        // And a name cannot be spelled into another branch's slot.
        assert_ne!(conflict_key("xa", 0, "b", "c"), conflict_key("x", 0, "ab", "c"));
    }

    #[test]
    fn resolution_works_on_disk_too() {
        let dir = tempdir().unwrap();
        let db = Db::open(dir.path(), None).unwrap();
        db.put("orders", "42", j(2), vec![], None, None).unwrap();
        resolve(&db, &a_conflict(), Resolution::TakeTheirs).unwrap();
        db.flush_all();
        assert_eq!(db.get("orders", "42").unwrap().data, j(3));
        assert_eq!(resolutions(&db).len(), 1);
    }
}

/// The two correctness holes the architecture review found in the first cut,
/// held shut.
#[cfg(test)]
mod scoped_to_the_branch_that_raised_it {
    use super::*;
    use crate::branch::{branch_put, create_branch, get_branch};
    use crate::merge;

    fn j(v: u64) -> Value { serde_json::json!({ "v": v }) }

    /// The reported case, exactly.
    ///
    /// ```text
    /// base orders/42 = 1     branch X = 7
    /// main           = 8     branch Y = 7
    /// ```
    ///
    /// Resolve X. Y must still be unresolved: nobody was asked about Y, and
    /// two branches agreeing about a value is not one of them agreeing to the
    /// other's merge.
    #[test]
    fn resolving_one_branch_does_not_settle_another_making_the_same_claim() {
        let db = Db::in_memory();
        db.put("orders", "42", j(1), vec![], None, None).unwrap();
        let base = db.seq.load(Ordering::SeqCst) - 1;

        create_branch(&db, "x", base).unwrap();
        create_branch(&db, "y", base).unwrap();
        branch_put(&db, "x", "orders", "42", j(7)).unwrap();
        branch_put(&db, "y", "orders", "42", j(7)).unwrap();
        db.put("orders", "42", j(8), vec![], None, None).unwrap();

        let px = merge::plan(&db, "x").unwrap();
        let py = merge::plan(&db, "y").unwrap();
        assert_eq!(px.conflicts.len(), 1, "X disagrees with the destination");
        assert_eq!(py.conflicts.len(), 1, "so does Y");

        resolve(&db, &px.conflicts[0], Resolution::TakeOurs).unwrap();

        assert!(is_settled(&db, &px.conflicts[0]), "X was decided");
        assert!(
            !is_settled(&db, &py.conflicts[0]),
            "NOBODY decided Y — a human decision about one line of history must \
             not implicitly authorise another"
        );
        assert_eq!(
            merge::plan(&db, "y").unwrap().conflicts.len(), 1,
            "and Y must still be planned as conflicted"
        );
    }

    /// A reused branch name does not inherit the previous branch's decisions.
    #[test]
    fn a_new_generation_of_a_name_starts_unresolved() {
        let db = Db::in_memory();
        db.put("orders", "42", j(1), vec![], None, None).unwrap();
        let base = db.seq.load(Ordering::SeqCst) - 1;

        create_branch(&db, "fix", base).unwrap();
        branch_put(&db, "fix", "orders", "42", j(7)).unwrap();
        db.put("orders", "42", j(8), vec![], None, None).unwrap();
        let first = merge::plan(&db, "fix").unwrap().conflicts.remove(0);
        resolve(&db, &first, Resolution::TakeOurs).unwrap();
        assert!(is_settled(&db, &first));
        crate::branch::abandon_branch(&db, "fix").unwrap();

        // Same label, new line of work.
        let base2 = db.seq.load(Ordering::SeqCst) - 1;
        create_branch(&db, "fix", base2).unwrap();
        branch_put(&db, "fix", "orders", "42", j(7)).unwrap();
        db.put("orders", "42", j(9), vec![], None, None).unwrap();

        let again = merge::plan(&db, "fix").unwrap();
        assert_eq!(again.conflicts.len(), 1);
        assert!(
            !is_settled(&db, &again.conflicts[0]),
            "a name is a working label; the decision belonged to the generation"
        );
        assert_ne!(
            get_branch(&db, "fix").unwrap().created_seq, first.branch_created_seq,
            "precondition: this really is a different generation"
        );
    }

    #[test]
    fn a_resolution_records_which_branch_it_was_taken_against() {
        let db = Db::in_memory();
        db.put("orders", "42", j(1), vec![], None, None).unwrap();
        let base = db.seq.load(Ordering::SeqCst) - 1;
        create_branch(&db, "x", base).unwrap();
        branch_put(&db, "x", "orders", "42", j(7)).unwrap();
        db.put("orders", "42", j(8), vec![], None, None).unwrap();

        let c = merge::plan(&db, "x").unwrap().conflicts.remove(0);
        resolve(&db, &c, Resolution::TakeTheirs).unwrap();

        let gen = get_branch(&db, "x").unwrap().created_seq;
        let rec = resolution_for(&db, "x", gen, "orders", "42")
            .expect("the decision is recorded under the branch that raised it");
        assert_eq!(rec.branch, "x");
        assert_eq!(rec.branch_created_seq, gen);
        // And not findable under a branch that never raised it.
        assert!(resolution_for(&db, "y", gen, "orders", "42").is_none());
    }
}

/// Merge replay must not produce causally anonymous nodes.
#[cfg(test)]
mod replay_carries_its_cause {
    use super::*;
    use crate::branch::{branch_put, create_branch};
    use crate::merge;

    fn j(v: u64) -> Value { serde_json::json!({ "v": v }) }

    #[test]
    fn a_replayed_write_points_back_at_the_branch_write_that_caused_it() {
        let db = Db::in_memory();
        db.put("orders", "a", j(1), vec![], None, None).unwrap();
        let base = db.seq.load(Ordering::SeqCst) - 1;
        create_branch(&db, "x", base).unwrap();
        let bw = branch_put(&db, "x", "orders", "a", j(2)).unwrap();
        assert!(!bw.source_hash.is_empty(), "the branch write is addressable");

        let plan = merge::plan(&db, "x").unwrap();
        assert!(plan.is_clean());
        assert_eq!(plan.changes.len(), 1);
        assert_eq!(plan.changes[0].source_hash, bw.source_hash,
                   "the plan carries the source identity through");

        merge::execute(&db, &plan).unwrap();

        let landed = db.get("orders", "a").expect("the replay landed");
        assert_eq!(landed.data, j(2));
        assert_eq!(
            landed.caused_by, vec![bw.source_hash.clone()],
            "the destination node names the branch write that caused it"
        );

        // And the edge is walkable, not just stored on the node.
        let traced = db.trace(&landed.hash, false, 10);
        assert!(
            traced.iter().any(|n| n.hash == bw.source_hash),
            "TRACE must reach the branch write from the merged node"
        );
    }

    #[test]
    fn every_replayed_change_carries_a_cause() {
        let db = Db::in_memory();
        for i in 0..4u64 {
            db.put("orders", &i.to_string(), j(1), vec![], None, None).unwrap();
        }
        let base = db.seq.load(Ordering::SeqCst) - 1;
        create_branch(&db, "x", base).unwrap();
        for i in 0..4u64 {
            branch_put(&db, "x", "orders", &i.to_string(), j(2)).unwrap();
        }
        let plan = merge::plan(&db, "x").unwrap();
        assert_eq!(plan.changes.len(), 4);
        assert!(
            plan.changes.iter().all(|c| !c.source_hash.is_empty()),
            "a plan with an anonymous change would replay an anonymous node"
        );
        merge::execute(&db, &plan).unwrap();
        for i in 0..4u64 {
            let n = db.get("orders", &i.to_string()).unwrap();
            assert_eq!(n.caused_by.len(), 1, "doc {} lost its causal edge", i);
        }
    }
}
