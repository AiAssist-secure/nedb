// SPDX-FileCopyrightText: 2026 INTERCHAINED LLC
// SPDX-License-Identifier: BUSL-1.1
// NEDB · © 2026 INTERCHAINED LLC × Eth-Interchained × Vex (Claude Opus 5)

//! Merge — replaying a branch into a destination as NEW history.
//!
//! # A merge does not graft
//!
//! The tempting implementation is to take the branch's nodes and attach them
//! to the destination's chains. It is also wrong here, and for a structural
//! reason rather than a stylistic one: those nodes were written at the
//! branch's sequences, against the branch's predecessors, and hashed over that
//! content. Making them part of the destination means either rewriting them
//! (which changes their hashes, so they are not the nodes any more, and any
//! root that committed to them is now false) or admitting into the destination
//! a version chain whose sequences do not belong to the destination's sequence
//! space. Both break the constitutional rule that committed history is
//! immutable.
//!
//! So a merge COMPUTES what the branch changed and REPLAYS it as fresh writes
//! at the destination tip. The branch's own nodes stay exactly where they were,
//! still valid, still hashed over what they always were. The destination gains
//! new versions, with new sequences, on top of the ones it already had. Nobody
//! has to lie.
//!
//! The visible consequence — and the test that proves it — is that the
//! destination's pre-merge value remains readable with `AS OF`. A merge adds
//! history; it never replaces it.
//!
//! # Three-way, with the convergent case called out
//!
//! For each document the branch touched, three values are compared: BASE (the
//! destination as of the fork point), OURS (the destination now) and THEIRS
//! (the branch). Unchanged on one side means take the other. Changed on both
//! to different values is a conflict.
//!
//! Changed on both to the SAME value is NOT a conflict. Two people
//! independently making a document say the same thing have not disagreed about
//! anything — there is no decision for a human to make, and no information to
//! be lost by proceeding. Reporting it would be reporting the coincidence of
//! agreement as a failure, and in practice (a schema default applied on both
//! sides, a backfill run twice) it is the single most common way a merge gets
//! blocked for no reason. It contributes no replay either: the destination
//! already holds the value.

use std::sync::atomic::Ordering;

use anyhow::{bail, Result};
use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::branch::{self, BranchStatus};
use crate::conflict::{Conflict, ConflictKind};
use crate::db::Db;
use crate::namespace;

/// The merge log. Ids are the zero-padded destination sequence the merge
/// landed at, so lexicographic order is chronological order.
pub const MERGES: &str = "_nedb.merges";

/// What a replayed change does to the destination.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ChangeKind {
    /// No live document at the destination; the replay creates one.
    Add,
    /// A live document is superseded by a new version.
    Update,
    /// A live document is tombstoned.
    Delete,
}

/// One document the merge would write, and the evidence for writing it.
///
/// `base` rides along so a plan can be reviewed without re-deriving it: an
/// operator reading a plan wants to see what the branch changed FROM, not just
/// what it changed to.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct PlannedChange {
    pub coll: String,
    pub id: String,
    pub kind: ChangeKind,
    pub base: Option<Value>,
    /// The value to write. `None` is a delete.
    pub value: Option<Value>,
    /// The branch write that causes this replay.
    ///
    /// Carried through the plan so `execute` can point the destination node
    /// back at what caused it. A merge that replayed anonymously could not
    /// have the edge added later: nothing downstream would know which
    /// destination write came from which branch write, and the answer is not
    /// derivable from the values.
    ///
    /// PHASE 5B: becomes a qualified `crate::cause::Cause` once the branch
    /// lives in its own store and a bare hash stops being unambiguous.
    #[serde(default)]
    pub source_hash: String,
}

/// What a merge would do. Produced by [`plan`], consumed by [`execute`].
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct MergePlan {
    pub branch: String,
    pub base_seq: u64,
    /// The destination tip the plan was computed against. [`execute`] checks
    /// it, because a plan is a statement about a specific destination state.
    pub into_seq: u64,
    pub changes: Vec<PlannedChange>,
    pub conflicts: Vec<Conflict>,
}

impl MergePlan {
    /// Would this merge write anything at all?
    pub fn is_empty(&self) -> bool {
        self.changes.is_empty() && self.conflicts.is_empty()
    }
    /// Can it be executed as it stands?
    pub fn is_clean(&self) -> bool {
        self.conflicts.is_empty()
    }
}

/// The durable record that a merge happened.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct MergeRecord {
    pub branch: String,
    pub base_seq: u64,
    /// The last destination sequence the replay consumed. For an empty merge,
    /// the tip it landed on.
    pub merged_at_seq: u64,
    pub replayed: usize,
    /// The destination's state root immediately after the replay and BEFORE
    /// this record was written — for the same reason `_nedb.roots` is
    /// reserved: a record that counted as part of the state would change the
    /// state it describes. `None` when the root could not be computed.
    pub state_root: Option<String>,
}

/// Work out what merging `branch` would do. Writes nothing.
///
/// Purity is not a nicety here. A plan is what an operator reviews before
/// deciding, and a review step that mutates the thing under review changes the
/// answer to the question being asked. The test `plan_writes_nothing` holds
/// this to the sequence counter.
pub fn plan(db: &Db, branch_name: &str) -> Result<MergePlan> {
    let Some(rec) = branch::get_branch(db, branch_name) else {
        bail!("branch {:?} does not exist", branch_name)
    };
    match rec.status {
        BranchStatus::Active => {}
        BranchStatus::Merged { at_seq } => bail!(
            "branch {:?} was already merged at sequence {} — merging it again would \
             replay changes that are already in the destination's history",
            branch_name, at_seq
        ),
        BranchStatus::Abandoned => bail!(
            "branch {:?} was abandoned; revive it by cutting a new branch rather than \
             merging a line of work the registry records as given up",
            branch_name
        ),
    }

    let into_seq = db.seq.load(Ordering::SeqCst).saturating_sub(1);
    let mut changes = Vec::new();
    let mut conflicts = Vec::new();

    // Only documents the BRANCH touched can need anything. A document only the
    // destination changed is, by definition, unchanged on the branch side —
    // three-way says take the destination, and the destination already has it.
    // Enumerating those too would produce a plan full of no-op rewrites.
    for w in branch::branch_writes(db, branch_name) {
        let base = db.get_as_of(&w.coll, &w.id, rec.base_seq).map(|n| n.data);
        let ours = db.get(&w.coll, &w.id).map(|n| n.data);
        let theirs = w.value;

        if theirs == base {
            // The branch wrote, but wrote back what was already there. Nothing
            // changed on the branch side, so there is nothing to carry over.
            continue;
        }
        if ours == base {
            // Only the branch moved. Clean.
            let kind = if theirs.is_none() {
                ChangeKind::Delete
            } else if ours.is_none() {
                ChangeKind::Add
            } else {
                ChangeKind::Update
            };
            changes.push(PlannedChange {
                coll: w.coll, id: w.id, kind, base, value: theirs,
                source_hash: w.source_hash,
            });
            continue;
        }
        if ours == theirs {
            // Convergent edit — see the module docs. Both sides moved, to the
            // same place. Not a disagreement, and nothing to replay.
            continue;
        }

        let kind = match (&ours, &theirs, &base) {
            (None, Some(_), _) => ConflictKind::DeletedModified,
            (Some(_), None, _) => ConflictKind::ModifiedDeleted,
            (Some(_), Some(_), None) => ConflictKind::BothAdded,
            _ => ConflictKind::BothModified,
        };
        let c = Conflict {
            branch: rec.name.clone(),
            branch_created_seq: rec.created_seq,
            coll: w.coll, id: w.id, base, ours, theirs, kind,
        };
        // A recorded decision about this exact branch-side claim already
        // settled it, and `resolve` already wrote the outcome. Re-reporting it
        // would make `TakeOurs` impossible to ever act on.
        if crate::conflict::is_settled(db, &c) {
            continue;
        }
        conflicts.push(c);
    }

    changes.sort_by(|a, b| (&a.coll, &a.id).cmp(&(&b.coll, &b.id)));
    conflicts.sort_by(|a, b| (&a.coll, &a.id).cmp(&(&b.coll, &b.id)));

    Ok(MergePlan {
        branch: branch_name.to_string(),
        base_seq: rec.base_seq,
        into_seq,
        changes,
        conflicts,
    })
}

/// Carry out a plan: replay its changes into the destination, record the
/// merge, and close the branch.
///
/// Refuses on unresolved conflicts, refuses a stale plan, and refuses a branch
/// that is no longer active.
pub fn execute(db: &Db, plan: &MergePlan) -> Result<MergeRecord> {
    if !plan.conflicts.is_empty() {
        // A merge that writes one side of a disagreement without being told
        // which side is not a merge, it is a guess with a commit attached.
        let names: Vec<String> = plan.conflicts.iter()
            .map(|c| format!("{}/{}", c.coll, c.id))
            .collect();
        bail!(
            "refusing to merge branch {:?}: {} unresolved conflict(s) — {}. Settle \
             each one with conflict::resolve and re-plan; there is no side the engine \
             may pick on your behalf.",
            plan.branch, names.len(), names.join(", ")
        );
    }

    let Some(rec) = branch::get_branch(db, &plan.branch) else {
        bail!("branch {:?} does not exist", plan.branch)
    };
    if !rec.status.is_live() {
        bail!("branch {:?} is {:?}, not active", plan.branch, rec.status);
    }
    if rec.base_seq != plan.base_seq {
        bail!(
            "plan for branch {:?} was computed against base sequence {}, but the \
             branch forked at {}",
            plan.branch, plan.base_seq, rec.base_seq
        );
    }

    // A plan is a statement about a specific destination state. If the
    // destination has moved, the three-way comparison that produced this plan
    // was against a different OURS, and the conflicts it cleared may have
    // reappeared. Replaying anyway would silently overwrite whatever landed in
    // between — which is the precise failure the conflict check exists to
    // prevent, arriving through the back door.
    let tip = db.seq.load(Ordering::SeqCst).saturating_sub(1);
    if tip != plan.into_seq {
        bail!(
            "plan for branch {:?} is stale: it was computed against destination \
             sequence {}, which is now {}. Re-plan.",
            plan.branch, plan.into_seq, tip
        );
    }

    // Replay. Through the PUBLIC write path, so a merged write is validated,
    // registers its collection and joins the Merkle chain exactly as a
    // hand-written one does. A merge gets no privileges.
    let mut replayed = 0usize;
    for ch in &plan.changes {
        namespace::validate_writable(&ch.coll)?;
        match &ch.value {
            Some(v) => {
                // The replay points back at the branch write that caused it.
                // This is the edge the design is built on —
                //
                //     branch write  --caused_by-->  new destination write
                //
                // and it has to be written now: a destination node created
                // without it is causally anonymous, and no later pass can
                // recover which branch write produced it.
                let cause = if ch.source_hash.is_empty() {
                    // An overlay record written before source hashes were
                    // captured. Named rather than silently dropped, because a
                    // missing causal edge is exactly the thing this field
                    // exists to prevent and it should not pass unremarked.
                    eprintln!(
                        "nedb: merge replay of {}/{} has no source hash — the \
                         destination node will carry no causal edge to the \
                         branch write that caused it (overlay record predates \
                         source-hash capture)",
                        ch.coll, ch.id
                    );
                    vec![]
                } else {
                    vec![ch.source_hash.clone()]
                };
                db.put(&ch.coll, &ch.id, v.clone(), cause, None, None)?;
            }
            None => { db.delete(&ch.coll, &ch.id)?; }
        }
        replayed += 1;
    }

    let merged_at_seq = db.seq.load(Ordering::SeqCst).saturating_sub(1);
    let state_root = db.state_root().ok().map(|r| r.state_root);

    let record = MergeRecord {
        branch: plan.branch.clone(),
        base_seq: plan.base_seq,
        merged_at_seq,
        replayed,
        state_root,
    };
    db.put_unchecked(
        MERGES,
        &namespace::seq_id(merged_at_seq),
        serde_json::to_value(&record)?,
        vec![], None, None,
    )?;

    // Closing the branch is what releases its pin on history, so it has to
    // happen after the replay has actually landed — a branch marked merged
    // whose changes are not in the destination is the failure mode this whole
    // module exists to avoid.
    branch::mark_merged(db, &plan.branch, merged_at_seq)?;

    Ok(record)
}

/// A merge record by the sequence it landed at.
pub fn get_merge(db: &Db, merged_at_seq: u64) -> Option<MergeRecord> {
    let n = db.get(MERGES, &namespace::seq_id(merged_at_seq))?;
    serde_json::from_value(n.data).ok()
}

/// Every merge, oldest first.
pub fn list_merges(db: &Db) -> Vec<MergeRecord> {
    let mut ids = db.list_ids_including_deleted(MERGES);
    ids.sort();
    ids.into_iter()
        .filter_map(|id| db.get(MERGES, &id))
        .filter_map(|n| serde_json::from_value(n.data).ok())
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::branch::{abandon_branch, branch_delete, branch_put, create_branch};
    use crate::conflict::Resolution;
    use tempfile::tempdir;

    fn j(v: u64) -> Value { serde_json::json!({ "v": v }) }

    fn tip(db: &Db) -> u64 { db.seq.load(Ordering::SeqCst).saturating_sub(1) }

    /// A database with `orders/a = 1` and `orders/b = 1`, and a branch `b1`
    /// forked from that state.
    fn forked() -> Db {
        let db = Db::in_memory();
        db.put("orders", "a", j(1), vec![], None, None).unwrap();
        db.put("orders", "b", j(1), vec![], None, None).unwrap();
        create_branch(&db, "b1", tip(&db)).unwrap();
        db
    }

    /// Where `forked()` forked from.
    ///
    /// NOT `tip(&db)` after the fact: registering a branch is a real write in
    /// a reserved collection, so it consumes a sequence and the tip is one
    /// past the fork point the moment `create_branch` returns. Reading the tip
    /// afterwards and calling it the base is off by exactly one bookkeeping
    /// record — which is the same trap that engine registration set for four
    /// other tests in this crate.
    fn fork_point(db: &Db) -> u64 {
        branch::get_branch(db, "b1").expect("the fixture forked").base_seq
    }

    // ── Planning ──────────────────────────────────────────────────────────

    #[test]
    fn plan_writes_nothing() {
        let db = forked();
        branch_put(&db, "b1", "orders", "a", j(2)).unwrap();
        db.put("orders", "b", j(9), vec![], None, None).unwrap();

        let before = db.seq.load(Ordering::SeqCst);
        let p = plan(&db, "b1").unwrap();
        let after = db.seq.load(Ordering::SeqCst);
        assert_eq!(before, after, "planning moved the sequence counter — it wrote something");
        assert!(!p.changes.is_empty(), "…and it did produce a real plan");

        // Re-planning is also stable: same answer, still no writes.
        let p2 = plan(&db, "b1").unwrap();
        assert_eq!(db.seq.load(Ordering::SeqCst), after);
        assert_eq!(p, p2);
    }

    #[test]
    fn a_branch_with_no_writes_plans_nothing() {
        let db = forked();
        let p = plan(&db, "b1").unwrap();
        assert!(p.is_empty());
        assert!(p.is_clean());
        assert_eq!(p.base_seq, fork_point(&db));
        assert_eq!(p.base_seq, tip(&db) - 1,
                   "the branch record itself advanced the tip past the fork point");
    }

    #[test]
    fn both_sides_unchanged_is_no_change_even_when_the_branch_rewrote_the_value() {
        let db = forked();
        branch_put(&db, "b1", "orders", "a", j(1)).unwrap();   // same value back
        let p = plan(&db, "b1").unwrap();
        assert!(p.changes.is_empty(), "a write that changed nothing carries nothing over");
        assert!(p.conflicts.is_empty());
    }

    #[test]
    fn a_one_sided_branch_change_is_a_clean_fast_forward() {
        let db = forked();
        branch_put(&db, "b1", "orders", "a", j(2)).unwrap();
        let p = plan(&db, "b1").unwrap();
        assert!(p.is_clean());
        assert_eq!(p.changes.len(), 1);
        assert_eq!(p.changes[0].kind, ChangeKind::Update);
        assert_eq!(p.changes[0].base, Some(j(1)));
        assert_eq!(p.changes[0].value, Some(j(2)));
    }

    #[test]
    fn a_one_sided_destination_change_produces_no_plan_entry() {
        let db = forked();
        db.put("orders", "a", j(5), vec![], None, None).unwrap();
        let p = plan(&db, "b1").unwrap();
        assert!(p.is_empty(), "the destination already holds its own change");
    }

    #[test]
    fn a_branch_add_and_a_branch_delete_are_classified() {
        let db = forked();
        branch_put(&db, "b1", "orders", "new", j(1)).unwrap();
        branch_delete(&db, "b1", "orders", "b").unwrap();
        let p = plan(&db, "b1").unwrap();
        assert!(p.is_clean());
        let kinds: Vec<(String, ChangeKind)> = p.changes.iter()
            .map(|c| (c.id.clone(), c.kind)).collect();
        assert_eq!(kinds, vec![
            ("b".to_string(), ChangeKind::Delete),
            ("new".to_string(), ChangeKind::Add),
        ]);
    }

    #[test]
    fn a_convergent_identical_edit_is_not_a_conflict() {
        let db = forked();
        branch_put(&db, "b1", "orders", "a", j(7)).unwrap();
        db.put("orders", "a", j(7), vec![], None, None).unwrap();
        let p = plan(&db, "b1").unwrap();
        assert!(p.conflicts.is_empty(), "agreeing is not disagreeing");
        assert!(p.changes.is_empty(), "and there is nothing left to write");
    }

    #[test]
    fn a_divergent_edit_is_a_conflict_carrying_all_three_sides() {
        let db = forked();
        branch_put(&db, "b1", "orders", "a", j(7)).unwrap();
        db.put("orders", "a", j(8), vec![], None, None).unwrap();
        let p = plan(&db, "b1").unwrap();
        assert!(p.changes.is_empty(), "nothing may be replayed while a conflict stands");
        assert_eq!(p.conflicts.len(), 1);
        let c = &p.conflicts[0];
        assert_eq!(c.kind, ConflictKind::BothModified);
        assert_eq!(c.base, Some(j(1)));
        assert_eq!(c.ours, Some(j(8)));
        assert_eq!(c.theirs, Some(j(7)));
    }

    #[test]
    fn delete_against_modify_is_classified_from_the_destinations_point_of_view() {
        let db = forked();
        branch_delete(&db, "b1", "orders", "a").unwrap();
        db.put("orders", "a", j(8), vec![], None, None).unwrap();
        assert_eq!(plan(&db, "b1").unwrap().conflicts[0].kind, ConflictKind::ModifiedDeleted);

        let db = forked();
        branch_put(&db, "b1", "orders", "a", j(8)).unwrap();
        db.delete("orders", "a").unwrap();
        assert_eq!(plan(&db, "b1").unwrap().conflicts[0].kind, ConflictKind::DeletedModified);
    }

    #[test]
    fn two_creations_of_the_same_id_are_both_added() {
        let db = forked();
        branch_put(&db, "b1", "orders", "fresh", j(1)).unwrap();
        db.put("orders", "fresh", j(2), vec![], None, None).unwrap();
        let p = plan(&db, "b1").unwrap();
        assert_eq!(p.conflicts.len(), 1);
        assert_eq!(p.conflicts[0].kind, ConflictKind::BothAdded);
        assert_eq!(p.conflicts[0].base, None);
    }

    #[test]
    fn planning_a_closed_branch_is_refused() {
        let db = forked();
        abandon_branch(&db, "b1").unwrap();
        assert!(plan(&db, "b1").unwrap_err().to_string().contains("abandoned"));
        assert!(plan(&db, "never-existed").is_err());
    }

    // ── Execution ─────────────────────────────────────────────────────────

    #[test]
    fn execute_refuses_while_conflicts_stand() {
        let db = forked();
        branch_put(&db, "b1", "orders", "a", j(7)).unwrap();
        db.put("orders", "a", j(8), vec![], None, None).unwrap();
        let p = plan(&db, "b1").unwrap();
        let before = db.seq.load(Ordering::SeqCst);

        let err = execute(&db, &p).unwrap_err().to_string();
        assert!(err.contains("unresolved conflict"), "{}", err);
        assert!(err.contains("orders/a"), "the refusal must name the document: {}", err);
        assert_eq!(db.seq.load(Ordering::SeqCst), before, "a refused merge writes nothing");
        assert_eq!(db.get("orders", "a").unwrap().data, j(8), "…and changes nothing");
        assert!(crate::branch::get_branch(&db, "b1").unwrap().status.is_live(),
                "…and leaves the branch open");
    }

    #[test]
    fn execute_replays_a_clean_plan_and_records_it() {
        let db = forked();
        branch_put(&db, "b1", "orders", "a", j(2)).unwrap();
        branch_put(&db, "b1", "orders", "new", j(3)).unwrap();
        branch_delete(&db, "b1", "orders", "b").unwrap();

        let p = plan(&db, "b1").unwrap();
        assert_eq!(p.changes.len(), 3);
        let rec = execute(&db, &p).unwrap();

        assert_eq!(db.get("orders", "a").unwrap().data, j(2));
        assert_eq!(db.get("orders", "new").unwrap().data, j(3));
        assert!(db.get("orders", "b").is_none());

        assert_eq!(rec.branch, "b1");
        assert_eq!(rec.replayed, 3);
        assert_eq!(rec.base_seq, p.base_seq);
        assert!(rec.state_root.is_some());
        assert_eq!(get_merge(&db, rec.merged_at_seq).as_ref(), Some(&rec));
        assert_eq!(list_merges(&db), vec![rec.clone()]);
    }

    #[test]
    fn execute_flips_the_branch_to_merged_and_releases_its_pin() {
        let db = forked();
        branch_put(&db, "b1", "orders", "a", j(2)).unwrap();
        assert!(crate::branch::minimum_pinned_seq(&db).is_some());

        let p = plan(&db, "b1").unwrap();
        let rec = execute(&db, &p).unwrap();

        let b = crate::branch::get_branch(&db, "b1").unwrap();
        assert_eq!(b.status, BranchStatus::Merged { at_seq: rec.merged_at_seq });
        assert_eq!(crate::branch::minimum_pinned_seq(&db), None);
        db.compact().expect("a merged branch no longer blocks compaction");
    }

    /// The constitutional property: a merge ADDS history.
    #[test]
    fn merged_writes_are_new_history_and_the_base_version_survives() {
        let db = forked();
        let base = tip(&db);
        branch_put(&db, "b1", "orders", "a", j(2)).unwrap();
        let p = plan(&db, "b1").unwrap();
        execute(&db, &p).unwrap();

        assert_eq!(db.get("orders", "a").unwrap().data, j(2), "the merge landed");
        assert_eq!(db.get_as_of("orders", "a", base).unwrap().data, j(1),
                   "the pre-merge value is still readable at the fork point");

        // …and the replayed node is a NEW version at a NEW sequence, not the
        // branch's node grafted in.
        let now = db.get("orders", "a").unwrap();
        assert!(now.seq > base, "the replayed write has a destination sequence");
        assert!(now.prev.is_some(), "it is a continuation of the destination's chain");
    }

    #[test]
    fn a_deleted_document_is_still_readable_before_the_merge_that_removed_it() {
        let db = forked();
        let base = tip(&db);
        branch_delete(&db, "b1", "orders", "b").unwrap();
        let p = plan(&db, "b1").unwrap();
        execute(&db, &p).unwrap();
        assert!(db.get("orders", "b").is_none());
        assert_eq!(db.get_as_of("orders", "b", base).unwrap().data, j(1));
    }

    #[test]
    fn an_empty_merge_is_allowed_and_still_closes_the_branch() {
        let db = forked();
        let p = plan(&db, "b1").unwrap();
        let rec = execute(&db, &p).unwrap();
        assert_eq!(rec.replayed, 0);
        assert!(matches!(crate::branch::get_branch(&db, "b1").unwrap().status,
                         BranchStatus::Merged { .. }));
    }

    #[test]
    fn a_branch_cannot_be_merged_twice() {
        let db = forked();
        branch_put(&db, "b1", "orders", "a", j(2)).unwrap();
        let p = plan(&db, "b1").unwrap();
        execute(&db, &p).unwrap();
        assert!(execute(&db, &p).is_err(), "the branch is closed");
        assert!(plan(&db, "b1").unwrap_err().to_string().contains("already merged"));
    }

    #[test]
    fn a_stale_plan_is_refused_rather_than_silently_overwriting() {
        let db = forked();
        branch_put(&db, "b1", "orders", "a", j(2)).unwrap();
        let p = plan(&db, "b1").unwrap();
        // Someone else writes to the destination between plan and execute.
        db.put("orders", "a", j(99), vec![], None, None).unwrap();

        let err = execute(&db, &p).unwrap_err().to_string();
        assert!(err.contains("stale"), "{}", err);
        assert_eq!(db.get("orders", "a").unwrap().data, j(99), "their write survived");

        // Re-planning surfaces the disagreement the stale plan would have hidden.
        let p2 = plan(&db, "b1").unwrap();
        assert_eq!(p2.conflicts.len(), 1);
    }

    // ── Conflict → resolution → merge, end to end ─────────────────────────

    #[test]
    fn resolving_toward_the_branch_clears_the_conflict_and_the_merge_proceeds() {
        let db = forked();
        branch_put(&db, "b1", "orders", "a", j(7)).unwrap();
        db.put("orders", "a", j(8), vec![], None, None).unwrap();

        let p = plan(&db, "b1").unwrap();
        assert_eq!(p.conflicts.len(), 1);
        crate::conflict::resolve(&db, &p.conflicts[0], Resolution::TakeTheirs).unwrap();

        let p2 = plan(&db, "b1").unwrap();
        assert!(p2.is_clean(), "the decision settled it");
        execute(&db, &p2).unwrap();
        assert_eq!(db.get("orders", "a").unwrap().data, j(7));
        assert_eq!(crate::conflict::resolutions(&db).len(), 1, "and it is auditable");
    }

    /// The case a naive implementation gets wrong: keeping the destination's
    /// value leaves the two sides still different, so without the recorded
    /// decision the same conflict would be reported forever.
    #[test]
    fn resolving_toward_the_destination_also_clears_the_conflict() {
        let db = forked();
        branch_put(&db, "b1", "orders", "a", j(7)).unwrap();
        db.put("orders", "a", j(8), vec![], None, None).unwrap();

        let p = plan(&db, "b1").unwrap();
        crate::conflict::resolve(&db, &p.conflicts[0], Resolution::TakeOurs).unwrap();

        let p2 = plan(&db, "b1").unwrap();
        assert!(p2.is_clean(), "a decision to keep ours is still a decision");
        execute(&db, &p2).unwrap();
        assert_eq!(db.get("orders", "a").unwrap().data, j(8));
    }

    #[test]
    fn a_hand_merged_third_value_settles_it_too() {
        let db = forked();
        branch_put(&db, "b1", "orders", "a", j(7)).unwrap();
        db.put("orders", "a", j(8), vec![], None, None).unwrap();
        let p = plan(&db, "b1").unwrap();
        let both = serde_json::json!({ "v": 15, "note": "summed by hand" });
        crate::conflict::resolve(&db, &p.conflicts[0], Resolution::TakeValue(both.clone())).unwrap();

        let p2 = plan(&db, "b1").unwrap();
        assert!(p2.is_clean());
        execute(&db, &p2).unwrap();
        assert_eq!(db.get("orders", "a").unwrap().data, both);
    }

    #[test]
    fn two_branches_from_one_fork_merge_independently() {
        let db = Db::in_memory();
        db.put("orders", "a", j(1), vec![], None, None).unwrap();
        db.put("orders", "b", j(1), vec![], None, None).unwrap();
        let base = tip(&db);
        create_branch(&db, "x", base).unwrap();
        create_branch(&db, "y", base).unwrap();
        branch_put(&db, "x", "orders", "a", j(2)).unwrap();
        branch_put(&db, "y", "orders", "b", j(2)).unwrap();

        let px = plan(&db, "x").unwrap();
        execute(&db, &px).unwrap();
        // y's plan must be recomputed against the moved destination.
        let py = plan(&db, "y").unwrap();
        assert!(py.is_clean(), "disjoint documents do not conflict");
        execute(&db, &py).unwrap();

        assert_eq!(db.get("orders", "a").unwrap().data, j(2));
        assert_eq!(db.get("orders", "b").unwrap().data, j(2));
        assert_eq!(list_merges(&db).len(), 2);
        assert_eq!(crate::branch::minimum_pinned_seq(&db), None);
    }

    #[test]
    fn a_merge_cannot_reach_a_reserved_collection() {
        let db = forked();
        // The overlay refuses it at write time, which is the real gate…
        assert!(branch_put(&db, "b1", namespace::ROOTS, "x", j(1)).is_err());
        // …and execute re-checks, so a hand-built plan cannot smuggle one in.
        let bad = MergePlan {
            branch: "b1".into(),
            base_seq: crate::branch::get_branch(&db, "b1").unwrap().base_seq,
            into_seq: tip(&db),
            changes: vec![PlannedChange {
                coll: namespace::ROOTS.into(), id: "x".into(),
                kind: ChangeKind::Add, base: None, value: Some(j(1)),
                source_hash: String::new(),
            }],
            conflicts: vec![],
        };
        assert!(execute(&db, &bad).is_err());
    }

    #[test]
    fn the_whole_cycle_works_on_disk() {
        let dir = tempdir().unwrap();
        let db = Db::open(dir.path(), None).unwrap();
        db.put("orders", "a", j(1), vec![], None, None).unwrap();
        create_branch(&db, "d1", tip(&db)).unwrap();
        branch_put(&db, "d1", "orders", "a", j(2)).unwrap();
        let p = plan(&db, "d1").unwrap();
        let rec = execute(&db, &p).unwrap();
        db.flush_all();
        assert_eq!(db.get("orders", "a").unwrap().data, j(2));
        assert_eq!(get_merge(&db, rec.merged_at_seq).unwrap().replayed, 1);
    }
}
