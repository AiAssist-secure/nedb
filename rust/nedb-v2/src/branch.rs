// SPDX-FileCopyrightText: 2026 INTERCHAINED LLC
// SPDX-License-Identifier: BUSL-1.1
// NEDB · © 2026 INTERCHAINED LLC × Eth-Interchained × Vex (Claude Opus 5)

//! Branching — a line of history that forked from a known sequence.
//!
//! # The shape that was chosen, and the one that was rejected
//!
//! A branch here is a CHILD STORE WITH READ-THROUGH: it has its own write
//! space, and a read that the branch has not written falls through to the
//! parent as the parent looked at the fork point.
//!
//! The rejected alternative was divergent refs inside one global sequence
//! space — two heads, one monotonic counter, order decided by whoever wrote
//! last. That cannot be made honest. A single monotonic sequence is a total
//! order, and two concurrent lines of history are not totally ordered. Encoding
//! them in one counter forces the engine to assert an ordering between writes
//! that have no ordering, and every `AS OF` afterwards reports that invention
//! as a fact. Better to have two sequence spaces and admit they are two.
//!
//! # What is actually built here (Phase 5A) versus what is coming (5B)
//!
//! [`crate::store::ObjectStore`] is a concrete struct wired directly into
//! [`crate::db::Db`], not a trait, so a genuinely separate child store is a
//! large surgery on the substrate. Until that lands, the child store is modelled
//! as an OVERLAY: branch writes go to the reserved [`BRANCH_WRITES`] collection
//! in the parent store, tagged with the branch they belong to, and
//! [`branch_get`] implements the read-through against `get_as_of(base_seq)`.
//!
//! The overlay is not a fake. The three-way merge, the conflict detection, the
//! pinning and the merge records all run against real recorded branch writes
//! with real isolation from the destination: a `branch_put` is invisible to
//! `db.get` on the user collection, and `db.put` on the destination is
//! invisible to `branch_get`. What the overlay does NOT give is an independent
//! sequence space — see the `PHASE 5B:` notes below for exactly what changes.
//!
//! # Pinning
//!
//! A live branch will one day need to reconcile against its fork point. If
//! compaction discards the history at `base_seq`, that reconciliation becomes
//! impossible and the branch becomes a promise the engine cannot keep. So a
//! live branch PINS its base, and `compact` refuses rather than stranding it.

use std::sync::atomic::Ordering;

use anyhow::{bail, Result};
use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::db::Db;
use crate::namespace;

/// The branch registry. One record per branch GENERATION (see [`branch_key`]).
pub const BRANCHES: &str = "_nedb.branches";

/// The branch write overlay — the child store, until the store actually splits.
///
/// PHASE 5B: this collection disappears. Branch writes go to the branch's own
/// `ObjectStore` with its own `AtomicU64` sequence counter, and the read-through
/// moves from [`branch_get`] down into the store layer.
pub const BRANCH_WRITES: &str = "_nedb.branch_writes";

/// Where a branch is in its life.
///
/// `Merged` carries the destination sequence the merge landed at, so a branch
/// record alone is enough to find the merge that consumed it — no scan of the
/// merge log required.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "state", rename_all = "snake_case")]
pub enum BranchStatus {
    Active,
    Merged { at_seq: u64 },
    Abandoned,
}

impl BranchStatus {
    /// A branch is LIVE while it can still be merged. Only a live branch pins.
    pub fn is_live(&self) -> bool {
        matches!(self, BranchStatus::Active)
    }
}

/// A forked line of history.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BranchRecord {
    pub name: String,
    /// The parent sequence this forked from. Reads fall through to the parent
    /// AS OF exactly this sequence — not to the parent's tip, which would make
    /// the branch's base drift under it.
    pub base_seq: u64,
    /// The parent sequence at which the fork was RECORDED. Distinct from
    /// `base_seq`: forking from the past is legal, so the two differ whenever a
    /// branch is cut retroactively.
    pub created_seq: u64,
    pub status: BranchStatus,
}

/// A single write made on a branch, as recorded in the overlay.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct BranchWrite {
    pub branch: String,
    /// Which generation of the name this belongs to — see [`branch_key`].
    pub created_seq: u64,
    pub coll: String,
    pub id: String,
    /// `None` is a branch-side delete, which is a different fact from
    /// "the branch never touched this id". Modelled as an explicit option
    /// rather than an absent record for exactly that reason.
    pub value: Option<Value>,
    /// The parent sequence the branch write consumed.
    ///
    /// PHASE 5B: this becomes the CHILD sequence, drawn from the branch's own
    /// counter. Today a branch write advances the parent's counter, which is
    /// the one place the overlay is visibly not a separate store.
    pub at_seq: u64,
}

// ── Identity ──────────────────────────────────────────────────────────────

/// The registry id for one generation of a branch name.
///
/// # Why a name is not the key
///
/// A branch name is a WORKING LABEL, not an identity, so reusing the name of a
/// merged or abandoned branch is ALLOWED. The argument:
///
/// A tag or a root is an identity because outside parties cite it — a release
/// note points at `v5.0.1` forever, so rebinding that name rewrites history
/// someone else already recorded. Nothing cites a branch name that way. The
/// things that cite a branch are its own merge record and its own registry
/// entry, and both of those capture `base_seq` and `created_seq`, which is the
/// tuple that actually identifies the line of history. `fix-pricing` merged
/// last March and `fix-pricing` cut this morning are two different branches
/// that happen to share a label, and refusing the second one buys nothing
/// except a naming ritual — operators would write `fix-pricing-2`, which is the
/// same reuse with worse ergonomics.
///
/// What reuse must NOT cost is auditability. If the registry were keyed by name
/// alone, the second generation's record would supersede the first in the id
/// index and the first branch would only be reachable through `AS OF`. So the
/// key is `{zero-padded created_seq}@{name}`: every generation is its own
/// durable record, chronologically ordered by id, and reuse adds history rather
/// than hiding it.
///
/// Reusing the name of an ACTIVE branch is still refused — that is not reuse,
/// that is two live branches answering to one label.
pub fn branch_key(name: &str, created_seq: u64) -> String {
    format!("{}@{}", namespace::seq_id(created_seq), name)
}

/// Is this a name a branch can durably have?
///
/// Same discipline as a collection name (refuse, never sanitise — a silently
/// rewritten name is a different branch than the one the caller asked for),
/// plus one extra rule: a purely numeric name is refused, because every
/// operator surface that takes a branch also takes a sequence number, and
/// `nedb branch 1234` must not be ambiguous about which one it means.
pub fn validate_branch_name(name: &str) -> Result<()> {
    namespace::validate_name(name)
        .map_err(|e| anyhow::anyhow!("branch name {:?} is unusable: {}", name, e))?;
    if namespace::is_reserved(name) {
        bail!(
            "branch name {:?} is reserved: everything under {:?} is engine-owned",
            name, namespace::RESERVED_PREFIX
        );
    }
    if !name.is_empty() && name.chars().all(|c| c.is_ascii_digit()) {
        bail!(
            "branch name {:?} is purely numeric — every surface that accepts a \
             branch also accepts a sequence number, and this name cannot be told \
             apart from one",
            name
        );
    }
    Ok(())
}

// ── Registry ──────────────────────────────────────────────────────────────

fn read_record(db: &Db, key: &str) -> Option<BranchRecord> {
    let n = db.get(BRANCHES, key)?;
    serde_json::from_value(n.data).ok()
}

fn write_record(db: &Db, rec: &BranchRecord) -> Result<()> {
    let key = branch_key(&rec.name, rec.created_seq);
    db.put_unchecked(BRANCHES, &key, serde_json::to_value(rec)?, vec![], None, None)?;
    Ok(())
}

/// Fork a branch from `base_seq`.
///
/// Refuses a base that does not exist yet, and a base below the history floor.
/// The second refusal is the one that matters: a branch whose fork point has
/// been pruned can never be three-way merged, because the BASE side of the
/// comparison is gone. Allowing the fork would only defer the failure to merge
/// time, when work has already been done on the branch.
pub fn create_branch(db: &Db, name: &str, base_seq: u64) -> Result<BranchRecord> {
    validate_branch_name(name)?;

    let next = db.seq.load(Ordering::SeqCst);
    if base_seq >= next {
        bail!(
            "cannot fork branch {:?} from sequence {}: the database has not reached \
             it (next sequence is {})",
            name, base_seq, next
        );
    }
    let floor = db.history_floor();
    if base_seq < floor {
        bail!(
            "cannot fork branch {:?} from sequence {}: history below {} has been \
             compacted away, so the merge base for this branch no longer exists and \
             it could never be reconciled",
            name, base_seq, floor
        );
    }

    if let Some(existing) = get_branch(db, name) {
        if existing.status.is_live() {
            bail!(
                "branch {:?} already exists and is active (forked from sequence {} at \
                 sequence {}); a name may be reused only after the branch holding it \
                 is merged or abandoned",
                name, existing.base_seq, existing.created_seq
            );
        }
    }

    let created_seq = db.seq.load(Ordering::SeqCst);
    let rec = BranchRecord {
        name: name.to_string(),
        base_seq,
        created_seq,
        status: BranchStatus::Active,
    };
    write_record(db, &rec)?;
    Ok(rec)
}

/// Every branch generation ever recorded, oldest first.
///
/// Ordered by id, and the id leads with a zero-padded `created_seq`, so
/// lexicographic order is chronological order.
pub fn list_all_branches(db: &Db) -> Vec<BranchRecord> {
    let mut ids = db.list_ids_including_deleted(BRANCHES);
    ids.sort();
    ids.into_iter().filter_map(|id| read_record(db, &id)).collect()
}

/// Every ACTIVE branch, sorted by name.
pub fn list_branches(db: &Db) -> Vec<BranchRecord> {
    let mut out: Vec<BranchRecord> = list_all_branches(db)
        .into_iter()
        .filter(|b| b.status.is_live())
        .collect();
    out.sort_by(|a, b| a.name.cmp(&b.name));
    out
}

/// The current branch answering to this name.
///
/// The newest generation, which — because creation refuses a live duplicate —
/// is the active one whenever any generation of the name is active.
pub fn get_branch(db: &Db, name: &str) -> Option<BranchRecord> {
    list_all_branches(db)
        .into_iter()
        .filter(|b| b.name == name)
        .next_back()
}

/// Retire a branch without merging it. Returns false when there was no live
/// branch by that name to abandon.
///
/// Append-only, like everything else: the record is superseded by a new version
/// carrying `Abandoned`, and the prior versions stay on the `prev` chain. The
/// branch's overlay writes are deliberately left in place — abandoning a line
/// of work is not a reason to destroy the record that it happened.
pub fn abandon_branch(db: &Db, name: &str) -> Result<bool> {
    let Some(mut rec) = get_branch(db, name) else { return Ok(false) };
    if !rec.status.is_live() {
        return Ok(false);
    }
    rec.status = BranchStatus::Abandoned;
    write_record(db, &rec)?;
    Ok(true)
}

/// Mark a branch merged at a destination sequence. Used by [`crate::merge`].
pub(crate) fn mark_merged(db: &Db, name: &str, at_seq: u64) -> Result<()> {
    let Some(mut rec) = get_branch(db, name) else {
        bail!("branch {:?} does not exist", name)
    };
    rec.status = BranchStatus::Merged { at_seq };
    write_record(db, &rec)
}

// ── Pinning ───────────────────────────────────────────────────────────────

/// Every live branch and the sequence it pins, sorted by name.
pub fn pinning_branches(db: &Db) -> Vec<(String, u64)> {
    list_branches(db).into_iter().map(|b| (b.name, b.base_seq)).collect()
}

/// The oldest sequence any LIVE branch still needs. `None` when nothing is
/// pinned, which is the only state in which history may be discarded freely.
///
/// Merged and abandoned branches do not pin: a merged branch has already been
/// replayed into the destination as new writes, and an abandoned one has said
/// in the registry that it will never be reconciled. Neither will ever look at
/// its base again.
pub fn minimum_pinned_seq(db: &Db) -> Option<u64> {
    list_branches(db).into_iter().map(|b| b.base_seq).min()
}

/// The message `compact` refuses with. Lives here so `db.rs` carries the policy
/// hook and this module carries the knowledge of what a branch is.
pub(crate) fn compaction_refusal(db: &Db, pinned: u64) -> String {
    let names: Vec<String> = pinning_branches(db)
        .into_iter()
        .map(|(n, s)| format!("{:?} (base seq {})", n, s))
        .collect();
    format!(
        "refusing to compact: {} live branch(es) pin history at or above sequence {} \
         — {}. Compaction is all-or-nothing to the tip, so proceeding would discard \
         the merge base these branches will need and leave them permanently \
         unmergeable. Merge or abandon them first.",
        names.len(), pinned, names.join(", ")
    )
}

// ── The child store, modelled as an overlay ───────────────────────────────

/// Stable, collision-free id for one (branch generation, coll, id) slot.
///
/// Hashed rather than concatenated because a collection name and a document id
/// are both arbitrary user text: any separator character could appear inside
/// either one, and a key that can be forged by choosing a clever id is not a
/// key. The components are length-prefixed before hashing so no two distinct
/// tuples can produce the same preimage, and they are also stored verbatim in
/// the record body so the tuple is recoverable without inverting the hash.
fn write_key(branch_key: &str, coll: &str, id: &str) -> String {
    use blake2::{Blake2b512, Digest};
    let mut h = Blake2b512::new();
    for part in [branch_key, coll, id] {
        h.update((part.len() as u64).to_be_bytes());
        h.update(part.as_bytes());
    }
    hex::encode(&h.finalize()[..32])
}

fn live_branch(db: &Db, name: &str) -> Result<BranchRecord> {
    let Some(rec) = get_branch(db, name) else {
        bail!("branch {:?} does not exist", name)
    };
    if !rec.status.is_live() {
        bail!(
            "branch {:?} is {:?}, not active — a branch that has been merged or \
             abandoned is closed history and cannot take new writes",
            name, rec.status
        );
    }
    Ok(rec)
}

fn record_branch_write(db: &Db, rec: &BranchRecord, coll: &str, id: &str, value: Option<Value>)
    -> Result<BranchWrite>
{
    // The same namespace policy the public `put` applies. A branch is not a
    // back door into the engine's own collections.
    namespace::validate_writable(coll)?;
    let at_seq = db.seq.load(Ordering::SeqCst);
    let w = BranchWrite {
        branch: rec.name.clone(),
        created_seq: rec.created_seq,
        coll: coll.to_string(),
        id: id.to_string(),
        value,
        at_seq,
    };
    let key = write_key(&branch_key(&rec.name, rec.created_seq), coll, id);
    db.put_unchecked(BRANCH_WRITES, &key, serde_json::to_value(&w)?, vec![], None, None)?;
    Ok(w)
}

/// Write a document on a branch. Invisible to the destination until merge.
///
/// PHASE 5B: becomes `child_store.put(coll, id, data)` against the branch's own
/// store and sequence counter. The signature and the isolation guarantee do not
/// change; what changes is that the write stops consuming a parent sequence.
pub fn branch_put(db: &Db, branch: &str, coll: &str, id: &str, data: Value) -> Result<BranchWrite> {
    let rec = live_branch(db, branch)?;
    record_branch_write(db, &rec, coll, id, Some(data))
}

/// Delete a document on a branch.
///
/// Recorded as an explicit `None`, not as the removal of the overlay entry:
/// "the branch deleted this" and "the branch never touched this" are different
/// facts and the merge treats them differently.
pub fn branch_delete(db: &Db, branch: &str, coll: &str, id: &str) -> Result<BranchWrite> {
    let rec = live_branch(db, branch)?;
    record_branch_write(db, &rec, coll, id, None)
}

/// Read a document as the branch sees it: the branch's own write if it has one,
/// otherwise the PARENT AS OF THE FORK POINT.
///
/// This is the read-through, and the fall-through target is `base_seq` rather
/// than the parent tip on purpose. A branch that saw the parent's later writes
/// would have no stable base to three-way merge against — its own "unchanged"
/// side would keep moving.
pub fn branch_get(db: &Db, branch: &str, coll: &str, id: &str) -> Option<Value> {
    let rec = get_branch(db, branch)?;
    let key = write_key(&branch_key(&rec.name, rec.created_seq), coll, id);
    if let Some(n) = db.get(BRANCH_WRITES, &key) {
        let w: BranchWrite = serde_json::from_value(n.data).ok()?;
        return w.value;
    }
    db.get_as_of(coll, id, rec.base_seq).map(|n| n.data)
}

/// Every write a branch has made, sorted by (coll, id) so a plan is
/// deterministic run to run.
///
/// PHASE 5B: becomes an enumeration of the child store's own contents rather
/// than a filtered scan of the shared overlay collection — which also removes
/// the current O(all branch writes) cost of listing one branch's changes.
pub fn branch_writes(db: &Db, branch: &str) -> Vec<BranchWrite> {
    let Some(rec) = get_branch(db, branch) else { return Vec::new() };
    let mut out: Vec<BranchWrite> = db
        .list_ids_including_deleted(BRANCH_WRITES)
        .into_iter()
        .filter_map(|k| db.get(BRANCH_WRITES, &k))
        .filter_map(|n| serde_json::from_value::<BranchWrite>(n.data).ok())
        .filter(|w| w.branch == rec.name && w.created_seq == rec.created_seq)
        .collect();
    out.sort_by(|a, b| (&a.coll, &a.id).cmp(&(&b.coll, &b.id)));
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    fn j(v: u64) -> Value { serde_json::json!({ "v": v }) }

    /// A database with `n` writes in it, so there are sequences to fork from.
    fn seeded(n: u64) -> Db {
        let db = Db::in_memory();
        for i in 0..n {
            db.put("orders", &i.to_string(), j(i), vec![], None, None).unwrap();
        }
        db
    }

    fn tip(db: &Db) -> u64 {
        db.seq.load(Ordering::SeqCst).saturating_sub(1)
    }

    #[test]
    fn create_get_list() {
        let db = seeded(3);
        let base = tip(&db);
        let made = create_branch(&db, "fix-pricing", base).unwrap();
        assert_eq!(made.name, "fix-pricing");
        assert_eq!(made.base_seq, base);
        assert_eq!(made.status, BranchStatus::Active);

        let got = get_branch(&db, "fix-pricing").expect("branch is readable back");
        assert_eq!(got, made);

        create_branch(&db, "audit", base).unwrap();
        let names: Vec<String> = list_branches(&db).into_iter().map(|b| b.name).collect();
        assert_eq!(names, vec!["audit".to_string(), "fix-pricing".to_string()],
                   "active branches come back sorted by name");
    }

    #[test]
    fn get_branch_is_none_for_a_name_never_used() {
        let db = seeded(2);
        assert!(get_branch(&db, "nope").is_none());
    }

    #[test]
    fn a_base_the_database_has_not_reached_is_refused() {
        let db = seeded(3);
        let next = db.seq.load(Ordering::SeqCst);
        let err = create_branch(&db, "future", next).unwrap_err().to_string();
        assert!(err.contains("has not reached"), "{}", err);
        assert!(create_branch(&db, "way-future", next + 1000).is_err());
        // The last assigned sequence IS reachable.
        create_branch(&db, "present", next - 1).unwrap();
    }

    #[test]
    fn forking_from_pruned_history_is_refused() {
        let db = seeded(4);
        let old = 1u64;
        // The floor is set directly rather than by compacting. Compaction only
        // raises it when it ACTUALLY pruned something, and the only substrate
        // that prunes is chosen by the process-global NEDB_DAG_V3 — which a
        // threaded test run cannot set without changing the substrate under
        // every other database opened at that instant.
        db.compact().expect("no branches yet, so compaction proceeds");
        db.set_history_floor(3).unwrap();
        let floor = db.history_floor();
        assert!(floor > old, "the database is in the pruned state past {}", old);

        let err = create_branch(&db, "archaeology", old).unwrap_err().to_string();
        assert!(err.contains("compacted away"), "{}", err);
        assert!(err.contains("never be reconciled"), "{}", err);

        // At the floor is fine — that history is still here.
        create_branch(&db, "from-the-floor", floor).unwrap();
    }

    #[test]
    fn unusable_names_are_refused_not_sanitised() {
        let db = seeded(2);
        let base = tip(&db);
        for bad in ["", "a/b", "..", "with\0nul", " lead", "trail ", "1234", "_nedb.x", "_nedb"] {
            assert!(
                create_branch(&db, bad, base).is_err(),
                "{:?} must not be usable as a branch name", bad
            );
        }
        let long = "x".repeat(256);
        assert!(create_branch(&db, &long, base).is_err(), "256 bytes is over the limit");
        // …and ordinary names survive, including ones with digits in them.
        for ok in ["fix-pricing", "v2-rollout", "release-2026", "Ünicode"] {
            create_branch(&db, ok, base).unwrap_or_else(|e| panic!("{:?} refused: {}", ok, e));
        }
    }

    #[test]
    fn a_live_name_cannot_be_taken_twice() {
        let db = seeded(3);
        let base = tip(&db);
        create_branch(&db, "dup", base).unwrap();
        let err = create_branch(&db, "dup", base).unwrap_err().to_string();
        assert!(err.contains("already exists and is active"), "{}", err);
    }

    /// A branch name is a working label, so a closed branch releases it — and
    /// reuse must ADD a record rather than overwrite the old one.
    #[test]
    fn a_closed_name_may_be_reused_without_losing_the_first_generation() {
        let db = seeded(3);
        let first = create_branch(&db, "recycle", 1).unwrap();
        assert!(abandon_branch(&db, "recycle").unwrap());

        db.put("orders", "x", j(99), vec![], None, None).unwrap();
        let second = create_branch(&db, "recycle", tip(&db)).unwrap();
        assert_ne!(first.created_seq, second.created_seq);

        let gens: Vec<BranchRecord> = list_all_branches(&db)
            .into_iter().filter(|b| b.name == "recycle").collect();
        assert_eq!(gens.len(), 2, "both generations stay durable and auditable");
        assert_eq!(gens[0].status, BranchStatus::Abandoned);
        assert_eq!(gens[1].status, BranchStatus::Active);
        assert_eq!(get_branch(&db, "recycle").unwrap(), second,
                   "the name resolves to the newest generation");
    }

    #[test]
    fn abandoning_is_idempotent_and_honest_about_it() {
        let db = seeded(3);
        create_branch(&db, "gone", 1).unwrap();
        assert!(abandon_branch(&db, "gone").unwrap(), "first abandon changes something");
        assert!(!abandon_branch(&db, "gone").unwrap(), "second one does not");
        assert!(!abandon_branch(&db, "never-existed").unwrap());
    }

    #[test]
    fn a_closed_branch_refuses_new_writes() {
        let db = seeded(3);
        create_branch(&db, "closed", 1).unwrap();
        abandon_branch(&db, "closed").unwrap();
        let err = branch_put(&db, "closed", "orders", "1", j(7)).unwrap_err().to_string();
        assert!(err.contains("not active"), "{}", err);
    }

    // ── Pinning ───────────────────────────────────────────────────────────

    #[test]
    fn nothing_pins_when_there_are_no_branches() {
        let db = seeded(3);
        assert_eq!(minimum_pinned_seq(&db), None);
    }

    #[test]
    fn one_branch_pins_its_own_base() {
        let db = seeded(5);
        create_branch(&db, "one", 2).unwrap();
        assert_eq!(minimum_pinned_seq(&db), Some(2));
    }

    #[test]
    fn several_branches_pin_the_oldest_base() {
        let db = seeded(9);
        create_branch(&db, "a", 5).unwrap();
        create_branch(&db, "b", 1).unwrap();
        create_branch(&db, "c", 7).unwrap();
        assert_eq!(minimum_pinned_seq(&db), Some(1));
    }

    #[test]
    fn abandoned_branches_do_not_pin() {
        let db = seeded(9);
        create_branch(&db, "old", 1).unwrap();
        create_branch(&db, "new", 6).unwrap();
        assert_eq!(minimum_pinned_seq(&db), Some(1));
        abandon_branch(&db, "old").unwrap();
        assert_eq!(minimum_pinned_seq(&db), Some(6),
                   "an abandoned branch will never reconcile, so it needs nothing");
        abandon_branch(&db, "new").unwrap();
        assert_eq!(minimum_pinned_seq(&db), None);
    }

    #[test]
    fn merged_branches_do_not_pin() {
        let db = seeded(9);
        create_branch(&db, "done", 2).unwrap();
        assert_eq!(minimum_pinned_seq(&db), Some(2));
        mark_merged(&db, "done", tip(&db)).unwrap();
        assert_eq!(minimum_pinned_seq(&db), None);
    }

    // ── Compaction interlock (the db.rs hook, tested from here too) ────────

    #[test]
    fn compaction_refuses_while_a_live_branch_pins_history() {
        let db = seeded(6);
        create_branch(&db, "keepme", 2).unwrap();
        let err = db.compact().unwrap_err().to_string();
        assert!(err.contains("refusing to compact"), "{}", err);
        assert!(err.contains("keepme"), "the error must name the branch: {}", err);
        assert!(err.contains("base seq 2"), "the error must name the pinned seq: {}", err);
        assert_eq!(db.history_floor(), 0, "a refused compaction must not move the floor");
    }

    #[test]
    fn compaction_proceeds_once_the_branch_is_abandoned() {
        let db = seeded(6);
        create_branch(&db, "keepme", 2).unwrap();
        assert!(db.compact().is_err());
        abandon_branch(&db, "keepme").unwrap();
        let stats = db.compact().expect("nothing pins any more");
        // The interlock is what this test is about: once nothing pins history,
        // compaction RUNS. Whether it then moves the floor depends on whether
        // it actually reclaimed anything, and on this substrate it does not —
        // `ObjectStore::compact` is a no-op outside the v3 segment store. A
        // floor that moved here would be the engine declaring history lost
        // that is demonstrably still present.
        assert_eq!(stats.dropped_objects, 0, "v2 compaction prunes nothing");
        assert_eq!(db.history_floor(), 0,
                   "and so it must not claim history was discarded");
    }

    #[test]
    fn the_compaction_interlock_holds_on_disk_too() {
        let dir = tempdir().unwrap();
        let db = Db::open(dir.path(), None).unwrap();
        for i in 0..4u64 {
            db.put("orders", &i.to_string(), j(i), vec![], None, None).unwrap();
        }
        create_branch(&db, "ondisk", 1).unwrap();
        assert!(db.compact().is_err(), "the refusal is a property of the engine, not of memory mode");
        abandon_branch(&db, "ondisk").unwrap();
        db.compact().unwrap();
    }

    // ── Read-through ──────────────────────────────────────────────────────

    #[test]
    fn a_branch_read_falls_through_to_the_parent_at_the_fork_point() {
        let db = seeded(0);
        db.put("orders", "a", j(1), vec![], None, None).unwrap();
        let base = tip(&db);
        create_branch(&db, "b", base).unwrap();
        assert_eq!(branch_get(&db, "b", "orders", "a"), Some(j(1)),
                   "untouched on the branch → the parent's value at the fork");
    }

    #[test]
    fn the_fall_through_is_pinned_to_the_fork_not_to_the_parent_tip() {
        let db = seeded(0);
        db.put("orders", "a", j(1), vec![], None, None).unwrap();
        let base = tip(&db);
        create_branch(&db, "b", base).unwrap();
        db.put("orders", "a", j(2), vec![], None, None).unwrap();
        assert_eq!(branch_get(&db, "b", "orders", "a"), Some(j(1)),
                   "a branch whose base drifts has nothing stable to merge against");
    }

    #[test]
    fn a_branch_write_is_invisible_to_the_destination_and_vice_versa() {
        let db = seeded(0);
        db.put("orders", "a", j(1), vec![], None, None).unwrap();
        create_branch(&db, "b", tip(&db)).unwrap();

        branch_put(&db, "b", "orders", "a", j(42)).unwrap();
        assert_eq!(branch_get(&db, "b", "orders", "a"), Some(j(42)));
        assert_eq!(db.get("orders", "a").unwrap().data, j(1),
                   "the destination must not see an unmerged branch write");

        db.put("orders", "a", j(7), vec![], None, None).unwrap();
        assert_eq!(branch_get(&db, "b", "orders", "a"), Some(j(42)),
                   "the branch must not see a destination write");
    }

    #[test]
    fn a_branch_delete_is_a_recorded_fact_not_an_absent_record() {
        let db = seeded(0);
        db.put("orders", "a", j(1), vec![], None, None).unwrap();
        create_branch(&db, "b", tip(&db)).unwrap();
        branch_delete(&db, "b", "orders", "a").unwrap();
        assert_eq!(branch_get(&db, "b", "orders", "a"), None);
        let ws = branch_writes(&db, "b");
        assert_eq!(ws.len(), 1);
        assert_eq!(ws[0].value, None);
        assert_eq!(ws[0].coll, "orders");
    }

    #[test]
    fn branch_writes_are_scoped_to_one_branch_generation() {
        let db = seeded(0);
        db.put("orders", "a", j(1), vec![], None, None).unwrap();
        let base = tip(&db);
        create_branch(&db, "x", base).unwrap();
        create_branch(&db, "y", base).unwrap();
        branch_put(&db, "x", "orders", "a", j(10)).unwrap();
        branch_put(&db, "y", "orders", "a", j(20)).unwrap();
        assert_eq!(branch_get(&db, "x", "orders", "a"), Some(j(10)));
        assert_eq!(branch_get(&db, "y", "orders", "a"), Some(j(20)));
        assert_eq!(branch_writes(&db, "x").len(), 1);
        assert_eq!(branch_writes(&db, "y").len(), 1);

        // …and a reused name does not inherit the previous generation's work.
        abandon_branch(&db, "x").unwrap();
        create_branch(&db, "x", base).unwrap();
        assert!(branch_writes(&db, "x").is_empty());
        assert_eq!(branch_get(&db, "x", "orders", "a"), Some(j(1)));
    }

    #[test]
    fn a_branch_cannot_write_to_a_reserved_collection() {
        let db = seeded(3);
        create_branch(&db, "sneaky", 1).unwrap();
        assert!(branch_put(&db, "sneaky", namespace::COLLECTIONS, "orders", j(1)).is_err());
        assert!(branch_put(&db, "sneaky", BRANCHES, "x", j(1)).is_err());
    }

    #[test]
    fn write_keys_cannot_be_forged_by_a_clever_id() {
        // "a" + "b|c" and "a|b" + "c" must not collide however they are joined.
        let k = branch_key("b", 1);
        assert_ne!(write_key(&k, "a", "b|c"), write_key(&k, "a|b", "c"));
        assert_ne!(write_key(&k, "ab", "c"), write_key(&k, "a", "bc"));
        assert_eq!(write_key(&k, "a", "b"), write_key(&k, "a", "b"), "…and it is stable");
    }
}
