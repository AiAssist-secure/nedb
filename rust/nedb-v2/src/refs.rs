// SPDX-FileCopyrightText: 2026 INTERCHAINED LLC
// SPDX-License-Identifier: BUSL-1.1
// NEDB · © 2026 INTERCHAINED LLC × Eth-Interchained × Vex (Claude Opus 5)

//! Named pointers into history: mutable **refs** and immutable **tags**.
//!
//! ```text
//! _nedb.refs   name -> seq     may move       (a branch head)
//! _nedb.tags   name -> seq     never moves    (a release)
//! ```
//!
//! # Why two kinds and not one with a flag
//!
//! Both are "a name pointing at a sequence", and it is tempting to make one
//! type with `immutable: bool`. The reason they are two collections is that
//! the guarantees are what the caller is buying. `set_ref` is allowed to
//! surprise you; `create_tag` is not. Keeping them apart means an operation on
//! a tag cannot be reached by accident from ref code, and `list_tags` cannot
//! ever return something mutable.
//!
//! # What immutability actually costs
//!
//! A tag whose target can change is not a tag, it is a ref with good manners:
//! a build that recorded "built from v1.0" would no longer be reproducible,
//! and nothing in the record would say it had moved. So re-pointing a tag is
//! refused, and — the sharper rule — a tag NAME IS NOT REUSABLE AFTER DELETION.
//!
//! Deletion has to exist (a tag published by mistake must be retractable), but
//! if `v1.0` could be deleted and recreated at a different sequence, then
//! "built from v1.0" is temporally ambiguous again and nothing has been
//! gained — the mutation just takes two commands instead of one. So a delete
//! leaves an AUDITED TOMBSTONE: the record stays, carrying the name, the
//! original target, and `deleted: true`. That tombstone is both the audit
//! trail and the enforcement mechanism, which is deliberate — there is no way
//! to lose the ban without also losing the evidence.
//!
//! Refs are the deliberate contrast: they move, they can be deleted, and a
//! deleted ref name can be reused. The `prev` chain on the underlying document
//! gives every move a walkable history for free.
//!
//! # Reserved, therefore not part of state
//!
//! Both collections live under `_nedb.`, and they are written with
//! `put_unchecked`, which does not register them in the collection registry.
//! So they are invisible to [`crate::db::Db::state_root`]. That is required,
//! not incidental: a tag records a state root, and if creating one changed the
//! state root it would invalidate what it just recorded.

use std::sync::atomic::Ordering;

use anyhow::{bail, Result};

use crate::db::Db;

/// Mutable named pointers. Ids are ref names.
pub const REFS: &str = "_nedb.refs";

/// Immutable named pointers, including tombstones for deleted ones. Ids are
/// tag names; a name present here is spent forever.
pub const TAGS: &str = "_nedb.tags";

// ── Records ───────────────────────────────────────────────────────────────

/// An immutable pointer at a sequence.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct TagRecord {
    pub name: String,
    /// The sequence this tag names. Fixed at creation, for all time.
    pub at_seq: u64,
    /// The `state_root` hex at `at_seq`, when a root was already persisted
    /// there. `None` means no root existed — NOT that the state had none.
    /// See [`create_tag`] for why one is not computed on the spot.
    pub state_root: Option<String>,
    /// The sequence at which the tag itself was created. Distinct from
    /// `at_seq`: a tag can be applied to the past.
    pub created_seq: u64,
    /// A tombstone. The record is retained precisely so this can be true.
    pub deleted: bool,
    pub message: Option<String>,
}

/// A mutable pointer at a sequence.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct RefRecord {
    pub name: String,
    pub at_seq: u64,
    /// The sequence at which the ref last moved.
    pub updated_seq: u64,
}

/// Internal shape of a ref document. `deleted` is not on [`RefRecord`] because
/// a deleted ref is simply absent to every reader — unlike a tag, nothing
/// downstream depends on knowing the name was once used.
#[derive(serde::Serialize, serde::Deserialize)]
struct StoredRef {
    name: String,
    at_seq: u64,
    updated_seq: u64,
    #[serde(default)]
    deleted: bool,
}

// ── Name validation ───────────────────────────────────────────────────────

/// Is this a name a ref or tag can HAVE?
///
/// Deliberately separate from [`crate::namespace::validate_name`]: a
/// collection name becomes a directory, a ref name becomes a CLI argument, and
/// the failure modes do not overlap.
///
/// Every rule here refuses rather than sanitises. A name silently rewritten is
/// a different pointer than the one the caller asked for, and they would find
/// out from the wrong build artifact rather than from an error.
pub fn validate_ref_name(name: &str) -> Result<()> {
    if name.is_empty() {
        bail!("ref/tag name is empty");
    }
    if name.len() > 255 {
        bail!("ref/tag name is {} bytes; the limit is 255", name.len());
    }
    if name.contains('/') || name.contains('\\') {
        bail!(
            "ref/tag name {:?} contains a path separator — the name is an id in a \
             reserved collection, and a separator makes it look like a namespace \
             that does not exist",
            name
        );
    }
    if name.contains('\0') {
        bail!("ref/tag name {:?} contains a NUL byte", name);
    }
    if name != name.trim() {
        bail!(
            "ref/tag name {:?} has leading or trailing whitespace — refused rather \
             than trimmed, because the name you get back must be the name you gave",
            name
        );
    }
    // The non-obvious one. Anywhere a revision is accepted — `nedb tag inspect
    // <rev>`, `AS OF <rev>` — the argument is either a sequence number or a
    // name, and the resolver has to be TOTAL: exactly one meaning per input,
    // decided without context. A tag literally called "42" makes `42` mean two
    // things, and any tie-break (prefer the number? prefer the name?) is a
    // silent wrong answer for whoever meant the other one. Refusing the name is
    // the only resolution that never guesses.
    if name.bytes().all(|b| b.is_ascii_digit()) {
        bail!(
            "ref/tag name {:?} is purely numeric — it would be ambiguous with a \
             sequence number wherever a revision is accepted, and an argument \
             resolver must not guess which was meant",
            name
        );
    }
    Ok(())
}

// ── Tags ──────────────────────────────────────────────────────────────────

/// Read the stored record for a name, tombstones included.
///
/// The single door to tag existence. Every rule in this module — no re-point,
/// no reuse after delete, idempotent re-create — is decided from what this
/// returns, so there is exactly one place the ban could be lost.
fn read_tag_raw(db: &Db, name: &str) -> Option<TagRecord> {
    let n = db.get(TAGS, name)?;
    serde_json::from_value(n.data).ok()
}

fn write_tag(db: &Db, rec: &TagRecord) -> Result<()> {
    db.put_unchecked(TAGS, &rec.name, serde_json::to_value(rec)?, vec![], None, None)?;
    Ok(())
}

/// Create an immutable tag at `at_seq`.
///
/// Refuses, naming itself each time:
///
///   - an invalid name (see [`validate_ref_name`]);
///   - a sequence that does not exist yet — a tag pointing into the future
///     names nothing, and would silently become valid later, naming whatever
///     happened to land there;
///   - a name already tagged at a DIFFERENT sequence, reporting the current
///     target so the caller can see what they collided with;
///   - a name that was tagged and then deleted, reporting what it pointed at.
///
/// Re-creating the same name at the SAME sequence is idempotent success. The
/// assertion the caller is making is already true, and tooling retries; an
/// error there would be noise that teaches people to ignore this error class.
///
/// `state_root` is captured from [`Db::get_root`] when a root is already
/// persisted at `at_seq`, and left `None` otherwise. It is NOT computed here:
/// per `create_root_at`, a historical root is O(live state) plus a
/// version-chain walk per document, and hiding that behind `tag` is how an
/// operator learns the cost by waiting. `None` means "no root was taken here",
/// and the caller can take one explicitly and re-tag at a new name.
pub fn create_tag(db: &Db, name: &str, at_seq: u64, message: Option<&str>) -> Result<TagRecord> {
    validate_ref_name(name)?;

    // `seq` is the NEXT sequence to be assigned, so the tip is one below it.
    let next_seq = db.seq.load(Ordering::SeqCst);
    if at_seq >= next_seq {
        bail!(
            "cannot tag {:?} at sequence {}: the database is at sequence {} — a tag \
             pointing into the future names no state, and would start naming \
             whatever is written there later",
            name,
            at_seq,
            next_seq.saturating_sub(1)
        );
    }

    if let Some(existing) = read_tag_raw(db, name) {
        if existing.deleted {
            bail!(
                "tag {:?} was previously deleted (it pointed at sequence {}) and its \
                 name cannot be reused: a name that could be recreated at a different \
                 target makes every past reference to it ambiguous — which {:?} did \
                 that build use? Pick a new name.",
                name,
                existing.at_seq,
                name
            );
        }
        if existing.at_seq != at_seq {
            bail!(
                "tag {:?} already points at sequence {} and a tag target is \
                 immutable; refusing to move it to {}. Use a ref if you want a \
                 pointer that moves.",
                name,
                existing.at_seq,
                at_seq
            );
        }
        // Same name, same target: the assertion already holds. Idempotent.
        return Ok(existing);
    }

    let state_root = db.get_root(at_seq).map(|r| r.root.state_root);
    let rec = TagRecord {
        name: name.to_string(),
        at_seq,
        state_root,
        created_seq: next_seq,
        deleted: false,
        message: message.map(|s| s.to_string()),
    };
    write_tag(db, &rec)?;
    Ok(rec)
}

/// A live tag by name. `None` for a name that was never tagged AND for one
/// whose tag was deleted — both mean "no tag here now". Use
/// [`get_tag_including_deleted`] to tell the two apart.
pub fn get_tag(db: &Db, name: &str) -> Option<TagRecord> {
    read_tag_raw(db, name).filter(|t| !t.deleted)
}

/// A tag by name, tombstones included. This is what answers "what did `v1.0`
/// point at?" for a build that referenced it before it was retracted.
pub fn get_tag_including_deleted(db: &Db, name: &str) -> Option<TagRecord> {
    read_tag_raw(db, name)
}

fn all_tags(db: &Db) -> Vec<TagRecord> {
    let mut out: Vec<TagRecord> = db
        .id_index
        .list_ids(TAGS)
        .into_iter()
        .filter_map(|id| read_tag_raw(db, &id))
        .collect();
    out.sort_by(|a, b| a.name.as_bytes().cmp(b.name.as_bytes()));
    out
}

/// Live tags, sorted by name (raw UTF-8 bytes, the one ordering everything
/// agrees on).
pub fn list_tags(db: &Db) -> Vec<TagRecord> {
    all_tags(db).into_iter().filter(|t| !t.deleted).collect()
}

/// Every tag ever created, tombstones included, sorted by name. The audit view.
pub fn list_tags_including_deleted(db: &Db) -> Vec<TagRecord> {
    all_tags(db)
}

/// Retract a tag, leaving an audited tombstone.
///
/// The record is REWRITTEN with `deleted: true`, not removed: it keeps the
/// original `at_seq` so history stays answerable, and it is what makes the
/// name permanently unusable. Returns `false` when there was no live tag to
/// delete (never created, or already deleted) — that is not an error, but it
/// is also not silence: the boolean is the answer.
pub fn delete_tag(db: &Db, name: &str) -> Result<bool> {
    validate_ref_name(name)?;
    let existing = match read_tag_raw(db, name) {
        None => return Ok(false),
        Some(t) => t,
    };
    if existing.deleted {
        return Ok(false);
    }
    // Every other field is preserved verbatim. A tombstone that forgot the
    // target would be an audit record that answers nothing.
    let rec = TagRecord { deleted: true, ..existing };
    write_tag(db, &rec)?;
    Ok(true)
}

// ── Refs ──────────────────────────────────────────────────────────────────

fn read_ref_raw(db: &Db, name: &str) -> Option<StoredRef> {
    let n = db.get(REFS, name)?;
    serde_json::from_value(n.data).ok()
}

/// Point a ref at a sequence, creating it or MOVING it.
///
/// Moving is allowed and is the entire reason refs exist. It is still
/// recorded: each move appends a new version of the same document, so the
/// `prev` chain is a complete, walkable history of where this ref has been —
/// the history comes free from the DAG rather than from a side log.
///
/// Future sequences are refused for the same reason as tags: a pointer at
/// state that does not exist is not a pointer.
pub fn set_ref(db: &Db, name: &str, at_seq: u64) -> Result<RefRecord> {
    validate_ref_name(name)?;
    let next_seq = db.seq.load(Ordering::SeqCst);
    if at_seq >= next_seq {
        bail!(
            "cannot point ref {:?} at sequence {}: the database is at sequence {} — \
             that state does not exist yet",
            name,
            at_seq,
            next_seq.saturating_sub(1)
        );
    }
    let rec = RefRecord { name: name.to_string(), at_seq, updated_seq: next_seq };
    let stored = StoredRef {
        name: rec.name.clone(),
        at_seq: rec.at_seq,
        updated_seq: rec.updated_seq,
        deleted: false,
    };
    db.put_unchecked(REFS, name, serde_json::to_value(&stored)?, vec![], None, None)?;
    Ok(rec)
}

/// A live ref by name.
pub fn get_ref(db: &Db, name: &str) -> Option<RefRecord> {
    let s = read_ref_raw(db, name)?;
    if s.deleted {
        return None;
    }
    Some(RefRecord { name: s.name, at_seq: s.at_seq, updated_seq: s.updated_seq })
}

/// Live refs, sorted by name.
pub fn list_refs(db: &Db) -> Vec<RefRecord> {
    let mut out: Vec<RefRecord> = db
        .id_index
        .list_ids(REFS)
        .into_iter()
        .filter_map(|id| get_ref(db, &id))
        .collect();
    out.sort_by(|a, b| a.name.as_bytes().cmp(b.name.as_bytes()));
    out
}

/// Delete a ref. Returns `false` when there was no live ref by that name.
///
/// Written as a `deleted: true` version rather than a real delete for one
/// mechanical reason and one design one: `Db::delete` refuses reserved
/// collections outright, and keeping the version chain intact means the ref's
/// movement history survives its deletion.
///
/// Unlike a tag, the NAME IS FREE AGAIN — [`set_ref`] will happily recreate
/// it. That is the whole difference between the two kinds, and it is safe here
/// because a ref never promised to stay put, so nothing downstream is entitled
/// to assume a past reference to it still resolves the same way.
pub fn delete_ref(db: &Db, name: &str) -> Result<bool> {
    validate_ref_name(name)?;
    let existing = match read_ref_raw(db, name) {
        None => return Ok(false),
        Some(s) => s,
    };
    if existing.deleted {
        return Ok(false);
    }
    let stored = StoredRef { deleted: true, ..existing };
    db.put_unchecked(REFS, name, serde_json::to_value(&stored)?, vec![], None, None)?;
    Ok(true)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    use tempfile::{tempdir, TempDir};

    /// A database with `n` ordinary writes in it, so there are real sequences
    /// to point at.
    fn db_with(n: u64) -> (TempDir, Db) {
        let dir = tempdir().unwrap();
        let db = Db::open(dir.path(), None).unwrap();
        for i in 0..n {
            db.put("orders", &format!("o{}", i), json!({ "i": i }), vec![], None, None)
                .unwrap();
        }
        (dir, db)
    }

    fn tip(db: &Db) -> u64 {
        db.seq.load(Ordering::SeqCst).saturating_sub(1)
    }

    #[test]
    fn a_tag_is_created_read_back_and_listed() {
        let (_d, db) = db_with(3);
        let t = create_tag(&db, "v1.0", 1, Some("first cut")).unwrap();
        assert_eq!(t.at_seq, 1);
        assert!(!t.deleted);
        assert_eq!(t.message.as_deref(), Some("first cut"));

        let got = get_tag(&db, "v1.0").expect("tag readable by name");
        assert_eq!(got, t);

        let listed = list_tags(&db);
        assert_eq!(listed.len(), 1);
        assert_eq!(listed[0].name, "v1.0");
    }

    #[test]
    fn retagging_the_same_name_at_a_different_seq_is_refused_and_names_the_target() {
        let (_d, db) = db_with(5);
        create_tag(&db, "v1.0", 1, None).unwrap();
        let err = create_tag(&db, "v1.0", 3, None).unwrap_err().to_string();
        assert!(err.contains("already points at sequence 1"), "message was: {}", err);
        assert!(err.contains("immutable"), "message was: {}", err);
        // And the tag did NOT move.
        assert_eq!(get_tag(&db, "v1.0").unwrap().at_seq, 1);
    }

    #[test]
    fn retagging_the_same_name_at_the_same_seq_is_idempotent_success() {
        let (_d, db) = db_with(5);
        let first = create_tag(&db, "v1.0", 2, Some("m")).unwrap();
        let again = create_tag(&db, "v1.0", 2, Some("different message")).unwrap();
        // The original record is returned unchanged — a retry must not quietly
        // rewrite the tag it was re-asserting.
        assert_eq!(first, again);
        assert_eq!(list_tags(&db).len(), 1);
    }

    #[test]
    fn deleting_a_tag_leaves_an_audited_tombstone_with_its_target_intact() {
        let (_d, db) = db_with(5);
        create_tag(&db, "v1.0", 2, Some("oops")).unwrap();
        assert!(delete_tag(&db, "v1.0").unwrap());

        assert!(get_tag(&db, "v1.0").is_none(), "a deleted tag is not live");
        assert!(list_tags(&db).is_empty());

        let audit = list_tags_including_deleted(&db);
        assert_eq!(audit.len(), 1, "the tombstone does not vanish");
        assert!(audit[0].deleted);
        assert_eq!(audit[0].at_seq, 2, "the tombstone remembers what it pointed at");
        assert_eq!(audit[0].message.as_deref(), Some("oops"));
        assert_eq!(get_tag_including_deleted(&db, "v1.0").unwrap().at_seq, 2);

        // Deleting again is false, not an error, and not a second tombstone.
        assert!(!delete_tag(&db, "v1.0").unwrap());
        assert_eq!(list_tags_including_deleted(&db).len(), 1);
    }

    /// The sharpest rule in the module.
    #[test]
    fn a_deleted_tag_name_cannot_be_reused_at_any_target() {
        let (_d, db) = db_with(5);
        create_tag(&db, "v1.0", 2, None).unwrap();
        delete_tag(&db, "v1.0").unwrap();

        // Not at a different sequence...
        let err = create_tag(&db, "v1.0", 4, None).unwrap_err().to_string();
        assert!(err.contains("previously deleted"), "message was: {}", err);
        assert!(err.contains("sequence 2"), "message must say what it pointed at: {}", err);

        // ...and not at the SAME sequence either. Idempotency applies to a live
        // tag being re-asserted, never to resurrecting a retracted one.
        let err = create_tag(&db, "v1.0", 2, None).unwrap_err().to_string();
        assert!(err.contains("previously deleted"), "message was: {}", err);

        assert!(get_tag(&db, "v1.0").is_none());
        assert_eq!(list_tags(&db).len(), 0);
        // A different name at the same target is of course fine.
        create_tag(&db, "v1.0.1", 2, None).unwrap();
    }

    #[test]
    fn the_no_reuse_ban_survives_a_reopen() {
        let dir = tempdir().unwrap();
        {
            let db = Db::open(dir.path(), None).unwrap();
            db.put("orders", "a", json!({}), vec![], None, None).unwrap();
            db.put("orders", "b", json!({}), vec![], None, None).unwrap();
            create_tag(&db, "v1.0", 1, None).unwrap();
            delete_tag(&db, "v1.0").unwrap();
            db.flush_all();
        }
        let db = Db::open(dir.path(), None).unwrap();
        let err = create_tag(&db, "v1.0", 1, None).unwrap_err().to_string();
        assert!(err.contains("previously deleted"), "message was: {}", err);
    }

    #[test]
    fn a_tag_captures_a_persisted_state_root_and_reports_none_when_there_is_not_one() {
        let (_d, db) = db_with(4);
        let at = tip(&db);
        let untagged = create_tag(&db, "no-root", at, None).unwrap();
        assert!(
            untagged.state_root.is_none(),
            "no root was persisted at {}, and the tag must say so rather than \
             computing one behind the operator's back",
            at
        );

        let persisted = db.create_root_at(at).unwrap();
        let tagged = create_tag(&db, "has-root", at, None).unwrap();
        assert_eq!(tagged.state_root.as_deref(), Some(persisted.root.state_root.as_str()));
    }

    #[test]
    fn tagging_a_future_sequence_is_refused() {
        let (_d, db) = db_with(3);
        let next = db.seq.load(Ordering::SeqCst);
        for future in [next, next + 1, u64::MAX] {
            let err = create_tag(&db, "ahead", future, None).unwrap_err().to_string();
            assert!(err.contains("future"), "message was: {}", err);
        }
        // The tip itself is fine.
        create_tag(&db, "here", tip(&db), None).unwrap();
    }

    #[test]
    fn invalid_names_are_refused_one_category_at_a_time() {
        let (_d, db) = db_with(2);
        let cases: &[(&str, &str)] = &[
            ("", "empty"),
            (" v1", "whitespace"),
            ("v1 ", "whitespace"),
            ("a/b", "path separator"),
            ("a\\b", "path separator"),
            ("a\0b", "NUL"),
            ("42", "numeric"),
            ("0", "numeric"),
        ];
        for (name, why) in cases {
            let e = validate_ref_name(name)
                .unwrap_err()
                .to_string();
            assert!(
                e.to_lowercase().contains(&why.to_lowercase()),
                "{:?} should be refused for {:?}, message was: {}", name, why, e
            );
            // And the refusal is enforced at every entry point, not just the
            // validator — a rule only the validator knows is a rule the API
            // does not have.
            assert!(create_tag(&db, name, 0, None).is_err(), "create_tag({:?})", name);
            assert!(set_ref(&db, name, 0).is_err(), "set_ref({:?})", name);
            assert!(delete_tag(&db, name).is_err(), "delete_tag({:?})", name);
            assert!(delete_ref(&db, name).is_err(), "delete_ref({:?})", name);
        }

        let too_long = "v".repeat(256);
        assert!(validate_ref_name(&too_long).unwrap_err().to_string().contains("256 bytes"));

        // Ordinary names, including ones with digits in them, still work.
        for ok in ["v1.0", "main", "release-2026", "v42", "42a", "a b"] {
            validate_ref_name(ok).unwrap_or_else(|e| panic!("{:?} refused: {}", ok, e));
        }
    }

    #[test]
    fn a_ref_is_set_moved_and_read_back() {
        let (_d, db) = db_with(5);
        let r = set_ref(&db, "main", 1).unwrap();
        assert_eq!(r.at_seq, 1);
        assert_eq!(get_ref(&db, "main").unwrap().at_seq, 1);

        // Moving is allowed — this is the whole difference from a tag.
        set_ref(&db, "main", 4).unwrap();
        assert_eq!(get_ref(&db, "main").unwrap().at_seq, 4);

        let listed = list_refs(&db);
        assert_eq!(listed.len(), 1);
        assert_eq!(listed[0].at_seq, 4);
        assert!(get_ref(&db, "nope").is_none());
    }

    /// Both halves of the contrast in one place, because the difference is the
    /// point and a test that only asserted one half would not document it.
    #[test]
    fn a_deleted_ref_name_is_reusable_but_a_deleted_tag_name_is_not() {
        let (_d, db) = db_with(5);

        set_ref(&db, "release", 1).unwrap();
        assert!(delete_ref(&db, "release").unwrap());
        assert!(get_ref(&db, "release").is_none());
        assert!(list_refs(&db).is_empty());
        assert!(!delete_ref(&db, "release").unwrap(), "already gone");
        // Reused, at a DIFFERENT target, with no complaint.
        set_ref(&db, "release", 3).unwrap();
        assert_eq!(get_ref(&db, "release").unwrap().at_seq, 3);

        create_tag(&db, "release", 1, None).unwrap();
        delete_tag(&db, "release").unwrap();
        assert!(
            create_tag(&db, "release", 3, None).is_err(),
            "the same sequence of operations that is legal for a ref must be \
             refused for a tag"
        );
    }

    #[test]
    fn tags_and_refs_survive_a_reopen() {
        let dir = tempdir().unwrap();
        let root_hex;
        {
            let db = Db::open(dir.path(), None).unwrap();
            for i in 0..4 {
                db.put("orders", &format!("o{}", i), json!({ "i": i }), vec![], None, None)
                    .unwrap();
            }
            let at = db.seq.load(Ordering::SeqCst) - 1;
            root_hex = db.create_root_at(at).unwrap().root.state_root;
            create_tag(&db, "v1.0", at, Some("ship it")).unwrap();
            create_tag(&db, "v0.9", 1, None).unwrap();
            delete_tag(&db, "v0.9").unwrap();
            set_ref(&db, "main", 2).unwrap();
            db.flush_all();
        }

        let db = Db::open(dir.path(), None).unwrap();
        let t = get_tag(&db, "v1.0").expect("tag survived reopen");
        assert_eq!(t.message.as_deref(), Some("ship it"));
        assert_eq!(t.state_root.as_deref(), Some(root_hex.as_str()));
        assert_eq!(list_tags(&db).len(), 1);
        assert_eq!(list_tags_including_deleted(&db).len(), 2);
        assert!(list_tags_including_deleted(&db).iter().any(|x| x.name == "v0.9" && x.deleted));
        assert_eq!(get_ref(&db, "main").unwrap().at_seq, 2);
        assert_eq!(list_refs(&db).len(), 1);
    }

    /// Refs and tags are engine records, so they must not be part of the state
    /// they point at. If they were, tagging would change the root the tag just
    /// captured.
    #[test]
    fn naming_a_state_does_not_change_it() {
        let (_d, db) = db_with(4);
        let before = db.state_root().unwrap();

        create_tag(&db, "v1.0", 1, Some("a message long enough to matter")).unwrap();
        set_ref(&db, "main", 2).unwrap();
        delete_tag(&db, "v1.0").unwrap();
        delete_ref(&db, "main").unwrap();

        assert_eq!(db.state_root().unwrap(), before);
        assert!(
            !db.collections().iter().any(|c| c == TAGS || c == REFS),
            "reserved collections must never enter the namespace"
        );
    }
}
