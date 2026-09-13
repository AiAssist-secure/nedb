// SPDX-FileCopyrightText: 2026 INTERCHAINED LLC
// SPDX-License-Identifier: BUSL-1.1
// NEDB · © 2026 INTERCHAINED LLC × Eth-Interchained × Vex (Claude Opus 5)

//! Collection identity — what it means for a collection to EXIST.
//!
//! # Why this module exists
//!
//! Before this, "which collections exist" was not a fact about the database.
//! It was a fact about the storage substrate, and the two substrates disagreed:
//!
//! ```text
//! disk, flush between PUT and DELETE : ["orders"]
//! disk, both inside one flush tick   : []
//! memory                             : []
//! ```
//!
//! All three are the same logical history — create a collection, then empty it.
//! Disk mode answered by listing directories ([`crate::index::IdIndex::collections`]
//! did a `read_dir`), and the WAL write buffer is keyed by `(coll, id)`, so a PUT
//! followed by a DELETE before the 1-second flush ticker fires overwrites the
//! buffered entry with its own tombstone. No directory is ever created. PUT,
//! flush, DELETE leaves the directory behind forever, because the flush path only
//! ever calls `remove_file` — it has no `remove_dir` in it at all.
//!
//! So the namespace was decided by a background timer. That is survivable for a
//! `LIST COLLECTIONS` convenience call, and fatal for a state root: a root
//! commits to a namespace, which is only meaningful if two replicas of the same
//! history agree on what the namespace IS.
//!
//! # The rule
//!
//! A collection exists because a record says so, not because a directory is
//! lying around. Creation is an event, the event is a node, and the node lives
//! in the DAG like everything else. Emptying a collection does not destroy it;
//! only an explicit drop does, and a drop is a tombstone rather than an absence.
//!
//! Putting the registry in the DAG rather than in a sidecar file is the boring
//! choice and it pays three times: `since()` replicates collection creation to
//! followers for free, `AS OF` answers "which collections existed at seq N"
//! for free, and `verify()` covers the registry for free. A `COLLECTIONS` file
//! would have needed all three written by hand.
//!
//! # Reserved names
//!
//! The registry has to live somewhere, and wherever it lives must not be
//! user-writable — otherwise a client can forge the namespace by writing to it
//! directly. The same reservation is what will later keep state-root records
//! from being part of the state they describe, which is a decent sign it is the
//! right primitive: one rule, used twice.

use anyhow::{bail, Result};

/// Everything under this prefix belongs to the engine. User writes are refused.
pub const RESERVED_PREFIX: &str = "_nedb";

/// The collection registry. Ids are collection names; the latest version of
/// each says whether that collection is currently live.
pub const COLLECTIONS: &str = "_nedb.collections";

/// Is this name part of the engine's own namespace?
pub fn is_reserved(coll: &str) -> bool {
    coll == RESERVED_PREFIX || coll.starts_with(&format!("{}.", RESERVED_PREFIX))
}

/// Refuse a write the caller is not allowed to make.
///
/// Named for what it does to the caller, not for what it returns, because the
/// only correct response at every call site is to stop.
pub fn refuse_reserved(coll: &str) -> Result<()> {
    if is_reserved(coll) {
        bail!(
            "collection {:?} is reserved: everything under {:?} is engine-owned, and \
             letting a client write there would let it forge the namespace the state \
             root commits to",
            coll, RESERVED_PREFIX
        );
    }
    Ok(())
}

/// Is this a name a collection can durably HAVE?
///
/// Two separate concerns land here.
///
/// The first is that a collection name becomes a directory name on disk
/// (`indexes/{coll}/{shard}/{id}`), so a name containing a path separator or a
/// `..` component does not address a collection at all — it addresses somewhere
/// else on the filesystem. That has to be refused at the entry point rather than
/// sanitised, because a silently rewritten name is a different collection than
/// the one the caller asked for, and they would never be told.
///
/// The second is that a state root commits to these names. A name that cannot
/// round-trip identically through every storage path is not an identity.
pub fn validate_name(coll: &str) -> Result<()> {
    if coll.is_empty() {
        bail!("collection name is empty");
    }
    if coll.len() > 255 {
        bail!("collection name is {} bytes; the limit is 255", coll.len());
    }
    if coll == "." || coll == ".." {
        bail!("collection name {:?} is a filesystem path component, not a name", coll);
    }
    if coll.contains('/') || coll.contains('\\') {
        bail!(
            "collection name {:?} contains a path separator — on disk a collection \
             name IS a directory name, so this does not name a collection, it names \
             a location",
            coll
        );
    }
    if coll.contains('\0') {
        bail!("collection name contains a NUL byte");
    }
    // A leading or trailing space survives JSON and dies in a shell, a URL, and
    // half the tools that will ever read a root. Refuse rather than trim: trimming
    // means the collection you created is not the collection you named.
    if coll != coll.trim() {
        bail!("collection name {:?} has leading or trailing whitespace", coll);
    }
    Ok(())
}

/// A name that may be written to: valid AND not engine-owned.
pub fn validate_writable(coll: &str) -> Result<()> {
    validate_name(coll)?;
    refuse_reserved(coll)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_registry_itself_is_reserved() {
        assert!(is_reserved(COLLECTIONS));
        assert!(refuse_reserved(COLLECTIONS).is_err());
    }

    #[test]
    fn reservation_is_by_namespace_not_by_leading_underscore() {
        // Users get to keep their underscores. Only OUR prefix is taken.
        assert!(!is_reserved("_private"));
        assert!(!is_reserved("_nedbish"));
        assert!(is_reserved("_nedb"));
        assert!(is_reserved("_nedb.roots"));
    }

    #[test]
    fn a_name_that_escapes_the_data_directory_is_refused() {
        for escape in ["../etc", "a/b", "..\\windows", "/absolute", ".."] {
            assert!(
                validate_name(escape).is_err(),
                "{:?} must not be usable as a collection name", escape
            );
        }
    }

    #[test]
    fn ordinary_names_survive() {
        for ok in ["orders", "itsl_ops", "blocks-v2", "Ünicode", "a.b"] {
            validate_writable(ok).unwrap_or_else(|e| panic!("{:?} refused: {}", ok, e));
        }
    }

    #[test]
    fn whitespace_is_refused_rather_than_trimmed() {
        // Trimming would mean the collection you created is not the one you named.
        assert!(validate_name(" orders").is_err());
        assert!(validate_name("orders ").is_err());
        assert!(validate_name("ord ers").is_ok(), "an interior space is a real name");
    }
}
