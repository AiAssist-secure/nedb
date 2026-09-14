// SPDX-FileCopyrightText: 2026 INTERCHAINED LLC
// SPDX-License-Identifier: BUSL-1.1
// NEDB · © 2026 INTERCHAINED LLC × Eth-Interchained × Vex (Claude Opus 5)

//! Qualified cause references — naming a causal ancestor that lives in
//! ANOTHER object store.
//!
//! # Why this module exists
//!
//! A node carries `caused_by: Vec<String>` ([`crate::store::Node`]), and every
//! entry in it is a bare BLAKE2b object hash. The causal edges those hashes
//! stand for are materialised in [`crate::graph`] as filesystem paths,
//! `graph/{from_hash}/{edge_type}/{to_hash}`, and `TRACE` walks them.
//!
//! That works for exactly as long as there is one object store, because with
//! one store "the store" is not information — there is nothing to say. The
//! moment branches exist as child stores it becomes the most important thing
//! in the reference and it is the one thing a bare hash cannot express. A
//! merge write in the destination store has to point at a node that was
//! written in the branch's store, and on read `TRACE` gets two bad outcomes
//! and no good one:
//!
//! ```text
//! hash absent from the reading store  → the edge dangles, trace truncates
//! hash present in BOTH stores         → resolves against the wrong one, silently
//! ```
//!
//! The second is the dangerous one. A dangling edge is a visible failure; a
//! confidently-wrong resolution is a corrupt causal history that verifies.
//! Content addressing makes the collision case unlikely-but-real: two stores
//! that share ancestry genuinely DO hold the same hashes, because the same
//! bytes hash the same way everywhere. That is the point of content
//! addressing, and it is precisely why a hash alone cannot be a locator.
//!
//! So a cause reference needs two parts — WHAT (the hash) and WHERE (the
//! store) — while staying a plain string, because `caused_by` is
//! `Vec<String>` on the wire today and changing the shape of a node is a
//! storage-format break we are not willing to take for this.
//!
//! # The format
//!
//! ```text
//! local      64 hex chars                 e.g. 3f9a...c1   (legacy, still valid)
//! qualified  64 hex chars '@' store id    e.g. 3f9a...c1@branch-feature-x
//! ```
//!
//! [`Cause::Local`] is not a deprecated form to be migrated away from. It is
//! the correct encoding of "this cause lives wherever I do", which is what
//! every intra-store edge means and what every node written before this module
//! existed says. Those resolve against the reading store and always did; this
//! module just gives that behaviour a name.
//!
//! # Why `@`
//!
//! The separator has to be a character that can appear in NEITHER side of the
//! reference, or the encoding is ambiguous and the parse is a guess:
//!
//!   - hex is `[0-9a-f]`, so anything outside that alphabet is safe on the left;
//!   - store ids are [`STORE_ID_ALPHABET`] (`[A-Za-z0-9_.-]`), which excludes
//!     `@` by construction, and [`StoreId::new`] REFUSES any id containing it
//!     rather than escaping it. An escape layer is a second encoding to get
//!     wrong, and a store id that can break the reference format is not a
//!     valid store id — it is a bug that has not been reported yet.
//!
//! Among the characters satisfying that, `@` is chosen over the alternatives
//! for reasons that are operational rather than aesthetic:
//!
//!   - `:` is not a legal filename character on Windows, and store ids and
//!     hashes both end up as path components in `graph/` and `objects/`;
//!   - `/` is a path separator on every platform, so it would let a store id
//!     escape its directory;
//!   - `#`, `?`, `&` are URL-significant and these strings appear in query
//!     strings and HTTP paths on the server surface;
//!   - `@` is filesystem-safe everywhere, shell-safe unquoted, needs no URL
//!     escaping in a path segment, and already means "at this location" to
//!     every reader who has seen an email address.
//!
//! Hash goes FIRST, store second — `{hash}@{store}` rather than
//! `{store}@{hash}` — so that the hash occupies the same leading bytes in both
//! variants. Every existing display path that abbreviates a cause by taking a
//! prefix (`&h[..8]`, the usual short-hash rendering) keeps showing a hash
//! instead of suddenly showing a store name, and sorting a mixed list still
//! groups by hash the way it does today. Grouping by store is the rarer query
//! and can afford a parse.
//!
//! # What is strict, and why
//!
//! A hash must be exactly 64 LOWERCASE hex characters. Uppercase is refused,
//! not normalised, and that is deliberate: normalising means `3F9A…` and
//! `3f9a…` are two spellings of one reference, and a content-addressed system
//! does not get to have two spellings of anything. The instant two exist,
//! equality, deduplication, edge-path construction and set membership must all
//! remember to canonicalise, one of them eventually forgets, and the graph
//! grows a duplicate edge under a second path. Refusing at the boundary costs
//! one error and buys the invariant everywhere downstream.

use std::fmt;

use serde::de::{self, Visitor};
use serde::{Deserialize, Deserializer, Serialize, Serializer};

/// Separator between hash and store id. See the module docs for why this
/// character and not another one.
pub const SEPARATOR: char = '@';

/// Length of a BLAKE2b object hash in hex characters.
const HASH_HEX_LEN: usize = 64;

/// Upper bound on a store id, in bytes.
///
/// Store ids become path components (`stores/{id}/...`) and are embedded in
/// every cause reference of every node that points across a store boundary, so
/// they are paid for repeatedly in both inodes and bytes-on-disk. 64 is chosen
/// to match the hash length: a qualified reference is then never more than
/// ~2x a bare one, which keeps the worst case on a node's `caused_by` bounded
/// and predictable. It is also comfortably under the 255-byte filename limit
/// on every filesystem we target, with room for prefixes and suffixes.
pub const MAX_STORE_ID_LEN: usize = 64;

/// The characters a store id may contain, for error messages and docs.
///
/// `[A-Za-z0-9_.-]` — the intersection of "safe as a filesystem path
/// component", "safe in a URL path segment unescaped", "safe unquoted in a
/// shell", and "typeable without thinking". Notably excluded: whitespace (an
/// id you cannot see the boundaries of), `/` and `\` (directory escape), `@`
/// (the separator), and everything non-ASCII (because two visually identical
/// ids under different Unicode normalisations would reintroduce exactly the
/// two-spellings problem that the lowercase-hex rule exists to prevent).
pub const STORE_ID_ALPHABET: &str = "A-Za-z0-9_.-";

// ---------------------------------------------------------------------------
// StoreId
// ---------------------------------------------------------------------------

/// A validated store identifier.
///
/// A newtype rather than a bare `String` so that the validation cannot be
/// skipped: the inner field is private and [`StoreId::new`] is the only way in,
/// which makes "this store id cannot break the cause encoding" a property of
/// the type instead of a convention callers are asked to remember.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct StoreId(String);

impl StoreId {
    /// Validate and construct.
    ///
    /// Refuses anything that would make a cause reference ambiguous,
    /// unparseable, or unsafe as a path component. See [`StoreIdError`].
    pub fn new(s: impl Into<String>) -> Result<Self, StoreIdError> {
        let s = s.into();

        if s.is_empty() {
            return Err(StoreIdError::Empty);
        }
        // Length is checked before the character scan so that an unbounded
        // input is rejected without walking all of it. The consequence is that
        // an oversized id that ALSO contains a bad character reports TooLong;
        // both diagnoses are true and the caller has to fix both anyway.
        if s.len() > MAX_STORE_ID_LEN {
            return Err(StoreIdError::TooLong { len: s.len(), max: MAX_STORE_ID_LEN });
        }

        for (position, ch) in s.char_indices() {
            // The separator gets its own variant even though the alphabet check
            // below would also catch it. "contains the separator" is a
            // different mistake from "contains a stray character" — it is
            // usually someone passing an already-rendered `hash@store` where a
            // store id was wanted — and it deserves a message that says so.
            if ch == SEPARATOR {
                return Err(StoreIdError::ContainsSeparator { position });
            }
            if !is_store_id_char(ch) {
                return Err(StoreIdError::InvalidChar { ch, position });
            }
        }

        // `.` and `..` are legal under the alphabet but mean "here" and "one
        // level up" to every filesystem. A store id is used as a path
        // component; these two would resolve to a directory that is not the
        // store's own. Refused by name rather than by banning `.` outright,
        // because `.` is genuinely useful inside an id (`team.alpha`).
        if s == "." || s == ".." {
            return Err(StoreIdError::Reserved { id: s });
        }

        Ok(StoreId(s))
    }

    /// Borrow the underlying string.
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// Consume and return the underlying string.
    pub fn into_string(self) -> String {
        self.0
    }
}

fn is_store_id_char(ch: char) -> bool {
    ch.is_ascii_alphanumeric() || ch == '_' || ch == '-' || ch == '.'
}

impl fmt::Display for StoreId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl AsRef<str> for StoreId {
    fn as_ref(&self) -> &str {
        &self.0
    }
}

impl std::str::FromStr for StoreId {
    type Err = StoreIdError;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        StoreId::new(s)
    }
}

// ---------------------------------------------------------------------------
// Cause
// ---------------------------------------------------------------------------

/// A reference to a causal ancestor.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Cause {
    /// A hash with no store qualification: every node written before this
    /// format existed, plus every ordinary intra-store edge written after it.
    /// Resolves against the store doing the reading.
    Local(String),
    /// Explicitly qualified — the hash lives in `store`, not in whichever
    /// store happens to be reading.
    Qualified { store: StoreId, hash: String },
}

impl Cause {
    /// Build a local (unqualified) cause, validating the hash.
    pub fn local(hash: impl Into<String>) -> Result<Self, CauseParseError> {
        let hash = hash.into();
        validate_hash(&hash)?;
        Ok(Cause::Local(hash))
    }

    /// Build a qualified cause, validating the hash. The store id is already
    /// validated by virtue of being a [`StoreId`].
    pub fn qualified(store: StoreId, hash: impl Into<String>) -> Result<Self, CauseParseError> {
        let hash = hash.into();
        validate_hash(&hash)?;
        Ok(Cause::Qualified { store, hash })
    }

    /// The object hash, regardless of variant.
    pub fn hash(&self) -> &str {
        match self {
            Cause::Local(h) => h,
            Cause::Qualified { hash, .. } => hash,
        }
    }

    /// The store id, or `None` for a local cause.
    pub fn store(&self) -> Option<&StoreId> {
        match self {
            Cause::Local(_) => None,
            Cause::Qualified { store, .. } => Some(store),
        }
    }

    /// True if this reference names a store explicitly.
    pub fn is_qualified(&self) -> bool {
        matches!(self, Cause::Qualified { .. })
    }

    /// Render to the wire form. Same as [`render`].
    pub fn render(&self) -> String {
        render(self)
    }
}

impl fmt::Display for Cause {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Cause::Local(h) => f.write_str(h),
            Cause::Qualified { store, hash } => write!(f, "{hash}{SEPARATOR}{store}"),
        }
    }
}

impl std::str::FromStr for Cause {
    type Err = CauseParseError;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        parse(s)
    }
}

impl TryFrom<String> for Cause {
    type Error = CauseParseError;
    fn try_from(s: String) -> Result<Self, Self::Error> {
        parse(&s)
    }
}

impl From<Cause> for String {
    fn from(c: Cause) -> String {
        render(&c)
    }
}

// ---------------------------------------------------------------------------
// parse / render
// ---------------------------------------------------------------------------

/// Parse a cause reference.
///
/// A string with no [`SEPARATOR`] is a bare hash and parses as [`Cause::Local`]
/// — this is the backward-compatibility path, and it is a path rather than a
/// fallback: no existing database needs migrating, because every 64-hex
/// `caused_by` entry ever written is already a valid input here and means
/// exactly what it always meant.
///
/// Never guesses. Every rejection carries what it saw.
pub fn parse(s: &str) -> Result<Cause, CauseParseError> {
    if s.is_empty() {
        return Err(CauseParseError::Empty);
    }

    let separators = s.matches(SEPARATOR).count();
    match separators {
        0 => {
            validate_hash(s)?;
            Ok(Cause::Local(s.to_string()))
        }
        1 => {
            // `split_once` is safe here: exactly one separator, so both halves
            // are well defined (either may be empty, which the validators
            // below reject with a specific reason rather than a generic one).
            let (hash, store) = s.split_once(SEPARATOR).expect("one separator counted");
            validate_hash(hash)?;
            let store = StoreId::new(store).map_err(CauseParseError::BadStoreId)?;
            Ok(Cause::Qualified { store, hash: hash.to_string() })
        }
        // More than one separator is never a store id we would have produced
        // (StoreId::new refuses the separator), so this is either a corrupted
        // value or a double-qualification like `h@a@b`. Refusing beats picking
        // a split and pretending we understood it.
        count => Err(CauseParseError::TooManySeparators { count, input: s.to_string() }),
    }
}

/// Render a cause to its wire form.
///
/// The inverse of [`parse`] for every value that [`parse`] can produce, and for
/// every value the constructors can produce, because both sides enforce the
/// same invariants: exactly-64 lowercase hex, and a store id that cannot
/// contain the separator.
pub fn render(c: &Cause) -> String {
    match c {
        Cause::Local(h) => h.clone(),
        Cause::Qualified { store, hash } => {
            let mut out = String::with_capacity(hash.len() + 1 + store.as_str().len());
            out.push_str(hash);
            out.push(SEPARATOR);
            out.push_str(store.as_str());
            out
        }
    }
}

/// Resolve a cause to the store it should be read from.
///
/// Local causes resolve to the reading store; qualified ones to their own.
/// This is the whole point of the module in one function: a caller holding a
/// `Cause` and knowing where it is reading from never has to decide what an
/// unqualified hash means.
pub fn target_store<'a>(c: &'a Cause, reading_store: &'a str) -> &'a str {
    match c {
        Cause::Local(_) => reading_store,
        Cause::Qualified { store, .. } => store.as_str(),
    }
}

/// Exactly 64 lowercase hex characters. No normalisation — see module docs.
fn validate_hash(h: &str) -> Result<(), CauseParseError> {
    if h.len() != HASH_HEX_LEN {
        return Err(CauseParseError::BadHashLength { got: h.len(), expected: HASH_HEX_LEN });
    }
    for (position, ch) in h.char_indices() {
        if ch.is_ascii_digit() || ('a'..='f').contains(&ch) {
            continue;
        }
        // Uppercase hex is a distinct diagnosis from garbage: the caller has a
        // real hash and the wrong case, and telling them that is the
        // difference between a one-line fix and a debugging session. It is
        // still an error, not a normalisation — see the module docs.
        if ch.is_ascii_uppercase() && ch.is_ascii_hexdigit() {
            return Err(CauseParseError::UppercaseHex { ch, position });
        }
        return Err(CauseParseError::NonHexChar { ch, position });
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Errors
// ---------------------------------------------------------------------------

/// Why a store id was refused.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum StoreIdError {
    /// Zero-length.
    Empty,
    /// Longer than [`MAX_STORE_ID_LEN`].
    TooLong { len: usize, max: usize },
    /// Contains [`SEPARATOR`], which would make the cause encoding ambiguous.
    ContainsSeparator { position: usize },
    /// Contains a character outside [`STORE_ID_ALPHABET`].
    InvalidChar { ch: char, position: usize },
    /// `.` or `..` — legal characters, but they name a directory that is not
    /// this store.
    Reserved { id: String },
}

impl fmt::Display for StoreIdError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            StoreIdError::Empty => write!(f, "store id is empty"),
            StoreIdError::TooLong { len, max } => {
                write!(f, "store id is {len} bytes, maximum is {max}")
            }
            StoreIdError::ContainsSeparator { position } => write!(
                f,
                "store id contains the reserved separator {SEPARATOR:?} at byte {position}; \
                 a store id that can break the cause encoding is not a valid store id"
            ),
            StoreIdError::InvalidChar { ch, position } => write!(
                f,
                "store id contains invalid character {ch:?} at byte {position}; \
                 allowed characters are [{STORE_ID_ALPHABET}]"
            ),
            StoreIdError::Reserved { id } => {
                write!(f, "store id {id:?} is reserved (it names a directory, not a store)")
            }
        }
    }
}

impl std::error::Error for StoreIdError {}

/// Why a cause reference was refused.
///
/// Every variant carries what was actually seen. A parser that says only
/// "invalid" forces the operator to reconstruct the input by hand, and the
/// inputs here are 64-character hex strings where the difference between valid
/// and invalid is one character in the middle.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CauseParseError {
    /// Empty input.
    Empty,
    /// Hash is not exactly 64 characters.
    BadHashLength { got: usize, expected: usize },
    /// Hash contains a character that is not a hex digit.
    NonHexChar { ch: char, position: usize },
    /// Hash contains uppercase hex. Refused rather than lowercased — see the
    /// module docs on why content addressing gets one spelling.
    UppercaseHex { ch: char, position: usize },
    /// The store half of a qualified reference is not a valid store id.
    BadStoreId(StoreIdError),
    /// More than one [`SEPARATOR`], so the split point is a guess.
    TooManySeparators { count: usize, input: String },
}

impl fmt::Display for CauseParseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            CauseParseError::Empty => {
                write!(f, "empty cause reference: expected a 64-char hex hash, optionally followed by {SEPARATOR:?} and a store id")
            }
            CauseParseError::BadHashLength { got, expected } => {
                write!(f, "cause hash is {got} characters, expected exactly {expected} hex characters")
            }
            CauseParseError::NonHexChar { ch, position } => {
                write!(f, "cause hash contains non-hex character {ch:?} at position {position}; expected [0-9a-f]")
            }
            CauseParseError::UppercaseHex { ch, position } => write!(
                f,
                "cause hash contains uppercase hex character {ch:?} at position {position}; \
                 hashes must be lowercase (refused rather than normalised, so that one hash has one spelling)"
            ),
            CauseParseError::BadStoreId(e) => write!(f, "invalid store id in cause reference: {e}"),
            CauseParseError::TooManySeparators { count, input } => write!(
                f,
                "cause reference {input:?} contains {count} {SEPARATOR:?} separators, expected at most 1"
            ),
        }
    }
}

impl std::error::Error for CauseParseError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            CauseParseError::BadStoreId(e) => Some(e),
            _ => None,
        }
    }
}

impl From<StoreIdError> for CauseParseError {
    fn from(e: StoreIdError) -> Self {
        CauseParseError::BadStoreId(e)
    }
}

// ---------------------------------------------------------------------------
// Serde
// ---------------------------------------------------------------------------
//
// A Cause serialises as a plain JSON STRING, never a tagged object. `caused_by`
// is `Vec<String>` on the wire today, so a node encoded with `Vec<Cause>` must
// be byte-identical to one encoded with `Vec<String>` for all existing values —
// otherwise adopting this type would be a storage-format break, and the whole
// design goal was that it not be one.
//
// Hand-written rather than `#[serde(try_from/into)]` so deserialisation borrows
// the input `&str` on the common path instead of allocating a String only to
// parse it and throw it away, and so the parse error surfaces with its own
// Display text rather than serde's generic wrapper.

impl Serialize for Cause {
    fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&render(self))
    }
}

impl<'de> Deserialize<'de> for Cause {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        struct CauseVisitor;

        impl Visitor<'_> for CauseVisitor {
            type Value = Cause;

            fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                write!(f, "a cause reference string: 64 lowercase hex characters, optionally followed by {SEPARATOR:?} and a store id")
            }

            fn visit_str<E: de::Error>(self, v: &str) -> Result<Cause, E> {
                // The parse error's Display is the whole diagnosis; passing it
                // through as a custom message keeps "which character, where"
                // instead of collapsing to "invalid value".
                parse(v).map_err(|e| E::custom(e.to_string()))
            }
        }

        d.deserialize_str(CauseVisitor)
    }
}

impl Serialize for StoreId {
    fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&self.0)
    }
}

impl<'de> Deserialize<'de> for StoreId {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        let s = String::deserialize(d)?;
        StoreId::new(s).map_err(|e| de::Error::custom(e.to_string()))
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    /// A real-shaped hash: 64 lowercase hex characters, deterministic per seed
    /// so tests can name specific values and still be readable.
    fn hash_n(seed: u8) -> String {
        let alphabet = b"0123456789abcdef";
        (0..HASH_HEX_LEN)
            .map(|i| alphabet[(i.wrapping_mul(7).wrapping_add(seed as usize)) % 16] as char)
            .collect()
    }

    const H: &str = "3f9a7c1e0b2d4f6a8c0e1b3d5f7a9c1e2d4f6a8c0e1b3d5f7a9c1e2d4f6a8c0e";

    // --- constraint 1: backward compatibility -----------------------------

    #[test]
    fn legacy_bare_hash_parses_as_local() {
        let c = parse(H).expect("64-hex must parse");
        assert_eq!(c, Cause::Local(H.to_string()));
        assert!(!c.is_qualified());
        assert_eq!(c.hash(), H);
        assert_eq!(c.store(), None);
    }

    #[test]
    fn legacy_bare_hash_renders_byte_identically() {
        // The backward-compatibility proof: parse-then-render of an existing
        // caused_by entry returns the exact original bytes, so re-encoding a
        // node written by today's engine changes nothing on disk.
        for seed in 0..32u8 {
            let h = hash_n(seed);
            let round = render(&parse(&h).unwrap());
            assert_eq!(round, h, "bare hash must survive parse/render unchanged");
        }
        assert_eq!(render(&parse(H).unwrap()), H);
    }

    #[test]
    fn legacy_caused_by_vec_needs_no_migration() {
        // A whole caused_by list as today's engine writes it.
        let legacy: Vec<String> = (0..8u8).map(hash_n).collect();
        let parsed: Vec<Cause> = legacy.iter().map(|s| parse(s).unwrap()).collect();
        assert!(parsed.iter().all(|c| !c.is_qualified()));
        let rendered: Vec<String> = parsed.iter().map(render).collect();
        assert_eq!(rendered, legacy);
    }

    // --- constraint 2: unambiguity ----------------------------------------

    #[test]
    fn qualified_can_never_look_like_a_bare_hash() {
        // A bare hash has no separator; a qualified one always does; and the
        // separator can appear in neither half. So membership of `@` decides
        // the variant with no lookahead and no ambiguity.
        let q = Cause::qualified(StoreId::new("branch-x").unwrap(), H).unwrap();
        let s = render(&q);
        assert!(s.contains(SEPARATOR));
        assert_eq!(s.matches(SEPARATOR).count(), 1);
        assert!(!render(&Cause::local(H).unwrap()).contains(SEPARATOR));
        // And the separator is outside the hex alphabet.
        assert!(!SEPARATOR.is_ascii_hexdigit());
        // ...and outside the store-id alphabet.
        assert!(!is_store_id_char(SEPARATOR));
    }

    #[test]
    fn store_id_containing_separator_is_refused_at_construction() {
        let e = StoreId::new("branch@evil").unwrap_err();
        assert_eq!(e, StoreIdError::ContainsSeparator { position: 6 });
        assert!(e.to_string().contains("separator"));

        // Every position, including the ends, where a naive `split_once` or
        // `rsplit_once` would otherwise silently produce a different parse.
        for bad in ["@main", "main@", "@", "a@b@c"] {
            assert!(
                matches!(StoreId::new(bad), Err(StoreIdError::ContainsSeparator { .. })),
                "{bad:?} must be refused"
            );
        }

        // And the shape that would actually be dangerous: feeding an
        // already-rendered reference back in as a store id. It is refused for
        // length first (70 > 64) — both diagnoses are true; what matters is
        // that it never becomes a store id.
        let rendered = format!("{H}{SEPARATOR}inner");
        assert_eq!(
            StoreId::new(&rendered).unwrap_err(),
            StoreIdError::TooLong { len: rendered.len(), max: MAX_STORE_ID_LEN }
        );
        // Under the length bound, the separator diagnosis is the one reported,
        // which is what a caller doing the same thing with a short id sees.
        assert!(matches!(
            StoreId::new("abcdef@inner"),
            Err(StoreIdError::ContainsSeparator { position: 6 })
        ));
    }

    #[test]
    fn too_many_separators_is_refused_not_guessed() {
        let s = format!("{H}@a@b");
        match parse(&s).unwrap_err() {
            CauseParseError::TooManySeparators { count, input } => {
                assert_eq!(count, 2);
                assert_eq!(input, s);
            }
            other => panic!("expected TooManySeparators, got {other:?}"),
        }
    }

    // --- constraint 3: round-trips ----------------------------------------

    #[test]
    fn qualified_round_trips() {
        let q = Cause::qualified(StoreId::new("branch-feature-x").unwrap(), H).unwrap();
        let s = render(&q);
        assert_eq!(s, format!("{H}@branch-feature-x"));
        assert_eq!(parse(&s).unwrap(), q);
        assert_eq!(render(&parse(&s).unwrap()), s);
    }

    #[test]
    fn table_driven_round_trip() {
        // 20+ varied inputs: both variants, every legal store-id character
        // class, boundary lengths, and hashes of differing shapes.
        let store_ids = [
            "a",
            "Z",
            "0",
            "_",
            "-",
            ".",                      // legal inside an id, illegal as the whole id
            "main",
            "MAIN",
            "branch-feature-x",
            "branch_feature_x",
            "team.alpha",
            "v1.2.3-rc.4_final",
            "0123456789",
            "A-Za-z0-9_.",
            &"x".repeat(MAX_STORE_ID_LEN),
            &"y".repeat(MAX_STORE_ID_LEN - 1),
        ];

        let mut cases: Vec<Cause> = Vec::new();

        // Local variants.
        for seed in 0..8u8 {
            cases.push(Cause::local(hash_n(seed)).unwrap());
        }
        cases.push(Cause::local("0".repeat(64)).unwrap());
        cases.push(Cause::local("f".repeat(64)).unwrap());
        cases.push(Cause::local(H).unwrap());

        // Qualified variants, cycling hashes so store and hash vary together.
        for (i, sid) in store_ids.iter().enumerate() {
            let store = if *sid == "." {
                // `.` alone is reserved; use it in a position where it is legal.
                StoreId::new("a.b").unwrap()
            } else {
                StoreId::new(*sid).unwrap_or_else(|e| panic!("{sid:?} should be valid: {e}"))
            };
            cases.push(Cause::qualified(store, hash_n(i as u8 * 3)).unwrap());
        }

        assert!(cases.len() >= 20, "want a decent sample, got {}", cases.len());

        for c in &cases {
            let s = render(c);
            let back = parse(&s).unwrap_or_else(|e| panic!("{s:?} must re-parse: {e}"));
            assert_eq!(&back, c, "parse(render(c)) must equal c");
            assert_eq!(render(&back), s, "render must be stable across a round trip");
            // Display agrees with render.
            assert_eq!(c.to_string(), s);
            // JSON round-trip of the same value.
            let json = serde_json::to_string(c).unwrap();
            assert!(json.starts_with('"') && json.ends_with('"'), "must be a JSON string");
            let from_json: Cause = serde_json::from_str(&json).unwrap();
            assert_eq!(&from_json, c);
        }
    }

    // --- constraint 4: strict hash validation ------------------------------

    #[test]
    fn short_and_long_hashes_are_refused_distinguishably() {
        let short = &H[..63];
        let long = format!("{H}a");

        let e_short = parse(short).unwrap_err();
        let e_long = parse(&long).unwrap_err();

        assert_eq!(e_short, CauseParseError::BadHashLength { got: 63, expected: 64 });
        assert_eq!(e_long, CauseParseError::BadHashLength { got: 65, expected: 64 });
        assert_ne!(e_short, e_long, "63 and 65 must be distinguishable");
        assert!(e_short.to_string().contains("63"));
        assert!(e_long.to_string().contains("65"));
    }

    #[test]
    fn uppercase_hex_is_refused_not_normalised() {
        let upper = H.to_uppercase();
        match parse(&upper).unwrap_err() {
            CauseParseError::UppercaseHex { ch, position } => {
                assert_eq!(ch, 'F');
                assert_eq!(position, 1); // "3F9A..." → the 'F'
            }
            other => panic!("expected UppercaseHex, got {other:?}"),
        }
        // Mixed case too, and nothing anywhere lowercases it for us.
        let mixed = format!("{}A{}", &H[..10], &H[11..]);
        assert!(matches!(parse(&mixed), Err(CauseParseError::UppercaseHex { ch: 'A', .. })));
        assert!(parse(&upper).is_err());
    }

    #[test]
    fn non_hex_character_is_refused_and_named() {
        let bad = format!("{}z{}", &H[..5], &H[6..]);
        match parse(&bad).unwrap_err() {
            CauseParseError::NonHexChar { ch, position } => {
                assert_eq!(ch, 'z');
                assert_eq!(position, 5);
            }
            other => panic!("expected NonHexChar, got {other:?}"),
        }
        assert!(parse(&bad).unwrap_err().to_string().contains("'z'"));

        // Non-ASCII counts too, and the byte position is reported.
        let uni = format!("{}é{}", &H[..3], &H[5..]); // 'é' is 2 bytes → keeps len 64
        assert!(matches!(parse(&uni), Err(CauseParseError::NonHexChar { ch: 'é', .. })));
    }

    #[test]
    fn empty_input_is_its_own_error() {
        assert_eq!(parse("").unwrap_err(), CauseParseError::Empty);
        assert!(parse("").unwrap_err().to_string().contains("empty"));
    }

    #[test]
    fn qualified_with_bad_hash_reports_the_hash_not_the_store() {
        let e = parse("abc@main").unwrap_err();
        assert_eq!(e, CauseParseError::BadHashLength { got: 3, expected: 64 });
    }

    // --- constraint 5: store id rules --------------------------------------

    #[test]
    fn empty_store_id_is_refused() {
        assert_eq!(StoreId::new("").unwrap_err(), StoreIdError::Empty);
        // And through the parser: a trailing separator with nothing after it.
        assert_eq!(
            parse(&format!("{H}@")).unwrap_err(),
            CauseParseError::BadStoreId(StoreIdError::Empty)
        );
    }

    #[test]
    fn oversized_store_id_is_refused() {
        let big = "a".repeat(MAX_STORE_ID_LEN + 1);
        assert_eq!(
            StoreId::new(&big).unwrap_err(),
            StoreIdError::TooLong { len: MAX_STORE_ID_LEN + 1, max: MAX_STORE_ID_LEN }
        );
        // Exactly at the bound is fine.
        assert!(StoreId::new("a".repeat(MAX_STORE_ID_LEN)).is_ok());
        assert!(matches!(
            parse(&format!("{H}@{big}")),
            Err(CauseParseError::BadStoreId(StoreIdError::TooLong { .. }))
        ));
    }

    #[test]
    fn whitespace_in_store_id_is_refused() {
        for (bad, pos) in [("main branch", 4), (" main", 0), ("main\t", 4), ("main\n", 4)] {
            match StoreId::new(bad).unwrap_err() {
                StoreIdError::InvalidChar { ch, position } => {
                    assert_eq!(position, pos, "for {bad:?}");
                    assert!(ch.is_whitespace(), "for {bad:?}");
                }
                other => panic!("expected InvalidChar for {bad:?}, got {other:?}"),
            }
        }
    }

    #[test]
    fn path_unsafe_and_exotic_store_ids_are_refused_naming_the_character() {
        for bad in ["a/b", "a\\b", "a:b", "a#b", "a?b", "a%b", "a*b", "a\0b", "brânch"] {
            let e = StoreId::new(bad).unwrap_err();
            match e {
                StoreIdError::InvalidChar { ch, .. } => {
                    assert!(
                        e.to_string().contains(&format!("{ch:?}")),
                        "message must name the offending character for {bad:?}"
                    );
                }
                other => panic!("expected InvalidChar for {bad:?}, got {other:?}"),
            }
        }
    }

    #[test]
    fn dot_store_ids_are_reserved_but_dots_inside_ids_are_fine() {
        assert_eq!(StoreId::new(".").unwrap_err(), StoreIdError::Reserved { id: ".".into() });
        assert_eq!(StoreId::new("..").unwrap_err(), StoreIdError::Reserved { id: "..".into() });
        assert_eq!(StoreId::new("team.alpha").unwrap().as_str(), "team.alpha");
        assert_eq!(StoreId::new("...").unwrap().as_str(), "...");
    }

    // --- constraint 6: typed, informative errors ---------------------------

    #[test]
    fn every_error_variant_has_a_distinct_informative_message() {
        let errs = vec![
            CauseParseError::Empty,
            CauseParseError::BadHashLength { got: 63, expected: 64 },
            CauseParseError::NonHexChar { ch: 'z', position: 5 },
            CauseParseError::UppercaseHex { ch: 'F', position: 1 },
            CauseParseError::BadStoreId(StoreIdError::Empty),
            CauseParseError::BadStoreId(StoreIdError::TooLong { len: 99, max: 64 }),
            CauseParseError::BadStoreId(StoreIdError::ContainsSeparator { position: 2 }),
            CauseParseError::BadStoreId(StoreIdError::InvalidChar { ch: '/', position: 1 }),
            CauseParseError::BadStoreId(StoreIdError::Reserved { id: "..".into() }),
            CauseParseError::TooManySeparators { count: 2, input: "a@b@c".into() },
        ];
        let msgs: Vec<String> = errs.iter().map(|e| e.to_string()).collect();
        for (i, m) in msgs.iter().enumerate() {
            assert!(!m.is_empty());
            for (j, n) in msgs.iter().enumerate() {
                if i != j {
                    assert_ne!(m, n, "error messages must be distinguishable");
                }
            }
        }
        // Debug is derived and useful; source() chains for the nested case.
        assert!(format!("{:?}", errs[1]).contains("BadHashLength"));
        use std::error::Error as _;
        assert!(errs[4].source().is_some());
        assert!(errs[0].source().is_none());
    }

    // --- constraint 7: serde ------------------------------------------------

    #[test]
    fn vec_of_causes_is_a_json_array_of_plain_strings() {
        let causes = vec![
            Cause::local(H).unwrap(),
            Cause::qualified(StoreId::new("branch-x").unwrap(), hash_n(1)).unwrap(),
            Cause::local(hash_n(2)).unwrap(),
        ];
        let json = serde_json::to_string(&causes).unwrap();
        assert_eq!(
            json,
            format!(
                "[\"{}\",\"{}@branch-x\",\"{}\"]",
                H,
                hash_n(1),
                hash_n(2)
            )
        );

        // It is an array of strings by the parser's own reckoning, not just by
        // eyeballing the text.
        let as_values: Vec<serde_json::Value> = serde_json::from_str(&json).unwrap();
        assert!(as_values.iter().all(|v| v.is_string()));

        let back: Vec<Cause> = serde_json::from_str(&json).unwrap();
        assert_eq!(back, causes);
    }

    #[test]
    fn caused_by_is_wire_compatible_with_vec_string() {
        // The storage-format claim, tested: a Vec<Cause> of legacy values
        // encodes to exactly the same JSON as the Vec<String> it replaces.
        let legacy: Vec<String> = (0..5u8).map(hash_n).collect();
        let as_causes: Vec<Cause> = legacy.iter().map(|h| Cause::local(h).unwrap()).collect();
        assert_eq!(
            serde_json::to_string(&as_causes).unwrap(),
            serde_json::to_string(&legacy).unwrap()
        );
        // And a legacy JSON array reads straight back into Vec<Cause>.
        let from_legacy: Vec<Cause> =
            serde_json::from_str(&serde_json::to_string(&legacy).unwrap()).unwrap();
        assert_eq!(from_legacy, as_causes);
    }

    #[test]
    fn deserialising_garbage_fails_with_the_parse_diagnosis() {
        let err = serde_json::from_str::<Cause>("\"nope\"").unwrap_err().to_string();
        assert!(err.contains("expected exactly 64"), "got: {err}");

        let err = serde_json::from_str::<Vec<Cause>>(&format!("[\"{}\"]", H.to_uppercase()))
            .unwrap_err()
            .to_string();
        assert!(err.contains("uppercase"), "got: {err}");

        // A tagged object is not a cause; only strings are.
        assert!(serde_json::from_str::<Cause>("{\"Local\":\"x\"}").is_err());
        assert!(serde_json::from_str::<Cause>("42").is_err());
    }

    #[test]
    fn store_id_serde_round_trips_and_validates() {
        let s = StoreId::new("branch-x").unwrap();
        let json = serde_json::to_string(&s).unwrap();
        assert_eq!(json, "\"branch-x\"");
        assert_eq!(serde_json::from_str::<StoreId>(&json).unwrap(), s);
        assert!(serde_json::from_str::<StoreId>("\"bad id\"").is_err());
    }

    // --- target_store --------------------------------------------------------

    #[test]
    fn target_store_resolves_local_to_reader_and_qualified_to_itself() {
        let local = Cause::local(H).unwrap();
        assert_eq!(target_store(&local, "main"), "main");
        assert_eq!(target_store(&local, "some-other-store"), "some-other-store");

        let q = Cause::qualified(StoreId::new("branch-x").unwrap(), H).unwrap();
        assert_eq!(target_store(&q, "main"), "branch-x");
        // The reading store is irrelevant for a qualified cause — that is the
        // whole guarantee: a merge edge resolves the same from anywhere.
        assert_eq!(target_store(&q, "branch-x"), "branch-x");
        assert_eq!(target_store(&q, "anything-at-all"), "branch-x");
    }

    // --- misc API surface ----------------------------------------------------

    #[test]
    fn constructors_validate_and_accessors_agree() {
        assert!(Cause::local("short").is_err());
        assert!(Cause::qualified(StoreId::new("s").unwrap(), "short").is_err());

        let q = Cause::qualified(StoreId::new("s").unwrap(), H).unwrap();
        assert_eq!(q.hash(), H);
        assert_eq!(q.store().unwrap().as_str(), "s");
        assert!(q.is_qualified());
        assert_eq!(q.render(), render(&q));

        // FromStr / TryFrom / Into<String> all agree with parse/render.
        use std::str::FromStr as _;
        assert_eq!(Cause::from_str(H).unwrap(), Cause::local(H).unwrap());
        assert_eq!(Cause::try_from(H.to_string()).unwrap(), Cause::local(H).unwrap());
        assert_eq!(String::from(q.clone()), render(&q));
        assert_eq!(StoreId::from_str("ok").unwrap().into_string(), "ok");
        assert_eq!(StoreId::new("ok").unwrap().as_ref() as &str, "ok");
        assert_eq!(StoreId::new("ok").unwrap().to_string(), "ok");
    }
}
