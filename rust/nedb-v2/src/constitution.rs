// SPDX-FileCopyrightText: 2026 INTERCHAINED LLC
// SPDX-License-Identifier: BUSL-1.1
// NEDB · © 2026 INTERCHAINED LLC × Eth-Interchained × Vex (Claude Opus 5)

//! The Constitution — what this engine guarantees, in a form a client can check.
//!
//! neSQL (the query language and CLI) ships as a separate artifact from NEDB
//! (the engine). The two are versioned independently and will routinely be at
//! different versions on one machine. So "can this CLI drive this engine?" has
//! to be answerable by asking the engine, not by reading anything the CLI
//! brought with it.
//!
//! # The failure mode this module exists to design out
//!
//! The tempting implementation of "grammar verification" is: the CLI ships a
//! copy of the grammar, hashes it at startup, and prints VERIFIED. That proves
//! exactly one thing — the CLI can read its own disk. It says nothing about the
//! engine on the other end of the socket, which is the only party whose grammar
//! actually decides whether a query parses. A client that self-hashes is
//! strictly worse than one that does not check at all, because it reports
//! confidence it has not earned.
//!
//! So verification here is a two-party comparison. The engine publishes a
//! [`Constitution`] describing the language and formats IT implements; the
//! client sends a [`ClientClaim`] describing what IT needs; and
//! [`check_compatibility`] is evaluated ON THE ENGINE, against the engine's own
//! tables. The client never gets to supply the thing it is being checked
//! against.
//!
//! # What is in it
//!
//! - `formats`     — wire/on-disk formats, name + integer version.
//! - `capabilities`— named features. Additive and stable: a name, once shipped,
//!                   keeps its meaning forever, and new ones are appended.
//! - `invariants`  — the semantic promises, each with a stable id. These are the
//!                   rules a client may build on; they are transcribed from the
//!                   modules that enforce them, not invented here.
//! - `grammar_digest` — a digest of an explicit structural description of NQL.
//!
//! Hash construction follows the house pattern from [`crate::root`]: BLAKE2b-512
//! truncated to 32 bytes, every variable-length field preceded by its length as
//! u64 little-endian, and a distinct domain tag per kind of input.

use blake2::{Blake2b512, Digest as _};
use serde::{Deserialize, Deserializer, Serialize};

// ── Domain tags ───────────────────────────────────────────────────────────
//
// Spelled out in full, so a hexdump of a mismatched implementation says what it
// was hashing.

const TAG_GRAMMAR: &[u8] = b"nedb:constitution_v1:nql_grammar_surface";
const TAG_CONSTITUTION: &[u8] = b"nedb:constitution_v1:constitution";

/// Bumped when the ENCODING below changes, as opposed to the grammar it
/// describes. Two engines that describe the same language with different
/// encoders must not be told they disagree about the language, so the encoder
/// version is committed inside the digest and moves in lockstep with any change
/// to the encoding rules.
const GRAMMAR_SURFACE_VERSION: u32 = 1;

fn h(parts: &[&[u8]]) -> [u8; 32] {
    let mut hasher = Blake2b512::new();
    for p in parts {
        hasher.update(p);
    }
    let out = hasher.finalize();
    let mut d = [0u8; 32];
    d.copy_from_slice(&out[..32]);
    d
}

/// Length-prefix a field: u64 little-endian length, then the bytes. Makes
/// concatenation unambiguous — `("ab","c")` and `("a","bc")` cannot collide.
fn lp(buf: &mut Vec<u8>, bytes: &[u8]) {
    buf.extend_from_slice(&(bytes.len() as u64).to_le_bytes());
    buf.extend_from_slice(bytes);
}

fn count(buf: &mut Vec<u8>, n: usize) {
    buf.extend_from_slice(&(n as u64).to_le_bytes());
}

// ── Deserialization of engine-owned strings ───────────────────────────────
//
// The Constitution's fields are `&'static str` because on the engine side they
// are compile-time constants, and that is the honest type for them. Crossing a
// process boundary means the CLIENT side must also be able to parse one — and a
// borrowed `&'static str` cannot be deserialized out of a buffer that will be
// dropped. So each type deserializes through an owned mirror and interns the
// result.
//
// Interning leaks. That is deliberate and bounded: a client parses a
// Constitution once per engine it connects to, at handshake time. The engine
// itself never deserializes a Constitution — the type it accepts from the
// network is `ClientClaim`, which is `String` throughout — so no untrusted,
// repeatable input path reaches this.
fn intern(s: String) -> &'static str {
    Box::leak(s.into_boxed_str())
}

#[derive(Deserialize)]
struct OwnedFormatVersion {
    name: String,
    version: u32,
}

#[derive(Deserialize)]
struct OwnedInvariant {
    id: String,
    statement: String,
}

#[derive(Deserialize)]
struct OwnedConstitution {
    engine_version: String,
    formats: Vec<OwnedFormatVersion>,
    capabilities: Vec<String>,
    invariants: Vec<OwnedInvariant>,
    grammar_digest: String,
}

impl From<OwnedFormatVersion> for FormatVersion {
    fn from(o: OwnedFormatVersion) -> Self {
        FormatVersion { name: intern(o.name), version: o.version }
    }
}

impl From<OwnedInvariant> for Invariant {
    fn from(o: OwnedInvariant) -> Self {
        Invariant { id: intern(o.id), statement: intern(o.statement) }
    }
}

impl From<OwnedConstitution> for Constitution {
    fn from(o: OwnedConstitution) -> Self {
        Constitution {
            engine_version: intern(o.engine_version),
            formats: o.formats.into_iter().map(Into::into).collect(),
            capabilities: o.capabilities.into_iter().map(intern).collect(),
            invariants: o.invariants.into_iter().map(Into::into).collect(),
            grammar_digest: o.grammar_digest,
        }
    }
}

// serde's derive scans field types for lifetimes and would emit `'de: 'static`
// even under `#[serde(from = ...)]`, which makes the type undeserializable from
// any temporary buffer. Written out by hand instead: deserialize the owned
// mirror, then intern.
macro_rules! deserialize_via_owned {
    ($t:ty, $owned:ty) => {
        impl<'de> Deserialize<'de> for $t {
            fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
                <$owned>::deserialize(d).map(Into::into)
            }
        }
    };
}

deserialize_via_owned!(FormatVersion, OwnedFormatVersion);
deserialize_via_owned!(Invariant, OwnedInvariant);
deserialize_via_owned!(Constitution, OwnedConstitution);

// ── The manifest ──────────────────────────────────────────────────────────

/// A format this engine implements, by name and integer version.
///
/// The conventional spelling elsewhere in the codebase is `state_root_v1` —
/// that is this pair, written as one token. It is split here because a
/// compatibility check has to compare VERSIONS, and `"state_root_v1" !=
/// "state_root_v2"` is a string inequality that cannot say which is newer or
/// what the engine has instead.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct FormatVersion {
    pub name: &'static str,
    pub version: u32,
}

impl FormatVersion {
    /// The single-token spelling used in records and on the wire.
    pub fn spelled(&self) -> String {
        format!("{}_v{}", self.name, self.version)
    }
}

/// A semantic promise, with an id stable across engine versions.
///
/// The id is what a client or a test pins against; the statement is for humans
/// and may be reworded. Ids are never reused for a different rule — retiring a
/// guarantee means removing the id, which is a breaking change by construction.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Invariant {
    pub id: &'static str,
    pub statement: &'static str,
}

/// Everything this engine guarantees, packaged for a client to verify against.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Constitution {
    pub engine_version: &'static str,
    pub formats: Vec<FormatVersion>,
    pub capabilities: Vec<&'static str>,
    pub invariants: Vec<Invariant>,
    /// Digest of the grammar THIS ENGINE implements. Never a digest of
    /// something the client supplied.
    pub grammar_digest: String,
}

// ── Formats ───────────────────────────────────────────────────────────────

/// Ordered. The order is committed by the digest, so entries are appended,
/// never inserted or reordered.
const FORMATS: &[(&str, u32)] = &[
    // The logical-content state root. `crate::root`.
    ("state_root", 1),
    // The DAG node record. `crate::store::Node`.
    ("node", 2),
    // Content-addressed object layout: objects/{hash[0:2]}/{hash[2:]}.
    ("object_store", 2),
    // Packed segment substrate. Implemented and readable/writable, but opt-in
    // at runtime via NEDB_DAG_V3 / --dag-v3; default storage stays v2.
    ("segment", 3),
    // `_nedb.collections` record shape — durable collection identity.
    ("collection_registry", 1),
    // `_nedb.roots` record shape — a StateRoot plus the seq it describes.
    ("root_record", 1),
];

// ── Capabilities ──────────────────────────────────────────────────────────

/// Everything under this prefix is DEFINED IN TERMS OF THE NQL GRAMMAR. That
/// property is what makes the grammar-digest rule in [`check_compatibility`]
/// decidable, so the prefix is load-bearing rather than cosmetic.
const GRAMMAR_CAPABILITY_PREFIX: &str = "nql.";

/// Ordered, additive, stable. A name never changes meaning; new capabilities go
/// at the end of their group.
const CAPABILITIES: &[&str] = &[
    // Language surface. Each of these names a clause or predicate form in
    // GRAMMAR below, and therefore depends on the grammar digest.
    "nql.from",
    "nql.as_of",
    "nql.valid_as_of",
    "nql.where.comparison",
    "nql.where.boolean",
    "nql.where.in",
    "nql.where.between",
    "nql.where.like",
    "nql.where.regex_subset",
    "nql.where.is_null",
    "nql.search",
    "nql.order_by.multi_key",
    "nql.limit",
    "nql.offset",
    "nql.group_by",
    "nql.aggregate.bare",
    "nql.having",
    "nql.trace",
    "nql.traverse",
    // Engine surface. Independent of how a query is spelled.
    "state_root.compute",
    "state_root.as_of",
    "root.persist",
    "root.verify.three_state",
    "history.as_of",
    "history.floor",
    "collections.registry",
    "collections.drop",
    "delete.tombstone",
    "graph.edges",
    "index.sorted",
    "replication.since",
    "storage.encryption.aes256gcm",
    "storage.compaction",
    "storage.segment_v3",
    "wire.http",
    "wire.pgwire",
];

/// Is this capability's meaning fixed by the grammar?
fn depends_on_grammar(capability: &str) -> bool {
    capability.starts_with(GRAMMAR_CAPABILITY_PREFIX)
}

// ── Invariants ────────────────────────────────────────────────────────────

/// Transcribed from the modules that enforce them — `crate::namespace`,
/// `crate::root`, `crate::db`, `crate::store`, `crate::nql`. Nothing here is a
/// guarantee the engine does not actually make.
const INVARIANTS: &[(&str, &str)] = &[
    (
        "INV-HISTORY-APPEND-ONLY",
        "Committed history is append-only: no operation rewrites or removes a committed node, \
         so a revert, rollback or merge is expressed as new nodes appended to history rather \
         than as an edit to the old ones.",
    ),
    (
        "INV-OBJECT-IMMUTABLE",
        "An object is addressed by the BLAKE2b digest of its stored bytes, written atomically, \
         and hash-verified on every read, so a stored version can never change under a reader.",
    ),
    (
        "INV-DELETE-TOMBSTONE",
        "A delete writes a tombstone node and moves the id to the graveyard index; the prior \
         versions remain reachable, so a delete hides a document rather than erasing it.",
    ),
    (
        "INV-RESERVED-NAMESPACE",
        "Everything under the `_nedb` prefix is engine-owned and refused to user writes, because \
         a client able to write there could forge the namespace a state root commits to.",
    ),
    (
        "INV-COLLECTION-BY-RECORD",
        "A collection exists because a record in `_nedb.collections` says it is live, never \
         because a directory is lying around, so emptying a collection does not destroy it and \
         only an explicit drop does.",
    ),
    (
        "INV-NAME-BYTE-EXACT",
        "A collection name is committed as the exact UTF-8 bytes it was created with — never \
         Unicode-normalised and never trimmed — so an unusable name is refused at creation \
         rather than silently rewritten into a different collection.",
    ),
    (
        "INV-ROOT-LOGICAL-CONTENT",
        "A state root commits to logical content rather than to object hashes, so it is \
         identical across encrypted and plaintext replicas and across disk and memory holding \
         the same data.",
    ),
    (
        "INV-ROOT-CURRENT-STATE",
        "A state root commits to what the database currently says — live collections and live \
         documents, with tombstones contributing nothing — and not to the history by which that \
         state was reached, which the running Merkle head covers instead.",
    ),
    (
        "INV-MERKLE-PROMOTE-ODD",
        "An odd leaf is promoted unchanged to the next level and never duplicated, because leaf \
         duplication is the CVE-2012-2459 construction in which two different leaf sets produce \
         one root.",
    ),
    (
        "INV-MERKLE-COUNT-COMMITTED",
        "The leaf count is committed alongside the fold in each subtree root, so promotion can \
         never leave two different leaf sets sharing a tree shape.",
    ),
    (
        "INV-COMPACTION-ONLY-DISCARD",
        "Compaction is the only operation that discards history, it runs only when an operator \
         explicitly asks, and nothing — no timer, no HTTP route — triggers it automatically.",
    ),
    (
        "INV-VERIFY-SEPARATE-FACTS",
        "A persisted root may outlive the material needed to recompute it, so verification \
         reports record validity and recomputation outcome as two separate facts and never \
         collapses `could not check` into either pass or fail.",
    ),
    (
        "INV-QUERY-STRICT",
        "A token the parser does not recognise is a query error, never a skipped token, because \
         silently dropping a clause answers a different question than the one that was asked.",
    ),
];

// ── The grammar surface ───────────────────────────────────────────────────

/// One clause of the query grammar, with the forms it accepts.
struct GrammarClause {
    name: &'static str,
    forms: &'static [&'static str],
}

/// WHY THIS IS DATA AND NOT A HASH OF `nql.rs`.
///
/// Hashing the parser source is the cheap implementation and it is wrong in
/// both directions. It is too sensitive: a renamed local, a reworded comment, a
/// refactor of the lexer, a rustfmt pass — every one of those changes the file
/// digest while the language stays byte-identical, and every one would tell a
/// perfectly good client it is incompatible. And it is too coarse: a source
/// digest cannot say WHAT differs, so a mismatch yields "these two hex strings
/// are unequal" and no path to a diagnosis. It also cannot be reproduced by a
/// second implementation in another language, which is the whole point of
/// publishing a digest across a process boundary.
///
/// So the hashed artifact is this: an explicit, ordered, versioned description
/// of the language surface. It changes exactly when the language changes, a
/// second implementation can produce it from a spec rather than from our
/// source tree, and the structure survives into the diagnostic — the clause
/// list is inspectable, so a future tool can report which clause differs
/// instead of only that something does.
///
/// ORDER IS PART OF THE LANGUAGE and is committed here positionally. The
/// canonical form is:
///
/// ```text
/// FROM coll [AS OF seq] [VALID AS OF "date"] [WHERE p] [SEARCH "t"]
///           [ORDER BY ...] [LIMIT n] [OFFSET n] [GROUP BY ...]
///           [<aggregate>] [HAVING p] [TRACE e [REVERSE]] [TRAVERSE r]
/// ```
///
/// `FROM` is positional and mandatory; the parser's clause loop then accepts
/// the optional clauses in any order, so the sequence above is the canonical
/// spelling a client should emit rather than a restriction the parser enforces.
/// It is committed because a client and an engine that disagree about the
/// canonical order will produce queries that read as valid and sort or group
/// differently to a reader.
const GRAMMAR: &[GrammarClause] = &[
    GrammarClause { name: "FROM", forms: &["FROM <collection>"] },
    GrammarClause { name: "AS OF", forms: &["AS OF <seq:number>"] },
    GrammarClause { name: "VALID AS OF", forms: &["VALID AS OF <date:string>"] },
    GrammarClause {
        name: "WHERE",
        forms: &[
            // The predicate grammar, loosest binding first.
            "<predicate> := <or>",
            "<or> := <and> [OR <and>]*",
            "<and> := <not> [AND <not>]*",
            "<not> := [NOT] <primary>",
            "<primary> := ( <predicate> ) | <comparison>",
            "<comparison> := <field> (= | != | > | < | >= | <=) <value>",
            "<comparison> := <field> [NOT] IN ( <value> [, <value>]* )",
            "<comparison> := <field> [NOT] BETWEEN <value> AND <value>",
            "<comparison> := <field> [NOT] LIKE <pattern:string>",
            "<comparison> := <field> [NOT] ILIKE <pattern:string>",
            "<comparison> := <field> (~ | ~* | !~ | !~*) <pattern:string>",
            "<comparison> := <field> IS [NOT] NULL",
            "<value> := <string> | <number> | TRUE | FALSE | NULL | <bare_ident_as_string>",
            // Semantics that two implementations would otherwise guess at.
            "BETWEEN is inclusive on both bounds",
            "LIKE wildcards: % matches any run, _ matches any one character",
            "regex subset: ^ $ . | ( ) [ ] * + ? and literal text; any other metacharacter is refused",
            "IS NULL is true when the field is JSON null OR absent",
            "a repeated WHERE clause is a conjunction",
        ],
    },
    GrammarClause { name: "SEARCH", forms: &["SEARCH <text:string>"] },
    GrammarClause {
        name: "ORDER BY",
        forms: &["ORDER BY <field> [ASC|DESC] [, <field> [ASC|DESC]]*", "default direction is ASC"],
    },
    GrammarClause { name: "LIMIT", forms: &["LIMIT <n:non-negative-number>"] },
    GrammarClause { name: "OFFSET", forms: &["OFFSET <n:non-negative-number>"] },
    GrammarClause {
        name: "GROUP BY",
        forms: &[
            "GROUP BY <field>",
            "GROUP BY <field> COUNT",
            "GROUP BY <field> (SUM|AVG|MIN|MAX) <field>",
            "a bare GROUP BY implies COUNT",
        ],
    },
    GrammarClause {
        name: "<aggregate>",
        forms: &[
            "COUNT",
            "(SUM|AVG|MIN|MAX) <field>",
            "an ungrouped aggregate returns exactly one row",
            "at most one aggregate per query",
        ],
    },
    GrammarClause {
        name: "HAVING",
        forms: &["HAVING <predicate>", "HAVING filters aggregated rows, WHERE filters input rows"],
    },
    GrammarClause { name: "TRACE", forms: &["TRACE <edge_type> [REVERSE]"] },
    GrammarClause { name: "TRAVERSE", forms: &["TRAVERSE <relation>"] },
];

/// Every operator the lexer produces. Part of the surface: an engine that lexes
/// `!~*` and one that does not are not running the same language.
const GRAMMAR_OPERATORS: &[&str] = &["=", "!=", ">", "<", ">=", "<=", "~", "~*", "!~", "!~*"];

/// Every reserved word. Reserved words are also accepted in field positions,
/// with their original spelling preserved, so this set is not a list of names a
/// document may not use — it is the set the lexer will tag as a keyword.
const GRAMMAR_KEYWORDS: &[&str] = &[
    "FROM", "AS", "OF", "VALID", "WHERE", "AND", "OR", "ORDER", "BY", "ASC", "DESC", "LIMIT",
    "OFFSET", "GROUP", "HAVING", "COUNT", "SUM", "AVG", "MIN", "MAX", "TRACE", "TRAVERSE",
    "REVERSE", "SEARCH", "NOT", "NULL", "TRUE", "FALSE", "IN", "BETWEEN", "LIKE", "ILIKE", "IS",
];

/// Digest the structural description above.
fn grammar_digest_of(
    clauses: &[GrammarClause],
    operators: &[&str],
    keywords: &[&str],
) -> String {
    let mut buf = Vec::new();
    buf.extend_from_slice(&(GRAMMAR_SURFACE_VERSION as u64).to_le_bytes());
    count(&mut buf, clauses.len());
    for c in clauses {
        lp(&mut buf, c.name.as_bytes());
        count(&mut buf, c.forms.len());
        for f in c.forms {
            lp(&mut buf, f.as_bytes());
        }
    }
    count(&mut buf, operators.len());
    for o in operators {
        lp(&mut buf, o.as_bytes());
    }
    count(&mut buf, keywords.len());
    for k in keywords {
        lp(&mut buf, k.as_bytes());
    }
    hex::encode(h(&[TAG_GRAMMAR, &buf]))
}

/// The digest of the grammar THIS ENGINE implements.
pub fn grammar_digest() -> String {
    grammar_digest_of(GRAMMAR, GRAMMAR_OPERATORS, GRAMMAR_KEYWORDS)
}

// ── Construction and digest ───────────────────────────────────────────────

/// This engine's Constitution.
pub fn constitution() -> Constitution {
    Constitution {
        engine_version: env!("CARGO_PKG_VERSION"),
        formats: FORMATS
            .iter()
            .map(|(name, version)| FormatVersion { name, version: *version })
            .collect(),
        capabilities: CAPABILITIES.to_vec(),
        invariants: INVARIANTS
            .iter()
            .map(|(id, statement)| Invariant { id, statement })
            .collect(),
        grammar_digest: grammar_digest(),
    }
}

impl Constitution {
    /// A stable digest of the whole Constitution.
    ///
    /// Built from an explicit ordered encoding rather than from serialized JSON:
    /// every list here is a `Vec` walked in declaration order, no hash map is
    /// involved at any point, and the counts are committed so a truncated list
    /// cannot digest as a shorter one. Declaration order IS committed — the
    /// lists are append-only, so reordering them is a change to the artifact and
    /// should read as one.
    pub fn digest(&self) -> String {
        let mut buf = Vec::new();
        lp(&mut buf, self.engine_version.as_bytes());

        count(&mut buf, self.formats.len());
        for f in &self.formats {
            lp(&mut buf, f.name.as_bytes());
            buf.extend_from_slice(&(f.version as u64).to_le_bytes());
        }

        count(&mut buf, self.capabilities.len());
        for c in &self.capabilities {
            lp(&mut buf, c.as_bytes());
        }

        count(&mut buf, self.invariants.len());
        for i in &self.invariants {
            lp(&mut buf, i.id.as_bytes());
            lp(&mut buf, i.statement.as_bytes());
        }

        lp(&mut buf, self.grammar_digest.as_bytes());
        hex::encode(h(&[TAG_CONSTITUTION, &buf]))
    }
}

/// Stable digest of this engine's whole Constitution.
pub fn digest() -> String {
    constitution().digest()
}

// ── Compatibility ─────────────────────────────────────────────────────────

/// What a client says it needs.
///
/// Note what this does NOT carry: the client's full vocabulary. It carries what
/// the client REQUIRES. That asymmetry is deliberate — a client should not have
/// to enumerate everything it knows in order to connect — and it bounds what the
/// engine can honestly report as a gap. See [`Compatibility::CompatibleWithGaps`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ClientClaim {
    pub client_name: String,
    pub client_version: String,
    /// The digest of the grammar the CLIENT implements. Supplied for comparison
    /// only; it is never the thing the engine hashes to answer the question.
    pub grammar_digest: String,
    pub required_capabilities: Vec<String>,
    pub required_formats: Vec<FormatVersion>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", tag = "verdict")]
pub enum Compatibility {
    Compatible,
    /// The client understands a superset/subset that still interoperates.
    ///
    /// `client_missing` lists engine capabilities the claim did not name. Since
    /// a claim carries requirements rather than a vocabulary, this is "you did
    /// not ask for these", not "you cannot do these" — it is informational, and
    /// it is never an error, because an engine that grew a capability must not
    /// thereby break every client written before it.
    ///
    /// `engine_missing` lists things the engine may not be able to honour that
    /// the client might use.
    CompatibleWithGaps { client_missing: Vec<String>, engine_missing: Vec<String> },
    Incompatible { reasons: Vec<String> },
}

impl Compatibility {
    /// The only way to build an `Incompatible`.
    ///
    /// A verdict of incompatible with no reason attached is a bug that produces
    /// an unactionable error at the far end of a socket, so it panics here
    /// rather than shipping an empty list to a user.
    fn incompatible(reasons: Vec<String>) -> Self {
        assert!(
            !reasons.is_empty(),
            "Incompatible with no reasons: a refusal a caller cannot act on is a bug, not a verdict"
        );
        Compatibility::Incompatible { reasons }
    }

    pub fn is_compatible(&self) -> bool {
        !matches!(self, Compatibility::Incompatible { .. })
    }
}

/// Decide whether a client can drive THIS engine.
///
/// Evaluated against the engine's own tables, never against anything in the
/// claim beyond the claim's requirements. That is the whole design: the client
/// supplies the question, the engine supplies the answer.
///
/// # The grammar-digest rule
///
/// A digest mismatch alone is a GAP, not a refusal. Two reasons. A client may
/// legitimately implement a subset — a scripting binding that only ever emits
/// `FROM c WHERE k = v` does not care that the engine also has `TRAVERSE`, and
/// refusing it would be refusing a client that works. And the surface
/// description is versioned, so a mismatch can also mean "same language,
/// different encoder generation", which is not a language difference at all.
///
/// But a mismatch stops being harmless the moment the client REQUIRES something
/// whose meaning is fixed by the grammar. `nql.where.regex_subset` is not a flag
/// the engine can promise in the abstract; it names a specific set of accepted
/// patterns, and if the two sides do not agree on the grammar they do not agree
/// on which set. Answering "yes, supported" there would be exactly the
/// self-hashing failure in a new costume — a confident yes backed by nothing
/// the two parties actually share. So: digests differ AND a required capability
/// is grammar-defined → Incompatible, naming the capability and both digests.
pub fn check_compatibility(client: &ClientClaim) -> Compatibility {
    let engine = constitution();
    let grammar_agrees = client.grammar_digest == engine.grammar_digest;
    let mut reasons: Vec<String> = Vec::new();

    for required in &client.required_capabilities {
        let engine_has = engine.capabilities.iter().any(|c| c == required);
        if !engine_has {
            reasons.push(format!(
                "capability {:?} is required by {} {} and is not implemented by nedb-engine {}",
                required, client.client_name, client.client_version, engine.engine_version
            ));
        } else if !grammar_agrees && depends_on_grammar(required) {
            reasons.push(format!(
                "capability {:?} is defined by the NQL grammar, and the two sides do not agree on \
                 that grammar (client {}, engine {}), so the engine cannot promise the client's \
                 reading of it",
                required, client.grammar_digest, engine.grammar_digest
            ));
        }
    }

    for required in &client.required_formats {
        if engine
            .formats
            .iter()
            .any(|f| f.name == required.name && f.version == required.version)
        {
            continue;
        }
        let have: Vec<String> = engine
            .formats
            .iter()
            .filter(|f| f.name == required.name)
            .map(|f| format!("v{}", f.version))
            .collect();
        if have.is_empty() {
            reasons.push(format!(
                "format {:?} is required at v{} and this engine implements no version of it",
                required.name, required.version
            ));
        } else {
            reasons.push(format!(
                "format {:?} is required at v{}; this engine implements {}",
                required.name,
                required.version,
                have.join(", ")
            ));
        }
    }

    if !reasons.is_empty() {
        return Compatibility::incompatible(reasons);
    }

    // Everything required is present. What remains is difference without
    // conflict, and difference without conflict is reported, not refused.
    let client_missing: Vec<String> = engine
        .capabilities
        .iter()
        .filter(|c| !client.required_capabilities.iter().any(|r| r == *c))
        .map(|c| c.to_string())
        .collect();

    let mut engine_missing: Vec<String> = Vec::new();
    if !grammar_agrees {
        // A grammar mismatch is unknown in BOTH directions: neither side can
        // enumerate the other's forms from a digest. It is recorded on the
        // engine side because that is the side that decides whether a query
        // parses — the client's extra forms are the ones at risk.
        engine_missing.push(format!(
            "nql_grammar_surface: client {} vs engine {} — the engine may not accept every form \
             this client can emit; no required capability depends on the grammar, so this is a \
             gap rather than a refusal",
            client.grammar_digest, engine.grammar_digest
        ));
    }

    if client_missing.is_empty() && engine_missing.is_empty() {
        Compatibility::Compatible
    } else {
        Compatibility::CompatibleWithGaps { client_missing, engine_missing }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A claim that matches this engine exactly.
    fn identical_claim() -> ClientClaim {
        let c = constitution();
        ClientClaim {
            client_name: "nesql".into(),
            client_version: "1.0.0".into(),
            grammar_digest: c.grammar_digest.clone(),
            required_capabilities: c.capabilities.iter().map(|s| s.to_string()).collect(),
            required_formats: c.formats.clone(),
        }
    }

    #[test]
    fn the_digest_is_stable_across_calls() {
        let a = digest();
        let b = digest();
        assert_eq!(a, b);
        assert_eq!(a.len(), 64, "32 bytes, hex");
        // And recomputing from a fresh Constitution agrees.
        assert_eq!(a, constitution().digest());
    }

    #[test]
    fn adding_a_capability_changes_the_digest() {
        // Digest a MODIFIED COPY; the engine's own tables are untouched.
        let base = constitution();
        let mut grown = base.clone();
        grown.capabilities.push("nql.window_functions");
        assert_ne!(base.digest(), grown.digest());
    }

    #[test]
    fn reordering_capabilities_changes_the_digest() {
        // Order is committed on purpose: these lists are append-only, so a
        // reorder is a change to the artifact and must read as one.
        let base = constitution();
        let mut shuffled = base.clone();
        shuffled.capabilities.swap(0, 1);
        assert_ne!(base.digest(), shuffled.digest());
    }

    #[test]
    fn length_prefixing_stops_the_concatenation_collision() {
        let base = constitution();
        let mut a = base.clone();
        let mut b = base.clone();
        a.capabilities.extend(["xy", "z"]);
        b.capabilities.extend(["x", "yz"]);
        assert_ne!(a.digest(), b.digest());
    }

    #[test]
    fn the_grammar_digest_is_stable_and_is_not_the_constitution_digest() {
        assert_eq!(grammar_digest(), grammar_digest());
        assert_eq!(grammar_digest().len(), 64);
        // Distinct domain tags, so one can never be presented as the other.
        assert_ne!(grammar_digest(), digest());
    }

    #[test]
    fn a_grammar_change_changes_the_grammar_digest() {
        let mine = grammar_digest();
        let theirs = grammar_digest_of(
            &GRAMMAR[..GRAMMAR.len() - 1], // an engine without TRAVERSE
            GRAMMAR_OPERATORS,
            GRAMMAR_KEYWORDS,
        );
        assert_ne!(mine, theirs);
    }

    #[test]
    fn an_identical_client_is_compatible() {
        assert_eq!(check_compatibility(&identical_claim()), Compatibility::Compatible);
    }

    #[test]
    fn an_unknown_capability_is_incompatible_and_the_reason_names_it() {
        let mut claim = identical_claim();
        claim.required_capabilities.push("nql.window_functions".into());
        match check_compatibility(&claim) {
            Compatibility::Incompatible { reasons } => {
                assert!(
                    reasons.iter().any(|r| r.contains("nql.window_functions")),
                    "reason must name the capability: {:?}",
                    reasons
                );
            }
            other => panic!("expected Incompatible, got {:?}", other),
        }
    }

    #[test]
    fn a_future_format_version_is_incompatible_and_names_both_versions() {
        let mut claim = identical_claim();
        claim.required_formats.push(FormatVersion { name: "state_root", version: 2 });
        match check_compatibility(&claim) {
            Compatibility::Incompatible { reasons } => {
                let r = reasons.join(" | ");
                assert!(r.contains("state_root"), "{}", r);
                assert!(r.contains("v2"), "must name what was asked for: {}", r);
                assert!(r.contains("v1"), "must name what the engine has: {}", r);
            }
            other => panic!("expected Incompatible, got {:?}", other),
        }
    }

    #[test]
    fn an_unknown_format_name_is_incompatible_and_says_so_distinctly() {
        let mut claim = identical_claim();
        claim.required_formats.push(FormatVersion { name: "quantum_root", version: 1 });
        match check_compatibility(&claim) {
            Compatibility::Incompatible { reasons } => {
                let r = reasons.join(" | ");
                assert!(r.contains("quantum_root") && r.contains("no version"), "{}", r);
            }
            other => panic!("expected Incompatible, got {:?}", other),
        }
    }

    #[test]
    fn a_capability_the_client_never_asked_for_is_a_gap_not_an_error() {
        // The old-client case: the engine grew, the client did not. Additive
        // changes must not break anybody.
        let mut claim = identical_claim();
        claim.required_capabilities.retain(|c| c != "nql.traverse" && c != "wire.pgwire");
        match check_compatibility(&claim) {
            Compatibility::CompatibleWithGaps { client_missing, engine_missing } => {
                assert!(client_missing.contains(&"nql.traverse".to_string()));
                assert!(client_missing.contains(&"wire.pgwire".to_string()));
                assert!(engine_missing.is_empty(), "{:?}", engine_missing);
            }
            other => panic!("expected a gap, got {:?}", other),
        }
    }

    #[test]
    fn a_grammar_digest_mismatch_alone_is_a_gap_not_an_incompatibility() {
        // A client that requires only engine-side capabilities does not care
        // that its grammar differs.
        let engine = constitution();
        let claim = ClientClaim {
            client_name: "nedb-admin".into(),
            client_version: "0.2.0".into(),
            grammar_digest: "00".repeat(32),
            required_capabilities: vec!["root.verify.three_state".into(), "state_root.compute".into()],
            required_formats: vec![FormatVersion { name: "state_root", version: 1 }],
        };
        match check_compatibility(&claim) {
            Compatibility::CompatibleWithGaps { engine_missing, .. } => {
                let joined = engine_missing.join(" | ");
                assert!(joined.contains(&"00".repeat(32)), "must report the client digest: {}", joined);
                assert!(joined.contains(&engine.grammar_digest), "must report the engine digest: {}", joined);
            }
            other => panic!("expected a gap, got {:?}", other),
        }
    }

    #[test]
    fn a_grammar_mismatch_plus_a_grammar_dependent_requirement_is_incompatible() {
        // The point of the whole module: a client cannot be told "yes, you have
        // regex predicates" by an engine it does not share a grammar with.
        let claim = ClientClaim {
            client_name: "nesql".into(),
            client_version: "9.9.9".into(),
            grammar_digest: "ff".repeat(32),
            required_capabilities: vec!["nql.where.regex_subset".into()],
            required_formats: vec![],
        };
        match check_compatibility(&claim) {
            Compatibility::Incompatible { reasons } => {
                let r = reasons.join(" | ");
                assert!(r.contains("nql.where.regex_subset"), "{}", r);
                assert!(r.contains(&"ff".repeat(32)), "must name the client digest: {}", r);
                assert!(r.contains(&grammar_digest()), "must name the engine digest: {}", r);
            }
            other => panic!("expected Incompatible, got {:?}", other),
        }
    }

    #[test]
    fn a_grammar_mismatch_does_not_poison_non_grammar_capabilities() {
        // Same mismatched digest, but nothing grammar-defined is required, so
        // the engine-side capability still checks out.
        let claim = ClientClaim {
            client_name: "nesql".into(),
            client_version: "9.9.9".into(),
            grammar_digest: "ff".repeat(32),
            required_capabilities: vec!["storage.compaction".into()],
            required_formats: vec![],
        };
        assert!(check_compatibility(&claim).is_compatible());
    }

    #[test]
    fn every_incompatible_verdict_carries_at_least_one_reason() {
        let engine = constitution();
        let mut claims = vec![];

        // Unknown capability.
        let mut c = identical_claim();
        c.required_capabilities.push("does.not.exist".into());
        claims.push(c);

        // Future version of every known format.
        let mut c = identical_claim();
        c.required_formats = engine
            .formats
            .iter()
            .map(|f| FormatVersion { name: f.name, version: f.version + 1 })
            .collect();
        claims.push(c);

        // Unknown format name.
        let mut c = identical_claim();
        c.required_formats.push(FormatVersion { name: "nope", version: 7 });
        claims.push(c);

        // Grammar mismatch with a grammar-dependent requirement, one per
        // grammar capability, so no single one of them can slip through.
        for cap in CAPABILITIES.iter().filter(|c| depends_on_grammar(c)) {
            claims.push(ClientClaim {
                client_name: "x".into(),
                client_version: "0".into(),
                grammar_digest: "ab".repeat(32),
                required_capabilities: vec![cap.to_string()],
                required_formats: vec![],
            });
        }

        let mut seen_incompatible = 0;
        for claim in &claims {
            if let Compatibility::Incompatible { reasons } = check_compatibility(claim) {
                seen_incompatible += 1;
                assert!(!reasons.is_empty(), "empty reasons for {:?}", claim.client_name);
                for r in &reasons {
                    assert!(!r.trim().is_empty(), "blank reason for {:?}", claim.client_name);
                }
            }
        }
        assert_eq!(seen_incompatible, claims.len(), "every one of these must be refused");
    }

    #[test]
    #[should_panic(expected = "Incompatible with no reasons")]
    fn an_incompatible_with_no_reasons_is_refused_at_construction() {
        let _ = Compatibility::incompatible(vec![]);
    }

    #[test]
    fn the_invariants_are_present_uniquely_identified_and_non_empty() {
        let c = constitution();
        assert!(!c.invariants.is_empty());
        let mut ids: Vec<&str> = c.invariants.iter().map(|i| i.id).collect();
        let total = ids.len();
        ids.sort_unstable();
        ids.dedup();
        assert_eq!(ids.len(), total, "invariant ids must be unique");
        for i in &c.invariants {
            assert!(!i.id.trim().is_empty(), "an invariant with no id cannot be pinned");
            assert!(!i.statement.trim().is_empty(), "invariant {} has no statement", i.id);
        }
        // The charter's minimum set, by id.
        for required in [
            "INV-HISTORY-APPEND-ONLY",
            "INV-DELETE-TOMBSTONE",
            "INV-RESERVED-NAMESPACE",
            "INV-COLLECTION-BY-RECORD",
            "INV-ROOT-LOGICAL-CONTENT",
            "INV-MERKLE-PROMOTE-ODD",
            "INV-COMPACTION-ONLY-DISCARD",
            "INV-VERIFY-SEPARATE-FACTS",
        ] {
            assert!(ids.contains(&required), "missing invariant {}", required);
        }
    }

    #[test]
    fn capabilities_and_formats_are_unique_and_non_empty() {
        let c = constitution();
        assert!(!c.capabilities.is_empty());
        let mut caps = c.capabilities.clone();
        let n = caps.len();
        caps.sort_unstable();
        caps.dedup();
        assert_eq!(caps.len(), n, "capability names must be unique");
        for cap in &c.capabilities {
            assert!(!cap.trim().is_empty());
        }
        let mut fs: Vec<String> = c.formats.iter().map(|f| f.spelled()).collect();
        let n = fs.len();
        fs.sort();
        fs.dedup();
        assert_eq!(fs.len(), n, "format name+version pairs must be unique");
    }

    #[test]
    fn constitution_survives_a_json_round_trip() {
        let c = constitution();
        let json = serde_json::to_string(&c).unwrap();
        let back: Constitution = serde_json::from_str(&json).unwrap();
        assert_eq!(c, back);
        // The digest is the thing that actually crosses the wire, so it has to
        // survive the trip too.
        assert_eq!(c.digest(), back.digest());
    }

    #[test]
    fn client_claim_and_compatibility_survive_a_json_round_trip() {
        let claim = identical_claim();
        let back: ClientClaim = serde_json::from_str(&serde_json::to_string(&claim).unwrap()).unwrap();
        assert_eq!(claim, back);

        for verdict in [
            Compatibility::Compatible,
            Compatibility::CompatibleWithGaps {
                client_missing: vec!["nql.traverse".into()],
                engine_missing: vec!["nql_grammar_surface: ...".into()],
            },
            Compatibility::Incompatible { reasons: vec!["because".into()] },
        ] {
            let json = serde_json::to_string(&verdict).unwrap();
            let back: Compatibility = serde_json::from_str(&json).unwrap();
            assert_eq!(verdict, back);
        }
    }
}
