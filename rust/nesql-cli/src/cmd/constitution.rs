// SPDX-FileCopyrightText: 2026 INTERCHAINED LLC
// SPDX-License-Identifier: BUSL-1.1
// NEDB · © 2026 INTERCHAINED LLC × Eth-Interchained × Vex (Claude Opus 5)

//! `nesql constitution` — what the engine guarantees, and whether this CLI and
//! that engine can actually work together.
//!
//! The check is CLI-against-ENGINE, deliberately: the claim is built from what
//! THIS build requires and handed to the ENGINE to judge. The capability and
//! format checks are the ones with teeth — the engine answers them from its own
//! constitution, and a capability this CLI needs but the engine lacks is a
//! refusal.
//!
//! WHAT THE GRAMMAR DIGEST IS AND IS NOT WORTH, stated plainly because getting
//! this wrong is what made the command useless. `nesql` links `nedb-engine` in
//! process, so the NQL grammar it "implements" IS the engine's. Against this
//! engine that comparison is therefore trivially true, and pretending otherwise
//! would be the "hashed its own disk and printed verified" failure. It earns
//! its keep only against a remote engine of a different build, which is the
//! case the field exists for.
//!
//! What it must NOT be is the CLI's own command-surface digest. That is a hash
//! of `nesql --help`; the engine's is a hash of a structural description of
//! NQL. Sending one where the other was meant made every `nql.*` capability
//! unpromisable and reported INCOMPATIBLE between a 6.1.0 CLI and a 6.1.0
//! engine.

use nedb_engine::constitution as engine;
use nedb_engine::Db;
use serde_json::json;

use crate::out::{Exit, Report};

/// What this CLI requires of an engine.
///
/// The capability list is what the implemented commands actually touch — not
/// everything the engine can do. Requiring more than you use turns a harmless
/// version skew into a refusal to start.
fn claim() -> engine::ClientClaim {
    engine::ClientClaim {
        client_name: "nesql".to_string(),
        client_version: crate::CLI_VERSION.to_string(),
        // The NQL GRAMMAR digest, which is what this field means and what the
        // engine gates `nql.*` capabilities on.
        //
        // This used to send `crate::grammar::digest()` -- the digest of the
        // CLI's COMMAND SURFACE. Those hash different artifacts: the engine's
        // is over a structural description of NQL (clauses, operators,
        // keywords), the CLI's is over the text of `nesql --help`. They could
        // never be equal, so `nql.from` was refused on every run and
        // `nesql constitution` reported INCOMPATIBLE against the very engine
        // it was compiled against -- 6.1.0 against 6.1.0.
        //
        // The honest value is the grammar THIS BUILD implements, and the CLI
        // implements NQL by linking nedb-engine, so it is the engine's own.
        grammar_digest: engine::grammar_digest(),
        required_capabilities: vec![
            "state_root.compute".to_string(),
            "state_root.as_of".to_string(),
            "root.persist".to_string(),
            "root.verify.three_state".to_string(),
            "history.as_of".to_string(),
            "history.floor".to_string(),
            "collections.registry".to_string(),
            "replication.since".to_string(),
            "nql.from".to_string(),
        ],
        required_formats: vec![
            engine::FormatVersion { name: "state_root", version: 1 },
            engine::FormatVersion { name: "root_record", version: 1 },
            engine::FormatVersion { name: "collection_registry", version: 1 },
        ],
    }
}

pub fn run(_db: &Db) -> Report {
    let c = engine::constitution();
    let compat = engine::check_compatibility(&claim());

    let (exit, verdict, detail) = match &compat {
        engine::Compatibility::Compatible => {
            (Exit::Ok, "compatible".to_string(), Vec::new())
        }
        engine::Compatibility::CompatibleWithGaps { client_missing, engine_missing } => {
            // A gap is NOT an error. Additive change must not break an old
            // client, and a subset client is a legitimate client.
            let mut d = Vec::new();
            for m in engine_missing {
                d.push(format!("engine does not advertise: {}", m));
            }
            for m in client_missing {
                d.push(format!("this build did not ask for: {}", m));
            }
            (Exit::Ok, "compatible with gaps".to_string(), d)
        }
        engine::Compatibility::Incompatible { reasons } => {
            (Exit::Unsupported, "INCOMPATIBLE".to_string(), reasons.clone())
        }
    };

    let mut human = format!(
        "engine         {}\nnesql          {}\nverdict        {}\n",
        c.engine_version, crate::CLI_VERSION, verdict
    );
    human.push_str(&format!("constitution   {}\n", engine::digest()));
    // Two digests over two different things, printed under two different
    // names. Showing them as "engine X / nesql Y" invited the reading that
    // they ought to be equal -- which is how the command-surface digest ended
    // up in the NQL grammar field to begin with.
    human.push_str(&format!("nql grammar    {}\n", &c.grammar_digest));
    if claim().grammar_digest != c.grammar_digest {
        // Only reachable against a REMOTE engine of a different build. In
        // process the two are the same function, and saying so is more useful
        // than implying a comparison happened that could have failed.
        human.push_str(
            "               (this build compiled against a different NQL grammar — \
             `nql.*` capabilities cannot be promised)\n",
        );
    } else {
        human.push_str("               (agrees — same grammar this build compiled against)\n");
    }
    human.push_str(&format!(
        "command surface {}\n               (nesql's own verbs — NOT the NQL grammar, and \
         deliberately not compared to it)\n",
        crate::grammar::digest()
    ));
    if !detail.is_empty() {
        human.push('\n');
        for d in &detail {
            human.push_str(&format!("  · {}\n", d));
        }
    }
    human.push_str(&format!("\nformats        {}\n", c.formats.len()));
    for f in &c.formats {
        human.push_str(&format!("  {} v{}\n", f.name, f.version));
    }
    human.push_str(&format!("\ninvariants     {}\n", c.invariants.len()));
    for i in &c.invariants {
        human.push_str(&format!("  {}\n    {}\n", i.id, i.statement));
    }
    human.push_str(&format!("\ncapabilities   {}\n  {}", c.capabilities.len(),
        c.capabilities.join("\n  ")));

    Report::new(
        exit,
        json!({
            "verdict": verdict,
            "detail": detail,
            "compatibility": compat,
            "constitution": c,
            "constitution_digest": engine::digest(),
            "client": claim(),
        }),
        human,
    )
}
