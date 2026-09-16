#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 INTERCHAINED LLC
# SPDX-License-Identifier: BUSL-1.1
"""Builds the deep-dive documentation site at docs/docs/ (GitBook-styled).

Regenerate after editing the PAGES content below:

    python3 tools/build_docs_site.py

Output: docs/docs/index.html + one HTML file per section, plus llms.txt
(machine-readable index for agents). Static, no build step, no dependencies.
Facts in PAGES were verified against the engine and repo as of v8.0.0.
"""
import html as html_mod
import os
import re

OUT = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "docs", "docs")

# ── content model ────────────────────────────────────────────────────────────
# Each page: (slug, title, group, blurb, body_html)
PAGES = [
    ("index", "Introduction", "Getting started",
     "What NEDB is, what it guarantees, and a five-minute start."),

    ("provenance", "Provenance & Time", "Core concepts",
     "The four axes: what, when, true-when, why — and the three commitments."),

    ("nesql", "The Query Language — neSQL", "Core concepts",
     "PostgreSQL SQL + the extended FROM-form: one grammar, one evaluator, one router."),

    ("nql", "The FROM-form in Depth", "Core concepts",
     "Full clause reference: predicates, three-valued logic, aggregates, indexes."),

    ("protocols", "Wire Protocols", "Running it",
     "HTTP/JSON, PostgreSQL wire (simple + extended), RESP2."),

    ("durability", "Durability", "Running it",
     "Flush contracts, crash boundaries, the v3 segment store, repair."),

    ("replication", "Replication", "Running it",
     "tip / since / scan_status, state roots, the SSE event stream."),

    ("cast", "Cast — the AI planner", "Running it",
     "A 3.33M-parameter local model that plans queries. Safety by construction."),

    ("clients", "Clients & Adapters", "Running it",
     "Embedded cores, the HTTP client, and the wrap_* audit family."),

    ("cli", "CLI Tools", "Reference",
     "nedb-cli, the nesql CLI, nedb-inspector — operating stores offline."),

    ("architecture", "Architecture", "Reference",
     "The OpLog, the deterministic fold, and three storage generations."),

    ("releasing", "Releasing", "Reference",
     "One tag, three distributions, every version file in lockstep."),
]

BODIES = {}

BODIES["index"] = """
<p class="lede">NEDB is an embedded, tamper-evident database built on a BLAKE2b hash chain and a
content-addressed Merkle DAG. It stores four things about every fact: <b>what</b> it is,
<b>when</b> it was written, <b>when it was true in the world</b>, and <b>why</b> it happened —
and it can prove all four, offline, to a third party.</p>

<h2>What it guarantees</h2>
<ul>
<li><b>Nothing is ever overwritten.</b> Every write is a new immutable version; deletes are tombstones. History is permanent unless an operator explicitly compacts it.</li>
<li><b>Tamper is detectable, not just unlikely.</b> Every object is BLAKE2b-verified on read; <code>verify()</code> walks the chain; a single flipped byte changes the verdict to false.</li>
<li><b>Causality is data.</b> A write can cite the writes that caused it (<code>caused_by</code>), and <code>TRACE</code> walks that graph in both directions as a query.</li>
<li><b>Provenance costs speed, not correctness.</b> Time-travel reads run at ~70% of current-state read speed.</li>
<li><b>One core, three languages, one version.</b> Python, Node and Rust all bind the same Rust engine; PyPI, npm and crates.io publish in lockstep from a single git tag.</li>
<li><b>You query it in SQL.</b> neSQL inherits PostgreSQL's grammar whole and extends it with the clauses a permanent store can answer — you don't learn a new query language, you learn the additions.</li>
</ul>

<h2>Five-minute start</h2>
<pre><code>pip install nedb-engine      # pure-Python core + native Rust wheel when available</code></pre>

<pre><code>from nedb import NEDB

db = NEDB("./mydata")                      # durable, hash-chained
db.put("users", "alice", {"name": "Alice", "age": 31})

db.query('SELECT * FROM users WHERE age > 30')   # PostgreSQL SQL — the daemon speaks it
db.query('FROM users WHERE age > 30')            # the extended FROM-form (embedded cores)
db.head                                     # the 64-char BLAKE2b Merkle head
db.verify()                                 # True — the chain is intact</code></pre>

<p>From there: <a href="nesql.html">the query language</a> — standard PostgreSQL SQL plus
NEDB's temporal and causal clauses — <a href="provenance.html">time travel and provenance</a>,
and <a href="protocols.html">the wire protocols your tools already speak</a>.</p>

<h2>Who this is for</h2>
<p>Audit-shaped workloads: agent memory where every belief must trace to its evidence,
blockchain state (a Bitcoin-fork node runs its chainstate on NEDB), compliance trails,
ledgers, RAG pipelines where a fact must be citable to its source. If a fact matters and
someone may someday ask you to <i>prove</i> it — that is the lane.</p>

<h2>License</h2>
<p>BUSL-1.1: free for any organisation under USD $1M annual revenue, including commercial
and production use, no permission needed. Converts to Apache 2.0 automatically on
2030-09-11. Versions 3.0.0–3.3.1 remain MIT, irrevocably.</p>
"""

BODIES["provenance"] = """
<p class="lede">Every database stores <i>what</i>. NEDB also stores <i>when</i>, <i>when it was
true</i>, and <i>why</i> — as queryable, indexed primitives, sealed in the same hash chain as the
data itself.</p>

<h2>Two time axes</h2>
<p><b>Transaction time</b> — <code>AS OF &lt;seq&gt;</code> — answers "what did the system
<i>know</i> at sequence N?" The engine never garbage-collects versions, so every past state is
reachable forever (unless an operator explicitly runs <code>compact()</code>, which announces
that it is trading history for space).</p>

<p><b>Valid time</b> — <code>VALID AS OF "&lt;date&gt;"</code> — answers "what was true in the
world on that date?" A row can carry <code>valid_from</code>/<code>valid_to</code> independent of
when it was written, which is bi-temporality: the two axes compose.</p>

<pre><code># What did the system know at seq 200 about what was true on 2024-02-15?
db.query('FROM policy AS OF 200 VALID AS OF "2024-02-15"')</code></pre>

<h2>Causal provenance</h2>
<p>A write may carry <code>caused_by</code> — a list of parent writes — plus
<code>evidence</code> and <code>confidence</code>. This is not a comment field: it is an indexed
edge in the DAG. <code>TRACE caused_by</code> walks ancestors (why did this happen?);
<code>TRACE caused_by REVERSE</code> walks descendants (what did this cause?).</p>

<pre><code>db.put("inputs", "msg_1", {"text": "user prefers dark mode"})
seq_msg = db.seq
db.put("beliefs", "dark_mode", {"value": True},
       caused_by=[seq_msg], evidence="user_message", confidence=0.95)

db.query('FROM beliefs WHERE _id = "dark_mode" TRACE caused_by')      # → msg_1
db.query('FROM inputs  WHERE _id = "msg_1" TRACE caused_by REVERSE')  # → dark_mode</code></pre>

<div class="callout"><b>Call-shape fact (learned the hard way):</b> <code>caused_by</code> goes at the
<b>top level</b> of a put request, not nested inside the document. A caused_by inside the document
is stored as ordinary user data and creates <b>no</b> edge. Stored rows expose the edge as
<code>_caused_by</code>.</div>

<h2>The three commitments</h2>
<table>
<tr><th>Commitment</th><th>Answers</th><th>Where</th></tr>
<tr><td>Merkle head (<code>head</code>)</td><td>"did this database's <i>history</i> change?" — chains every write by seq and object hash</td><td>returned on every response</td></tr>
<tr><td>State root</td><td>"do two databases say the same thing <i>right now</i>?" — computable from live state alone, equal for equal state regardless of route</td><td><code>docs/state-root-v1.md</code>, test vectors in <code>vectors/</code></td></tr>
<tr><td>Merkle proofs</td><td>"prove this row existed at this time" — verifiable <b>locally, without the server</b></td><td><code>proof()</code> / <code>verify_proof()</code></td></tr>
</table>

<p>Keeping head and state root separate is deliberate: a root that folded in history could not
compare two replicas that arrived by different routes — and that comparison (replica agreement,
drift detection, anchoring) is most of what a root is for. One subtlety the spec pins: with
encryption on, a node's hash is a function of its <i>ciphertext</i> (a fresh AES-GCM nonce per
write), so state-root leaves commit to logical content, never object hashes.</p>

<h2>Provenance in SQL</h2>
<p>The metadata is selectable like any column, and settable from SQL — the causal chain does not
require the HTTP API or the Python client:</p>

<pre><code>SELECT _id, _hash, _seq FROM audit ORDER BY _seq;
INSERT INTO audit (_id, _caused_by, kind) VALUES ('leaf', '&lt;parent-hash&gt;', 'reprice');
SELECT _id FROM audit TRACE caused_by;</code></pre>

<h2>What tamper-evidence actually means</h2>
<p><code>verify()</code> recomputes the chain (~21,000 BLAKE2b/sec; 30k objects in 1.38 s in the
dated benchmark). Content tampering is <b>never</b> masked — the self-healing pass repairs
<i>structural</i> gaps only, and a tampered log verifies false. A durable store answers "not
available at that sequence" for pruned history rather than returning a stale value.</p>
"""

BODIES["nql"] = """
<p class="lede">The <b>extended FROM-form</b> is neSQL's other statement shape — the form that
carries the full clause set natively, and the one embedded cores execute. It began as NQL, the
project's first query language; today it is folded into neSQL as an equal form, not a separate
dialect (<a href="nesql.html">see the language overview</a>).</p>

<h2>Clause grammar</h2>
<pre><code>FROM &lt;collection&gt;
  [ AS OF &lt;seq&gt; ]                            transaction time
  [ VALID AS OF "&lt;date&gt;" ]                   valid time
  [ WHERE &lt;predicate&gt; ]                      full boolean predicate
  [ SEARCH "&lt;text&gt;" ]                        full-text search
  [ TRAVERSE &lt;relation&gt; ]                    graph traversal
  [ TRACE caused_by [REVERSE] ]              causal provenance
  [ GROUP BY &lt;field&gt; [COUNT|SUM f|AVG f|MIN f|MAX f] ]
  [ COUNT | SUM f | AVG f | MIN f | MAX f ]  whole-result aggregate
  [ HAVING &lt;predicate&gt; ]                     filters the AGGREGATED rows
  [ ORDER BY &lt;field&gt; [ASC|DESC] (, ...) ]
  [ LIMIT &lt;n&gt; ] [ OFFSET &lt;n&gt; ]</code></pre>

<p>Clauses are evaluated in SQL's order — <code>FROM → WHERE → GROUP BY → HAVING → ORDER BY →
OFFSET → LIMIT</code> — whatever order you write them. Before 3.3.0 this was wrong in ways that
lied: <code>LIMIT</code> truncated an aggregate's <i>input</i>, <code>ORDER BY</code> ran before
grouping (so sorting on <code>count</code> did nothing), and <code>VALID AS OF</code> ran after
<code>LIMIT</code> in the Python engine.</p>

<h2>Predicates</h2>
<p><code>WHERE</code> takes a full boolean expression. <code>AND</code> binds tighter than
<code>OR</code>; parentheses nest to any depth.</p>
<table>
<tr><th>Comparison</th><th>Notes</th></tr>
<tr><td><code>= != &lt; &lt;= &gt; &gt;=</code></td><td></td></tr>
<tr><td><code>IN (…) / NOT IN (…)</code></td><td>set membership</td></tr>
<tr><td><code>BETWEEN a AND b</code></td><td>inclusive both ends, as in SQL</td></tr>
<tr><td><code>LIKE / NOT LIKE / ILIKE</code></td><td><code>%</code> any run, <code>_</code> any one char; <code>ILIKE</code> case-insensitive</td></tr>
<tr><td><code>IS NULL / IS NOT NULL</code></td><td>matches absent <b>and</b> explicitly-null</td></tr>
</table>

<div class="callout"><b>Three-valued logic.</b> An ordering comparison against a missing or null
field is never true — <code>WHERE fee &lt; 5</code> will not return a row with no <code>fee</code>.
<code>LIKE</code> is false in <i>both</i> polarities, so a null row appears in neither
<code>LIKE</code> nor <code>NOT LIKE</code>. <code>=</code> and <code>!=</code> <i>do</i> operate on
null: <code>WHERE fee = NULL</code> selects absent-or-null rows. Use <code>IS NULL</code> to test
presence explicitly.</div>

<h2>Aggregates</h2>
<p><code>GROUP BY</code> rows carry the group key, <code>count</code>, and one named aggregate
(<code>sum_fee</code>, <code>max_price</code>…). The aggregate only considers rows whose target
field is numeric; a group of 5 where 2 carry numeric <code>price</code> reports
<code>count: 5</code> and averages over 2. No numeric input aggregates to <code>null</code>,
never <code>0</code>. Integer inputs stay in 64-bit integers — a sum over satoshi amounts above
2^53 is exact; <code>AVG</code> is always fractional.</p>

<p>Drop the <code>GROUP BY</code> for a whole-result aggregate (exactly one row);
<code>COUNT</code> of an empty result is one row holding <code>0</code>, <code>SUM</code> of an
empty result is <code>null</code>. <code>HAVING</code> runs through the same evaluator as
<code>WHERE</code> — the whole predicate surface, not a lesser copy.</p>

<h2>Indexes and the planner</h2>
<p><code>=</code>, <code>IN</code>, <code>BETWEEN</code> and the one-sided inequalities are served
from a sorted index when one covers the field. Measured on 20,000 rows
(<code>scripts/bench_index_range.py</code>): a point lookup goes 137 ms → 0.01 ms; a 1%-selective
<code>BETWEEN</code> 186 ms → 1.1 ms. The planner asks each candidate index how many rows its
range covers and takes the narrowest; same-field bounds are merged.</p>

<p>An index only <b>narrows candidates</b> — the full predicate is re-evaluated on whatever comes
back, so the answer never depends on an index existing. Three cases deliberately decline it:</p>
<ul>
<li><b><code>IS NULL</code></b> — absent fields are not in the index; a scan would return the exact complement of the answer.</li>
<li><b>Anything under <code>OR</code>/<code>NOT</code></b> — a disjunct does not constrain the result set.</li>
<li><b><code>AS OF</code></b> — the index holds current versions only; it cannot answer historical queries.</li>
</ul>

<h2>Unknown clauses are errors</h2>
<p>A clause the engine does not implement is rejected with the offending token (HTTP 400) — never
silently skipped. Before 3.3.0 a misspelled <code>ORDRE BY fee</code> returned unsorted rows with
HTTP 200; the engine answered a <i>different query</i> than the one asked and said nothing. That
failure class is closed.</p>

<h2>Cross-engine parity</h2>
<p>NQL has two independent implementations — the Python reference and the Rust engine — and two
parity suites (<code>tests/test_nql_predicates.py</code>,
<code>tests/test_nql_shaping.py</code>) run the same battery through both and assert identical
answers. They drifted in five places before the gate existed; the gate exists so they cannot
drift again.</p>
"""

BODIES["nesql"] = """
<p class="lede">Nobody should have to learn a query language to use a database. That sentence cost
us one — and then it built the answer. <b>neSQL is the language NEDB speaks:</b> PostgreSQL's
SQL, inherited whole, plus the clauses only a permanent, hash-chained store can answer.</p>

<h2>The equation</h2>
<pre><code>neSQL  =  PostgreSQL SQL          ·  inherited whole, not reimplemented
       +  NEDB's clauses          ·  AS OF SYSTEM TIME, VALID AS OF, SEARCH, TRACE, TRAVERSE
       +  the extended FROM-form  ·  NQL folded in — one grammar, two statement forms</code></pre>

<p>Standard SQL is the user-facing surface: if it is valid PostgreSQL and the evaluator can
parse it, it runs. The additions exist because a store with permanent memory can answer
questions SQL has no spelling for — <code>SYSTEM_TIME</code>, <code>PERIOD</code> and
<code>PORTION</code> appear <b>zero</b> times in PostgreSQL's grammar, and
<code>AS OF SYSTEM TIME</code> is a CockroachDB extension. NEDB adds its clauses
<b>to</b> PostgreSQL's real grammar — <code>gram.y</code>, 19,513 lines and 492 keywords,
vendored from 17.4 at <code>vendor/postgresql/</code> with its licence intact — never as
deviations from it. What the vendored grammar hands over free:
<code>WITH RECURSIVE</code>, window functions, <code>GROUPING SETS</code>, <code>MERGE</code>.</p>

<h2>Two statement forms, one grammar</h2>
<p>The same statements can also be written in the <b>extended FROM-form</b> — the form NQL used,
now one of neSQL's two statement shapes. It begins <code>FROM</code>, carries the full clause
set (<a href="nql.html">reference</a>), and is what embedded cores execute natively. Routing
between the forms is <b>structural, never guessed</b>: PostgreSQL has no statement form that
begins with <code>FROM</code>, so the leading keyword partitions the vocabularies — and a first
word in neither is refused <i>naming both</i>:</p>

<pre><code>curl -X POST :7070/v1/databases/shop/query -H 'Content-Type: application/json' \
  -d '{"nql":"GRANT ALL ON users"}'
# → 400  "GRANT" does not begin a statement in either half of neSQL
#          FROM-form statements begin with: FROM
#          SQL statements begin with: SELECT, INSERT, UPDATE, ...</code></pre>

<div class="callout"><b>Dialects by surface</b> (verified against the live 8.0.0 daemon):
the HTTP <code>/query</code> endpoint and the <code>nesql</code> CLI accept <b>both</b> forms
through one router (the response names its <code>dialect</code>). The PostgreSQL wire endpoint
serves SQL, with the NEDB clauses as SQL keywords. Embedded cores execute the FROM-form
natively — send those statements over HTTP or the wire when you want SQL-form.</div>

<h2>One evaluator, no flag</h2>
<p>The SQL evaluator answers <b>every <code>SELECT</code> it can parse</b> — joins (nested-loop
and hash), subqueries, <code>EXISTS</code>, set operations, <code>DISTINCT</code>, derived
tables, <code>LATERAL</code>, <code>array_agg(x ORDER BY y)</code> — with nothing to enable.
The translator that once served <code>SELECT</code> is kept only for writes and unparsable
statements, so every statement gets an answer rather than a syntax error.</p>

<p>NEDB's clauses are SQL keywords now, and they compose:</p>
<pre><code>-- full-text search + a join, one statement
SELECT o._id, d.name FROM orders SEARCH 'acme' o
  JOIN drivers d ON o.driver = d._id;

-- one relation in the past, joined against another at the tip
SELECT h.total, n.total FROM orders AS OF SYSTEM TIME 412 h
  JOIN audit n ON h._id = n._id;</code></pre>

<p>There is <b>one implementation</b> of each clause — the SQL side parses, the query engine
executes — so neither form reimplements the other. <code>AS OF SYSTEM TIME</code>,
<code>VALID AS OF</code> and <code>SEARCH</code> are unreserved keywords: a collection aliased
<code>search</code> keeps working.</p>

<h2>Writes</h2>
<p>SQL write semantics line up with append-only storage: <code>INSERT</code> is a put,
<code>UPDATE</code> creates a <b>new version</b>, <code>DELETE</code> writes a <b>tombstone</b> —
and <code>verify()</code> still passes afterwards, because a SQL write is an ordinary engine
write, not a side door. <code>INSERT</code> requires an explicit column list (there is no schema
to infer order from) and literal values only. <code>_caused_by</code> is an insertable column —
provenance does not require a special API.</p>

<p><code>TRUNCATE</code> and DDL are refused <b>on purpose</b>: TRUNCATE discards history — that
is the one thing NEDB exists to make impossible — and collections are created by the first
write to them.</p>

<h2>The nesql CLI</h2>
<pre><code>$ nesql --db ./store query "SELECT who, total FROM orders ORDER BY total DESC"
$ nesql --db ./store query "FROM orders WHERE total > 150"</code></pre>

<p>One <code>query</code> command, both forms, routed on the leading keyword;
<code>--nql</code>/<code>--sql</code> force a form when you want <i>that</i> form's error.
Exit codes carry the verdict: <code>0</code> success, <code>1</code> failure, <code>2</code>
usage, <code>3</code> <b>could not determine</b> (pruned history — a pruned store is not a
corrupt one), <code>4</code> not found, <code>5</code> unsupported. <code>root verify</code>
reports the stored record and the recomputation as two independent facts, never collapsed.</p>

<p>The packages are real and version-aligned with the engine: the crates.io crate
<code>nesql</code> is the CLI itself (<code>cargo add nesql</code>, building against the registry
engine); PyPI <code>nesql</code> and npm <code>nesql-engine</code> carry the language reference. And the
same CLI binary is staged into every platform build of <code>nedb-engine</code> — one install
carries everything. The <a href="https://github.com/Eth-Interchained/neSQL">neSQL repository</a>
is the language's home: vendored grammar, CLI source, NQL reference, NEDB specs.</p>
"""

BODIES["nql"] = """
<p class="lede">The <b>extended FROM-form</b> is neSQL's other statement shape — the form that
carries the full clause set natively, and the one embedded cores execute. It began as NQL, the
project's first query language; today it is folded into neSQL as an equal form, not a separate
dialect (<a href="nesql.html">see the language overview</a>).</p>

<h2>Clause grammar</h2>
<pre><code>FROM &lt;collection&gt;
  [ AS OF &lt;seq&gt; ]                            transaction time
  [ VALID AS OF "&lt;date&gt;" ]                   valid time
  [ WHERE &lt;predicate&gt; ]                      full boolean predicate
  [ SEARCH "&lt;text&gt;" ]                        full-text search
  [ TRAVERSE &lt;relation&gt; ]                    graph traversal
  [ TRACE caused_by [REVERSE] ]              causal provenance
  [ GROUP BY &lt;field&gt; [COUNT|SUM f|AVG f|MIN f|MAX f] ]
  [ COUNT | SUM f | AVG f | MIN f | MAX f ]  whole-result aggregate
  [ HAVING &lt;predicate&gt; ]                     filters the AGGREGATED rows
  [ ORDER BY &lt;field&gt; [ASC|DESC] (, ...) ]
  [ LIMIT &lt;n&gt; ] [ OFFSET &lt;n&gt; ]</code></pre>

<p>Clauses are evaluated in SQL's order — <code>FROM → WHERE → GROUP BY → HAVING → ORDER BY →
OFFSET → LIMIT</code> — whatever order you write them. Before 3.3.0 this was wrong in ways that
lied: <code>LIMIT</code> truncated an aggregate's <i>input</i>, <code>ORDER BY</code> ran before
grouping (so sorting on <code>count</code> did nothing), and <code>VALID AS OF</code> ran after
<code>LIMIT</code> in the Python engine.</p>

<h2>Predicates</h2>
<p><code>WHERE</code> takes a full boolean expression. <code>AND</code> binds tighter than
<code>OR</code>; parentheses nest to any depth.</p>
<table>
<tr><th>Comparison</th><th>Notes</th></tr>
<tr><td><code>= != &lt; &lt;= &gt; &gt;=</code></td><td></td></tr>
<tr><td><code>IN (…) / NOT IN (…)</code></td><td>set membership</td></tr>
<tr><td><code>BETWEEN a AND b</code></td><td>inclusive both ends, as in SQL</td></tr>
<tr><td><code>LIKE / NOT LIKE / ILIKE</code></td><td><code>%</code> any run, <code>_</code> any one char; <code>ILIKE</code> case-insensitive</td></tr>
<tr><td><code>IS NULL / IS NOT NULL</code></td><td>matches absent <b>and</b> explicitly-null</td></tr>
</table>

<div class="callout"><b>Three-valued logic.</b> An ordering comparison against a missing or null
field is never true — <code>WHERE fee &lt; 5</code> will not return a row with no <code>fee</code>.
<code>LIKE</code> is false in <i>both</i> polarities, so a null row appears in neither
<code>LIKE</code> nor <code>NOT LIKE</code>. <code>=</code> and <code>!=</code> <i>do</i> operate on
null: <code>WHERE fee = NULL</code> selects absent-or-null rows. Use <code>IS NULL</code> to test
presence explicitly.</div>

<h2>Aggregates</h2>
<p><code>GROUP BY</code> rows carry the group key, <code>count</code>, and one named aggregate
(<code>sum_fee</code>, <code>max_price</code>…). The aggregate only considers rows whose target
field is numeric; a group of 5 where 2 carry numeric <code>price</code> reports
<code>count: 5</code> and averages over 2. No numeric input aggregates to <code>null</code>,
never <code>0</code>. Integer inputs stay in 64-bit integers — a sum over satoshi amounts above
2^53 is exact; <code>AVG</code> is always fractional.</p>

<p>Drop the <code>GROUP BY</code> for a whole-result aggregate (exactly one row);
<code>COUNT</code> of an empty result is one row holding <code>0</code>, <code>SUM</code> of an
empty result is <code>null</code>. <code>HAVING</code> runs through the same evaluator as
<code>WHERE</code> — the whole predicate surface, not a lesser copy.</p>

<h2>Indexes and the planner</h2>
<p><code>=</code>, <code>IN</code>, <code>BETWEEN</code> and the one-sided inequalities are served
from a sorted index when one covers the field. Measured on 20,000 rows
(<code>scripts/bench_index_range.py</code>): a point lookup goes 137 ms → 0.01 ms; a 1%-selective
<code>BETWEEN</code> 186 ms → 1.1 ms. The planner asks each candidate index how many rows its
range covers and takes the narrowest; same-field bounds are merged.</p>

<p>An index only <b>narrows candidates</b> — the full predicate is re-evaluated on whatever comes
back, so the answer never depends on an index existing. Three cases deliberately decline it:</p>
<ul>
<li><b><code>IS NULL</code></b> — absent fields are not in the index; a scan would return the exact complement of the answer.</li>
<li><b>Anything under <code>OR</code>/<code>NOT</code></b> — a disjunct does not constrain the result set.</li>
<li><b><code>AS OF</code></b> — the index holds current versions only; it cannot answer historical queries.</li>
</ul>

<h2>Unknown clauses are errors</h2>
<p>A clause the engine does not implement is rejected with the offending token (HTTP 400) — never
silently skipped. Before 3.3.0 a misspelled <code>ORDRE BY fee</code> returned unsorted rows with
HTTP 200; the engine answered a <i>different query</i> than the one asked and said nothing. That
failure class is closed.</p>

<h2>Cross-engine parity</h2>
<p>NQL has two independent implementations — the Python reference and the Rust engine — and two
parity suites (<code>tests/test_nql_predicates.py</code>,
<code>tests/test_nql_shaping.py</code>) run the same battery through both and assert identical
answers. They drifted in five places before the gate existed; the gate exists so they cannot
drift again.</p>
"""

BODIES["nesql"] = """
<p class="lede">Nobody should have to learn a query language to use a database. That sentence cost
us one. neSQL is the name for what NEDB now speaks: <b>PostgreSQL's SQL, inherited whole — plus the
clauses a permanent, hash-chained store can answer.</b></p>

<h2>The equation</h2>
<pre><code>neSQL  =  PostgreSQL SQL   ·  inherited whole, not reimplemented
       +  NEDB SQL         ·  AS OF SYSTEM TIME, VALID AS OF, SEARCH, TRACE, TRAVERSE</code></pre>

<p>The left-hand side is PostgreSQL's real grammar — <code>gram.y</code>, 19,513 lines and 492
keywords, vendored from 17.4 at <code>vendor/postgresql/</code> with its licence intact. The
right-hand side is added <b>to</b> the grammar, never deviating from it. Why the temporal clauses
were never free: <code>SYSTEM_TIME</code>, <code>PERIOD</code> and <code>PORTION</code> appear
<b>zero</b> times in PostgreSQL's grammar — Postgres has no temporal SQL at all;
<code>AS OF SYSTEM TIME</code> is a CockroachDB extension. What the vendored grammar hands over
free: <code>WITH RECURSIVE</code>, window functions, <code>GROUPING SETS</code>, <code>MERGE</code>.</p>

<h2>One evaluator, no flag</h2>
<p>The SQL evaluator answers <b>every <code>SELECT</code> it can parse</b> — joins (nested-loop
and hash), subqueries, <code>EXISTS</code>, set operations, <code>DISTINCT</code>, derived tables,
<code>LATERAL</code>, <code>array_agg(x ORDER BY y)</code> — with nothing to enable. The
translator that once served <code>SELECT</code> is kept only for writes and unparsable
statements, so every statement gets an answer rather than a syntax error.</p>

<p>NQL's own verbs are SQL clauses now, and they compose:</p>
<pre><code>-- full-text search from NQL, a join from SQL, one statement
SELECT o._id, d.name FROM orders SEARCH 'acme' o
  JOIN drivers d ON o.driver = d._id;

-- one relation in the past, joined against another at the tip
SELECT h.total, n.total FROM orders AS OF SYSTEM TIME 412 h
  JOIN audit n ON h._id = n._id;</code></pre>

<p>There is <b>one implementation</b> of each verb — the SQL side parses, the NQL engine executes —
so neither language reimplements the other. <code>AS OF SYSTEM TIME</code>,
<code>VALID AS OF</code> and <code>SEARCH</code> are unreserved keywords: a collection aliased
<code>search</code> keeps working.</p>

<h2>Routing is structural</h2>
<p>NQL statements begin <code>FROM</code>; PostgreSQL has no statement form that begins with
<code>FROM</code>. The leading keyword partitions the two vocabularies — a first word in neither
is refused <i>naming both</i>, never handed to whichever parser seems likelier. The same router
(<code>nedb_engine::neql::route</code>) serves the daemon's <code>/query</code> endpoint and the
<code>nesql</code> CLI; two implementations of that decision would let the two disagree about
what a statement <i>means</i>, which is worse than disagreeing about a result.</p>

<h2>Writes</h2>
<p>SQL write semantics line up with append-only storage: <code>INSERT</code> is a put,
<code>UPDATE</code> creates a <b>new version</b>, <code>DELETE</code> writes a <b>tombstone</b> —
and <code>verify()</code> still passes afterwards, because a SQL write is an ordinary engine
write, not a side door. <code>INSERT</code> requires an explicit column list (there is no schema
to infer order from) and literal values only. <code>_caused_by</code> is an insertable column.</p>

<p><code>TRUNCATE</code> and DDL are refused <b>on purpose</b>: TRUNCATE discards history — that
is the one thing NEDB exists to make impossible — and collections are created by the first write
to them.</p>

<h2>The nesql CLI</h2>
<pre><code>$ nesql --db ./store query "SELECT who, total FROM orders ORDER BY total DESC"
$ nesql --db ./store query "FROM orders WHERE total > 150"</code></pre>

<p>One <code>query</code> command, two dialects, routed on the leading keyword;
<code>--nql</code>/<code>--sql</code> force a dialect when you want <i>that</i> dialect's error.
Exit codes carry the verdict: <code>0</code> success, <code>1</code> failure, <code>2</code>
usage, <code>3</code> <b>could not determine</b> (pruned history — a pruned store is not a corrupt
one, and an operator who cannot tell those apart will ignore a real alarm or panic at a routine
one), <code>4</code> not found, <code>5</code> unsupported. <code>root verify</code> reports the
stored record and the recomputation as two independent facts, never collapsed.</p>

<p>The packages are real and version-aligned with the engine: the crates.io crate
<code>nesql</code> is the CLI itself (<code>cargo add nesql</code>, building against the registry
engine); PyPI <code>nesql</code> and npm <code>nesql-engine</code> carry the language reference. And the
same CLI binary is staged into every platform build of <code>nedb-engine</code> — one install
carries everything. The <a href="https://github.com/Eth-Interchained/neSQL">neSQL repository</a>
is the language's home: vendored grammar, CLI source, NQL reference, NEDB specs.</p>
"""

BODIES["protocols"] = """
<p class="lede">NEDB speaks three protocols natively: its own HTTP/JSON, PostgreSQL's wire
protocol, and RESP2. The point of the last two is that <b>your existing tools already speak
them</b> — no bespoke client, no driver to write.</p>

<h2>HTTP/JSON — the native surface</h2>
<p>The daemon (<code>nedbd</code>) serves <code>/v1/databases/*</code>: put/get/query/tx (atomic
CAS transactions), TTL, indexes, relations, <code>/verify</code>, Merkle proofs, the
Mongo-compatible route, <code>/cast</code>, and <code>/events</code> (SSE). Optional bearer
token via <code>NEDBD_TOKEN</code>. Binds loopback by default since v2.2.31 — a hardening fix;
expose deliberately or tunnel.</p>

<h2>PostgreSQL wire protocol</h2>
<p><code>nedbd --pg-port 5433</code> opens a real pgwire endpoint — reads <b>and</b> writes.
<code>psql</code>, DBeaver, Metabase, Grafana, psycopg, asyncpg and JDBC all work against a
tamper-evident store with ordinary SQL:</p>

<pre><code>UPDATE orders SET total = 999 WHERE _id = 'o1';
SELECT total FROM orders WHERE _id = 'o1';                       -- 999
SELECT total FROM orders AS OF SYSTEM TIME 0 WHERE _id = 'o1';   -- 120, forever</code></pre>

<p><b>Both wire protocols are implemented</b> — simple (<code>psql</code>, psycopg2) and extended
<code>Parse</code>/<code>Bind</code>/<code>Describe</code>/<code>Execute</code> (psycopg3,
asyncpg, JDBC). Until the extended protocol landed, those frameworks could not run a single
query — psycopg3 hung, asyncpg refused. Parameters arrive in text <b>and binary</b> format; a
row-capped <code>Execute</code> suspends its portal so a JDBC <code>setFetchSize</code> pages
instead of stalling.</p>

<p><b>Typing without a schema:</b> the type is sampled from the documents already stored — the
data <i>is</i> the catalogue. Placeholders in clause positions (<code>AS OF SYSTEM TIME $1</code>)
are typed by the grammar; aggregates by meaning (<code>COUNT</code> integer, <code>AVG</code>
fractional). A driver that declares types is believed; only unspecified slots are inferred.</p>

<p><b>Introspection is real SQL:</b> <code>pg_catalog</code> and <code>information_schema</code>
are queryable relations synthesised from the live database — <code>\\dt</code> is two
<code>LEFT JOIN</code>s and a nine-branch <code>CASE</code>; <code>\\d orders</code> is a regex
plus three correlated subqueries. Every psql 17 backslash-describe command exits 0
(<code>tests/test_psql_introspection.py</code> drives the real binary, psql 16 and 17); three
exit 1 exactly as on fresh Postgres. Derived values are honest: sizes are blank cells, never
invented numbers.</p>

<p><b>Limits, named:</b> SQL-level cursors (<code>DECLARE</code>/<code>FETCH</code>) are
refused by name, not hung. A column with disagreeing stored types advertises
<code>text</code>. The connection is cleartext — the endpoint is off without
<code>--pg-port</code>, loopback by default; <code>NEDBD_PG_READ_ONLY=1</code> for
never-mutate deployments. Verified by 64 checks in <code>tests/test_pgwire.py</code> driven
through psycopg2 — which is libpq.</p>

<h2>RESP2</h2>
<p><code>NEDBD_RESP2_PORT=6380 nedbd</code> also speaks RESP2 — <code>redis-cli</code> and
<code>redis-benchmark</code> work unchanged, with per-database selection
(<code>SELECT shop</code>) and neSQL queries through <code>EVAL</code>:</p>

<pre><code>redis-cli -p 6380 SELECT shop
redis-cli -p 6380 EVAL 'FROM users AS OF 10 WHERE status = "active"' 0
redis-cli -p 6380 EVAL 'FROM beliefs TRACE caused_by' 0</code></pre>
"""

BODIES["durability"] = """
<p class="lede">NEDB's durability model was not designed on a whiteboard — it was found by killing
a real engine at every persistence boundary and by filling a real filesystem to zero free blocks.
Three defect classes came out of that campaign, all fixed and regression-tested.</p>

<h2>Flush contracts</h2>
<pre><code>db.try_flush_all()?;      // Result&lt;()&gt; — use this when the outcome matters
db.flush_all();           // still logs; for ticker / Drop, nowhere to propagate</code></pre>

<p>A failed flush used to silently discard acknowledged writes: the id-index buffer cleared
entries regardless of whether the disk write landed, so a flush that hit <code>ENOSPC</code>
lost rows while <code>verify()</code> reported every object healthy — the objects were durable;
the index entries that made them findable were gone. An entry now leaves the WAL only when its
write actually landed. Flush errors are observable (<code>try_flush_all</code>,
<code>try_flush_manifest</code>, <code>IdIndex::try_flush_write_buf</code>).</p>

<p><b>Embedded bindings flush on a cadence:</b> <code>NedbCore.open()</code> (Node + Python) runs
the 1-second manifest ticker exactly as <code>nedbd</code> does, so a <code>SIGKILL</code> / OOM /
power cut loses at most one tick of acknowledged writes. <code>NEDB_FLUSH_MS</code> tunes or
disables it. Durable stores also flush on <code>Ctrl+C</code>/<code>SIGTERM</code> — automatic in
the bindings, <code>Db::install_exit_flush(Arc&lt;Db&gt;)</code> for standalone Rust binaries.
<code>nedb-inspector</code> warns when a durable open lacks flush-on-exit wiring.</p>

<h2>The v3 segment store</h2>
<p>v2 stores every version as its own content-addressed file: trivially atomic, corruption-proof,
but each write costs file-create + fsync + rename plus a directory B-tree update — on a busy
disk that caps sustained writes around ~185/s, and the bottleneck is the <i>number of files
touched</i>, not bytes.</p>

<p>v3 batches objects into append-only segment packs; a batch commits with a <b>single
fsync</b>. Flush cost scales with bytes, not object count. Each segment carries a checksummed
<code>.idx</code> sidecar so reopen rebuilds the in-memory index from the sidecar (missing or
corrupt sidecar falls back to a full scan-and-heal — slower, never fatal). Enabling is
non-destructive: old loose objects stay fully readable, only new writes go to segments.</p>

<pre><code>nedbd-v2 --dag-v3 --data /var/lib/nedb     # or NEDB_DAG_V3=1</code></pre>

<div class="callout"><b>Measured on a real blockchain node</b> (itcd, FlushStateToDisk on live
chainstate): 2,549 coins / 366 kB went from <i>minutes</i> on v2 to <b>1.71 s</b> on v3 — and the
larger batch finishes faster than the smaller one, because cost is the per-batch fsync, not the
coin count.</div>

<h2>Repair</h2>
<p>Every object carries its own <code>coll</code>, <code>id</code> and <code>seq</code> — the id
index is fully derivable, nothing is invented:</p>

<pre><code>nedb-cli repair ./data
# repaired: 203 id-index entr(ies) rebuilt, 203 node(s) verified, flushed</code></pre>

<p>The self-healing pass on open repairs <i>structural</i> gaps only; content tampering is never
masked — a tampered log verifies false, on purpose.</p>

<h2>Known sharp edges (documented, not hidden)</h2>
<ul>
<li><code>since()</code>'s cursor is exclusive and seqs start at 0, so the very first write (seq 0) is unreachable through any cursor value — ten writes drain as nine records. Changing the convention would break existing consumers; gate on <code>ScanStatus.seq_index_ready</code>, not <code>scan_complete</code>.</li>
<li><code>compact()</code> prunes superseded versions and tombstones — <code>AS OF</code> can no longer reach them. Nothing invokes it automatically: not on the HTTP surface, not in the CLI, not on a timer. A compacted store answers "not available at that sequence", never a stale value.</li>
<li><code>NEDB_FAST_FSYNC</code> trades <code>F_FULLFSYNC</code> for plain <code>fsync(2)</code> on macOS (faster, weaker durability guarantee; no-op elsewhere).</li>
</ul>
"""

BODIES["replication"] = """
<p class="lede">NEDB is single-node by design — but it ships the <b>contract</b> that replicas and
followers need: a tip to poll, a bounded changefeed to drain, a readiness gate to trust, and
state roots to prove two stores agree.</p>

<h2>The replication contract</h2>
<table>
<tr><th>Primitive</th><th>What it gives you</th></tr>
<tr><td><code>tip()</code> / <code>tip_collection()</code></td><td>the latest write — the "am I behind?" check</td></tr>
<tr><td><code>since(cursor)</code></td><td>a bounded changefeed of everything after a cursor; <code>has_more</code> is true whenever the cursor is behind head</td></tr>
<tr><td><code>scan_status()</code> / <code>seq_index_ready</code></td><td>readiness — gate replication on this, not on <code>scan_complete</code></td></tr>
</table>

<div class="callout"><b>Why the gate matters:</b> on a warm boot the seq index is empty <i>by
design</i> (it rebuilds from the cold scan). A <code>since()</code> drain that trusted
"zero nodes, has_more = false" would conclude it was caught up while holding none of the
records. <code>has_more</code> is now true whenever the cursor is behind head, and
<code>seq_index_ready</code> says when the index can actually serve.</div>

<h2>State roots — comparing two stores in one hash</h2>
<p>A state root commits to <b>what a database currently says</b> — which collections exist and
what is in them — computable from live state alone, equal for any two databases holding the same
data regardless of route. Uses: replica agreement, drift detection, anchoring, and the
before/after of a diff.</p>

<p>The format (<code>state_root_v1</code>) is specified in <code>docs/state-root-v1.md</code> and
pinned by test vectors (<code>vectors/state_root_v1.json</code>) that both engines must produce
byte-identically — a format pinned by one implementation is not pinned. Leaves commit to logical
content, not object hashes: with encryption on, a node's hash is a function of its ciphertext
(fresh nonce per write), so hashing objects would make equal data produce different roots.</p>

<h2>Live events</h2>
<p><code>GET /events</code> streams SSE: cold-scan progress (objects, rate, ETA), the
<code>ready</code> event, and a <code>write</code> event per commit carrying the seq, collection
and <b>new Merkle head</b> — a follower can tail the chain itself. Query subscriptions
(<code>POST /subscribe</code>) push when a query's results change.</p>

<h2>Honest scope</h2>
<p>This is a replication <i>contract</i>, not a consensus layer. There is no built-in Raft, no
automatic failover, no distributed transactions. If you need multi-master consensus, put a
coordinator above NEDB and use the contract to keep its followers honest. What the contract
<i>does</i> give you: proofs. A follower can verify its store against the source's head, roots
and per-object hashes without trusting it.</p>
"""

BODIES["cast"] = """
<p class="lede">Cast turns a short English prompt into a query plan, using a
<b>3.33M-parameter model that runs locally on CPU</b> — no API key, no network call, no per-token
bill. Ten clauses and six operators is the whole grammar; small enough that a small model can
learn it completely, and small enough that shipping every query to a frontier model is an absurd
amount of machinery.</p>

<h2>The safety properties</h2>
<table>
<tr><th>Property</th><th>What it means</th></tr>
<tr><td>The model never executes</td><td>It emits text; the text goes through the same query path a hand-typed query uses. There is no second executor to audit.</td></tr>
<tr><td>Validation is parsing</td><td>Parse and execute share one code path, so they cannot disagree about what is well-formed. Invalid output is refused with the offending text.</td></tr>
<tr><td><code>execute</code> defaults to false</td><td>You get a plan for review. Running a guess silently is worse than admitting uncertainty.</td></tr>
</table>

<p>That last default earns its keep. A real miss: <i>"paid orders over 100"</i> planned as
<code>LIMIT 100</code> instead of <code>total &gt; 100</code> — and the count came back
<i>correct anyway</i>, because both paid orders happened to exceed 100. A count-only assertion
would have scored it a pass. A human reading the plan catches it; an auto-executing client
does not.</p>

<h2>Why the planner lives in the engine</h2>
<p>The hard part of NL querying is the <b>schema</b>, and a client's copy is stale on arrival.
The engine holds the live collection list, so a plan naming a collection that does not exist
returns <b>422 with the reason</b> — never silently empty rows, because zero rows reads as "no
matching data", which would be a lie. Every daemon client inherits this.</p>

<h2>Drift — the failure <code>valid</code> cannot catch</h2>
<p>A model outside its vocabulary substitutes a memorised literal:
<i>"memories about pricing"</i> became <code>SEARCH "handoff"</code> — which parses, names a real
collection, returns real rows, and answers a question nobody asked. Measured on the released
checkpoint: in-vocabulary terms copied 3/3; out-of-vocabulary terms 0/3. So the response carries
a <code>drift</code> field when a quoted literal does not appear in the prompt — advisory, never
fatal, validated at 24/24 with zero false alarms (correctly inferred enum values stay silent).
An unattended caller should gate on all three:
<code>plan["valid"] and plan["collection_known"] and not plan.get("drift")</code>.</p>

<h2>Where it is strong (and weak) — measured</h2>
<table>
<tr><th>Clause</th><th>Exact-plan match (eval)</th></tr>
<tr><td><code>TRACE caused_by</code></td><td>96.5%</td></tr>
<tr><td><code>TRAVERSE</code></td><td>93.3%</td></tr>
<tr><td>single <code>WHERE</code></td><td>91.2%</td></tr>
<tr><td><code>LIMIT</code></td><td>91.1%</td></tr>
<tr><td><code>SEARCH</code></td><td>90.5%</td></tr>
<tr><td><code>ORDER BY</code></td><td>87.7%</td></tr>
<tr><td>two+ <code>WHERE</code></td><td>85.1% (61.2% adversarial holdout)</td></tr>
<tr><td><code>GROUP BY</code> + aggregate</td><td>77.0%</td></tr>
</table>

<p>Two habits avoid most misses: <b>name the field</b> when a number could be a limit ("orders
with total over 100" beats "orders over 100"), and <b>check numbers over four digits</b> —
digits tokenize one at a time, so <code>400000</code> can come back <code>4000</code>. The model
card publishes every failure mode with examples.</p>

<h2>Enabling it</h2>
<pre><code># compile-time: cargo install nedb-engine --features cast
# weights (~13 MB): GitHub release asset, checksum-verified on load
nedbd --dag --cast ./data</code></pre>

<p>Off by default, feature-gated at compile time and flag-gated at runtime. Built without the
feature the route returns <b>501</b> (not 404) so clients can detect the capability. Without
weights, the daemon logs loudly and serves everything else normally.</p>

<div class="callout"><b>Dogfooding note:</b> the model was trained with NEDB's own parser as
corpus generator (200,000 pairs in 16.5 s, perfect labels), grader (parsed-plan equality, not
string equality) and gate (no example enters unless it round-trips to a canonically identical
plan). Training lineage — datasets → runs → checkpoints → evals — lives in a NEDB database,
chained by <code>caused_by</code>. The engine did not just host the model; it built and audited
it.</div>
"""

BODIES["clients"] = """
<p class="lede">One Rust engine, five ways in. Everything below speaks the same NQL and returns
the same provenance metadata — pick by embedding model, not by feature set.</p>

<h2>Embedded cores (no server)</h2>
<pre><code># Python — pure-Python core, native Rust wheel when available
from nedb import NEDB
db = NEDB("./mydata")          # or NEDB() for in-memory</code></pre>
<pre><code>// Node — napi-rs prebuilt binaries
import { NedbCore } from "nedb-engine";
const db = new NedbCore();     // or NedbCore.open("./data") for durable</code></pre>

<p>Platform coverage: Linux x86_64 + aarch64 (glibc and musl), macOS arm64 + x86_64, Windows
x86_64. On Python, platforms without a native wheel fall back to the universal pure-Python
wheel — correct, slower, no embedded DAG. On Node there is no fallback.</p>

<h2>The HTTP client</h2>
<p><code>nedb.client.NedbClient</code> (Python) and <code>nedb-engine-client</code> (npm) speak
the full daemon surface: queries, atomic CAS transactions (<code>if_seq</code> — the primitive
that replaces Redis Lua scripts), TTL, indexes, relations, Merkle proofs. A CAS miss raises the
same <code>PreconditionFailed</code> shape the embedded engine raises, so code ports without
changing except-clauses.</p>

<pre><code>proof = c.proof(c.log(limit=1)[0]["hash"])
from nedb import verify_proof
verify_proof(proof)   # → True, locally — integrity without trusting the server</code></pre>

<h2>The wrap family — audit what you already run</h2>
<p>One line adds tamper-evident provenance <b>alongside</b> an existing database, no
rip-and-replace. Coverage is opt-out (three tables registered out of twelve looks exactly like
a complete audit trail until the day you need it), and <code>exclude_columns</code> exists
because NEDB cannot forget — that is the product, and it is exactly wrong for a secret.</p>

<table>
<tr><th>wrapper</th><th>host</th><th>shadowing</th></tr>
<tr><td><code>wrap_redis</code></td><td>redis.Redis</td><td>automatic — every write command</td></tr>
<tr><td><code>wrap_sqlite</code></td><td>sqlite3.Connection</td><td>automatic — execute/executemany</td></tr>
<tr><td><code>wrap_postgresql</code></td><td>DB-API 2.0 (psycopg2/3)</td><td>automatic — every cursor write</td></tr>
<tr><td><code>wrap_mysql</code></td><td>DB-API 2.0</td><td>explicit <code>shadow_row()</code></td></tr>
<tr><td><code>wrap_mongo</code></td><td>pymongo</td><td>explicit <code>shadow_row()</code></td></tr>
</table>

<p><b>The limit, stated plainly:</b> interception sees writes made <i>through this connection</i>.
Cron jobs, <code>psql</code> sessions and other services do not pass through — for
whole-database coverage the right mechanism is Postgres logical replication, which is not
implemented yet and is not pretended. Unmirrored writes land in
<code>nedb.unmirrored_tables</code> rather than vanishing.</p>

<p><b>Backends:</b> <code>backend="auto"</code> selects nedbd over HTTP, the embedded DAG, or
the v1 AOF engine as universal fallback — and auto never picks an engine <i>less durable</i>
than the call site had.</p>

<div class="callout"><b>Isolation guarantee:</b> NEDB never writes into the host database's
namespace. Shadow data lives only in the NEDB engine (Redis: the
<code>nedb:{db}:oplog|snapshot|meta</code> keys, nothing else).</div>
"""

BODIES["cli"] = """
<p class="lede">Three CLIs ship with the engine. Two operate on store directories offline — no
daemon, no port; one opens a store and speaks both halves of the query language.</p>

<h2>nedb-cli — offline operations</h2>
<pre><code>cargo install nedb-engine   # ships nedb-cli + nedb-inspector

nedb-cli head ./data         # the Merkle tip
nedb-cli status ./data       # objects, segments, scan state
nedb-cli verify ./data       # walk the chain
nedb-cli get ./data &lt;coll&gt; &lt;id&gt;
nedb-cli scan ./data         # force the integrity scan
nedb-cli flush ./data
nedb-cli repair ./data       # rebuild the derivable id index
nedb-cli export ./data</code></pre>

<p><code>repair</code> exists because every object carries its own <code>coll</code>/<code>id</code>/<code>seq</code>:
the index is fully derivable, nothing is invented — it rebuilds entries, verifies nodes, flushes,
and reports exactly what it did.</p>

<h2>nesql — the language CLI</h2>
<pre><code>nesql --db ./store query "SELECT who, total FROM orders ORDER BY total DESC"
nesql --db ./store query "FROM orders WHERE total > 150"
nesql --db ./store root verify
nesql --db ./store constitution</code></pre>

<p>Speaks both neSQL statement forms through one router (the same
<code>nedb_engine::neql::route</code> the daemon uses). <code>--json</code> emits exactly one JSON object on stdout with diagnostics on
stderr — a pipe stays clean. Exit codes: <code>0</code> success · <code>1</code> failure ·
<code>2</code> usage · <code>3</code> <b>could not determine</b> (pruned history) · <code>4</code>
not found · <code>5</code> unsupported. <b>3 is the one that matters:</b> a pruned store is not a
corrupt one, and <code>root verify</code> reports stored record and recomputation as two
independent facts — only <code>recomputation DIFFERS</code> is an alarm.</p>

<p>Beyond query: <code>status</code>, <code>log</code>, <code>inspect</code> (collection /
document / sequence / persisted root — named by kind, because a bare <code>42</code> could be
either and the CLI refuses to pick), <code>diff</code>, immutable <code>tag</code>,
<code>branch</code>, <code>merge</code> with first-class conflicts, and
<code>grammar</code>/<code>constitution</code> — digests of the command surface and the engine's
guarantees, comparable across builds, so a deployment can prove it agrees with the binary that
shipped.</p>

<h2>nedb-inspector</h2>
<p>A deterministic checker (no regex, no LLM) that warns when a durable open lacks
flush-on-exit wiring — the exact gap that made crash-lost-writes possible in embedded use.
See <a href="durability.html">Durability</a>.</p>

<h2>Shell tooling for Cast</h2>
<pre><code>. ./scripts/nedb.sh      # bash / zsh / Git Bash
nedb-dbs                  # which databases exist
nedb-use shop             # pick one
cast "orders over 100"    # plan only — nothing runs
cast -x "orders over 100" # plan AND execute</code></pre>

<p><code>NEDB=http://host:7070</code> points the shell helpers at a remote daemon. Prompts are
JSON-escaped, so quotes and apostrophes are safe.</p>
"""

BODIES["architecture"] = """
<p class="lede">One principle, three generations: <b>state is a pure function of a sealed
log.</b> Everything else — time travel, provenance, proofs — falls out of that sentence.</p>

<h2>The pipeline</h2>
<pre><code>            ┌──────────────────────────────────────────────────────────┐
  put/del → │  OpLog  (BLAKE2b hash chain · per-client nonce ·          │ ← single source of truth
  link      │          idempotency keys · causal provenance fields)     │
            └───────────────┬──────────────────────────────────────────┘
            deterministic fold │ (state = pure function of the log)
     ┌──────────────┬──────────┴──────┬───────────────┬────────────────┐
     ▼              ▼                 ▼               ▼                ▼
MVCC store     Relations          Indexes         CauseMap          BlobStore
(time-travel)  (graph+AS OF)      eq/ord/search   (reverse index)   (Cascade CDC)

                     ┌─────────────────────────────────┐
  Thread-safe →      │  Sequencer (group-commit)         │ ← single writer, parallel readers
                     │  — one committer thread/db        │
                     │  — batch fsync                    │
                     └─────────────────────────────────┘</code></pre>

<p>The provenance machinery is load-bearing, not metadata stapled on: <code>CauseMap</code> is a
reverse index over causal edges (that is why <code>TRACE … REVERSE</code> is as fast as forward),
and the Relations layer backs both <code>TRAVERSE</code> and the <code>AS OF</code> joins. The
daemon is a single-writer group-commit sequencer — parallel reads, batched durable writes, one
hash chain per database, zero write-write races.</p>

<h2>Three storage generations</h2>
<table>
<tr><th>Gen</th><th>Layout</th><th>Trade</th></tr>
<tr><td>v1 · AOF</td><td>append-only log, replay on open</td><td>simple, universal fallback; O(n) restart</td></tr>
<tr><td>v2 · DAG</td><td>content-addressed loose objects, one file per version, MANIFEST for O(1) warm start</td><td>trivially atomic writes; file-metadata churn at scale (~185 writes/s ceiling on busy disks)</td></tr>
<tr><td>v3 · segments</td><td>append-only packs, one fsync per batch, .idx sidecars, compaction</td><td>cost tracks bytes not object count; opt-in, dual-read compatible with v2</td></tr>
</table>

<p>Same API across all three — a v1 store auto-migrates to the DAG on first <code>--dag</code>
startup, and v2 stores open in v3 mode without a rewrite. Cold starts accept connections
immediately (reads serve from the DAG; writes return 503 until the scan gate flips, progress
streams over <code>/events</code>); every restart after the first is O(1) from the MANIFEST.</p>

<h2>Encryption</h2>
<p>AES-256-GCM at rest with a TMK/DEK double-envelope: a 32-byte hex master key
(<code>NEDB_TMK</code>) wraps per-database data keys. Key handling fails <b>closed</b> — a
malformed provided key is an error, never a silent fall-through to plaintext. Because a node's
hash is a function of its ciphertext, state-root leaves commit to logical content rather than
object hashes (see <a href="provenance.html">Provenance</a>).</p>

<h2>Repo layout</h2>
<pre><code>python/nedb/        reference engine (pure Python — always-works baseline)
rust/
  nedb-v2/          v2/v3 DAG engine (tokio + axum + BLAKE2b) — the core everything binds
  nesql-cli/        the nesql CLI
  nedb-core/        v1 Rust engine
  nedb-py/          maturin PyO3 binding → PyPI native wheels
  nedb-node/        napi-rs binding → npm native addons
  nedb-wrap/        the wrap_* surface at native speed
vendor/postgresql/  PostgreSQL 17.4 grammar, vendored (gram.y, kwlist.h, …)
distributions/      crypto-database + aof-db submodules (tri-distribution)
bench/              benchmarks.py + RESULTS.md — the dated numbers
vectors/            state_root_v1.json — cross-engine test vectors
tests/              engine + concurrent + causal + bitemporal + deploy + perf suites</code></pre>
"""

BODIES["releasing"] = """
<p class="lede">NEDB ships as <b>three version-aligned distributions from a single git tag</b> —
<code>nedb-engine</code> (flagship), <code>crypto-database</code> (verifiable v2/v3 DAG),
<code>aof-db</code> (fast append-only) — across PyPI, npm and crates.io, with native addons for
macOS (arm64 + x86_64), Linux (x86_64 + aarch64, glibc + musl) and Windows x86_64.</p>

<h2>The tool</h2>
<pre><code>python3 scripts/release.py "vFROM" "vTO"     # both args require the leading 'v'</code></pre>

<p>One command: bumps <b>every version-bearing manifest</b> in the flagship and both
distribution forks, opens and merges a release PR per repo, repoints the
<code>distributions/*</code> submodules, and tags <code>vTO</code> — firing <code>release.yml</code>
(flagship), <code>release-distros.yml</code> (distros) and Codemagic (macOS wheels) to publish
all three distributions aligned on one version. It is idempotent: repos already at
<code>TO</code> are skipped, an existing tag is left in place, remaining steps always run — a
half-finished release re-runs safely. It never force-pushes and never commits to master
directly; every change lands through a branch + PR + merge.</p>

<h2>The rules the hard way</h2>
<ul>
<li><b>Never retag.</b> A bug in vX.Y.Z is fixed by vX.Y.Z+1. Retagging breaks CI, Codemagic and immutable-release semantics — always bump, never retag.</li>
<li><b>Only tag when the work is 100% complete.</b> Commit to master freely; hold the tag and the publish until everything is done and tested. One sprint, one bump, one tag, one ship.</li>
<li><b>Version files move together or not at all.</b> Six files must always carry the identical string — root <code>pyproject.toml</code>, <code>python/nedb/__init__.py</code>, <code>package.json</code>, <code>rust/Cargo.toml</code> (workspace), <code>rust/crates/nedb-py/pyproject.toml</code>, <code>rust/nedb-v2/Cargo.toml</code>. A straggler stuck at an old version is the classic failure mode: single-token regex bumps silently miss them.</li>
<li><b>A version string in a repo is not evidence of a publish.</b> Verify against the registries — a fresh install — before calling a release shipped. CI green is necessary, never sufficient.</li>
<li><b>Never claim shipped off an in-flight workflow.</b> Real CI job conclusions first, then a live registry check.</li>
</ul>

<h2>CI layout</h2>
<p><code>test.yml</code> runs the suite matrix on every push and PR — dependency-free suites
across interpreters, the Rust engine and bindings, the Node addon with a smoke gate, maturin
wheels, and the daemon HTTP suites. It was not always so: for the first year the only workflows
fired on version tags, so the first automated opinion arrived <i>after</i> publishing to three
registries. The push-gate found four real defects in its first hour. Release workflows build
and publish on <code>v*</code>; macOS addons build on Codemagic M2 runners.</p>

<h2>Registry names</h2>
<table>
<tr><th>Distribution</th><th>PyPI</th><th>npm</th><th>crates.io</th></tr>
<tr><td>flagship</td><td><code>nedb-engine</code></td><td><code>nedb-engine</code></td><td><code>nedb-engine</code></td></tr>
<tr><td>verifiable DAG</td><td><code>cryptodb</code> (name taken by a third party)</td><td><code>crypto-database</code></td><td><code>crypto-database</code></td></tr>
<tr><td>append-only</td><td><code>aof-db</code></td><td><code>aof-db</code></td><td><code>aof-db</code></td></tr>
</table>

<p>The neSQL packages (<code>nesql</code> on PyPI/crates, <code>nesql-engine</code> on npm) are
version-aligned with the engine; the crates.io crate is the working CLI. See
<a href="https://github.com/Eth-Interchained/neSQL">Eth-Interchained/neSQL</a>.</p>
"""

# ── rendering ────────────────────────────────────────────────────────────────

CSS = """
:root{--sb:#0b0e14;--sb2:#0f131c;--line:#232b3d;--line2:#2c3550;--text:#1f2430;--dim:#5b6474;
--faint:#8a93a3;--amber:#ea580c;--amber2:#c2410c;--emerald:#059669;--cyan:#0891b2;--code-bg:#0b0e14;
--sans:'Inter',system-ui,sans-serif;--mono:'JetBrains Mono',ui-monospace,monospace}
*{margin:0;padding:0;box-sizing:border-box}
html{scroll-behavior:smooth}
body{font-family:var(--sans);color:var(--text);line-height:1.7;font-size:16px;background:#fff}
a{color:var(--amber2);text-decoration:none}a:hover{text-decoration:underline}
.layout{display:flex;min-height:100vh}
/* sidebar */
.sidebar{width:290px;flex-shrink:0;background:var(--sb);color:#cdd5e1;position:sticky;top:0;height:100vh;overflow-y:auto;padding:26px 0 40px}
.sidebar .brand{display:flex;align-items:center;gap:10px;font-weight:800;font-size:17px;color:#fff;padding:0 24px 18px;letter-spacing:-.02em;text-decoration:none}
.sidebar .brand .dot{width:10px;height:10px;border-radius:50%;background:var(--emerald);box-shadow:0 0 12px var(--emerald)}
.sidebar .brand small{font-family:var(--mono);font-size:10.5px;color:#6b7690;font-weight:400;margin-left:auto}
.sgroup{font-family:var(--mono);font-size:10.5px;letter-spacing:.14em;text-transform:uppercase;color:#6b7690;padding:18px 24px 6px}
.sidebar a.item{display:block;padding:7px 24px;font-size:14px;color:#9aa5bd;text-decoration:none;border-left:3px solid transparent}
.sidebar a.item:hover{color:#fff;background:rgba(255,255,255,.04);text-decoration:none}
.sidebar a.item.active{color:#fff;border-left-color:var(--emerald);background:rgba(52,211,153,.08)}
.search{margin:4px 20px 10px}
.search input{width:100%;background:var(--sb2);border:1px solid var(--line);border-radius:9px;color:#e8ecf4;font-family:var(--sans);font-size:13.5px;padding:9px 12px;outline:none}
.search input:focus{border-color:var(--line2)}
/* content */
.main{flex:1;min-width:0;background:#fff}
.content{max-width:820px;padding:48px 56px 80px}
.crumbs{font-family:var(--mono);font-size:12px;color:var(--faint);margin-bottom:18px}
.crumbs a{color:var(--faint)}.crumbs a:hover{color:var(--amber2)}
h1{font-size:34px;font-weight:800;letter-spacing:-.025em;line-height:1.15;margin-bottom:14px}
h2{font-size:22px;font-weight:750;letter-spacing:-.015em;margin:38px 0 12px;padding-top:8px}
h3{font-size:17px;font-weight:700;margin:24px 0 8px}
p{margin:0 0 14px}
.lede{font-size:18.5px;color:#3a4152;border-left:3px solid var(--emerald);padding-left:16px;margin-bottom:24px}
ul,ol{margin:0 0 14px 22px}
li{margin-bottom:6px}
code{font-family:var(--mono);font-size:.86em;background:#f1f3f7;border:1px solid #e4e8ef;border-radius:5px;padding:1.5px 6px;color:#0f172a}
pre{background:var(--code-bg);border:1px solid #1c2331;border-radius:12px;padding:18px 20px;overflow-x:auto;margin:16px 0 20px}
pre code{background:none;border:none;color:#d5dde8;padding:0;font-size:13px;line-height:1.7}
table{border-collapse:collapse;width:100%;font-size:14.5px;margin:16px 0 20px}
th{font-family:var(--mono);font-size:11px;letter-spacing:.07em;text-transform:uppercase;color:var(--faint);text-align:left;padding:9px 12px;border-bottom:2px solid #e4e8ef}
td{padding:9px 12px;border-bottom:1px solid #eef1f5;color:#3a4152;vertical-align:top}
td:first-child{color:var(--text);font-weight:600}
.callout{background:#fff7ed;border:1px solid #fed7aa;border-radius:12px;padding:14px 18px;margin:16px 0 20px;font-size:14.5px}
.pager{display:flex;justify-content:space-between;gap:16px;margin-top:52px;padding-top:22px;border-top:1px solid #eef1f5}
.pager a{display:block;max-width:46%;padding:14px 18px;border:1px solid #e4e8ef;border-radius:12px;color:var(--text);font-weight:600;font-size:14px}
.pager a:hover{border-color:var(--amber);text-decoration:none}
.pager a small{display:block;font-family:var(--mono);font-size:11px;color:var(--faint);font-weight:400;margin-bottom:3px}
.pager a.next{text-align:right;margin-left:auto}
.editlink{font-family:var(--mono);font-size:12px;color:var(--faint);margin-top:26px}
.editlink a{color:var(--faint)}
@media(max-width:900px){.sidebar{position:fixed;left:-300px;transition:.2s;z-index:99}.sidebar.open{left:0}.content{padding:28px 22px 60px}.menu-btn{display:block !important}}
.menu-btn{display:none;position:fixed;top:12px;left:12px;z-index:100;background:var(--sb);color:#fff;border:1px solid var(--line2);border-radius:9px;font-size:17px;padding:7px 13px;cursor:pointer}
"""

SHELL = """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>{title} — NEDB Documentation</title>
<meta name="description" content="{desc}">
<link rel="preconnect" href="https://fonts.googleapis.com">
<link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
<link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700;800&family=JetBrains+Mono:wght@400;500;700&display=swap" rel="stylesheet">
<style>{css}</style>
</head>
<body>
<button class="menu-btn" onclick="document.querySelector('.sidebar').classList.toggle('open')">☰</button>
<div class="layout">
<nav class="sidebar">
  <a class="brand" href="index.html"><span class="dot"></span>NEDB Docs <small id="docsver">v8.0.0</small></a>
  <div class="search"><input type="search" placeholder="Filter pages…" oninput="filterPages(this.value)"></div>
  {nav}
</nav>
<main class="main"><div class="content">
  <div class="crumbs">{crumbs}</div>
  {body}
  {editlink}
  <div class="pager">{pager}</div>
</div></main>
</div>
<script>
(function () {{
  var el = document.getElementById("docsver");
  if (!el) return;
  fetch("https://pypi.org/pypi/nedb-engine/json")
    .then(function (r) {{ return r.json(); }})
    .then(function (d) {{
      if (d && d.info && d.info.version) el.textContent = "v" + d.info.version;
    }})
    .catch(function () {{}});
}})();
</script>
<script>
function filterPages(q){{
  q=q.toLowerCase();
  document.querySelectorAll('.sidebar a.item').forEach(a=>{{
    a.style.display = a.textContent.toLowerCase().includes(q) ? 'block':'none';
  }});
}}
</script>
</body>
</html>
"""


def build():
    os.makedirs(OUT, exist_ok=True)
    groups = []
    for slug, title, group, blurb in PAGES:
        if group not in groups:
            groups.append(group)

    nav_parts = []
    for g in groups:
        nav_parts.append(f'<div class="sgroup">{html_mod.escape(g)}</div>')
        for slug, title, g2, _ in PAGES:
            if g2 == g:
                nav_parts.append(
                    f'<a class="item" data-slug="{slug}" href="{slug}.html">{html_mod.escape(title)}</a>')
    nav_html = "\n  ".join(nav_parts)

    written = []
    for i, (slug, title, group, blurb) in enumerate(PAGES):
        prev_pg = PAGES[i - 1] if i > 0 else None
        next_pg = PAGES[i + 1] if i < len(PAGES) - 1 else None
        pager = ""
        if prev_pg:
            pager += (f'<a class="prev" href="{prev_pg[0]}.html"><small>← Previous</small>'
                      f'{html_mod.escape(prev_pg[1])}</a>')
        if next_pg:
            pager += (f'<a class="next" href="{next_pg[0]}.html"><small>Next →</small>'
                      f'{html_mod.escape(next_pg[1])}</a>')
        body = BODIES[slug]
        crumbs = f'<a href="index.html">NEDB Docs</a> / {html_mod.escape(group)}'
        if slug != "index":
            crumbs = f'<a href="index.html">NEDB Docs</a> / {html_mod.escape(group)} / {html_mod.escape(title)}'
        editlink = ('<div class="editlink">Found something wrong or missing? '
                    '<a href="https://github.com/aiassistsecure/nedb/edit/master/tools/build_docs_site.py" '
                    'target="_blank" rel="noopener noreferrer">Edit the source</a> and rebuild — '
                    'these pages are generated from <code>tools/build_docs_site.py</code>.</div>'
                    ) if slug != "index" else ""
        page = SHELL.format(
            title=html_mod.escape(title), desc=html_mod.escape(blurb), css=CSS,
            nav=nav_html, crumbs=crumbs, body=body, pager=pager, editlink=editlink)
        path = os.path.join(OUT, f"{slug}.html")
        with open(path, "w") as f:
            f.write(page)
        written.append(f"{slug}.html")

    # llms.txt — machine-readable twin
    lines = ["# NEDB Documentation (deep dives)", "",
             "GitBook-styled official docs for nedb-engine v8.0.0. Generated from tools/build_docs_site.py.", ""]
    for slug, title, group, blurb in PAGES:
        lines.append(f"- [{title}]({slug}.html): {blurb}")
    with open(os.path.join(OUT, "llms.txt"), "w") as f:
        f.write("\n".join(lines) + "\n")
    written.append("llms.txt")

    print("written:", ", ".join(written))


if __name__ == "__main__":
    build()
