"""SQLite-backed retrieval and memory for the Prompt Injection Firewall demo.

Two things live here, both of them security-relevant:

**Retrieval.** Records in `data/*.jsonl` are split into one chunk per field,
and each chunk carries a `source` and a `trust` label. Trust is per-field, not
per-document (D-007): a log line written by our own collector is trustworthy
about its timestamp and source IP, and says nothing at all about whether the
user-agent string an attacker chose is safe to follow. That split is what makes
S1 legible in the trace — one chunk of an otherwise ordinary log line is the
untrusted one.

**Memory.** Records are per-session and tiered: `long_term` is reused by later
runs, `quarantine` is held for human review. The `tier`, `status` and
`provenance` columns exist from the first schema so that D2 (the memory write
gate, M2) arrives as a policy change rather than a migration.
"""
from __future__ import annotations

import json
import re
import sqlite3
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path

import yaml

BASE_DIR = Path(__file__).resolve().parent
DATA_DIR = BASE_DIR / "data"
TRUST_MAP_PATH = DATA_DIR / "trust_map.yaml"

INTERNAL = "internal"
ATTACKER_CONTROLLABLE = "attacker_controllable"
TRUST_LEVELS = frozenset({INTERNAL, ATTACKER_CONTROLLABLE})

TIERS = frozenset({"long_term", "quarantine"})
STATUSES = frozenset({"active", "approved", "rejected"})

#: Fields that identify a record rather than carry content.
_SKIP_FIELDS = frozenset({"id", "doc_type"})


@dataclass(frozen=True)
class Chunk:
    """One retrievable field of one record."""

    id: str  # "doc_type:doc_id:field", e.g. "log:evt-00042:user_agent"
    text: str
    source: str  # human-readable provenance, shown in the UI
    trust: str  # "internal" | "attacker_controllable"
    doc_type: str  # "log" | "alert" | "ticket"
    score: float  # higher is more relevant


@dataclass
class MemoryRecord:
    """One remembered fact, with the provenance it was written from."""

    id: str
    session_id: str
    tier: str
    content: str
    provenance: list[str] = field(default_factory=list)
    trust: str = INTERNAL
    status: str = "active"
    created_at: str = ""


# --- trust -------------------------------------------------------------------


_TRUST_MAP_CACHE: dict[str, dict] = {}


def load_trust_rules(path: Path | str = TRUST_MAP_PATH) -> dict:
    """The trust map: globally untrusted fields, plus per-doc-type additions.

    Cached per path: consulted once per chunk on every ingest and once per
    provenance id on every memory write.
    """
    key = str(path)
    if key not in _TRUST_MAP_CACHE:
        with open(path, "r", encoding="utf-8") as fh:
            raw = yaml.safe_load(fh) or {}
        _TRUST_MAP_CACHE[key] = {
            "global": set(raw.get("attacker_controllable") or []),
            "by_doc_type": {
                doc_type: set(fields or [])
                for doc_type, fields in (raw.get("by_doc_type") or {}).items()
            },
        }
    return _TRUST_MAP_CACHE[key]


def load_trust_map(path: Path | str = TRUST_MAP_PATH) -> set[str]:
    """Field names an attacker can influence in any document type."""
    return load_trust_rules(path)["global"]


def trust_for_field(
    field_name: str, untrusted_fields: set[str] | None = None, doc_type: str | None = None
) -> str:
    """Trust label for a field of a document.

    Keyed on the document type as well as the field name: the same word means
    different things in different records. A detection rule writes an alert's
    `title`; whoever opens a ticket writes the ticket's, and they are exactly
    the person who writes its `comment`. Found in review — a payload moved
    from a ticket comment into its title was labelled `internal`, which turned
    off D1, D2 and D3 at once.

    Defaults to `internal` only because the map enumerates what is reachable
    by an attacker; a field added later without a map entry is a known gap,
    not a safe default. Keep the map current when data gains fields.
    """
    rules = load_trust_rules()
    fields = rules["global"] if untrusted_fields is None else set(untrusted_fields)
    if doc_type:
        fields = fields | rules["by_doc_type"].get(doc_type, set())
    return ATTACKER_CONTROLLABLE if field_name in fields else INTERNAL


def chunk_trust(chunk_id: str, conn: sqlite3.Connection | None = None) -> str:
    """Trust of a chunk id: from the DB when it knows the chunk, else closed.

    An id the corpus cannot resolve — stale provenance that survived a rebuild,
    a hand-written fixture, a crafted string — is treated as
    attacker_controllable. "Provenance I cannot check" is the case the memory
    gate most needs to catch, and a field-name guess fails open on anything it
    does not recognise: a trailing space, different case, an extra segment, or
    simply a field added to the data without a trust_map entry.
    """
    if conn is not None:
        row = conn.execute("SELECT trust FROM chunks WHERE id = ?", (chunk_id,)).fetchone()
        return row[0] if row is not None else ATTACKER_CONTROLLABLE
    parts = chunk_id.split(":")
    if len(parts) >= 2:
        return trust_for_field(parts[-1].strip(), doc_type=parts[0].strip())
    return ATTACKER_CONTROLLABLE


def max_trust(chunk_ids, conn: sqlite3.Connection | None = None) -> str:
    """The least trustworthy label across these chunks."""
    for cid in chunk_ids or ():
        if chunk_trust(cid, conn) == ATTACKER_CONTROLLABLE:
            return ATTACKER_CONTROLLABLE
    return INTERNAL


# --- schema and ingestion -----------------------------------------------------

_SCHEMA = """
CREATE TABLE IF NOT EXISTS chunks (
    id       TEXT PRIMARY KEY,
    text     TEXT NOT NULL,
    source   TEXT NOT NULL,
    trust    TEXT NOT NULL,
    doc_type TEXT NOT NULL,
    doc_id   TEXT NOT NULL,
    field    TEXT NOT NULL
);

CREATE VIRTUAL TABLE IF NOT EXISTS chunks_fts USING fts5(
    id UNINDEXED,
    text
);

CREATE TABLE IF NOT EXISTS memory (
    id         TEXT PRIMARY KEY,
    session_id TEXT NOT NULL,
    tier       TEXT NOT NULL,
    content    TEXT NOT NULL,
    provenance TEXT NOT NULL,
    trust      TEXT NOT NULL,
    status     TEXT NOT NULL,
    created_at TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS memory_session_idx ON memory (session_id);
"""


def _flatten(value) -> str:
    if isinstance(value, (list, tuple)):
        return " ".join(str(v) for v in value)
    return str(value)


def iter_chunk_rows(data_dir: Path | str = DATA_DIR):
    """Yield `(Chunk, doc_id, field)` for every field of every record.

    The doc id and field name come from the record itself rather than from
    splitting the chunk id: a doc id containing a colon would otherwise write
    the wrong value into the `field` column.
    """
    data_dir = Path(data_dir)
    untrusted_fields = load_trust_map(data_dir / "trust_map.yaml")

    for path in sorted(data_dir.glob("*.jsonl")):
        with open(path, "r", encoding="utf-8") as fh:
            for line in fh:
                line = line.strip()
                if not line:
                    continue
                record = json.loads(line)
                doc_id = record["id"]
                doc_type = record["doc_type"]
                for name, value in record.items():
                    if name in _SKIP_FIELDS or value in (None, "", [], {}):
                        continue
                    text = _flatten(value)
                    yield (
                        Chunk(
                            id=f"{doc_type}:{doc_id}:{name}",
                            text=text,
                            source=f"{path.name}#{doc_id} field={name}",
                            trust=trust_for_field(name, untrusted_fields, doc_type=doc_type),
                            doc_type=doc_type,
                            score=0.0,
                        ),
                        doc_id,
                        name,
                    )


def iter_chunks(data_dir: Path | str = DATA_DIR):
    """Yield one Chunk per field of every record in `data/*.jsonl`."""
    for chunk, _doc_id, _field in iter_chunk_rows(data_dir):
        yield chunk


def build_db(path: str = ":memory:", data_dir: Path | str = DATA_DIR) -> sqlite3.Connection:
    """Create the schema and (re)load `data/` into it. Idempotent.

    Rebuilding replaces the chunk corpus but never touches `memory`: sessions
    survive a rebuild, which is what makes S2's "persists across runs" real.
    """
    # check_same_thread=False: FastAPI runs sync handlers on a threadpool.
    # Note this permits sharing but does not make sharing safe — see
    # `app.get_db`, which hands every caller its own connection.
    conn = sqlite3.connect(path, check_same_thread=False)
    if path != ":memory:":
        # WAL lets readers and writers work concurrently instead of
        # serialising behind a global lock. Without it, two side-by-side runs
        # deadlock or drop writes.
        conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA busy_timeout=10000")
    conn.executescript(_SCHEMA)

    conn.execute("DELETE FROM chunks")
    conn.execute("DELETE FROM chunks_fts")

    rows = [
        (c.id, c.text, c.source, c.trust, c.doc_type, doc_id, field_name)
        for c, doc_id, field_name in iter_chunk_rows(data_dir)
    ]
    conn.executemany(
        "INSERT OR REPLACE INTO chunks (id, text, source, trust, doc_type, doc_id, field)"
        " VALUES (?, ?, ?, ?, ?, ?, ?)",
        rows,
    )
    conn.executemany(
        "INSERT INTO chunks_fts (id, text) VALUES (?, ?)",
        [(r[0], r[1]) for r in rows],
    )
    conn.commit()
    return conn


# --- retrieval ----------------------------------------------------------------

_TOKEN_RE = re.compile(r"[A-Za-z0-9_]+")

#: FTS5's operators. They are only operators in upper case, so a lower-case
#: "not" in an analyst's query stays a search term.
_FTS5_KEYWORDS = frozenset({"AND", "OR", "NOT", "NEAR"})


def to_match_query(query: str) -> str:
    """Turn arbitrary user/agent text into a safe FTS5 MATCH expression.

    FTS5's query language is a language: quotes, `*`, `NEAR`, `AND`/`OR` and
    unbalanced parentheses all parse, and a malformed one raises
    sqlite3.OperationalError mid-request. Rather than escape the syntax, drop
    it: keep the alphanumeric tokens and quote each one, so the query can only
    ever be a conjunction of literal terms. An empty result means "no usable
    terms", which callers treat as no match.
    """
    tokens = [t for t in _TOKEN_RE.findall(query or "") if t not in _FTS5_KEYWORDS]
    return " ".join('"%s"' % t for t in tokens)


def search(conn: sqlite3.Connection, query: str, limit: int = 5) -> list[Chunk]:
    """Full-text search over the corpus, most relevant first.

    Every result carries `source` and `trust` (§3) — there is no code path
    that returns a chunk without them, because the defenses downstream key
    off exactly those two fields.
    """
    match = to_match_query(query)
    if not match:
        return []

    try:
        rows = conn.execute(
            """
            SELECT c.id, c.text, c.source, c.trust, c.doc_type, bm25(chunks_fts) AS rank
            FROM chunks_fts
            JOIN chunks c ON c.id = chunks_fts.id
            WHERE chunks_fts MATCH ?
            ORDER BY rank
            LIMIT ?
            """,
            (match, limit),
        ).fetchall()
    except sqlite3.OperationalError:
        # Defence in depth: tokenisation should make this unreachable, but a
        # retrieval error must not take down a run.
        return []

    # bm25() is negative and lower-is-better; flip it so `score` reads as
    # "higher is more relevant" everywhere above this line.
    return [
        Chunk(id=r[0], text=r[1], source=r[2], trust=r[3], doc_type=r[4], score=-float(r[5]))
        for r in rows
    ]


def get_chunk(conn: sqlite3.Connection, chunk_id: str) -> Chunk | None:
    row = conn.execute(
        "SELECT id, text, source, trust, doc_type FROM chunks WHERE id = ?", (chunk_id,)
    ).fetchone()
    if row is None:
        return None
    return Chunk(id=row[0], text=row[1], source=row[2], trust=row[3], doc_type=row[4], score=0.0)


# --- memory -------------------------------------------------------------------


def _row_to_record(row) -> MemoryRecord:
    return MemoryRecord(
        id=row[0],
        session_id=row[1],
        tier=row[2],
        content=row[3],
        provenance=json.loads(row[4]),
        trust=row[5],
        status=row[6],
        created_at=row[7],
    )


def save_memory(
    conn: sqlite3.Connection,
    session_id: str,
    content: str,
    provenance: list[str] | None = None,
    tier: str = "long_term",
) -> MemoryRecord:
    """Write a fact into a session's memory.

    The record keeps the chunk ids that were in context when it was written.
    That provenance is what D2 gates on in M2, and it is why the tier is a
    parameter here rather than a decision made inside this function — the
    policy lives in the agent loop, the storage does not have opinions.
    """
    if tier not in TIERS:
        raise ValueError(f"unknown memory tier {tier!r}; expected one of {sorted(TIERS)}")

    provenance = list(provenance or [])
    record = MemoryRecord(
        id=f"mem-{uuid.uuid4().hex[:12]}",
        session_id=session_id,
        tier=tier,
        content=content,
        provenance=provenance,
        trust=max_trust(provenance, conn),
        status="active",
        created_at=datetime.now(timezone.utc).isoformat(),
    )
    conn.execute(
        "INSERT INTO memory (id, session_id, tier, content, provenance, trust, status,"
        " created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
        (
            record.id,
            record.session_id,
            record.tier,
            record.content,
            json.dumps(record.provenance),
            record.trust,
            record.status,
            record.created_at,
        ),
    )
    conn.commit()
    return record


def recall_memory(conn: sqlite3.Connection, session_id: str) -> list[MemoryRecord]:
    """Facts this session may reuse: long_term, and not rejected.

    Quarantined records are never returned, whatever their status — that is
    the whole point of the tier. A human moves one into `long_term` by
    approving it.
    """
    rows = conn.execute(
        "SELECT id, session_id, tier, content, provenance, trust, status, created_at"
        " FROM memory WHERE session_id = ? AND tier = 'long_term'"
        " AND status IN ('active', 'approved') ORDER BY created_at",
        (session_id,),
    ).fetchall()
    return [_row_to_record(r) for r in rows]


def list_memory(conn: sqlite3.Connection, session_id: str, tier: str | None = None):
    """Every record for a session, for the UI's quarantine panel."""
    sql = (
        "SELECT id, session_id, tier, content, provenance, trust, status, created_at"
        " FROM memory WHERE session_id = ?"
    )
    params: list = [session_id]
    if tier is not None:
        sql += " AND tier = ?"
        params.append(tier)
    return [_row_to_record(r) for r in conn.execute(sql + " ORDER BY created_at", params)]


def approve(conn: sqlite3.Connection, rec_id: str, session_id: str | None = None) -> None:
    """Human approval: promote a quarantined record into long-term memory.

    `session_id` scopes the update. The UI must always pass it: record ids are
    guessable, and without the scope one visitor's approval can promote another
    visitor's quarantined record into their long-term memory.
    """
    if session_id is None:
        conn.execute(
            "UPDATE memory SET tier = 'long_term', status = 'approved' WHERE id = ?", (rec_id,)
        )
    else:
        conn.execute(
            "UPDATE memory SET tier = 'long_term', status = 'approved'"
            " WHERE id = ? AND session_id = ?",
            (rec_id, session_id),
        )
    conn.commit()


def reject(conn: sqlite3.Connection, rec_id: str, session_id: str | None = None) -> None:
    """Human rejection: the record stays quarantined and is never recalled."""
    if session_id is None:
        conn.execute("UPDATE memory SET status = 'rejected' WHERE id = ?", (rec_id,))
    else:
        conn.execute(
            "UPDATE memory SET status = 'rejected' WHERE id = ? AND session_id = ?",
            (rec_id, session_id),
        )
    conn.commit()


def reset_session(conn: sqlite3.Connection, session_id: str) -> None:
    """Clear everything this session remembers, both tiers (§3)."""
    conn.execute("DELETE FROM memory WHERE session_id = ?", (session_id,))
    conn.commit()


# --- alert-centric retrieval ----------------------------------------------

#: Chunks pulled in for an alert before the first model turn.
RETRIEVAL_LIMIT = 16

#: Field ordering for retrieval. Per-field chunking means one alert can emit a
#: dozen chunks, most of them a timestamp or a port number; without an order,
#: a naive limit fills the context with metadata and never reaches the field
#: that actually says something. Content first, identifiers next, bookkeeping
#: last.
FIELD_PRIORITY = [
    "summary",
    "title",
    "message",
    "user_agent",
    "url",
    "referer",
    "comment",
    "body",
    "dns_query",
    "filename",
    "host",
    "hostname",
    "src_ip",
    "dest_ip",
    "user",
    "severity",
    "rule",
    "event_type",
    "action",
    "status",
    "assignee",
    "dest_port",
    "related_logs",
    "ts",
]


def field_rank(chunk_id: str) -> int:
    field_name = chunk_id.split(":")[-1]
    return FIELD_PRIORITY.index(field_name) if field_name in FIELD_PRIORITY else len(FIELD_PRIORITY)


def retrieve_for_alert(conn, alert_id: str, limit: int = RETRIEVAL_LIMIT) -> list[Chunk]:
    """Pull the alert and the logs it references.

    This is the RAG step an analyst assistant actually performs: the alert
    names related records, so those get read. It is also how the injection
    gets in — evt-00042 is in ALR-1001's related_logs, and one of its fields
    is attacker-controlled.

    Documents are interleaved rather than concatenated, so every related log
    contributes its most informative field before any document contributes its
    second. Otherwise the first log's metadata crowds out the fourth log
    entirely, and which record gets read becomes an accident of file order.
    """
    documents: list[list[Chunk]] = []
    seen: set[str] = set()

    def collect(doc_type: str, doc_id: str) -> None:
        rows = conn.execute(
            "SELECT id FROM chunks WHERE doc_type = ? AND doc_id = ?", (doc_type, doc_id)
        ).fetchall()
        chunks = []
        for (chunk_id,) in sorted(rows, key=lambda r: field_rank(r[0])):
            if chunk_id in seen:
                continue
            chunk = get_chunk(conn, chunk_id)
            if chunk is not None:
                seen.add(chunk_id)
                chunks.append(chunk)
        if chunks:
            documents.append(chunks)

    collect("alert", alert_id)

    def collect_linked(field: str, doc_type: str) -> None:
        row = conn.execute(
            "SELECT text FROM chunks WHERE id = ?", (f"alert:{alert_id}:{field}",)
        ).fetchone()
        for doc_id in (row[0].split() if row else ()):
            collect(doc_type, doc_id)

    collect_linked("related_logs", "log")
    # Tickets are linked explicitly rather than discovered by keyword: a
    # ticket comment is where S2's poison and S3's fake remediation step live,
    # and which record reaches the model must not be an accident of bm25
    # ranking (D-011, D-017).
    collect_linked("related_tickets", "ticket")

    # Round-robin across documents, most informative field of each first.
    ordered: list[Chunk] = []
    for rank in range(max((len(d) for d in documents), default=0)):
        for doc in documents:
            if rank < len(doc):
                ordered.append(doc[rank])

    # Top up with a keyword search on the alert's host, so anything the
    # related_logs list missed can still surface.
    host_row = conn.execute(
        "SELECT text FROM chunks WHERE id = ?", (f"alert:{alert_id}:host",)
    ).fetchone()
    if host_row:
        for chunk in search(conn, host_row[0], limit=5):
            if chunk.id not in seen:
                seen.add(chunk.id)
                ordered.append(chunk)

    return ordered[:limit]


