from __future__ import annotations

import fcntl
import hashlib
import json
import os
import hmac
import sqlite3
import threading
from contextlib import closing
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

DATA_DIR = Path(os.getenv("ROITH_DATA_DIR", "/var/lib/roith"))
JOBS_DIR = DATA_DIR / "jobs"
DB_PATH = DATA_DIR / "jobs.sqlite3"
AUDIT_PATH = DATA_DIR / "audit.jsonl"
ZERO_HASH = "0" * 64
_audit_thread_lock = threading.Lock()


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def canonical_json(value: Any) -> str:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"))


def connect_db() -> sqlite3.Connection:
    DATA_DIR.mkdir(parents=True, exist_ok=True, mode=0o700)
    db = sqlite3.connect(DB_PATH, timeout=30, isolation_level=None)
    db.row_factory = sqlite3.Row
    db.execute("PRAGMA busy_timeout=30000")
    db.execute("PRAGMA journal_mode=WAL")
    db.execute("PRAGMA synchronous=FULL")
    return db


def init_store() -> None:
    DATA_DIR.mkdir(parents=True, exist_ok=True, mode=0o700)
    JOBS_DIR.mkdir(parents=True, exist_ok=True, mode=0o700)
    os.chmod(DATA_DIR, 0o700)
    os.chmod(JOBS_DIR, 0o700)
    with closing(connect_db()) as db:
        db.execute(
            """CREATE TABLE IF NOT EXISTS jobs (
                id TEXT PRIMARY KEY,
                task TEXT NOT NULL,
                status TEXT NOT NULL CHECK(status IN ('queued','running','completed','failed')),
                filename TEXT NOT NULL,
                size_bytes INTEGER NOT NULL,
                sha256 TEXT NOT NULL,
                rules_sha256 TEXT,
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL,
                started_at TEXT,
                finished_at TEXT,
                result_json TEXT,
                error TEXT
            )"""
        )
        db.execute("CREATE INDEX IF NOT EXISTS jobs_status_created ON jobs(status, created_at)")
    if not AUDIT_PATH.exists():
        fd = os.open(AUDIT_PATH, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
        os.close(fd)
    os.chmod(AUDIT_PATH, 0o600)
    verify_audit_chain()


def _audit_file_lock(fd: int, operation: int) -> None:
    fcntl.flock(fd, operation)


def _scan_audit(handle) -> dict[str, Any]:
    previous = ZERO_HASH
    count = 0
    for line_number, raw in enumerate(handle, start=1):
        if not raw.strip():
            continue
        try:
            entry = json.loads(raw)
            claimed_prev = entry.pop("prev_hash")
            claimed_hash = entry.pop("entry_hash")
        except Exception as exc:
            raise RuntimeError(f"Audit log is malformed at line {line_number}") from exc
        if claimed_prev != previous:
            raise RuntimeError(f"Audit chain link mismatch at line {line_number}")
        expected = hashlib.sha256((previous + canonical_json(entry)).encode("utf-8")).hexdigest()
        if not hmac.compare_digest(expected, claimed_hash):
            raise RuntimeError(f"Audit hash mismatch at line {line_number}")
        previous = claimed_hash
        count += 1
    return {"valid": True, "entries": count, "head": previous}


def verify_audit_chain() -> dict[str, Any]:
    AUDIT_PATH.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    if not AUDIT_PATH.exists():
        return {"valid": True, "entries": 0, "head": ZERO_HASH}
    with _audit_thread_lock, open(AUDIT_PATH, "rb") as handle:
        _audit_file_lock(handle.fileno(), fcntl.LOCK_SH)
        try:
            return _scan_audit(handle)
        finally:
            _audit_file_lock(handle.fileno(), fcntl.LOCK_UN)


def append_audit(event: str, job_id: str | None = None, details: dict[str, Any] | None = None) -> str:
    payload = {
        "timestamp": utc_now(),
        "event": event,
        "job_id": job_id,
        "details": details or {},
    }
    AUDIT_PATH.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    with _audit_thread_lock:
        fd = os.open(AUDIT_PATH, os.O_CREAT | os.O_APPEND | os.O_WRONLY, 0o600)
        try:
            _audit_file_lock(fd, fcntl.LOCK_EX)
            with open(AUDIT_PATH, "rb") as reader:
                chain = _scan_audit(reader)
            previous = chain["head"]
            digest = hashlib.sha256((previous + canonical_json(payload)).encode("utf-8")).hexdigest()
            record = {**payload, "prev_hash": previous, "entry_hash": digest}
            data = (canonical_json(record) + "\n").encode("utf-8")
            view = memoryview(data)
            while view:
                written = os.write(fd, view)
                view = view[written:]
            os.fsync(fd)
            return digest
        finally:
            _audit_file_lock(fd, fcntl.LOCK_UN)
            os.close(fd)


def insert_job(job: dict[str, Any]) -> None:
    with closing(connect_db()) as db:
        db.execute(
            """INSERT INTO jobs(id,task,status,filename,size_bytes,sha256,rules_sha256,created_at,updated_at)
               VALUES(?,?,?,?,?,?,?,?,?)""",
            (job["id"], job["task"], "queued", job["filename"], job["size_bytes"],
             job["sha256"], job.get("rules_sha256"), job["created_at"], job["created_at"]),
        )


def get_job(job_id: str) -> dict[str, Any] | None:
    with closing(connect_db()) as db:
        row = db.execute("SELECT * FROM jobs WHERE id=?", (job_id,)).fetchone()
    return dict(row) if row else None


def list_jobs(limit: int = 25) -> list[dict[str, Any]]:
    with closing(connect_db()) as db:
        rows = db.execute("SELECT * FROM jobs ORDER BY created_at DESC LIMIT ?", (limit,)).fetchall()
    return [dict(row) for row in rows]


def claim_next_job() -> dict[str, Any] | None:
    with closing(connect_db()) as db:
        db.execute("BEGIN IMMEDIATE")
        row = db.execute("SELECT * FROM jobs WHERE status='queued' ORDER BY created_at LIMIT 1").fetchone()
        if row is None:
            db.execute("COMMIT")
            return None
        now = utc_now()
        db.execute("UPDATE jobs SET status='running', started_at=?, updated_at=? WHERE id=? AND status='queued'", (now, now, row["id"]))
        db.execute("COMMIT")
        result = dict(row)
        result.update(status="running", started_at=now, updated_at=now)
        return result


def quota_stats() -> dict[str, int]:
    with closing(connect_db()) as db:
        queued = db.execute("SELECT COUNT(*) FROM jobs WHERE status='queued'").fetchone()[0]
        since = datetime.fromtimestamp(datetime.now(timezone.utc).timestamp() - 3600, timezone.utc).isoformat(timespec="seconds")
        recent = db.execute("SELECT COUNT(*) FROM jobs WHERE created_at >= ?", (since,)).fetchone()[0]
        stored = db.execute("SELECT COALESCE(SUM(size_bytes),0) FROM jobs").fetchone()[0]
    return {"queued": int(queued), "last_hour": int(recent), "stored_bytes": int(stored)}


def fail_interrupted_jobs() -> list[str]:
    now = utc_now()
    with closing(connect_db()) as db:
        rows = db.execute("SELECT id FROM jobs WHERE status='running'").fetchall()
        ids = [row["id"] for row in rows]
        if ids:
            db.executemany(
                "UPDATE jobs SET status='failed', error=?, finished_at=?, updated_at=? WHERE id=? AND status='running'",
                [("Dispatcher restarted during analysis; manual review required.", now, now, job_id) for job_id in ids],
            )
    return ids


def finish_job(job_id: str, status: str, result: dict[str, Any] | None = None, error: str | None = None) -> None:
    if status not in {"completed", "failed"}:
        raise ValueError("Invalid terminal job status")
    now = utc_now()
    with closing(connect_db()) as db:
        db.execute(
            "UPDATE jobs SET status=?, result_json=?, error=?, finished_at=?, updated_at=? WHERE id=?",
            (status, canonical_json(result) if result is not None else None, error, now, now, job_id),
        )
