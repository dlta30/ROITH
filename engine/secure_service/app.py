from __future__ import annotations

import asyncio
import hashlib
import hmac
from contextlib import asynccontextmanager
import os
import re
import shutil
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from fastapi import Depends, FastAPI, File, Form, Header, HTTPException, Request, UploadFile
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse

import core

APP_VERSION = "1.0.0-secure-preview"
MAX_UPLOAD_BYTES = int(os.getenv("ROITH_MAX_UPLOAD_BYTES", str(25 * 1024 * 1024)))
MAX_RULE_BYTES = 1 * 1024 * 1024
MAX_QUEUED_JOBS = int(os.getenv("ROITH_MAX_QUEUED_JOBS", "10"))
MAX_JOBS_PER_HOUR = int(os.getenv("ROITH_MAX_JOBS_PER_HOUR", "20"))
MAX_STORED_BYTES = int(os.getenv("ROITH_MAX_STORED_BYTES", str(5 * 1024 * 1024 * 1024)))
MAX_BODY_BYTES = MAX_UPLOAD_BYTES + MAX_RULE_BYTES + 1024 * 1024
_upload_lock = asyncio.Lock()
ALLOWED_TASKS = {
    "triage": "Static file triage (SHA-256, signature, entropy, strings)",
    "pcap": "Offline PCAP protocol and DNS summary",
    "evtx": "Windows EVTX event summary",
    "yara": "YARA scan using supplied rules",
    "exif": "Read-only ExifTool metadata extraction",
}
ALLOWED_ORIGINS = [x.strip() for x in os.getenv("ROITH_ALLOWED_ORIGINS", "").split(",") if x.strip()]


@asynccontextmanager
async def lifespan(_: FastAPI):
    core.init_store()
    yield


app = FastAPI(title="ROITH Secure Forensic Job API", version=APP_VERSION, docs_url=None, redoc_url=None, openapi_url=None, lifespan=lifespan)
app.add_middleware(
    CORSMiddleware,
    allow_origins=ALLOWED_ORIGINS,
    allow_methods=["GET", "POST"],
    allow_headers=["authorization", "content-type"],
    allow_credentials=False,
)


def verify_bearer(authorization: str | None) -> str:
    expected = os.getenv("ROITH_API_TOKEN_SHA256", "").strip().lower()
    if not re.fullmatch(r"[a-f0-9]{64}", expected):
        raise HTTPException(status_code=503, detail="Service authentication is not configured.")
    if not authorization or not authorization.startswith("Bearer "):
        raise HTTPException(status_code=401, detail="Bearer token required.", headers={"WWW-Authenticate": "Bearer"})
    token = authorization[7:].strip()
    if len(token) < 32 or len(token) > 512:
        raise HTTPException(status_code=401, detail="Invalid bearer token.", headers={"WWW-Authenticate": "Bearer"})
    actual = hashlib.sha256(token.encode("utf-8")).hexdigest()
    if not hmac.compare_digest(actual, expected):
        raise HTTPException(status_code=401, detail="Invalid bearer token.", headers={"WWW-Authenticate": "Bearer"})
    return actual[:16]


def authenticated_actor(authorization: str | None = Header(default=None)) -> str:
    return verify_bearer(authorization)


@app.middleware("http")
async def authenticate_before_multipart(request: Request, call_next):
    # Reject unauthenticated requests before Starlette parses/spools multipart uploads.
    if request.url.path.startswith("/v2/") and request.method != "OPTIONS":
        try:
            verify_bearer(request.headers.get("authorization"))
        except HTTPException as exc:
            return JSONResponse({"detail": exc.detail}, status_code=exc.status_code, headers=exc.headers)
        if request.url.path == "/v2/jobs" and request.method == "POST":
            raw_length = request.headers.get("content-length")
            if raw_length and raw_length.isdigit() and int(raw_length) > MAX_BODY_BYTES:
                return JSONResponse({"detail": "Request body exceeds the configured upload limit."}, status_code=413)
    return await call_next(request)


async def save_upload(upload: UploadFile, destination: Path, limit: int) -> tuple[int, str]:
    destination.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    fd = os.open(destination, flags, 0o600)
    total = 0
    digest = hashlib.sha256()
    try:
        with os.fdopen(fd, "wb") as target:
            while chunk := await upload.read(1024 * 1024):
                total += len(chunk)
                if total > limit:
                    raise HTTPException(status_code=413, detail=f"Upload exceeds the {limit}-byte limit.")
                digest.update(chunk)
                target.write(chunk)
            target.flush()
            os.fsync(target.fileno())
        if total == 0:
            raise HTTPException(status_code=400, detail="Empty evidence files are not accepted.")
        os.chmod(destination, 0o444)
        return total, digest.hexdigest()
    except Exception:
        try:
            destination.unlink(missing_ok=True)
        except OSError:
            pass
        raise
    finally:
        await upload.close()


def safe_filename(raw: str | None) -> str:
    name = Path(raw or "evidence.bin").name
    name = "".join(ch for ch in name if ch.isprintable() and ch not in "\\/\x00")
    return (name or "evidence.bin")[:160]


def public_job(row: dict[str, Any]) -> dict[str, Any]:
    result = None
    if row.get("result_json"):
        import json
        try:
            result = json.loads(row["result_json"])
        except json.JSONDecodeError:
            result = {"error": "Stored result could not be decoded."}
    return {
        "id": row["id"], "task": row["task"], "status": row["status"],
        "filename": row["filename"], "size_bytes": row["size_bytes"],
        "sha256": row["sha256"], "rules_sha256": row.get("rules_sha256"),
        "created_at": row["created_at"], "updated_at": row["updated_at"],
        "started_at": row.get("started_at"), "finished_at": row.get("finished_at"),
        "result": result, "error": row.get("error"),
    }


@app.get("/health")
def health() -> dict[str, str]:
    return {"status": "ok", "service": "ROITH Secure Forensic Job API", "version": APP_VERSION}


@app.get("/v2/tasks")
def tasks(_: str = Depends(authenticated_actor)) -> dict[str, Any]:
    return {"tasks": [{"id": key, "description": value} for key, value in ALLOWED_TASKS.items()]}


@app.post("/v2/jobs", status_code=202)
async def create_job(
    task: str = Form(...),
    file: UploadFile = File(...),
    rules: UploadFile | None = File(default=None),
    actor: str = Depends(authenticated_actor),
) -> dict[str, Any]:
    if task not in ALLOWED_TASKS:
        raise HTTPException(status_code=422, detail="Task is not in the forensic allowlist.")
    if task == "yara" and rules is None:
        raise HTTPException(status_code=422, detail="YARA task requires a rules file.")
    if task != "yara" and rules is not None:
        raise HTTPException(status_code=422, detail="Rules files are accepted only for YARA tasks.")

    async with _upload_lock:
        quotas = core.quota_stats()
        if quotas["queued"] >= MAX_QUEUED_JOBS:
            raise HTTPException(status_code=429, detail="The forensic queue is full. Try again after a job finishes.")
        if quotas["last_hour"] >= MAX_JOBS_PER_HOUR:
            raise HTTPException(status_code=429, detail="The hourly forensic job quota has been reached.")
        if quotas["stored_bytes"] >= MAX_STORED_BYTES:
            raise HTTPException(status_code=507, detail="The evidence storage quota has been reached.")
        job_id = uuid.uuid4().hex
        job_dir = core.JOBS_DIR / job_id
        job_dir.mkdir(mode=0o700, parents=True, exist_ok=False)
        evidence_path = job_dir / "evidence.bin"
        rules_path = job_dir / "rules.yar"
        persisted = False
        try:
            size, digest = await save_upload(file, evidence_path, min(MAX_UPLOAD_BYTES, MAX_STORED_BYTES - quotas["stored_bytes"]))
            rules_digest = None
            if rules is not None:
                _, rules_digest = await save_upload(rules, rules_path, MAX_RULE_BYTES)
            # The worker receives a read-only bind mount. No endpoint can overwrite a stored original.
            os.chmod(job_dir, 0o555)
            created = datetime.now(timezone.utc).isoformat(timespec="seconds")
            job = {
                "id": job_id, "task": task, "filename": safe_filename(file.filename),
                "size_bytes": size, "sha256": digest, "rules_sha256": rules_digest,
                "created_at": created,
            }
            core.insert_job(job)
            persisted = True
            core.append_audit("job.queued", job_id, {
                "task": task, "size_bytes": size, "sha256": digest,
                "rules_sha256": rules_digest, "actor_fingerprint": actor,
            })
            return {"job": {**job, "status": "queued"}, "message": "Evidence stored read-only; queued for isolated analysis."}
        except Exception:
            if persisted:
                # Preserve the stored evidence if audit persistence fails; never leave a queued row pointing to deleted bytes.
                core.finish_job(job_id, "failed", error="Audit persistence failed; job was not dispatched. Preserve evidence for review.")
            else:
                try:
                    os.chmod(job_dir, 0o700)
                    shutil.rmtree(job_dir, ignore_errors=True)
                except OSError:
                    pass
            raise


@app.get("/v2/jobs")
def jobs(limit: int = 25, _: str = Depends(authenticated_actor)) -> dict[str, Any]:
    limit = max(1, min(limit, 100))
    return {"jobs": [public_job(row) for row in core.list_jobs(limit)]}


@app.get("/v2/jobs/{job_id}")
def job_status(job_id: str, _: str = Depends(authenticated_actor)) -> dict[str, Any]:
    if not re.fullmatch(r"[a-f0-9]{32}", job_id):
        raise HTTPException(status_code=404, detail="Job not found.")
    row = core.get_job(job_id)
    if row is None:
        raise HTTPException(status_code=404, detail="Job not found.")
    return {"job": public_job(row)}


@app.get("/v2/audit/verify")
def audit_verify(_: str = Depends(authenticated_actor)) -> dict[str, Any]:
    try:
        return core.verify_audit_chain()
    except RuntimeError as exc:
        raise HTTPException(status_code=500, detail="Audit chain verification failed; stop processing and preserve logs.") from exc
