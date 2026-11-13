from __future__ import annotations
import hashlib, math, os, tempfile
from collections import Counter
from pathlib import Path
from fastapi import FastAPI, File, HTTPException, UploadFile
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse

APP_VERSION = "0.1.0"
MAX_BYTES = int(os.getenv("ROITH_MAX_UPLOAD_BYTES", str(25 * 1024 * 1024)))
ALLOWED_ORIGINS = [x.strip() for x in os.getenv("ROITH_ALLOWED_ORIGINS", "").split(",") if x.strip()]

app = FastAPI(title="ROITH Analysis Engine", version=APP_VERSION, docs_url=None, redoc_url=None)
app.add_middleware(CORSMiddleware, allow_origins=ALLOWED_ORIGINS, allow_methods=["GET", "POST"], allow_headers=["content-type"], allow_credentials=False)

def classify(data: bytes) -> str:
    signatures = [
        (b"%PDF-", "PDF"), (b"\x89PNG\r\n\x1a\n", "PNG"),
        (b"\xff\xd8\xff", "JPEG"), (b"PK\x03\x04", "ZIP"),
        (b"MZ", "Windows PE (header only)"), (b"\x7fELF", "ELF"),
        (b"SQLite format 3\x00", "SQLite"), (b"\x1f\x8b", "GZIP")
    ]
    for magic, label in signatures:
        if data.startswith(magic): return label
    return "Unknown"

def shannon_entropy(data: bytes) -> float:
    if not data: return 0.0
    counts = Counter(data)
    n = len(data)
    return round(-sum((c/n) * math.log2(c/n) for c in counts.values()), 4)

def printable_strings(data: bytes, minimum: int = 6, limit: int = 100) -> list[str]:
    found, current = [], bytearray()
    for b in data:
        if 32 <= b <= 126: current.append(b)
        else:
            if len(current) >= minimum: found.append(current.decode("ascii", "replace"))
            current.clear()
            if len(found) >= limit: break
    if len(current) >= minimum and len(found) < limit:
        found.append(current.decode("ascii", "replace"))
    return found[:limit]

@app.get("/health")
def health():
    return {"status": "ok", "service": "ROITH Analysis Engine", "version": APP_VERSION}

@app.post("/v1/analyze")
async def analyze(file: UploadFile = File(...)):
    name = Path(file.filename or "evidence.bin").name[:180]
    digest = hashlib.sha256()
    size = 0
    sample = bytearray()
    # Stream to a bounded temporary file; never execute or unpack evidence.
    fd, temp_path = tempfile.mkstemp(prefix="roith-")
    try:
        with os.fdopen(fd, "wb") as target:
            while chunk := await file.read(1024 * 1024):
                size += len(chunk)
                if size > MAX_BYTES:
                    raise HTTPException(status_code=413, detail=f"File exceeds {MAX_BYTES} byte limit")
                digest.update(chunk)
                if len(sample) < 2 * 1024 * 1024:
                    sample.extend(chunk[: 2 * 1024 * 1024 - len(sample)])
                target.write(chunk)
        data = bytes(sample)
        return JSONResponse({
            "engine": "ROITH", "engine_version": APP_VERSION,
            "filename": name, "size_bytes": size,
            "sha256": digest.hexdigest(), "file_signature": classify(data),
            "sample_entropy_bits_per_byte": shannon_entropy(data),
            "sample_bytes_for_entropy": len(data),
            "printable_strings_sample": printable_strings(data),
            "analysis_scope": "Static triage only; signature and entropy are heuristics, not a malware verdict.",
            "evidence_handling": "Uploaded to this service for processing; temporary file removed after analysis."
        })
    finally:
        try: os.unlink(temp_path)
        except FileNotFoundError: pass
        await file.close()
