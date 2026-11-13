# ROITH Analysis Engine (starter)

A small, allowlisted HTTP service for static evidence triage. It does not execute uploaded files, invoke a shell, unpack archives, scan remote hosts, or claim to provide a malware verdict.

## Run locally
Requires Python 3.12+.

```bash
cd engine
python -m venv .venv
# Windows: .venv\Scripts\activate
# macOS/Linux: source .venv/bin/activate
pip install -r requirements.txt
set ROITH_ALLOWED_ORIGINS=http://localhost:8000
uvicorn app:app --host 127.0.0.1 --port 8000
```

Check `GET /health`, then send a file as multipart field `file` to `POST /v1/analyze`.

## Docker
```bash
docker build -t roith-engine .
docker run --rm -p 8000:8000 -e ROITH_ALLOWED_ORIGINS=https://YOUR-PAGES-DOMAIN.pages.dev roith-engine
```

## Before public deployment
This starter is not production-ready for public exposure. Put it behind authentication and authorization, TLS, request rate limits, per-user quotas, malware-safe storage, audit logging, job timeouts, and private networking. Restrict origins to the exact ROITH frontend domain. Use non-root container execution (already configured), no privileged mode, no host mounts, and an ephemeral filesystem. Consider private object storage with retention controls for larger evidence. Never expose arbitrary shell execution.

## Endpoint
- `GET /health`: service status
- `POST /v1/analyze`: bounded upload; SHA-256, basic file signature, sample entropy and printable strings

Results are heuristic triage. Preserve original evidence and independently validate findings.
