# ROITH Analysis Engine

Local-first forensic API for authorized evidence analysis. It never executes evidence or initiates network scans.

## Run on Windows / Linux
Requires Python 3.12+.

```bash
cd engine
python -m venv .venv
# Windows PowerShell: .venv\\Scripts\\Activate.ps1
# macOS/Linux: source .venv/bin/activate
pip install -r requirements.txt
uvicorn app:app --host 127.0.0.1 --port 8000
```

Check `GET http://127.0.0.1:8000/health` for installed module status.

## Active endpoints
- `GET /health`: engine and optional-module readiness.
- `POST /v1/analyze`: bounded static file triage, SHA-256, signature, entropy and printable strings.
- `POST /v1/pcap/analyze`: offline PCAP packet/protocol/IP/DNS summary (multipart field `file`).
- `POST /v1/evtx/analyze`: Windows EVTX event ID/provider/time summary (multipart field `file`).
- `POST /v1/yara/scan`: scan evidence with a supplied UTF-8 YARA rules file (multipart fields `file` and `rules`).

Upload limit defaults to 25 MiB; configure with `ROITH_MAX_UPLOAD_BYTES`. EVTX parsing is capped at 100,000 records.

## Safety and deployment
This is a local development engine, not production-ready for public exposure. Keep it bound to 127.0.0.1. Do not expose it to the internet: there is no authentication yet. Before remote deployment add authentication, authorization, TLS, rate limits, quotas, audit logs, job isolation, private storage and retention controls. Preserve original evidence and work on authorized copies. YARA hits and heuristic file indicators require independent validation.
