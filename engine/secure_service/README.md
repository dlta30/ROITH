# ROITH Secure Linux Analysis Service (preview)

A separate Linux-only job API and rootless Podman dispatcher for ROITH. This is a deployment-ready source preview, not a live service: it is intentionally not exposed on the public internet.

## Security model

- Every API operation except the minimal /health probe requires a Bearer token. Authentication is checked in ASGI middleware before multipart bodies are parsed or spooled. The service stores only the token's SHA-256 digest in ROITH_API_TOKEN_SHA256; never place the raw token in the static site or Git repository.
- Only five fixed task IDs are accepted: triage, pcap, evtx, yara, and exif. No shell, command, executable path, plugin name, or arbitrary arguments are accepted from a client.
- Uploads are streamed with size caps, stored under random job IDs, hashed, fsync'd and changed to read-only mode. The API exposes no evidence overwrite or delete operation.
- The dispatcher verifies evidence and YARA-rule hashes before analysis and verifies evidence again afterward.
- Each job runs in a fresh rootless Podman container with no network, read-only root filesystem, read-only evidence bind mount, dropped capabilities, no-new-privileges, a non-root UID, a bounded tmpfs, 768 MiB RAM, 1 CPU, 64 PIDs and a 120-second host timeout.
- Queue quotas default to 10 queued jobs, 20 submissions/hour and 5 GiB of retained evidence. A single dispatcher lock prevents multiple worker loops; jobs left in running after a dispatcher restart are marked failed for manual review rather than silently rerun.
- SQLite stores job state. audit.jsonl is append-only at the application layer and hash-chained; /v2/audit/verify checks the chain. Keep the data directory on a private disk and back it up separately.
- No evidence is executed. PCAP analysis is offline. Nmap, password testing, credential attacks, stealth and persistence are not included.

This is a security-focused preview, not a certified forensic acquisition platform. Read-only permissions and hashes provide tamper evidence, not cryptographic WORM storage. For high-assurance cases, place originals on a hardware/write-blocked or immutable evidence store and preserve an independently signed acquisition manifest.

## Linux setup (rootless Podman)

1. Create a dedicated unprivileged account, for example roith. Configure rootless Podman and subordinate UID/GID ranges for that account. Do not run the dispatcher as root.
2. Copy this directory to a private path such as /opt/roith/secure_service, owned by roith and not writable by other users.
3. Create /var/lib/roith owned by roith, mode 0700.
4. Create a Python 3.12 virtual environment and install requirements-api.txt.
5. Generate a token locally and keep the raw value outside the repo:

       TOKEN="$(python -c 'import secrets; print(secrets.token_urlsafe(48))')"
       printf '%s' "$TOKEN" | sha256sum
       # Store the 64-character digest as ROITH_API_TOKEN_SHA256 in a root-readable env file.
       # Deliver the raw TOKEN to the operator over a secure channel; do not commit it.

6. Copy .env.example to a private env file and set the digest, exact allowed browser origin, data directory and worker image. Restrict that env file to mode 0600. Load it into both API and dispatcher processes (or use systemd EnvironmentFile=).
7. As the roith account, build the worker image with: sh build-worker.sh. The script refuses rootful Podman.
8. Start the API with sh run-api.sh and the dispatcher with sh run-dispatcher.sh in separate service sessions. Keep the API bound to 127.0.0.1:8080; put a private VPN or authenticated TLS reverse proxy in front if remote access is required.

Do not expose port 8080 directly to the public internet. If using a reverse proxy, enforce a request-body limit no larger than approximately 27 MiB and HTTPS. For a Cloudflare Pages front end, use a private authenticated gateway/VPN or an Access-protected tunnel. Do not embed the master token in index.html, JavaScript source, a public repository, or a browser-exposed Pages variable.

## API contract

- GET /health — minimal unauthenticated liveness response.
- GET /v2/tasks — authenticated allowlist.
- POST /v2/jobs — authenticated multipart form: task, file, and rules only for yara; returns HTTP 202 and a job ID.
- GET /v2/jobs/{id} — authenticated job status and bounded JSON result.
- GET /v2/jobs?limit=25 — authenticated recent jobs.
- GET /v2/audit/verify — authenticated audit-chain verification.

The static browser connector in client.js keeps the operator token in memory only, uses HTTPS for remote hosts, omits browser credentials/cookies and never writes the token to localStorage. The ROITH page integration asks the operator to enter the private service URL and token for the current page session.

## Currently enabled / not enabled

Enabled in the worker image: static triage, offline PCAP, EVTX, YARA, and ExifTool metadata extraction. Memory forensics (Volatility 3), disk-image examination (Sleuth Kit/Autopsy), and Nmap are deliberately not enabled in this preview. They need separate reviewed worker images, file-format/size limits and tests before they are added to the task allowlist.

## Local checks

Run python -m pytest -q from this directory for API/auth/storage/audit/command-policy tests. A full integration test requires rootless Podman and a built worker image; source-only tests do not claim that the container runtime is installed or deployed.
