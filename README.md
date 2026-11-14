# ROITH — Digital Forensics

ROITH is a bilingual (English/Arabic), dark forensic command-center interface with an **F** emblem and a local-first evidence workflow.

## Deploy with Cloudflare Pages
1. Connect `dlta30/ROITH` to Cloudflare Pages.
2. Framework preset: **None**.
3. Build command: leave empty.
4. Build output directory: `/` (or `.` if the dashboard requires it).
5. Deploy. Cloudflare provides a `*.pages.dev` URL.

This is a static HTML project: it does not need Wrangler deploy or preview commands in the Pages build configuration.

## Active browser capabilities
- SHA-256 hashing through the Web Crypto API.
- Basic file-signature recognition (magic bytes).
- Shannon entropy estimate and printable ASCII string extraction.
- Browser metadata timeline based on last-modified timestamps.
- JSON integrity manifest.
- Local case notes saved in browser storage.
- PDF report export (jsPDF CDN; internet required).

Files selected in the browser are processed locally and are not uploaded to a server. SHA-256 requires HTTPS or localhost.

## Secure Linux engine preview
The optional Engine Console is connected to a separate authenticated job API in `engine/secure_service`. Its fixed allowlist currently covers static triage, offline PCAP, EVTX, YARA and ExifTool. The service uses rootless per-job Podman containers, no network access, read-only evidence mounts, resource quotas and a hash-chained audit log. It is source code only until installed on a private Linux host; do not expose the legacy `engine/app.py` API publicly.

Volatility 3 memory analysis and Sleuth Kit/Autopsy disk-image examination remain disabled until dedicated worker images and large-evidence handling are reviewed and tested. Nmap is not enabled in this forensic job allowlist.

The secure engine preview implements the API-side authentication, fixed task allowlist, per-job isolation, resource limits, audit logging and read-only evidence handling. It still requires a private Linux host, HTTPS/VPN gateway and end-to-end runtime tests before production use. Do not expose arbitrary shell execution to the browser or public internet.

ROITH is a specialized forensic workspace, not a replacement for Kali Linux or a certified forensic acquisition suite. Preserve originals, examine authorized copies, and independently validate important findings.
