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

## Planned specialist integrations
Nmap, Autopsy/Sleuth Kit, Volatility 3, PCAP analysis, EVTX parsing and YARA require a separate hardened Linux analysis service. These are roadmap items, not active tools in this static release.

Before connecting a remote engine, implement authentication, a strict allowlist of forensic jobs, per-job isolation, resource limits, audit logging and safe evidence handling. Do not expose arbitrary shell execution to the browser or public internet.

ROITH is a specialized forensic workspace, not a replacement for Kali Linux or a certified forensic acquisition suite. Preserve originals, examine authorized copies, and independently validate important findings.
