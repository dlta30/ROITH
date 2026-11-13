# ROITH Engineering Roadmap

ROITH is a digital-forensics investigation workspace. It is not intended to replace Kali Linux, a certified forensic acquisition suite, or the specialist tools it integrates.

## Product identity
- Product name: ROITH
- Emblem: F
- Visual system: black / deep red, high-contrast command-center interface
- Languages: Arabic and English
- Hosting target: Cloudflare Pages for the frontend, with a separately deployed analysis worker when required

## Current browser release
The static frontend currently provides:
- SHA-256 hashing using Web Crypto
- Basic magic-byte file-type hints
- Shannon entropy estimate and printable ASCII string extraction
- A browser-metadata timeline based on last-modified timestamps
- JSON hash manifest export
- Local case notes
- PDF report export

These are triage aids, not proof of maliciousness or a certified chain-of-custody system. Browser metadata is not a forensic acquisition source.

## Target architecture
1. **Frontend** — Cloudflare Pages, bilingual responsive UI, case workspace and report viewer.
2. **API gateway** — authenticated API, schema validation, request-size limits, per-user quotas and audit events.
3. **Linux analysis workers** — isolated short-lived jobs in containers or VMs; no public shell, no arbitrary command arguments, no privileged host mounts.
4. **Evidence storage** — private object storage with immutable/versioned evidence objects, recorded SHA-256 before and after processing, explicit retention and deletion policy.
5. **Results** — normalized JSON findings, tool/version metadata, timestamps, provenance and downloadable reports.

## Safe integration order
- Phase 1: strengthen browser triage, validation, test fixtures and export provenance.
- Phase 2: add authenticated job API and isolated worker orchestration.
- Phase 3: integrate read-only forensic workflows: file metadata, EVTX parsing, PCAP summaries, YARA scanning with curated defensive rules, and Volatility 3 analysis of authorized memory images.
- Phase 4: integrate disk-image workflows through Autopsy / Sleuth Kit in an isolated environment, with read-only source handling.
- Phase 5: add Nmap only as an explicitly authorized network-inventory workflow with target allowlists, rate limits and audit logs.

## Non-negotiable safeguards
- Never execute arbitrary shell commands supplied by a browser user.
- Never run untrusted evidence files as programs.
- Do not add credential brute forcing, password spraying, stealth, persistence, or unauthorized access features.
- Keep original evidence unchanged; work from verified copies.
- Record tool name, version, parameters, operator, timestamps and output hashes for every job.
- Enforce authentication, authorization, quotas, job timeouts, file-size limits and audit logging before enabling remote analysis.

## Deployment
For the static Pages site, use the repository root as the output directory and no build command when the Cloudflare Pages dashboard supports static deployment. Do not use Wrangler Worker deploy/preview commands as Pages build commands. A separate Linux worker is not deployed by Cloudflare Pages and must be configured independently.

## Definition of done
A module is not marked active until it has:
- A real implementation (not a decorative card)
- Input validation and safe failure behavior
- Tests using benign fixtures
- Documented limits and supported formats
- Provenance in its output
- Verification in the actual deployment environment
