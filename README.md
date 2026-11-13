# ROITH — Digital Forensics Lab

Bilingual English/Arabic static web app for local evidence triage.

## Deploy on Cloudflare Pages (free static hosting)
1. Connect this repository `dlta30/ROITH` to Cloudflare Pages.
2. Framework preset: **None**.
3. Build command: leave empty.
4. Build output directory: `/` (or `.` if required by the dashboard).
5. Deploy. Cloudflare will provide a `*.pages.dev` URL.

## Current capabilities
- SHA-256 hashing using Web Crypto.
- Basic file signature identification (magic bytes).
- Shannon entropy estimate and printable ASCII extraction.
- Limited timeline using browser-provided last-modified timestamps.
- SHA-256 JSON evidence manifest.
- Case notes stored in the current browser localStorage.
- PDF reports using jsPDF CDN (internet required for the PDF library).

## Limitations and safety
This version does **not** execute Kali tools, Nmap, Autopsy, Volatility, or parse disk images, EVTX, PCAP, or memory dumps. A separately hosted, hardened Linux analysis engine is required for those capabilities. Never expose a general shell or arbitrary command execution to the public internet. Add strict authentication, allowlisted jobs, isolation, quotas, and audit logs before connecting a remote engine.

Files selected in the browser are processed locally and are not uploaded. Use only evidence you are authorized to examine. Preserve originals and validate findings with established forensic tools. This is an educational triage utility, not a certified forensic acquisition suite.
