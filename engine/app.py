from __future__ import annotations
import hashlib, math, os, tempfile, xml.etree.ElementTree as ET
from collections import Counter
from pathlib import Path
from io import BytesIO
from fastapi import FastAPI, File, HTTPException, UploadFile
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse

APP_VERSION = "0.2.0"
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

async def read_bounded(upload: UploadFile) -> bytes:
    chunks, total = [], 0
    while chunk := await upload.read(1024 * 1024):
        total += len(chunk)
        if total > MAX_BYTES:
            raise HTTPException(status_code=413, detail=f"File exceeds {MAX_BYTES} byte limit")
        chunks.append(chunk)
    await upload.close()
    return b"".join(chunks)

@app.get("/health")
def health():
    modules = {}
    for name, module in (("pcap", "scapy"), ("yara", "yara"), ("evtx", "Evtx")):
        try:
            __import__(module)
            modules[name] = "ready"
        except ImportError:
            modules[name] = "not_installed"
    return {"status": "ok", "service": "ROITH Analysis Engine", "version": APP_VERSION, "modules": modules}

@app.post("/v1/analyze")
async def analyze(file: UploadFile = File(...)):
    name = Path(file.filename or "evidence.bin").name[:180]
    data = await read_bounded(file)
    return JSONResponse({
        "engine": "ROITH", "engine_version": APP_VERSION,
        "filename": name, "size_bytes": len(data),
        "sha256": hashlib.sha256(data).hexdigest(), "file_signature": classify(data),
        "sample_entropy_bits_per_byte": shannon_entropy(data[:2 * 1024 * 1024]),
        "sample_bytes_for_entropy": min(len(data), 2 * 1024 * 1024),
        "printable_strings_sample": printable_strings(data[:2 * 1024 * 1024]),
        "analysis_scope": "Static triage only; signature and entropy are heuristics, not a malware verdict.",
        "evidence_handling": "Processed in memory; no evidence is retained."
    })

@app.post("/v1/pcap/analyze")
async def analyze_pcap(file: UploadFile = File(...)):
    try:
        from scapy.all import rdpcap, IP, IPv6, TCP, UDP, DNS, DNSQR
    except ImportError:
        raise HTTPException(status_code=503, detail="PCAP module unavailable. Install engine requirements.")
    data = await read_bounded(file)
    try:
        packets = rdpcap(BytesIO(data))
    except Exception as exc:
        raise HTTPException(status_code=400, detail=f"Invalid or unsupported PCAP: {str(exc)[:180]}")
    protocols, sources, destinations, dns_queries = Counter(), Counter(), Counter(), Counter()
    for packet in packets:
        if TCP in packet: protocols["TCP"] += 1
        elif UDP in packet: protocols["UDP"] += 1
        elif IPv6 in packet: protocols["IPv6"] += 1
        elif IP in packet: protocols["IP"] += 1
        else: protocols["Other"] += 1
        if IP in packet:
            sources[packet[IP].src] += 1; destinations[packet[IP].dst] += 1
        elif IPv6 in packet:
            sources[packet[IPv6].src] += 1; destinations[packet[IPv6].dst] += 1
        if DNS in packet and packet[DNS].qd and DNSQR in packet:
            try: dns_queries[packet[DNSQR].qname.decode("utf-8", "replace").rstrip(".")] += 1
            except Exception: pass
    return {"filename": Path(file.filename or "capture.pcap").name[:180], "packet_count": len(packets),
            "protocol_counts": dict(protocols), "top_sources": sources.most_common(15),
            "top_destinations": destinations.most_common(15), "dns_queries": dns_queries.most_common(50),
            "note": "Offline packet-file analysis only; no network traffic is generated."}

@app.post("/v1/evtx/analyze")
async def analyze_evtx(file: UploadFile = File(...)):
    try:
        from Evtx.Evtx import Evtx
    except ImportError:
        raise HTTPException(status_code=503, detail="EVTX module unavailable. Install engine requirements.")
    data = await read_bounded(file)
    fd, path = tempfile.mkstemp(prefix="roith-", suffix=".evtx")
    try:
        with os.fdopen(fd, "wb") as target: target.write(data)
        event_ids, providers, times = Counter(), Counter(), []
        total = 0
        try:
            with Evtx(path) as log:
                for record in log.records():
                    total += 1
                    if total > 100000: break
                    try:
                        root = ET.fromstring(record.xml())
                        ns = {"e": "http://schemas.microsoft.com/win/2004/08/events/event"}
                        event_id = root.findtext(".//e:EventID", default="Unknown", namespaces=ns)
                        event_ids[event_id] += 1
                        provider = root.find(".//e:Provider", ns)
                        if provider is not None: providers[provider.attrib.get("Name", "Unknown")] += 1
                        stamp = root.find(".//e:TimeCreated", ns)
                        if stamp is not None and stamp.attrib.get("SystemTime") and len(times) < 30:
                            times.append(stamp.attrib["SystemTime"])
                    except ET.ParseError: continue
        except Exception as exc:
            raise HTTPException(status_code=400, detail=f"Could not parse EVTX: {str(exc)[:180]}")
        return {"filename": Path(file.filename or "events.evtx").name[:180], "events_parsed": total,
                "event_id_counts": event_ids.most_common(40), "providers": providers.most_common(25),
                "sample_timestamps_utc": times, "truncated": total >= 100000}
    finally:
        try: os.unlink(path)
        except FileNotFoundError: pass

@app.post("/v1/yara/scan")
async def scan_yara(file: UploadFile = File(...), rules: UploadFile = File(...)):
    try:
        import yara
    except ImportError:
        raise HTTPException(status_code=503, detail="YARA module unavailable. Install engine requirements.")
    evidence = await read_bounded(file)
    rule_data = await read_bounded(rules)
    if len(rule_data) > 1024 * 1024:
        raise HTTPException(status_code=413, detail="YARA rules file exceeds 1 MiB")
    fd, path = tempfile.mkstemp(prefix="roith-yara-")
    try:
        with os.fdopen(fd, "wb") as target: target.write(evidence)
        try:
            compiled = yara.compile(source=rule_data.decode("utf-8-sig"))
            matches = compiled.match(filepath=path, timeout=10)
        except Exception as exc:
            raise HTTPException(status_code=400, detail=f"YARA rule/scan error: {str(exc)[:180]}")
        return {"filename": Path(file.filename or "evidence.bin").name[:180],
                "sha256": hashlib.sha256(evidence).hexdigest(), "matches": [
                    {"rule": m.rule, "namespace": m.namespace, "tags": list(m.tags),
                     "meta": dict(m.meta)} for m in matches],
                "match_count": len(matches),
                "note": "A YARA match is a rule hit, not proof that a file is malicious. Use trusted rules and validate results."}
    finally:
        try: os.unlink(path)
        except FileNotFoundError: pass
