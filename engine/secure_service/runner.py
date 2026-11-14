from __future__ import annotations

import argparse
import hashlib
import json
import math
import shutil
import subprocess
from collections import Counter
from pathlib import Path
from typing import Any

EVIDENCE = Path("/evidence/evidence.bin")
MAX_FILE_BYTES = 25 * 1024 * 1024


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as source:
        for chunk in iter(lambda: source.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def signature(data: bytes) -> str:
    signatures = [
        (b"%PDF-", "PDF"), (b"\x89PNG\r\n\x1a\n", "PNG"),
        (b"\xff\xd8\xff", "JPEG"), (b"PK\x03\x04", "ZIP"),
        (b"MZ", "Windows PE header"), (b"\x7fELF", "ELF"),
        (b"SQLite format 3\x00", "SQLite"), (b"\x1f\x8b", "GZIP"),
    ]
    for magic, name in signatures:
        if data.startswith(magic):
            return name
    return "Unknown"


def entropy(data: bytes) -> float:
    if not data:
        return 0.0
    counts = Counter(data)
    n = len(data)
    return round(-sum((count / n) * math.log2(count / n) for count in counts.values()), 4)


def strings(data: bytes, minimum: int = 6, limit: int = 100) -> list[str]:
    found: list[str] = []
    current = bytearray()
    for byte in data:
        if 32 <= byte <= 126:
            current.append(byte)
        else:
            if len(current) >= minimum:
                found.append(current.decode("ascii", "replace"))
            current.clear()
            if len(found) >= limit:
                break
    if len(current) >= minimum and len(found) < limit:
        found.append(current.decode("ascii", "replace"))
    return found[:limit]


def run_triage() -> dict[str, Any]:
    data = EVIDENCE.read_bytes()
    sample = data[:2 * 1024 * 1024]
    return {
        "task": "triage", "filename": "evidence.bin", "size_bytes": len(data),
        "sha256": hashlib.sha256(data).hexdigest(), "signature": signature(data),
        "sample_entropy_bits_per_byte": entropy(sample), "sample_bytes": len(sample),
        "printable_strings": strings(sample),
        "note": "Static triage only. Heuristics are not a malware verdict.",
    }


def run_pcap() -> dict[str, Any]:
    from scapy.layers.dns import DNS, DNSQR
    from scapy.layers.inet import IP, TCP, UDP
    from scapy.layers.inet6 import IPv6
    from scapy.utils import PcapReader

    protocols, sources, destinations, dns_queries = Counter(), Counter(), Counter(), Counter()
    packet_count = 0
    truncated = False
    try:
        with PcapReader(str(EVIDENCE)) as reader:
            for packet in reader:
                packet_count += 1
                if packet_count > 200000:
                    packet_count -= 1
                    truncated = True
                    break
                if TCP in packet:
                    protocols["TCP"] += 1
                elif UDP in packet:
                    protocols["UDP"] += 1
                elif IPv6 in packet:
                    protocols["IPv6"] += 1
                elif IP in packet:
                    protocols["IP"] += 1
                else:
                    protocols["Other"] += 1
                if IP in packet:
                    sources[packet[IP].src] += 1
                    destinations[packet[IP].dst] += 1
                elif IPv6 in packet:
                    sources[packet[IPv6].src] += 1
                    destinations[packet[IPv6].dst] += 1
                if DNS in packet and packet[DNS].qd and DNSQR in packet:
                    try:
                        dns_queries[packet[DNSQR].qname.decode("utf-8", "replace").rstrip(".")] += 1
                    except Exception:
                        pass
    except Exception as exc:
        raise ValueError(f"Invalid or unsupported PCAP: {str(exc)[:180]}") from exc
    return {
        "task": "pcap", "filename": "evidence.bin", "sha256": sha256_file(EVIDENCE),
        "packet_count": packet_count, "truncated": truncated,
        "protocol_counts": dict(protocols), "top_sources": sources.most_common(15),
        "top_destinations": destinations.most_common(15), "dns_queries": dns_queries.most_common(50),
        "note": "Offline packet-file analysis only; no network traffic is generated.",
    }


def run_evtx() -> dict[str, Any]:
    from Evtx.Evtx import Evtx
    import xml.etree.ElementTree as ET

    event_ids, providers, times = Counter(), Counter(), []
    total = 0
    truncated = False
    with Evtx(str(EVIDENCE)) as log:
        for record in log.records():
            if total >= 100000:
                truncated = True
                break
            total += 1
            try:
                root = ET.fromstring(record.xml())
                ns = {"e": "http://schemas.microsoft.com/win/2004/08/events/event"}
                event_id = root.findtext(".//e:EventID", default="Unknown", namespaces=ns)
                event_ids[event_id] += 1
                provider = root.find(".//e:Provider", ns)
                if provider is not None:
                    providers[provider.attrib.get("Name", "Unknown")] += 1
                stamp = root.find(".//e:TimeCreated", ns)
                if stamp is not None and stamp.attrib.get("SystemTime") and len(times) < 30:
                    times.append(stamp.attrib["SystemTime"])
            except ET.ParseError:
                continue
    return {
        "task": "evtx", "filename": "evidence.bin", "sha256": sha256_file(EVIDENCE),
        "events_parsed": total, "truncated": truncated,
        "event_id_counts": event_ids.most_common(40), "providers": providers.most_common(25),
        "sample_timestamps_utc": times,
    }


def run_yara() -> dict[str, Any]:
    import yara
    rules_path = Path("/evidence/rules.yar")
    if not rules_path.is_file() or rules_path.stat().st_size > 1024 * 1024:
        raise ValueError("YARA rules file is missing or exceeds 1 MiB.")
    source = rules_path.read_text(encoding="utf-8-sig")
    compiled = yara.compile(source=source)
    matches = compiled.match(filepath=str(EVIDENCE), timeout=10)
    rows = [{"rule": match.rule, "namespace": match.namespace, "tags": list(match.tags), "meta": dict(match.meta)} for match in matches[:1000]]
    return {
        "task": "yara", "filename": "evidence.bin", "sha256": sha256_file(EVIDENCE),
        "matches": rows, "match_count": len(rows),
        "note": "A YARA hit is not proof of maliciousness. Validate the rule and finding independently.",
    }


def run_exif() -> dict[str, Any]:
    executable = shutil.which("exiftool")
    if not executable:
        raise RuntimeError("ExifTool is not installed in the isolated worker image.")
    try:
        result = subprocess.run(
            [executable, "-json", "-G1", "-a", "-s", "-charset", "filename=UTF8", "--", str(EVIDENCE)],
            capture_output=True, text=True, encoding="utf-8", errors="replace", timeout=20, check=False,
        )
    except subprocess.TimeoutExpired as exc:
        raise TimeoutError("ExifTool timed out after 20 seconds.") from exc
    if result.returncode not in (0, 1) or not result.stdout.strip():
        raise ValueError("ExifTool could not read metadata: " + result.stderr[:300])
    parsed = json.loads(result.stdout)
    metadata = parsed[0] if parsed and isinstance(parsed, list) else {}
    return {
        "task": "exif", "filename": "evidence.bin", "size_bytes": EVIDENCE.stat().st_size,
        "sha256": sha256_file(EVIDENCE), "metadata": metadata, "metadata_fields": len(metadata),
        "note": "Metadata may be missing, altered or unreliable. GPS fields can be sensitive.",
    }


RUNNERS = {"triage": run_triage, "pcap": run_pcap, "evtx": run_evtx, "yara": run_yara, "exif": run_exif}


def main() -> None:
    parser = argparse.ArgumentParser(add_help=False)
    parser.add_argument("task", choices=sorted(RUNNERS))
    args = parser.parse_args()
    if not EVIDENCE.is_file() or EVIDENCE.stat().st_size > MAX_FILE_BYTES:
        raise SystemExit("Evidence file is missing or exceeds the worker limit.")
    result = RUNNERS[args.task]()
    output = json.dumps(result, ensure_ascii=False, separators=(",", ":"), allow_nan=False)
    if len(output.encode("utf-8")) > 512 * 1024:
        raise SystemExit("Result exceeds the worker output limit.")
    print(output)


if __name__ == "__main__":
    main()
