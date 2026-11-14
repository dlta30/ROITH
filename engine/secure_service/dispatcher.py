from __future__ import annotations

import argparse
import fcntl
import hashlib
import json
import os
import shutil
import subprocess
import time
from pathlib import Path
from typing import Any

import core

PODMAN = os.getenv("ROITH_PODMAN_BIN", "podman")
WORKER_IMAGE = os.getenv("ROITH_WORKER_IMAGE", "localhost/roith-worker:1.0")
JOB_TIMEOUT_SECONDS = max(30, min(int(os.getenv("ROITH_JOB_TIMEOUT_SECONDS", "120")), 300))
MAX_RESULT_BYTES = 512 * 1024
TASKS = {"triage", "pcap", "evtx", "yara", "exif"}


def file_sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as source:
        for chunk in iter(lambda: source.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def build_podman_args(job: dict[str, Any], podman: str = PODMAN, image: str = WORKER_IMAGE) -> list[str]:
    task = job["task"]
    if task not in TASKS:
        raise ValueError("Task is not allowlisted")
    job_dir = (core.JOBS_DIR / job["id"]).resolve(strict=True)
    if not job_dir.is_relative_to(core.JOBS_DIR.resolve()):
        raise ValueError("Invalid evidence directory")
    return [
        podman, "run", "--rm", "--pull=never",
        "--network=none", "--read-only", "--cap-drop=all",
        "--security-opt=no-new-privileges",
        "--memory=768m", "--memory-swap=768m", "--cpus=1.0", "--pids-limit=64",
        "--user=65532:65532",
        "--tmpfs", "/tmp:rw,noexec,nosuid,nodev,size=64m,uid=65532,gid=65532",
        "--mount", f"type=bind,src={job_dir},dst=/evidence,ro",
        image, task,
    ]


def run_one(job: dict[str, Any]) -> None:
    if job["task"] not in TASKS:
        core.finish_job(job["id"], "failed", error="Task is not allowlisted.")
        core.append_audit("job.failed", job["id"], {"reason": "task_not_allowlisted"})
        return
    job_dir = core.JOBS_DIR / job["id"]
    evidence_path = job_dir / "evidence.bin"
    rules_path = job_dir / "rules.yar"
    try:
        if not evidence_path.is_file() or file_sha256(evidence_path) != job["sha256"]:
            raise RuntimeError("Evidence integrity check failed before analysis.")
        if job["task"] == "yara" and (not rules_path.is_file() or file_sha256(rules_path) != job["rules_sha256"]):
            raise RuntimeError("YARA rules integrity check failed before analysis.")
        args = build_podman_args(job)
        env = {
            "PATH": os.getenv("PATH", "/usr/bin:/bin"),
            "HOME": os.getenv("HOME", "/tmp"),
            "XDG_RUNTIME_DIR": os.getenv("XDG_RUNTIME_DIR", ""),
        }
        completed = subprocess.run(
            args, capture_output=True, text=True, encoding="utf-8", errors="replace",
            timeout=JOB_TIMEOUT_SECONDS, check=False, env=env,
        )
        if completed.returncode != 0:
            detail = (completed.stderr or completed.stdout or "Isolated worker failed.")[:1200]
            raise RuntimeError(f"Isolated worker exited with code {completed.returncode}: {detail}")
        if len(completed.stdout.encode("utf-8")) > MAX_RESULT_BYTES:
            raise RuntimeError("Worker result exceeded the output limit.")
        result = json.loads(completed.stdout)
        if file_sha256(evidence_path) != job["sha256"]:
            raise RuntimeError("Evidence integrity check failed after analysis; preserve the evidence and audit log.")
        core.finish_job(job["id"], "completed", result=result)
        core.append_audit("job.completed", job["id"], {"task": job["task"], "sha256": job["sha256"]})
    except subprocess.TimeoutExpired:
        core.finish_job(job["id"], "failed", error=f"Analysis timed out after {JOB_TIMEOUT_SECONDS} seconds.")
        core.append_audit("job.failed", job["id"], {"reason": "timeout", "task": job["task"]})
    except Exception as exc:
        core.finish_job(job["id"], "failed", error=str(exc)[:1500])
        core.append_audit("job.failed", job["id"], {"reason": type(exc).__name__, "task": job["task"]})


def loop(poll_seconds: float = 2.0, once: bool = False) -> None:
    core.init_store()
    lock_path = core.DATA_DIR / "dispatcher.lock"
    lock_fd = os.open(lock_path, os.O_CREAT | os.O_RDWR, 0o600)
    try:
        fcntl.flock(lock_fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
    except BlockingIOError:
        os.close(lock_fd)
        raise SystemExit("Another ROITH dispatcher is already running.")
    if not shutil.which(PODMAN):
        os.close(lock_fd)
        raise SystemExit(f"Podman executable not found: {PODMAN}")
    try:
        for interrupted_id in core.fail_interrupted_jobs():
            core.append_audit("job.interrupted", interrupted_id, {"reason": "dispatcher_restart"})
        while True:
            job = core.claim_next_job()
            if job is None:
                if once:
                    return
                time.sleep(poll_seconds)
                continue
            core.append_audit("job.started", job["id"], {"task": job["task"], "sha256": job["sha256"]})
            run_one(job)
            if once:
                return
    finally:
        os.close(lock_fd)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="ROITH allowlisted isolated forensic dispatcher")
    parser.add_argument("--once", action="store_true", help="process at most one queued job")
    parser.add_argument("--poll-seconds", type=float, default=2.0)
    args = parser.parse_args()
    loop(poll_seconds=max(0.5, min(args.poll_seconds, 30.0)), once=args.once)
