from __future__ import annotations

import hashlib
import importlib
import os
import stat

import pytest
from fastapi.testclient import TestClient


def load_app(tmp_path, monkeypatch):
    monkeypatch.setenv("ROITH_DATA_DIR", str(tmp_path / "data"))
    monkeypatch.setenv("ROITH_API_TOKEN_SHA256", hashlib.sha256(b"T" * 48).hexdigest())
    monkeypatch.setenv("ROITH_ALLOWED_ORIGINS", "https://roith-test.pages.dev")
    import core
    import app
    importlib.reload(core)
    importlib.reload(app)
    return app, core


def test_health_is_minimal_and_public(tmp_path, monkeypatch):
    app, _ = load_app(tmp_path, monkeypatch)
    with TestClient(app.app) as client:
        response = client.get("/health")
        assert response.status_code == 200
        assert response.json()["status"] == "ok"
        assert "token" not in response.text.lower()


def test_auth_and_task_allowlist(tmp_path, monkeypatch):
    app, _ = load_app(tmp_path, monkeypatch)
    with TestClient(app.app) as client:
        assert client.get("/v2/tasks").status_code == 401
        bad = client.get("/v2/tasks", headers={"Authorization": "Bearer " + "X" * 48})
        assert bad.status_code == 401
        good = client.get("/v2/tasks", headers={"Authorization": "Bearer " + "T" * 48})
        assert good.status_code == 200
        assert {x["id"] for x in good.json()["tasks"]} == {"triage", "pcap", "evtx", "yara", "exif"}


def test_job_upload_is_read_only_and_audited(tmp_path, monkeypatch):
    app, core = load_app(tmp_path, monkeypatch)
    headers = {"Authorization": "Bearer " + "T" * 48}
    with TestClient(app.app) as client:
        response = client.post("/v2/jobs", headers=headers, data={"task": "triage"}, files={"file": ("sample.txt", b"hello forensic world", "application/octet-stream")})
        assert response.status_code == 202, response.text
        job = response.json()["job"]
        assert job["status"] == "queued"
        path = core.JOBS_DIR / job["id"] / "evidence.bin"
        assert path.read_bytes() == b"hello forensic world"
        assert stat.S_IMODE(path.stat().st_mode) == 0o444
        assert stat.S_IMODE(path.parent.stat().st_mode) == 0o555
        assert client.get("/v2/jobs/" + job["id"], headers=headers).json()["job"]["sha256"] == hashlib.sha256(b"hello forensic world").hexdigest()
        assert client.get("/v2/audit/verify", headers=headers).json()["valid"] is True


def test_rejects_unlisted_tasks_and_missing_yara_rules(tmp_path, monkeypatch):
    app, _ = load_app(tmp_path, monkeypatch)
    headers = {"Authorization": "Bearer " + "T" * 48}
    with TestClient(app.app) as client:
        bad = client.post("/v2/jobs", headers=headers, data={"task": "shell"}, files={"file": ("x.bin", b"x")})
        assert bad.status_code == 422
        yara = client.post("/v2/jobs", headers=headers, data={"task": "yara"}, files={"file": ("x.bin", b"x")})
        assert yara.status_code == 422


def test_audit_chain_detects_tampering(tmp_path, monkeypatch):
    _, core = load_app(tmp_path, monkeypatch)
    core.init_store()
    core.append_audit("test.event", "a" * 32, {"sha256": "abc"})
    assert core.verify_audit_chain()["entries"] == 1
    raw = core.AUDIT_PATH.read_text()
    core.AUDIT_PATH.write_text(raw.replace('"event":"test.event"', '"event":"tampered"'))
    with pytest.raises(RuntimeError):
        core.verify_audit_chain()


def test_dispatcher_uses_only_fixed_container_command(tmp_path, monkeypatch):
    _, core = load_app(tmp_path, monkeypatch)
    core.init_store()
    job_id = "a" * 32
    job_dir = core.JOBS_DIR / job_id
    job_dir.mkdir()
    (job_dir / "evidence.bin").write_bytes(b"sample")
    os.chmod(job_dir / "evidence.bin", 0o444)
    os.chmod(job_dir, 0o555)
    import dispatcher
    importlib.reload(dispatcher)
    args = dispatcher.build_podman_args({"id": job_id, "task": "pcap"}, podman="podman", image="test-image")
    assert "--network=none" in args
    assert "--read-only" in args
    assert "--cap-drop=all" in args
    assert args[-2:] == ["test-image", "pcap"]
    with pytest.raises(ValueError):
        dispatcher.build_podman_args({"id": job_id, "task": "shell"}, podman="podman", image="test-image")


def test_upload_limit_rejects_and_cleans_partial_job(tmp_path, monkeypatch):
    app, core = load_app(tmp_path, monkeypatch)
    app.MAX_UPLOAD_BYTES = 4
    headers = {"Authorization": "Bearer " + "T" * 48}
    with TestClient(app.app) as client:
        response = client.post("/v2/jobs", headers=headers, data={"task": "triage"}, files={"file": ("large.bin", b"12345")})
        assert response.status_code == 413
        assert list(core.JOBS_DIR.iterdir()) == []


def test_yara_job_requires_and_hashes_rules(tmp_path, monkeypatch):
    app, core = load_app(tmp_path, monkeypatch)
    headers = {"Authorization": "Bearer " + "T" * 48}
    evidence = b"MZ" + b"sample"
    rules = b'rule demo { strings: $a = "sample" condition: $a }'
    with TestClient(app.app) as client:
        response = client.post(
            "/v2/jobs", headers=headers, data={"task": "yara"},
            files={"file": ("sample.exe", evidence), "rules": ("demo.yar", rules)},
        )
        assert response.status_code == 202, response.text
        job = response.json()["job"]
        assert job["sha256"] == hashlib.sha256(evidence).hexdigest()
        assert job["rules_sha256"] == hashlib.sha256(rules).hexdigest()
        assert (core.JOBS_DIR / job["id"] / "rules.yar").read_bytes() == rules


def test_audit_append_fails_closed_after_tamper(tmp_path, monkeypatch):
    _, core = load_app(tmp_path, monkeypatch)
    core.init_store()
    core.append_audit("test.event")
    raw = core.AUDIT_PATH.read_text().replace('"event":"test.event"', '"event":"changed"')
    core.AUDIT_PATH.write_text(raw)
    with pytest.raises(RuntimeError):
        core.append_audit("should.not.append")


def test_runner_triage_hashes_and_classifies(tmp_path, monkeypatch):
    import runner
    evidence = tmp_path / "evidence.bin"
    evidence.write_bytes(b"%PDF-1.7\nforensic sample text")
    monkeypatch.setattr(runner, "EVIDENCE", evidence)
    result = runner.run_triage()
    assert result["signature"] == "PDF"
    assert result["sha256"] == hashlib.sha256(evidence.read_bytes()).hexdigest()
    assert result["size_bytes"] == evidence.stat().st_size


def test_auth_runs_before_upload_and_cors_preflight_is_allowed(tmp_path, monkeypatch):
    app, core = load_app(tmp_path, monkeypatch)
    with TestClient(app.app) as client:
        denied = client.post("/v2/jobs", data={"task": "triage"}, files={"file": ("x.bin", b"large body")})
        assert denied.status_code == 401
        assert list(core.JOBS_DIR.iterdir()) == []
        preflight = client.options(
            "/v2/jobs",
            headers={
                "Origin": "https://roith-test.pages.dev",
                "Access-Control-Request-Method": "POST",
                "Access-Control-Request-Headers": "authorization,content-type",
            },
        )
        assert preflight.status_code == 200
        assert preflight.headers.get("access-control-allow-origin") == "https://roith-test.pages.dev"


def test_request_body_cap_is_checked_before_form_parsing(tmp_path, monkeypatch):
    app, _ = load_app(tmp_path, monkeypatch)
    app.MAX_BODY_BYTES = 5
    headers = {"Authorization": "Bearer " + "T" * 48}
    with TestClient(app.app) as client:
        response = client.post("/v2/jobs", headers=headers, data={"task": "triage"}, files={"file": ("x.bin", b"long body")})
        assert response.status_code == 413


def test_interrupted_jobs_are_failed_for_manual_review(tmp_path, monkeypatch):
    _, core = load_app(tmp_path, monkeypatch)
    core.init_store()
    now = core.utc_now()
    core.insert_job({
        "id": "b" * 32, "task": "triage", "filename": "x.bin",
        "size_bytes": 3, "sha256": hashlib.sha256(b"abc").hexdigest(),
        "created_at": now,
    })
    with core.connect_db() as db:
        db.execute("UPDATE jobs SET status='running' WHERE id=?", ("b" * 32,))
    assert core.fail_interrupted_jobs() == ["b" * 32]
    assert core.get_job("b" * 32)["status"] == "failed"
