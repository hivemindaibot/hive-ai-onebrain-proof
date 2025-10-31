from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Iterator

import pytest

from brain.server.proof_app import ProofConfig, create_app
from scripts.proof_replay_check import generate_proof_replay_report


class StubModel:
    """Model stub that echoes the first context entry."""

    def generate(self, *, req, messages, temperature, max_tokens):  # pragma: no cover - exercised in tests
        entry = req.context[0]
        payload = {
            "answer": entry.text,
            "citations": [
                {
                    "id": entry.cid,
                    "sha256": entry.sha256,
                    "evidence": entry.text[:32],
                }
            ],
            "confidence": 0.7,
        }
        return json.dumps(payload), {"prompt_tokens": len(messages), "completion_tokens": 12}


@pytest.fixture()
def app(tmp_path: Path):
    cfg = ProofConfig(api_token="test-token", artifacts_dir=str(tmp_path / "artifacts"))
    app = create_app(cfg, model=StubModel(), testing=True)
    yield app


@pytest.fixture()
def client(app):
    return app.test_client()


@pytest.fixture()
def cors_client(tmp_path: Path) -> Iterator:
    cfg = ProofConfig(
        api_token="test-token",
        artifacts_dir=str(tmp_path / "artifacts"),
        cors_origins=("https://example.com",),
    )
    app = create_app(cfg, model=StubModel(), testing=True)
    yield app.test_client()


def _headers(token: str) -> dict[str, str]:
    return {"Authorization": f"Bearer {token}", "Content-Type": "application/json"}


def _example_payload() -> dict[str, object]:
    text = "Evidence for deterministic response."
    digest = hashlib.sha256(text.encode("utf-8")).hexdigest()
    return {
        "query": "Provide the summary.",
        "context": [
            {
                "id": "doc-ctx",
                "text": text,
                "sha256": digest,
            }
        ],
    }


def test_query_accepts_valid_request(tmp_path: Path, client):
    text = "Evidence that Phase 1 governance is active."
    digest = hashlib.sha256(text.encode("utf-8")).hexdigest()
    context_entry = {
        "id": "doc-1",
        "text": text,
        "sha256": digest,
    }
    payload = {"query": "What does the evidence say?", "context": [context_entry]}

    resp = client.post("/io/query", headers=_headers("test-token"), json=payload)
    assert resp.status_code == 200
    data = resp.get_json()
    assert data["decision"] == "accept"
    assert data["citations"][0]["id"] == "doc-1"
    probe_gate = tmp_path / "artifacts" / "io" / "probe_gate.json"
    assert probe_gate.exists()


def test_query_rejects_bad_token(client):
    resp = client.post("/io/query", headers=_headers("wrong"), json={})
    assert resp.status_code == 401
    assert resp.get_json()["error"] == "unauthorized"


def test_proof_replay_report(tmp_path: Path):
    dest = tmp_path / "proof.json"
    report = generate_proof_replay_report(dest, artifacts_dir=tmp_path)
    assert report["equal"] is True
    assert report["sha256"]
    saved = json.loads(dest.read_text())
    assert saved == report


def test_config_requires_api_token(monkeypatch):
    monkeypatch.delenv("PROOF_API_TOKEN", raising=False)
    with pytest.raises(RuntimeError):
        ProofConfig()


def test_cors_disabled_by_default(client):
    payload = _example_payload()
    headers = _headers("test-token")
    headers["Origin"] = "https://example.com"
    resp = client.post("/io/query", headers=headers, json=payload)
    assert resp.status_code == 200
    assert "Access-Control-Allow-Origin" not in resp.headers


def test_cors_allows_configured_origin(cors_client):
    payload = _example_payload()
    headers = _headers("test-token")
    origin = "https://example.com"
    headers["Origin"] = origin
    resp = cors_client.post("/io/query", headers=headers, json=payload)
    assert resp.headers["Access-Control-Allow-Origin"] == origin

    preflight = cors_client.options(
        "/io/query",
        headers={
            "Origin": origin,
            "Access-Control-Request-Method": "POST",
            "Access-Control-Request-Headers": "Authorization, Content-Type",
        },
    )
    assert preflight.status_code == 204
    assert preflight.headers["Access-Control-Allow-Origin"] == origin
