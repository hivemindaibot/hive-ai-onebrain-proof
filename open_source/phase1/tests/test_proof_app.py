from __future__ import annotations

import hashlib
import json
from pathlib import Path

import pytest

from brain.server.proof_app import ProofConfig, create_app


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


def _headers(token: str) -> dict[str, str]:
    return {"Authorization": f"Bearer {token}", "Content-Type": "application/json"}


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
