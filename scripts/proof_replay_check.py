from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
from typing import Any, Dict

from brain.server.proof_app import ProofConfig, create_app


_DEFAULT_TOKEN = "proof-determinism"


def _default_request() -> Dict[str, Any]:
    text = "Artificial superintelligence research notes."
    digest = hashlib.sha256(text.encode("utf-8")).hexdigest()
    return {
        "query": "What is the summary?",
        "context": [
            {
                "id": "kb-asi-brief",
                "text": text,
                "sha256": digest,
            }
        ],
        "budget": {
            "seconds": 3,
            "tokens": 256,
        },
    }


def _hash_payload(data: Dict[str, Any]) -> str:
    serialized = json.dumps(data, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return hashlib.sha256(serialized).hexdigest()


def _canonicalize_response(payload: Dict[str, Any]) -> Dict[str, Any]:
    """Drop non-deterministic fields before hashing."""

    data = json.loads(json.dumps(payload))  # deep copy
    data.pop("run_id", None)
    validation = data.get("validation")
    if isinstance(validation, dict):
        validation.pop("latency_seconds", None)
    return data


def generate_proof_replay_report(dest: Path, *, artifacts_dir: Path | None = None) -> Dict[str, Any]:
    """Run the proof app twice with the same payload and write a determinism report."""

    artifacts_base = artifacts_dir or dest.parent
    artifacts_base.mkdir(parents=True, exist_ok=True)

    cfg = ProofConfig(api_token=_DEFAULT_TOKEN, artifacts_dir=str(artifacts_base / "artifacts"))
    app = create_app(cfg, testing=True)
    client = app.test_client()

    headers = {
        "Authorization": f"Bearer {_DEFAULT_TOKEN}",
        "Content-Type": "application/json",
    }
    payload = _default_request()

    resp1 = client.post("/io/query", headers=headers, json=payload)
    resp2 = client.post("/io/query", headers=headers, json=payload)
    if resp1.status_code != 200 or resp2.status_code != 200:
        raise RuntimeError("Proof app did not return 200 status during determinism check.")

    json1 = resp1.get_json()
    json2 = resp2.get_json()
    canon1 = _canonicalize_response(json1)
    canon2 = _canonicalize_response(json2)
    match = canon1 == canon2
    digest = _hash_payload(canon1)

    report = {"equal": match, "sha256": digest}
    dest.parent.mkdir(parents=True, exist_ok=True)
    dest.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")

    if not match:
        raise AssertionError("Determinism check failed; responses diverged.")

    return report


def _parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Verify proof runtime determinism.")
    parser.add_argument(
        "--dest",
        default=os.getenv("PROOF_REPLAY_REPORT", "dist/proofs/proof_replay_report.json"),
        help="Path for the determinism report JSON (default: dist/proofs/proof_replay_report.json).",
    )
    return parser.parse_args(argv)


def main() -> None:  # pragma: no cover - exercised via CLI
    args = _parse_args()
    dest = Path(args.dest)
    report = generate_proof_replay_report(dest)
    print(json.dumps(report, indent=2))


if __name__ == "__main__":  # pragma: no cover - CLI entrypoint
    main()
