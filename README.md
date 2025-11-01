# Hive AI OneBrain Proof (Phase 1)

A lightweight reference implementation of the Hive OneBrain "proof" runtime used during Phase 1 research. It ships a deterministic model stub, hardened IO validators, and a bundle exporter so teams can study how the production brain validates and audits tool responses without exposing private code.

## Features

- Minimal Flask app exposing `/healthz` and `/io/query` built in `brain/server/proof_app.py`.
- Deterministic fallback model (`DefaultProofModel`) so the proof runs without external services.
- Validation and probing pipeline (`brain/io/*`) that enforces guardrails before returning an answer.
- `scripts/export_phase1_proof.py` to assemble zip bundles for distribution.
- Pytest coverage under `open_source/phase1/tests` to ensure the public API stays stable.
- Prometheus `/metrics` endpoint (guarded by the API token) with counters and latency histograms.

## What the proof runtime does

- Normalizes inbound queries into the canonical Hive request shape, enforcing field level validation before any model call.
- Runs a deterministic reasoning stub that mirrors the structure of production tool outputs while staying offline friendly.
- Applies policy probes and schema validation to the model response, emitting `accept`, `review`, or `reject` decisions plus audit artifacts on disk.
- Returns a structured JSON envelope that downstream systems can consume without needing the private Hive codebase.

## Typical uses

- Demonstrating the Hive guardrail pipeline to external partners without exposing proprietary models or plugins.
- Building integration tests or proof of compliance flows against the `/io/query` contract before onboarding to the full platform.
- Packaging the proof bundle (`dist/phase1.zip`) for workshops, security reviews, or academic replication studies.

## RAP overview

While the Phase 1 proof keeps the footprint small, the production Hive stack also ships a Reward-Assisted Planning (RAP) pipeline located in `brain/learn/rap_harvest.py` and `scripts/rap_harvest.py`. The harvester scores execution traces, tags them with autonomy metadata, and writes bundles under `artifacts/rap/harvests/<timestamp>/traces.jsonl`. Those bundles flow into the learning adapters and the ToolForge promotion gates, providing evaluators with structured evidence before new behaviors are promoted. This repository does not include the RAP code itself, but the proof runtime is compatible with the same trace schema, so harvested artifacts can be replayed or audited alongside `/io/query` runs.

## Quick start

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r open_source/phase1/requirements.txt
pip install pytest
pytest
python scripts/export_phase1_proof.py --dest dist/phase1 --zip --overwrite
```

To run the proof server locally:

```bash
export PROOF_API_TOKEN=dev-token
export FLASK_ENV=development
python -m brain.server.proof_app
```

Then POST to `http://127.0.0.1:8100/io/query` with the payload shape defined in `open_source/phase1/README.md`. Include `Authorization: Bearer dev-token` in the request headers.

Example request using `curl`:

```bash
curl -s \
-H "Authorization: Bearer dev-token" \
-H "Content-Type: application/json" \
-d '{"query":"Summarize the approved context","context":[{"id":"kb-doc-1","text":"Artificial superintelligence research notes.","sha256":"3ffb24e75982277bc6218180eedcd80e2fce46f84b686b21083a87c05ee00bca"}]}' \
http://127.0.0.1:8100/io/query | jq
```

## Configuration

- `PROOF_API_TOKEN` (required): shared secret for `/io/query` and `/metrics`. The runtime refuses to start if it is unset or empty.
- `PROOF_CORS_ORIGINS` (optional): comma-separated list of origins allowed for browser clients. When omitted, CORS is disabled.
- `PROOF_HOST` (optional): bind address (default `127.0.0.1`). Binding to `0.0.0.0` or `::` requires `PROOF_ALLOW_PUBLIC=1`.
- `PROOF_ARTIFACTS_DIR`, `PROOF_AUTONOMY_LEVEL`: override artifact location and default autonomy budget if needed.

## Determinism proof

Generate a replay report that hashes two identical `/io/query` calls and asserts they match:

```bash
python scripts/proof_replay_check.py --dest dist/proofs/proof_replay_report.json
```

The command prints the resulting digest and writes `dist/proofs/proof_replay_report.json` containing `{ "equal": true, "sha256": "..." }`.

## JSON schemas

- Request schema (`0.1.0`): `open_source/phase1/schema/request.json`
- Response schema (`0.1.0`): `open_source/phase1/schema/response.json`
- Tests (`tests/test_proof_app.py`) validate both schemas using `jsonschema` to prevent accidental drift.

## Bundle manifest

`dist/phase1/manifest.json` records the git commit, Python version, selected `PROOF_*` environment flags (tokens noted only as "set"/"unset"), schema versions, and a SHA-256 digest of `open_source/phase1/tests`. CI uploads the manifest alongside the determinism report and bundle archive for easy provenance checks.

## What this proof is not

- No production plugins or external tool execution; the bundle ships a deterministic fallback model only.
- No training pipelines. Use it to validate IO contracts and governance paths, not to fine-tune or harvest new behaviors.
- Not a replacement for production observability or RBAC. It omits enterprise integrations (OIDC, quota enforcement, ToolForge promotions).

## Documentation

- `open_source/phase1/README.md` — full protocol reference for `/io/query`.
- `open_source/phase1/SAFETY.md` — threat model, rate limiting, token handling, and log redaction guidance.
- `open_source/phase1/manifest.json` — bundle inventory consumed by `scripts/export_phase1_proof.py`.

## License

This proof bundle is published under the license in `open_source/phase1/LICENSE`. Please review the terms before redistributing.
