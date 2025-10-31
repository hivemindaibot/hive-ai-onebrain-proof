# Hive AI OneBrain Proof (Phase 1)

A lightweight reference implementation of the Hive OneBrain "proof" runtime used during Phase 1 research. It ships a deterministic model stub, hardened IO validators, and a bundle exporter so teams can study how the production brain validates and audits tool responses without exposing private code.

## Features

- Minimal Flask app exposing `/healthz` and `/io/query` built in `brain/server/proof_app.py`.
- Deterministic fallback model (`DefaultProofModel`) so the proof runs without external services.
- Validation and probing pipeline (`brain/io/*`) that enforces guardrails before returning an answer.
- `scripts/export_phase1_proof.py` to assemble zip bundles for distribution.
- Pytest coverage under `open_source/phase1/tests` to ensure the public API stays stable.

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

## Documentation

Detailed background, schema references, and governance notes live in `open_source/phase1/README.md` and `open_source/phase1/manifest.json`.

## License

This proof bundle is published under the license in `open_source/phase1/LICENSE`. Please review the terms before redistributing.
