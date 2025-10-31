# Hive AI OneBrain Proof (Phase 1)

A lightweight reference implementation of the Hive OneBrain "proof" runtime used during Phase 1 research. It ships a deterministic model stub, hardened IO validators, and a bundle exporter so teams can study how the production brain validates and audits tool responses without exposing private code.

## Features

- Minimal Flask app exposing `/healthz` and `/io/query` built in `brain/server/proof_app.py`.
- Deterministic fallback model (`DefaultProofModel`) so the proof runs without external services.
- Validation and probing pipeline (`brain/io/*`) that enforces guardrails before returning an answer.
- `scripts/export_phase1_proof.py` to assemble zip bundles for distribution.
- Pytest coverage under `open_source/phase1/tests` to ensure the public API stays stable.

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
