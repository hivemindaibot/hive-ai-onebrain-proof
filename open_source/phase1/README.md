# Hive AI OneBrain Proof Release

This directory captures the artifacts that will be published as the Hive AI OneBrain Proof (Phase 1) drop. It contains:

- `LICENSE` – Apache 2.0 license text for the release bundle.
- `pyproject.toml` – minimal build metadata for packaging the proof service.
- `requirements.txt` – runtime dependencies required by the proof app.
- `tests/` – smoke tests mirroring the closed-source suite to ensure the proof app remains healthy.
- Source modules sourced from the internal tree (`brain/io/*`, `brain/server/proof_app.py`). These are copied into the release bundle when running the export script.

## Exporting the release bundle

Use the helper script `scripts/export_phase1_proof.py` to assemble the open-source bundle. By default, the script writes a ready-to-publish tree under `dist/phase1`. You can optionally request a zipped archive for attaching to the Hive AI OneBrain Proof GitHub release.

```bash
python scripts/export_phase1_proof.py --dest dist/phase1 --zip
```

The export script always reads from a manifest (`open_source/phase1/manifest.json`) to guarantee we only ship the audited files. The manifest was derived from the artifacts touched during the Phase 1 hardening work.

## Running the proof server locally

```bash
python -m venv .venv
source .venv/bin/activate
pip install -r open_source/phase1/requirements.txt
pip install -e .
python -m brain.server.proof_app
```

Once the server is running, send an authenticated request to `/io/query`:

```bash
curl -X POST http://127.0.0.1:8100/io/query \
  -H "Authorization: dev-token" \
  -H "Content-Type: application/json" \
  -d '{
        "query": "Summarize the supplied evidence",
        "context": [{
            "id": "doc-1",
            "text": "Evidence shows Phase 1 governance is live.",
            "sha256": "a3d1fe..."
        }]
      }'
```

The reply mirrors production behavior: validated JSON output, probe findings, and a run identifier for audit trails.

## Testing

The bundled tests exercise the Flask blueprint and confirm probe governance is enforced. Run them before publishing a new drop:

```bash
pytest open_source/phase1/tests
```
