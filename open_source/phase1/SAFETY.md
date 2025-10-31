# Hive Proof Runtime Safety Notes

This Phase 1 proof is intentionally minimal. Use this checklist before exposing the runtime outside of a controlled lab.

## Attack surface

- HTTP endpoints: `/healthz`, `/io/query`, and `/metrics` (the latter requires the API token).
- All requests must include the shared `PROOF_API_TOKEN`. Refuse to run if the token is unset and rotate it periodically.
- The runtime performs no tool execution or outbound network calls; responses come from the deterministic fallback model unless you inject a custom client.

## Rate limiting

- Ship the proof behind a reverse proxy or gateway that enforces rate limits per token.
- Recommended baseline: burst of 5 requests, sustained rate of 1 RPS per token. Adjust for your environment.

## Network and environment restrictions

- Keep the process bound to `127.0.0.1` or a private network segment. Only use `PROOF_ALLOW_PUBLIC=1` (when implemented) in hardened staging.
- Do not grant the container or VM outbound internet access when running with untrusted inputs.

## File system behaviour

- Artifacts and audit logs are written beneath `PROOF_ARTIFACTS_DIR` (default `artifacts/proof`). Ensure the directory is on a trusted volume with least-privilege permissions.
- Rotate or purge artifacts regularly; they may contain user prompts, citations, and probe findings.

## Token handling

- Store tokens in a secure secret manager or environment variable manager. Avoid committing tokens to source control or embedding them in scripts.
- Enforce TLS when the proof service is accessed remotely so the token is never sent over plaintext HTTP.

## Logging and redaction

- The proof runtime does not log request bodies by default. If you add logging, redact user-provided context and tokens.
- Monitor artifacts for personally identifying information; probes flag obvious PII patterns but manual review is still required before sharing artifacts.

## Operational checklist

- Run `pytest` and the determinism replay check before each release to confirm validator and schema stability.
- When distributing bundles, include `dist/proofs/proof_replay_report.json` and the request/response schemas so integrators can reproduce safety checks.
