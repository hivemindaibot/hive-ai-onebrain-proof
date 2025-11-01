# SPDX-License-Identifier: Apache-2.0

from __future__ import annotations

import json
import logging
import os
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, Iterable, Optional, Protocol, Sequence, Tuple
from uuid import uuid4

from flask import Flask, Response, jsonify, request
from prometheus_client import Counter, Histogram, generate_latest

from brain.io import validators as io_validators
from brain.io.artifacts import write_artifacts as io_write_artifacts
from brain.io.probes import run_probes

LOGGER = logging.getLogger(__name__)

IO_REQUESTS = Counter(
    "proof_io_requests_total",
    "Total IO requests processed",
    labelnames=("decision",),
)

IO_LATENCY = Histogram(
    "proof_io_latency_seconds",
    "Latency of IO requests",
    buckets=(0.05, 0.1, 0.25, 0.5, 1.0, 2.0, 5.0, 10.0),
)

VALIDATOR_FAIL = Counter(
    "proof_validator_fail_total",
    "Validation failures by stage",
    labelnames=("stage",),
)


class ModelClientProtocol(Protocol):
    """Protocol describing the minimal interface for a proof model client."""

    def generate(  # pragma: no cover - structural typing hook
        self,
        *,
        req: io_validators.NormalizedRequest,
        messages: Sequence[Dict[str, str]],
        temperature: float,
        max_tokens: int,
    ) -> Tuple[str, Dict[str, Any]]:
        ...


@dataclass
class ProofConfig:
    """Lightweight configuration for the proof application."""

    api_token: str | None = None
    artifacts_dir: str = os.getenv("PROOF_ARTIFACTS_DIR", "artifacts/proof")
    default_autonomy: str = os.getenv("PROOF_AUTONOMY_LEVEL", "full")
    cors_origins: tuple[str, ...] = field(default_factory=tuple)

    def __post_init__(self) -> None:
        if not self.api_token:
            env_token = os.getenv("PROOF_API_TOKEN")
            if not env_token:
                raise RuntimeError("PROOF_API_TOKEN must be set before starting the proof runtime")
            self.api_token = env_token
        if not self.cors_origins:
            origins = os.getenv("PROOF_CORS_ORIGINS", "")
            values = tuple(o.strip() for o in origins.split(",") if o.strip())
            if values:
                self.cors_origins = values


class DefaultProofModel:
    """Deterministic fallback model used for the Phase 1 release."""

    def generate(
        self,
        *,
        req: io_validators.NormalizedRequest,
        messages: Sequence[Dict[str, str]],
        temperature: float,
        max_tokens: int,
    ) -> Tuple[str, Dict[str, Any]]:
        if req.context:
            entry = req.context[0]
            answer = entry.text
            citations = [
                {
                    "id": entry.cid,
                    "sha256": entry.sha256,
                    "evidence": entry.text[:120],
                }
            ]
            confidence = 0.55
        else:
            answer = "No approved context was provided."
            citations = []
            confidence = 0.1
        payload = {
            "answer": answer,
            "citations": citations,
            "confidence": confidence,
        }
        usage = {"prompt_tokens": len(messages), "completion_tokens": len(answer.split())}
        return json.dumps(payload), usage


class ProofBrain:
    """Container that holds the model client for the proof app."""

    def __init__(self, model: Optional[ModelClientProtocol] = None) -> None:
        self.model = model or DefaultProofModel()


def _ensure_dir(path: str) -> None:
    Path(path).mkdir(parents=True, exist_ok=True)


def _merge_vary_header(current: str, value: str) -> str:
    parts = [segment.strip() for segment in current.split(",") if segment.strip()]
    if value not in parts:
        parts.append(value)
    return ", ".join(parts)


def _set_cors_headers(resp: Response, origin: str) -> Response:
    resp.headers["Access-Control-Allow-Origin"] = origin
    resp.headers["Access-Control-Allow-Methods"] = "POST, OPTIONS"
    resp.headers["Access-Control-Allow-Headers"] = "Authorization, Content-Type"
    resp.headers["Access-Control-Max-Age"] = "600"
    vary = resp.headers.get("Vary", "")
    resp.headers["Vary"] = _merge_vary_header(vary, "Origin")
    return resp


def _call_model(
    model: Any,
    req: io_validators.NormalizedRequest,
    messages: Sequence[Dict[str, str]],
    *,
    temperature: float,
    max_tokens: int,
) -> Tuple[str, Dict[str, Any]]:
    """Invoke the configured model, supporting multiple call signatures."""

    try:
        return model.generate(
            req=req,
            messages=messages,
            temperature=temperature,
            max_tokens=max_tokens,
        )
    except TypeError:
        return model.generate(messages, temperature=temperature, max_tokens=max_tokens)


def _authorize(headers: Dict[str, str], expected_token: str) -> bool:
    auth = headers.get("Authorization") or ""
    if auth.startswith("Bearer "):
        token = auth.split(" ", 1)[1].strip()
    else:
        token = auth.strip()
    return token == expected_token


def _metrics_unauthorized() -> Response:
    resp = Response("", status=401)
    resp.headers["WWW-Authenticate"] = "Bearer"
    return resp


def resolve_bind_host(default: str = "127.0.0.1") -> str:
    """Resolve the host binding while enforcing local-only default."""

    host = os.getenv("PROOF_HOST", default).strip() or default
    public_hosts = {"0.0.0.0", "::", "[::]"}
    if host in public_hosts:
        if os.getenv("PROOF_ALLOW_PUBLIC") != "1":
            raise RuntimeError(
                "Refusing to bind to a public interface without PROOF_ALLOW_PUBLIC=1"
            )
    return host


def create_app(
    config: Optional[ProofConfig] = None,
    *,
    model: Optional[ModelClientProtocol] = None,
    testing: bool = False,
) -> Flask:
    """Create a lightweight Flask app exposing the proof `/io/query` route."""

    cfg = config or ProofConfig()
    _ensure_dir(cfg.artifacts_dir)

    brain = ProofBrain(model=model)

    app = Flask(__name__)
    if testing:
        app.config["TESTING"] = True

    app.config["PROOF_CONFIG"] = cfg
    app.config["PROOF_BRAIN"] = brain
    app.config["PROOF_ALLOWED_ORIGINS"] = set(cfg.cors_origins)

    def _cors_enabled(origin: Optional[str]) -> bool:
        allowed: set[str] = app.config["PROOF_ALLOWED_ORIGINS"]
        return bool(allowed and origin and origin in allowed)

    @app.after_request
    def _apply_cors(resp: Response) -> Response:
        origin = request.headers.get("Origin")
        if _cors_enabled(origin):
            _set_cors_headers(resp, origin)  # ensures vary + allow headers
        return resp

    @app.get("/healthz")
    def healthz() -> Any:
        return jsonify({"ok": True})

    @app.get("/metrics")
    def metrics() -> Response:
        cfg: ProofConfig = app.config["PROOF_CONFIG"]
        if not _authorize(request.headers, cfg.api_token):
            return _metrics_unauthorized()
        payload = generate_latest()
        resp = Response(payload, mimetype="text/plain; version=0.0.4; charset=utf-8")
        vary = resp.headers.get("Vary", "")
        resp.headers["Vary"] = _merge_vary_header(vary, "Authorization")
        return resp

    @app.route("/io/query", methods=["POST", "OPTIONS"])
    def io_query() -> Any:
        cfg: ProofConfig = app.config["PROOF_CONFIG"]
        brain: ProofBrain = app.config["PROOF_BRAIN"]

        if request.method == "OPTIONS":
            origin = request.headers.get("Origin")
            if not _cors_enabled(origin):
                return jsonify({"ok": False, "error": "cors_not_allowed"}), 403
            return _set_cors_headers(Response(status=204), origin)

        if not _authorize(request.headers, cfg.api_token):
            return jsonify({"ok": False, "error": "unauthorized"}), 401

        payload = request.get_json(silent=True) or {}
        try:
            req = io_validators.normalize_request(payload, autonomy_level=cfg.default_autonomy)
        except io_validators.ValidationError as exc:
            VALIDATOR_FAIL.labels(stage="request").inc()
            return jsonify({"ok": False, "error": "invalid_request", "details": str(exc)}), 400

        messages = io_validators.build_messages(req)
        start = time.perf_counter()
        try:
            llm_output, usage = _call_model(
                brain.model,
                req,
                messages,
                temperature=0.0,
                max_tokens=req.budget_tokens,
            )
            latency = time.perf_counter() - start
        except Exception as exc:  # pragma: no cover - defensive guard
            latency = time.perf_counter() - start
            LOGGER.exception("model invocation failed: %s", exc)
            VALIDATOR_FAIL.labels(stage="model").inc()
            run_id = uuid4().hex
            validation = io_validators.ValidationResult(
                ok=False,
                decision="reject",
                errors=[f"llm_failure:{exc}"],
                warnings=[],
                parsed=None,
                latency_seconds=float(latency),
                usage={},
                citations_hash=None,
            )
            io_write_artifacts(cfg.artifacts_dir, run_id, req, messages, str(exc), validation)
            return (
                jsonify(
                    {
                        "ok": False,
                        "error": "llm_failure",
                        "details": str(exc),
                        "decision": validation.decision,
                        "run_id": run_id,
                    }
                ),
                502,
            )

        usage = usage or {}
        run_id = uuid4().hex

        try:
            parsed = io_validators.parse_llm_response(llm_output)
            validation = io_validators.validate_response(
                req,
                parsed,
                latency_seconds=float(latency),
                usage=dict(usage),
            )
        except io_validators.ValidationError as exc:
            VALIDATOR_FAIL.labels(stage="response_parse").inc()
            validation = io_validators.ValidationResult(
                ok=False,
                decision="reject",
                errors=[f"parse_error:{exc}"],
                warnings=[],
                parsed=None,
                latency_seconds=float(latency),
                usage=dict(usage),
                citations_hash=None,
            )
        else:
            probe_report = run_probes(req, parsed)
            validation.probe_findings = probe_report.to_dict()
            for issue in validation.probe_findings["issues"]:
                label = f"{issue['kind']}:{issue['severity']}:{','.join(issue['context_ids'])}"
                target = validation.errors if issue["severity"] == "error" else validation.warnings
                target.append(label)
            validation.update_decision()

        IO_LATENCY.observe(latency)
        IO_REQUESTS.labels(decision=validation.decision).inc()

        io_write_artifacts(
            cfg.artifacts_dir,
            run_id,
            req,
            messages,
            llm_output,
            validation,
        )

        response_payload = {
            "ok": validation.decision == "accept",
            "decision": validation.decision,
            "answer": validation.parsed.answer if validation.parsed else "",
            "citations": validation.parsed.citations if validation.parsed else [],
            "confidence": validation.parsed.confidence if validation.parsed else None,
            "errors": validation.errors,
            "warnings": validation.warnings,
            "run_id": run_id,
            "probe_findings": validation.probe_findings,
            "validation": {
                "ok": validation.ok,
                "decision": validation.decision,
                "errors": validation.errors,
                "warnings": validation.warnings,
                "latency_seconds": validation.latency_seconds,
                "usage": validation.usage,
                "citations_hash": validation.citations_hash,
                "probe_findings": validation.probe_findings,
            },
        }
        return jsonify(response_payload)

    return app


def main() -> None:  # pragma: no cover - manual entry point
    logging.basicConfig(level=logging.INFO)
    app = create_app()
    port = int(os.getenv("PROOF_PORT", "8100"))
    host = resolve_bind_host()
    app.run(host=host, port=port)


if __name__ == "__main__":  # pragma: no cover - script execution
    main()
