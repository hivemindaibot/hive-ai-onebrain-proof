#!/usr/bin/env python3
"""Assemble the Phase 1 proof bundle from the audited manifest."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import platform
import shutil
import subprocess
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List

ROOT = Path(__file__).resolve().parent.parent
DEFAULT_MANIFEST = ROOT / "open_source" / "phase1" / "manifest.json"
DEFAULT_DEST = ROOT / "dist" / "phase1"
SCHEMA_REQUEST = ROOT / "open_source" / "phase1" / "schema" / "request.json"
SCHEMA_RESPONSE = ROOT / "open_source" / "phase1" / "schema" / "response.json"


def _git_commit() -> str:
    try:
        return (
            subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=ROOT, text=True)
            .strip()
        )
    except Exception:  # pragma: no cover - git metadata optional
        return "unknown"


def _schema_version(path: Path) -> str:
    try:
        data = json.loads(path.read_text())
        return str(data.get("x-version", "unknown"))
    except Exception:  # pragma: no cover - defensive guard
        return "unknown"


def compute_tests_hash() -> str:
    """Compute a stable hash across the Phase 1 test suite."""

    tests_dir = ROOT / "open_source" / "phase1" / "tests"
    digest = hashlib.sha256()
    for path in sorted(tests_dir.rglob("*.py")):
        digest.update(path.relative_to(ROOT).as_posix().encode("utf-8"))
        digest.update(path.read_bytes())
    return digest.hexdigest()


def _env_flags() -> Dict[str, Any]:
    return {
        "PROOF_API_TOKEN_set": bool(os.getenv("PROOF_API_TOKEN")),
        "PROOF_CORS_ORIGINS": os.getenv("PROOF_CORS_ORIGINS", ""),
        "PROOF_AUTONOMY_LEVEL": os.getenv("PROOF_AUTONOMY_LEVEL", ""),
    }


def _collect_bundle_metadata(entries: List[Dict[str, str]], manifest_path: Path) -> Dict[str, Any]:
    timestamp = (
        datetime.now(timezone.utc)
        .replace(microsecond=0)
        .isoformat()
        .replace("+00:00", "Z")
    )
    try:
        manifest_label = manifest_path.resolve().relative_to(ROOT).as_posix()
    except ValueError:  # pragma: no cover - external manifest path
        manifest_label = manifest_path.resolve().as_posix()

    return {
        "bundle_version": "phase1",
        "generated_at": timestamp,
        "git_commit": _git_commit(),
        "python_version": platform.python_version(),
        "env_flags": _env_flags(),
        "schema_versions": {
            "request": _schema_version(SCHEMA_REQUEST),
            "response": _schema_version(SCHEMA_RESPONSE),
        },
        "tests_sha256": compute_tests_hash(),
        "files_count": len(entries),
        "source_manifest": manifest_label,
        "ci_run_id": os.getenv("GITHUB_RUN_ID"),
    }


def _write_bundle_manifest(dest: Path, entries: List[Dict[str, str]], manifest_path: Path) -> None:
    bundle = _collect_bundle_metadata(entries, manifest_path)
    payload = {
        "bundle": bundle,
        "files": entries,
    }
    (dest / "manifest.json").write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")
SCHEMA_REQUEST = ROOT / "open_source" / "phase1" / "schema" / "request.json"
SCHEMA_RESPONSE = ROOT / "open_source" / "phase1" / "schema" / "response.json"


def _load_manifest(path: Path) -> list[dict[str, str]]:
    data = json.loads(path.read_text())
    files = data.get("files")
    if not isinstance(files, list):  # pragma: no cover - defensive branch
        raise ValueError("manifest must contain a 'files' list")
    normalized: list[dict[str, str]] = []
    for entry in files:
        if not isinstance(entry, dict):
            raise ValueError("manifest entries must be objects")
        source = entry.get("source")
        dest = entry.get("dest")
        if not source or not dest:
            raise ValueError("manifest entries require 'source' and 'dest'")
        normalized.append({"source": source, "dest": dest})
    return normalized


def _copy_file(source: Path, dest: Path) -> None:
    dest.parent.mkdir(parents=True, exist_ok=True)
    shutil.copy2(source, dest)


def export_bundle(*, manifest: Path, dest: Path, overwrite: bool = False, zip_archive: bool = False) -> Path:
    if not manifest.exists():  # pragma: no cover - defensive guard
        raise FileNotFoundError(f"manifest not found: {manifest}")

    if dest.exists():
        if not overwrite:
            raise FileExistsError(f"destination already exists: {dest}")
        shutil.rmtree(dest)
    dest.mkdir(parents=True, exist_ok=True)

    entries = _load_manifest(manifest)
    for entry in entries:
        source = ROOT / entry["source"]
        if not source.exists():
            raise FileNotFoundError(f"source missing: {source}")
        target = dest / entry["dest"]
        _copy_file(source, target)

    _write_bundle_manifest(dest, entries, manifest)

    if zip_archive:
        archive_path = shutil.make_archive(dest.as_posix(), "zip", root_dir=dest)
        return Path(archive_path)
    return dest


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Export the Phase 1 proof bundle")
    parser.add_argument("--manifest", default=DEFAULT_MANIFEST, type=Path, help="Path to manifest json")
    parser.add_argument("--dest", default=DEFAULT_DEST, type=Path, help="Destination directory for the bundle")
    parser.add_argument("--overwrite", action="store_true", help="Overwrite destination if it exists")
    parser.add_argument("--zip", action="store_true", help="Create a .zip archive alongside the directory")
    return parser.parse_args()


def main() -> None:  # pragma: no cover - CLI glue
    args = parse_args()
    artifact = export_bundle(
        manifest=args.manifest,
        dest=args.dest,
        overwrite=args.overwrite,
        zip_archive=args.zip,
    )
    print(f"Created bundle at {artifact}")


if __name__ == "__main__":  # pragma: no cover - script entry
    main()
