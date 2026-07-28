#!/usr/bin/env python3
"""Fetch pinned password blocklists and rebuild deterministic deployment subsets."""

from __future__ import annotations

import argparse
import hashlib
import json
import shutil
import sys
import unicodedata
import urllib.error
import urllib.request
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

REPOSITORY = "danielmiessler/SecLists"
PRODUCTION_FILES = [
    {
        "name": "2025-199_most_used_passwords.txt",
        "path": "Passwords/Common-Credentials/2025-199_most_used_passwords.txt",
        "minimum": 199,
        "description": "SecLists / 2025 annual high-frequency password list",
    },
    {
        "name": "10k-most-common.txt",
        "path": "Passwords/Common-Credentials/10k-most-common.txt",
        "minimum": 10_000,
        "description": "SecLists / 10k common passwords",
    },
    {
        "name": "Pwdb_top-100000.txt",
        "path": "Passwords/Common-Credentials/Pwdb_top-100000.txt",
        "minimum": 100_000,
        "description": "SecLists / Pwdb top 100k",
    },
    {
        "name": "100k-most-used-passwords-NCSC.txt",
        "path": "Passwords/Common-Credentials/100k-most-used-passwords-NCSC.txt",
        "minimum": 99_800,
        "description": "SecLists / NCSC top 100k",
    },
]
OPTIONAL_PROBABLE = {
    "name": "probable-v2_top-12000.txt",
    "path": "Passwords/Common-Credentials/probable-v2_top-12000.txt",
    "minimum": 12_000,
    "description": "Probable Wordlists v2 snapshot; archival/secondary",
}
EXTRA_FILES = [
    {"name": "SecLists-LICENSE", "path": "LICENSE", "minimum": 1},
    {
        "name": "SecLists-Common-Credentials-README.md",
        "path": "Passwords/Common-Credentials/README.md",
        "minimum": 1,
    },
]
USER_AGENT = "passguard-list-updater/1.0.1"


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Rebuild browser and Java weak-password blocklists from a pinned SecLists release."
    )
    parser.add_argument("--ref", default="2026.1", help="SecLists tag/commit, or 'latest'")
    parser.add_argument("--root", type=Path, default=Path(__file__).resolve().parents[1])
    parser.add_argument(
        "--input-dir",
        type=Path,
        help="Copy production source files from a local directory instead of downloading",
    )
    parser.add_argument("--frontend-size", type=int, default=25_000)
    parser.add_argument(
        "--include-probable",
        action="store_true",
        help=(
            "Append the archival Probable Wordlists v2 source to the backend union. "
            "Review its separate CC BY-SA 4.0 terms before redistribution."
        ),
    )
    return parser.parse_args()


def request_bytes(url: str) -> bytes:
    request = urllib.request.Request(
        url,
        headers={"User-Agent": USER_AGENT, "Accept": "application/octet-stream"},
    )
    try:
        with urllib.request.urlopen(request, timeout=45) as response:
            return response.read()
    except (urllib.error.URLError, TimeoutError) as exc:
        raise RuntimeError(f"download failed: {url}: {exc}") from exc


def resolve_ref(ref: str) -> str:
    if ref != "latest":
        return ref
    payload = request_bytes(f"https://api.github.com/repos/{REPOSITORY}/releases/latest")
    document = json.loads(payload.decode("utf-8"))
    tag = document.get("tag_name")
    if not isinstance(tag, str) or not tag:
        raise RuntimeError("GitHub latest release response did not contain tag_name")
    return tag


def decode_lines(path: Path) -> list[str]:
    text = path.read_text(encoding="utf-8-sig")
    # Do not strip or trim passwords. splitlines removes line delimiters only.
    return [unicodedata.normalize("NFC", line) for line in text.splitlines() if line != ""]


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def ordered_union(paths: list[Path]) -> list[str]:
    output: list[str] = []
    seen: set[str] = set()
    for path in paths:
        for password in decode_lines(path):
            if password not in seen:
                seen.add(password)
                output.append(password)
    return output


def materialize(
    *,
    spec: dict[str, Any],
    destination_dir: Path,
    resolved_ref: str,
    input_dir: Path | None,
    local_fallback_dir: Path | None = None,
) -> tuple[Path, str]:
    filename = str(spec["name"])
    destination = destination_dir / filename
    destination_dir.mkdir(parents=True, exist_ok=True)

    if input_dir is not None:
        candidate = input_dir.resolve() / filename
        if not candidate.is_file() and local_fallback_dir is not None:
            candidate = local_fallback_dir.resolve() / filename
        if not candidate.is_file():
            raise RuntimeError(f"missing local source: {candidate}")
        if candidate.resolve() != destination.resolve():
            shutil.copyfile(candidate, destination)
        canonical_url = (
            f"https://raw.githubusercontent.com/{REPOSITORY}/{resolved_ref}/{spec['path']}"
        )
        return destination, canonical_url

    url = f"https://raw.githubusercontent.com/{REPOSITORY}/{resolved_ref}/{spec['path']}"
    destination.write_bytes(request_bytes(url))
    return destination, url


def password_record(
    path: Path,
    spec: dict[str, Any],
    source: str,
    included: bool,
    resolved_ref: str,
) -> dict[str, Any]:
    values = decode_lines(path)
    minimum = int(spec["minimum"])
    if len(values) < minimum:
        raise RuntimeError(
            f"{path.name}: expected at least {minimum} non-empty lines, got {len(values)}"
        )
    return {
        "name": path.name,
        "description": str(spec["description"]).replace("SecLists /", f"SecLists {resolved_ref} /"),
        "source": source,
        "lineCount": len(values),
        "uniqueNfcCount": len(set(values)),
        "minimumExpectedLines": minimum,
        "sha256": sha256(path),
        "includedInProductionUnion": included,
    }


def write_lines(path: Path, values: list[str]) -> None:
    path.write_text("\n".join(values) + "\n", encoding="utf-8", newline="\n")


def main() -> int:
    args = parse_args()
    if args.frontend_size < 1:
        raise SystemExit("--frontend-size must be positive")

    root = args.root.resolve()
    input_dir = args.input_dir.resolve() if args.input_dir else None
    source_dir = root / "data" / "source"
    optional_dir = root / "data" / "optional"
    generated_dir = root / "data" / "generated"
    frontend_public = root / "frontend" / "public" / "passwords"
    java_resources = root / "java" / "src" / "main" / "resources" / "weak-passwords"
    for directory in (source_dir, optional_dir, generated_dir, frontend_public, java_resources):
        directory.mkdir(parents=True, exist_ok=True)

    resolved_ref = resolve_ref(args.ref)
    records: list[dict[str, Any]] = []
    production_paths: list[Path] = []

    for spec in PRODUCTION_FILES:
        path, source = materialize(
            spec=spec,
            destination_dir=source_dir,
            resolved_ref=resolved_ref,
            input_dir=input_dir,
        )
        production_paths.append(path)
        records.append(password_record(path, spec, source, True, resolved_ref))

    for spec in EXTRA_FILES:
        path, _ = materialize(
            spec=spec,
            destination_dir=source_dir,
            resolved_ref=resolved_ref,
            input_dir=input_dir,
        )
        raw_line_count = len(path.read_text(encoding="utf-8-sig").splitlines())
        if raw_line_count < int(spec["minimum"]):
            raise RuntimeError(f"{path.name}: source file appears empty")

    optional_path, optional_source = materialize(
        spec=OPTIONAL_PROBABLE,
        destination_dir=optional_dir,
        resolved_ref=resolved_ref,
        input_dir=input_dir,
        local_fallback_dir=optional_dir,
    )
    records.append(
        password_record(
            optional_path,
            OPTIONAL_PROBABLE,
            optional_source,
            args.include_probable,
            resolved_ref,
        )
    )

    base_backend = ordered_union(production_paths)
    optional_values = decode_lines(optional_path)
    backend = ordered_union(production_paths + ([optional_path] if args.include_probable else []))
    if args.frontend_size > len(backend):
        raise RuntimeError(
            f"--frontend-size {args.frontend_size} exceeds backend union size {len(backend)}"
        )
    frontend = backend[: args.frontend_size]

    backend_path = generated_dir / "backend-blocklist.txt"
    frontend_path = generated_dir / "frontend-blocklist.txt"
    write_lines(backend_path, backend)
    write_lines(frontend_path, frontend)
    shutil.copyfile(frontend_path, frontend_public / frontend_path.name)
    shutil.copyfile(backend_path, java_resources / backend_path.name)

    metadata = {
        "kitVersion": "1.0.1",
        "generatedAtUtc": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "normalization": "Unicode NFC; exact whole-password matching; no trim",
        "seclistsPinnedRelease": resolved_ref,
        "frontend": {
            "entries": len(frontend),
            "bytes": frontend_path.stat().st_size,
            "sha256": sha256(frontend_path),
        },
        "backend": {
            "entries": len(backend),
            "bytes": backend_path.stat().st_size,
            "sha256": sha256(backend_path),
            "includesProbableWordlists": args.include_probable,
        },
        "optionalProbableWordlists": {
            "entries": len(optional_values),
            "incrementalEntriesIfMerged": len(ordered_union(production_paths + [optional_path]))
            - len(base_backend),
            "includedInProductionUnion": args.include_probable,
            "license": "CC BY-SA 4.0; review NOTICE.md before redistribution",
            "excludedByDefaultBecause": (
                "archival age, separate CC BY-SA 4.0 terms, and negligible incremental coverage"
            ),
        },
        "sources": records,
    }
    (generated_dir / "metadata.json").write_text(
        json.dumps(metadata, ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8",
    )
    print(json.dumps(metadata, ensure_ascii=False, indent=2))
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except Exception as exc:  # concise CLI error without leaking password content
        print(f"error: {exc}", file=sys.stderr)
        raise SystemExit(1)
