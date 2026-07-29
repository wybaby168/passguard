#!/usr/bin/env python3
"""Fail when a public Java or TypeScript API symbol is missing from API docs."""

from __future__ import annotations

import re
from pathlib import Path


ROOT = Path(__file__).resolve().parent.parent
JAVA_SOURCE = ROOT / "java/src/main/java/dev/flyfish/passguard"
JAVA_DOC = ROOT / "java/API.md"
TS_SOURCE = ROOT / "frontend/src"
TS_DOC = ROOT / "frontend/API.md"

JAVA_TYPE = re.compile(
    r"\bpublic\s+(?:static\s+)?(?:final\s+)?"
    r"(?:class|interface|enum)\s+([A-Za-z_][A-Za-z0-9_]*)"
)
JAVA_METHOD = re.compile(
    r"^\s*public\s+(?:static\s+)?(?:final\s+)?"
    r"[A-Za-z_][A-Za-z0-9_<>, ?.\[\]]*\s+"
    r"([A-Za-z_][A-Za-z0-9_]*)\s*\(",
    re.MULTILINE,
)
JAVA_CONSTANT = re.compile(
    r"^\s*public\s+static\s+final\s+"
    r"[A-Za-z_][A-Za-z0-9_<>, ?.\[\]]*\s+"
    r"([A-Z][A-Z0-9_]*)\s*=",
    re.MULTILINE,
)
TS_EXPORT = re.compile(
    r"^export\s+(?:type|interface|class|function|const)\s+"
    r"([A-Za-z_][A-Za-z0-9_]*)",
    re.MULTILINE,
)
OBJECT_METHODS = {"equals", "hashCode", "toString"}


def documented(symbol: str, text: str) -> bool:
    pattern = rf"(?<![A-Za-z0-9_]){re.escape(symbol)}(?![A-Za-z0-9_])"
    return re.search(pattern, text) is not None


def java_symbols() -> set[str]:
    symbols: set[str] = set()
    for source in sorted(JAVA_SOURCE.glob("*.java")):
        text = source.read_text(encoding="utf-8")
        symbols.update(JAVA_TYPE.findall(text))
        symbols.update(
            method
            for method in JAVA_METHOD.findall(text)
            if method not in OBJECT_METHODS and method != "main"
        )
        symbols.update(JAVA_CONSTANT.findall(text))
    return symbols


def typescript_symbols() -> set[str]:
    symbols: set[str] = set()
    for source in sorted(TS_SOURCE.glob("*.ts")):
        if source.name == "default-blocklist.ts":
            continue
        symbols.update(TS_EXPORT.findall(source.read_text(encoding="utf-8")))
    return symbols


def missing_symbols(symbols: set[str], document: Path) -> list[str]:
    text = document.read_text(encoding="utf-8")
    return sorted(symbol for symbol in symbols if not documented(symbol, text))


def main() -> None:
    java = java_symbols()
    typescript = typescript_symbols()
    missing_java = missing_symbols(java, JAVA_DOC)
    missing_typescript = missing_symbols(typescript, TS_DOC)
    if missing_java or missing_typescript:
        if missing_java:
            print("Java API symbols missing from java/API.md:")
            for symbol in missing_java:
                print(f"  - {symbol}")
        if missing_typescript:
            print("TypeScript API symbols missing from frontend/API.md:")
            for symbol in missing_typescript:
                print(f"  - {symbol}")
        raise SystemExit(1)
    print(
        "API documentation covers "
        f"{len(java)} Java symbols and "
        f"{len(typescript)} TypeScript symbols."
    )


if __name__ == "__main__":
    main()
