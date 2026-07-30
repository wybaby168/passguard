#!/usr/bin/env python3
"""Fail CI when a JMH throughput result regresses beyond the committed budget."""

from __future__ import annotations

import json
import sys
from pathlib import Path


def load(path: Path) -> object:
    with path.open(encoding="utf-8") as stream:
        return json.load(stream)


def result_key(result: dict[str, object]) -> str:
    parameters = result.get("params")
    suffix = ""
    if isinstance(parameters, dict):
        suffix = "|" + ",".join(
            f"{key}={parameters[key]}" for key in sorted(parameters)
        )
    return f"{result['benchmark']}{suffix}"


def main() -> None:
    if len(sys.argv) != 3:
        raise SystemExit(
            "usage: check_jmh_regression.py BASELINE.json JMH_RESULT.json"
        )
    baseline = load(Path(sys.argv[1]))
    results = load(Path(sys.argv[2]))
    if not isinstance(baseline, dict) or not isinstance(results, list):
        raise SystemExit("invalid benchmark JSON")

    allowed = float(baseline["allowed_regression"])
    expected = baseline["benchmarks"]
    if not 0 <= allowed < 1 or not isinstance(expected, dict):
        raise SystemExit("invalid benchmark baseline")

    actual: dict[str, float] = {}
    for item in results:
        if not isinstance(item, dict):
            continue
        metric = item.get("primaryMetric")
        if isinstance(metric, dict) and metric.get("scoreUnit") == "ops/s":
            actual[result_key(item)] = float(metric["score"])

    failures: list[str] = []
    for key, baseline_score in sorted(expected.items()):
        if key not in actual:
            failures.append(f"{key}: missing result")
            continue
        minimum = float(baseline_score) * (1 - allowed)
        score = actual[key]
        if score < minimum:
            failures.append(
                f"{key}: {score:.2f} ops/s < {minimum:.2f} ops/s "
                f"({allowed:.0%} regression budget)"
            )

    if failures:
        print("JMH performance regression:")
        for failure in failures:
            print(f"  - {failure}")
        raise SystemExit(1)
    print(
        f"JMH baseline passed: {len(expected)} results, "
        f"maximum allowed regression {allowed:.0%}."
    )


if __name__ == "__main__":
    main()
