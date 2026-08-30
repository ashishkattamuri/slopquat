#!/usr/bin/env python3
"""slopquat CLI."""

from __future__ import annotations

import argparse
import json
import sys

from .detector import HALLUCINATED, SUSPICIOUS, WRONG_NAME, detect, __version__

# ANSI colors (no deps).
_C = {"red": "\033[31m", "yellow": "\033[33m", "cyan": "\033[36m",
      "green": "\033[32m", "bold": "\033[1m", "dim": "\033[2m", "off": "\033[0m"}

_ICON = {HALLUCINATED: "✖", SUSPICIOUS: "⚠", WRONG_NAME: "→", "ok": "✔"}
_VERDICT_COLOR = {HALLUCINATED: "red", SUSPICIOUS: "yellow", WRONG_NAME: "cyan", "ok": "green"}


def _c(text: str, color: str, enabled: bool) -> str:
    return f"{_C[color]}{text}{_C['off']}" if enabled else text


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(
        prog="slopquat",
        description=("Catch AI-hallucinated package names (slopsquatting) before they "
                     "reach your lockfile. Scans requirements.txt, pyproject.toml, "
                     "package.json, and Python imports; verifies every name against "
                     "PyPI/npm."))
    ap.add_argument("paths", nargs="*", default=["."],
                    help="Files or directories to scan (default: current directory)")
    ap.add_argument("--json", action="store_true", help="Machine-readable output")
    ap.add_argument("--offline", action="store_true",
                    help="Skip registry checks; use static heuristics only")
    ap.add_argument("--strict", action="store_true",
                    help="Also fail (exit 1) on 'suspicious' findings, not just hallucinations")
    ap.add_argument("--no-color", action="store_true", help="Disable ANSI colors")
    ap.add_argument("--version", action="version", version=f"slopquat {__version__}")
    args = ap.parse_args(argv)

    color = sys.stdout.isatty() and not args.no_color and not args.json
    report = detect(args.paths, offline=args.offline)

    if args.json:
        print(json.dumps(report.to_dict(), indent=2))
    else:
        _print_report(report, color)

    if report.findings and report.worst == HALLUCINATED:
        return 1
    if args.strict and report.worst in (HALLUCINATED, SUSPICIOUS):
        return 1
    return 0


def _print_report(report, color: bool) -> None:
    print(_c("slopquat", "bold", color) + _c(" — hallucinated-package scanner", "dim", color))
    print()

    flagged = [f for f in report.findings if f.verdict != "ok"]
    oks = [f for f in report.findings if f.verdict == "ok"]

    if not report.findings:
        print(_c("  No dependency files or Python files found to scan.", "dim", color))
        return

    for f in flagged:
        vc = _VERDICT_COLOR[f.verdict]
        icon = _ICON[f.verdict]
        head = _c(f"{icon} {f.verdict.upper():<13}", vc, color) + _c(f"{f.name}", "bold", color)
        if f.source:
            head += _c(f"  ({f.source})", "dim", color)
        print(head)
        print(f"    {f.reason}")
        if f.suggestion:
            print(f"    {f.suggestion and _c('↳ use: ' + f.suggestion, 'green', color)}")
        print()

    if oks:
        names = ", ".join(sorted({f.name for f in oks}))
        print(_c(f"✔ {len(oks)} checked and found on the registry: {names}", "green", color))

    print()
    summary = (f"{len([f for f in flagged if f.verdict == HALLUCINATED])} hallucinated, "
               f"{len([f for f in flagged if f.verdict == SUSPICIOUS])} suspicious, "
               f"{len([f for f in flagged if f.verdict == WRONG_NAME])} wrong-name "
               f"· {report.files_scanned} file(s) scanned")
    print(_c(summary, "dim", color))
    if report.registry_errors:
        print(_c("⚠ some registry checks failed (network) — results may be incomplete",
                 "yellow", color))
    if report.worst == HALLUCINATED:
        print(_c("Blocking: hallucinated package(s) found. Fix your dependency file before install.",
                 "red", color))


if __name__ == "__main__":
    sys.exit(main())