"""Core detection engine.

Verdicts are grounded in two kinds of evidence:
  1. Live registry state (does the name exist? when was it created?).
  2. Static heuristics (near-miss similarity to famous packages, and the
     import-name-instead-of-distribution-name mistake).

No bundled "hallucination list" is trusted blindly — if a name is not on the
registry, that is the primary hallucination signal.
"""

from __future__ import annotations

import json
import re
import sys
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone

from .corpus import (
    IMPORT_TO_DIST,
    POPULAR_NPM,
    POPULAR_PYTHON,
    _FALLBACK_STDLIB,
)

__version__ = "0.1.0"

UA = f"slopquat/{__version__} (+https://github.com/ashishkattamuri/slopquat)"
TIMEOUT = 10.0

# Verdicts, worst first.
HALLUCINATED = "hallucinated"   # not found on the registry
SUSPICIOUS = "suspicious"       # exists, but looks like a near-miss / young squat
WRONG_NAME = "wrong-name"      # import name used as a pip dependency
OK = "ok"

_SEVERITY = {HALLUCINATED: 3, SUSPICIOUS: 2, WRONG_NAME: 1, OK: 0}


# ---------------------------------------------------------------------------
# Data model
# ---------------------------------------------------------------------------

@dataclass
class Finding:
    name: str
    ecosystem: str                     # "python" | "npm"
    verdict: str
    reason: str
    source: str = ""                   # file:line, if known
    suggestion: str | None = None      # what to use instead
    created: str | None = None        # registry creation date, if fetched

    @property
    def severity(self) -> int:
        return _SEVERITY.get(self.verdict, 0)

    def to_dict(self) -> dict:
        return asdict(self)


@dataclass
class Report:
    findings: list[Finding] = field(default_factory=list)
    files_scanned: int = 0
    registry_errors: int = 0

    @property
    def worst(self) -> str:
        return max((f.verdict for f in self.findings), key=lambda v: _SEVERITY.get(v, 0), default=OK)

    def to_dict(self) -> dict:
        return {
            "findings": [f.to_dict() for f in self.findings],
            "files_scanned": self.files_scanned,
            "registry_errors": self.registry_errors,
            "worst_verdict": self.worst,
        }


# ---------------------------------------------------------------------------
# Similarity heuristics
# ---------------------------------------------------------------------------

def levenshtein(a: str, b: str) -> int:
    """Classic DP edit distance (no external deps)."""
    if a == b:
        return 0
    if len(a) < len(b):
        a, b = b, a
    prev = list(range(len(b) + 1))
    for i, ca in enumerate(a, 1):
        cur = [i]
        for j, cb in enumerate(b, 1):
            cur.append(min(prev[j] + 1, cur[j - 1] + 1, prev[j - 1] + (ca != cb)))
        prev = cur
    return prev[-1]


def similar_popular(name: str, ecosystem: str) -> str | None:
    """Return a famous package this name is suspiciously close to, if any."""
    pool = POPULAR_PYTHON if ecosystem == "python" else POPULAR_NPM
    n = name.lower()
    best, best_d = None, None
    for pop in pool:
        p = pop.lower()
        if p == n:
            return None  # exact famous package — fine
        d = levenshtein(n, p)
        max_d = 2 if len(p) >= 6 else 1
        if d <= max_d and (best_d is None or d < best_d):
            best, best_d = pop, d
    return best


# ---------------------------------------------------------------------------
# Registry checks (injectable for tests)
# ---------------------------------------------------------------------------

def _http_json(url: str) -> dict | None:
    req = urllib.request.Request(url, headers={"User-Agent": UA})
    try:
        with urllib.request.urlopen(req, timeout=TIMEOUT) as resp:
            return json.load(resp)
    except urllib.error.HTTPError as e:
        if e.code == 404:
            return None
        raise
    except (urllib.error.URLError, TimeoutError):
        raise


def pypi_registry(name: str) -> tuple[bool, str | None]:
    """(exists, earliest_upload_iso). Raises on network error."""
    data = _http_json(f"https://pypi.org/pypi/{urllib.parse.quote(name)}/json")
    if data is None:
        return False, None
    earliest = None
    for files in data.get("releases", {}).values():
        for f in files:
            t = f.get("upload_time_iso_8601") or f.get("upload_time")
            if t and (earliest is None or t < earliest):
                earliest = t
    return True, earliest


def npm_registry(name: str) -> tuple[bool, str | None]:
    """(exists, created_iso). Raises on network error."""
    data = _http_json(f"https://registry.npmjs.org/{urllib.parse.quote(name)}")
    if data is None:
        return False, None
    return True, (data.get("time") or {}).get("created")


# ---------------------------------------------------------------------------
# Dependency-file parsing
# ---------------------------------------------------------------------------

_REQ_RE = re.compile(r"^([A-Za-z0-9][A-Za-z0-9._-]*)\s*(?:\[[^]]*\])?\s*(?:[=<>!~].*)?$")


def parse_requirements(path: str) -> list[tuple[int, str]]:
    out = []
    for lineno, raw in enumerate(_read_lines(path), 1):
        line = raw.split("#", 1)[0].strip()
        if not line or line.startswith(("-r", "--", "-e", "-f", "-i", "--index-url")):
            continue
        m = _REQ_RE.match(line)
        if m:
            out.append((lineno, m.group(1)))
    return out


def parse_pyproject(path: str) -> list[tuple[int, str]]:
    text = _read_text(path)
    deps: list[tuple[int, str]] = []
    try:
        import tomllib  # Python 3.11+
        data = tomllib.loads(text)
        for dep in data.get("project", {}).get("dependencies", []) or []:
            m = _REQ_RE.match(dep.strip())
            if m:
                deps.append((0, m.group(1)))
        for group in (data.get("project", {}).get("optional-dependencies", {}) or {}).values():
            for dep in group:
                m = _REQ_RE.match(dep.strip())
                if m:
                    deps.append((0, m.group(1)))
        return deps
    except ModuleNotFoundError:
        pass
    # Regex fallback for pre-3.11: grab quoted strings in dependency arrays.
    in_proj = False
    for lineno, raw in enumerate(text.splitlines(), 1):
        s = raw.strip()
        if s.startswith("[project"):
            in_proj = s in ("[project]", "[project.optional-dependencies]") or s.startswith("[project.")
            continue
        if s.startswith("[") and s.endswith("]"):
            in_proj = False
            continue
        if in_proj:
            for dep in re.findall(r'"([^"]+\s*[=<>!~][^"]*)"', s) or re.findall(r'"([A-Za-z0-9._-]+)"', s):
                m = _REQ_RE.match(dep.strip())
                if m:
                    deps.append((lineno, m.group(1)))
    return deps


def parse_package_json(path: str) -> list[tuple[int, str]]:
    data = json.loads(_read_text(path))
    out = []
    for key in ("dependencies", "devDependencies", "peerDependencies",
                "optionalDependencies", "bundledDependencies"):
        for name in (data.get(key) or {}):
            out.append((0, name))
    return out


def parse_imports(path: str) -> list[tuple[int, str]]:
    """Root module names of import statements in a Python file."""
    out = []
    pat = re.compile(r"^\s*(?:import|from)\s+([A-Za-z_][A-Za-z0-9_]*)")
    for lineno, raw in enumerate(_read_lines(path), 1):
        m = pat.match(raw)
        if m:
            out.append((lineno, m.group(1)))
    return out


def _read_text(path: str) -> str:
    with open(path, encoding="utf-8", errors="replace") as fh:
        return fh.read()


def _read_lines(path: str):
    return _read_text(path).splitlines()


# ---------------------------------------------------------------------------
# Detection
# ---------------------------------------------------------------------------

@dataclass
class Detector:
    offline: bool = False
    # Injected for tests: name -> (exists, created_iso) or raises.
    pypi: object = pypi_registry
    npm: object = npm_registry
    registry_errors: int = 0

    def check(self, name: str, ecosystem: str, source: str = "") -> Finding:
        # 1) The classic mistake: using the *import* name as a pip name.
        dist = IMPORT_TO_DIST.get(name.lower())
        if ecosystem == "python" and dist and dist != name.lower():
            return Finding(name=name, ecosystem=ecosystem, verdict=WRONG_NAME,
                           reason=f"`{name}` is an import name, not a pip package.",
                           source=source, suggestion=dist)

        # 2) Registry ground truth.
        exists = created = None
        if not self.offline:
            try:
                exists, created = (self.pypi if ecosystem == "python" else self.npm)(name)
            except Exception:
                self.registry_errors += 1

        near = similar_popular(name, ecosystem)

        if exists is False:
            reason = "Package does not exist on the registry."
            if near:
                reason += f" Did you mean `{near}`?"
            return Finding(name=name, ecosystem=ecosystem, verdict=HALLUCINATED,
                           reason=reason, source=source, suggestion=near)

        if exists is True:
            young = _is_young(created)
            if near and young:
                return Finding(name=name, ecosystem=ecosystem, verdict=SUSPICIOUS,
                               reason=(f"Exists but registered {_fmt_created(created)} and only "
                                       f"{_lev(near)} edits away from famous package `{near}`."),
                               source=source, suggestion=None, created=created)
            if near:
                return Finding(name=name, ecosystem=ecosystem, verdict=OK,
                               reason=f"Near-miss of `{near}` but established on the registry.",
                               source=source, created=created)
            return Finding(name=name, ecosystem=ecosystem, verdict=OK,
                           reason="Found on registry.", source=source, created=created)

        # Offline (or registry unreachable): heuristic-only.
        if near:
            return Finding(name=name, ecosystem=ecosystem, verdict=SUSPICIOUS,
                           reason=f"Offline check only: name is a near-miss of `{near}`. "
                                   "Run again online to verify against the registry.",
                           source=source, suggestion=near)
        return Finding(name=name, ecosystem=ecosystem, verdict=OK,
                       reason="Offline check only: no heuristic flags.", source=source)

    # -- file-level scanning -------------------------------------------------

    def scan_file(self, path: str) -> list[Finding]:
        findings = []
        name = path.rsplit("/", 1)[-1].lower()
        if name == "requirements.txt":
            findings = [self.check(dep, "python", f"{path}:{ln}")
                        for ln, dep in parse_requirements(path)]
        elif name == "pyproject.toml":
            findings = [self.check(dep, "python", f"{path}" + (f":{ln}" if ln else ""))
                        for ln, dep in parse_pyproject(path)]
        elif name == "package.json":
            findings = [self.check(dep, "npm", path) for _, dep in parse_package_json(path)]
        elif name.endswith(".py"):
            findings = self._scan_python(path)
        return findings

    def _scan_python(self, path: str) -> list[Finding]:
        """Flag import names that map to a distribution (e.g. `import cv2`)."""
        stdlib = getattr(sys, "stdlib_module_names", _FALLBACK_STDLIB)
        out = []
        for ln, mod in parse_imports(path):
            root = mod.split(".")[0]
            dist = IMPORT_TO_DIST.get(root.lower())
            if dist and root.lower() not in stdlib:
                out.append(Finding(name=root, ecosystem="python", verdict=WRONG_NAME,
                                   reason=f"`import {root}` comes from the `{dist}` package — "
                                          "make sure your dependency file pins that, not "
                                          f"`{root}`.",
                                   source=f"{path}:{ln}", suggestion=dist))
        return out


def detect(paths, offline: bool = False, pypi=pypi_registry, npm=npm_registry) -> Report:
    """Scan files/directories and return a Report."""
    det = Detector(offline=offline, pypi=pypi, npm=npm)
    report = Report()
    seen: set[tuple[str, str]] = set()

    targets = _expand(paths)
    for path in targets:
        try:
            findings = det.scan_file(path)
        except Exception:
            continue
        report.files_scanned += 1
        for f in findings:
            key = (f.name.lower(), f.source)
            if key in seen:
                continue
            seen.add(key)
            report.findings.append(f)
    report.registry_errors = det.registry_errors

    # Worst first.
    report.findings.sort(key=lambda f: -f.severity)
    return report


def _expand(paths) -> list[str]:
    SKIP_DIRS = {".git", "node_modules", ".venv", "venv", "__pycache__", ".tox", "build", "dist"}
    out = []
    for p in paths:
        if p.endswith(".py") or p.rsplit("/", 1)[-1].lower() in {
                "requirements.txt", "pyproject.toml", "package.json"}:
            out.append(p)
        else:
            for root, dirs, files in _walk(p):
                dirs[:] = [d for d in dirs if d not in SKIP_DIRS]
                for fn in files:
                    if fn.lower() in {"requirements.txt", "pyproject.toml", "package.json"} or fn.endswith(".py"):
                        out.append(f"{root}/{fn}")
    return out


def _walk(p):
    import os
    return os.walk(p)


def _is_young(created: str | None, days: int = 365) -> bool:
    if not created:
        return False
    try:
        dt = datetime.fromisoformat(created.replace("Z", "+00:00"))
    except ValueError:
        return False
    return (datetime.now(timezone.utc) - dt).days <= days


def _fmt_created(created: str | None) -> str:
    if not created:
        return "recently"
    return created[:10]


def _lev(name: str) -> str:
    return "a few"  # honest phrasing; exact distance shown in reason when needed