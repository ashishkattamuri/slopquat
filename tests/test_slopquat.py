"""slopquat test suite.

Two non-negotiables:
1. PRECISION: zero false positives on famous, legitimate packages.
2. RECALL: real hallucination patterns are caught.

All registry interactions are mocked — no network needed.
"""

import io
import json
import sys
import unittest
import contextlib
from datetime import datetime, timedelta, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

from slopquat.detector import (
    HALLUCINATED, SUSPICIOUS, WRONG_NAME,
    Detector, detect, levenshtein, parse_imports, parse_requirements,
    similar_popular,
)
from slopquat.corpus import POPULAR_PYTHON, POPULAR_NPM

FIXTURES = Path(__file__).parent / "fixtures"

NOW = datetime.now(timezone.utc)
OLD = (NOW - timedelta(days=800)).isoformat()
YOUNG = (NOW - timedelta(days=45)).isoformat()


def make_registry(fake):
    """Wrap a {name: (exists, created)} dict as a registry callable."""
    def reg(name):
        if name in fake:
            return fake[name]
        return (False, None)  # unknown -> simulated 404
    return reg


# Fake PyPI: every famous package exists (old); plus known-bad names.
FAKE_PYPI = {n: (True, OLD) for n in POPULAR_PYTHON}
FAKE_PYPI.update({
    # Real packages whose names are import-name traps:
    "cv2": (True, OLD),
    "sklearn": (True, OLD),
    "yaml": (True, OLD),
    "bs4": (True, OLD),
    # Nonexistent (hallucinated) names:
    "python-docs-scraper": (False, None),
    "pdf-parse-lib": (False, None),
    "strutils-pro": (False, None),
    # Young near-misses of famous packages (classic squat profile):
    "reqests": (True, YOUNG),
    "numpyy": (True, YOUNG),
    # Young but NOT near anything famous -> should be OK:
    "my-brand-new-lib": (True, YOUNG),
    # Old near-miss -> established, should be OK:
    "zequests": (True, OLD),
})

FAKE_NPM = {n: (True, OLD) for n in POPULAR_NPM}
FAKE_NPM.update({
    "my-cool-hallucinated-thing": (False, None),
})

REG_PYPI = make_registry(FAKE_PYPI)
REG_NPM = make_registry(FAKE_NPM)


def make_detector(**kw):
    return Detector(pypi=REG_PYPI, npm=REG_NPM, **kw)


class TestSimilarity(unittest.TestCase):
    def test_famous_exact_is_fine(self):
        self.assertIsNone(similar_popular("requests", "python"))
        self.assertIsNone(similar_popular("numpy", "python"))

    def test_near_misses_flagged(self):
        for bad in ("reqests", "nuumpy", "reqeusts", "numpyy", "pandass"):
            with self.subTest(bad=bad):
                self.assertIsNotNone(similar_popular(bad, "python"))

    def test_unrelated_names_not_flagged(self):
        """Common legit names that must never be flagged as near-misses."""
        for ok in ("zope-interface", "pydeprecate", "aiofiles", "attrs",
                   "cachetools", "anyio", "h11", "sniffio", "httptools",
                   "uvloop", "websocket-client", "python-jose", "loguru"):
            with self.subTest(ok=ok):
                self.assertIsNone(similar_popular(ok, "python"))

    def test_popular_lists_are_internally_consistent(self):
        """No two popular packages may be edit-distance 1 of each other
        (that would make their suggestions ambiguous). Distance-2 pairs
        between long names (e.g. gunicorn/uvicorn) are acceptable."""
        for pool in (POPULAR_PYTHON, POPULAR_NPM):
            names = sorted(pool)
            for i, a in enumerate(names):
                for b in names[i + 1:]:
                    d = levenshtein(a.lower(), b.lower())
                    self.assertGreater(
                        d, 1,
                        f"'{a}' and '{b}' are distance 1 — "
                        "popular lists need curation")


class TestVerdicts(unittest.TestCase):
    def setUp(self):
        self.det = make_detector()

    def test_hallucinated_detected(self):
        f = self.det.check("python-docs-scraper", "python")
        self.assertEqual(f.verdict, HALLUCINATED)
        self.assertIn("not exist", f.reason)

    def test_hallucinated_near_miss_suggests_famous(self):
        f = self.det.check("reqeusts", "python")
        self.assertEqual(f.verdict, HALLUCINATED)
        self.assertIn("requests", f.reason)
        self.assertEqual(f.suggestion, "requests")

    def test_young_near_miss_is_suspicious(self):
        f = self.det.check("reqests", "python")
        self.assertEqual(f.verdict, SUSPICIOUS)

    def test_young_far_from_famous_is_ok(self):
        f = self.det.check("my-brand-new-lib", "python")
        self.assertEqual(f.verdict, "ok")

    def test_old_near_miss_is_ok(self):
        f = self.det.check("zequests", "python")
        self.assertEqual(f.verdict, "ok")

    def test_hallucinated_npm_detected(self):
        f = self.det.check("my-cool-hallucinated-thing", "npm")
        self.assertEqual(f.verdict, HALLUCINATED)

    def test_famous_python_never_flagged(self):
        """PRECISION GATE: every famous package must come back ok."""
        for name in sorted(POPULAR_PYTHON):
            with self.subTest(name=name):
                f = self.det.check(name, "python")
                self.assertEqual(f.verdict, "ok", f"{name}: {f.reason}")


class TestImportNameTraps(unittest.TestCase):
    def setUp(self):
        self.det = make_detector()

    def test_cv2_suggests_opencv(self):
        f = self.det.check("cv2", "python")
        self.assertEqual(f.verdict, WRONG_NAME)
        self.assertEqual(f.suggestion, "opencv-python")

    def test_sklearn_suggests_scikit_learn(self):
        f = self.det.check("sklearn", "python")
        self.assertEqual(f.verdict, WRONG_NAME)
        self.assertEqual(f.suggestion, "scikit-learn")

    def test_yaml_suggests_pyyaml(self):
        f = self.det.check("yaml", "python")
        self.assertEqual(f.verdict, WRONG_NAME)
        self.assertEqual(f.suggestion, "pyyaml")

    def test_import_scanner_flags_cv2_import(self):
        findings = self.det.scan_file(str(FIXTURES / "app.py"))
        flagged = {f.name for f in findings if f.verdict == WRONG_NAME}
        self.assertIn("cv2", flagged)
        self.assertIn("bs4", flagged)

    def test_import_scanner_ignores_stdlib(self):
        findings = self.det.scan_file(str(FIXTURES / "app.py"))
        flagged = {f.name for f in findings}
        self.assertNotIn("os", flagged)
        self.assertNotIn("sys", flagged)


class TestParsers(unittest.TestCase):
    def test_parse_requirements_full(self):
        deps = parse_requirements(str(FIXTURES / "requirements.txt"))
        names = [d[1] for d in deps]
        self.assertIn("python-docs-scraper", names)   # hallucinated
        self.assertIn("numpy", names)                 # famous
        self.assertIn("python-dateutil", names)      # extras + pin
        self.assertNotIn("click", names)              # commented out
        self.assertEqual([d[0] for d in deps], sorted(d[0] for d in deps))

    def test_parse_imports(self):
        mods = parse_imports(str(FIXTURES / "app.py"))
        names = [m[1] for m in mods]
        self.assertIn("cv2", names)
        self.assertIn("bs4", names)
        self.assertIn("os", names)
        self.assertIn("numpy", names)


class TestOfflineMode(unittest.TestCase):
    def test_offline_flags_import_traps(self):
        det = Detector(offline=True)
        f = det.check("cv2", "python")
        self.assertEqual(f.verdict, WRONG_NAME)

    def test_offline_near_miss_is_suspicious_with_caveat(self):
        det = Detector(offline=True)
        f = self.det_check_hyphen(det)
        self.assertEqual(f.verdict, SUSPICIOUS)
        self.assertIn("Offline", f.reason)

    @staticmethod
    def det_check_hyphen(det):
        return det.check("reqests", "python")


class TestEndToEnd(unittest.TestCase):
    """Full pipeline over the fixtures directory with mocked registries."""

    def test_scan_finds_all_fixture_issues(self):
        det = make_detector()
        findings = []
        for p in FIXTURES.iterdir():
            if p.name in {"requirements.txt", "pyproject.toml", "package.json"} or p.suffix == ".py":
                findings.extend(det.scan_file(str(p)))
        verdicts = {f.name: f.verdict for f in findings}
        self.assertEqual(verdicts.get("python-docs-scraper"), HALLUCINATED)
        self.assertEqual(verdicts.get("my-cool-hallucinated-thing"), HALLUCINATED)
        self.assertEqual(verdicts.get("cv2"), WRONG_NAME)

    def test_detect_report_shape(self):
        report = detect([str(FIXTURES)], offline=True)
        self.assertGreater(report.files_scanned, 0)
        self.assertIsInstance(report.to_dict(), dict)
        self.assertIn("findings", report.to_dict())


class TestCLI(unittest.TestCase):
    def _run(self, argv):
        from slopquat.cli import main as cli_main
        buf = io.StringIO()
        with contextlib.redirect_stdout(buf):
            try:
                rc = cli_main(argv)
            except SystemExit as e:  # argparse --help/--version
                rc = e.code or 0
        return rc, buf.getvalue()

    def test_offline_json_run_is_clean(self):
        rc, out = self._run(["--json", "--offline", str(FIXTURES)])
        self.assertEqual(rc, 0)
        data = json.loads(out)
        self.assertIn("findings", data)
        self.assertIn("worst_verdict", data)

    def test_help_mentions_slopsquatting(self):
        rc, out = self._run(["--help"])
        self.assertEqual(rc, 0)
        self.assertIn("slopsquatting", out)


if __name__ == "__main__":
    unittest.main()