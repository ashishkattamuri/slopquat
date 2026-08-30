<div align="center">

# slopquat

**Catch AI-hallucinated package names before they reach your lockfile.**

`pip install slopquat`

Zero dependencies · Python 3.9+ · works on `requirements.txt`, `pyproject.toml`, `package.json`, and Python imports

</div>

---

Ask an LLM for code and it will sometimes invent a package that **does not exist** — then recommend you install it. Attackers monitor for these names and register them first. Install the hallucination, and you pull *their* code. This is **slopsquatting**, and a USENIX Security 2025 study found code-generation models produced **2,013 unique hallucinated package names** across 580k generations ([arXiv:2409.01619](https://arxiv.org/abs/2409.01619)).

`slopquat` scans your dependency files and Python imports, checks **every name against the live PyPI/npm registry**, and blocks on hallucinations.

## Demo

```text
$ slopquat .

✖ HALLUCINATED  python-docs-scraper  (demo/requirements.txt:3)
    Package does not exist on the registry.

✖ HALLUCINATED  langchain-communiy  (demo/requirements.txt:5)
    Package does not exist on the registry.

✖ HALLUCINATED  react-markdown-renderer-x  (demo/package.json)
    Package does not exist on the registry.

→ WRONG-NAME    cv2  (demo/requirements.txt:4)
    `cv2` is an import name, not a pip package.
    ↳ use: opencv-python

→ WRONG-NAME    bs4  (demo/app.py:4)
    `import bs4` comes from the `beautifulsoup4` package — make sure your
    dependency file pins that, not `bs4`.
    ↳ use: beautifulsoup4

✔ 5 checked and found on the registry: expres, lodash, numpy, react, requests

3 hallucinated, 0 suspicious, 3 wrong-name · 3 file(s) scanned
Blocking: hallucinated package(s) found. Fix your dependency file before install.
```

## Why

When a model writes `import python-docs-scraper` — a package it invented — two bad things can happen:

1. **Your install fails** (best case) because the package doesn't exist.
2. **A slopsquatter already registered that name** (worst case) and your `pip install` fetches their malicious code. There is real malware in the wild that was planted this way.

LLM coding agents make this worse: they write the dependency *and* run the install in one step, with no human reading the name first.

## Verdicts

| Verdict | Meaning | Exit code |
|---|---|---|
| `HALLUCINATED` | Name not found on the registry — the core slopsquatting risk | 1 |
| `SUSPICIOUS` | Exists, but registered < 1 year ago *and* an edit-distance near-miss of a famous package (classic squat profile) | 0 (1 with `--strict`) |
| `WRONG-NAME` | An import name used as a dependency (`cv2`, `sklearn`, `yaml`…) — with the correct distribution suggested | 0 |
| `ok` | Verified on the registry | 0 |

Every verdict is grounded in **live registry state** — existence and registration date — not a static blocklist that goes stale.

## Usage

```bash
# scan current directory
slopquat

# scan specific paths
slopquat src/ requirements.txt

# CI: fail on hallucinations (default) — also fail on suspicious
slopquat --strict

# machine-readable output
slopquat --json

# air-gapped: heuristic checks only (import traps, near-miss names)
slopquat --offline
```

### CI example (GitHub Actions)

```yaml
- name: Guard against hallucinated packages
  run: |
    pip install slopquat
    slopquat --strict
```

## How it works

1. **Parse** — `requirements.txt`, `pyproject.toml` (PEP 621), `package.json` (all dep sections), and `import` lines in `.py` files.
2. **Verify** — every dependency is checked against the real PyPI JSON API / npm registry. Not found → `HALLUCINATED`.
3. **Profile** — for names that *do* exist: registration date (from registry metadata) + edit-distance similarity to ~150 well-known packages. Young + near-miss → `SUSPICIOUS`.
4. **Correct** — import-name→distribution mapping table (`cv2` → `opencv-python`, `sklearn` → `scikit-learn`, `yaml` → `pyyaml`, …) flags the most common LLM packaging mistake and suggests the fix.

No bundled blocklist to maintain, no network required for the offline heuristics, no dependencies to install (pure stdlib — so `pip install slopquat` can't itself be a vector).

## What it's not

- Not an antivirus — it doesn't inspect package contents. If a hallucinated name is *already* registered and malware, slopquat flags it as suspicious (young + near-miss) rather than scanning payloads.
- Not a lockfile auditor — it scans dependency *declarations* (and imports), not resolved trees. Pair it with `pip-audit` / `npm audit` for known-CVE coverage.

## Development

```bash
git clone https://github.com/ashishkattamuri/slopquat
cd slopquat
python -m unittest discover -s tests -v   # 24 tests, no network needed
```

Tests run fully offline against mocked registries and include a **precision gate**: every well-known package must pass clean (zero false positives is the design constraint).

## References

- Lanyu, Wang, Zou et al., *"We Have a Package for You! Comprehensive Analysis of Package Hallucinations Induced by Code Generation Models"*, USENIX Security 2025 ([arXiv:2409.01619](https://arxiv.org/abs/2409.01619))
- Spracklen et al., *"We Have a Package for You!"* slopsquatting analysis (arXiv:2408.08687)
- The term **slopsquatting** was coined by Bar Lanyadoo (Sectec, Feb 2025).

## License

MIT © Ashish Kattamuri