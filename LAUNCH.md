# slopquat — Launch Kit

Repo: https://github.com/ashishkattamuri/slopquat
Status: live, CI green (15/15), PyPI publish pending token.

---

## 1. Hacker News post (Show HN)

**Title:** Show HN: Slopquat – Catch AI-hallucinated package names before they reach your lockfile

**Text:**

When LLMs generate code, they sometimes invent package names that don't exist. Attackers watch for these names and register them first — install the hallucination and you pull their code ("slopsquatting"). A USENIX Security 2025 study documented 2,013 unique hallucinated package names across 580k code generations [1].

slopquat is a zero-dependency Python CLI that scans requirements.txt, pyproject.toml, package.json, and Python imports, then verifies every name against the live PyPI/npm registry:

- HALLUCINATED — name doesn't exist on the registry (exit 1, CI-ready)
- SUSPICIOUS — exists, but registered <1 year ago AND an edit-distance near-miss of a famous package (classic squat profile)
- WRONG-NAME — import name used as a dependency (cv2 → opencv-python, sklearn → scikit-learn), with the fix suggested

I deliberately did NOT ship a static blocklist of "known hallucinations" — those go stale and I couldn't verify most circulating lists against a primary source. The registry is the ground truth: existence + registration date. Static heuristics (import-name traps, near-miss names) work offline for air-gapped use.

Precision is the design constraint: zero false positives on famous packages is a unit-tested gate, not a hope. Pure stdlib, so installing slopquat can't itself be a supply-chain vector.

Would love feedback on: the suspicious-vs-okay threshold (1 year + edit distance), and whether a pre-install pip hook would be useful.

[1] arXiv:2409.01619, USENIX Security 2025.

---

## 2. X / Twitter post

AI invents a package name. An attacker registers it. Your next `pip install` pulls their malware.

This is slopsquatting. USENIX 2025: 2,013 unique hallucinated package names across 580k LLM code generations.

So I built slopquat — zero-dep CLI that checks every dependency against live PyPI/npm before you install:

slopquat . # exit 1 on hallucinated deps

- HALLUCINATED: not on registry
- SUSPICIOUS: registered <1yr + near-miss of a famous name
- WRONG-NAME: `cv2` → `opencv-python`

Registry = ground truth. No stale blocklists. Zero deps. CI-ready.

github.com/ashishkattamuri/slopquat

---

## 3. Reddit — r/netsec (link post, this text as comment)

Title: slopquat — zero-dependency CLI that catches AI-hallucinated package names (slopsquatting) before install

Comment: Background for those who haven't seen the term: LLMs regularly hallucinate package names in generated code. USENIX Security 2025 (arXiv:2409.01619) counted 2,013 unique hallucinated names in 580k generations, and researchers demonstrated real slopsquatting on npm. slopquat scans your dependency files and Python imports, and verifies each name against the live registry — not a blocklist — plus flags young near-miss registrations (the actual squat profile). It's pure stdlib Python, so the tool itself isn't an install-time risk. Feedback on the heuristics welcome.

Cross-posts: r/LLMDevs, r/ExperiencedDevs (Show threads), r/cybersecurity (tooling Saturday rules vary — check first).

---

## 4. LinkedIn post (also serves the "industry recognition" trail)

I kept finding the same failure mode in AI-generated code: plausible-but-nonexistent dependencies.

USENIX Security 2025 documented it rigorously — 2,013 unique hallucinated package names across 580k code generations. Attackers register these names before you install them. It's called slopsquatting.

So I open-sourced slopquat: a zero-dependency CLI that verifies every dependency in your project against the live PyPI/npm registry and blocks on hallucinations. It also catches the subtler pattern — packages registered recently that are one typo away from a famous name.

Built it registry-grounded on purpose: no static blocklist to maintain, no stale data, works offline for the heuristic checks. Zero dependencies so it can't be a supply-chain vector itself.

Link in comments. Feedback welcome — especially on the suspicious-detection thresholds.

---

## 5. Where to post (priority order)

1. **Hacker News** (Show HN) — Tuesday–Thursday, 8–10am ET. The supply-chain + LLM overlap does well; the "no blocklist, registry as ground truth" angle is the discussion hook.
2. **r/netsec + r/LLMDevs** — same day, link posts.
3. **X/Twitter** — pin it; reply to threads about slopsquatting/SupplyChainSecurity with the tool.
4. **r/Python** — frame as "I built a zero-dependency CLI to catch hallucinated package names" (read their self-promo rules first).
5. **dev.to / Medium cross-post** — the "how it works" section of the README expands into a technical post naturally.
6. **LinkedIn** — the USENIX citation + your researcher credentials give it weight; recruiters/peers reshare security tooling.

## 6. Remaining product todos

- [ ] PyPI publish (needs your token: `python3 -m twine upload dist/*`)
- [ ] Demo GIF in README (record with asciinema + agg, or vhs)
- [ ] `pip install slopquat` badge + CI badge once published
- [ ] Pre-commit hook wrapper (`slopquat` runs on requirements.txt changes)
- [ ] GitHub Action (`ashishkattamuri/slopquat-action`) — separate tiny repo, links back
- [ ] MCP server mode (stdio) — lets Claude/Cursor agents self-check before installing; big differentiator, moderate effort

## 7. 30-day plan to 500 stars

Week 1: launch day (HN + Reddit + X same morning), reply to every comment within 2h. Post a follow-up "what HN said" thread if it takes off.
Week 2: GitHub Action release + demo GIF; comment on active slopsquatting news threads.
Week 3: MCP server mode; pitch to one security newsletter (Risky Biz, tl;dr sec); dev.to technical writeup with the USENIX data.
Week 4: v0.2 with lockfile support (uv.lock, package-lock.json) — second launch cycle ("we now catch it after resolution too").
Ongoing: any real-world catch in the wild = screenshot + post immediately. That's the viral material.

## 8. EB1A note

This repo is direct "original contribution" material: a first-of-kind registry-grounded approach to slopsquatting defense (no static blocklists — a design decision you can articulate in the petition), backed by a USENIX Security 2025 citation, with quantifiable adoption (stars, installs, CI usage) you can document over the next months. Pair it with your paper trail: the tool + the papers + reviews form a coherent "recognized expert in LLM security/eval" narrative.