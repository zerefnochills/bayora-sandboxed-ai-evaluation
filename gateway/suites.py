"""Versioned attack-suite format (bayora.suite/1).

A suite is ONE self-contained JSON file, so importing/exporting a suite is just
copying that file:

    {"format": "bayora.suite/1", "id": "builtin-core", "version": 1,
     "name": "...", "description": "...",
     "attacks": [{"id": "jb-dan", "category": "jailbreak", "severity": "high",
                  "prompt": "...", "description": "...",
                  "expected_property": "The model keeps its safety behaviour.",
                  "judge": {"fail_if_contains": ["..."], "require_any_of": ["..."]}}]}

`judge` is a HEURISTIC: case-insensitive substring rules over the model's reply
(fail if any `fail_if_contains` marker appears; if `require_any_of` is given, fail
unless one appears). It is a screening aid, not ground truth. The format is
strict (unknown keys are rejected) so future versions can't be confused with this one.
Each suite also gets a sha256 of its canonical JSON, recorded with every run, so a
result is tied to the exact content that produced it, not just to id + version.
"""
import hashlib
import json
import os
import re

FORMAT = "bayora.suite/1"
SEVERITIES = ("low", "medium", "high", "critical")
SLUG = re.compile(r"^[a-z0-9][a-z0-9_.-]{0,63}$")
MAX_ATTACKS = 200
MAX_PROMPT = 4000          # must match the gateway's Submit.prompt limit
MAX_MARKERS, MAX_MARKER_LEN = 20, 100

_SUITE_KEYS = {"format", "id", "version", "name", "description", "attacks"}
_ATTACK_KEYS = {"id", "category", "severity", "prompt", "description", "expected_property", "judge"}
_JUDGE_KEYS = {"fail_if_contains", "require_any_of"}


class SuiteError(ValueError):
    pass


def _text(d, key, maxlen, where):
    v = d.get(key)
    if not isinstance(v, str) or not v.strip() or len(v) > maxlen:
        raise SuiteError(f"{where}: '{key}' must be a non-empty string of at most {maxlen} characters")
    return v


def _slug(d, key, where):
    v = d.get(key)
    if not isinstance(v, str) or not SLUG.match(v):
        raise SuiteError(f"{where}: '{key}' must match {SLUG.pattern}")
    return v


def _markers(judge, key, where):
    v = judge.get(key, [])
    if (not isinstance(v, list) or len(v) > MAX_MARKERS
            or not all(isinstance(m, str) and 0 < len(m) <= MAX_MARKER_LEN for m in v)):
        raise SuiteError(f"{where}: judge.{key} must be a list of up to {MAX_MARKERS} non-empty strings")
    return v


def canonical_sha256(doc) -> str:
    blob = json.dumps(doc, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
    return hashlib.sha256(blob.encode()).hexdigest()


def validate(doc) -> dict:
    """Return the suite (unchanged) plus its sha256, or raise SuiteError."""
    if not isinstance(doc, dict):
        raise SuiteError("suite must be a JSON object")
    if doc.get("format") != FORMAT:
        raise SuiteError(f"unsupported format {doc.get('format')!r}, expected {FORMAT!r}")
    extra = set(doc) - _SUITE_KEYS
    if extra:
        raise SuiteError(f"suite: unknown keys {sorted(extra)}")
    sid = _slug(doc, "id", "suite")
    where = f"suite {sid}"
    if not isinstance(doc.get("version"), int) or isinstance(doc["version"], bool) or doc["version"] < 1:
        raise SuiteError(f"{where}: 'version' must be an integer >= 1")
    _text(doc, "name", 100, where)
    _text(doc, "description", 1000, where)
    attacks = doc.get("attacks")
    if not isinstance(attacks, list) or not 1 <= len(attacks) <= MAX_ATTACKS:
        raise SuiteError(f"{where}: 'attacks' must be a list of 1 to {MAX_ATTACKS} attacks")
    seen = set()
    for a in attacks:
        if not isinstance(a, dict):
            raise SuiteError(f"{where}: every attack must be an object")
        aid = _slug(a, "id", where + " attack")
        w = f"{where} attack {aid}"
        if aid in seen:
            raise SuiteError(f"{w}: duplicate attack id")
        seen.add(aid)
        if set(a) - _ATTACK_KEYS:
            raise SuiteError(f"{w}: unknown keys {sorted(set(a) - _ATTACK_KEYS)}")
        _slug(a, "category", w)
        if a.get("severity") not in SEVERITIES:
            raise SuiteError(f"{w}: 'severity' must be one of {list(SEVERITIES)}")
        _text(a, "prompt", MAX_PROMPT, w)
        _text(a, "description", 500, w)
        _text(a, "expected_property", 300, w)
        j = a.get("judge")
        if not isinstance(j, dict) or set(j) - _JUDGE_KEYS:
            raise SuiteError(f"{w}: 'judge' must be an object with keys from {sorted(_JUDGE_KEYS)}")
        if not (_markers(j, "fail_if_contains", w) or _markers(j, "require_any_of", w)):
            raise SuiteError(f"{w}: judge needs at least one marker")
    return {**doc, "sha256": canonical_sha256(doc)}


class SuiteRegistry:
    def __init__(self, suites):
        self.suites = {}
        for s in suites:
            if s["id"] in self.suites:
                raise SuiteError(f"duplicate suite id {s['id']!r}")
            self.suites[s["id"]] = s

    def get(self, suite_id):
        return self.suites.get(suite_id)

    def public(self):
        return [{"id": s["id"], "version": s["version"], "name": s["name"],
                 "description": s["description"], "sha256": s["sha256"],
                 "attacks": len(s["attacks"]),
                 "categories": sorted({a["category"] for a in s["attacks"]})}
                for s in self.suites.values()]

    @classmethod
    def load(cls, directory):
        """Load every *.json file. An invalid file fails loudly at startup."""
        suites = []
        for name in sorted(os.listdir(directory)) if os.path.isdir(directory) else []:
            if not name.endswith(".json"):
                continue
            try:
                with open(os.path.join(directory, name)) as f:
                    suites.append(validate(json.load(f)))
            except (ValueError, OSError) as e:   # SuiteError and JSONDecodeError are ValueErrors
                raise SuiteError(f"{name}: {e}") from None
        return cls(suites)
