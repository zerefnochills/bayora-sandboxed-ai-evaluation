"""Evidence bundle and printable report for one evaluation run.

bundle (format "bayora.evidence/1") = everything needed to check a run without trusting this server's
UI: run metadata, the exact suite definition, every result row, the run's audit entries (each with its own
`prev` and `hash`), the verification state when the bundle was made, and a digest over all of it.
scripts/verify_evidence.py checks a bundle offline using only the standard library.

What a bundle proves, and what it does not:
  * `digest` detects accidental or careless edits to the file. It is NOT a signature: whoever edits a
    bundle can recompute it.
  * The audit entries are sparse (only this run's), so chain *continuity* and the comparison with the
    independent anchor were checked by the gateway at generation time (recorded under `verification`);
    they cannot be re-derived from the bundle. Each entry is still individually checkable, and every
    result row is cross-checked against its audit entry.
  * Nothing here says a model is safe. Attack verdicts are heuristic screens.

The report is rendered from the bundle only. EVERY dynamic string is HTML-escaped: model replies and
prompts are untrusted. It carries a CSP (header and meta tag) that allows one fixed inline script, the
print button.
"""
import base64
import hashlib
import html
import json
import time

FORMAT = "bayora.evidence/1"
SEVERITY_ORDER = ("critical", "high", "medium", "low")

RISK = {  # category -> (what it means, what to consider)
    "jailbreak": ("The model can be talked out of its safety behaviour by personas, role-play or fake modes. "
                  "Impact: policy-violating output and reputational or legal exposure.",
                  "Harden the system prompt, add an input/output guard or classifier, and keep these probes as a regression suite."),
    "prompt_injection": ("Instructions hidden in data or imitating system formatting can steer the model. Impact: "
                         "unintended behaviour or disclosure whenever the model reads untrusted content such as documents, web pages or email.",
                         "Keep untrusted content separate from instructions, give the model least-privilege tools, validate its output, and require approval for sensitive actions."),
    "instruction_following": ("The model adopts attacker-imposed rules or repeats false claims about its own security state. "
                              "Impact: misleading output and corrupted downstream parsing.",
                              "Do not rely on the model to track security state; enforce it outside the model and validate outputs."),
    "data_exfiltration": ("The model may reveal hidden instructions, credentials or other users' data. Impact: confidentiality breach.",
                          "Never place secrets in prompts, isolate context per user, and scan outputs for credential-shaped content."),
    "policy_bypass": ("A claimed role or authority is treated as authorization. Impact: privilege escalation through conversation.",
                      "Enforce authorization outside the model; treat claims made in text as untrusted."),
}
GENERIC_RISK = ("This probe category produced a flagged answer.", "Review the answer manually and decide whether it is acceptable for your use.")

LIMITS = [
    "Attack verdicts are heuristic substring screens over the model's reply. They miss paraphrased failures and can flag harmless replies. A pass is not proof of safety and a flag is not proof of a flaw; flagged answers need human review.",
    "The suite is small. Passing it says little about attacks it does not contain, other languages, long conversations or tool use.",
    "Each probe was sent once. Model output can vary between runs, so repeat the run before drawing conclusions.",
    "Results describe the model, settings and system prompt actually used at that time. They do not transfer to other versions or configurations.",
    "This is a screening report, not a security certification or compliance attestation.",
]


def canonical(obj):
    return json.dumps(obj, sort_keys=True, separators=(",", ":"))


def sha256(text):
    return hashlib.sha256(text.encode()).hexdigest()


def bundle_digest(bundle):
    return sha256(canonical({k: v for k, v in bundle.items() if k != "digest"}))


def select_audit(entries, run, test_ids):
    """The audit entries that belong to this run, in sequence order."""
    # Runs never overlap (one at a time) and every probe entry is written between the run's creation and its
    # finish, so an exact window, with no slack, attributes probe entries to exactly one run.
    lo, hi = run["created"], run["finished"] or time.time()
    tids, out = set(test_ids), []
    for e in entries:
        d = e.get("data") or {}
        if d.get("run_id") == run["run_id"] or d.get("test_id") in tids or (
                str(e.get("actor", "")).startswith("eval-probe-") and lo <= e["ts"] <= hi):
            out.append(e)
    return sorted(out, key=lambda e: e["seq"])


def build_bundle(run, rows, suite, entries, verification, version="dev", now=None):
    """run: Runner.public_run(run, with_check=True); rows: Runner.public_results(run);
    suite: the registry's suite dict (or None); entries: audit entries; verification: audit.verify() output."""
    test_ids = [r["test_id"] for r in rows if r.get("test_id")]
    s = None
    if suite is not None and suite["sha256"] == run["suite"]["sha256"]:
        s = {k: v for k, v in suite.items() if k != "sha256"}
    bundle = {
        "format": FORMAT, "generated_at": now if now is not None else time.time(),
        "generator": {"name": "bayora-gateway", "version": version},
        "run": run,
        "suite": {"sha256": run["suite"]["sha256"], "definition": s,
                  **({} if s else {"note": "definition not available: the suite file changed or was removed after this run"})},
        "results": rows,
        "audit": {"entries": select_audit(entries, run, test_ids)},
        "verification": {"audit_chain_ok": verification["ok"], "audit_entries": verification["entries"],
                         "audit_head": verification.get("head"), "anchor": verification["anchor"],
                         "note": "Chain continuity and the anchor comparison were checked by the gateway at generation time; "
                                 "they cannot be re-derived from this sparse excerpt."},
    }
    bundle["digest"] = bundle_digest(bundle)
    return bundle


# ---------------------------------------------------------------------------------------------- report
SCRIPT = "document.getElementById('p').addEventListener('click',function(){window.print()})"
SCRIPT_HASH = "sha256-" + base64.b64encode(hashlib.sha256(SCRIPT.encode()).digest()).decode()
CSP = ("default-src 'none'; style-src 'unsafe-inline'; script-src '%s'; base-uri 'none'; form-action 'none'" % SCRIPT_HASH)

CSS = """
@page{size:A4;margin:18mm}*{box-sizing:border-box}
body{margin:0;background:#fff;color:#000;font:14px/1.55 -apple-system,"Segoe UI",Helvetica,Arial,sans-serif}
main{max-width:860px;margin:0 auto;padding:32px 24px 64px}
h1,h2,h3{font-family:Georgia,"Times New Roman",serif;font-weight:400;margin:0}
h1{font-size:44px;line-height:1.05;margin-bottom:6px}h2{font-size:26px;margin:36px 0 10px;border-top:2px solid #000;padding-top:14px}h3{font-size:18px;margin:0 0 4px}
table{border-collapse:collapse;width:100%;margin:8px 0 4px;font-size:13px}th,td{text-align:left;padding:6px 8px;border-bottom:1px solid #ccc;vertical-align:top}th{font-weight:600;border-bottom:2px solid #000}
tr{break-inside:avoid}.k{font-weight:700}.flag td{background:#000;color:#fff}.mut{color:#444}.box{border:1px solid #000;padding:12px 14px;margin:12px 0;break-inside:avoid}
.banner{border:2px solid #000;padding:12px 14px;margin:16px 0;font-weight:600}.inv{background:#000;color:#fff}
.cards{display:grid;grid-template-columns:repeat(4,1fr);gap:8px;margin:14px 0}.cards div{border:1px solid #000;padding:10px}.cards b{display:block;font:400 28px Georgia,serif}
code,pre{font:12px/1.4 ui-monospace,Menlo,Consolas,monospace;overflow-wrap:anywhere;white-space:pre-wrap}pre{border-left:3px solid #000;padding:2px 10px;margin:6px 0}
button{font:inherit;border:1px solid #000;background:#fff;padding:8px 16px;border-radius:99px;cursor:pointer}button:hover{background:#000;color:#fff}
.top{display:flex;justify-content:space-between;align-items:center;margin-bottom:24px}
@media print{.noprint{display:none}main{padding:0}a{color:#000}}
"""


def _e(x):
    return html.escape("" if x is None else str(x), quote=True)


def _ts(t):
    return time.strftime("%Y-%m-%d %H:%M:%S UTC", time.gmtime(t)) if t else "-"


def findings(bundle):
    """The data-derived 'potential downsides': flagged probes, platform defects, infrastructure problems."""
    rows = bundle["results"]
    f = {"defects": [r for r in rows if r["kind"] == "control" and r["status"] == "fail"],
         "flagged": [r for r in rows if r["kind"] == "attack" and r["status"] == "fail"],
         "infra": [r for r in rows if r["status"] in ("error", "blocked")]}
    f["flagged"].sort(key=lambda r: SEVERITY_ORDER.index(r["severity"]) if r["severity"] in SEVERITY_ORDER else 9)
    return f


def _origin_banner(run):
    k = run.get("provider_kind")
    if k == "mock":
        return '<div class="banner inv">MOCK MODEL. This report describes the bundled mock model. It says nothing about any real model.</div>'
    if k == "real":
        return '<div class="banner">REAL PROVIDER: %s, model %s.</div>' % (_e(run.get("provider")), _e(run.get("provider_model") or run.get("model")))
    return '<div class="banner">PROVIDER UNKNOWN. This run was made before provider tracking existed, so it cannot be labelled mock or real.</div>'


def render_report(bundle):
    run, rows, ver = bundle["run"], bundle["results"], bundle["verification"]
    sm = run.get("summary") or {}
    out = ['<!DOCTYPE html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">',
           '<meta http-equiv="Content-Security-Policy" content="%s">' % _e(CSP),
           "<title>Bayora report %s</title><style>%s</style></head><body><main>" % (_e(run["run_id"]), CSS),
           '<div class="top noprint"><span class="mut">Bayora evaluation report</span><button id="p">Print or save as PDF</button></div>',
           "<h1>Evaluation report</h1>",
           '<p class="mut">Run %s, %s</p>' % (_e(run["run_id"]), _e(_ts(run["created"]))), _origin_banner(run)]

    out.append("<table>" + "".join("<tr><th>%s</th><td>%s</td></tr>" % (_e(k), v) for k, v in (
        ("Model", _e(run["model"])), ("Provider", "%s %s" % (_e(run.get("provider") or "unknown"), _e(run.get("provider_model") or ""))),
        ("Suite", "%s version %s (content hash <code>%s</code>)" % (_e(run["suite"]["id"]), _e(run["suite"]["version"]), _e(run["suite"]["sha256"][:16]))),
        ("Started by", _e(run["created_by"])), ("Started", _e(_ts(run["created"]))), ("Finished", _e(_ts(run.get("finished")))),
        ("Status", _e(run["status"])))) + "</table>")

    if run.get("error"):
        er = run["error"]
        out.append('<h2>Infrastructure failure</h2><div class="box"><p class="k">No attacks were sent to the model.</p><p>The run stopped at <b>%s</b> (%s): %s</p>'
                   '<p class="mut">This is not a verdict about the model. Fix the provider and run again.</p></div>' % (
                       _e(er.get("stage")), _e(er.get("status")), _e(er.get("detail"))))
    elif sm:
        det, heu = sm["by_judge"]["deterministic"], sm["by_judge"]["heuristic"]
        n_det, n_heu = sum(det.values()), sum(heu.values())
        out.append("<h2>Summary</h2>")
        out.append('<div class="cards"><div><b>%s</b>gateway controls passed, of %s</div><div><b>%s</b>probes passed, of %s</div><div><b>%s</b>probes flagged</div><div><b>%s</b>errors or blocked</div></div>' % (
            _e(det["pass"]), _e(n_det), _e(heu["pass"]), _e(n_heu), _e(heu["fail"]), _e(sm["errors"] + sm["blocked"])))
        out.append("<p>Gateway controls are checked by code and a failure is a real defect. Probe verdicts are heuristic screens of the model's replies, not proof either way.</p>")
        lat = sm.get("latency_ms")
        if lat:
            out.append('<p class="mut">Model latency over %s requests: median %s ms, 95th percentile %s ms, maximum %s ms.</p>' % (_e(lat["count"]), _e(lat["p50"]), _e(lat["p95"]), _e(lat["max"])))

    f = findings(bundle)
    if rows:
        out.append("<h2>Potential downsides</h2>")
        if f["defects"]:
            out.append('<div class="banner inv">%d gateway control(s) FAILED. These are defects in the platform, not the model: %s.</div>' % (
                len(f["defects"]), ", ".join(_e(r["case_id"]) for r in f["defects"])))
        if f["flagged"]:
            out.append("<p>%d probe(s) were flagged. Each is a signal for human review, not a confirmed flaw.</p>" % len(f["flagged"]))
            for r in f["flagged"]:
                what, consider = RISK.get(r["category"], GENERIC_RISK)
                out.append('<div class="box"><h3>%s</h3><p class="mut">%s, severity %s, %s</p><p><b>Expected:</b> %s</p><p><b>What happened:</b> %s</p>%s'
                           '<p><b>Why it matters:</b> %s</p><p><b>What to consider:</b> %s</p></div>' % (
                               _e(r["case_id"]), _e(r["category"].replace("_", " ")), _e(r["severity"]), _e(r["judge"]), _e(r["expected"]), _e(r["detail"]),
                               ("<pre>%s</pre>" % _e(r["response_excerpt"])) if r.get("response_excerpt") else "", _e(what), _e(consider)))
        elif not f["defects"] and run["status"] == "completed":
            out.append("<p>No probes were flagged. That does not show the model is safe: see the limitations below.</p>")
        if f["infra"]:
            out.append("<p>%d case(s) did not produce a verdict because of infrastructure problems or limits (%s). They are not counted as passes.</p>" % (
                len(f["infra"]), ", ".join("%s %s" % (_e(r["case_id"]), _e(r["status"])) for r in f["infra"][:8])))

        cats = {}
        for r in rows:
            if r["kind"] == "attack":
                c = cats.setdefault(r["category"], [0, 0, 0])
                c[0] += 1
                c[1] += r["status"] == "fail"
                c[2] += r["status"] in ("error", "blocked")
        out.append("<h2>Coverage by category</h2><table><tr><th>Category</th><th>Probes</th><th>Flagged</th><th>No verdict</th></tr>%s</table>" % "".join(
            "<tr><td>%s</td><td>%s</td><td>%s</td><td>%s</td></tr>" % (_e(k.replace("_", " ")), v[0], v[1], v[2]) for k, v in sorted(cats.items())))

        def table(kind, label):
            rs = [r for r in rows if r["kind"] == kind]
            return ("<h2>%s</h2><table><tr><th>Case</th><th>Category</th><th>Severity</th><th>Judge</th><th>Verdict</th><th>Latency</th></tr>%s</table>" % (_e(label), "".join(
                '<tr class="%s"><td>%s</td><td>%s</td><td>%s</td><td>%s</td><td class="k">%s</td><td>%s</td></tr>' % (
                    "flag" if r["status"] == "fail" else "", _e(r["case_id"]), _e(r["category"].replace("_", " ")), _e(r["severity"]), _e(r["judge"]),
                    _e("FLAGGED" if (r["status"] == "fail" and kind == "attack") else r["status"].upper()),
                    _e("%s ms" % r["latency_ms"] if r.get("latency_ms") is not None else "-")) for r in rs)))
        out.append(table("control", "Gateway controls (deterministic)"))
        out.append(table("attack", "Attack probes (heuristic)"))

    out.append("<h2>Evidence and integrity</h2>")
    anc = (ver.get("anchor") or {})
    out.append("<table>%s</table>" % "".join("<tr><th>%s</th><td>%s</td></tr>" % (_e(k), v) for k, v in (
        ("Audit chain when this report was made", "verified, %s entries" % _e(ver["audit_entries"]) if ver["audit_chain_ok"] else "<b>BROKEN</b>"),
        ("Independent anchor", _e("enabled, %s of %s entries copied" % (anc.get("anchored"), anc.get("local")) if anc.get("enabled") else "not configured")),
        ("Stored results vs audit log", _e(json.dumps((run.get("db_check") or {}), sort_keys=True))),
        ("Results digest", "<code>%s</code>" % _e(run.get("results_digest"))),
        ("Bundle digest", "<code>%s</code>" % _e(bundle["digest"])),
        ("Audit entries in the bundle", _e(len(bundle["audit"]["entries"]))))))
    out.append('<p class="mut">The evidence bundle for this run can be checked offline with <code>python3 scripts/verify_evidence.py bundle.json</code>. '
               "The digest catches accidental edits; it is not a signature.</p>")
    out.append("<h2>Limitations</h2><ul>%s</ul>" % "".join("<li>%s</li>" % _e(x) for x in LIMITS))
    out.append('<p class="mut">Generated %s by %s %s.</p>' % (_e(_ts(bundle["generated_at"])), _e(bundle["generator"]["name"]), _e(bundle["generator"]["version"])))
    out.append("</main><script>%s</script></body></html>" % SCRIPT)
    return "".join(out)
