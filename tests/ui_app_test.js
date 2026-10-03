const { JSDOM, VirtualConsole } = require("jsdom");
const base = process.argv[2], BOOT = process.env.BOOT_CODE;
let pass = 0, fail = 0;
const check = (n, c, x = "") => { c ? pass++ : fail++; console.log((c ? "  PASS  " : "  FAIL  ") + n + (c ? "" : "  " + String(x).slice(0, 300))); };
const sleep = ms => new Promise(r => setTimeout(r, ms));
async function until(f, ms = 20000) { const t = Date.now(); while (Date.now() - t < ms) { try { if (await f()) return true } catch {} await sleep(80) } return false }
const errors = [];
async function browser() {
  const vc = new VirtualConsole(); vc.on("jsdomError", e => errors.push(String(e.message || e)));
  const dom = await JSDOM.fromURL(base + "/app", { runScripts: "dangerously", resources: "usable", pretendToBeVisual: true, virtualConsole: vc,
    beforeParse(w) { w.fetch = (u, o) => fetch(new URL(u, w.location.href), o); w.confirm = () => true; w.URL.createObjectURL = b => { w.__blobs.push(b); return "blob:test" }; w.__blobs = []; w.__opened = []; w.open = () => { const o = { location: null, close() {} }; w.__opened.push(o); return o };
      w.HTMLAnchorElement.prototype.click = function () { w.__downloads = (w.__downloads || []).concat([[this.getAttribute("download"), this.getAttribute("href")]]) } } });
  const w = dom.window, d = w.document;
  const $ = s => d.querySelector(s), $$ = s => [...d.querySelectorAll(s)];
  const text = () => $("#nav").textContent + " " + $("#app").textContent;   // rendered UI only, not the page's own script source
  const btn = t => $$("button").find(b => b.textContent.trim() === t);
  const fill = (el, v) => { el.value = v };
  const blobText = b => new Promise(r => { const f = new w.FileReader(); f.onload = () => r(f.result); f.readAsText(b) });
  return { w, d, $, $$, text, btn, fill, blobText, close: () => w.close() };
}
const tab = (B, t) => { B.btn(t).click(); };

(async () => {
  const A = await browser();
  console.log("== first-run setup");
  check("shows the setup screen with how to get the code", await until(() => /Set up Bayora/.test(A.text()) && /bootstrap_code/.test(A.text())), A.text().slice(0, 200));
  check("no navigation is shown while signed out", A.$("#nav").children.length === 0);
  A.fill(A.$("#c"), "wrongcode"); A.fill(A.$("#u"), "admin1"); A.fill(A.$("#p"), "Admin-pass-2026!"); A.btn("Set up Bayora").click();
  check("a wrong setup code shows the server's reason and stays on the form", await until(() => /invalid setup code/.test(A.$("#flash").textContent)) && /Set up Bayora/.test(A.text()));
  A.fill(A.$("#c"), BOOT); A.fill(A.$("#p"), "short"); A.btn("Set up Bayora").click();
  check("a weak password shows the policy message", await until(() => /10 to 128 characters|Please check the form/.test(A.$("#flash").textContent)), A.$("#flash").textContent);
  A.fill(A.$("#p"), "Admin-pass-2026!"); A.btn("Set up Bayora").click();
  check("the right code creates the admin and opens the app", await until(() => /Evaluate a model/.test(A.text())));
  const navT = () => [...A.$("#nav").children].map(b => b.textContent);
  check("admin navigation: Evaluate, All runs, Overview, Users, Account, Sign out", navT().join("|") === "Evaluate|All runs|Overview|Users|Account|Sign out (admin1)", navT().join("|"));
  check("the token is kept in sessionStorage only", !!A.w.sessionStorage.getItem("bayora_token") && !A.w.localStorage.getItem("bayora_token"));

  console.log("== admin: users");
  tab(A, "Users");
  check("users table lists admin1 as an active admin", await until(() => /admin1/.test(A.text()) && /Create an account/.test(A.text())));
  const inputs = () => A.$$("input"); const sel = () => A.$$("select").slice(-1)[0];
  const mk = async (u, p, role) => { const i = inputs(); A.fill(i[0], u); A.fill(i[1], p); A.fill(sel(), role); A.btn("Create").click(); return until(() => /Account created/.test(A.$("#flash").textContent) || /taken|Please check|characters|username/.test(A.$("#flash").textContent)) };
  await mk("alice", "weak", "user");
  check("a too-short password for a new account is refused with the reason", /characters|Please check/.test(A.$("#flash").textContent), A.$("#flash").textContent);
  await mk("alice", "violet rain tomorrow 1", "user"); await mk("bob", "granite window 22", "user");
  check("alice and bob are created and appear in the table", await until(() => /alice/.test(A.text()) && /bob/.test(A.text())) && A.$$("tbody tr").length === 3, A.$$("tbody tr").length);
  A.$$("tbody tr").find(r => /bob/.test(r.textContent)).querySelectorAll("button")[0].click();
  check("Disable marks bob DISABLED", await until(() => A.$$("tbody tr").find(r => /bob/.test(r.textContent)).textContent.includes("DISABLED")));
  A.$$("tbody tr").find(r => /bob/.test(r.textContent)).querySelectorAll("button")[0].click();
  check("Enable brings bob back", await until(() => !A.$$("tbody tr").find(r => /bob/.test(r.textContent)).textContent.includes("DISABLED")));
  A.$$("tbody tr").find(r => /admin1/.test(r.textContent)).querySelectorAll("button")[0].click();
  check("the only admin cannot disable themselves (server says why)", await until(() => /last active admin/.test(A.$("#flash").textContent)), A.$("#flash").textContent);
  tab(A, "Sign out (admin1)");
  check("sign out returns to the sign-in form and drops the token", await until(() => /Sign in/.test(A.$("h1").textContent)) && !A.w.sessionStorage.getItem("bayora_token") && A.$("#nav").children.length === 0);

  console.log("== a normal user");
  const login = async (B, u, p) => { B.fill(B.$("#u"), u); B.fill(B.$("#p"), p); B.btn("Sign in").click() };
  await login(A, "alice", "wrong wrong wrong");
  check("a wrong password shows one generic error", await until(() => /invalid username or password/.test(A.$("#flash").textContent)));
  await login(A, "alice", "violet rain tomorrow 1");
  check("alice signs in: navigation has no admin tabs", await until(() => /Evaluate a model/.test(A.text())) && navT().join("|") === "Evaluate|My runs|Account|Sign out (alice)", navT().join("|"));
  const opts = [...A.$("#model").options].map(o => o.textContent);
  check("model selector labels the mock as [MOCK]; suite selector lists builtin-core with 13 attacks", opts.some(o => /^\[MOCK\] Mock LLM/.test(o)) && /13 attacks/.test(A.$("#suite").selectedOptions[0].textContent) && /MOCK MODEL/.test(A.$("#app").textContent), opts.join("|"));
  A.btn("Test connection").click();
  check("Test connection reports the provider status", await until(() => /OK/.test(A.text())));
  A.btn("Run evaluation").click();
  check("starting a run shows live progress", await until(() => /Running|cases done/.test(A.text()) || /Finished|CONTROLS/.test(A.text())));
  check("the run finishes with the five summary cards", await until(() => A.$$(".card").length === 5, 60000));
  const cards = Object.fromEntries(A.$$(".card").map(c => [c.querySelector("span").textContent, c.querySelector("b").textContent]));
  check("controls 12 of 12 (checked by code), 11 of 13 probes passed, 2 flagged, audit chain Verified", cards["Gateway controls (checked by code)"] === "12 of 12" && cards["Attack probes (heuristic)"] === "11 passed of 13" && cards["Probes flagged"] === "2" && cards["Audit chain"] === "Verified", JSON.stringify(cards));
  check("the run header says MOCK MODEL; results table has 25 rows with 2 FLAGGED", /MOCK MODEL/.test(A.text()) && A.$$("tbody tr").length === 25 && A.$$("tbody tr.fl").length === 2 && A.$$("tbody tr.fl").every(r => /FLAGGED/.test(r.textContent)));
  check("a tip points at the report when something was flagged", /signals for human review/.test(A.text()));
  A.btn("Open printable report").click();
  check("the report opens in a new window from a blob that contains the report", await until(() => A.w.__blobs.length === 1 && A.w.__opened[0] && A.w.__opened[0].location === "blob:test"));
  const rep = await A.blobText(A.w.__blobs[0]);
  check("the report is the real one: sections, MOCK banner, both flagged jailbreaks, limitations, started by user:alice", /Evaluation report/.test(rep) && /MOCK MODEL/.test(rep) && /jb-dan-persona/.test(rep) && /jb-developer-mode/.test(rep) && /Limitations/.test(rep) && /user:alice/.test(rep));
  A.btn("Download evidence").click();
  check("evidence downloads as a JSON bundle named for the run", await until(() => (A.w.__downloads || []).length === 1) && /^bayora-evidence-[0-9a-f]{12}\.json$/.test(A.w.__downloads[0][0]));
  const ev = JSON.parse(await A.blobText(A.w.__blobs[1]));
  check("the bundle is bayora.evidence/1 with 25 results and a digest", ev.format === "bayora.evidence/1" && ev.results.length === 25 && ev.digest.length === 64 && /verify_evidence/.test(A.$("#flash").textContent));
  tab(A, "My runs");
  check("My runs lists exactly this run with its origin and result", await until(() => A.$$("tbody tr").length === 1) && /MOCK MODEL/.test(A.$$("tbody tr")[0].textContent) && /11 of 25 passed|23 of 25 passed/.test(A.$$("tbody tr")[0].textContent), A.$$("tbody tr")[0].textContent);
  A.$$("tbody tr")[0].click();
  check("clicking the run shows its detail again, with a way back", await until(() => A.$$("tbody tr").length === 25 && /Back to the list/.test(A.text())));
  tab(A, "Account");
  await until(() => A.$$("input").length === 2); const pw = A.$$("input"); A.fill(pw[0], "violet rain tomorrow 1"); A.fill(pw[1], "amber orchard seven 7"); A.btn("Change password").click();
  check("changing the password keeps alice signed in on a fresh session", await until(() => /Password changed/.test(A.$("#flash").textContent)));

  console.log("== isolation between users, and a second browser");
  const Bb = await browser(); await until(() => /Sign in/.test(Bb.$("h1").textContent));
  await login(Bb, "bob", "granite window 22");
  await until(() => /Evaluate a model/.test(Bb.text())); tab(Bb, "My runs");
  check("bob sees none of alice's runs", await until(() => /Nothing yet/.test(Bb.text())) && Bb.$$("tbody tr").length === 0);
  const Cc = await browser(); await until(() => /Sign in/.test(Cc.$("h1").textContent));
  await login(Cc, "admin1", "Admin-pass-2026!"); await until(() => /Evaluate a model/.test(Cc.text()));
  tab(Cc, "All runs");
  check("the admin's All runs shows alice's run and who started it", await until(() => Cc.$$("tbody tr").length === 1) && /user:alice/.test(Cc.$$("tbody tr")[0].textContent));
  tab(Cc, "Overview");
  check("Overview: accounts, runs, audit chain Verified and anchor status", await until(() => /Accounts/.test(Cc.text())) && /3 active of 3/.test(Cc.text()) && /Verified/.test(Cc.text()) && /Anchor/.test(Cc.text()) && /Mock LLM/.test(Cc.text()), Cc.text().slice(0, 400));
  tab(Cc, "Users");
  await until(() => /bob/.test(Cc.text()));
  Cc.$$("tbody tr").find(r => /alice/.test(r.textContent)).querySelectorAll("button")[0].click();
  await until(() => Cc.$$("tbody tr").find(r => /alice/.test(r.textContent)).textContent.includes("DISABLED"));
  tab(A, "My runs");
  check("alice's open session is ended at once when the admin disables her", await until(() => /Your session ended/.test(A.text()) && /Sign in/.test(A.$("h1").textContent)), A.text().slice(0, 200));
  await login(A, "alice", "amber orchard seven 7");
  check("a disabled account cannot sign in (generic error)", await until(() => /invalid username or password/.test(A.$("#flash").textContent)));

  console.log("== safety");
  const hostile = '<img src=x onerror="window.__xss=1"><script>window.__xss=2<\/script>';
  const el = Bb.w.eval("h('div',{class:'x'},'" + hostile.replace(/'/g, "\\'") + "')"); Bb.$("#app").append(el); await sleep(50);
  check("hostile text passed to the DOM builder becomes text, never elements or script", !Bb.$("#app img") && Bb.w.__xss === undefined && /<img src=x/.test(el.textContent));
  const raw = await (await fetch(base + "/app")).text();
  check("the served page still has the CSP header", /script-src 'sha256-/.test((await fetch(base + "/app")).headers.get("content-security-policy")));
  check("no uncaught script errors in any of the three browsers", errors.length === 0, errors.join(" | "));
  console.log(`\nResult: ${pass} passed, ${fail} failed`);
  process.exit(fail ? 1 : 0);
})();
