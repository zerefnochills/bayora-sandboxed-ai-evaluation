const chromium = require("@sparticuz/chromium").default || require("@sparticuz/chromium");
const puppeteer = require("puppeteer-core");
const fs = require("fs");
const BASE = process.env.BASE, BOOT = process.env.BOOT_CODE, SHOTS = process.env.SHOTS || "/tmp/shots";
fs.mkdirSync(SHOTS, { recursive: true });
let pass = 0, fail = 0;
const check = (n, c, x = "") => { c ? pass++ : fail++; console.log((c ? "  PASS  " : "  FAIL  ") + n + (c ? "" : "  " + String(x).slice(0, 300))); };
const sleep = ms => new Promise(r => setTimeout(r, ms));
const api = async (m, p, tok, body) => { const r = await fetch(BASE + p, { method: m, headers: { ...(tok ? { Authorization: "Bearer " + tok } : {}), ...(body ? { "Content-Type": "application/json" } : {}) }, body: body ? JSON.stringify(body) : undefined }); let d = null; try { d = await r.json() } catch {} return { status: r.status, data: d } };
const SIZES = [["desktop", 1280, 900], ["tablet", 820, 1100], ["phone", 390, 844]];

(async () => {
  const admin = (await api("POST", "/auth/bootstrap", null, { code: BOOT, username: "admin1", password: "Admin-pass-2026!" })).data.token;
  await api("POST", "/admin/users", admin, { username: "alice", password: "violet rain tomorrow 1", role: "user" });
  const alice = (await api("POST", "/auth/login", null, { username: "alice", password: "violet rain tomorrow 1" })).data.token;
  const run = (await api("POST", "/evaluations", alice, { suite_id: "builtin-core" })).data;
  for (let i = 0; i < 300; i++) { if ((await api("GET", "/evaluations/" + run.run_id, alice)).data.status !== "running") break; await sleep(100) }
  const browser = await puppeteer.launch({ executablePath: await chromium.executablePath(), args: [...chromium.args, "--no-sandbox"], headless: "shell" });
  const errors = [];
  const open = async (token, w, h, opts = {}) => {
    /* sessionStorage is per tab, so a new page is a clean signed-out browser */ const p = await browser.newPage(); await p.setViewport({ width: w, height: h });
    if (opts.reduce) await p.emulateMediaFeatures([{ name: "prefers-reduced-motion", value: "reduce" }]);
    if (token) await p.evaluateOnNewDocument(t => { try { sessionStorage.setItem("bayora_token", t) } catch {} }, token);
    p.on("pageerror", e => errors.push(String(e))); p.on("console", m => { if (m.type() === "error") errors.push(m.text()) });
    await p.goto(BASE + "/app", { waitUntil: "networkidle0" }); return p;
  };
  const noOverflow = async (p, label) => { const o = await p.evaluate(() => [document.documentElement.scrollWidth, window.innerWidth]); check(label + ": no horizontal scrolling (" + o[0] + " <= " + o[1] + ", viewport " + o[1] + "x" + (await p.evaluate(() => innerHeight)) + ")", o[0] <= o[1] + 1, o.join("/")) };
  const shot = async (p, name) => { await sleep(700); return p.screenshot({ path: SHOTS + "/" + name + ".png" }) };
  const text = p => p.evaluate(() => document.querySelector("#nav").textContent + " | " + document.querySelector("#app").textContent);
  const click = (p, label) => p.evaluate(l => { const b = [...document.querySelectorAll("button")].find(x => x.textContent.trim() === l); if (!b) throw new Error("no button " + l); b.click() }, label);
  const until = async (p, fn, ms = 20000) => { const t = Date.now(); while (Date.now() - t < ms) { if (await p.evaluate(fn).catch(() => false)) return true; await sleep(100) } return false };

  console.log("== landing (signed out)");
  for (const [name, w, h] of SIZES) {
    const p = await open(null, w, h); await sleep(2600);
    const t = await text(p);
    check(`${name}: hero, SANDBOX, description, nav items and the four steps are on the page`, /Bayora/.test(t) && /Sandbox/i.test(t) && /Isolated Red Team and Blue Team testing/.test(t) && /Home.*About.*Method.*Try it.*Sign in/.test(t) && /Red team sends a test/.test(t) && /Gateway checks who, when and where/.test(t) && /Model answers/.test(t) && /Audit log keeps the proof/.test(t), t.slice(0, 200));
    await noOverflow(p, name + " landing"); await shot(p, `landing-${name}`);
    if (name === "desktop") {
      check("the live gateway status pill is real (Gateway online)", await until(p, () => /Gateway online/.test(document.querySelector("#live").textContent)));
      await click(p, "Guide me"); await sleep(1200);
      const g = await p.evaluate(() => ({ on: document.querySelector("#tt").classList.contains("on"), h: document.querySelector("#ttH").textContent }));
      check("Guide me opens the tour with its first step", g.on && g.h === "Move around", JSON.stringify(g)); await shot(p, "tour-desktop");
      await p.keyboard.press("Escape"); await sleep(300);
      check("Escape closes the tour", !(await p.evaluate(() => document.querySelector("#tt").classList.contains("on"))));
      await p.evaluate(() => document.getElementById("pipe").scrollIntoView()); await sleep(1800);
      check("the method pipeline animates in (all four nodes become visible)", await p.evaluate(() => [...document.querySelectorAll(".pn")].every(n => getComputedStyle(n).opacity === "1")));
    }
    await p.close();
  }
  console.log("== reduced motion");
  const rm = await open(null, 1280, 900, { reduce: true }); await sleep(300);
  const rmState = await rm.evaluate(() => ({ anim: getComputedStyle(document.querySelector(".name span")).animationName, card: getComputedStyle(document.querySelector(".lcard")).animationName, pn: [...document.querySelectorAll(".pn")].every(n => getComputedStyle(n).opacity === "1") }));
  check("prefers-reduced-motion: hero animations are off and content is fully visible immediately", rmState.anim === "none" && rmState.card === "none" && rmState.pn, JSON.stringify(rmState)); await rm.close();

  console.log("== signed-in user (alice)");
  for (const [name, w, h] of SIZES) {
    const p = await open(alice, w, h); await sleep(400);
    check(`${name}: normal-user navigation is Home, Evaluate, My Runs, Account, Sign out`, (await p.evaluate(() => [...document.querySelector("#nav").children].map(b => b.textContent).join("|"))) === "Home|Evaluate|My Runs|Account|Sign out (alice)");
    await p.evaluate(() => go("evaluate")); await until(p, () => !!document.querySelector("#catalog .mc"));
    await noOverflow(p, name + " evaluate"); await shot(p, `evaluate-${name}`);
    if (name === "desktop") {
      const cat = await p.evaluate(() => [...document.querySelectorAll("#catalog .mc")].map(c => c.textContent));
      check("the model catalog shows name, provider, MOCK/REAL and availability for each configured model", cat.length >= 1 && cat.every(c => /MOCK MODEL|REAL PROVIDER/.test(c) && /NOT CHECKED/.test(c)), cat.join(" || "));
      await click(p, "Check all models"); check("checking availability turns NOT CHECKED into AVAILABLE for the mock", await until(p, () => /AVAILABLE/.test(document.querySelector("#catalog").textContent)));
      await click(p, "How this evaluation works"); await until(p, () => document.querySelectorAll("#why .acc").length >= 5);
      const ex = await p.evaluate(() => document.querySelector("#why").textContent);
      check("the explainer shows both groups and all ten categories from the live definitions", ["jailbreak", "prompt injection", "instruction following", "data exfiltration", "policy bypass", "authentication", "authorization", "session isolation", "phase gating", "audit"].every(c => ex.includes(c)) && /HEURISTIC/.test(ex) && /DETERMINISTIC/.test(ex), ex.slice(0, 200));
      await p.evaluate(() => document.querySelector("#why .acc button").click()); await sleep(400);
      const open1 = await p.evaluate(() => document.querySelector("#why .acc").textContent);
      check("opening a category explains what is tested, why it matters, what Bayora checks and what PASS/FLAGGED/ERROR mean", /What is tested/.test(open1) && /Why it matters/.test(open1) && /What Bayora checks/.test(open1) && /FLAGGED/.test(open1) && /ERROR/.test(open1) && /not proof/.test(open1));
      await shot(p, "explainer-desktop");
    }
    await p.close();
  }
  console.log("== results, expandable probes, verification");
  const pr = await open(alice, 1280, 900); await sleep(300);
  await pr.evaluate(id => { go("runs"); }, run.run_id); await until(pr, () => document.querySelectorAll("tbody tr.clk").length === 1);
  await pr.evaluate(() => document.querySelector("tbody tr.clk").click()); await until(pr, () => document.querySelectorAll("tbody tr").length === 25);
  const rows = await pr.evaluate(() => ({ n: document.querySelectorAll("tbody tr").length, fl: document.querySelectorAll("tbody tr.fl").length, cards: document.querySelectorAll(".card").length }));
  check("results: 25 rows, 2 FLAGGED, summary cards and verification cards present", rows.n === 25 && rows.fl === 2 && rows.cards >= 8, JSON.stringify(rows));
  await pr.evaluate(() => document.querySelector("tbody tr.fl").click()); await sleep(400);
  const det = await pr.evaluate(() => (document.querySelector("tr.det") || {}).textContent || "");
  check("clicking a flagged probe expands it: HEURISTIC label, expected property, verdict, the model's reply, evidence", /HEURISTIC probe/.test(det) && /Expected:/.test(det) && /Verdict:/.test(det) && /MOCK-UNSAFE/.test(det) && /Evidence/.test(det), det.slice(0, 200));
  await shot(pr, "results-desktop");
  const ver = await pr.evaluate(() => document.body.textContent);
  check("verification shows audit chain, independent anchor and stored-results-vs-audit-log", /Audit chain at the end of the run/.test(ver) && /Independent anchor/.test(ver) && /Stored results vs audit log/.test(ver) && /Match/.test(ver));
  await pr.close();

  console.log("== account");
  const pa = await open(alice, 1280, 900); await sleep(300); await pa.evaluate(() => go("account")); await until(pa, () => !!document.querySelector("#dn"));
  await pa.type("#dn", "Alice Example"); await pa.type("#nn", "ali"); await pa.type("#em", "alice@example.org");
  await click(pa, "Save profile"); check("saving the profile confirms it", await until(pa, () => /Profile saved/.test(document.querySelector("#flash").textContent)));
  await shot(pa, "account-desktop");
  const note = await pa.evaluate(() => document.querySelector("#app").textContent);
  check("the email note says there is no verification or recovery", /does not send email, verify addresses or offer email password recovery/.test(note));
  await click(pa, "Preferences"); await pa.evaluate(() => { const c = document.getElementById("su"); c.checked = false }); await click(pa, "Save preferences");
  check("turning off 'show username' changes the navigation to the display name", await until(pa, () => /Sign out \(Alice Example\)/.test(document.querySelector("#nav").textContent)));
  await pa.close();

  console.log("== admin");
  for (const [name, w, h] of SIZES) {
    const p = await open(admin, w, h); await sleep(300);
    if (name === "desktop") check("admin navigation is Home, Evaluate, All Runs, Overview, Users, Account, Sign out", (await p.evaluate(() => [...document.querySelector("#nav").children].map(b => b.textContent).join("|"))) === "Home|Evaluate|All Runs|Overview|Users|Account|Sign out (admin1)");
    await p.evaluate(() => go("overview")); await until(p, () => document.querySelectorAll("#chain .blk").length > 0);
    await noOverflow(p, name + " overview"); await shot(p, `overview-${name}`);
    if (name === "desktop") {
      const n = await p.evaluate(() => document.querySelectorAll("#chain .blk").length);
      check("the audit chain strip shows real entries with sequence numbers and hashes", n >= 3 && /#\d+ /.test(await p.evaluate(() => document.querySelector("#chain").textContent)));
      await click(p, "Verify now"); check("Verify now returns the live chain and anchor state", await until(p, () => /CHAIN VERIFIED/.test(document.querySelector("#vres").textContent) && /ANCHOR|NO ANCHOR/.test(document.querySelector("#vres").textContent)));
    }
    await p.close();
  }
  check("no script or console errors in any page", errors.length === 0, errors.join(" | "));
  await browser.close();
  console.log(`\nResult: ${pass} passed, ${fail} failed`); process.exit(fail ? 1 : 0);
})().catch(e => { console.log("CRASH", e); process.exit(1) });
