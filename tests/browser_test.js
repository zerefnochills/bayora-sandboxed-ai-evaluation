const chromium = require("@sparticuz/chromium").default || require("@sparticuz/chromium");
const puppeteer = require("puppeteer-core");
const BASE = process.env.BASE, BOOT = process.env.BOOT_CODE;
let pass = 0, fail = 0;
const check = (n, c, x = "") => { c ? pass++ : fail++; console.log((c ? "  PASS  " : "  FAIL  ") + n + (c ? "" : "  " + String(x).slice(0, 300))); };
const sleep = ms => new Promise(r => setTimeout(r, ms));
const api = async (m, p, tok, body) => { const r = await fetch(BASE + p, { method: m, headers: { ...(tok ? { Authorization: "Bearer " + tok } : {}), ...(body ? { "Content-Type": "application/json" } : {}) }, body: body ? JSON.stringify(body) : undefined }); let d = null; try { d = await r.json() } catch {} return { status: r.status, data: d } };

(async () => {
  console.log("== setup through the real API");
  const admin = (await api("POST", "/auth/bootstrap", null, { code: BOOT, username: "admin1", password: "Admin-pass-2026!" })).data.token;
  const run = (await api("POST", "/evaluations", admin, { suite_id: "builtin-core" })).data;
  for (let i = 0; i < 200; i++) { if ((await api("GET", "/evaluations/" + run.run_id, admin)).data.status !== "running") break; await sleep(100) }
  const browser = await puppeteer.launch({ executablePath: await chromium.executablePath(), args: [...chromium.args, "--no-sandbox"], headless: "shell" });
  const page = await browser.newPage(); await page.setViewport({ width: 1280, height: 900 });
  await page.evaluateOnNewDocument(t => { try { sessionStorage.setItem("bayora_token", t) } catch {} }, admin);
  const appErrors = []; page.on("pageerror", e => appErrors.push(String(e))); page.on("console", m => { if (m.type() === "error") appErrors.push(m.text()) });
  await page.goto(BASE + "/app", { waitUntil: "networkidle0" });
  console.log("== the printable report in a real browser (opened the way the app opens it)");
  const popupPromise = new Promise(res => browser.once("targetcreated", t => res(t)));
  const reportErrors = [];
  await page.evaluate(id => openReport(id), run.run_id);
  const target = await popupPromise; const rp = await target.page();
  rp.on("console", m => reportErrors.push(m.text())); const violations = [];
  await rp.evaluateOnNewDocument(() => document.addEventListener("securitypolicyviolation", e => (window.__v = (window.__v || []).concat([e.violatedDirective + " " + e.blockedURI]))));
  await sleep(1500); await rp.reload({ waitUntil: "load" }).catch(() => {});   // the blob URL is still valid; reload re-parses it under the same policy
  await sleep(500);
  const title = await rp.title();
  check("the report page opened and rendered", /Bayora report/.test(title), title);
  const hasBtn = await rp.$("#p") !== null; check("the report has its print button", hasBtn);
  await rp.evaluate(() => { window.__printed = 0; window.print = () => { window.__printed++ } });
  await rp.click("#p"); await sleep(200);
  const printed = await rp.evaluate(() => window.__printed);
  check("clicking 'Print or save as PDF' really calls window.print() (the handler script was allowed to run)", printed === 1, "printed=" + printed + " console=" + JSON.stringify(reportErrors).slice(0, 300));
  check("no Content Security Policy violation was reported in the report page", !reportErrors.some(t => /Content Security Policy|Refused to execute/i.test(t)), reportErrors.join(" | ").slice(0, 300));
  await browser.close();
  console.log(`\nResult: ${pass} passed, ${fail} failed`); process.exit(fail ? 1 : 0);
})().catch(e => { console.log("CRASH", e); process.exit(1) });
