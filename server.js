/**
 * PackageGuard — x402-gated agent-to-agent package-safety tool.
 * Rebuilt for mainnet + Coinbase CDP facilitator (so it is cataloged in the
 * x402 Bazaar that agents query), under an account Dan controls.
 *
 * Endpoints:
 *   GET  /health           free
 *   POST /check            x402-gated ($0.005 USDC, Base mainnet) — the paid path
 *   POST /mcp              MCP JSON-RPC: initialize + tools/list (free discovery)
 *
 * Config via env:
 *   PORT, RECEIVE_ADDRESS, NETWORK, PRICE,
 *   CDP_API_KEY_ID + CDP_API_KEY_SECRET  (enables CDP facilitator -> Bazaar)
 */
require("dotenv").config();
const express = require("express");
const axios = require("axios");
const levenshtein = require("fast-levenshtein");
const { paymentMiddleware, x402ResourceServer } = require("@x402/express");
const { HTTPFacilitatorClient } = require("@x402/core/server");
const { ExactEvmScheme } = require("@x402/evm/exact/server");
const { createFacilitatorConfig } = require("@coinbase/x402");

const app = express();
app.use(express.json());

const PORT = process.env.PORT || 4021;
const NETWORK = process.env.NETWORK || "eip155:8453"; // Base mainnet
const PRICE = process.env.PRICE || "$0.005";
// Dan's Coinbase wallet (verified on-chain payee). Override via env if needed.
const RECEIVE_ADDRESS = process.env.RECEIVE_ADDRESS || "0x0a512951Ac25B66fb6379295621E3A9486cdD504";

// ---- Facilitator: CDP (Bazaar-indexed) when keys present, else public fallback ----
const CDP_ID = process.env.CDP_API_KEY_ID;
const CDP_SECRET = process.env.CDP_API_KEY_SECRET;
const usingCdp = Boolean(CDP_ID && CDP_SECRET);
const facilitatorConfig = usingCdp
  ? createFacilitatorConfig(CDP_ID, CDP_SECRET)
  : { url: "https://x402.org/facilitator" };
const facilitatorClient = new HTTPFacilitatorClient(facilitatorConfig);
const resourceServer = new x402ResourceServer(facilitatorClient).register(
  NETWORK,
  new ExactEvmScheme(),
);

// ---------------- safety-check logic ----------------
const POPULAR_NPM = [
  "react","react-dom","express","lodash","axios","next","vue","typescript","webpack",
  "eslint","chalk","commander","dotenv","moment","jquery","request","async","underscore",
  "classnames","prop-types","redux","babel-core","jest","mocha","chai","socket.io",
  "mongoose","sequelize","cors","body-parser","uuid","yargs","inquirer","colors","debug",
];
const POPULAR_PYPI = [
  "requests","numpy","pandas","flask","django","boto3","urllib3","pytest","setuptools",
  "pyyaml","click","cryptography","certifi","six","python-dateutil","pip","wheel","jinja2",
  "sqlalchemy","beautifulsoup4","pillow","scipy","matplotlib","scikit-learn",
];
function typosquatRisk(name, ecosystem) {
  const pool = ecosystem === "pypi" ? POPULAR_PYPI : POPULAR_NPM;
  let closest = null, minDist = Infinity;
  for (const c of pool) {
    if (c === name) continue;
    const d = levenshtein.get(name, c);
    if (d < minDist) { minDist = d; closest = c; }
  }
  const risky = minDist > 0 && minDist <= 2 && name.length > 3;
  return { risky, closest, distance: minDist === Infinity ? null : minDist };
}
async function checkNpmRegistry(name) {
  try {
    const res = await axios.get(`https://registry.npmjs.org/${encodeURIComponent(name)}`, { timeout: 8000, validateStatus: () => true });
    if (res.status === 404) return { exists: false };
    const data = res.data;
    return { exists: true, versionCount: Object.keys(data.versions || {}).length,
      firstPublished: data.time && data.time.created, lastPublished: data.time && data.time.modified,
      latestVersion: data["dist-tags"] && data["dist-tags"].latest, maintainerCount: (data.maintainers || []).length };
  } catch { return { exists: null, error: "registry_lookup_failed" }; }
}
async function checkPyPiRegistry(name) {
  try {
    const res = await axios.get(`https://pypi.org/pypi/${encodeURIComponent(name)}/json`, { timeout: 8000, validateStatus: () => true });
    if (res.status === 404) return { exists: false };
    const data = res.data, info = data.info || {};
    let firstPublished = null;
    for (const rv of Object.values(data.releases || {})) for (const f of rv) if (!firstPublished || f.upload_time < firstPublished) firstPublished = f.upload_time;
    return { exists: true, versionCount: Object.keys(data.releases || {}).length, firstPublished, latestVersion: info.version, author: info.author || null };
  } catch { return { exists: null, error: "registry_lookup_failed" }; }
}
async function checkOsv(name, ecosystem) {
  try {
    const res = await axios.post("https://api.osv.dev/v1/query", { package: { name, ecosystem: ecosystem === "pypi" ? "PyPI" : "npm" } }, { timeout: 8000, validateStatus: () => true });
    if (res.status !== 200) return { checked: false };
    const vulns = res.data.vulns || [];
    return { checked: true, vulnerabilityCount: vulns.length, vulnerabilities: vulns.slice(0,5).map(v => ({ id: v.id, summary: v.summary || null, severity: (v.severity && v.severity[0] && v.severity[0].score) || null })) };
  } catch { return { checked: false, error: "osv_lookup_failed" }; }
}
function daysSince(s){ if(!s) return null; const d=new Date(s); return isNaN(d.getTime())?null:Math.floor((Date.now()-d.getTime())/86400000); }
async function runSafetyCheck(ecosystem, name) {
  const eco = ecosystem === "pypi" ? "pypi" : "npm";
  const [registry, osv] = await Promise.all([ eco==="pypi"?checkPyPiRegistry(name):checkNpmRegistry(name), checkOsv(name, eco) ]);
  const typosquat = typosquatRisk(name, eco);
  const flags = []; let score = 100;
  if (registry.exists === false) { flags.push("package_does_not_exist_in_registry"); score -= 60; }
  if (typosquat.risky) { flags.push(`possible_typosquat_of_${typosquat.closest}`); score -= 35; }
  if (osv.checked && osv.vulnerabilityCount > 0) { flags.push(`${osv.vulnerabilityCount}_known_vulnerabilities`); score -= Math.min(40, osv.vulnerabilityCount*10); }
  const ageDays = registry.firstPublished ? daysSince(registry.firstPublished) : null;
  if (ageDays !== null && ageDays < 14) { flags.push("very_new_package_under_14_days_old"); score -= 20; }
  if (registry.exists && registry.versionCount === 1 && ageDays !== null && ageDays < 30) { flags.push("single_version_recently_published"); score -= 10; }
  score = Math.max(0, Math.min(100, score));
  const verdict = score >= 80 ? "safe" : score >= 50 ? "caution" : "unsafe";
  return { ecosystem: eco, package: name, verdict, safetyScore: score, flags, evidence: { registry, knownVulnerabilities: osv, typosquat, ageDays }, checkedAt: new Date().toISOString() };
}

// ---- upgraded agent-facing metadata ----
const TOOL_DESCRIPTION = "Vet an npm or PyPI package for supply-chain risk BEFORE installing it or adding it as a dependency. Checks that the package exists on the registry, known CVEs (OSV.dev), typosquatting against popular packages, and suspicious newness. Returns verdict (safe/caution/unsafe), safetyScore (0-100), and flags. Call before running npm install / pip install or editing package.json / requirements.txt. $0.005 USDC per call via x402 — no API key, no signup.";
const TOOL_TAGS = ["security","npm","pypi","supply-chain","typosquat","cve","vulnerability","dependency","malware","slopsquatting"];
const OUTPUT_SCHEMA = { type:"object", properties:{ ecosystem:{type:"string",enum:["npm","pypi"]}, package:{type:"string"}, verdict:{type:"string",enum:["safe","caution","unsafe"]}, safetyScore:{type:"number"}, flags:{type:"array",items:{type:"string"}} }, required:["ecosystem","package","verdict","safetyScore","flags"] };
const INPUT_SCHEMA = { type:"object", properties:{ ecosystem:{type:"string",enum:["npm","pypi"],description:"Package ecosystem to check"}, name:{type:"string",description:"Exact package name to check for safety before installing"} }, required:["ecosystem","name"], additionalProperties:false };

app.get("/health", (req,res)=> res.json({ ok:true, service:"packageguard", version:"2.0.0", network:NETWORK, facilitator: usingCdp?"cdp":"fallback" }));

// ---- MCP discovery (unpaid): initialize + tools/list ----
app.post("/mcp", (req, res, next) => {
  const { method, id } = req.body || {};
  if (method === "initialize") {
    return res.json({ jsonrpc:"2.0", id, result:{ protocolVersion:"2024-11-05", capabilities:{ tools:{} }, serverInfo:{ name:"PackageGuard", version:"2.0.0" } } });
  }
  if (method === "tools/list") {
    return res.json({ jsonrpc:"2.0", id, result:{ tools:[{ name:"check_package_safety", description:TOOL_DESCRIPTION, inputSchema:INPUT_SCHEMA, outputSchema:OUTPUT_SCHEMA, annotations:{ readOnlyHint:true, destructiveHint:false, idempotentHint:true, openWorldHint:true } }] } });
  }
  // tools/call is a PAID action — handled after the x402 middleware below
  return next();
});

// ---- x402 payment gate ----
app.use(paymentMiddleware({
  "POST /check": {
    accepts: [{ scheme:"exact", price:PRICE, network:NETWORK, payTo:RECEIVE_ADDRESS }],
    description: TOOL_DESCRIPTION,
    mimeType: "application/json",
    outputSchema: OUTPUT_SCHEMA,
  },
}, resourceServer));

app.post("/check", async (req,res)=>{
  const { ecosystem, name } = req.body || {};
  if (!name || typeof name !== "string") return res.status(400).json({ error:"missing_required_field", field:"name" });
  res.json(await runSafetyCheck(ecosystem, name.trim()));
});

if (require.main === module) {
  app.listen(PORT, ()=>{ console.log(`PackageGuard v2 on :${PORT} network=${NETWORK} facilitator=${usingCdp?"cdp":"fallback"} payTo=${RECEIVE_ADDRESS}`); });
}
module.exports = { app, runSafetyCheck, typosquatRisk };
