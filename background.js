/* =========================
   SentinelAI - background.js (MV3 Service Worker)

   Progress:
   - Stage 2A: AI JSON verdict (category/score/summary/reason/action)
   - Stage 2B: Heuristics + Fusion
   - Stage 2C: Authority & impersonation detection
   - Stage 3: Production hardening (caching + de-dup)

   THIS version:
   ✅ 60-second scan result caching (url + text hash)
   ✅ In-flight de-duplication (avoid duplicate concurrent scans)
   ✅ Cache eviction (size cap)
   ✅ User-facing summary remains CLEAN (no "(Risk..., Verdict...)" appended)

   ========================= */

const SETTINGS_KEY = "sentinelai_settings_v1";

const DEFAULT_SETTINGS = {
  openrouterKey: "",
  primaryModel: "mistralai/mistral-7b-instruct",
  fallbackModels: [
    "meta-llama/llama-3.1-8b-instruct",
    "qwen/qwen-2.5-7b-instruct"
  ]
};

const YOUR_SITE_URL = "http://localhost";
const YOUR_APP_NAME = "SentinelAI Extension";
const OR_URL = "https://openrouter.ai/api/v1/chat/completions";

/* =========================
   Stage 3: caching
   ========================= */
const SCAN_CACHE_TTL_MS = 60_000;
const SCAN_CACHE_MAX = 120;

// key -> { ts, resp }
const scanCache = new Map();

// key -> Promise<resp>
const inflight = new Map();

function nowMs() { return Date.now(); }

function pruneCache() {
  const cutoff = nowMs() - SCAN_CACHE_TTL_MS;

  for (const [k, v] of scanCache.entries()) {
    if (!v || typeof v.ts !== "number" || v.ts < cutoff) scanCache.delete(k);
  }

  if (scanCache.size <= SCAN_CACHE_MAX) return;

  // Evict oldest
  const entries = Array.from(scanCache.entries());
  entries.sort((a, b) => (a[1]?.ts || 0) - (b[1]?.ts || 0));
  const toRemove = scanCache.size - SCAN_CACHE_MAX;
  for (let i = 0; i < toRemove; i++) {
    scanCache.delete(entries[i][0]);
  }
}

function stableUrl(url) {
  try {
    const u = new URL(url);
    u.hash = "";
    return u.toString();
  } catch {
    return String(url || "");
  }
}

// fast non-crypto hash for cache keys
function djb2Hash(str) {
  let h = 5381;
  const s = String(str || "");
  for (let i = 0; i < s.length; i++) {
    h = ((h << 5) + h) ^ s.charCodeAt(i);
  }
  return (h >>> 0).toString(16);
}

function makeCacheKey(url, text) {
  const u = stableUrl(url);
  const slice = String(text || "").slice(0, 1200);
  return `${u}|${djb2Hash(slice)}`;
}

/* =========================
   Settings cache
   ========================= */
let SETTINGS_CACHE = null;
let SETTINGS_CACHE_TS = 0;
const SETTINGS_CACHE_TTL_MS = 30_000;

console.log("🟢 SentinelAI service worker ready");

chrome.runtime.onInstalled.addListener(async () => {
  const s = await loadSettings();
  if (!s) {
    await saveSettings(DEFAULT_SETTINGS);
    SETTINGS_CACHE = DEFAULT_SETTINGS;
  }
});

chrome.runtime.onMessage.addListener((msg, sender, sendResponse) => {
  const action = String(msg?.action || "");

  if (action === "deep_scan") {
    deepScanStage2B({ url: String(msg.url || ""), text: String(msg.text || "") })
      .then(sendResponse)
      .catch((err) => {
        console.error("❌ deep_scan error:", err);
        sendResponse({ success: false, feedback: "Scan failed (internal error)." });
      });
    return true;
  }

  if (action === "deep_scan_url") {
    deepScanFromUrl({ url: String(msg.url || "") })
      .then(sendResponse)
      .catch((err) => {
        console.error("❌ deep_scan_url error:", err);
        sendResponse({ success: false, feedback: "URL scan failed (internal error)." });
      });
    return true;
  }

  if (action === "get_settings") {
    loadSettings().then((s) => sendResponse({ success: true, settings: sanitizeSettings(s) }));
    return true;
  }

  if (action === "set_settings") {
    const incoming = msg?.settings || {};
    saveSettings(mergeSettings(incoming))
      .then(async () => {
        const s = await loadSettings(true);
        sendResponse({ success: true, settings: sanitizeSettings(s) });
      })
      .catch((e) => {
        console.error("❌ set_settings error:", e);
        sendResponse({ success: false, feedback: "Failed to save settings." });
      });
    return true;
  }

  return false;
});

/* =========================
   Settings helpers
   ========================= */
function sanitizeSettings(s) {
  const key = String(s?.openrouterKey || "");
  return {
    primaryModel: String(s?.primaryModel || DEFAULT_SETTINGS.primaryModel),
    fallbackModels: Array.isArray(s?.fallbackModels) ? s.fallbackModels : DEFAULT_SETTINGS.fallbackModels,
    openrouterKeyPresent: key.trim().length > 10
  };
}

function mergeSettings(incoming) {
  const out = { ...DEFAULT_SETTINGS };

  if (typeof incoming.openrouterKey === "string") out.openrouterKey = incoming.openrouterKey.trim();
  if (typeof incoming.primaryModel === "string" && incoming.primaryModel.trim()) out.primaryModel = incoming.primaryModel.trim();
  if (Array.isArray(incoming.fallbackModels) && incoming.fallbackModels.length) out.fallbackModels = incoming.fallbackModels.map(String);

  return out;
}

async function loadSettings(force = false) {
  const t = nowMs();
  if (!force && SETTINGS_CACHE && (t - SETTINGS_CACHE_TS) < SETTINGS_CACHE_TTL_MS) return SETTINGS_CACHE;

  const data = await chrome.storage.local.get(SETTINGS_KEY);
  const s = data?.[SETTINGS_KEY];
  const merged = mergeSettings(s || {});
  SETTINGS_CACHE = merged;
  SETTINGS_CACHE_TS = t;
  return merged;
}

async function saveSettings(settings) {
  SETTINGS_CACHE = mergeSettings(settings);
  SETTINGS_CACHE_TS = nowMs();
  await chrome.storage.local.set({ [SETTINGS_KEY]: SETTINGS_CACHE });
}

function hasValidKey(key) {
  return typeof key === "string" && key.trim().length > 10;
}

/* =========================
   Background fetch pipeline
   ========================= */
async function deepScanFromUrl({ url }) {
  if (!url) return { success: false, feedback: "Missing URL for background scan." };

  if (url.startsWith("data:text/html,")) {
    try {
      const htmlPart = url.split("data:text/html,")[1] || "";
      const html = decodeURIComponent(htmlPart);
      const text = htmlToVisibleText(html).slice(0, 3500);
      if (!text || text.trim().length < 20) return { success: false, feedback: "Data URL text too short to analyze." };
      return deepScanStage2B({ url: "data://local-test", text });
    } catch {
      return { success: false, feedback: "Failed to decode data URL." };
    }
  }

  if (!/^https?:\/\//i.test(url)) return { success: false, feedback: "Invalid URL for background scan." };

  const fetched = await fetchPageText(url, 15000);
  if (!fetched.ok) return { success: false, feedback: fetched.error || "Could not fetch page content." };

  return deepScanStage2B({ url, text: fetched.text });
}

async function fetchPageText(url, timeoutMs) {
  const controller = new AbortController();
  const kill = setTimeout(() => controller.abort(), timeoutMs);

  try {
    const res = await fetch(url, {
      method: "GET",
      redirect: "follow",
      signal: controller.signal,
      headers: { Accept: "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8" }
    });

    const html = await res.text();

    if (!res.ok) return { ok: false, error: `Fetch failed (HTTP ${res.status}).` };
    if (!html || html.trim().length < 40) return { ok: false, error: "Fetched content was empty or too short." };

    const text = htmlToVisibleText(html).slice(0, 3500);
    if (!text || text.trim().length < 40) return { ok: false, error: "Could not extract readable text from fetched HTML." };

    return { ok: true, text };
  } catch (e) {
    if (e?.name === "AbortError") return { ok: false, error: "Fetch timed out." };
    return { ok: false, error: e?.message || "Network fetch error." };
  } finally {
    clearTimeout(kill);
  }
}

function htmlToVisibleText(html) {
  let s = String(html || "");
  s = s.replace(/<script[\s\S]*?>[\s\S]*?<\/script>/gi, " ");
  s = s.replace(/<style[\s\S]*?>[\s\S]*?<\/style>/gi, " ");
  s = s.replace(/<noscript[\s\S]*?>[\s\S]*?<\/noscript>/gi, " ");
  s = s.replace(/<\/?[^>]+>/g, " ");

  s = s
    .replaceAll("&nbsp;", " ")
    .replaceAll("&amp;", "&")
    .replaceAll("&lt;", "<")
    .replaceAll("&gt;", ">")
    .replaceAll("&quot;", "\"")
    .replaceAll("&#39;", "'");

  return s.replace(/\s+/g, " ").trim();
}

/* =========================
   Stage 2B + Stage 3 cache wrapper
   ========================= */
async function deepScanStage2B({ url, text }) {
  pruneCache();

  const key = makeCacheKey(url, text);

  // Cache hit
  const cached = scanCache.get(key);
  if (cached && (nowMs() - cached.ts) < SCAN_CACHE_TTL_MS && cached.resp?.success) {
    return { ...cached.resp, cacheHit: true };
  }

  // In-flight de-dup
  if (inflight.has(key)) {
    return inflight.get(key);
  }

  const p = (async () => {
    const heur = computeHeuristics({ url, text });
    const settings = await loadSettings();
    const apiKey = String(settings.openrouterKey || "");

    let ai = null;
    if (hasValidKey(apiKey)) {
      const aiResp = await analyzeContentStage2A(text, settings);
      if (aiResp?.success && aiResp.result) ai = aiResp.result;
    }

    const fused = fuseScores({ heur, ai });

    const verdict =
      fused.category === "SAFE" ? "SAFE" :
      (fused.category === "SUSPICIOUS" || fused.category === "MISINFORMATION") ? "SUSPICIOUS" :
      "DANGEROUS";

    const confidence = computeConfidence({ fused, heur, ai });
    const summary = buildUserSummary({ ai, verdict });
    const proceed = buildProceed({ ai, fused, verdict });

    const resp = {
      success: true,
      verdict,
      confidence,
      summary,
      proceed,
      result: { url: stableUrl(url), heuristics: heur, ai, fused }
    };

    scanCache.set(key, { ts: nowMs(), resp });
    pruneCache();
    return resp;
  })();

  inflight.set(key, p);

  try {
    return await p;
  } finally {
    inflight.delete(key);
  }
}

function computeConfidence({ fused, heur, ai }) {
  let c = 100 - Math.min(100, Math.max(0, Number(fused.risk || 0)));

  if (heur?.context?.hasHardTrap && fused.category !== "SAFE") c = Math.max(c, 90);

  if (ai?.category) {
    const aiCat = String(ai.category).toUpperCase();
    const fusedCat = String(fused.category).toUpperCase();
    const agree = (aiCat === "SAFE" && fusedCat === "SAFE") || (aiCat !== "SAFE" && fusedCat !== "SAFE");
    c = agree ? Math.min(100, c + 8) : Math.max(55, c - 10);
  }

  return Math.max(0, Math.min(100, Math.round(c)));
}

function buildUserSummary({ ai, verdict }) {
  const s = String(ai?.summary || "").trim();
  if (s) return s;

  if (verdict === "DANGEROUS") return "This page shows patterns commonly linked to scams or phishing.";
  if (verdict === "SUSPICIOUS") return "This page contains signals that need extra verification.";
  return "This page looks informational with no strong risk signals detected.";
}

function buildProceed({ ai, fused, verdict }) {
  const action = String(ai?.action || "").trim();
  if (action) return action;
  if (fused?.advice) return String(fused.advice).trim();

  if (verdict === "DANGEROUS") return "Close the page and do not enter credentials or download files.";
  if (verdict === "SUSPICIOUS") return "Avoid entering sensitive information until the source is verified.";
  return "Proceed normally but avoid sharing personal or financial data.";
}

/* =========================
   Stage 2C: Authority & impersonation heuristics
   ========================= */
function getHost(url) {
  try { return new URL(url).hostname.toLowerCase(); } catch { return ""; }
}

function isTrustedGovDomain(host) {
  return host.endsWith(".gov.in") || host.endsWith(".nic.in");
}

const AUTH_BRANDS = [
  "google", "gmail", "youtube",
  "facebook", "instagram", "whatsapp",
  "sbi", "state bank of india", "hdfc", "icici", "axis",
  "paytm", "phonepe", "gpay", "google pay", "upi", "bhim",
  "uidai", "aadhaar", "aadhar", "pan", "income tax", "gst", "irctc",
  "mahadbt"
];

function normalizeForMatch(s) {
  return String(s || "").toLowerCase().replace(/[^a-z0-9]/g, "");
}

function etldPlus1(host) {
  const parts = String(host || "").split(".").filter(Boolean);
  if (parts.length < 2) return host || "";
  return parts.slice(-2).join(".");
}

function authorityImpersonationHeuristics({ host, textLower, trustedGov }) {
  let addRisk = 0;
  const signals = [];
  const domainKey = normalizeForMatch(host);

  for (const brand of AUTH_BRANDS) {
    if (textLower.includes(brand)) {
      const brandKey = normalizeForMatch(brand);
      if (brandKey && !domainKey.includes(brandKey)) {
        addRisk += 22;
        signals.push({
          id: "brand_domain_mismatch",
          weight: 22,
          label: `Brand "${brand}" mentioned but domain mismatch (${etldPlus1(host)})`
        });
        break;
      }
    }
  }

  const govtClaim =
    textLower.includes("gov.in") ||
    textLower.includes("government") ||
    textLower.includes("official portal") ||
    textLower.includes("national portal") ||
    textLower.includes("ministry");

  if (govtClaim && !trustedGov) {
    addRisk += 18;
    signals.push({
      id: "fake_gov_claim",
      weight: 18,
      label: "Government/official claims on a non-government domain"
    });
  }

  const kycUrgency =
    (textLower.includes("kyc") || textLower.includes("re-kyc")) &&
    (textLower.includes("urgent") || textLower.includes("immediately") || textLower.includes("within 24 hours"));

  if (kycUrgency) {
    addRisk += 16;
    signals.push({
      id: "kyc_urgency_trap",
      weight: 16,
      label: "Urgent KYC update pressure (common scam pattern)"
    });
  }

  const helplineTrap =
    (textLower.includes("helpline") || textLower.includes("customer care") || textLower.includes("call now")) &&
    (textLower.includes("+91") || /\b\d{10}\b/.test(textLower));

  if (helplineTrap) {
    addRisk += 14;
    signals.push({
      id: "helpline_trap",
      weight: 14,
      label: "Suspicious helpline/customer-care bait pattern"
    });
  }

  return { addRisk, signals };
}

/* =========================
   Heuristic engine
   ========================= */
function computeHeuristics({ url, text }) {
  const host = getHost(url);
  const textLower = String(text || "").toLowerCase();

  const allSignals = [];
  let risk = 0;

  function addSignal(id, weight, label) {
    allSignals.push({ id, weight, label });
    risk += weight;
  }

  const trustedGov = isTrustedGovDomain(host);

  if (url.startsWith("http://")) addSignal("http", 12, "Uses HTTP instead of HTTPS");
  if (url.includes("@")) addSignal("at_symbol", 10, "URL contains '@' (often used in redirect tricks)");
  if (url.length > 120) addSignal("long_url", 8, "URL is unusually long (possible obfuscation)");
  if (host.includes("xn--")) addSignal("punycode", 14, "Possible lookalike domain (punycode)");

  const credWords = ["password", "otp", "pin", "cvv", "bank account", "netbanking", "login to continue", "verify your account"];
  if (credWords.some(w => textLower.includes(w))) {
    addSignal("credential_trap", 22, "Credential capture pattern (password/OTP/CVV/PIN) detected");
  }

  const urgentWords = ["urgent", "immediately", "within 24 hours", "account will be suspended", "limited time"];
  if (urgentWords.some(w => textLower.includes(w))) {
    addSignal("urgent", 10, "Urgency pressure language detected");
  }

  const downloadWords = ["download now", "install now", "enable notifications", "allow notifications"];
  if (downloadWords.some(w => textLower.includes(w))) {
    addSignal("download_trap", 14, "Aggressive download/notification push pattern detected");
  }

  const piracyWords = ["watch free", "download hd", "streaming free", "telegram channel", "tamilrockers", "filmywap"];
  if (piracyWords.some(w => textLower.includes(w))) {
    addSignal("piracy", 16, "Piracy-style streaming/download indicators found");
  }

  const eduWords = ["wikipedia", "encyclopedia", "research", "paper", "journal", "university", "documentation", "docs"];
  const isEducationalOrReference = eduWords.some(w => textLower.includes(w)) || host.includes("wikipedia.org");

  const stage2c = authorityImpersonationHeuristics({ host, textLower, trustedGov });
  for (const s of stage2c.signals) addSignal(s.id, s.weight, s.label);

  if (isEducationalOrReference) addSignal("context_dampener", -12, "Informational/security context reduces risk");

  risk = Math.max(0, Math.min(100, Math.round(risk)));

  const topSignals = allSignals
    .slice()
    .sort((a, b) => Math.abs(b.weight) - Math.abs(a.weight))
    .slice(0, 5);

  return {
    risk,
    topSignals,
    allSignals,
    context: {
      trustedGov,
      isEducationalOrReference,
      isReputationCheckerContext: false,
      hasHardTrap: allSignals.some(s => s.id === "credential_trap" || s.id === "download_trap")
    }
  };
}

/* =========================
   Fusion
   ========================= */
function fuseScores({ heur, ai }) {
  const heurRisk = heur?.risk ?? 0;

  const aiRisk =
    ai && typeof ai.score === "number"
      ? Math.max(0, Math.min(100, Math.round((10 - ai.score) * 10)))
      : null;

  const fusedRisk =
    aiRisk === null ? heurRisk : Math.max(0, Math.min(100, Math.round(0.65 * heurRisk + 0.35 * aiRisk)));

  let category = "SAFE";
  if (fusedRisk >= 80) category = "PHISHING";
  else if (fusedRisk >= 60) category = "SCAM";
  else if (fusedRisk >= 40) category = "SUSPICIOUS";

  if (heur?.context?.trustedGov && category === "PHISHING") category = "SUSPICIOUS";

  const hasPiracy = heur?.allSignals?.some((s) => s.id === "piracy");
  if (hasPiracy && category === "SAFE") category = "SUSPICIOUS";

  if (ai?.category === "MISINFORMATION" && category !== "PHISHING") category = "MISINFORMATION";

  const advice =
    category === "SAFE"
      ? "Proceed normally, but avoid sharing sensitive information."
      : category === "SUSPICIOUS"
      ? "Avoid entering sensitive info; verify the site and links first."
      : category === "SCAM"
      ? "Do not send money or personal info; use official channels."
      : category === "PHISHING"
      ? "Do not enter credentials; close the page and report it."
      : "Cross-check claims with reliable sources before sharing.";

  return { category, risk: fusedRisk, aiRisk, heurRisk, advice };
}

/* =========================
   Stage 2A (AI)
   ========================= */
async function analyzeContentStage2A(text, settings) {
  const key = String(settings?.openrouterKey || "");
  if (!hasValidKey(key)) return { success: false, feedback: "AI disabled: set OpenRouter API key in Settings." };

  const trimmed = String(text || "").replace(/\s+/g, " ").trim().slice(0, 3500);

  const system =
    "You are SentinelAI, a security-focused web risk analyst for a browser extension. " +
    "Be concise. Do not hallucinate. Base everything strictly on the provided text. " +
    "If the text describes a hub page with multiple sections/headings, summarize it as a multi-topic overview.";

  const user =
    "Return ONLY valid minified JSON. No markdown. No extra text.\n" +
    "Schema:\n" +
    "{\"category\":\"SAFE|SUSPICIOUS|SCAM|PHISHING|MISINFORMATION\",\"score\":1-10," +
    "\"summary\":\"2 sentences max\",\"reason\":\"1 sentence\",\"action\":\"1 sentence\"}\n\n" +
    "Rules:\n" +
    "- score: 10 = highly authentic/low risk, 1 = very risky.\n" +
    "- Never invent specific events/topics not clearly present.\n" +
    "- If input contains SECTION_HEADINGS_AND_SNIPPETS, write an overview summary mentioning multiple sections and 3-5 themes.\n" +
    "- summary MUST NOT include text like \"Risk:\" or \"Verdict:\".\n" +
    "- action MUST be security guidance, one sentence.\n" +
    "- action MUST NOT say: \"navigate\", \"visit for information\", \"use this site\", \"go to the homepage\".\n\n" +
    "TEXT:\n" + trimmed;

  const models = [
    String(settings.primaryModel || DEFAULT_SETTINGS.primaryModel),
    ...(settings.fallbackModels || DEFAULT_SETTINGS.fallbackModels)
  ];
  const provider = { sort: "throughput", allow_fallbacks: true };

  const data = await openRouterChat({
    key,
    models,
    provider,
    messages: [
      { role: "system", content: system },
      { role: "user", content: user }
    ],
    max_tokens: 420,
    temperature: 0.2,
    timeoutMs: 40000
  });

  const raw = extractChatText(data);
  if (!raw) return { success: false, feedback: extractErrorMessage(data) || "No AI output." };

  const parsed = safeParseJson(raw);
  if (!parsed) return { success: false, feedback: "AI returned invalid JSON." };

  const allowed = new Set(["SAFE", "SUSPICIOUS", "SCAM", "PHISHING", "MISINFORMATION"]);
  const category = String(parsed.category || "SUSPICIOUS").toUpperCase();
  const finalCategory = allowed.has(category) ? category : "SUSPICIOUS";

  let score = Number(parsed.score);
  if (!Number.isFinite(score)) score = 5;
  score = Math.max(1, Math.min(10, Math.round(score)));

  let summary = String(parsed.summary || "").trim();
  summary = summary
    .replace(/\(.*?risk.*?\)/ig, "")
    .replace(/\bRisk:\s*\d+\/100\b/ig, "")
    .replace(/\bVerdict:\s*\w+\b/ig, "")
    .trim();

  let action = String(parsed.action || "").trim();
  const badAction = /navigate|visit|go to|homepage|use this site/i.test(action);

  if (!action || badAction) {
    if (finalCategory === "PHISHING" || finalCategory === "SCAM") {
      action = "Do not enter credentials or download anything; close the page and use official sources.";
    } else if (finalCategory === "SUSPICIOUS" || finalCategory === "MISINFORMATION") {
      action = "Avoid sharing sensitive information; verify the source and domain before trusting it.";
    } else {
      action = "Proceed normally, but verify external links before entering personal information.";
    }
  }

  return {
    success: true,
    result: {
      category: finalCategory,
      score,
      summary,
      reason: String(parsed.reason || "").trim(),
      action
    }
  };
}

/* =========================
   OpenRouter wrapper
   ========================= */
async function openRouterChat({ key, models, provider, messages, max_tokens, temperature, timeoutMs }) {
  const controller = new AbortController();
  const kill = setTimeout(() => controller.abort(), timeoutMs || 40000);

  try {
    const payload = {
      model: models[0],
      models,
      provider,
      messages,
      max_tokens: max_tokens ?? 420,
      temperature: temperature ?? 0.2
    };

    const res = await fetch(OR_URL, {
      method: "POST",
      signal: controller.signal,
      headers: {
        "Content-Type": "application/json",
        "Authorization": `Bearer ${key}`,
        "HTTP-Referer": YOUR_SITE_URL,
        "X-Title": YOUR_APP_NAME
      },
      body: JSON.stringify(payload)
    });

    const json = await res.json().catch(() => ({}));
    if (!res.ok) return { error: true, status: res.status, json };
    return json;
  } catch (e) {
    if (e?.name === "AbortError") return { error: true, timeout: true };
    return { error: true, message: e?.message || "OpenRouter request failed." };
  } finally {
    clearTimeout(kill);
  }
}

/* =========================
   Helpers
   ========================= */
function extractChatText(data) {
  try {
    const msg = data?.choices?.[0]?.message?.content;
    return typeof msg === "string" ? msg.trim() : "";
  } catch {
    return "";
  }
}

function extractErrorMessage(data) {
  try {
    if (data?.timeout) return "AI timed out.";
    if (data?.error && data?.json?.error?.message) return String(data.json.error.message);
    if (data?.error && data?.message) return String(data.message);
    return "";
  } catch {
    return "";
  }
}

function safeParseJson(s) {
  try {
    return JSON.parse(String(s || "").trim());
  } catch {
    return null;
  }
}
