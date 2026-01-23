document.addEventListener("DOMContentLoaded", () => {
  const el = (id) => document.getElementById(id);

  const ui = {
    btnScan: el("btnScan"),
    btnReset: el("btnReset"),
    status: el("status"),
    result: el("result"),
    verdictPill: el("verdictPill"),
    confidenceText: el("confidenceText"),
    summary: el("summary"),
    proceed: el("proceed"),
    settingsLink: el("settingsLink"),
    helpLink: el("helpLink"),
  };

  function setStatus(msg) {
    ui.status.textContent = msg || "";
  }

  function showResult(show) {
    ui.result.classList.toggle("hidden", !show);
  }

  function setVerdictPill(verdict) {
    ui.verdictPill.classList.remove("safe", "warn", "danger");
    ui.verdictPill.textContent = verdict || "—";

    if (verdict === "SAFE") ui.verdictPill.classList.add("safe");
    else if (verdict === "SUSPICIOUS") ui.verdictPill.classList.add("warn");
    else if (verdict === "DANGEROUS") ui.verdictPill.classList.add("danger");
    else ui.verdictPill.classList.add("warn");
  }

  function clampPct(x) {
    const n = Number(x);
    if (!Number.isFinite(n)) return null;
    return Math.max(0, Math.min(100, Math.round(n)));
  }

  function toUserVerdict(category) {
    const c = String(category || "").toUpperCase();
    if (c === "PHISHING" || c === "SCAM") return "DANGEROUS";
    if (c === "SUSPICIOUS" || c === "MISINFORMATION") return "SUSPICIOUS";
    return "SAFE";
  }

  function getProceedLine({ verdict, fused, ai, topProceed }) {
    if (topProceed) return String(topProceed).trim();
    if (ai && (ai.action || ai.proceed)) return String(ai.action || ai.proceed).trim();
    if (fused?.advice) return String(fused.advice).trim();

    if (verdict === "DANGEROUS") return "Close the page and do not enter credentials or download files.";
    if (verdict === "SUSPICIOUS") return "Avoid entering sensitive information until the source is verified.";
    return "Proceed normally but avoid sharing personal or financial data.";
  }

  function sendMessageWithTimeout(message, timeoutMs = 45000) {
    return new Promise((resolve, reject) => {
      const timer = setTimeout(() => reject(new Error("Scan timeout")), timeoutMs);

      chrome.runtime.sendMessage(message, (resp) => {
        clearTimeout(timer);
        const err = chrome.runtime.lastError;
        if (err) return reject(new Error(err.message));
        resolve(resp);
      });
    });
  }

  async function extractTextForScan(tabId) {
    const injection = await chrome.scripting.executeScript({
      target: { tabId },
      func: () => {
        const getText = (node) =>
          node ? (node.innerText || node.textContent || "").replace(/\s+/g, " ").trim() : "";

        const url = location.href;
        const host = location.hostname || "";
        const isWikipedia = /(^|\.)wikipedia\.org$/i.test(host);

        const bodyText = getText(document.body).slice(0, 3500);

        const hs = Array.from(document.querySelectorAll("h2, h3")).slice(0, 18);
        const sections = [];

        for (const h of hs) {
          const heading = getText(h).replace(/\[.*?\]$/g, "").trim();
          if (!heading) continue;

          let snippet = "";
          let n = h.nextElementSibling;
          let guard = 0;

          while (n && guard < 6 && snippet.length < 500) {
            const tag = (n.tagName || "").toLowerCase();
            if (["table", "nav", "aside"].includes(tag)) {
              n = n.nextElementSibling;
              guard++;
              continue;
            }

            const t = getText(n);
            if (t && t.length > 30) snippet += (snippet ? " " : "") + t;

            n = n.nextElementSibling;
            guard++;
          }

          snippet = snippet.replace(/\s+/g, " ").trim().slice(0, 500);
          sections.push({ heading, snippet });
        }

        const isMultiTopic = isWikipedia || sections.length >= 8;

        if (isMultiTopic && sections.length) {
          const title = document.title || "";
          const leadP = document.querySelector("p");
          const lead = getText(leadP).slice(0, 500);

          const parts = [];
          parts.push(`PAGE_TITLE: ${title}`);
          parts.push(`PAGE_URL: ${url}`);
          if (lead) parts.push(`LEAD_SNIPPET: ${lead}`);
          parts.push("SECTION_HEADINGS_AND_SNIPPETS:");

          for (const s of sections.slice(0, 12)) {
            const head = String(s.heading || "").trim();
            const snip = String(s.snippet || "").trim();
            if (!head) continue;
            parts.push(`- ${head}: ${snip || "(no snippet found)"}`);
          }

          return parts.join("\n").slice(0, 3500);
        }

        return bodyText;
      }
    });

    return injection?.[0]?.result || "";
  }

  function renderResponse(resp) {
    const r = resp?.result || {};
    const fused = r.fused || {};
    const ai = r.ai || null;

    const verdict = resp?.verdict || toUserVerdict(fused.category);
    setVerdictPill(verdict);

    const conf =
      resp?.confidence != null
        ? clampPct(resp.confidence)
        : ai?.score
        ? clampPct((Number(ai.score) / 10) * 100)
        : clampPct(100 - Number(fused.risk || 0));

    ui.confidenceText.textContent = conf != null ? `${conf}% confidence` : "";

    ui.summary.textContent = resp?.summary || ai?.summary || "Scan complete.";

    ui.proceed.textContent = getProceedLine({
      verdict,
      fused,
      ai,
      topProceed: resp?.proceed
    });

    showResult(true);
  }

  async function runScan() {
    ui.btnScan.disabled = true;
    setStatus("Scanning...");
    showResult(false);

    try {
      const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });

      if (!tab?.url || tab.url.startsWith("chrome://")) {
        throw new Error("Cannot scan this page.");
      }

      let pageText = "";
      try {
        pageText = await extractTextForScan(tab.id);
      } catch {
        pageText = "";
      }

      if ((!pageText || pageText.trim().length < 60) && !tab.url.startsWith("data:")) {
        setStatus("Page blocked or unreadable. Using URL scan fallback...");
        const resp = await sendMessageWithTimeout({ action: "deep_scan_url", url: tab.url }, 45000);
        if (!resp || !resp.success) throw new Error(resp?.feedback || "URL scan failed.");
        renderResponse(resp);
        setStatus("");
        return;
      }

      if (!pageText || pageText.trim().length < 20) {
        throw new Error("Could not extract readable text from this page.");
      }

      setStatus("Analyzing with SentinelAI...");
      const resp = await sendMessageWithTimeout({ action: "deep_scan", url: tab.url, text: pageText }, 45000);

      if (!resp || !resp.success) throw new Error(resp?.feedback || "Scan error.");
      renderResponse(resp);
      setStatus("");
    } catch (err) {
      setStatus(err?.message || String(err));
    } finally {
      ui.btnScan.disabled = false;
    }
  }

  ui.btnScan.addEventListener("click", runScan);

  ui.btnReset.addEventListener("click", () => {
    setStatus("");
    showResult(false);
    setVerdictPill("—");
    ui.confidenceText.textContent = "";
    ui.summary.textContent = "—";
    ui.proceed.textContent = "—";
  });

  ui.settingsLink?.addEventListener("click", async (e) => {
    e.preventDefault();
    if (chrome.runtime.openOptionsPage) chrome.runtime.openOptionsPage();
  });

  ui.helpLink?.addEventListener("click", (e) => {
    e.preventDefault();
    setStatus("Help: Open Settings → unlock with PIN → set OpenRouter key. Then run scans.");
    setTimeout(() => setStatus(""), 3500);
  });
});
