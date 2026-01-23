document.addEventListener("DOMContentLoaded", async () => {
  const el = (id) => document.getElementById(id);

  const ui = {
    lockState: el("lockState"),
    firstTime: el("firstTime"),
    unlockSection: el("unlockSection"),
    newPin: el("newPin"),
    newPin2: el("newPin2"),
    setPinBtn: el("setPinBtn"),
    pin: el("pin"),
    unlockBtn: el("unlockBtn"),
    lockBtn: el("lockBtn"),
    status: el("status"),

    keyState: el("keyState"),
    apiKey: el("apiKey"),
    primaryModel: el("primaryModel"),
    fallbackModels: el("fallbackModels"),
    saveBtn: el("saveBtn"),
    clearBtn: el("clearBtn"),
    testBtn: el("testBtn"),
    sstatus: el("sstatus"),
  };

  const PIN_STORAGE_KEY = "sentinelai_admin_pin_v1"; // {saltB64, hashB64}
  let unlocked = false;

  function setStatus(msg) { ui.status.textContent = msg || ""; }
  function setSStatus(msg) { ui.sstatus.textContent = msg || ""; }

  function setLockState(isUnlocked) {
    unlocked = !!isUnlocked;
    ui.lockState.textContent = unlocked ? "Unlocked" : "Locked";
    ui.lockState.className = "pill " + (unlocked ? "ok" : "bad");

    const disabled = !unlocked;
    ui.apiKey.disabled = disabled;
    ui.primaryModel.disabled = disabled;
    ui.fallbackModels.disabled = disabled;
    ui.saveBtn.disabled = disabled;
    ui.clearBtn.disabled = disabled;
    ui.testBtn.disabled = disabled;

    if (disabled) {
      ui.apiKey.value = "";
      setSStatus("");
      ui.keyState.textContent = "Hidden";
      ui.keyState.className = "pill bad";
    }
  }

  function sendMessage(message) {
    return new Promise((resolve, reject) => {
      chrome.runtime.sendMessage(message, (resp) => {
        const err = chrome.runtime.lastError;
        if (err) return reject(new Error(err.message));
        resolve(resp);
      });
    });
  }

  // ---- crypto helpers (SHA-256) ----
  function toB64(bytes) {
    let s = "";
    bytes.forEach((b) => (s += String.fromCharCode(b)));
    return btoa(s);
  }

  function fromB64(b64) {
    const bin = atob(b64);
    const bytes = new Uint8Array(bin.length);
    for (let i = 0; i < bin.length; i++) bytes[i] = bin.charCodeAt(i);
    return bytes;
  }

  async function sha256(bytes) {
    const buf = await crypto.subtle.digest("SHA-256", bytes);
    return new Uint8Array(buf);
  }

  async function hashPin(pin, saltBytes) {
    const enc = new TextEncoder();
    const pinBytes = enc.encode(String(pin));
    const combined = new Uint8Array(saltBytes.length + pinBytes.length);
    combined.set(saltBytes, 0);
    combined.set(pinBytes, saltBytes.length);
    return sha256(combined);
  }

  async function getStoredPinRecord() {
    const data = await chrome.storage.local.get(PIN_STORAGE_KEY);
    return data?.[PIN_STORAGE_KEY] || null;
  }

  async function setStoredPinRecord(rec) {
    await chrome.storage.local.set({ [PIN_STORAGE_KEY]: rec });
  }

  async function pinExists() {
    const rec = await getStoredPinRecord();
    return !!(rec && rec.saltB64 && rec.hashB64);
  }

  async function verifyPin(pin) {
    const rec = await getStoredPinRecord();
    if (!rec?.saltB64 || !rec?.hashB64) return false;

    const salt = fromB64(rec.saltB64);
    const expected = fromB64(rec.hashB64);
    const actual = await hashPin(pin, salt);

    if (actual.length !== expected.length) return false;
    let same = 0;
    for (let i = 0; i < actual.length; i++) same |= actual[i] ^ expected[i];
    return same === 0;
  }

  async function setPin(pin) {
    const salt = crypto.getRandomValues(new Uint8Array(16));
    const h = await hashPin(pin, salt);
    await setStoredPinRecord({ saltB64: toB64(salt), hashB64: toB64(h) });
  }

  async function loadSettingsLocked() {
    const resp = await sendMessage({ action: "get_settings" });
    const s = resp?.settings || {};
    ui.primaryModel.value = s.primaryModel || "mistralai/mistral-7b-instruct";
    ui.fallbackModels.value = Array.isArray(s.fallbackModels) ? s.fallbackModels.join("\n") : "";
  }

  async function saveSettings() {
    const key = String(ui.apiKey.value || "").trim();
    const primaryModel = String(ui.primaryModel.value || "").trim() || "mistralai/mistral-7b-instruct";
    const fallbackModels = String(ui.fallbackModels.value || "")
      .split("\n")
      .map((x) => x.trim())
      .filter(Boolean);

    const resp = await sendMessage({
      action: "set_settings",
      settings: { openrouterKey: key, primaryModel, fallbackModels }
    });

    if (!resp?.success) throw new Error(resp?.feedback || "Save failed.");

    ui.apiKey.value = "";
    ui.keyState.textContent = resp.settings?.openrouterKeyPresent ? "Set" : "Not set";
    ui.keyState.className = "pill " + (resp.settings?.openrouterKeyPresent ? "ok" : "bad");

    setSStatus("Saved.");
    setTimeout(() => setSStatus(""), 2000);
  }

  async function clearKey() {
    const resp = await sendMessage({ action: "set_settings", settings: { openrouterKey: "" } });
    if (!resp?.success) throw new Error(resp?.feedback || "Clear failed.");

    ui.apiKey.value = "";
    ui.keyState.textContent = "Not set";
    ui.keyState.className = "pill bad";

    setSStatus("Key cleared.");
    setTimeout(() => setSStatus(""), 2000);
  }

  async function testConnection() {
    setSStatus("Testing...");
    const resp = await sendMessage({
      action: "deep_scan",
      url: "https://example.com",
      text: "PAGE_TITLE: Example Domain\nSECTION_HEADINGS_AND_SNIPPETS:\n- Example Domain: This domain is for use in illustrative examples in documents."
    });

    if (!resp?.success) {
      setSStatus(resp?.feedback || "Test failed.");
      return;
    }
    setSStatus(`OK: ${resp.verdict} (${resp.confidence}% confidence)`);
  }

  async function init() {
    setLockState(false);
    await loadSettingsLocked();

    const exists = await pinExists();
    ui.firstTime.classList.toggle("hidden", exists);
    ui.unlockSection.classList.toggle("hidden", !exists);

    setStatus(exists ? "Locked. Enter Admin PIN to unlock settings." : "First-time setup: Create an Admin PIN.");
  }

  ui.setPinBtn.addEventListener("click", async () => {
    try {
      const p1 = String(ui.newPin.value || "").trim();
      const p2 = String(ui.newPin2.value || "").trim();

      if (!/^\d{4,}$/.test(p1)) throw new Error("PIN must be at least 4 digits.");
      if (p1 !== p2) throw new Error("PIN confirmation does not match.");

      await setPin(p1);

      ui.newPin.value = "";
      ui.newPin2.value = "";

      ui.firstTime.classList.add("hidden");
      ui.unlockSection.classList.remove("hidden");

      setStatus("PIN set. Now enter PIN to unlock.");
    } catch (e) {
      setStatus(e?.message || String(e));
    }
  });

  ui.unlockBtn.addEventListener("click", async () => {
    try {
      const pin = String(ui.pin.value || "").trim();
      if (!pin) throw new Error("Enter your Admin PIN.");

      const ok = await verifyPin(pin);
      if (!ok) throw new Error("Wrong PIN.");

      ui.pin.value = "";
      setLockState(true);

      const resp = await sendMessage({ action: "get_settings" });
      const present = !!resp?.settings?.openrouterKeyPresent;
      ui.keyState.textContent = present ? "Set" : "Not set";
      ui.keyState.className = "pill " + (present ? "ok" : "bad");

      setStatus("Unlocked.");
      setTimeout(() => setStatus(""), 1500);
    } catch (e) {
      setLockState(false);
      setStatus(e?.message || String(e));
    }
  });

  ui.lockBtn.addEventListener("click", () => {
    setLockState(false);
    setStatus("Locked.");
    setTimeout(() => setStatus(""), 1500);
  });

  ui.saveBtn.addEventListener("click", async () => {
    try {
      if (!unlocked) throw new Error("Unlock with PIN first.");
      await saveSettings();
    } catch (e) {
      setSStatus(e?.message || String(e));
    }
  });

  ui.clearBtn.addEventListener("click", async () => {
    try {
      if (!unlocked) throw new Error("Unlock with PIN first.");
      await clearKey();
    } catch (e) {
      setSStatus(e?.message || String(e));
    }
  });

  ui.testBtn.addEventListener("click", async () => {
    try {
      if (!unlocked) throw new Error("Unlock with PIN first.");
      await testConnection();
    } catch (e) {
      setSStatus(e?.message || String(e));
    }
  });

  await init();
});
