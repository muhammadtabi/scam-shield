// Scam Shield - Popup Controller

document.addEventListener("DOMContentLoaded", () => {
  // Elements
  const tabCurrent = document.getElementById("tabCurrent");
  const tabQuick = document.getElementById("tabQuick");
  const tabSettings = document.getElementById("tabSettings");

  const viewCurrent = document.getElementById("viewCurrent");
  const viewQuick = document.getElementById("viewQuick");
  const viewSettings = document.getElementById("viewSettings");

  const serverStatus = document.getElementById("serverStatus");
  const currentDomain = document.getElementById("currentDomain");
  const currentVerdictBanner = document.getElementById("currentVerdictBanner");
  const currentVerdict = document.getElementById("currentVerdict");
  const currentConfidence = document.getElementById("currentConfidence");
  const currentProgressBar = document.getElementById("currentProgressBar");
  const currentReasons = document.getElementById("currentReasons");
  const currentExplanationBox = document.getElementById("currentExplanationBox");
  const currentExplanation = document.getElementById("currentExplanation");
  const btnRescan = document.getElementById("btnRescan");

  const manualUrlInput = document.getElementById("manualUrlInput");
  const btnManualScan = document.getElementById("btnManualScan");
  const manualResults = document.getElementById("manualResults");
  const manualVerdictBanner = document.getElementById("manualVerdictBanner");
  const manualVerdict = document.getElementById("manualVerdict");
  const manualConfidence = document.getElementById("manualConfidence");
  const manualReasons = document.getElementById("manualReasons");

  const apiEndpointInput = document.getElementById("apiEndpointInput");
  const authTokenInput = document.getElementById("authTokenInput");
  const btnSaveSettings = document.getElementById("btnSaveSettings");
  const saveToast = document.getElementById("saveToast");

  // Tab switching
  function switchTab(activeBtn, activeView) {
    [tabCurrent, tabQuick, tabSettings].forEach(b => b.classList.remove("active"));
    [viewCurrent, viewQuick, viewSettings].forEach(v => v.classList.add("hidden"));

    activeBtn.classList.add("active");
    activeView.classList.remove("hidden");
  }

  tabCurrent.addEventListener("click", () => switchTab(tabCurrent, viewCurrent));
  tabQuick.addEventListener("click", () => switchTab(tabQuick, viewQuick));
  tabSettings.addEventListener("click", () => switchTab(tabSettings, viewSettings));

  // Check Backend Server Health
  function checkHealth() {
    chrome.runtime.sendMessage({ action: "CHECK_SERVER_HEALTH" }, (res) => {
      if (res && res.online) {
        serverStatus.className = "server-status online";
        serverStatus.title = "Connected to Scam Shield API";
      } else {
        serverStatus.className = "server-status offline";
        serverStatus.title = "Backend unreachable. Is FastAPI running on localhost:8000?";
      }
    });
  }

  // Render verdict card
  function renderVerdict(banner, verdictEl, confidenceEl, progressEl, reasonsEl, explanationBox, explanationEl, result) {
    banner.className = "verdict-banner " + (result.scam_level || "safe");
    verdictEl.textContent = (result.scam_level || "safe").toUpperCase();
    confidenceEl.textContent = `${result.confidence || 0}%`;

    if (progressEl) {
      progressEl.style.width = `${Math.min(result.confidence || 0, 100)}%`;
    }

    if (reasonsEl) {
      reasonsEl.innerHTML = "";
      const reasons = Array.isArray(result.reasons) && result.reasons.length ? result.reasons : ["No suspicious threat factors detected"];
      reasons.forEach(r => {
        const item = document.createElement("div");
        item.className = "reason-item";
        item.textContent = r;
        reasonsEl.appendChild(item);
      });
    }

    if (explanationBox && explanationEl) {
      if (result.explanation) {
        explanationBox.style.display = "block";
        explanationEl.textContent = result.explanation;
      } else {
        explanationBox.style.display = "none";
      }
    }
  }

  // Load and inspect active tab
  function loadActiveTab() {
    currentVerdict.textContent = "ANALYZING...";
    currentReasons.innerHTML = '<div class="reason-item">Contacting Scam Shield API...</div>';

    chrome.runtime.sendMessage({ action: "INSPECT_CURRENT_TAB" }, (response) => {
      if (!response || response.error) {
        currentDomain.textContent = "No Web Page";
        currentVerdictBanner.className = "verdict-banner safe";
        currentVerdict.textContent = "INACTIVE";
        currentConfidence.textContent = "--";
        currentReasons.innerHTML = `<div class="reason-item">${response?.error || "Open an HTTP/HTTPS webpage to analyze"}</div>`;
        return;
      }

      const { tab, result } = response;
      try {
        const urlObj = new URL(tab.url);
        currentDomain.textContent = urlObj.hostname;
      } catch (e) {
        currentDomain.textContent = tab.url.slice(0, 30);
      }

      renderVerdict(
        currentVerdictBanner,
        currentVerdict,
        currentConfidence,
        currentProgressBar,
        currentReasons,
        currentExplanationBox,
        currentExplanation,
        result
      );
    });
  }

  // Rescan button
  btnRescan.addEventListener("click", () => {
    loadActiveTab();
    checkHealth();
  });

  // Manual Quick Scan
  btnManualScan.addEventListener("click", () => {
    const rawUrl = manualUrlInput.value.trim();
    if (!rawUrl) return;

    btnManualScan.disabled = true;
    btnManualScan.textContent = "Scanning...";

    chrome.runtime.sendMessage({ action: "MANUAL_SCAN", url: rawUrl }, (res) => {
      btnManualScan.disabled = false;
      btnManualScan.textContent = "Scan";

      if (res && res.result) {
        manualResults.classList.remove("hidden");
        renderVerdict(
          manualVerdictBanner,
          manualVerdict,
          manualConfidence,
          null,
          manualReasons,
          null,
          null,
          res.result
        );
      }
    });
  });

  manualUrlInput.addEventListener("keydown", (e) => {
    if (e.key === "Enter") {
      btnManualScan.click();
    }
  });

  // Load saved settings
  chrome.storage.local.get(["apiUrl", "authToken"], (items) => {
    if (items.apiUrl) apiEndpointInput.value = items.apiUrl;
    if (items.authToken) authTokenInput.value = items.authToken;
  });

  // Save settings
  btnSaveSettings.addEventListener("click", () => {
    const apiUrl = apiEndpointInput.value.trim() || "http://localhost:8000";
    const authToken = authTokenInput.value.trim() || "";

    chrome.storage.local.set({ apiUrl, authToken }, () => {
      saveToast.classList.remove("hidden");
      setTimeout(() => saveToast.classList.add("hidden"), 2000);
      checkHealth();
    });
  });

  // Init
  checkHealth();
  loadActiveTab();
});

