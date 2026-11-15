// Scam Shield - Background Service Worker (Manifest V3)

const DEFAULT_API_URL = "http://localhost:8000";
const CACHE_TTL_MS = 10 * 60 * 1000; // 10 minutes cache
const scanCache = new Map();

// Helper: Normalize URL to avoid cache misses on trailing slashes
function normalizeUrl(url) {
  try {
    const parsed = new URL(url);
    return parsed.origin + parsed.pathname;
  } catch (e) {
    return url;
  }
}

// Retrieve user settings (custom API URL or Auth Token)
async function getSettings() {
  return new Promise((resolve) => {
    chrome.storage.local.get(["apiUrl", "authToken"], (items) => {
      resolve({
        apiUrl: items.apiUrl || DEFAULT_API_URL,
        authToken: items.authToken || null,
      });
    });
  });
}

// Set toolbar badge status
function updateBadge(tabId, scamLevel, confidence) {
  if (!tabId) return;

  if (scamLevel === "scam") {
    chrome.action.setBadgeText({ tabId, text: "SCAM" });
    chrome.action.setBadgeBackgroundColor({ tabId, color: "#ef4444" });
  } else if (scamLevel === "suspicious") {
    chrome.action.setBadgeText({ tabId, text: "WARN" });
    chrome.action.setBadgeBackgroundColor({ tabId, color: "#f59e0b" });
  } else if (scamLevel === "safe") {
    chrome.action.setBadgeText({ tabId, text: "SAFE" });
    chrome.action.setBadgeBackgroundColor({ tabId, color: "#10b981" });
  } else {
    chrome.action.setBadgeText({ tabId, text: "" });
  }
}

// Helper: Check if URL belongs to local development host
function isLocalhostUrl(url) {
  try {
    const parsed = new URL(url);
    const host = parsed.hostname.toLowerCase();
    return (
      host === "localhost" ||
      host === "127.0.0.1" ||
      host === "0.0.0.0" ||
      host === "[::1]" ||
      host === "::1" ||
      host.endsWith(".localhost") ||
      host.endsWith(".local")
    );
  } catch (e) {
    return false;
  }
}

// Scan a URL using the Scam Shield FastAPI Backend
async function inspectUrl(url) {
  if (!url || (!url.startsWith("http://") && !url.startsWith("https://"))) {
    return {
      scam_level: "safe",
      confidence: 100,
      reasons: ["Internal or non-HTTP browser page"],
      explanation: "Browser internal pages and extensions are excluded from scan.",
      skipped: true,
    };
  }

  // Exclude local development environments from threat classification
  if (isLocalhostUrl(url)) {
    return {
      scam_level: "safe",
      confidence: 0,
      reasons: ["Local development host (localhost or 127.0.0.1)"],
      explanation: "This is your local machine / development environment. It is completely safe from external phishing.",
      skipped: true,
    };
  }

  const norm = normalizeUrl(url);
  const now = Date.now();
  if (scanCache.has(norm)) {
    const cached = scanCache.get(norm);
    if (now - cached.timestamp < CACHE_TTL_MS) {
      return cached.result;
    }
  }

  const { apiUrl, authToken } = await getSettings();
  const headers = { "Content-Type": "application/json" };
  if (authToken) {
    headers["Authorization"] = `Bearer ${authToken}`;
  }

  try {
    const response = await fetch(`${apiUrl}/api/detect/url`, {
      method: "POST",
      headers,
      body: JSON.stringify({ url }),
    });

    if (!response.ok) {
      throw new Error(`API returned status ${response.status}`);
    }

    const data = await response.json();
    scanCache.set(norm, { timestamp: now, result: data });
    return data;
  } catch (error) {
    console.warn("[Scam Shield] Scan error:", error);
    return {
      error: error.message || "Failed to connect to Scam Shield API",
      scam_level: "unknown",
      confidence: 0,
      reasons: ["Backend unreachable at " + apiUrl],
      explanation: "Ensure the Scam Shield backend server is running on " + apiUrl,
    };
  }
}

// Handle tab URL check and badge update
async function processTab(tab) {
  if (!tab?.id || !tab.url) return;
  if (!tab.url.startsWith("http://") && !tab.url.startsWith("https://")) {
    updateBadge(tab.id, "neutral");
    return;
  }

  const result = await inspectUrl(tab.url);
  if (!result.error) {
    updateBadge(tab.id, result.scam_level, result.confidence);

    // If it's a confirmed high-confidence scam, dispatch warning to content script
    if (result.scam_level === "scam" && result.confidence >= 65) {
      try {
        chrome.tabs.sendMessage(tab.id, {
          action: "SHOW_THREAT_WARNING",
          result,
          url: tab.url,
        });
      } catch (e) {
        // Content script might not be injected yet
      }
    }
  }
}

// Tab navigation listeners
chrome.tabs.onUpdated.addListener((tabId, changeInfo, tab) => {
  if (changeInfo.status === "complete" && tab.active) {
    processTab(tab);
  }
});

chrome.tabs.onActivated.addListener(async (activeInfo) => {
  chrome.tabs.get(activeInfo.tabId, (tab) => {
    if (tab) processTab(tab);
  });
});

// Runtime messages from popup or content script
chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
  if (message.action === "INSPECT_CURRENT_TAB") {
    chrome.tabs.query({ active: true, currentWindow: true }, async (tabs) => {
      const activeTab = tabs[0];
      if (!activeTab || !activeTab.url) {
        sendResponse({ error: "No active HTTP tab found" });
        return;
      }
      const result = await inspectUrl(activeTab.url);
      sendResponse({ tab: activeTab, result });
    });
    return true; // Keep message channel open for async response
  }

  if (message.action === "MANUAL_SCAN") {
    inspectUrl(message.url).then((result) => {
      sendResponse({ result });
    });
    return true;
  }

  if (message.action === "CHECK_SERVER_HEALTH") {
    getSettings().then(async ({ apiUrl }) => {
      try {
        const res = await fetch(`${apiUrl}/health`, { method: "GET" });
        sendResponse({ online: res.ok, status: res.status });
      } catch (err) {
        sendResponse({ online: false, error: err.message });
      }
    });
    return true;
  }
});

