// Scam Shield - Content Script Threat Interstitial

(function () {
  let warningBannerRendered = false;

  chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
    if (message.action === "SHOW_THREAT_WARNING") {
      renderWarningBanner(message.result, message.url);
      sendResponse({ received: true });
    }
  });

  function renderWarningBanner(result, url) {
    if (warningBannerRendered || document.getElementById("scam-shield-warning-overlay")) {
      return;
    }
    warningBannerRendered = true;

    const overlay = document.createElement("div");
    overlay.id = "scam-shield-warning-overlay";

    const reasonsSummary = Array.isArray(result?.reasons) && result.reasons.length
      ? result.reasons[0]
      : "Deceptive domain patterns or suspicious credentials detected.";

    overlay.innerHTML = `
      <div class="scam-shield-banner">
        <div class="scam-shield-banner-content">
          <div class="scam-shield-icon-badge">
            <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5">
              <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/>
              <line x1="12" y1="8" x2="12" y2="12"/>
              <line x1="12" y1="16" x2="12.01" y2="16"/>
            </svg>
          </div>
          <div class="scam-shield-text">
            <div class="scam-shield-title">
              <span>Security Warning: High-Risk Website</span>
              <span class="scam-shield-confidence-tag">${result?.confidence || 90}% Risk</span>
            </div>
            <div class="scam-shield-subtitle">
              ${reasonsSummary} Do not enter passwords, OTPs, or payment details.
            </div>
          </div>
        </div>
        <div class="scam-shield-actions">
          <button class="scam-shield-btn-leave" id="scam-shield-leave-btn">Leave Site (Recommended)</button>
          <button class="scam-shield-btn-dismiss" id="scam-shield-dismiss-btn">Dismiss</button>
        </div>
      </div>
    `;

    document.documentElement.appendChild(overlay);

    document.getElementById("scam-shield-leave-btn")?.addEventListener("click", () => {
      window.location.href = "about:blank";
    });

    document.getElementById("scam-shield-dismiss-btn")?.addEventListener("click", () => {
      overlay.remove();
    });
  }
})();

