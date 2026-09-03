/**
 * public/js/csp-bypass-app.js — legitimate first-party app logic for the
 * csp-bypass lab (routes/vulns-clientside.js).
 *
 * Loaded via <script src="/js/csp-bypass-app.js" ...>, not inline — same
 * as any real production app would structure things to stay
 * CSP-compliant. This is what makes the "medium" and "hard" tiers work at
 * all: an external, same-origin script is covered by `script-src 'self'`
 * without needing 'unsafe-inline'. (For the "hard"/nonce tier, this tag
 * also carries a nonce attribute — real sites commonly do this too before
 * adopting 'strict-dynamic', since a nonce-source in script-src makes
 * browsers ignore 'self' for that directive entirely.)
 */
(function () {
  var script = document.currentScript;
  var TOKEN = script.dataset.token;
  var DIFFICULTY = script.dataset.difficulty;
  var confirmed = false;

  async function revealFlag() {
    if (confirmed) return;
    confirmed = true;
    const r = await fetch("/api/confirm-client-exploit", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ labId: "csp-bypass", difficulty: DIFFICULTY, token: TOKEN }),
    });
    const d = await r.json();
    const box = document.getElementById("flagBox");
    if (d.success && box) {
      box.style.display = "block";
      box.innerHTML =
        "<strong>🚩 CSP bypass confirmed — arbitrary script execution achieved despite the policy.</strong>\nFLAG: " + d.flag;
    } else {
      confirmed = false;
    }
  }

  // Any script that genuinely executes on this page (inline, past CSP, at
  // any tier) has full access to the page's global scope and can call any
  // function already defined there — same as a real attacker's payload
  // would. This is the proof hook a successfully-executed injection calls.
  window.__cspBypassConfirmed = revealFlag;

  // Medium tier's actual vulnerable sink: a "formula preview" feature that
  // naively eval()s whatever the user types — a realistic internal-tool
  // shortcut ("just eval the formula, it's only used by our own team").
  // Only reachable if the CSP's script-src actually permits 'unsafe-eval'.
  var formulaInput = document.getElementById("formulaInput");
  if (formulaInput) {
    formulaInput.addEventListener("input", function () {
      var out = document.getElementById("formulaResult");
      try {
        // eslint-disable-next-line no-eval
        var result = eval(formulaInput.value);
        out.textContent = "Result: " + result;
      } catch (e) {
        out.textContent = "[error] " + e.message;
      }
    });
  }
})();
