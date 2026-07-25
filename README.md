<div align="center">

# Faultline

**Break it to understand it.**

36 hands-on, intentionally vulnerable web security labs — real sandboxed
target apps, one exploit at a time.

![Faultline homepage screenshot](docs/screenshot.png)

`Node.js 18+` · `Easy / Medium / Hard` · `Dark & Light mode` · `Zero cloud, all local`

</div>

---

> [!WARNING]
> **This app is deliberately insecure.** Every bug here is intentional and
> exists to teach. Run it only on `localhost` or in an isolated sandbox/VM
> — never deploy it publicly or reuse this code in a real product.
> Risky-sounding techniques (file reads, "command execution", SSRF) are all
> simulated against fake in-memory data, so nothing touches your real
> filesystem or makes real outbound requests. Details in
> [How the sandboxing works](#how-the-sandboxing-works).

## Quick start

```bash
cd faultline-labs
npm install
npm start
```

Open **http://localhost:3000** in a desktop browser. That's it — no
database, no config, no account to create.

## What makes this different

| | |
|---|---|
| 🎯 **Real standalone targets** | Each lab's "Lab" tab opens an actual vulnerable app in a new tab — its own login flow, its own URL you edit directly in the address bar. Not a simulated console. |
| 🔀 **Genuinely different payloads per tier** | The exploit that works on Easy is verified to *fail* on Medium and Hard. See [How the difficulty tiers work](#how-the-difficulty-tiers-work) for the audit. |
| 🚩 **Real flag verification** | Each session gets a unique, server-issued flag per lab+difficulty, only revealed when the exploit *actually* succeeds. Guessing or replaying an old flag correctly fails. |
| 📋 **Per-severity reports** | The Report tab's Summary, Reproduction Steps, and Impact are genuinely different text per tier — not one card reused three times. |
| ↺ **Reset anytime** | Wipe a single lab's demo data and solved status to practice it again from scratch. |
| 🌓 **Dark / Light / System** | Appearance toggle in the header, saved across visits. |
| 🔍 **Search** | Filter all 36 labs by name, description, or category from the homepage. |

## The labs

<table>
<tr><th align="left">Category</th><th align="left">Labs</th></tr>
<tr><td><b>Injection</b></td><td>SQL Injection <sub>(real SQLite)</sub>, Command Injection, SSTI, XXE, CRLF Injection</td></tr>
<tr><td><b>Server-Side Logic</b></td><td>SSRF, Insecure File Upload, Path Traversal, LFI, Cache Poisoning, Cache Deception, Request Smuggling, Secondary Context, Race Conditions</td></tr>
<tr><td><b>Client-Side</b></td><td>XSS, CSRF, Open Redirect, Client-Side Template Injection, postMessage, Prototype Pollution</td></tr>
<tr><td><b>Authentication</b></td><td>2FA Bypass, Weak Password Checks, Brute Force Attack, Password Reset Issues, OAuth Misconfiguration, SAML Vulnerabilities</td></tr>
<tr><td><b>Authorization</b></td><td>IDOR, Broken Access Control, Information Disclosure</td></tr>
<tr><td><b>Infrastructure</b></td><td>Cloud Storage Misconfiguration, Subdomain Takeover</td></tr>
<tr><td><b>Web Enumeration</b></td><td>Files & Directories, Virtual Host Enumeration, Fuzzing & HTTP Parameters, DNS Zone Transfer</td></tr>
<tr><td><b>Final</b></td><td>Chained challenge — Broken Access Control → IDOR</td></tr>
</table>

## How it works

**1. Pick a lab and a difficulty.** The Easy/Medium/Hard toggle in the
header applies globally and changes real server-side behavior, not just
the hint text.

**2. Read the Goal tab**, then hit **Open Live Lab** — this opens the real
vulnerable app in a new tab with its own URL you can edit directly.

**3. Exploit it.** Stuck? The Exploit tab has a hint button and a full
step-by-step solution.

**4. Submit the flag.** A `FLAG{...}` appears in the vulnerable app's
response the moment your exploit genuinely works. Paste it into the Report
tab to mark the lab solved.

**5. Practice again anytime** with **↺ Reset this lab**, which wipes that
lab's demo data and issues a fresh flag.

### How the difficulty tiers work

<details>
<summary><b>Expand for the tier-by-tier breakdown</b></summary>

<br>

Every tier was audited so the easier technique genuinely stops working a
tier up — not just harder in theory. A few examples:

| Lab | Easy → Medium → Hard |
|---|---|
| **XSS** | `<script>` → blocked, use `onerror=` → blocked, use `autofocus`+`onfocus` |
| **Path Traversal / LFI** | plain `../` → blocked, use `....//` → blocked, use double URL-encoding |
| **SQL Injection** | login unescaped → password field escaped only → login fully safe, but department search is UNION-injectable |
| **CSRF** | no protection → shallow `Origin` check (still bypassed) → blocks img/fetch but a real link click still works |
| **SSRF** | literal internal IPs → blocked, use hex/decimal encoding → blocked, chain through a "trusted" redirector |
| **Cache Poisoning** | unkeyed param is `utm_source` → fixed, but `ref` is unkeyed → fixed, but `lang` is unkeyed |
| **Prototype Pollution** | no denylist → blocks `__proto__` (bypassed via `constructor.prototype`) → blocks all three keys — **honestly not exploitable**, a real fix |
| **Subdomain Takeover** | dangling domain is `old-blog` → doesn't exist, it's `beta` instead → doesn't exist, it's `archive` instead |
| **Brute Force** | error message reveals valid usernames → response-timing side channel → account-lockout side channel |

One honest caveat: a couple of labs (Client-Side Template Injection,
postMessage's origin-check gap) have a core mechanic that's identical by
nature across tiers. Those say so explicitly in their Goal tab rather than
faking a difference.

</details>

### How the sandboxing works

<details>
<summary><b>Expand for what's real vs. simulated</b></summary>

<br>

| Technique | What actually happens |
|---|---|
| SQL Injection | **Real** — an in-memory SQLite database via `sql.js`, seeded with fake rows |
| Command Injection | **Simulated** — pattern-matched and answered with canned fake output; never calls a real shell |
| Path Traversal / LFI / XXE | **Simulated** — resolves against a fake in-memory "filesystem" in `routes/vuln-common.js`, never touches your real disk |
| SSRF | **Simulated** — pattern-matched against a fake list of "internal services"; no real outbound network request is ever made |
| File Upload | **Real upload**, immediately deleted after inspection; never written anywhere web-accessible or executed |
| Everything else | Real Express routes, real session/cookie/header logic — the actual bug class, just with fake demo data |

</details>

### 📁 Project structure

<details>
<summary><b>Expand for the file layout</b></summary>

<br>

```
faultline-labs/
├── server.js                    Express entrypoint, mounts every route module
├── routes/
│   ├── vuln-common.js           Session store, fake filesystem, fake internal services, page shell, flag system
│   ├── vulns-authz.js           IDOR · Broken Access Control · Final Challenge
│   ├── vulns-clientside.js      XSS · CSRF · Open Redirect · CSTI · postMessage · Prototype Pollution
│   ├── vulns-injection.js       SQLi · Command Injection · SSTI · XXE · CRLF
│   ├── vulns-serverlogic.js     SSRF · File Upload · Path Traversal · LFI · Cache Poisoning/Deception ·
│   │                            Request Smuggling · Secondary Context · Race Conditions
│   ├── vulns-auth.js            2FA Bypass · Weak Password · Brute Force · Password Reset · OAuth · SAML
│   ├── vulns-infra.js           Info Disclosure · Cloud Storage Misconfig · Subdomain Takeover
│   ├── vulns-enum.js            Files & Directories · Virtual Hosts · Fuzzing & Parameters · DNS Zone Transfer
│   └── reset-and-validate.js    POST /api/reset-lab · POST /api/validate-lab (real flag verification)
├── public/
│   ├── index.html / lab.html
│   ├── css/style.css
│   └── js/
│       ├── labs-data.js         All lab content: goals, hints, solutions, per-severity reports
│       ├── app.js               Homepage: grid, search, filters, progress
│       ├── lab.js               Lab detail page: tabs, flag submission, reset
│       └── theme.js             Dark/Light/System appearance toggle
└── README.md
```

</details>

## Progress & state

|  | Where it lives | Reset |
|---|---|---|
| **Lab progress** (solved status) | Browser `localStorage` | "reset all progress" on the homepage, or per-lab from its page |
| **Server-side demo state** (sessions, notes, balances...) | In memory | Restarting the server, or instantly via **↺ Reset this lab** |

## Disclaimer

For legal, hands-on security education only. Do not use any technique
learned here against systems you don't own or have explicit written
permission to test.
