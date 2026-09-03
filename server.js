/**
 * Web Hacking Labs — server.js
 *
 * This server contains INTENTIONALLY VULNERABLE endpoints, built for legal,
 * hands-on security training in an isolated sandbox / localhost environment.
 * Risky mechanics (arbitrary file reads, command execution, SSRF) are all
 * simulated against fake in-memory data — see routes/vuln-common.js.
 */
const express = require("express");
const cookieParser = require("cookie-parser");
const path = require("path");
const { difficultyGuard } = require("./src/middleware/difficulty-guard");

const app = express();
const PORT = process.env.PORT || 3000;

app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(cookieParser());
app.use(difficultyGuard);

const authz = require("./routes/vulns-authz");
const clientSide = require("./routes/vulns-clientside");
const injection = require("./routes/vulns-injection");
const serverLogic = require("./routes/vulns-serverlogic");
const auth = require("./routes/vulns-auth");
const infra = require("./routes/vulns-infra");
const enumeration = require("./routes/vulns-enum");
const api = require("./routes/vulns-api");
const business = require("./routes/vulns-business");
const chains = require("./routes/vulns-chains");
const companyHub = require("./routes/company-hub");
const resetAndValidate = require("./routes/reset-and-validate");
const discovery = require("./routes/discovery");

app.use(authz.router);
app.use(clientSide.router);
app.use(injection.router);
app.use(serverLogic.router);
app.use(auth.router);
app.use(infra.router);
app.use(enumeration.router);
app.use(api.router);
app.use(business.router);
app.use(chains.router);
app.use(companyHub.router);
app.use(discovery.router);
app.use(resetAndValidate.router);

app.use(express.static(path.join(__dirname, "public")));

const server = app.listen(PORT, () => {
  console.log(`\nWeb Hacking Labs running at http://localhost:${PORT}`);
  console.log(`Intentionally vulnerable — sandbox / localhost use only.\n`);
});
api.attachWebSocketServer(server);
