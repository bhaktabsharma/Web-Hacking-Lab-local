#!/usr/bin/env node
/**
 * tests/run-all.js — the actual `npm test` entrypoint.
 *
 * Boots the app as a child process, waits for it to be reachable on :3000,
 * runs the lab-registry validator plus every *.test.js file in this
 * directory in sequence, then shuts the server down and exits with the
 * aggregate status — 0 only if EVERYTHING passed.
 *
 * This is the "at minimum" automated suite from the upgrade spec's Section
 * 36: it covers routes (every lab's live route), labs (full registry
 * validation), flags (issuance, single-use client-proof tokens, session
 * isolation, difficulty isolation), sessions (isolation between two
 * independent cookie jars), and reset (both per-lab and reset-all).
 */
const { spawn } = require("child_process");
const path = require("path");
const http = require("http");
const fs = require("fs");

const ROOT = path.join(__dirname, "..");

function waitForServer(maxWaitMs) {
  const start = Date.now();
  return new Promise((resolve, reject) => {
    (function attempt() {
      const req = http.request({ host: "localhost", port: 3000, path: "/index.html", method: "GET" }, (res) => {
        res.resume();
        resolve();
      });
      req.on("error", () => {
        if (Date.now() - start > maxWaitMs) reject(new Error("server did not come up within " + maxWaitMs + "ms"));
        else setTimeout(attempt, 200);
      });
      req.end();
    })();
  });
}

function runNodeScript(scriptPath) {
  return new Promise((resolve) => {
    const child = spawn(process.execPath, [scriptPath], { cwd: ROOT, stdio: "inherit" });
    child.on("exit", (code) => resolve(code === 0));
  });
}

async function main() {
  console.log("Booting server for the test run...");
  const server = spawn(process.execPath, ["server.js"], { cwd: ROOT, stdio: ["ignore", "pipe", "pipe"] });
  let serverOutput = "";
  server.stdout.on("data", (d) => (serverOutput += d));
  server.stderr.on("data", (d) => (serverOutput += d));

  let allOk = true;
  try {
    await waitForServer(8000);
    console.log("Server is up. Running suites...\n");

    console.log("=".repeat(70) + "\nLab registry validator\n" + "=".repeat(70));
    allOk = (await runNodeScript(path.join(ROOT, "tools", "validate-labs.js"))) && allOk;

    const testFiles = fs
      .readdirSync(__dirname)
      .filter((f) => f.endsWith(".test.js"))
      .sort();

    for (const f of testFiles) {
      console.log("\n" + "=".repeat(70) + `\n${f}\n` + "=".repeat(70));
      const ok = await runNodeScript(path.join(__dirname, f));
      allOk = ok && allOk;
    }
  } catch (e) {
    console.error("\nFAILED TO START SERVER FOR TESTING:", e.message);
    console.error("--- server output ---\n" + serverOutput);
    allOk = false;
  } finally {
    server.kill("SIGKILL");
  }

  console.log("\n" + "=".repeat(70));
  console.log(allOk ? "ALL SUITES PASSED ✅" : "ONE OR MORE SUITES FAILED ❌");
  console.log("=".repeat(70));
  process.exit(allOk ? 0 : 1);
}

main();
