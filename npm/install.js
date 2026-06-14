#!/usr/bin/env node
"use strict";

/**
 * Postinstall hook: download the prebuilt aurguard binary matching this
 * platform/arch from the matching GitHub Release and drop it at bin/aurguard.
 *
 * Pure Node, no dependencies. Honors AURGUARD_BINARY to skip the download
 * (useful for offline installs / local testing).
 */

const fs = require("fs");
const os = require("os");
const path = require("path");
const https = require("https");
const { createGunzip } = require("zlib");
const { execFileSync } = require("child_process");

const REPO = "lunanoir21/aurguard-project";
const VERSION = require("./package.json").version;

const TARGETS = {
  "linux-x64": "x86_64-unknown-linux-gnu",
  "linux-arm64": "aarch64-unknown-linux-gnu",
};

function fail(msg) {
  console.error(`aurguard: ${msg}`);
  process.exit(1);
}

function targetTriple() {
  if (os.platform() !== "linux") {
    fail("aurguard only supports Linux (AUR is Arch-specific).");
  }
  const key = `linux-${os.arch()}`;
  const triple = TARGETS[key];
  if (!triple) fail(`unsupported architecture: ${os.arch()}`);
  return triple;
}

function get(url) {
  return new Promise((resolve, reject) => {
    https
      .get(url, { headers: { "User-Agent": "aurguard-npm-installer" } }, (res) => {
        if (res.statusCode >= 300 && res.statusCode < 400 && res.headers.location) {
          resolve(get(res.headers.location));
          return;
        }
        if (res.statusCode !== 200) {
          reject(new Error(`HTTP ${res.statusCode} for ${url}`));
          return;
        }
        resolve(res);
      })
      .on("error", reject);
  });
}

async function main() {
  const binDir = path.join(__dirname, "bin");
  const binPath = path.join(binDir, "aurguard");
  fs.mkdirSync(binDir, { recursive: true });

  // Escape hatch: use a locally built binary.
  if (process.env.AURGUARD_BINARY) {
    fs.copyFileSync(process.env.AURGUARD_BINARY, binPath);
    fs.chmodSync(binPath, 0o755);
    printDone();
    return;
  }

  const triple = targetTriple();
  const asset = `aurguard-${triple}.tar.gz`;
  const url = `https://github.com/${REPO}/releases/download/v${VERSION}/${asset}`;

  console.log(`aurguard: downloading ${asset} …`);
  const res = await get(url);

  // Stream tarball → gunzip → temp file, then extract the single binary.
  const tmpTar = path.join(os.tmpdir(), `aurguard-${Date.now()}.tar`);
  await new Promise((resolve, reject) => {
    const out = fs.createWriteStream(tmpTar);
    res.pipe(createGunzip()).pipe(out);
    out.on("finish", resolve);
    out.on("error", reject);
  });

  execFileSync("tar", ["-xf", tmpTar, "-C", binDir, "aurguard"], { stdio: "inherit" });
  fs.chmodSync(binPath, 0o755);
  fs.unlinkSync(tmpTar);
  printDone();
}

/** Print the post-install completion notice (always English). */
function printDone() {
  const line = "─".repeat(58);
  console.log("");
  console.log(`  \x1b[32m✓\x1b[0m aurguard installed.`);
  console.log("");
  console.log(`  ${line}`);
  console.log("  To finish setting up aurguard, run:");
  console.log("");
  console.log("      \x1b[1maurguard --setup\x1b[0m");
  console.log("");
  console.log("  This picks your interface language (English, Türkçe,");
  console.log("  Français, Español, Azərbaycan) and security policy.");
  console.log("  Then try:  aurguard -I <package>");
  console.log(`  ${line}`);
  console.log("");
}

main().catch((e) => fail(e.message));
