#!/usr/bin/env node
"use strict";

/**
 * Thin launcher for aurguard.
 *
 * There is NO install script. The prebuilt binary is delivered as a
 * platform-specific optional dependency (`aurguard-linux-x64` /
 * `aurguard-linux-arm64`); npm installs only the package matching the host's
 * os/cpu. This launcher resolves that binary and execs it — nothing is
 * downloaded or executed at install time, so there is no remote-code
 * supply-chain surface (and no `allow-scripts`/postinstall prompt).
 *
 * Escape hatch: set AURGUARD_BINARY to point at a locally built binary.
 */

const { spawnSync } = require("child_process");

function resolveBinary() {
  if (process.env.AURGUARD_BINARY) {
    return process.env.AURGUARD_BINARY;
  }
  if (process.platform !== "linux") {
    console.error("aurguard: only Linux is supported (AUR is Arch-specific).");
    process.exit(1);
  }
  const pkg =
    process.arch === "arm64" ? "aurguard-linux-arm64" : "aurguard-linux-x64";
  try {
    return require.resolve(`${pkg}/bin/aurguard`);
  } catch {
    console.error(
      `aurguard: no prebuilt binary found for linux-${process.arch}.\n` +
        `Install the matching optional package, or set AURGUARD_BINARY to a local build.`
    );
    process.exit(1);
  }
}

const res = spawnSync(resolveBinary(), process.argv.slice(2), {
  stdio: "inherit",
});
if (res.error) {
  console.error(`aurguard: ${res.error.message}`);
  process.exit(1);
}
process.exit(res.status === null ? 1 : res.status);
