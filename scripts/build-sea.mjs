import * as fs from "node:fs";
import * as path from "node:path";
import { execSync } from "node:child_process";

const rootDir = process.cwd();
const distDir = path.join(rootDir, "dist");
if (!fs.existsSync(distDir)) {
  fs.mkdirSync(distDir, { recursive: true });
}

console.log("[build:sea] 1. Bundling CLI with esbuild into dist/bundle.cjs...");
execSync(
  "npx esbuild src/cli.ts --bundle --platform=node --target=node20 --format=cjs --outfile=dist/bundle.cjs",
  { stdio: "inherit" }
);

console.log("[build:sea] 2. Generating SEA preparation blob (dist/sea-prep.blob)...");
execSync("node --experimental-sea-config sea-config.json", { stdio: "inherit" });

const isWin = process.platform === "win32";
const isMac = process.platform === "darwin";
const binaryName = isWin ? "s3-guardian.exe" : "s3-guardian";
const binaryPath = path.join(distDir, binaryName);

console.log(`[build:sea] 3. Copying Node executable to ${binaryPath}...`);
fs.copyFileSync(process.execPath, binaryPath);

if (isMac) {
  try {
    console.log("[build:sea] Removing existing macOS code signature...");
    execSync(`codesign --remove-signature "${binaryPath}"`, { stdio: "inherit" });
  } catch (err) {
    console.warn("[build:sea] codesign remove-signature warning:", err);
  }
}

console.log("[build:sea] 4. Injecting SEA blob via postject...");
const postjectCmd = isMac
  ? `npx postject "${binaryPath}" NODE_SEA_BLOB dist/sea-prep.blob --sentinel-fuse NODE_SEA_FUSE_fce680ab2cc467b6e072b8b5df1996b2 --macho-segment-name NODE_SEA`
  : `npx postject "${binaryPath}" NODE_SEA_BLOB dist/sea-prep.blob --sentinel-fuse NODE_SEA_FUSE_fce680ab2cc467b6e072b8b5df1996b2`;

execSync(postjectCmd, { stdio: "inherit" });

if (isMac) {
  try {
    console.log("[build:sea] Applying ad-hoc macOS code signature...");
    execSync(`codesign --sign - "${binaryPath}"`, { stdio: "inherit" });
  } catch (err) {
    console.warn("[build:sea] codesign ad-hoc sign warning:", err);
  }
}

if (!isWin) {
  fs.chmodSync(binaryPath, 0o755);
}

console.log(`[build:sea] ✅ Local platform binary created successfully: ${binaryPath}`);
