// apply-finding-overrides.ts
//
// Consumes AWS Inspector SBOM scan results and generates quilt patches
// to override vulnerable npm packages. Also prunes stale patches after
// upstream updates.
//
// Usage:
//   npx ts-node apply-finding-overrides.ts apply [--dry-run] <scan-result.json> ...
//   npx ts-node apply-finding-overrides.ts prune [--dry-run]

import { readFileSync, writeFileSync, readdirSync, unlinkSync, existsSync } from "fs";
import { join, dirname, relative, resolve } from "path";
import { execSync } from "child_process";
import semver from "semver";

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

interface ScanAffect {
  fixed_version: string;
  installed_version: string; // purl like "pkg:npm/undici@7.19.0"
}

interface ScanVulnerability {
  id: string;
  severity: string;
  related?: string[];
  affects: ScanAffect[];
}

interface ScanResult {
  sbom: {
    vulnerabilities?: ScanVulnerability[];
  };
}

interface ConsolidatedFinding {
  packageName: string;
  currentVersion: string;
  fixedVersion: string;
  findingIds: string[]; // CVE + GHSA ids with severity
  highestSeverity: string;
}

interface AffectedFile {
  packageJsonPath: string; // relative to code-editor-src/
  depType: "direct" | "transitive";
  depSection?: "dependencies" | "devDependencies";
}

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

const ROOT = resolve(__dirname, "../..");
const PATCHED_SRC = join(ROOT, "code-editor-src");
const UPSTREAM_SRC = join(ROOT, "third-party-src");
const PATCHES_DIR = join(ROOT, "patches");
const COMMON_PATCHES = join(PATCHES_DIR, "common");
const SCRIPT_PATH = "build-tools/apply-finding-overrides/apply-finding-overrides.ts";

const SEVERITY_RANK: Record<string, number> = {
  critical: 4,
  high: 3,
  medium: 2,
  other: 1,
  low: 0,
};

const PATCH_PREFIX = "finding-override-";

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/** Parse purl like "pkg:npm/undici@7.19.0" or "pkg:npm/%40scope/name@1.0.0" */
function parsePurl(purl: string): { name: string; version: string } | null {
  const match = purl.match(/^pkg:npm\/(.+)@(.+)$/);
  if (!match) return null;
  const name = decodeURIComponent(match[1]);
  return { name, version: match[2] };
}

/** Sanitize package name for use in filenames: @scope/name → scope-name */
function sanitizePkgName(name: string): string {
  return name.replace(/^@/, "").replace(/\//g, "-");
}

/** Strip version range prefix: "^7.24.0" → "7.24.0" */
function stripRange(spec: string): string {
  const coerced = semver.coerce(spec);
  return coerced ? coerced.version : spec.replace(/^[\^~>=<\s]+/, "");
}

function findAllLockfiles(baseDir: string): string[] {
  const results: string[] = [];
  function walk(dir: string) {
    for (const entry of readdirSync(dir, { withFileTypes: true })) {
      if (entry.name === "node_modules") continue;
      const full = join(dir, entry.name);
      if (entry.isDirectory()) {
        walk(full);
      } else if (entry.name === "package-lock.json") {
        results.push(full);
      }
    }
  }
  walk(baseDir);
  return results;
}

function getSeriesFiles(): string[] {
  return readdirSync(PATCHES_DIR)
    .filter((f) => f.endsWith(".series"))
    .map((f) => join(PATCHES_DIR, f));
}

function readJson(path: string): any {
  return JSON.parse(readFileSync(path, "utf-8"));
}

/** Insert line into series file after the last common/finding-overrides.diff or last common/ line */
function insertIntoSeries(seriesPath: string, patchEntry: string) {
  const lines = readFileSync(seriesPath, "utf-8").split("\n");
  let insertIdx = -1;
  for (let i = 0; i < lines.length; i++) {
    if (lines[i] === "common/finding-overrides.diff") {
      insertIdx = i + 1;
      break;
    }
  }
  if (insertIdx === -1) {
    for (let i = lines.length - 1; i >= 0; i--) {
      if (lines[i].startsWith("common/")) {
        insertIdx = i + 1;
        break;
      }
    }
  }
  if (insertIdx === -1) insertIdx = lines.length;
  if (lines.includes(patchEntry)) return;
  lines.splice(insertIdx, 0, patchEntry);
  writeFileSync(seriesPath, lines.join("\n"));
}

function removeFromSeries(seriesPath: string, patchEntry: string) {
  const content = readFileSync(seriesPath, "utf-8");
  const lines = content.split("\n").filter((l) => l !== patchEntry);
  writeFileSync(seriesPath, lines.join("\n"));
}

// ---------------------------------------------------------------------------
// Apply command
// ---------------------------------------------------------------------------

function parseFindings(scanFiles: string[]): Map<string, ConsolidatedFinding> {
  const findings = new Map<string, ConsolidatedFinding>();

  for (const file of scanFiles) {
    const data: ScanResult = readJson(file);
    const vulns = data.sbom?.vulnerabilities ?? [];

    for (const vuln of vulns) {
      if (SEVERITY_RANK[vuln.severity] === undefined) continue;
      if (SEVERITY_RANK[vuln.severity] < SEVERITY_RANK["medium"]) continue;

      for (const affect of vuln.affects) {
        const parsed = parsePurl(affect.installed_version);
        if (!parsed) continue;

        const ids = [vuln.id, ...(vuln.related ?? [])];
        const existing = findings.get(parsed.name);

        if (existing) {
          for (const id of ids) {
            const entry = `${id} (${vuln.severity})`;
            if (!existing.findingIds.includes(entry)) {
              existing.findingIds.push(entry);
            }
          }
          if (!semver.gte(existing.fixedVersion, affect.fixed_version)) {
            existing.fixedVersion = affect.fixed_version;
          }
          if (
            SEVERITY_RANK[vuln.severity] >
            SEVERITY_RANK[existing.highestSeverity]
          ) {
            existing.highestSeverity = vuln.severity;
          }
        } else {
          findings.set(parsed.name, {
            packageName: parsed.name,
            currentVersion: parsed.version,
            fixedVersion: affect.fixed_version,
            findingIds: ids.map((id) => `${id} (${vuln.severity})`),
            highestSeverity: vuln.severity,
          });
        }
      }
    }
  }

  return findings;
}

function discoverAffectedFiles(
  packageName: string,
  lockfiles: string[]
): AffectedFile[] {
  const affected: AffectedFile[] = [];

  for (const lockfile of lockfiles) {
    const lock = readJson(lockfile);
    const packages = lock.packages ?? {};

    const found = Object.keys(packages).some(
      (key) =>
        key === `node_modules/${packageName}` ||
        key.endsWith(`/node_modules/${packageName}`)
    );
    if (!found) continue;

    const pkgJsonPath = join(dirname(lockfile), "package.json");
    if (!existsSync(pkgJsonPath)) continue;

    const pkgJson = readJson(pkgJsonPath);
    const relPath = relative(PATCHED_SRC, pkgJsonPath);

    if (pkgJson.dependencies?.[packageName]) {
      affected.push({
        packageJsonPath: relPath,
        depType: "direct",
        depSection: "dependencies",
      });
    } else if (pkgJson.devDependencies?.[packageName]) {
      affected.push({
        packageJsonPath: relPath,
        depType: "direct",
        depSection: "devDependencies",
      });
    } else {
      affected.push({ packageJsonPath: relPath, depType: "transitive" });
    }
  }

  return affected;
}

function isAlreadyFixed(
  pkgJsonPath: string,
  packageName: string,
  fixedVersion: string
): boolean {
  const pkgJson = readJson(pkgJsonPath);

  for (const section of ["dependencies", "devDependencies"] as const) {
    const spec = pkgJson[section]?.[packageName];
    if (spec && semver.gte(stripRange(spec), fixedVersion)) return true;
  }

  const overrideSpec = pkgJson.overrides?.[packageName];
  if (overrideSpec && typeof overrideSpec === "string") {
    if (semver.gte(stripRange(overrideSpec), fixedVersion)) return true;
  }

  return false;
}

function applyFix(
  pkgJsonAbsPath: string,
  af: AffectedFile,
  packageName: string,
  fixedVersion: string
) {
  const content = readFileSync(pkgJsonAbsPath, "utf-8");
  const versionSpec = `^${fixedVersion}`;

  const indentMatch = content.match(/^(\t+|\s{2,})"/m);
  const indent = indentMatch ? indentMatch[1] : "  ";
  const indent2 = indent + indent;

  if (af.depType === "direct" && af.depSection) {
    const escaped = packageName.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
    const re = new RegExp(`("${escaped}"\\s*:\\s*)"[^"]*"`);
    const updated = content.replace(re, `$1"${versionSpec}"`);
    if (updated === content) {
      console.error(
        `  WARNING: Could not find ${packageName} in ${af.depSection} of ${af.packageJsonPath}`
      );
      return;
    }
    writeFileSync(pkgJsonAbsPath, updated);
  } else {
    const pkgJson = JSON.parse(content);

    if (!pkgJson.overrides) {
      const insertAfter =
        content.lastIndexOf('"devDependencies"') !== -1
          ? '"devDependencies"'
          : '"dependencies"';
      const sectionStart = content.indexOf(insertAfter);
      if (sectionStart === -1) {
        console.error(
          `  WARNING: Cannot find insertion point in ${af.packageJsonPath}`
        );
        return;
      }
      let depth = 0;
      let i = content.indexOf("{", sectionStart);
      for (; i < content.length; i++) {
        if (content[i] === "{") depth++;
        if (content[i] === "}") depth--;
        if (depth === 0) break;
      }
      const insertPoint = i + 1;
      const overridesBlock = `,\n${indent}"overrides": {\n${indent2}"${packageName}": "${versionSpec}"\n${indent}}`;
      const updated =
        content.slice(0, insertPoint) +
        overridesBlock +
        content.slice(insertPoint);
      writeFileSync(pkgJsonAbsPath, updated);
    } else if (pkgJson.overrides[packageName]) {
      const escaped = packageName.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
      const re = new RegExp(`("${escaped}"\\s*:\\s*)"[^"]*"`);
      const updated = content.replace(re, `$1"${versionSpec}"`);
      writeFileSync(pkgJsonAbsPath, updated);
    } else {
      const overridesIdx = content.indexOf('"overrides"');
      const braceIdx = content.indexOf("{", overridesIdx);
      const insertPoint = braceIdx + 1;
      const newEntry = `\n${indent2}"${packageName}": "${versionSpec}",`;
      const updated =
        content.slice(0, insertPoint) + newEntry + content.slice(insertPoint);
      writeFileSync(pkgJsonAbsPath, updated);
    }
  }
}

function runApply(scanFiles: string[], dryRun: boolean) {
  if (!existsSync(PATCHED_SRC)) {
    console.error(
      "Error: code-editor-src/ does not exist. Run prepare-src.sh first."
    );
    process.exit(1);
  }

  const findings = parseFindings(scanFiles);
  if (findings.size === 0) {
    console.log("No actionable findings found in scan results.");
    return;
  }

  const lockfiles = findAllLockfiles(PATCHED_SRC);
  const seriesFiles = getSeriesFiles();
  let patchCount = 0;

  const primarySeries = seriesFiles[0];
  if (!primarySeries) {
    console.error("Error: No series files found in patches/");
    process.exit(1);
  }

  for (const [, finding] of findings) {
    console.log(`\nPackage: ${finding.packageName}`);
    console.log(
      `  Current: ${finding.currentVersion} → Fixed: >= ${finding.fixedVersion}`
    );
    console.log(`  Findings: ${finding.findingIds.join(", ")}`);

    const affected = discoverAffectedFiles(finding.packageName, lockfiles);
    if (affected.length === 0) {
      console.log(
        "  WARNING: Package not found in any package-lock.json, skipping"
      );
      continue;
    }

    const needsFix = affected.filter(
      (af) =>
        !isAlreadyFixed(
          join(PATCHED_SRC, af.packageJsonPath),
          finding.packageName,
          finding.fixedVersion
        )
    );

    if (needsFix.length === 0) {
      console.log("  Already fixed in all affected files, skipping");
      continue;
    }

    for (const af of needsFix) {
      const action =
        af.depType === "direct"
          ? `${af.depSection} → version update`
          : "transitive → override";
      console.log(`  ${af.packageJsonPath} (${action})`);
    }

    const sanitized = sanitizePkgName(finding.packageName);
    const patchName = `common/${PATCH_PREFIX}${sanitized}.diff`;
    const patchFile = join(PATCHES_DIR, patchName);

    if (dryRun) {
      console.log(`  Would create patch: ${patchName}`);
      patchCount++;
      continue;
    }

    const patchExists = existsSync(patchFile);

    const quiltEnv = {
      ...process.env,
      QUILT_PATCHES: PATCHES_DIR,
      QUILT_SERIES: primarySeries,
    };
    const execOpts = { cwd: PATCHED_SRC, env: quiltEnv };

    if (patchExists) {
      try {
        execSync(`quilt pop -q common/finding-override-${sanitized}.diff`, {
          ...execOpts,
          stdio: "pipe",
        });
        execSync(`quilt push -q common/finding-override-${sanitized}.diff`, {
          ...execOpts,
          stdio: "pipe",
        });
      } catch {
        // Best effort
      }
    } else {
      try {
        execSync("quilt pop -q common/finding-overrides.diff", {
          ...execOpts,
          stdio: "pipe",
        });
      } catch {
        try {
          execSync("quilt pop -qa", { ...execOpts, stdio: "pipe" });
        } catch {
          // Already fully popped
        }
      }
      execSync(`quilt new ${patchName}`, { ...execOpts, stdio: "pipe" });
    }

    const findingIdsClean = finding.findingIds
      .map((f) => f.replace(/ \([^)]+\)/, ""))
      .filter((v, i, a) => a.indexOf(v) === i);
    const header = [
      `Auto-generated by ${SCRIPT_PATH}`,
      `Affected package: ${finding.packageName}`,
      `Fixed version: >= ${finding.fixedVersion}`,
      `Findings: ${findingIdsClean.join(", ")}`,
      `Removal condition: Upstream updates ${finding.packageName} to >= ${finding.fixedVersion}`,
    ].join("\n");

    for (const af of needsFix) {
      const absPath = join(PATCHED_SRC, af.packageJsonPath);
      try {
        execSync(`quilt add ${af.packageJsonPath}`, {
          ...execOpts,
          stdio: "pipe",
        });
      } catch {
        // File may already be tracked by this patch
      }
      applyFix(absPath, af, finding.packageName, finding.fixedVersion);
    }

    execSync(`quilt refresh -p ab --no-timestamps`, {
      ...execOpts,
      stdio: "pipe",
    });

    const patchContent = readFileSync(patchFile, "utf-8");
    writeFileSync(patchFile, header + "\n\n" + patchContent);

    try {
      execSync("quilt push -a", { ...execOpts, stdio: "pipe" });
    } catch {
      // May already be fully applied
    }

    if (!patchExists) {
      for (const sf of seriesFiles) {
        if (sf === primarySeries) continue;
        insertIntoSeries(sf, patchName);
      }
    }

    console.log(`  Patch: ${patchName}`);
    patchCount++;
  }

  console.log(`\n=== Summary ===`);
  console.log(
    `${dryRun ? "Would create" : "Created"} ${patchCount} patch(es)`
  );
  if (!dryRun && patchCount > 0) {
    console.log(`\nNext steps:`);
    console.log(
      `  1. Run update-package-locks.sh in Docker to regenerate lock files`
    );
    console.log(
      `  2. Verify with: ./scripts/security-scan.sh scan-main-dependencies <target> <branch>`
    );
  }
}

// ---------------------------------------------------------------------------
// Prune command
// ---------------------------------------------------------------------------

interface PatchMeta {
  file: string;
  patchName: string;
  packageName: string;
  fixedVersion: string;
}

function parsePatchHeader(patchFile: string): PatchMeta | null {
  const content = readFileSync(patchFile, "utf-8");
  const pkgMatch = content.match(/^Affected package:\s*(.+)$/m);
  const verMatch = content.match(/^Fixed version:\s*>=\s*(.+)$/m);
  if (!pkgMatch || !verMatch) return null;

  const basename = relative(COMMON_PATCHES, patchFile);
  return {
    file: patchFile,
    patchName: `common/${basename}`,
    packageName: pkgMatch[1].trim(),
    fixedVersion: verMatch[1].trim(),
  };
}

function getUpstreamVersions(
  packageName: string,
  lockfiles: string[]
): { lockfile: string; version: string }[] {
  const results: { lockfile: string; version: string }[] = [];

  for (const lockfile of lockfiles) {
    const lock = readJson(lockfile);
    const packages = lock.packages ?? {};

    for (const [key, value] of Object.entries(packages) as [string, any][]) {
      if (
        key === `node_modules/${packageName}` ||
        key.endsWith(`/node_modules/${packageName}`)
      ) {
        if (value.version) {
          results.push({
            lockfile: relative(ROOT, lockfile),
            version: value.version,
          });
        }
      }
    }
  }

  return results;
}

function runPrune(dryRun: boolean) {
  if (!existsSync(UPSTREAM_SRC)) {
    console.error("Error: third-party-src/ does not exist.");
    process.exit(1);
  }

  const patchFiles = existsSync(COMMON_PATCHES)
    ? readdirSync(COMMON_PATCHES)
        .filter(
          (f) => f.startsWith(PATCH_PREFIX) && f.endsWith(".diff")
        )
        .map((f) => join(COMMON_PATCHES, f))
    : [];

  if (patchFiles.length === 0) {
    console.log("No auto-generated finding override patches found.");
    return;
  }

  const upstreamLockfiles = findAllLockfiles(UPSTREAM_SRC);
  const seriesFiles = getSeriesFiles();
  let removedCount = 0;
  let keptCount = 0;

  console.log("=== Finding Override Patch Status ===\n");

  for (const patchFile of patchFiles) {
    const meta = parsePatchHeader(patchFile);
    if (!meta) {
      console.log(
        `SKIP: ${relative(PATCHES_DIR, patchFile)} (missing header fields)\n`
      );
      continue;
    }

    const upstreamVersions = getUpstreamVersions(
      meta.packageName,
      upstreamLockfiles
    );

    console.log(`${meta.patchName}`);
    console.log(`  Affected package: ${meta.packageName}`);
    console.log(`  Required fixed version: >= ${meta.fixedVersion}`);

    if (upstreamVersions.length === 0) {
      console.log(`  Upstream: package no longer present (removed upstream)`);
      if (dryRun) {
        console.log(`  → Would remove (package dropped upstream)\n`);
      } else {
        unlinkSync(patchFile);
        for (const sf of seriesFiles) {
          removeFromSeries(sf, meta.patchName);
        }
        console.log(
          `  → Removed patch, updated ${seriesFiles.length} series files\n`
        );
      }
      removedCount++;
      continue;
    }

    let allFixed = true;
    for (const uv of upstreamVersions) {
      const fixed = semver.gte(uv.version, meta.fixedVersion);
      const icon = fixed ? "✅" : "❌";
      console.log(
        `  ${uv.lockfile}: ${uv.version} (${icon} ${fixed ? ">=" : "<"} ${meta.fixedVersion})`
      );
      if (!fixed) allFixed = false;
    }

    if (allFixed) {
      if (dryRun) {
        console.log(`  → Would remove (upstream is fixed)\n`);
      } else {
        unlinkSync(patchFile);
        for (const sf of seriesFiles) {
          removeFromSeries(sf, meta.patchName);
        }
        console.log(
          `  → Removed patch, updated ${seriesFiles.length} series files\n`
        );
      }
      removedCount++;
    } else {
      console.log(`  → Kept (still needed)\n`);
      keptCount++;
    }
  }

  console.log(`=== Summary ===`);
  console.log(
    `${dryRun ? "Would remove" : "Removed"} ${removedCount} stale patch(es), kept ${keptCount} current patch(es).`
  );
  if (!dryRun && removedCount > 0) {
    console.log(`\nNext steps:`);
    console.log(
      `  1. Run update-package-locks.sh in Docker to regenerate lock files`
    );
    console.log(`  2. Verify build: ./scripts/prepare-src.sh <target>`);
  }
}

// ---------------------------------------------------------------------------
// CLI
// ---------------------------------------------------------------------------

function main() {
  const args = process.argv.slice(2);
  const command = args[0];

  if (!command || !["apply", "prune"].includes(command)) {
    console.error(
      `Usage:\n  npx ts-node ${SCRIPT_PATH} apply [--dry-run] <scan-result.json> ...\n  npx ts-node ${SCRIPT_PATH} prune [--dry-run]`
    );
    process.exit(1);
  }

  const rest = args.slice(1);
  const dryRun = rest.includes("--dry-run");
  const files = rest.filter((a) => a !== "--dry-run");

  if (command === "apply") {
    if (files.length === 0) {
      console.error("Error: At least one scan result file is required.");
      process.exit(1);
    }
    for (const f of files) {
      if (!existsSync(f)) {
        console.error(`Error: File not found: ${f}`);
        process.exit(1);
      }
    }
    runApply(files, dryRun);
  } else {
    runPrune(dryRun);
  }
}

main();
