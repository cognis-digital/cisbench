#!/usr/bin/env node
/**
 * cisbench CLI (TypeScript/Node port). Mirrors the passive `scan` and `list`
 * surface of the Python reference tool. Passive and offline only.
 *
 *   cisbench scan <inventory.json> [--json]
 *   cisbench list [--json]
 */
import { pathToFileURL } from "node:url";
import {
  loadInventory,
  scan,
  reportToObject,
  score,
  weightedScore,
  total,
  passedCount,
} from "./cisbench.ts";
import { builtinProfile } from "./baseline.ts";

export function run(argv: string[]): number {
  if (argv.length === 0) {
    process.stderr.write("usage: cisbench <scan|list> [args]\n");
    return 2;
  }
  const jsonOut = argv.includes("--json");
  const positional = argv.slice(1).filter((a) => !a.startsWith("--"));
  const cmd = argv[0];

  if (cmd === "list") {
    const prof = builtinProfile();
    if (jsonOut) {
      process.stdout.write(JSON.stringify(prof, null, 2) + "\n");
      return 0;
    }
    process.stdout.write(
      `Profile: ${prof.name} (v${prof.version}) - ${prof.checks.length} checks\n`,
    );
    for (const c of prof.checks) {
      process.stdout.write(
        `${c.id.padEnd(10)} [${c.severity.padEnd(8)}] ${c.title}\n`,
      );
    }
    return 0;
  }

  if (cmd === "scan") {
    if (positional.length < 1) {
      process.stderr.write("error: scan requires an inventory path\n");
      return 2;
    }
    let inv: unknown;
    try {
      inv = loadInventory(positional[0]);
    } catch (e) {
      process.stderr.write(`error: ${(e as Error).message}\n`);
      return 2;
    }
    const report = scan(builtinProfile(), inv);
    if (jsonOut) {
      process.stdout.write(JSON.stringify(reportToObject(report), null, 2) + "\n");
    } else {
      process.stdout.write(
        `\ncisbench scan - profile: ${report.profile.name} (v${report.profile.version})\n`,
      );
      process.stdout.write("=".repeat(72) + "\n");
      for (const r of report.results) {
        const status = r.passed ? "PASS" : "FAIL";
        process.stdout.write(`[${status}] ${r.check.id.padEnd(8)} ${r.check.title}\n`);
        process.stdout.write(`        evidence: ${r.evidence}\n`);
      }
      process.stdout.write("-".repeat(72) + "\n");
      process.stdout.write(
        `${passedCount(report)}/${total(report)} passed  |  score ${score(report).toFixed(1)}%  |  weighted ${weightedScore(report).toFixed(1)}%\n`,
      );
    }
    return 0;
  }

  process.stderr.write(`unknown command ${cmd}\n`);
  return 2;
}

// Only auto-run when invoked as the entry script (cross-platform check).
if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  process.exit(run(process.argv.slice(2)));
}
