/**
 * cisbench (TypeScript/Node port) — core passive evaluation engine.
 *
 * A declarative hardening checker that scores an offline inventory snapshot
 * (a settings JSON) against the cognis-db-baseline profile. Passive and
 * offline by design: it only reads the inventory you give it and never
 * connects to a database. The CDB-* control identifiers mirror the authored
 * Python baseline; they are not copied from any external benchmark document.
 */

import { readFileSync } from "node:fs";

export type Severity = "low" | "medium" | "high" | "critical";

const SEVERITY_WEIGHT: Record<string, number> = {
  low: 1,
  medium: 2,
  high: 3,
  critical: 4,
};

export interface Check {
  id: string;
  title: string;
  path: string;
  operator: string;
  expected?: unknown;
  reference?: string;
  severity: Severity;
  remediation?: string;
}

export interface Profile {
  name: string;
  version: string;
  description?: string;
  checks: Check[];
}

export interface Result {
  check: Check;
  passed: boolean;
  evidence: string;
}

export function weight(check: Check): number {
  return SEVERITY_WEIGHT[check.severity] ?? 2;
}

const MISSING = Symbol("missing");

export function resolvePath(inv: unknown, path: string): unknown {
  let cur: unknown = inv;
  for (const seg of path.split(".")) {
    if (cur !== null && typeof cur === "object" && !Array.isArray(cur)) {
      const obj = cur as Record<string, unknown>;
      if (!(seg in obj)) return MISSING;
      cur = obj[seg];
    } else if (Array.isArray(cur)) {
      const idx = Number(seg);
      if (!Number.isInteger(idx) || idx < 0 || idx >= cur.length) return MISSING;
      cur = cur[idx];
    } else {
      return MISSING;
    }
  }
  return cur;
}

function asNumber(v: unknown): number | undefined {
  if (typeof v === "number" && !Number.isNaN(v)) return v;
  return undefined;
}

function truthy(v: unknown): boolean {
  return Boolean(v);
}

const NO_EXPECTED = new Set(["is_true", "is_false", "present", "absent"]);

export function evaluateCheck(check: Check, inv: unknown): Result {
  const observed = resolvePath(inv, check.path);
  const present = observed !== MISSING;

  if (check.operator === "present") {
    return {
      check,
      passed: present,
      evidence: present
        ? `setting '${check.path}' is present`
        : `setting '${check.path}' is missing`,
    };
  }
  if (check.operator === "absent") {
    return {
      check,
      passed: !present,
      evidence: present
        ? `setting '${check.path}' is present but should be absent`
        : `setting '${check.path}' is absent (as required)`,
    };
  }

  if (!present) {
    return {
      check,
      passed: false,
      evidence: `setting '${check.path}' is missing; cannot satisfy '${check.operator}' (FAIL)`,
    };
  }

  const outcome = applyOperator(check.operator, observed, check.expected);
  if (outcome === undefined) {
    return {
      check,
      passed: false,
      evidence: `could not evaluate '${check.operator}' on '${check.path}'`,
    };
  }

  let evidence: string;
  if (NO_EXPECTED.has(check.operator)) {
    const verb = outcome ? "satisfies" : "violates";
    evidence = `'${check.path}' = ${JSON.stringify(observed)} (${verb} ${check.operator.replace(/_/g, " ")})`;
  } else {
    const rel = outcome ? "matches" : "does not match";
    evidence = `'${check.path}' = ${JSON.stringify(observed)} ${rel} expectation (${check.operator} ${JSON.stringify(check.expected)})`;
  }
  return { check, passed: outcome, evidence };
}

function applyOperator(
  op: string,
  v: unknown,
  e: unknown,
): boolean | undefined {
  switch (op) {
    case "equals":
      return v === e;
    case "not_equals":
      return v !== e;
    case "gte":
    case "lte":
    case "gt":
    case "lt": {
      const vn = asNumber(v);
      const en = asNumber(e);
      if (vn === undefined || en === undefined) return undefined;
      if (op === "gte") return vn >= en;
      if (op === "lte") return vn <= en;
      if (op === "gt") return vn > en;
      return vn < en;
    }
    case "is_true":
      return truthy(v);
    case "is_false":
      return !truthy(v);
    case "in":
      return Array.isArray(e) ? e.includes(v) : undefined;
    case "not_in":
      return Array.isArray(e) ? !e.includes(v) : undefined;
    case "contains":
      if (Array.isArray(v)) return v.includes(e);
      if (typeof v === "string" && typeof e === "string") return v.includes(e);
      return undefined;
    case "not_contains": {
      const r = applyOperator("contains", v, e);
      return r === undefined ? undefined : !r;
    }
    default:
      return undefined;
  }
}

export interface Report {
  profile: Profile;
  results: Result[];
}

export function scan(profile: Profile, inv: unknown): Report {
  return { profile, results: profile.checks.map((c) => evaluateCheck(c, inv)) };
}

function round1(n: number): number {
  return Math.round(n * 10) / 10;
}

export function total(r: Report): number {
  return r.results.length;
}
export function passedCount(r: Report): number {
  return r.results.filter((x) => x.passed).length;
}
export function failedCount(r: Report): number {
  return total(r) - passedCount(r);
}
export function score(r: Report): number {
  return total(r) === 0 ? 0 : round1((100 * passedCount(r)) / total(r));
}
export function weightedScore(r: Report): number {
  const tw = r.results.reduce((s, x) => s + weight(x.check), 0);
  if (tw === 0) return 0;
  const earned = r.results
    .filter((x) => x.passed)
    .reduce((s, x) => s + weight(x.check), 0);
  return round1((100 * earned) / tw);
}

export function reportToObject(r: Report): Record<string, unknown> {
  return {
    profile: r.profile.name,
    profile_version: r.profile.version,
    summary: {
      total: total(r),
      passed: passedCount(r),
      failed: failedCount(r),
      score: score(r),
      weighted_score: weightedScore(r),
    },
    results: r.results.map((x) => ({
      id: x.check.id,
      title: x.check.title,
      severity: x.check.severity,
      status: x.passed ? "PASS" : "FAIL",
      evidence: x.evidence,
    })),
  };
}

export function loadInventory(path: string): unknown {
  const raw = readFileSync(path, "utf-8");
  const data = JSON.parse(raw);
  if (
    data &&
    typeof data === "object" &&
    !Array.isArray(data) &&
    "settings" in data &&
    typeof (data as Record<string, unknown>).settings === "object"
  ) {
    return (data as Record<string, unknown>).settings;
  }
  return data;
}
