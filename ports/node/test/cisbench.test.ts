import { test } from "node:test";
import assert from "node:assert/strict";
import {
  evaluateCheck,
  resolvePath,
  scan,
  score,
  weightedScore,
  failedCount,
  passedCount,
  reportToObject,
  type Check,
} from "../src/cisbench.ts";
import { builtinProfile } from "../src/baseline.ts";

const HARDENED = {
  network: { require_tls: true, min_tls_version: 1.3, bind_address: "10.0.0.5" },
  auth: {
    password_min_length: 16,
    password_complexity_enabled: true,
    failed_login_lockout_threshold: 5,
    anonymous_login_enabled: false,
  },
  audit: { logging_enabled: true, retention_days: 365 },
  accounts: { default_admin_renamed: true },
  storage: { encryption_at_rest: true },
  diagnostics: { verbose_client_errors: false },
};

test("builtin profile has 12 checks", () => {
  assert.equal(builtinProfile().checks.length, 12);
});

test("resolvePath resolves nested + list index", () => {
  assert.equal(resolvePath({ a: { b: { c: 5 } } }, "a.b.c"), 5);
  assert.equal(resolvePath({ u: [{ n: "x" }, { n: "y" }] }, "u.1.n"), "y");
});

test("is_true operator", () => {
  const c: Check = { id: "x", title: "t", path: "f", operator: "is_true", severity: "critical" };
  assert.equal(evaluateCheck(c, { f: true }).passed, true);
  assert.equal(evaluateCheck(c, { f: false }).passed, false);
});

test("gte operator and missing fails", () => {
  const c: Check = { id: "x", title: "t", path: "a.len", operator: "gte", expected: 14, severity: "high" };
  assert.equal(evaluateCheck(c, { a: { len: 16 } }).passed, true);
  assert.equal(evaluateCheck(c, { a: { len: 8 } }).passed, false);
  assert.equal(evaluateCheck(c, { a: {} }).passed, false);
});

test("not_equals bind address", () => {
  const c: Check = { id: "x", title: "t", path: "b", operator: "not_equals", expected: "0.0.0.0", severity: "high" };
  assert.equal(evaluateCheck(c, { b: "10.0.0.1" }).passed, true);
  assert.equal(evaluateCheck(c, { b: "0.0.0.0" }).passed, false);
});

test("hardened inventory scores 100", () => {
  const r = scan(builtinProfile(), HARDENED);
  assert.equal(score(r), 100.0);
  assert.equal(failedCount(r), 0);
});

test("partial inventory yields partial weighted score", () => {
  const r = scan(builtinProfile(), { network: { require_tls: true } });
  assert.equal(passedCount(r), 1);
  assert.ok(weightedScore(r) > 0 && weightedScore(r) < 100);
});

test("report object shape mirrors python", () => {
  const r = scan(builtinProfile(), { network: { require_tls: true } });
  const obj = reportToObject(r) as any;
  assert.equal(obj.profile, "cognis-db-baseline");
  assert.equal(obj.summary.total, 12);
  assert.equal(obj.results.length, 12);
});
