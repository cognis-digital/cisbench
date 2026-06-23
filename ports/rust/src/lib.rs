//! cisbench (Rust port) — core passive evaluation engine.
//!
//! Declarative hardening checks evaluated against an offline inventory
//! snapshot (a settings JSON), producing a plain and a severity-weighted
//! score. Passive and offline by design: it only reads the inventory you give
//! it and never connects to a database. The CDB-* control identifiers mirror
//! the authored Python baseline; they are not copied from any external
//! benchmark document.

use serde::{Deserialize, Serialize};
use serde_json::Value;

pub mod baseline;

/// One declarative hardening expectation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Check {
    pub id: String,
    pub title: String,
    pub path: String,
    pub operator: String,
    #[serde(default)]
    pub expected: Value,
    #[serde(default)]
    pub reference: String,
    pub severity: String,
    #[serde(default)]
    pub remediation: String,
}

impl Check {
    /// Severity-derived weight (default medium=2).
    pub fn weight(&self) -> u32 {
        match self.severity.as_str() {
            "low" => 1,
            "medium" => 2,
            "high" => 3,
            "critical" => 4,
            _ => 2,
        }
    }
}

/// A named, ordered collection of checks.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Profile {
    pub name: String,
    pub version: String,
    #[serde(default)]
    pub description: String,
    pub checks: Vec<Check>,
}

/// Outcome of evaluating one check.
#[derive(Debug, Clone)]
pub struct CheckResult {
    pub check: Check,
    pub passed: bool,
    pub evidence: String,
}

/// Aggregate of scanning a profile against an inventory.
pub struct Report {
    pub profile: Profile,
    pub results: Vec<CheckResult>,
}

impl Report {
    pub fn total(&self) -> usize {
        self.results.len()
    }
    pub fn passed(&self) -> usize {
        self.results.iter().filter(|r| r.passed).count()
    }
    pub fn failed(&self) -> usize {
        self.total() - self.passed()
    }
    pub fn score(&self) -> f64 {
        if self.total() == 0 {
            return 0.0;
        }
        round1(100.0 * self.passed() as f64 / self.total() as f64)
    }
    pub fn weighted_score(&self) -> f64 {
        let total: u32 = self.results.iter().map(|r| r.check.weight()).sum();
        if total == 0 {
            return 0.0;
        }
        let earned: u32 = self
            .results
            .iter()
            .filter(|r| r.passed)
            .map(|r| r.check.weight())
            .sum();
        round1(100.0 * earned as f64 / total as f64)
    }
}

fn round1(f: f64) -> f64 {
    (f * 10.0).round() / 10.0
}

/// Resolve a dotted path against the inventory, returning None when absent.
pub fn resolve_path<'a>(inv: &'a Value, path: &str) -> Option<&'a Value> {
    let mut cur = inv;
    for seg in path.split('.') {
        match cur {
            Value::Object(map) => {
                cur = map.get(seg)?;
            }
            Value::Array(arr) => {
                let idx: usize = seg.parse().ok()?;
                cur = arr.get(idx)?;
            }
            _ => return None,
        }
    }
    Some(cur)
}

fn as_number(v: &Value) -> Option<f64> {
    if v.is_boolean() {
        return None;
    }
    v.as_f64()
}

fn truthy(v: &Value) -> bool {
    match v {
        Value::Bool(b) => *b,
        Value::Null => false,
        Value::Number(n) => n.as_f64().map(|f| f != 0.0).unwrap_or(true),
        Value::String(s) => !s.is_empty(),
        Value::Array(a) => !a.is_empty(),
        Value::Object(o) => !o.is_empty(),
    }
}

/// Evaluate one check against an inventory snapshot.
pub fn evaluate_check(check: &Check, inv: &Value) -> CheckResult {
    let observed = resolve_path(inv, &check.path);
    let present = observed.is_some();

    if check.operator == "present" {
        let ev = if present {
            format!("setting '{}' is present", check.path)
        } else {
            format!("setting '{}' is missing", check.path)
        };
        return CheckResult { check: check.clone(), passed: present, evidence: ev };
    }
    if check.operator == "absent" {
        let ev = if present {
            format!("setting '{}' is present but should be absent", check.path)
        } else {
            format!("setting '{}' is absent (as required)", check.path)
        };
        return CheckResult { check: check.clone(), passed: !present, evidence: ev };
    }

    let observed = match observed {
        Some(v) => v,
        None => {
            return CheckResult {
                check: check.clone(),
                passed: false,
                evidence: format!(
                    "setting '{}' is missing; cannot satisfy '{}' (FAIL)",
                    check.path, check.operator
                ),
            }
        }
    };

    match apply_operator(&check.operator, observed, &check.expected) {
        None => CheckResult {
            check: check.clone(),
            passed: false,
            evidence: format!(
                "could not evaluate '{}' on '{}'",
                check.operator, check.path
            ),
        },
        Some(passed) => {
            let ev = if matches!(check.operator.as_str(), "is_true" | "is_false") {
                let verb = if passed { "satisfies" } else { "violates" };
                format!(
                    "'{}' = {} ({} {})",
                    check.path,
                    observed,
                    verb,
                    check.operator.replace('_', " ")
                )
            } else {
                let rel = if passed { "matches" } else { "does not match" };
                format!(
                    "'{}' = {} {} expectation ({} {})",
                    check.path, observed, rel, check.operator, check.expected
                )
            };
            CheckResult { check: check.clone(), passed, evidence: ev }
        }
    }
}

fn apply_operator(op: &str, v: &Value, e: &Value) -> Option<bool> {
    match op {
        "equals" => Some(values_equal(v, e)),
        "not_equals" => Some(!values_equal(v, e)),
        "gte" | "lte" | "gt" | "lt" => {
            let vn = as_number(v)?;
            let en = as_number(e)?;
            Some(match op {
                "gte" => vn >= en,
                "lte" => vn <= en,
                "gt" => vn > en,
                _ => vn < en,
            })
        }
        "is_true" => Some(truthy(v)),
        "is_false" => Some(!truthy(v)),
        "in" => e.as_array().map(|arr| arr.iter().any(|x| values_equal(v, x))),
        "not_in" => e
            .as_array()
            .map(|arr| !arr.iter().any(|x| values_equal(v, x))),
        "contains" => {
            if let Some(arr) = v.as_array() {
                Some(arr.iter().any(|x| values_equal(x, e)))
            } else if let (Some(s), Some(es)) = (v.as_str(), e.as_str()) {
                Some(s.contains(es))
            } else {
                None
            }
        }
        "not_contains" => apply_operator("contains", v, e).map(|b| !b),
        _ => None,
    }
}

fn values_equal(a: &Value, b: &Value) -> bool {
    if let (Some(an), Some(bn)) = (a.as_f64(), b.as_f64()) {
        return an == bn;
    }
    a == b
}

/// Evaluate every check in the profile against the inventory.
pub fn scan(profile: &Profile, inv: &Value) -> Report {
    let results = profile
        .checks
        .iter()
        .map(|c| evaluate_check(c, inv))
        .collect();
    Report { profile: profile.clone(), results }
}

/// Load an inventory snapshot, unwrapping an optional top-level `settings`.
pub fn load_inventory(path: &str) -> Result<Value, String> {
    let raw = std::fs::read_to_string(path)
        .map_err(|_| format!("inventory file not found: {path}"))?;
    let data: Value = serde_json::from_str(&raw)
        .map_err(|e| format!("inventory is not valid JSON: {e}"))?;
    if let Some(settings) = data.get("settings") {
        if settings.is_object() {
            return Ok(settings.clone());
        }
    }
    Ok(data)
}

/// Render the report as the same JSON shape the Python tool emits.
pub fn report_to_json(report: &Report) -> Value {
    let results: Vec<Value> = report
        .results
        .iter()
        .map(|r| {
            serde_json::json!({
                "id": r.check.id,
                "title": r.check.title,
                "severity": r.check.severity,
                "status": if r.passed { "PASS" } else { "FAIL" },
                "evidence": r.evidence,
            })
        })
        .collect();
    serde_json::json!({
        "profile": report.profile.name,
        "profile_version": report.profile.version,
        "summary": {
            "total": report.total(),
            "passed": report.passed(),
            "failed": report.failed(),
            "score": report.score(),
            "weighted_score": report.weighted_score(),
        },
        "results": results,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::baseline::builtin_profile;
    use serde_json::json;

    #[test]
    fn builtin_has_12_checks() {
        assert_eq!(builtin_profile().checks.len(), 12);
    }

    #[test]
    fn is_true_operator() {
        let c = Check {
            id: "x".into(),
            title: "t".into(),
            path: "network.require_tls".into(),
            operator: "is_true".into(),
            expected: Value::Null,
            reference: String::new(),
            severity: "critical".into(),
            remediation: String::new(),
        };
        assert!(evaluate_check(&c, &json!({"network":{"require_tls":true}})).passed);
        assert!(!evaluate_check(&c, &json!({"network":{"require_tls":false}})).passed);
    }

    #[test]
    fn gte_and_missing() {
        let c = Check {
            id: "x".into(),
            title: "t".into(),
            path: "auth.len".into(),
            operator: "gte".into(),
            expected: json!(14),
            reference: String::new(),
            severity: "high".into(),
            remediation: String::new(),
        };
        assert!(evaluate_check(&c, &json!({"auth":{"len":16}})).passed);
        assert!(!evaluate_check(&c, &json!({"auth":{"len":8}})).passed);
        assert!(!evaluate_check(&c, &json!({"auth":{}})).passed);
    }

    #[test]
    fn not_equals_bind_address() {
        let c = Check {
            id: "x".into(),
            title: "t".into(),
            path: "b".into(),
            operator: "not_equals".into(),
            expected: json!("0.0.0.0"),
            reference: String::new(),
            severity: "high".into(),
            remediation: String::new(),
        };
        assert!(evaluate_check(&c, &json!({"b":"10.0.0.1"})).passed);
        assert!(!evaluate_check(&c, &json!({"b":"0.0.0.0"})).passed);
    }

    #[test]
    fn resolve_nested_and_index() {
        let inv = json!({"a":{"b":{"c":5}}, "u":[{"n":"x"},{"n":"y"}]});
        assert_eq!(resolve_path(&inv, "a.b.c"), Some(&json!(5)));
        assert_eq!(resolve_path(&inv, "u.1.n"), Some(&json!("y")));
        assert_eq!(resolve_path(&inv, "a.z"), None);
    }

    #[test]
    fn hardened_scores_100() {
        let inv = json!({
            "network":{"require_tls":true,"min_tls_version":1.3,"bind_address":"10.0.0.5"},
            "auth":{"password_min_length":16,"password_complexity_enabled":true,
                    "failed_login_lockout_threshold":5,"anonymous_login_enabled":false},
            "audit":{"logging_enabled":true,"retention_days":365},
            "accounts":{"default_admin_renamed":true},
            "storage":{"encryption_at_rest":true},
            "diagnostics":{"verbose_client_errors":false}
        });
        let r = scan(&builtin_profile(), &inv);
        assert_eq!(r.score(), 100.0);
        assert_eq!(r.failed(), 0);
    }

    #[test]
    fn partial_weighted_score() {
        let r = scan(&builtin_profile(), &json!({"network":{"require_tls":true}}));
        assert_eq!(r.passed(), 1);
        assert!(r.weighted_score() > 0.0 && r.weighted_score() < 100.0);
    }
}
