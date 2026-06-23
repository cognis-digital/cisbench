//! The cognis-db-baseline profile. CDB-* identifiers and wording mirror the
//! authored Python baseline (defaults.py); they are not copied from any
//! external benchmark document.

use crate::{Check, Profile};
use serde_json::{json, Value};

fn check(id: &str, title: &str, path: &str, op: &str, expected: Value,
         reference: &str, severity: &str, remediation: &str) -> Check {
    Check {
        id: id.into(),
        title: title.into(),
        path: path.into(),
        operator: op.into(),
        expected,
        reference: reference.into(),
        severity: severity.into(),
        remediation: remediation.into(),
    }
}

/// Return the built-in cognis-db-baseline profile (12 checks).
pub fn builtin_profile() -> Profile {
    Profile {
        name: "cognis-db-baseline".into(),
        version: "1.0".into(),
        description:
            "Cognis Database Baseline: a vendor-neutral set of offline \
             configuration-hardening checks for relational databases."
                .into(),
        checks: vec![
            check("CDB-1.1", "Transport encryption is required for client connections",
                  "network.require_tls", "is_true", Value::Null, "CDB-NET-1",
                  "critical", "Enable mandatory TLS for all client connections."),
            check("CDB-1.2", "Minimum TLS protocol version is 1.2 or higher",
                  "network.min_tls_version", "gte", json!(1.2), "CDB-NET-2",
                  "high", "Negotiate only TLS 1.2 or newer."),
            check("CDB-2.1", "Password minimum length meets baseline",
                  "auth.password_min_length", "gte", json!(14), "CDB-AUTH-1",
                  "high", "Set the password minimum length to at least 14."),
            check("CDB-2.2", "Password complexity enforcement is enabled",
                  "auth.password_complexity_enabled", "is_true", Value::Null,
                  "CDB-AUTH-2", "medium", "Enable password complexity enforcement."),
            check("CDB-2.3", "Failed-login lockout threshold is configured",
                  "auth.failed_login_lockout_threshold", "lte", json!(10),
                  "CDB-AUTH-3", "medium",
                  "Set the failed-login lockout threshold to 10 or fewer."),
            check("CDB-3.1", "Audit logging is enabled",
                  "audit.logging_enabled", "is_true", Value::Null, "CDB-AUD-1",
                  "high", "Enable database audit logging."),
            check("CDB-3.2", "Audit log retention meets baseline",
                  "audit.retention_days", "gte", json!(90), "CDB-AUD-2",
                  "medium", "Retain audit logs for at least 90 days."),
            check("CDB-4.1", "Anonymous or guest login is disabled",
                  "auth.anonymous_login_enabled", "is_false", Value::Null,
                  "CDB-ACC-1", "critical", "Disable anonymous and guest login."),
            check("CDB-4.2", "Default administrative account has been renamed",
                  "accounts.default_admin_renamed", "is_true", Value::Null,
                  "CDB-ACC-2", "medium", "Rename the default administrative account."),
            check("CDB-5.1", "Listener is not bound to all interfaces",
                  "network.bind_address", "not_equals", json!("0.0.0.0"),
                  "CDB-NET-3", "high",
                  "Bind the listener to specific trusted interfaces."),
            check("CDB-6.1", "Data-at-rest encryption is enabled",
                  "storage.encryption_at_rest", "is_true", Value::Null,
                  "CDB-DAT-1", "high", "Enable transparent data-at-rest encryption."),
            check("CDB-7.1", "Verbose error messages are not exposed to clients",
                  "diagnostics.verbose_client_errors", "is_false", Value::Null,
                  "CDB-DIA-1", "low",
                  "Disable verbose client-facing error messages."),
        ],
    }
}
