/**
 * The cognis-db-baseline profile. CDB-* identifiers and wording mirror the
 * authored Python baseline (defaults.py); they are not copied from any
 * external benchmark document.
 */
import type { Profile } from "./cisbench.ts";

export function builtinProfile(): Profile {
  return {
    name: "cognis-db-baseline",
    version: "1.0",
    description:
      "Cognis Database Baseline: a vendor-neutral set of offline " +
      "configuration-hardening checks for relational databases.",
    checks: [
      {
        id: "CDB-1.1",
        title: "Transport encryption is required for client connections",
        path: "network.require_tls",
        operator: "is_true",
        reference: "CDB-NET-1",
        severity: "critical",
        remediation: "Enable mandatory TLS for all client connections.",
      },
      {
        id: "CDB-1.2",
        title: "Minimum TLS protocol version is 1.2 or higher",
        path: "network.min_tls_version",
        operator: "gte",
        expected: 1.2,
        reference: "CDB-NET-2",
        severity: "high",
        remediation: "Negotiate only TLS 1.2 or newer.",
      },
      {
        id: "CDB-2.1",
        title: "Password minimum length meets baseline",
        path: "auth.password_min_length",
        operator: "gte",
        expected: 14,
        reference: "CDB-AUTH-1",
        severity: "high",
        remediation: "Set the password minimum length to at least 14.",
      },
      {
        id: "CDB-2.2",
        title: "Password complexity enforcement is enabled",
        path: "auth.password_complexity_enabled",
        operator: "is_true",
        reference: "CDB-AUTH-2",
        severity: "medium",
        remediation: "Enable password complexity enforcement.",
      },
      {
        id: "CDB-2.3",
        title: "Failed-login lockout threshold is configured",
        path: "auth.failed_login_lockout_threshold",
        operator: "lte",
        expected: 10,
        reference: "CDB-AUTH-3",
        severity: "medium",
        remediation: "Set the failed-login lockout threshold to 10 or fewer.",
      },
      {
        id: "CDB-3.1",
        title: "Audit logging is enabled",
        path: "audit.logging_enabled",
        operator: "is_true",
        reference: "CDB-AUD-1",
        severity: "high",
        remediation: "Enable database audit logging.",
      },
      {
        id: "CDB-3.2",
        title: "Audit log retention meets baseline",
        path: "audit.retention_days",
        operator: "gte",
        expected: 90,
        reference: "CDB-AUD-2",
        severity: "medium",
        remediation: "Retain audit logs for at least 90 days.",
      },
      {
        id: "CDB-4.1",
        title: "Anonymous or guest login is disabled",
        path: "auth.anonymous_login_enabled",
        operator: "is_false",
        reference: "CDB-ACC-1",
        severity: "critical",
        remediation: "Disable anonymous and guest login.",
      },
      {
        id: "CDB-4.2",
        title: "Default administrative account has been renamed",
        path: "accounts.default_admin_renamed",
        operator: "is_true",
        reference: "CDB-ACC-2",
        severity: "medium",
        remediation: "Rename the default administrative account.",
      },
      {
        id: "CDB-5.1",
        title: "Listener is not bound to all interfaces",
        path: "network.bind_address",
        operator: "not_equals",
        expected: "0.0.0.0",
        reference: "CDB-NET-3",
        severity: "high",
        remediation: "Bind the listener to specific trusted interfaces.",
      },
      {
        id: "CDB-6.1",
        title: "Data-at-rest encryption is enabled",
        path: "storage.encryption_at_rest",
        operator: "is_true",
        reference: "CDB-DAT-1",
        severity: "high",
        remediation: "Enable transparent data-at-rest encryption.",
      },
      {
        id: "CDB-7.1",
        title: "Verbose error messages are not exposed to clients",
        path: "diagnostics.verbose_client_errors",
        operator: "is_false",
        reference: "CDB-DIA-1",
        severity: "low",
        remediation: "Disable verbose client-facing error messages.",
      },
    ],
  };
}
