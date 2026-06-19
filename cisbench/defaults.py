"""Built-in default hardening profile for cisbench.

All check titles, descriptions, references, and remediation text below are
original wording authored for cisbench. The control identifiers use the
"CDB" (Cognis Database Baseline) namespace and are our own scheme; they are
not copied from any external benchmark document.

The checks target generic, vendor-neutral database configuration concepts.
"""

DEFAULT_PROFILE = {
    "name": "cognis-db-baseline",
    "version": "1.0",
    "description": (
        "Cognis Database Baseline: a vendor-neutral set of offline "
        "configuration-hardening checks for relational database deployments."
    ),
    "checks": [
        {
            "id": "CDB-1.1",
            "title": "Transport encryption is required for client connections",
            "path": "network.require_tls",
            "operator": "is_true",
            "reference": "CDB-NET-1",
            "severity": "critical",
            "description": (
                "Client-to-server traffic should be encrypted in transit so "
                "credentials and query payloads are not exposed on the wire."
            ),
            "remediation": (
                "Enable mandatory TLS for all client connections and reject "
                "plaintext sessions at the listener."
            ),
        },
        {
            "id": "CDB-1.2",
            "title": "Minimum TLS protocol version is 1.2 or higher",
            "path": "network.min_tls_version",
            "operator": "gte",
            "expected": 1.2,
            "reference": "CDB-NET-2",
            "severity": "high",
            "description": (
                "Legacy TLS and SSL versions contain known weaknesses and "
                "should be disabled in favour of TLS 1.2 or newer."
            ),
            "remediation": (
                "Configure the database listener to negotiate only TLS 1.2 "
                "or higher and remove support for SSLv3/TLS 1.0/1.1."
            ),
        },
        {
            "id": "CDB-2.1",
            "title": "Password minimum length meets baseline",
            "path": "auth.password_min_length",
            "operator": "gte",
            "expected": 14,
            "reference": "CDB-AUTH-1",
            "severity": "high",
            "description": (
                "Account passwords should meet a minimum length to resist "
                "brute-force and guessing attacks."
            ),
            "remediation": (
                "Set the password policy minimum length to at least 14 "
                "characters for all database accounts."
            ),
        },
        {
            "id": "CDB-2.2",
            "title": "Password complexity enforcement is enabled",
            "path": "auth.password_complexity_enabled",
            "operator": "is_true",
            "reference": "CDB-AUTH-2",
            "severity": "medium",
            "description": (
                "Complexity rules reduce the prevalence of trivially "
                "guessable account passwords."
            ),
            "remediation": (
                "Enable password complexity enforcement so new passwords must "
                "include mixed character classes."
            ),
        },
        {
            "id": "CDB-2.3",
            "title": "Failed-login lockout threshold is configured",
            "path": "auth.failed_login_lockout_threshold",
            "operator": "lte",
            "expected": 10,
            "reference": "CDB-AUTH-3",
            "severity": "medium",
            "description": (
                "Locking accounts after repeated failures slows online "
                "password-guessing campaigns."
            ),
            "remediation": (
                "Set the failed-login lockout threshold to 10 attempts or "
                "fewer before the account is temporarily locked."
            ),
        },
        {
            "id": "CDB-3.1",
            "title": "Audit logging is enabled",
            "path": "audit.logging_enabled",
            "operator": "is_true",
            "reference": "CDB-AUD-1",
            "severity": "high",
            "description": (
                "An audit trail of administrative and security-relevant "
                "events is needed for detection and forensics."
            ),
            "remediation": (
                "Enable database audit logging so privileged operations and "
                "authentication events are recorded."
            ),
        },
        {
            "id": "CDB-3.2",
            "title": "Audit log retention meets baseline",
            "path": "audit.retention_days",
            "operator": "gte",
            "expected": 90,
            "reference": "CDB-AUD-2",
            "severity": "medium",
            "description": (
                "Audit records must be retained long enough to support "
                "incident investigation."
            ),
            "remediation": (
                "Configure audit log retention to at least 90 days, or longer "
                "where policy requires."
            ),
        },
        {
            "id": "CDB-4.1",
            "title": "Anonymous or guest login is disabled",
            "path": "auth.anonymous_login_enabled",
            "operator": "is_false",
            "reference": "CDB-ACC-1",
            "severity": "critical",
            "description": (
                "Unauthenticated or guest access removes accountability and "
                "should never be permitted on a hardened deployment."
            ),
            "remediation": (
                "Disable anonymous and guest login so every session is tied "
                "to an authenticated principal."
            ),
        },
        {
            "id": "CDB-4.2",
            "title": "Default administrative account has been renamed",
            "path": "accounts.default_admin_renamed",
            "operator": "is_true",
            "reference": "CDB-ACC-2",
            "severity": "medium",
            "description": (
                "Renaming the well-known default administrator account raises "
                "the bar for targeted credential attacks."
            ),
            "remediation": (
                "Rename the default administrative account from its shipped "
                "name and disable the original where possible."
            ),
        },
        {
            "id": "CDB-5.1",
            "title": "Listener is not bound to all interfaces",
            "path": "network.bind_address",
            "operator": "not_equals",
            "expected": "0.0.0.0",
            "reference": "CDB-NET-3",
            "severity": "high",
            "description": (
                "Binding to all interfaces can needlessly expose the "
                "database to untrusted networks."
            ),
            "remediation": (
                "Bind the listener to specific trusted interfaces rather than "
                "0.0.0.0, and restrict access with a firewall."
            ),
        },
        {
            "id": "CDB-6.1",
            "title": "Data-at-rest encryption is enabled",
            "path": "storage.encryption_at_rest",
            "operator": "is_true",
            "reference": "CDB-DAT-1",
            "severity": "high",
            "description": (
                "Encrypting stored data protects confidentiality if storage "
                "media or backups are exposed."
            ),
            "remediation": (
                "Enable transparent data-at-rest encryption for data files "
                "and backups."
            ),
        },
        {
            "id": "CDB-7.1",
            "title": "Verbose error messages are not exposed to clients",
            "path": "diagnostics.verbose_client_errors",
            "operator": "is_false",
            "reference": "CDB-DIA-1",
            "severity": "low",
            "description": (
                "Detailed internal error messages can leak schema and "
                "configuration details useful to an attacker."
            ),
            "remediation": (
                "Disable verbose client-facing error messages and route "
                "detailed diagnostics to server-side logs only."
            ),
        },
    ],
}
