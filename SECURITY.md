# Security Policy

## Supported Versions

| Version | Supported |
|---------|-----------|
| 0.1.x   | Yes       |

## Reporting a Vulnerability

**Do not open a public GitHub issue for security vulnerabilities.**

Instead, please report via [GitHub Security Advisories](https://github.com/nichochar/closedshell/security/advisories/new).

### What qualifies as a security issue

- Sandbox escapes (processes bypassing Seatbelt restrictions)
- Proxy bypasses (traffic reaching the network without passing through the MITM proxy)
- Permission tree violations (actions allowed despite explicit forbid rules)
- TLS interception flaws (certificate validation issues, key leakage)
- Judge manipulation (prompt injection causing incorrect permit/deny decisions)

### Response Timeline

- **72 hours**: Initial acknowledgment
- **7 days**: Assessment and severity classification
- **30 days**: Fix or mitigation for critical issues

### Disclosure

We follow coordinated disclosure. We'll work with you on timing and credit you in the advisory unless you prefer otherwise.
