# Security Policy

## Supported Versions

| Version | Supported          |
|---------|--------------------|
| latest  | Yes                |
| < latest| No                 |

## Reporting a Vulnerability

If you discover a security vulnerability in Clone, please report it responsibly.

**Do NOT open a public GitHub issue for security vulnerabilities.**

To report a vulnerability, use GitHub's private vulnerability reporting:
https://github.com/unixshells/clone/security/advisories/new

Include:
- Description of the vulnerability
- Steps to reproduce
- Potential impact
- Suggested fix (if any)

We aim to release a fix within 7 days for critical issues.

## Scope

Clone is a VMM that provides KVM hardware isolation. Security issues in the following areas are especially critical:

- **VM escape** -- guest accessing host memory or resources outside its boundary
- **Privilege escalation** -- unprivileged user gaining root through Clone
- **Memory safety** -- use-after-free, buffer overflow, or other memory corruption
- **Denial of service** -- crashing the VMM or host from within a guest
- **Information disclosure** -- guest reading other guests' or host's memory
