# Security Policy

## Reporting a vulnerability

If you discover a security vulnerability in CSC, please report it responsibly.

**Do not open a public issue.**

Instead, use [GitHub Security Advisories](https://github.com/madeinplutofabio/command-scope-contract/security/advisories/new) to report vulnerabilities privately. This allows us to assess and address the issue before public disclosure.

Alternatively, you can email: fabio@madeinpluto.com

## What to include

- Description of the vulnerability
- Steps to reproduce
- Potential impact
- Suggested fix (if any)

## Response timeline

- Acknowledgment: within 48 hours
- Initial assessment: within 7 days
- Fix or mitigation: best effort, depending on severity

## Scope

This policy applies to the CSC specification, schemas, reference runner, and any official tooling in this repository.

## Important context

CSC is an execution-boundary protocol. The reference runner is a minimal implementation intended to validate protocol shape, not a production-hardened sandbox.

CSC does not itself provide container isolation, OS sandboxing, or network enforcement. Issues in those layers should also be reported to the appropriate underlying projects where relevant.
