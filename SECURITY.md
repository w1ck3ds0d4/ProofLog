# Security Policy

## Reporting a vulnerability

Please report security vulnerabilities privately through GitHub's
**private vulnerability reporting**: open the repository's **Security** tab and
choose **Report a vulnerability** (Security Advisories). This keeps the report
confidential until a fix is available.

Please do not open a public issue for security problems.

ProofLog is an audit-evidence library, so cryptographic soundness reports are
especially welcome: hash-chain canonicalization, signing (HMAC / ECDSA),
verification logic, and anything that could let a forged or altered record pass
`Verify()`.

## What to expect

This is a solo-maintained project. Reports are triaged weekly; acknowledgement
within a few business days, and a coordinated disclosure timeline agreed with
you once triaged. Fixes ship as a new NuGet release with the advisory published
after users have had a reasonable window to update.

## Scope

The `ProofLog` library (`src/ProofLog`), its samples, and its release pipeline
in this repository.
