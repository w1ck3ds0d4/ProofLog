# Changelog

All notable changes to ProofLog are documented here. The format is based on
[Keep a Changelog](https://keepachangelog.com/), and the project follows
semantic versioning.

## [Unreleased]
- Sqlite dependency modernization and evidence-claim corrections (#11)
- Standard actions: CI, security scan, monthly Dependabot (#13)

## [0.4.0] - v0.4
### Added
- Named regulator evidence export profiles (CRA, DORA, NIS2) (#7)
- MGA-gaming regulator profile plus the ProofSettle settlement-evidence demo (#9)
- Digital-evidence chain-of-custody profile and forensic positioning (#10)

## [0.3.0] - v0.3
### Added
- Asymmetric ECDSA P-256 signing for auditor-verifiable evidence (#6)

## [0.2.x]
### Added
- `Verify(expectedHead)` anchoring to detect chain truncation (#5)
- Drop-in dependency-injection and logging adoption helpers (#4)
- Optional HMAC signing, defeats a full-chain rewrite (#3)

## [0.1.0] - v0.1
### Added
- Hash-chained, identity-bound audit log with a SQLite store and `Verify()` (#1)
- Runnable demo and the NuGet release workflow (#2)
