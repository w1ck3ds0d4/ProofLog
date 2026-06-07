# ProofLog

**A tamper-evident, identity-bound audit-log SDK.**

ProofLog is hash-chained, queryable, evidence-grade logging for systems that must prove who did what, when, to an auditor - the kind of record regulations like the CRA, DORA, NIS2, and the EU AI Act (Article 12) increasingly require. It is drop-in, OpenTelemetry-friendly, and ships a one-call regulator-ready evidence export.

It is the open-source credibility core of the CRADesk line and the immutable evidence store inside [CRADesk](https://github.com/w1ck3ds0d4/CRADesk).

---

## Tech stack

| Layer | Technology |
| --- | --- |
| v1 | .NET 8 (NuGet) |
| v2 | Rust core |
| Store | SQLite |

---

## Roadmap

- **v0.1** - core append + hash-chain + verify, SQLite store, tamper-detection tests.
- **Later** - OpenTelemetry bridge, additional stores, regulator-ready export profiles, Rust core.

---

## Status

Specced, early. v0.1 in progress.
