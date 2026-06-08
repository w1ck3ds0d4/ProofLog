# ProofLog

**A tamper-evident, identity-bound audit-log SDK.**

ProofLog is hash-chained, queryable, evidence-grade logging for systems that must prove *who did what, when* to an auditor - the kind of record regulations like the CRA, DORA, NIS2, and the EU AI Act (Article 12) increasingly require. It's drop-in, SQLite-backed, and ships a one-call evidence export.

It is the open-source core of the CRADesk line and the immutable evidence store inside [CRADesk](https://github.com/w1ck3ds0d4/CRADesk).

[![CI](https://github.com/w1ck3ds0d4/ProofLog/actions/workflows/ci.yml/badge.svg)](https://github.com/w1ck3ds0d4/ProofLog/actions/workflows/ci.yml)
[![License: Apache-2.0](https://img.shields.io/badge/license-Apache--2.0-blue.svg)](LICENSE)
[![.NET](https://img.shields.io/badge/.NET-8.0-512BD4.svg)](https://dotnet.microsoft.com/)

---

## Why

Ordinary logs are editable. If an attacker (or an insider) can change history, your logs can't *prove* anything to a regulator or a court. ProofLog makes every record **cryptographically chained** to the one before it: change, delete, reorder, or insert a single entry and verification fails at exactly that point. Each record is also **identity-bound** - the actor is part of the chain, so you can't later rewrite who did something.

## Install

```bash
dotnet add package ProofLog
```

## Quickstart

```csharp
using ProofLog;

// Durable, file-backed log (or InMemoryProofLog for tests / embedding).
using var log = new SqliteProofLog("audit.db");

log.Append(new AuditEntry { Actor = "alice", Action = "user.login", Resource = "session/abc" });
log.Append(new AuditEntry { Actor = "alice", Action = "payout.approve", Resource = "payout/42", Data = "{\"amount\":1500}" });

// Verify the whole chain - O(n), no external service.
VerificationResult v = log.Verify();
Console.WriteLine(v.Ok ? "intact" : $"TAMPERED at #{v.BrokenAtSeq}: {v.Reason}");

// One-call, self-verifying evidence export for an auditor.
File.WriteAllText("evidence.json", Evidence.ToJson(log));
```

## How it works

Each record's hash is:

```
hash_i = SHA-256( hash_{i-1}  ||  seq  ||  timestamp  ||  actor  ||  action  ||  resource  ||  data )
```

Fields are **length-prefixed** before hashing, so no value can be crafted to forge an equivalent encoding. The first record chains from a fixed genesis hash. `Verify()` walks the log, recomputes every hash from the stored fields, and checks each record's `PrevHash` against the actual previous hash and that sequence numbers are contiguous.

| Tampering | Detected by |
| --- | --- |
| Edit a field (actor, action, data, time) | content hash mismatch |
| Overwrite a stored hash | content hash mismatch |
| Delete a record | sequence break + prev-hash mismatch |
| Insert or reorder records | sequence break + prev-hash mismatch |
| **Truncate the tail** | anchor `Head()` externally - see below |

### A note on truncation

Deleting records from the *end* leaves a chain that's still internally consistent - that's a fundamental property of hash chains, not a bug. `Head()` returns the current chain-head hash; anchor it somewhere the attacker can't reach (publish it, notarize it, send it to a second system) and a shrunken log is immediately obvious because its head no longer matches. ProofLog is honest about this rather than pretending a local-only log can detect its own truncation.

## Evidence export

`Evidence.ToJson(log)` produces a portable bundle - every record plus the head hash and a fresh verification statement. An auditor needs nothing but that file and the public hashing rule above to **independently replay the chain** and confirm it. (Named regulator profiles - CRA / DORA / NIS2 / EU AI Act Article 12 - are on the roadmap.)

## API

| Type | Purpose |
| --- | --- |
| `IProofLog` | `Append`, `Read`, `Head`, `Count`, `Verify` |
| `SqliteProofLog` | durable SQLite-backed store |
| `InMemoryProofLog` | non-durable store for tests / embedding |
| `AuditEntry` | what you append (actor + action required) |
| `ProofRecord` | a committed, chained record |
| `Evidence` | one-call JSON evidence export |
| `Hashing` | the canonicalization + SHA-256 rule (so anyone can re-verify) |

## Tech stack

| Layer | Technology |
| --- | --- |
| v1 | .NET 8 (NuGet) |
| v2 | Rust core |
| Store | SQLite |

## Roadmap

- **v0.1** *(done)* - core append + hash-chain + identity binding + verify, SQLite store, tamper-detection tests, evidence export, CI.
- **Later** - OpenTelemetry bridge, additional stores, regulator-ready export profiles, per-actor signatures, Rust core.

## License

Apache-2.0. Permissive on purpose: ProofLog is meant to be adopted.
