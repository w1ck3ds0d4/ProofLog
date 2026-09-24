# How It Works

ProofLog is a library you add to a .NET app so its audit trail can prove
itself later. Each entry you append is linked to the one before it by a
hash, so changing, deleting, reordering, or inserting a record after the
fact breaks the chain at exactly that point when someone verifies it.

## What it does

- Appends identity-bound audit entries (`Actor`, `Action`, `Resource`, plus
  free-form `Data`) to a hash-chained log, backed by SQLite or in-memory.
- Verifies the whole chain in one call (`Verify()`), returning either "intact"
  or the exact sequence number and reason it broke.
- Optionally signs the chain with HMAC (shared secret) or ECDSA P-256
  (asymmetric, auditor-verifiable with only the public key).
- Exports a self-contained, self-verifying evidence bundle as JSON, either
  as a plain export or scoped to a named regulator profile (CRA, DORA, NIS2,
  MGA-gaming, or a digital-evidence chain-of-custody profile).
- Does not phone home. No network calls, no telemetry.

## How to use it

### Install and append

```bash
dotnet add package ProofLog
```

```csharp
using var log = new SqliteProofLog("audit.db");
log.Append(new AuditEntry { Actor = "alice", Action = "payout.approve", Resource = "payout/42" });
```

### Verify

```csharp
VerificationResult v = log.Verify();
Console.WriteLine(v.Ok ? "intact" : $"TAMPERED at #{v.BrokenAtSeq}: {v.Reason}");
```

### Export evidence for an auditor

```csharp
File.WriteAllText("evidence.json", Evidence.ToJson(log));
```

An auditor, regulator, or independent verifier opens the JSON and re-derives
every hash (and signature, if signing is enabled) without needing access to
the original database or any shared secret beyond a public key.

### See it work

```bash
dotnet run --project samples/ProofLog.Demo       # appends, verifies, tampers, watches verification fail
dotnet run --project samples/ProofSettle.Demo    # signed settlement-evidence for mock prediction markets
```

## What it does not prove

ProofLog proves integrity and order, not wall-clock time: timestamps come
from the host clock, so an operator with write access to the machine could
set the clock before writing. For an independent time guarantee, anchor the
chain to an external trusted timestamp authority or a public ledger (see the
README's "Scope of the guarantee" note and the Later section of ROADMAP.md).
