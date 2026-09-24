# Architecture

ProofLog is a small .NET 8 class library with no server component. A
consumer app links the NuGet package, calls it in-process, and owns the
storage file (or in-memory store) itself.

## Tech stack

- .NET 8.0, C# with `Nullable` and `TreatWarningsAsErrors` enabled
- `Microsoft.Data.Sqlite` for the file-backed store
- `Microsoft.Extensions.DependencyInjection.Abstractions` and
  `Microsoft.Extensions.Logging.Abstractions` for optional host integration
- Packaged and published via `dotnet pack` / NuGet Trusted Publishing

## Component breakdown

`src/ProofLog/`:

- `IProofLog.cs`, `ProofLogBase.cs`: the append/verify contract and shared
  chain logic (hashing, sequencing) common to both store implementations.
- `InMemoryProofLog.cs`: an in-process store for tests and embedding.
- `SqliteProofLog.cs`: the durable, file-backed store built on
  `Microsoft.Data.Sqlite`, using only fixed-schema, parameterized queries.
- `AuditEntry.cs`, `ProofRecord.cs`: the entry a caller appends and the
  chained record it becomes (with hash, sequence, actor, timestamp).
- `Hashing.cs`: the chain hash function linking each record to the previous.
- `Signing.cs`: optional HMAC and asymmetric ECDSA P-256 signing over the chain.
- `VerificationResult.cs`: the result of `Verify()` (`Ok`, or the exact
  sequence and reason a chain broke).
- `RegulatorProfile.cs`, `Evidence.cs`: named evidence-export profiles (CRA,
  DORA, NIS2, MGA, chain-of-custody) and the one-call JSON export.
- `ServiceCollectionExtensions.cs`, `ProofLogExtensions.cs`: DI registration
  helpers (`AddProofLog`) for ASP.NET Core / worker hosts.

## Data flow

1. A caller constructs a `SqliteProofLog` (or `InMemoryProofLog`) and calls
   `Append(AuditEntry)`.
2. The record is hashed against the previous chain head, assigned the next
   sequence number, optionally signed, and written (SQLite: a single
   parameterized `INSERT`; in-memory: appended to a list).
3. `Verify()` walks every record in sequence, recomputing each hash and
   checking it against the stored one and (if signed) the signature. It
   returns `Ok` or the first sequence number where the chain breaks and why.
4. `Evidence.ToJson(log)` (or a `RegulatorProfile`-scoped export) serializes
   the chain, or a filtered view of it, into a self-contained JSON bundle an
   auditor verifies independently with only the public key.

## What ProofLog does not do

- No network calls, no external service dependency, no telemetry.
- No independent time source: timestamps come from the host clock (see the
  README's "Scope of the guarantee" note).
- No schema migration tooling beyond what `SqliteProofLog` creates on first
  use.
