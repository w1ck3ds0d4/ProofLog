# ProofLog

A tamper-evident, identity-bound, hash-chained audit-log SDK for .NET, with a
SQLite store, optional HMAC/ECDSA signing, regulator export profiles, and a
one-call self-verifying evidence export. Free, open-source (Apache-2.0),
published on NuGet. The evidence core reused by CRADesk.

## Commands

```bash
dotnet restore
dotnet build -c Release
dotnet test -c Release             # tests/ProofLog.Tests
dotnet run --project samples/ProofLog.Demo       # tamper-detection demo
dotnet run --project samples/ProofSettle.Demo    # signed settlement-evidence demo
dotnet pack src/ProofLog/ProofLog.csproj -c Release -o artifacts
```

A version tag (`v*`) triggers `release.yml`, which publishes to NuGet via
Trusted Publishing (no long-lived API key in this repo).

## Layout

| Path | What it is |
| --- | --- |
| `src/ProofLog/` | The library: chain, hashing, signing, SQLite store, DI helpers |
| `tests/ProofLog.Tests/` | xUnit-style tests: chain, signing, tamper detection, evidence profiles |
| `samples/ProofLog.Demo/` | Runnable tamper-detection walkthrough |
| `samples/ProofSettle.Demo/` | Signed settlement-evidence use case (MGA-profiled) |
| `.github/workflows/` | `ci.yml` (build/test/pack), `release.yml` (NuGet trusted publish), `security.yml` |

## Conventions

- Commit format: `(type) lowercase summary` - `feat`, `fix`, `chore`, `docs`.
  No trailing period, no body unless needed.
- ASCII hyphens only. No em dashes or en dashes anywhere.
- Feature branch per change set, one PR per branch, squash-merge.
- `TreatWarningsAsErrors` is on; a warning fails the build, not just CI.
- Third-party actions in `.github/workflows/` are pinned to a commit SHA.
- Known pinned-dependency advisory: `SQLitePCLRaw` is pinned pending a
  SQLite 3.50.2 fix for CVE-2025-6965 (not reachable in ProofLog's own code
  path; see the README note). Check this before bumping the Sqlite dependency.

## Do not read

- `bin/`, `obj/` (build output)
- `artifacts/` (packed nupkg output, not committed)
