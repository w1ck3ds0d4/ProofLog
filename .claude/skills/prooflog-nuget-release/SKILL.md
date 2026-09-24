---
name: prooflog-nuget-release
description: Cut a NuGet release of ProofLog by tagging a version. Use when Daniel says "release ProofLog", "cut a NuGet version", or "publish ProofLog to NuGet" - verifies the build first, then tags so the version tag itself triggers publish, and flags the pinned SQLitePCLRaw advisory before any dependency bump in the same change.
---

# ProofLog NuGet release

`.github/workflows/release.yml` publishes to NuGet on every `v*` tag push, using NuGet
Trusted Publishing (OIDC): the job exchanges a short-lived GitHub OIDC token for a
temporary NuGet key at run time, so no API key is stored in this repository. That also
means **pushing a `v*` tag is the publish trigger** - there is no separate confirm step,
so get the checks right before tagging, not after.

## 1. Verify the build and tests are green

```bash
dotnet restore
dotnet build -c Release --no-restore
dotnet test -c Release --no-build
```

These are the same steps `release.yml` runs. Do not tag if any of them fail locally or on
CI (`gh run list --repo w1ck3ds0d4/ProofLog --branch main --limit 1`).

## 2. Bump the version

The package version lives in `src/ProofLog/ProofLog.csproj`:

```xml
<Version>0.4.0</Version>
```

Bump it to match the tag you are about to push (semantic: patch for a fix, minor for a
new feature that keeps the API, major for a breaking API change). Commit that bump before
tagging, so the tag points at a commit whose `.csproj` version matches the tag.

## 3. Check the SQLitePCLRaw advisory before touching that dependency

`README.md` documents a known transitive advisory: via `Microsoft.Data.Sqlite` this
package pulls `SQLitePCLRaw.*.e_sqlite3`, covered by CVE-2025-6965 (a SQLite
memory-corruption bug). ProofLog is not affected in normal use because it only runs its
own fixed-schema, parameterized queries. The dependency is deliberately pinned to the
newest maintained build and is meant to move only when SQLitePCLRaw ships the SQLite
3.50.2 fix. If this release bumps `Microsoft.Data.Sqlite` or `SQLitePCLRaw.*`, check
whether the fix has shipped and update the README's advisory note in the same change
rather than silently dropping it.

## 4. Tag and push

```bash
git tag v0.4.0
git push origin v0.4.0
```

## 5. Watch the release run

```bash
gh run watch --repo w1ck3ds0d4/ProofLog $(gh run list --repo w1ck3ds0d4/ProofLog --branch main -e push --limit 1 --json databaseId -q '.[0].databaseId')
```

The job builds, tests, packs, and uploads the `.nupkg` as an artifact regardless of
whether publishing succeeds. The `Exchange OIDC token for a short-lived NuGet key` step
uses `continue-on-error: true`, so a Trusted Publishing misconfiguration does not fail the
whole run, it just skips the push step and prints a `::notice::`.

## What Daniel does himself (one-time, on nuget.org)

Trusted Publishing needs a policy registered on nuget.org before the first automated
publish will work: Account -> Trusted Publishing -> Add, with:
- Package owner: `w1ck3ds0d4`
- Repository: `w1ck3ds0d4/ProofLog`
- Workflow file: `release.yml`
- Environment: (leave empty)

This is a nuget.org account action; Claude cannot do it. If the run's `Report when
publishing was skipped` step fires, tell Daniel the policy is missing or stale and point
him at this setup.

## What proves it worked

- The tagged run's `Push to NuGet` step ran (not skipped) and exited clean.
- `https://www.nuget.org/packages/ProofLog/<version>` resolves.
- The version badge in README.md matches the new tag once it refreshes.

## Traps

- A stray `v*` tag ships a release with no further confirmation. Do not push a `v*` tag
  as a test or a placeholder.
- Tagging before bumping `<Version>` in the `.csproj` produces a NuGet package whose
  version does not match the git tag, which is confusing later. Always bump first,
  commit, then tag that commit.
- Bumping `SQLitePCLRaw.*` or `Microsoft.Data.Sqlite` without checking the advisory note
  in README.md can silently reintroduce or misdescribe CVE-2025-6965 exposure.
