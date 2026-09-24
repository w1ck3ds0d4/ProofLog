# Roadmap

**Status:** continue. **Last reviewed:** 2026-09-24.

ProofLog is the free, open-source evidence core (hash-chained, signed audit
log) underneath CRADesk, and the planned home for VeilBreak's evidence
integrity work. "Done" here is never a fixed endpoint: it stays a small,
dependable library that CRADesk and other consumers can trust, with each
release adding a well-scoped capability (a signing mode, a regulator profile)
rather than growing into a framework.

> How this file is used: Claude Project threads build the first unticked item
> under **Now**, one item per branch and pull request, and tick it in that
> same PR as `- [x] ... (#PR)`. Daniel owns the order and the lists; threads
> never add to Now, Next or Later themselves, they propose under **Ideas**.

## Now
- [ ] **Add a CHANGELOG.md**: this PR adds one covering v0.1 through v0.4;
  keep it updated going forward. Done when: CHANGELOG.md exists and is linked
  from README.
- [ ] **Confirm the trusted-publishing release flow still works post-Sqlite
  bump**: the 2026-07-27 Sqlite modernization (#11) touched the dependency the
  NuGet release relies on. Done when: a test tag through `release.yml`
  publishes successfully (or the flow is re-verified against the last real
  release).
- [ ] **Review the pinned SQLitePCLRaw advisory before the next version
  bump**: CVE-2025-6965 is tracked as not reachable in ProofLog's own code
  path; re-check this claim and whether a patched release exists. Done when:
  the README note is re-verified against current SQLitePCLRaw releases or
  updated.
- [ ] **Plan the VeilBreak evidence-integrity harvest**: scope what from
  VeilBreak's evidence-integrity work becomes a ProofLog feature versus stays
  in VeilBreak. Done when: a short design note exists (in this roadmap's
  Ideas or a linked issue) naming what moves and what does not.

## Next
- [ ] **RFC 3161 trusted timestamp anchoring**: an opt-in way to anchor chain
  heads to an external time authority, closing the "operator controls the
  clock" gap the README already documents. Done when: a documented API exists
  and is covered by a test.
- [ ] **Additional regulator export profile**: add one more named profile
  beyond the existing CRA/DORA/NIS2/MGA/chain-of-custody set, based on the
  next real consumer need. Done when: a new profile ships with a test and a
  README entry.

## Later
- Public ledger anchoring as an alternative to RFC 3161
- A CLI for ad-hoc chain verification outside of a .NET host
- Benchmarks published for chain append/verify at scale

## Ideas
(empty to start; threads add proposals here)

## Done
- [x] v0.4: named regulator evidence export profiles (#7)
- [x] Digital-evidence chain-of-custody profile and forensic positioning (#10)
- [x] MGA-gaming regulator profile plus ProofSettle settlement-evidence demo (#9)
- [x] v0.3: asymmetric ECDSA P-256 signing, auditor-verifiable evidence (#6)
- [x] Anchored `Verify(expectedHead)` to detect truncation (#5)
- [x] Drop-in DI and logging adoption helpers (#4)
- [x] v0.2: optional HMAC signing, defeats a full-chain rewrite (#3)
- [x] v0.1: hash-chained, identity-bound audit log with SQLite and verify (#1)
- [x] Sqlite dependency modernization and evidence-claim corrections (#11)
