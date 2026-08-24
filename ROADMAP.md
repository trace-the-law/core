# Roadmap

**The global contracts come first; a bounded jurisdiction pilot comes next.**
Trace the Law is not ready to ingest or publish a production corpus until the
launch gates below are met.

## 0. Global foundation

- Freeze the first source, authority, jurisdiction, capture, artifact,
  derivation, record, relationship, coverage, snapshot, evidence, correction,
  invalidation, and publication-clearance contracts.
- Validate every contract against small, synthetic examples in CI.
- Validate stable producer identities and reject review timestamps older than
  the evidence, captured bytes, or derived output under review.
- Publish the Charter, governance, rights, privacy, security, agent, and
  contribution boundaries.
- Exercise the correction skill with conflicting, missing, stale, and
  privacy-blocked evidence. Prove that `READY_TO_OPEN` passes only after its
  review gates and that spoofed `OPENED`, `APPLIED`, issue, merge, and snapshot
  receipts fail closed.

## 1. Bounded pilot

The first adapter is India GST because it is a useful test of legislation,
delegated rules, notifications, circulars, judgments, multiple publishers, and
changing applicability. It is an adapter, not the shape of the global model.

- Declare a narrow source and date envelope before fetching anything.
- Build the authority and source register, entrypoint inventory, rights and
  publication-clearance matrices, language policy, and expected identifier
  sequences.
- Preserve a small set of source captures and reproducible Markdown
  derivatives.
- Test amendments, commencement, correction notices, judicial interpretation,
  conflicts, gaps, and point-in-time evidence bundles end to end.
- Publish measured coverage only for the declared envelope.

## 2. Repeatable ingestion

- Run independent discovery paths and save index snapshots.
- Emit a content-addressed enumeration-result manifest for every run, listing
  the exact discovered capture/artifact identities and source-manifest
  revision; derive counts from that manifest instead of trusting counters.
- Detect changed bytes, broken sources, numbering and date gaps, referenced but
  missing documents, and conversion regressions.
- Sandbox retrieval and conversion; treat every document as untrusted input.
- Keep large source bytes in content-addressed object storage only when the
  exact capture route permits it. Keep normalized text and metadata in Git.
- Design the release-as-of delivery manifest, attribution, unofficial-copy
  notice, and receipt policy. Keep public mirrors disabled until that contract
  exists in addition to exact source rights and publication clearance.
- Make rebuilds deterministic and publish a new snapshot atomically.

## 3. Agent and correction services

- Serve snapshot-bound, coverage-aware evidence bundles.
- Publish a dependency invalidation feed without collecting users' questions.
- Implement the private, expiring, two-gesture correction review flow.
- Configure the trusted project repository and narrowly scoped issue bot, then
  implement authenticated receipts before enabling `OPENED` or public-review
  states.
- Have the privacy broker or source monitor reconstruct each public report from
  independently retrieved public sources. Require per-evidence clearance and an
  identified human review of the complete payload before a project bot may open
  a public GitHub issue.
- Replay affected evidence bundles after a reviewed fix; keep failures visibly
  stale.
- Mark a correction `APPLIED` only when its merge commit, successful
  invalidation event, and replacement snapshot resolve and agree.
- Define and review a signed source-monitor-run contract before adding monitor
  causes. Enable correction-caused invalidation and post-genesis snapshots only
  after the trusted receipt verifier is live; reject local, ready-only, or
  unverified reports as causes.

## 4. Expand by legal system

Default repository shape:

- one global core repository;
- one global source registry;
- one corpus repository per country or independently governed legal system;
- subnational jurisdictions inside the parent corpus until measured scale or
  independent stewardship justifies a split; and
- no topic-based shards.

Each adapter inherits the global contracts and adds local institutions,
languages, rights, privacy, coverage, and maintainers.

## Launch gates

Public ingestion or services remain blocked until all of these exist:

1. A project GitHub organization with protected branches, required review, and
   least-privilege bot access, following
   [the organization setup checklist](docs/organization-setup.md).
2. At least two human maintainers and the specialist roles required by
   [GOVERNANCE.md](GOVERNANCE.md).
3. Monitored private routes for security, privacy, and legal-removal reports.
4. Source-specific rights decisions, independent publication-clearance review,
   and a takedown/quarantine procedure.
5. Sandboxed fetch and conversion infrastructure, SSRF controls, secrets
   handling, backups, and recovery tests.
6. A published pilot coverage envelope whose gaps are visible to agents, with
   every positive result reconciled to content-addressed enumeration output and
   the exact source-manifest revision.
7. End-to-end checks that record authority roles resolve to cited assertions,
   incomplete or expired coverage cannot receive an optimistic agent status,
   spoofed external receipts fail closed, and an enabled `APPLIED` correction
   has authenticated, resolvable propagation proof.
8. Public-issue tests proving broker reconstruction,
   per-evidence clearance, identified human privacy review, and review-time
   ordering; signed source-monitor, nested-transform rights, public-delivery,
   and invalidation-cause tests must also pass before their features are
   enabled.
