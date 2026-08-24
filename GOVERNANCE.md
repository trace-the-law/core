# Governance

## Principles

Trace the Law is governed as an independent evidence archive. Decisions should
be public, attributable, reversible where possible, and based on cited primary
sources. Review confirms that the project's process and evidence standard were
followed; it is not a legal opinion or a guarantee of correctness.

No government, funder, company, maintainer, or contributor may silently replace
the archive's recorded history.

Crawler findings, agent output, correction reports, and GitHub issues are
untrusted leads. They may create review work but never facts. Only a reviewed
pull request may change the corpus.

## Roles

- **Contributors** propose sources, corrections, policy, code, or documentation.
- **Triagers** classify reports, remove accidental sensitive material, identify
  duplicates, and request missing evidence. They do not decide legal force.
- **Maintainers** review and merge routine project changes.
- **Jurisdiction maintainers** understand a jurisdiction's sources, languages,
  institutions, and publication practices.
- **Rights, privacy, and security maintainers** review changes within their
  respective risk areas and manage private reports.

Roles are earned through sustained, accurate, respectful work. The list of
people holding each role and the method for granting or removing access must be
public before a jurisdiction is launched. No role may be held only by an
automated agent.

## Decision classes

### Routine changes

Routine code, documentation, source discovery, and low-risk metadata changes
require review by at least one human maintainer. The author must not merge a
change without another person's review.

### High-impact changes

The following require approval from at least two human maintainers with no
unresolved evidence objection:

- legal-force, in-force, effective-date, commencement, repeal, supersession, or
  precedential-status claims;
- a link that changes which document amends, reverses, or controls another;
- a source-rights or redistribution determination;
- privacy redaction, de-anonymisation risk, removal, or restoration;
- deletion, tombstoning, or alteration of a preserved source artifact;
- a material coverage or completeness representation;
- changes to the Charter, governance, contributor rights, privacy, or security
  policy.

At least one approver must be a jurisdiction maintainer for jurisdiction-specific
claims. A rights, privacy, or security maintainer must approve changes in that
area. Bots may prepare evidence or review notes but cannot supply either human
approval.

### Emergency action

A maintainer may temporarily restrict access when delay could expose private
information, credentials, sealed material, active exploitation, or a credible
legal risk. A second qualified maintainer must review the action promptly. The
project should publish a minimal tombstone and decision record when lawful, but
must not repeat the sensitive material in that record.

## Corrections are append-only

Base V1 has no authenticated public-receipt or transition service. It can
prepare local or `READY_TO_OPEN` evidence, but it cannot mark a report
`OPENED`, `APPLIED`, or `PROPAGATION_FAILED`, emit an invalidation event, or
publish a post-genesis snapshot. The lifecycle below governs the future service
after those receipts are implemented and tested.

A published factual record is never silently rewritten. A correction must:

1. identify the affected artifact and version;
2. cite the evidence that supports the change;
3. record who or what proposed the correction and how it was reviewed;
4. preserve the prior state as superseded, unless privacy, security, or law
   requires restriction; and
5. state when the corrected version became available.

Raw source captures are immutable. If a publisher changes or replaces a file,
the replacement is a new capture linked to the earlier one. If the project made
an extraction or metadata error, the corrected derived record points back to the
unchanged source capture.

Relationship assertions use the explicit states `candidate`, `verified`,
`disputed`, `superseded`, and `retracted`; an earlier assertion is not deleted
merely because a later one replaces it. After merge, affected descendants must
be marked stale and rebuilt in dependency order. The replacement snapshot is
published atomically, so clients cannot receive a mixture of old and new graph
state. A report reaches `APPLIED` only after this propagation succeeds; otherwise
it remains `PROPAGATION_FAILED` and affected outputs stay visibly stale.

## Conflicts and independence

Reviewers must disclose employment, representation, funding, litigation, or
other interests that a reasonable person could see as affecting a decision and
must recuse when that conflict is material. A contributor's official position,
customer status, or financial support does not lower the evidence or review
standard.

Private requests from authorities or rights holders must be documented through
the appropriate rights, privacy, security, or legal-removal process. They must
not produce an unlogged content change.

## Appeals

Public decisions may be challenged in a focused, evidence-backed pull request,
or through a bot-created public issue after the monitored broker route exists.
Do not place a person's legal situation in either channel. Privacy, security,
and legal-removal appeals remain private. An appeal must be reviewed by at least
one maintainer who did not make the original disputed decision.

Disagreement is not resolved by contributor popularity. The decision record
must explain the evidence applied, the project's uncertainty, and any remaining
dissent.

## Jurisdiction adapters

Jurisdiction adapters may add stricter local safeguards but may not weaken this
Charter, conceal known gaps, treat unofficial translations as authoritative, or
remove the global correction trail. New adapters require, before publication:

- a source and authority register;
- a rights and privacy matrix;
- an original-language and translation policy;
- a documented coverage boundary;
- at least two human maintainers, including a jurisdiction maintainer; and
- working private privacy, legal-removal, and security reporting routes.

## Policy changes

Material governance changes require a public proposal, an opportunity for
community review, and the high-impact approvals above. Security or privacy
details may be discussed privately, but the resulting public rule must explain
the decision without exposing protected information.
