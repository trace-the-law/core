# Contributing to Trace the Law

Thank you for helping make public legal material easier to trace. Contributions
are welcome from every jurisdiction and language. Accuracy, provenance, rights,
and privacy matter more than volume.

Read the [Charter](CHARTER.md), [Governance](GOVERNANCE.md),
[Rights](RIGHTS.md), and [Privacy](PRIVACY.md) policies before contributing
content.

## Never submit your legal situation

Issues, pull requests, commits, reviews, and attachments are public and may be
copied permanently. Do not include facts about your own or another person's
case, private correspondence, personal identifiers, credentials, sealed
material, or confidential information.

There is no live correction intake, reporting API, review-link service, or
correction issue bot. Public factual correction issues may be created only
after a future trusted bot, independent reconstruction, and human review are
implemented. They are not requests for legal advice. No private privacy or
legal-removal route should be advertised until it is genuinely monitored; use
the process status in [PRIVACY.md](PRIVACY.md) and [SECURITY.md](SECURITY.md).

## Ways to contribute

- **Propose an official source:** identify an authority, source URL, document
  type, language, coverage period, and source terms.
- **Correct an artifact:** propose a focused, source-backed pull request, or use
  the private correction review flow once its monitored service is live.
- **Improve extraction:** correct an unofficial transcription while preserving
  the unchanged source capture.
- **Add relationships:** cite evidence for amendments, repeals, commencement,
  citations, appeals, reversals, and supersession.
- **Build a jurisdiction adapter:** provide the launch material required by
  [GOVERNANCE.md](GOVERNANCE.md).
- **Improve code, tests, documentation, or policy.**

Do not upload a third-party document merely because it is visible on a public
website. A source link and rights evidence must come first.

## Correction reports

Do not open a public GitHub issue to report an artifact correction. The direct
public correction form is intentionally disabled because a warning cannot stop
case facts or personal data entering permanent Git history. Until the monitored
private intake service exists, submit only a focused pull request based entirely
on public official evidence, or keep the finding local.

An agent may prepare a local correction candidate containing only the minimum
structured public evidence needed to identify a defect. In base V1 it must stop
there: it may not offer a private draft, review link, reporting URL, or GitHub
issue. The two-gesture private-draft design applies only after its service is
launched. An agent must never create a prefilled GitHub issue or transmit
conversation text, user identity, case facts, private files, credentials, or
non-public URLs.

Once live, private intake treats every report as an untrusted lead. It validates,
privacy-scans, deduplicates, and independently reproduces the public evidence.
Only then may a project bot publish a sanitised issue. A report or issue never
changes the corpus directly; only a reviewed pull request can do that.

## Pull requests

Keep each pull request focused. Complete the pull request template and include:

- affected artifact identifiers and versions;
- primary-source URLs and retrieval dates;
- the source-rights basis and required attribution;
- the layer changed: source manifest, artifact or derived artifact, record,
  relationship assertion, evidence bundle, code, or policy;
- a correction or supersession link when changing a published record;
- tests or repeatable checks where applicable; and
- disclosure of material conflicts of interest.

If an agent generated or materially transformed a contribution, say so and
identify what a person verified. An agent cannot certify rights, approve its own
work, or count as a required human reviewer.

## Rights certification

The repository uses MIT for project-owned code, schemas, documentation, and
metadata. MIT does not apply to official documents or other third-party
material; see [RIGHTS.md](RIGHTS.md).

Every commit must include a [Developer Certificate of Origin 1.1](https://developercertificate.org/)
sign-off:

```text
Signed-off-by: Your Name <your-address@example.com>
```

Use `git commit -s` to add it. By signing off, you certify that you have the
right to submit the contribution under the licence stated for the affected
file. For a third-party artifact, you must also provide the source-specific
rights metadata. A sign-off alone does not grant redistribution rights.

Do not use a fabricated identity or another person's sign-off. Remember that a
sign-off is part of the permanent public commit history.

## Review levels

| Change | Minimum review |
| --- | --- |
| Routine code, documentation, or low-risk metadata | One human maintainer other than the author |
| Legal force, effective date, commencement, repeal, supersession, precedent, or controlling relationship | Two human maintainers, including a jurisdiction maintainer |
| Rights, privacy, removal, tombstone, restoration, coverage claim, or core policy | Two human maintainers, including the relevant specialist maintainer |

An approval means the evidence and project process were checked. It is not a
legal opinion or a completeness guarantee.

## Correction history

Do not rewrite a published state without recording the correction. Preserve the
prior state as superseded and link it to the new state, unless privacy, security,
or law requires restriction. Never modify a raw source capture to make it match
an extraction or metadata correction. In the future public workflow, a
correction is not `APPLIED` until its reviewed corpus change is merged, the
receipt is authenticated, and all affected derivatives are invalidated and
rebuilt successfully. Base V1 cannot emit that state.

## Conduct and moderation

Discuss evidence and process, not a contributor's politics, nationality,
identity, or motives. Maintainers may hide or remove accidental personal data,
secrets, threats, harassment, spam, or material that creates legal or safety
risk. Sensitive moderation details will not be reproduced publicly.
