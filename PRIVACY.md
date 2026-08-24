# Privacy

## Scope and promise

Trace the Law archives public legal material; it is not a service for publishing
a user's legal situation. The project minimises personal data, follows the
responsible authority's publication and anonymisation rules, and does not use
public correction channels for sensitive reports.

This file defines requirements for repositories, agents, correction intake, and
future services. It does not claim that a reporting or website service exists.
Public ingestion must not launch until the private privacy and legal-removal
routes described here are operational and identified in the project interface.

## Public repositories are public

GitHub issues, pull requests, commits, reviews, usernames, and attachments are
public, searchable, copyable, and difficult to erase from clones, caches, and
forks. Do not submit:

- facts about your own or another person's legal situation;
- addresses, phone numbers, email addresses, account or government identifiers;
- information about children, health, sexuality, abuse, or alleged offences;
- sealed, confidential, privileged, or unlawfully obtained material;
- credentials, security details, or private correspondence; or
- a request whose existence would reveal sensitive involvement in a case.

Public reports may describe only a defect in a Trace the Law artifact and may
cite public, official evidence. If sensitive information is posted accidentally,
notify a maintainer through the private privacy route; do not quote or repeat it
in another public message.

The bundled pattern scanner catches known credential, URL, and personal-data
shapes; it cannot reliably recognize every name, address, account number,
currency, or paraphrased case fact in arbitrary text. A scanner pass therefore
never authorizes upload or publication. Base V1 has no upload route, and any
future public report must be reconstructed from public sources and cleared by
an identified human reviewing the complete payload.

## Source documents and linking

An official website's publication of personal data does not make unlimited
republishing or enrichment safe. Before the project mirrors or republishes
source bytes, a jurisdiction adapter must document applicable anonymisation,
reporting-restriction, retention, and removal rules. Capture metadata may be
kept link-only or quarantined while that review is incomplete.

Trace the Law must:

- prefer the authority's already-anonymised public version;
- preserve pseudonyms and redactions;
- never infer or publish a protected person's identity;
- avoid person-level graph links that undo anonymisation or create a dossier;
- avoid enriching source material with external personal data; and
- apply a privacy review before personal data enters public Git history.

Uncertainty is a reason to quarantine an artifact, not to publish first and
attempt deletion later.

## Publication clearance

Publication clearance is a separate gate from copyright or reuse rights. A
capture or derivative can have permission to be copied and still be restricted
because it contains personal data, is sealed, loses official redactions, or is
sensitive. Conversely, privacy clearance does not grant a right to copy,
transform, mirror, or redistribute it.

Every capture records all four clearance checks: personal data, sealing or
reporting restrictions, preservation of official redactions, and sensitive
material. A public mirror requires `cleared` status after human or specialist
review. A `not_reviewed`, `restricted`, or `quarantined` status, an `unknown`
check, or a disputed review cannot pass the publication gate. Machine scanning
may prioritize work but cannot clear publication. The human reviewer uses a
stable producer ID; a display name is not sufficient. Review must occur after
the source bytes were retrieved.

Base V1 also rejects every public mirror after this review. Clearance is
necessary but cannot enable publication until the release-as-of delivery
manifest and receipt policy are implemented.

Every derivative also needs output-specific clearance. The publication path
must resolve cleared source captures for all inputs as well as a cleared output;
a Markdown conversion, OCR run, translation, extraction, or summary does not
inherit clearance from its source. A changed source, redaction, input route, or
transformation requires review of the new capture or output rather than reuse
of an unrelated clearance. Output clearance must occur after that derivative
was created.

## Agent-generated correction links

No correction-link service exists in base V1. Agents must keep candidates local
and must not offer a URL or upload action. The remainder of this section is the
future service requirement.

An agent may offer a local correction candidate and a review action after it
finds a possible corpus defect. It must not transmit the candidate until the
user chooses to create a private review draft. The candidate may contain only
the minimum structured public evidence needed to identify the defect. It must
not contain the conversation, prompt, user query, user identity, case facts,
unrestricted free-form text, private files, credentials, local paths, signed
URLs, or other non-public URLs.

The reporting page must:

1. show the exact sanitised payload before any transmission;
2. use one explicit user action to create a private draft and a second explicit
   action to submit it to private intake;
3. permit the user to edit or cancel at either stage;
4. state that a sanitised report may later become a public, bot-created GitHub
   issue only after broker or source-monitor reconstruction, per-evidence
   publication clearance, and identified human review of the complete public
   payload; and
5. never submit merely because a link was opened.

The review link must use an opaque, high-entropy token in the URL fragment; the
token contains no report data. The encrypted draft expires after 24 hours, the
service stores only the token hash, and an explicit request is required to
exchange the token. The review origin must be isolated and send `no-store`,
`no-referrer`, `noindex`, and a restrictive content-security policy. It must not
use advertising, session replay, third-party analytics, or other third-party
resources. Agents must not generate prefilled GitHub issue URLs.

## Reporting routes

These routes are planned, not live. Source-monitor publication and invalidation
also remain disabled until a signed monitor-run contract is modeled and
reviewed.

- **Public factual correction:** a structured issue created only by the project
  bot after the broker or source monitor reconstructs it from public sources and
  it passes the review gates below. A reporter's payload is never promoted
  directly into a public issue.
- **No-account correction:** a private intake queue whose broker reconstructs
  public evidence and whose identified human reviewer clears the complete
  payload before any bot-created public issue. “No account required” must not
  be called “anonymous” if IP addresses or other identifiers are processed.
- **Privacy or legal-removal request:** the designated private privacy route,
  never a public issue.
- **Security vulnerability:** the private route in [SECURITY.md](SECURITY.md).

An anonymous public API must not create GitHub issues directly.

## Private intake requirements

Before a private intake service is enabled, it must have:

- a fixed, minimal schema and no unnecessary attachments or free text;
- request, body, and evidence-URL size limits;
- rate limits, abuse controls, and duplicate detection;
- personal-data, credential, and secret screening before human access;
- no request bodies in access or error logs;
- encryption in transit and at rest with role-limited access;
- a documented retention period and deletion process; and
- an access and decision audit trail that does not reproduce report content.

Optional contact information must be collected separately and may not be made
public without a separate, explicit choice. Report content must never be used to
build a profile of the reporter or to provide personalised legal advice.

Before any public issue is created, the broker or source monitor must reconstruct
the payload from independently retrieved public sources. Each public evidence
item requires its own cleared publication decision. An identified human, using
a stable producer ID, must then review the complete reconstructed payload; that
review time cannot predate any evidence retrieval. Automated scanning, user
review of the private draft, or a blanket clearance cannot replace this release
decision.

## Restriction, correction, and removal

Privacy and safety can override ordinary archival preservation. When material
must be restricted, the project should retain only a minimal public tombstone
when lawful and safe. The tombstone must not identify a protected person or
repeat removed information. Maintainers must also assess derived metadata,
search indexes, summaries, caches, and graph edges rather than removing only the
source file.

Restriction or removal invalidates the affected publication clearances and all
dependent outputs. Re-publication requires a new reviewed clearance; a prior
decision must not silently survive changed bytes or changed redactions.

The project cannot promise deletion from third-party forks or mirrors. That is
why pre-publication review is mandatory.
