# Source Rights and Licensing

## The short rule

The repository's MIT License applies to project-owned code, schemas,
documentation, and metadata. It does not place an official document, court
decision, government publication, third-party attachment, publisher
enhancement, or other third-party material under MIT. Trace the Law cannot
grant rights that it does not own.

Public availability is not the same as permission to copy, transform, or
redistribute. Copyright, database rights, contract terms, attribution duties,
privacy, court orders, and other restrictions vary by source and jurisdiction.
The [Berne Convention, Article 2(4)](https://www.wipo.int/wipolex/en/treaties/textdetails/12214)
expressly leaves protection of official legislative, administrative, and legal
texts to each country.

## Rights are not publication clearance

Rights and publication clearance are independent publication gates. Rights
answer whether Trace the Law may copy, transform, mirror, and redistribute a
work. Publication clearance separately checks personal data, sealing or
reporting restrictions, preservation of official redactions, and sensitive
material.

An open-licensed or public-domain document can still require restriction or
quarantine. A privacy-cleared document can still lack permission to be copied.
Public mirroring requires both a publishable, human- or counsel-reviewed rights
basis and a human- or specialist-reviewed `cleared` publication decision.
Unknown or unreviewed status on either side blocks publication.

Base V1 applies one additional fail-closed gate: it rejects every public
artifact mirror even when rights and clearance appear sufficient. Public
delivery remains official-link-and-hash only until a release-as-of manifest can
bind the delivered bytes, attribution, unofficial-copy notice, rights decision,
and clearance. The mirror fields below define the future review contract; they
do not enable mirroring today.

## Rights layers

Rights must be evaluated separately for:

- project-owned code;
- project-authored documentation, metadata, summaries, and translations;
- the source artifact and embedded third-party material;
- an unofficial OCR or Markdown transcription;
- an official or unofficial translation;
- a database or collection as a whole; and
- commercial editorial additions such as headnotes, annotations, pagination,
  and classification.

A right to reproduce a judgment does not automatically include a commercial
publisher's headnote or editing. A right to link to a document does not
automatically include a right to mirror it. Converting a document to Markdown,
OCR text, or another language may still be reproduction or adaptation.

## Required per-source record

Every source adapter must maintain machine-readable rights metadata supported
by evidence, and every capture must preserve the assessment for its exact
publisher route. At minimum it must record:

- publisher and, when known, rights holder;
- source and terms-of-use URLs with retrieval dates;
- asserted status: `open-license`, `public-domain`, `statutory-exception`,
  `permission`, `restricted`, or `unknown`;
- the named licence, version, jurisdiction, and required attribution;
- whether capture, public mirroring, transcription, translation, summarisation,
  and redistribution are permitted;
- relevant exclusions, embedded third-party material, and database terms;
- the evidence and date supporting the determination; and
- review state, review time, stable reviewer producer ID, an optional
  fail-closed `next_review_at` validity deadline, and advisory review triggers.

`Unknown` is a real status, not permission.

A reviewed rights decision cannot predate retrieval of its terms or supporting
evidence. A display name is not a reviewer identity, and a prior decision does
not silently cover evidence retrieved later. When `next_review_at` is present,
publication at or after that instant is blocked until a new assessment is
recorded; `next_review_trigger` alone is advisory.

## Default actions

- **Express open licence or public domain:** follow the exact conditions and
  preserve the evidence for that status; publish only after separate
  publication clearance.
- **Statutory exception or direct permission:** publish only the material and
  uses covered by that basis, with jurisdiction and limits recorded, and only
  after separate publication clearance.
- **Restricted or unknown:** the public archive may keep a source URL, public
  bibliographic facts, retrieval time, and content hash, but must not mirror a
  full artifact or publish a full transcription until reviewed.
- **Mixed material:** separate or exclude restricted attachments, photographs,
  maps, publisher enhancements, signatures, and logos when the controlling
  permission does not cover them.

A derivative must resolve a rights basis for every input route and recursively
walk all earlier derivations. Required uses accumulate across the chain:
transcription for Markdown, OCR, or extraction; translation for translations;
and summarisation for summaries. For example, publishing a summary of a
translation of OCR text requires transcription, translation, and summarisation
permission from every applicable source route, not only summarisation for the
last step. An unclassified transformation cannot establish permission
automatically.
When a public bundle selects that route, every nested derivation ID must be an
explicit bundle dependency. Each selected output clearance is checked; an
undeclared or uncleared intermediate hop fails closed even if the final hop is
cleared. Quarantine or removal of any artifact on the selected route also
blocks the route and its descendants; a new derivative cannot revive it.

A public summary or translation is a derived claim. Material source language
that is reproduced verbatim remains a source excerpt and requires transcription
permission even when a contributor labels it as a summary or translation.

The derivative also needs output-specific publication clearance after the
output was created. Neither source rights nor source clearance automatically
transfers to a direct or nested derivative.

Robots directives and website terms are inputs to the review, not substitutes
for a legal rights determination. Source access must not bypass authentication,
paywalls, technical controls, or access restrictions.

## Attribution and official status

Required attribution travels with every copy and derived record. Attribution
must identify the actual publisher and must not suggest that the publisher
endorses Trace the Law. Government seals and logos may appear inside a lawful,
unaltered source capture but may not be reused as project branding.

Every transcription, translation, and summary must be visibly unofficial unless
the responsible authority expressly designated that exact version as official.

## Contributions

Contributors must identify the source, provenance, and rights basis for every
third-party artifact. By contributing project-owned work, they certify that they
have the right to submit it under the licence stated for that file. A
contributor's certification does not convert a third-party work to MIT.

The contribution workflow is defined in [CONTRIBUTING.md](CONTRIBUTING.md).

## Challenges and removal

Rights challenges must use the project's private rights or legal-removal route
when the report contains non-public information. Maintainers may quarantine
material while a claim is reviewed. The public decision record should identify
the affected artifact and outcome without republishing protected content or
personal contact details.

This policy is a publication safeguard, not legal advice or a declaration that
any particular use is lawful. A jurisdiction must obtain qualified local review
when its rights basis is uncertain.
