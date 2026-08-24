# Data model

**The model preserves evidence first and treats every legal connection or
current-state view as a reviewable claim.** JSON Schema validates document
shape; deterministic repository checks validate cross-document integrity;
neither proves that a legal interpretation is correct.

## Schema identity

All schemas use JSON Schema 2020-12. Every corpus document has:

- `schema_id`, exactly equal to the validating schema's `$id`; and
- `schema_version`, currently `1.0`.

Schema IDs use the reserved identifier-only base
`https://schemas.trace-the-law.invalid/v1/`. The `.invalid` top-level domain is
deliberately non-resolving: it does not assume ownership of a project domain.
Relative `$ref` values resolve against that base inside the validator's local
registry; validators must not fetch schemas over the network. A future change
to these IDs is an API migration, not a search-and-replace deployment detail.

## Identifiers

Project entities use typed UUID URNs:

```text
urn:trace-the-law:<entity-type>:uuid:<uuid>
```

Schemas provide distinct types such as `RecordId`, `ProvisionId`, `CaptureId`,
`DerivationId`, `ComponentId`, and `AssertionId`, so an assertion ID cannot
validate in an authority field.
Identifiers are opaque, globally unique, and independent of repository,
directory, filename, language, numbering, or current jurisdiction labels.
External citations and publisher identifiers remain metadata and may change or
collide.

Reviewed decisions use stable producer identities:

```text
urn:trace-the-law:producer:<opaque-stable-id>
```

A display name or tool version is not an identity and cannot prove independent
review. Reviewed relationship assertions, authority or jurisdiction profiles,
and sourced names identify both producer and reviewer by stable ID. Reviewed
rights, publication-clearance, and public-payload privacy decisions identify
their human reviewer by stable ID.

Two identities are content-addressed:

```text
urn:trace-the-law:artifact:sha256:<64 lowercase hex characters>
urn:trace-the-law:snapshot:sha256:<64 lowercase hex characters>
```

The validator must confirm that an artifact ID's digest suffix equals
`content_digest.value`; JSON Schema cannot compare those two values.

## Source manifests

A source manifest identifies a publisher-facing source, not an entire legal
system. It declares:

- responsible authorities and jurisdictions;
- source and document classes;
- languages and official entrypoints;
- whether each entrypoint is exhaustive, partial, discovery-only, or unknown;
- expected update frequency and adapter change-detection methods; and
- a source-specific rights assessment with public basis evidence.

Entrypoints carry `independent_group`. Two pages backed by the same database are
not independent completeness checks merely because their URLs differ.

A capture does not become official evidence merely by naming a `source_id`.
Its `acquisition` selects one entrypoint and either requires an exact entrypoint
URL or an RFC 3986-resolved link cited from a successful parent capture under
the same source and entrypoint. Discovery chains are acyclic. HTTP failures are
retained for monitoring, but only complete final HTTP 200 captures can support citations,
record/derivation provenance, or public release.

## Authorities and jurisdictions

Authority and jurisdiction documents make the graph's typed references
resolvable. Both keep sourced, time-scoped official names, profile evidence,
candidate or reviewed state, producer, and lifecycle state. An authority also
records its kind and one or more branches. A jurisdiction kind may be global,
supranational, treaty-based, sovereign, federal, autonomous, Indigenous,
municipal, judicial, administrative, functional, historical, or unknown.

This taxonomy does not impose a country tree. Authority parentage,
jurisdictions served, territorial containment or overlap, and competence to
review another authority's decisions are canonical relationship assertions.
Profile documents contain typed adjacency references to those assertion IDs for
discovery; they do not repeat the assertion's dates, evidence, confidence, or
legal meaning. Empty relationship arrays mean unmodelled, not no relationship.
Reviewed profile, name, and hierarchy claims identify both review time and
reviewer. Their producer and reviewer IDs remain stable when display names or
software versions change, and the review time cannot predate the claim or its
cited evidence. `profile_bindings` covers authority kind, each indexed branch,
jurisdiction kind, and lifecycle state exactly once. Each sourced name has its
own `field_bindings` for text, language, name type, and validity interval; a
name cannot borrow another name's evidence. Every binding selects evidence by
an in-range local index and its `source_value` must occupy a complete field in
the selected source-language quote. Stored values equal `normalized_value`.
Sourced-name text is always source-exact. Other non-source-exact values require
an identified, independent human review whose digest binds the complete
mapping, producer, reviewer, and times. Binding and review clocks follow the
profile or name and cited artifact/capture, and cannot postdate the profile's
`updated_at`. These checks are language-agnostic; no English label establishes
a classification.

## Captures, artifacts, and derivations

A capture is one observation of bytes at one source URL. It keeps a typed
`capture_id`, source and artifact IDs, source-status claim, representation,
retrieval response, quality, a source-scoped rights assessment, and a separate
publication clearance. The clearance records checks for personal data,
sealing or reporting restrictions, preservation of official redactions, and
sensitive material. If two official publishers serve identical bytes, the
corpus keeps two captures and one artifact. If one URL later changes, the new
observation points to a new artifact. Capture identity is independent of both
URL and repository path.

An artifact is only one immutable byte sequence: SHA-256 identity, media type,
size, storage/publication state, optional byte-level quality, and creation time.
It contains no single `source_id`, URL, rights record, or transformation route.
`official_link_only` forbids project storage. Restricted and quarantined bytes
require non-public storage. A public mirror requires public storage and at
least one typed capture or derivation publication basis; the semantic validator
must prove that basis permits mirroring and redistribution and has independent
publication clearance.

The base V1 nevertheless rejects every `public_mirror`. Those fields preserve
the future contract, but publication stays link-only until a release-as-of
delivery manifest binds rights, attribution, an unofficial-copy notice, and
the exact publication clearance.

A derivation is one append-only transformation run. It records the output
artifact, ordered and role-named input artifacts, output representation and
language where needed, tool and version, settings digest, reproducibility, and
the source captures whose rights must be checked. A reproducible run also names
the immutable settings artifact. Multiple derivation records may produce the
same output hash, preserving alternate tools or input routes. An
authority-issued translation has at least one directly captured artifact and a
verified, independently reviewed issuing assertion for that exact record
version. A record-wide publisher relationship does not establish that a
particular translation is official. Project translations are derivations and
unofficial versions. Every derivation has an output-specific publication
clearance; it cannot inherit clearance merely because its inputs were cleared.

Before publishing a derivation, resolve every rights-basis capture and its
publication clearance. Markdown, OCR and extracted text require transcription
permission; translations require translation permission; summaries require
summarisation permission; all public outputs also require mirroring and
redistribution permission. Every input route and the derivative output must be
cleared independently. Rights traversal is recursive: a source PDF transformed
to OCR, then translated, then summarized requires the applicable permission for
every step, not only summarisation for the final output. A nested `other`
transformation cannot establish publication rights automatically. `unknown`,
`review_required`, or `not_reviewed` never grants publication.
For a public evidence bundle, every derivation on the chosen route is an exact
dependency rather than an implicit corpus-wide lookup. Every input capture,
nested output, and clearance must exist no later than bundle generation.
Every artifact on that route, including transitive inputs, must also remain
outside `quarantined` and `removed_with_tombstone`; a cleared final derivative
cannot revive withdrawn source bytes.

A capture clearance cannot predate retrieval of the captured bytes. A
derivative's output clearance cannot predate that derivation's creation time.
Rights review cannot predate its terms or basis-evidence retrieval. These
orderings prevent a later artifact or evidence item from silently inheriting an
older decision. An optional rights `next_review_at` is a fail-closed validity
deadline evaluated at bundle generation or the selected corpus publication
time; its advisory `next_review_trigger` does not grant continued validity.

## Records, versions, and provisions

A record is the stable identity of a public document. It contains one or more
versions, each of which identifies:

- issued, corrected, republished, consolidated, or translated status;
- language and exact artifacts;
- publisher state, separate from legal force;
- all four intrinsic time axes; and
- provision snapshots when the document can be segmented.

Each version has its own `metadata_evidence` and `metadata_bindings` for
`version_kind`, `language`, and `publication_state`. Every binding cites an
exact source-language field span from an artifact in that version, preserves
the source value and controlled value, and uses either identical
`source_exact` values or an independent digest-bound human review. Binding and
review times cannot predate the selected artifact or capture, and the record's
`updated_at` cannot predate either the binding or its review. An
`official_translation` additionally requires a verified, independently
reviewed `issued_by` assertion attached through that exact version's issuing
authority relationship, plus at least one directly captured version artifact;
a project derivation or record-wide authority label cannot supply official
status.

Top-level record metadata is evidence-backed. `metadata_evidence` contains
immutable artifact-and-locator citations, including the source capture when the
bytes were acquired from a source. `metadata_bindings` maps
`canonical_title`, `record_kind`, and each `identifiers` array item to one or
more indexes in that evidence array. Identifier bindings also name the exact
`identifier_index`. Every title, kind, and identifier must be covered; binding
indexes must resolve, and the canonical title and identifier value must appear
at an exact field boundary in the selected quoted public text, rather than as
an arbitrary substring of a larger title or identifier. Adapters select the
exact source-language field span; the global validator does not infer titles
from English legislative phrases. A `record_kind`
binding preserves the exact source term and its normalized controlled value
under an independent, digest-bound human review, so changing both the kind and
its label still fails validation. Provision designations and headings also
carry source-to-value bindings; exact headings may use `source_exact` only when
the selected quote establishes the whole heading field, while normalized
designations retain a digest-bound review. Every binding creation time and
normalization review must be at or after both the selected artifact's creation
and its cited capture's retrieval. A filename, URL slug, importer guess, or
neighbouring record cannot silently supply these fields.

Authorities attached to a record are assertion-backed roles, not bare metadata.
Each `authority_relationships` item names an `authority_id`, a semantic `role`,
and the supporting `assertion_id`. The assertion subject must be that record,
its object must be that authority, and its predicate must match the role:
`adopting/adopted_by`, `enacting/enacted_by`, `making/made_by`,
`assenting/assented_by`, `issuing/issued_by`, `deciding/decided_by`,
`publishing/published_by`, `administering/administered_by`,
`consolidating/consolidated_by`, `translating/translated_by`, or
`custodian/held_by_custodian`. Publishing, administering, or holding a copy
does not silently establish who made, enacted, issued, or decided it. An empty
array means the roles are unmodelled, not that the record has no authority.

A provision has a stable `provision_id`. Each exact textual and temporal state
has a separate `provision_version_id`, content digest, artifact locators, and
time axes. Renumbering and substitution are assertions; they do not silently
change a provision's identity. Unofficial consolidations must name the
assertions from which they were derived.

A provision snapshot also declares `text_completeness` and `digest_scope`.
`complete` means the digest covers the canonical whole provision text;
`partial` means it covers only the named citation quotes in index order. The
canonicalization is explicit. A partial digest must never be presented as the
hash of a complete provision. A digest-bound human scope attestation is still
fail-closed when the artifact carries unresolved `possible_missing_*` quality
warnings; an attestation cannot silently erase contradictory extraction
evidence.

## Four intrinsic time axes

Every record version, provision version, and relationship assertion keeps:

| Axis | Meaning |
|---|---|
| `publication` | When the issuing authority published or decided the material. |
| `effectiveness` | When the material was legally operative. |
| `applicability` | The facts or transaction interval to which it applies. |
| `observation` | When the corpus observed this exact state. |

A point can be exact, approximate, or unknown. An interval can be known,
open-ended, unknown, or not applicable. Normalized values use the proleptic
Gregorian calendar; `verbatim_value` preserves another calendar or source
expression. For an exact or approximate record publication time, its citation
also binds that expression to the normalized value and carries reviewable
`quoted_text`; an opaque, self-consistent quote digest cannot establish what the
source said. A canonical source-exact date token is a bibliographic fact rather
than a copied passage. Other conversions require either a content-addressed
settings artifact or an independent identified human review. Unknown values
must stay unknown rather than inheriting a nearby publication or Git timestamp.

On record and provision versions, a known or open-ended effectiveness or
applicability interval requires at least one `basis_assertion_id`. A cited
commencement, retrospective-effect, transition, stay, repeal, or scope
assertion—not a nearby date—is what supports the legal interval.
The basis must be reviewed as verified or superseded, target the same record or
provision, use a predicate capable of establishing that axis, state the same
interval, and collectively cover the record's jurisdictions. Merely resolving
an assertion ID is insufficient.

These are not the agent query's four fields. An evidence bundle separately
requires `evaluation_context.facts_period`, `effective_at`,
`authority_cutoff`, and `corpus_snapshot`. The authority cutoff limits which
published authorities an answer may consider. The snapshot makes retrieval
reproducible.

## Relationship assertions

Relationships are typed assertions, not mutable properties on a document.
Predicates include amendment, insertion, substitution, correction,
commencement, repeal, expiry, supersession, interpretation, citation, stay,
invalidation, overruling, distinction, limitation, institutional parentage,
territorial containment or overlap, jurisdiction service, and review of another
authority's decisions. Structural predicates constrain their typed endpoints
and use `applicability: not_applicable`; their effective interval remains
explicitly known, open-ended, or unknown.

Every assertion has:

- typed subject and object references;
- whole-document or provision-level scope;
- intrinsic time axes;
- `explicit_source_text`, `structural_inference`, or
  `legal_interpretation` classification;
- candidate, verified, disputed, superseded, or retracted state;
- confidence and producer metadata; and
- at least one artifact-and-locator citation.

Reviewed states require `reviewed_at`. Both producer and reviewer use stable
producer IDs; name-and-version matching is not an independence check. Review
cannot predate creation of the assertion or acquisition of its cited evidence.
Conflicting assertions coexist and cite one another through dispute or
supersession IDs; history is not overwritten. A superseding or disputing
assertion cannot precede the observation of the assertion it names. Likewise,
a record or provision version cannot name a predecessor first observed later.
An assertion history edge must keep the same subject and object and overlap in
scope. Supersession keeps the same predicate; a dispute keeps the same predicate
or a controlled conflicting predicate family. Evidence selection follows both
outgoing and incoming history, because the newer assertion owns the edge to its
predecessor.

## Coverage ledgers

Coverage is always a dated claim over a declared envelope:

- jurisdictions, authorities, document kinds, and languages;
- publication, effectiveness, applicability, or observation date axis;
- a bounded or open interval; and
- the entrypoints actually enumerated.

States are `unknown`, `enumerating`, `covered_for_declared_scope`,
`known_gap`, `stale`, `degraded`, and `blocked`. The strongest state requires a
successful enumeration and no unresolved gap. `known_gap` requires an explicit
open, investigating, or accepted-unresolved gap. Gaps have stable IDs, affected
intervals, evidence, checks, and resolution history.

“Covered” never means globally complete. It means only that the declared
methods account for the declared envelope as of the ledger timestamp.
`covered_for_declared_scope` cannot use an unknown or not-applicable date
interval. A superseding ledger must preserve the exact source and declared
scope and be generated strictly after its predecessor.

Selecting an older ledger by ID does not freeze away a newer result. An
evidence bundle must use the newest directly superseding ledger visible at its
selected snapshot; a snapshot-visible successor makes its predecessor stale
for bundle coverage even when the bundle never names the successor.

The v1 local validator reserves but does not yet admit
`covered_for_declared_scope`. A successful run's integer `discovered_count`
cannot prove which objects were enumerated. Positive coverage remains
fail-closed until each run resolves to a content-addressed result manifest and
the ledger binds the exact source-manifest revision; source changes then
invalidate the ledger instead of silently reusing it.

## Correction reports

A correction report is an untrusted lead, never a corpus patch. Its fixed
finding types cover missing documents, metadata, conversion, version-chain,
relationship, source, coverage, and rights defects. Proposed actions are typed
data, not executable patches.

The base V1 has no trusted project repository, issue bot, private intake, or
authenticated receipt verifier. It accepts local reports and fully gated
`READY_TO_OPEN` payloads only. It rejects `AWAITING_USER_ACTION`,
`PRIVATE_DRAFT`, `OPENED`, `EXPIRED`, `REVOKED`, every public-review state,
`public_issue`, and `application`. Those lifecycle values reserve a future
protocol; their presence is not evidence that the protocol is live.

The report schema has separate finding, draft, privacy, and public-review
states. Verified finding states must agree with verification state. A privacy
block forces `LOCAL_ONLY` and forbids any public issue. Duplicate states require
the earlier report ID. Any public-review state requires a factual public
summary and a bot-created issue reference.

In the future protocol, an `OPENED` public report is reconstructed from public
sources by the privacy broker; its submission mode is `broker_sanitized`, never
promotion of a local or user-submitted payload. Source-monitor publication is
disabled until its acquisition and signed-run contract is modeled. The report
requires a `privacy_review` of the complete reconstructed payload with
`independently_reproduced_public_sources` origin, an identified human reviewer,
and a SHA-256 bound to the exact canonical pre-publication report. The
projection omits the receipt fields `draft_status`, `public_review_status`,
`public_issue`, `application`, and `duplicate_of_report_id`, plus
`privacy_review.reviewed_payload_digest` itself. The reviewer, evidence, and
clearance decisions remain covered. A future authenticated issue receipt must
repeat that reviewed digest. Every `public_evidence` item also carries its own cleared
publication decision at or after its retrieval. Verification cannot predate a
supporting or contrary evidence retrieval. The payload review cannot predate
any evidence retrieval or publication clearance. Automated scanning, a generic
maintainer name, or one blanket clearance cannot satisfy these gates.

When correction evidence discloses a `public_excerpt`, it also carries the
excerpt digest and an independent `content_verification` attestation. That
attestation binds the exact artifact, capture, locator, excerpt digest, method,
time, and verifier. A self-consistent excerpt hash does not prove source
inclusion, and the verification cannot predate acquisition or postdate the
containing report state.

In the future protocol, `APPLIED` is an evidence-bearing state, not a
maintainer label. Its
`application` object records the public `merge_commit_url`, the
`invalidation_event_id`, and the content-addressed `snapshot_after`. Those
references must resolve to the merged correction, its successful propagation,
and the resulting published snapshot. `PROPAGATION_FAILED` carries the same
application coordinates for the failed attempt, while affected outputs remain
stale. For either state, the resolved invalidation event cannot predate the
report's verification, any evidence retrieval or clearance, or privacy review.

`privacy_attestation` requires false values for user query, user facts,
authentication material, local-file content, and sender identity. The strict
schema also forbids arbitrary fields. The semantic privacy validator rejects
forbidden key names, credentials, signed or tracking URLs, local/non-public
hosts, and unsafe text. Passing these checks is a gate, not proof that a report
is harmless; the broker still reconstructs its own public payload from
independently retrieved public sources.

## Evidence bundles

An evidence bundle is a derived, snapshot-bound packet for an agent. It has one
top-level agent status: `SUPPORTED`, `CONFLICTED`, `MISSING_FACTS`, or
`INSUFFICIENT_COVERAGE`. It includes:

- the four query evaluation fields;
- all stable dependencies used;
- direct or derived claims and exact citations;
- assertion and contrary-assertion IDs;
- coverage states and gap IDs;
- unresolved conflicts or missing dependencies; and
- independent verification tasks.

Each claim names exact `subjects`. `dependencies` contains the snapshot and
every subject, assertion, citation route, coverage ledger, and transitive entity
needed to invalidate or replay the claim. Artifacts, captures, and derivations
on that route must exist by the selected snapshot, not merely by later bundle
generation. Capture-less derived evidence selects exactly one producing
derivation dependency, which recursively brings its inputs, settings, and
rights-basis captures into the closure. Source identity evidence is part of the
same replayable closure. The snapshot cutoff also applies to the complete state
of every declared truth or evidence dependency: its observation, evidence
bindings, and independent truth reviews cannot be borrowed from the future.
Capture and derivation rights or publication-clearance reviews are delivery
state and may follow the snapshot, but must follow the retrieved or derived item
and precede bundle generation and public release. Public bundles preserve that
separate delivery clock through digest-bound `delivery_bases`: every relied-on
capture or derivation clearance is pinned, as is each capture rights review used
for redistribution. This applies to every selected capture or derivation
dependency, including routes reached through profile evidence, record or
provision content, source identity, assertions, and coverage enumeration—not
only the bundle's top-level citations. Every selected route must have valid
clearance and remain outside quarantine or removal. A stable entity ID alone
cannot identify mutable release state. Resolved conflicts stay in the bundle and name reviewed resolution
assertions. Every unresolved conflict uses one
exact assertion set across an affected claim's supporting and contrary IDs, one
blocking `conflicting_assertions` item, and one `reason: conflicting`
verification task. The blocker and task name that same assertion set and the
same affected claim IDs. Each assertion must concern a non-assertion subject of
the affected claim, so unrelated relationships cannot manufacture
`CONFLICTED`.
For every relied-on assertion, including nested time-basis assertions, the
bundle also closes over reviewed incoming supersession and dispute edges visible
by the selected snapshot when they may affect the evaluation context. A
superseder remains in the same evidence role; a disputer moves to the opposite
role and is modeled as a conflict. Unknown time cannot prove irrelevance.
For non-bibliographic claims, the same reverse-history rule applies to record
versions and provision versions. Every snapshot-visible successor that may
affect the evaluation context is an explicit dependency, appears in the
claim's modeled state, and is connected through a matching transition
assertion. A containing version also closes the history of provision versions
used beneath it. Omitting the newer state requires an exact blocking
`missing_dependency`; an unmentioned successor cannot silently disappear.
`content_use` distinguishes bibliographic facts from copied excerpts,
summaries, translations, and unclassified uses. Public excerpts and transforms
must resolve the source-scoped reviewed permissions needed for redistribution
and each transformation. A privacy clearance never substitutes for that rights
route. Under unknown rights, only safe bibliographic facts, official links,
retrieval times, and hashes may appear.
Summaries and translations are `DERIVED`. A transformed-content label cannot
hide a material verbatim passage already known at the same source capture and
locator; that passage must be classified as a source excerpt and satisfy
transcription rights. Verbatim comparison removes Unicode format controls and
variation selectors, so invisible characters cannot relabel copied text.
`bibliographic_fact` is not a free-text escape hatch: the bundle carries
subject-indexed structured fields, every value must exactly match whitelisted
corpus metadata, and `claim_text` is their deterministic rendering. A stable
provision ID cannot supply a designation or heading because those fields can
change; such a fact must name the exact `provision_version`.

A quote digest proves consistency of the disclosed quote, not that the quote
occurs in the cited bytes. Every evidence citation that discloses quote text or
its digest therefore carries an independent `content_verification` attestation.
It binds the exact artifact ID, optional capture ID, locator, and quote digest,
identifies the verifier and method, and records when the check occurred. The
check cannot predate the artifact or capture or postdate the enclosing
document's lifecycle clock. For a bundle citation it must also exist by the
selected snapshot and bundle generation. Capture acquisition and discovery
evidence obeys the same snapshot cutoff. A temporal normalizer cannot serve as
its own source-content verifier. Where selected bytes are locally available,
the verifier should perform an exact machine match; otherwise a human visual
match is an explicit attestation, not cryptographic proof of source truth.

Every coverage result is a snapshot-bound dependency, not copied status text.
Its `coverage_id` must resolve to a coverage ledger and the same ID must appear
in `dependencies` as `entity_type: coverage`. The `status`, `fresh_until`,
`last_successful_enumeration_at`, and `gap_ids` in that coverage result must
exactly match the resolved ledger, including every open, investigating, or
accepted-unresolved gap. A bundle cannot omit the ledger dependency or soften
its state while retaining an optimistic answer status. It also cannot select a
ledger whose direct superseder was already visible at the snapshot.

A `SUPPORTED` bundle must contain claims and citations, use only
`covered_for_declared_scope` coverage with no gaps, and contain no conflicts,
unresolved items, or pending verification tasks. A derived claim requires at
least one assertion. An insufficient-coverage bundle requires a blocking
unresolved item. Safety flags make the unofficial, coverage-qualified boundary
machine-readable.

`CONFLICTED` also requires positive, gap-free, current coverage and no blocking
unresolved check; conflict is not a substitute for inadequate coverage. For
both positive and conflicted answers, `fresh_until` must be at or after the
bundle's `generated_at`. Any material missing, gapped, non-positive, or expired
coverage takes precedence over apparent conflict or missing user facts and
forces `INSUFFICIENT_COVERAGE`. `MISSING_FACTS` is available only when the
coverage needed to identify those missing facts is adequate. That ordering and
status precedence are semantic validator checks.

Sensitive-looking claim details must be present in the claim's cited public
text. The validator currently rejects uncited currency amounts and email
addresses; this is a narrow structural safeguard, not a complete privacy
review.

Query shape can itself disclose a person even when no obvious private field is
present. Interactive bundles therefore use `client_ephemeral` and are not
logged, cached, uploaded, registered, or replayed server-side. A
`private_retained` bundle has an explicit expiry. A `public` bundle is newly
constructed from public-only inputs, requires cleared cited inputs, and carries
identified human publication clearance bound to the exact canonical bundle
digest. Closed public-corpus validation rejects ephemeral and private bundles.

## Composite snapshots

A snapshot is a content-addressed manifest spanning any number of independently
versioned components. Each component has a stable `ComponentId`, kind, revision
identifier, SHA-256 root digest, and optional authority and jurisdiction scope.
The set can combine global core, registry, adapters, corpora, and object indexes
across repositories without storing a GitHub URL or forcing one country per
component. The schema catalog records the exact schema IDs, versions, and byte
digests used. In closed-corpus validation, every selected snapshot's catalog
must equal the set of schema contracts named by the selected documents plus the
transitive closure of their local `$ref` targets. Missing contracts, contracts
outside that closure, and duplicate schema IDs fail validation. The closure is
derived from the selected schema registry, including a custom `--schemas`
directory; the catalog cannot define its own expected membership.

Snapshot hashing has one contract. Parse JSON or YAML into the JSON data model,
reject YAML aliases, recursive containers, non-JSON values, documents nested
more than 128 levels, and expanded validation walks over 250,000 nodes. Require
`components` sorted by `component_id` and
`schema_catalog` sorted by `schema_id`, remove only the root `snapshot_id`
member, serialize the remaining root object with RFC 8785 JSON
canonicalization, and SHA-256 the UTF-8 bytes. The snapshot ID is
`urn:trace-the-law:snapshot:sha256:<digest>`. The validator must recompute it;
serialization whitespace, object key order, and JSON-versus-YAML input do not
change identity. Component repositories independently publish the manifest
whose root digest and revision the snapshot commits to.

The self-hash authenticates the snapshot's asserted component roots; it does
not by itself prove that those roots contain the claimed corpus. A consumer must
resolve each `component_id` and revision to its independently published
component manifest and recompute `root_digest`. An unavailable component
manifest makes reproduction incomplete and must surface as insufficient
coverage, not as a verified snapshot. Every non-genesis snapshot names both
`predecessor_snapshot_id` and the exact `transition_event_id` whose before and
after IDs bind that edge. A closed corpus contains exactly one genesis
snapshot, and all other snapshots stay on its event-bound predecessor chain.
The predecessor's `generated_at` is strictly earlier. Because trusted external
receipts are not configured, base V1 ships only the genesis snapshot;
post-genesis snapshots use `.template` examples and are rejected by the default
publication gate.

## Invalidation events

An invalidation event connects an old and new content-addressed snapshot. The
base V1 schema permits only a resolved correction report in the required
reviewed lifecycle state as its cause. Source-monitor causes are disabled until
a signed monitor-run contract exists. The event records each changed stable ID
and rebuild results for normalized artifacts,
provisions, graph, summaries, search, embeddings, coverage, and evidence
bundles. A `LOCAL_ONLY`, `READY_TO_OPEN`, or unverified correction report may
create review work but cannot be an invalidation cause. Since the base V1 also
rejects public lifecycle receipts, no invalidation event or post-genesis
snapshot can pass the complete base publication gate yet.
The before snapshot must predate the after snapshot, and the event time must
fall between their generation times.

`succeeded` propagation permits only succeeded or unnecessary rebuilds;
`failed` requires a failed rebuild and its failure code; `pending` requires a
pending rebuild. Historical bundles retain their old snapshots. The public
event contains no user data.

## Deterministic semantic checks

The repository validator must supplement JSON Schema with checks that require
more than one value or document:

1. Artifact ID digest equals `content_digest.value`; every capture's retrieved
   bytes hash to its artifact; duplicate capture events are reconciled without
   collapsing distinct sources; every referenced artifact is reachable under
   its recorded access state.
2. Every derivation input, output, settings artifact, and rights-basis capture
   resolves; inputs do not form cycles; settings digest matches its artifact;
   public output permissions match its representation and every relevant source
   capture, including every explicitly selected nested transformation; every
   basis capture and every derivative output have independent, human publication
   clearance whose review does not predate the bytes or output or postdate a
   public bundle that relies on it.
3. Stable IDs are unique, entity-reference prefixes match their types, all
   references resolve, and record/provision parent graphs are acyclic.
4. Temporal values match their precision and use the proleptic Gregorian
   calendar after normalization; interval start is not after end; an
   observation is not silently substituted for publication or legal effect.
5. Artifact citations resolve to the exact bytes and locator; source-acquired
   citations name a capture that resolves to that artifact; quoted-text and
   provision-content digests match the declared complete or partial scope;
   quote-bearing evidence has an independent digest-bound content verification;
   record title, kind, every identifier, and provision designation and heading
   have valid evidence bindings; context-sensitive normalizations are bound to
   exact independent-review digests.
6. Authority and jurisdiction adjacency references resolve to canonical
   assertions with matching subject, object and predicate; every record
   authority role resolves to the exact role-specific assertion and authority;
   every profile classification and sourced-name field has one local,
   exact-boundary evidence binding, while non-source-exact mappings have
   independent digest-bound human review; reviewed profile and name claims use
   stable, distinct producer identities;
   structural and court review graphs use only reviewed relationship windows
   and do not self-cycle while those windows overlap where the predicate is
   acyclic.
7. Assertion endpoints exist, typed predicates permit their endpoint classes,
   reviewed decisions use stable producer and reviewer IDs after the assertion
   and evidence exist, supersession/dispute chains do not self-cycle or connect
   unrelated propositions, and bundles cannot omit a context-relevant reviewed
   incoming history edge visible by their selected snapshot.
8. Coverage entrypoints exist in the source manifest, independent groups are
   genuinely distinct, freshness dates are ordered, and counts reconcile with
   captured identities; a bundle cannot use a coverage ledger superseded by a
   ledger already visible at its snapshot.
9. Evidence-bundle `citation_indexes` are within the citations array, claim and
   dependency IDs resolve, each sensitive detail appears in one cited public
   quote, bibliographic values are exact structured subject metadata,
   every coverage ledger is an explicit dependency whose copied state and gaps
   match exactly, material coverage failure has status precedence,
   positive/conflicted coverage is fresh at generation, and the selected
   evidence falls within the declared evaluation context and was available in
   its selected state by the snapshot; public delivery pins every later
   clearance or reuse-rights decision it relies on; non-bibliographic claims
   close over snapshot-visible record-version and provision-version successors
   and their transition assertions.
10. Snapshot arrays are ordered and unique, component and schema digests
    resolve, and snapshot IDs recompute under the documented RFC 8785
    projection.
11. A non-genesis snapshot has one resolving transition event, the closed corpus
    has one genesis, and invalidation snapshots differ, resolve, and are strictly
    time-ordered around the event; pending or failed propagation blocks every
    descendant until a later successful repair on the selected lineage.
12. Once trusted receipts are enabled, an `APPLIED` correction's merge commit,
    invalidation event, and replacement
    snapshot resolve and agree; the event identifies the correction and records
    successful propagation. A failed application remains
    `PROPAGATION_FAILED` and cannot expose a successfully published replacement
    as if the correction had applied.
13. Once the future public flow is enabled, a public correction is reconstructed
    by the broker, every evidence item has publication clearance, and an
    identified human reviews the complete pre-publication payload after evidence
    retrieval. Invalidation causes resolve a correction in the required reviewed
    state; local, ready-only, unverified, and unmodeled source-monitor reports
    cannot trigger propagation.

These checks establish internal consistency and reproducibility. They do not
establish universal completeness, official status, legal force, or correct
application to a person's situation.
