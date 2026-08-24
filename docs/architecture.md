# Architecture

**Trace the Law is an evidence system, not an authority and not a legal-answer
database.** Immutable source captures sit below reviewable assertions and
rebuildable agent inputs. No crawler, agent, report, or GitHub issue writes
directly into the corpus.

The base V1 implements local evidence contracts, a genesis snapshot, and
fail-closed validation. It has no trusted GitHub organization, intake service,
issue bot, receipt verifier, or public-mirror delivery manifest. Public
correction receipts, invalidation events, post-genesis snapshots, and public
artifact mirrors are therefore disabled; their schemas describe guarded future
interfaces, not live capabilities.

## Global core and adapters

The global core defines identifiers, schemas, validators, correction workflow,
and the agent contract. A jurisdiction adapter adds source manifests,
institutional hierarchy, language handling, rights and privacy rules, and
bounded coverage ledgers. Adapters may represent national, supranational,
subnational, Indigenous, treaty-based, or historical legal systems without
forcing them into a country-only hierarchy.

The initial repository split is:

- a global core for schemas, validators, governance, and agent skills;
- a global source registry for authorities, source manifests, and coverage
  discovery; and
- one corpus repository per country or independently governed legal system at
  first.

Subnational sources stay with their parent corpus until measured Git, build, or
stewardship limits justify a split. Large corpora may later shard by stable
jurisdiction or publisher and time window. They must not shard by topic: tax,
labour, trade, criminal, and constitutional material routinely cross-link.
Stable IDs are URNs and never contain repository paths, so files can move
without breaking the graph.

## Evidence layers

1. **Source manifest:** declares who publishes a source, what it contains, how
   it can be enumerated, and its rights and access boundary.
2. **Capture:** one append-only retrieval from one source. It keeps the source
   URL, retrieval response, exact artifact hash, source status, and
   source-scoped rights plus a separate privacy and publication clearance.
   Identical bytes at two sources create two captures and one artifact, so
   deduplication loses no official link or provenance.
3. **Artifact:** one immutable byte sequence identified only by SHA-256.
   Storage and publication state may point to capture or derivation routes, but
   source and transformation claims are not embedded in byte identity.
4. **Derivation:** one transformation run with ordered, named input artifacts,
   one output artifact, tool and settings identity, reproducibility state, and
   source-capture rights bases plus output-specific publication clearance.
   Multiple runs may produce the same output hash. Publication rights are
   resolved through the complete nested transformation chain, not only the
   final run. Public evidence bundles name every chosen hop explicitly; no
   favorable undeclared route may be discovered from the wider corpus. A route
   fails if any transitive artifact has been quarantined or removed.
5. **Authority and jurisdiction profiles:** field-bound sourced names and
   classifications for the typed graph nodes used everywhere else. Authority
   kind, every branch, jurisdiction kind, lifecycle state, and every component
   of every name resolve to their own exact evidence bindings. Hierarchy,
   territorial containment or overlap, service scope, and decision-review
   competence remain separately cited, time-aware relationship assertions.
6. **Record:** stable identity for a public document, with evidence-bound title,
   kind, external identifiers, version kind, version language, publisher state,
   provision designations, and headings; assertion-backed authority roles;
   issued or derived versions; and provision-level snapshots. Context-sensitive
   controlled values use independent digest-bound review. Official translations
   additionally require reviewed authority issuance for the exact version and
   at least one directly captured artifact.
7. **Relationship assertion:** a typed claim such as `amends`, `commences`,
   `stays`, `interprets`, or `overrules`. It cites an exact artifact locator and
   carries interpretation, confidence, and review states. Disclosed source text
   or its digest also carries an independent content-verification attestation
   binding the artifact, capture, locator, and quote digest; self-consistent
   quote text is not proof that the source contains it.
8. **Evidence bundle:** a snapshot-bound selection for an agent. It includes
   cited dependencies, conflicts, unresolved items, coverage state, and
   independent checks still required.

Summaries, tags, consolidated views, search indexes, embeddings, and suggested
applicability are derived outputs. None can overwrite or acquire the official
status of a source artifact.

Authority and jurisdiction topology is a graph, not a rank column or country
tree. `institutionally_part_of`, `serves_jurisdiction`,
`territorially_within`, `territorially_overlaps`, and
`reviews_decisions_of` assertions can change over time and may coexist or be
disputed. An empty parent list means unmodelled, not parentless. Adapters decide
the locally correct court-review and institutional structure; the global core
does not assign a universal numeric legal rank.

Profile adjacency is discovery data, not proof that an authority serves a
jurisdiction for a claim. That scope must resolve to the exact
`serves_jurisdiction` assertion, reviewed and context-eligible by the selected
snapshot. Candidate, disputed, retracted, future-reviewed, or merely adjacent
relationships cannot establish jurisdiction. Likewise, a public bibliographic
claim may use an authority or jurisdiction name only when that exact sourced
name was created and independently reviewed by the snapshot; an unreviewed
profile value remains a lead.

Record authority is also asserted, not inferred from the website that hosted a
file. Each authority role points to a cited relationship whose subject is the
record, whose object is the authority, and whose predicate matches the role.
Publishing, administering, translating, or holding a copy does not establish
who enacted, made, issued, or decided the record.

Reviewed legal and profile claims use stable producer IDs for both the creator
and reviewer. Reviewed rights, publication-clearance, and correction-privacy
decisions use an identified human reviewer's stable producer ID. Display names
and software versions are presentation metadata, not proof of independence.
No review timestamp may predate the claim, source evidence, captured bytes, or
derived output it purports to review. Profile classifications and sourced-name
fields bind exact whole-field source-language values; a non-source-exact
mapping requires an independent human review digest over the complete binding.
The core does not infer a language, institution type, or lifecycle state from
English labels or any other language-specific heuristic.

## Time model

Each record or assertion keeps four intrinsic clocks under `time_axes`:

- `publication`: when the responsible authority published or decided it;
- `effectiveness`: when it was legally operative;
- `applicability`: the facts or transaction period to which it applies; and
- `observation`: when this exact state was observed by the corpus.

Unknown is an explicit value. Publication does not imply commencement, later
publication does not prevent retrospective applicability, and Git history is
not legal time.

An agent query has a separate evaluation context: `facts_period`,
`effective_at`, `authority_cutoff`, and `corpus_snapshot`. `authority_cutoff`
limits which published authorities may be considered; it is not a fifth
intrinsic clock. A corpus snapshot is content-addressed and includes a recorded
time, but it does not replace artifact observation times.

The snapshot is an availability boundary for the complete selected evidence
state, not only the cited bytes. A bundle cannot backfill a dependency,
observation, evidence binding, or truth review that was created after the
snapshot. Delivery reviews are a distinct clock: source-capture and derivation
rights or publication clearance may be completed after the snapshot so an older
state can later be delivered lawfully, but they must follow the retrieval or
derivation they review and precede bundle generation and public release. A
later delivery decision does not add legal evidence to the older snapshot. A
bundle-local content verification must exist by both the selected snapshot and
bundle generation; a later attestation cannot be backdated into an older
answer. A public bundle pins the valid clearance for every selected capture or
derivation dependency—including nested evidence and content or coverage
routes—and each rights review used for redistribution, by digest inside its
independently reviewed payload. A bare capture or derivation ID is not
replayable delivery proof.

`SUPPORTED` is fail-closed across that context. Each substantive claim has a
known applicability interval covering `facts_period`; a bibliographic-only
claim may instead say `not_applicable`. Every relied-on version, provision
version, and relationship assertion must concern the requested jurisdictions
and structured scope, be effective at `effective_at`, apply throughout
`facts_period` when applicability is relevant, and have a known publication no
later than `authority_cutoff`. Unknown or out-of-context evidence remains
visible behind an exact blocking unresolved item and forces
`INSUFFICIENT_COVERAGE`; a fluent claim cannot make it eligible.

## Source-driven acquisition and completeness

Every adapter declares entrypoints and whether each is exhaustive, partial,
discovery-only, or unknown. Scheduled jobs capture index snapshots, enumerate
declared ranges, fetch artifacts, compare hashes, and reconcile independent
entrypoint groups. Citation mining creates leads for referenced-but-missing
documents. Structural checks detect numbering gaps, date gaps, dangling
amendments, broken links, and parser regressions.

Every capture has a fail-closed acquisition route. It either records the exact
URL of its declared manifest entrypoint or cites the exact link value and
successful parent capture through which that URL was discovered. The lineage
must terminate at the declared entrypoint without crossing sources or forming a
cycle. Any response other than a complete HTTP 200 remains useful monitoring evidence, but its bytes
cannot establish a legal/profile citation, derived provenance, or publication
route.

Coverage is a dated claim about one envelope: jurisdictions, authorities,
document kinds, languages, date axis, date interval, and entrypoints. Its states
are `unknown`, `enumerating`, `covered_for_declared_scope`, `known_gap`,
`stale`, `degraded`, and `blocked`. `covered_for_declared_scope` never means all
relevant law exists in the corpus. Every gap remains addressable and visible.
In v1 the validator deliberately rejects this positive state until successful
enumeration runs resolve to content-addressed result manifests and bind the
exact source-manifest revision. Naked discovery counts cannot prove coverage.

The highest-risk failure is a successful crawler that missed a source family.
Agents therefore inspect coverage before retrieval and say “not found in the
declared coverage” rather than “does not exist.” A stale, failed, or unknown
material source forces `INSUFFICIENT_COVERAGE` under the agent contract. That
coverage failure outranks an apparent conflict or missing user fact; neither
may mask an incomplete evidence envelope.

An evidence bundle must name each resolved coverage ledger as an explicit
dependency and reproduce its status, freshness, enumeration time, and unresolved
gap IDs exactly. Coverage is not a free-text summary that retrieval may soften.
A ledger directly superseded by another ledger visible at the selected snapshot
cannot be selected as if it were still current.

## Correction and trust boundaries

Reports can create work; they cannot create facts.

The following numbered flow is the future service design. In base V1 the flow
stops after step 2: an agent keeps a candidate local or prepares a fully gated
`READY_TO_OPEN` payload, but it does not transmit it or offer a reporting URL.

1. A client agent independently checks an official public source when it
   suspects a defect.
2. It builds a local correction candidate containing only public source
   evidence and typed changes. The user's question and facts stay local.
3. After explicit user review, private intake treats the candidate only as a
   lead. The privacy broker validates, deduplicates, rate-limits, independently
   refetches public evidence, and reconstructs a new public payload. A source
   monitor follows the same reconstruction boundary without user context.
4. Every public evidence item receives its own publication clearance at or
   after that item was retrieved. Verification cannot predate any supporting or
   contrary evidence retrieval. An identified human then reviews the complete
   reconstructed payload at or after every evidence retrieval and publication
   clearance. That review is bound to the SHA-256 of the exact canonical
   pre-publication report, including the reviewer and clearance decisions. Its
   projection omits receipt fields and its own digest. Only then may a future
   project bot create a sanitized GitHub issue and return an authenticated
   receipt carrying that same digest. The issue is a workflow
   projection, not a corpus record.
5. A bot or maintainer proposes a separate pull request. Schema checks,
   artifact integrity checks, citations, rights policy, publication clearance,
   and review gates must pass before merge.
6. Merge creates a new corpus snapshot and triggers dependency invalidation.
   A correction-caused invalidation event cannot predate verification, any
   evidence retrieval or clearance, or the complete-payload privacy review.

Source monitors may prepare local evidence leads, but V1 has no signed
monitor-run contract and does not accept a source-monitor run as an invalidation
cause. A future monitor protocol must use the same evidence, clearance, and
public-payload review boundary and still receives no privileged corpus mutation
path.

Trust boundaries are explicit:

- the client owns private query context; interactive evidence bundles are
  ephemeral and their dependency IDs may be retained separately without
  retaining the query-shaped payload;
- correction intake treats every submission as an untrusted lead;
- sandboxed fetchers retrieve public evidence without forwarding client
  cookies, credentials, or headers;
- source text is untrusted data and never executable agent instruction;
- assertion review evaluates a project claim, not the authority of the project;
  and
- a merged corpus remains unofficial and may still be corrected.

Anti-abuse controls include a fixed report schema, no arbitrary uploads,
credential and private-data rejection, URL normalization, SSRF and DNS-rebinding
protection, MIME and size limits, malware and archive-bomb checks, duplicate
aggregation, rate limits, bot-created public issues, Markdown escaping, and
rights and publication-clearance quarantine. Reporter reputation can prioritize
review but never establish truth. Batching or delaying user-triggered reports
prevents submission timing from revealing a legal concern.

## Propagation and reproducibility

Artifacts are append-only. A changed official URL creates a new artifact; a
converter upgrade creates a new derived artifact; a corrected relationship
supersedes or disputes an earlier assertion. Historical snapshots remain
reproducible.

History closure is bidirectional. Following an older assertion's outgoing
links is insufficient because the newer assertion owns the supersession or
dispute edge. For each relied-on assertion and each nested time-basis assertion,
a bundle also traverses reviewed incoming edges visible by the snapshot. A
context-relevant superseder remains in the same supporting or contrary role; a
disputer moves to the opposite role and appears in the conflict model. Unknown
time cannot be used to prove that a visible incoming edge is irrelevant.

Reverse closure also covers record and provision versions. A
non-bibliographic claim includes every snapshot-visible successor that may
affect its context, models that state in the claim, and carries the matching
transition assertion. Coverage uses the same fail-closed principle: a visible
direct successor makes the selected predecessor ledger stale.

After a future receipt verifier is enabled, invalidation walks this dependency
order:

```text
source manifests + captures + immutable artifacts
  authority and jurisdiction profiles
  derivation records + normalized artifacts
  records + provision versions
    relationship assertions
      summaries, search indexes, and evidence bundles
```

The build marks affected descendants stale before rebuilding them. Publication
of the replacement snapshot is atomic: clients never receive a mixture of old
and new graph state. An invalidation event lists changed stable IDs and rebuild
outcomes. Clients can retain evidence-bundle dependency IDs locally and compare
them with the public invalidation feed, so earlier answers can be flagged
without the server learning the underlying questions.

Only deliberately retained public bundles participate in server-side replay.
A public bundle is reconstructed from public-only inputs, not promoted from an
interactive answer, and receives identified human publication review bound to
the exact canonical payload—including reviewer identity and clearance checks,
with only the digest field omitted from its own projection. Private retained bundles have explicit
expiry and never enter a public corpus. This prevents dates, jurisdictions,
claim selection, or request timing from becoming a quiet reporting channel.

Invalidation has only attributable causes. Base V1 permits only a correction in
the required independently verified and reviewed lifecycle state; source-monitor
causes remain disabled until their signed-run contract exists. A local,
ready-only, or unverified report can create review work but cannot mark
dependencies stale, rebuild outputs, or produce a replacement snapshot. Since
base V1 rejects the required external lifecycle receipts, its event and
post-genesis snapshot examples remain non-publishable `.template` files.

In the future protocol, a report reaches `APPLIED` only after its separate
corpus change is merged and
all required propagation succeeds. Its application proof records the public
merge commit, the resolving invalidation event, and the content-addressed
replacement snapshot. Those references must agree with one another; a status
label alone is not proof. The invalidation event must occur at or after the
report's verification, every evidence retrieval and publication clearance, and
its complete-payload privacy review. Otherwise the report remains
`PROPAGATION_FAILED`, records the attempted application coordinates, and
affected outputs stay visibly stale.

Every published corpus state has a snapshot document. Its content-addressed ID
commits to ordered component identities, revisions and root digests across the
global core, registry, adapters and corpora, plus the exact schema catalog. A
component ID is independent of its repository location; repository URLs are
optional discovery data outside the hash contract. This supports a single
answer spanning several country or institutional repositories without claiming
that any Git host is permanent. A resolved predecessor is always strictly older
than its successor, and every non-genesis edge is bound to the exact
invalidation event that names its before and after snapshots. A closed corpus
has exactly one genesis. Base V1 publishes no later edge until trusted receipts
are enabled.

## Storage and publication

Git stores schemas, manifests, capture and derivation metadata, normalized
Markdown, assertions, coverage ledgers, and review history. Large original
binaries live in content-addressed object storage with hashes and, where
permitted, redundant mirrors. Every original source URL stays on its capture;
an official URL must never be the only preservation copy when mirroring is
lawful.

Reuse rights and publication clearance are independent gates, not cleanup
tasks. Rights answer whether the project may copy, transform, mirror, and
redistribute. Clearance separately checks personal data, sealing or reporting
restrictions, preservation of official redactions, and sensitive material.
Passing either gate never implies passing the other. `unknown` rights or a
`not_reviewed`, restricted, or quarantined clearance does not permit a public
mirror. A derivative needs cleared source routes, permissions accumulated from
every nested transformation, and its own output clearance. Rights review must
follow its evidence retrieval; source clearance must follow byte retrieval;
output clearance must follow derivation creation.
Even when those checks pass, base V1 rejects `public_mirror` until a
release-as-of delivery manifest binds attribution, an unofficial-copy notice,
rights review, and clearance for the delivered bytes.
Restricted or uncertain artifacts may expose only safe bibliographic facts,
official links, retrieval times, and hashes until reviewed. Sensitive official
material may be quarantined even when technically public. Removal must also
invalidate transcriptions, summaries, indexes, caches, and graph edges;
deleting one file is not sufficient.
Public bibliographic claims are structured subject metadata, not arbitrary
prose. Designations and headings belong to an exact provision version, not its
stable cross-version identity. Public bundle release review is bound to the exact payload including the
reviewer and checks, with only the digest field omitted from its own projection.
Its delivery bases bind the exact capture and derivation clearance digests and,
when content reuse is relied on, the exact capture rights-review digests.
Summaries and translations are derived claims; copied source language cannot be
relabelled as a transform to bypass transcription permission.

The India GST pilot exercises this architecture as adapter one. It contributes
no India-specific assumption to the global schemas.

Validation has two explicit scopes. Fragment mode checks one document or an
open cross-repository selection without assuming that every global dependency
was vendored locally. Closed-corpus mode is the CI and publication gate: every
reference, provenance route, snapshot, and public-bundle dependency must
resolve inside the selected composite input. Evidence used by a bundle must
be available in its complete selected state by the snapshot; a derived evidence
route selects one exact derivation and recursively closes over source identity,
inputs, settings, and rights captures. JSON and YAML are untrusted structured
inputs. YAML aliases are rejected before construction, recursive containers
are outside the data model, nesting is limited to 128 levels, and validation
stops after 250,000 expanded nodes rather than exhausting the process.
