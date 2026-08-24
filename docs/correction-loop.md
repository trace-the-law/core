# Correction loop

A correction report never edits Trace the Law. It records evidence for a
separate reviewed change. The agent has no submit, merge, or corpus-write
capability. A local candidate is an untrusted lead; it is never copied directly
into a public issue.

> **Base V1 status:** no correction API, private intake, trusted GitHub bot, or
> authenticated receipt verifier exists. Agents may create `LOCAL_ONLY` and,
> after every evidence and human-review gate, `READY_TO_OPEN` documents. The
> validator rejects every other draft state—including `AWAITING_USER_ACTION`,
> `PRIVATE_DRAFT`, `OPENED`, `EXPIRED`, and `REVOKED`—plus
> `public_review_status`, `public_issue`, and `application`; the closed-corpus
> publication gate therefore rejects
> invalidation events and post-genesis snapshots. Do not offer a
> review URL or claim that a report, issue, merge, rebuild, or replacement
> snapshot exists. The later sections describe a gated future service.

## Agent behavior

When a possible defect could affect the answer:

1. Warn before relying on the affected evidence.
2. Independently inspect the issuing authority's official source. Do this read-only work without asking.
3. Classify an unverifiable observation as a lead, not a correction.
4. Build and privacy-scan a local candidate. Do not transmit it yet.
5. Show the user the complete sanitized payload and say that reporting is not
   enabled. The user may keep it local or independently prepare a focused pull
   request using only public official evidence.
6. After giving the safe answer, say at most once: “A sanitized, evidence-only
   correction can help future users by improving the shared record.”
7. Stop locally. Do not upload the candidate, create a link, open an issue, or
   invent an external receipt.

Use this warning shape:

> **Evidence warning:** Trace the Law may be **[missing/wrong about item]**. This **[blocks/may change/does not change]** the claim **[claim]**. I independently checked **[official source]** on **[date]** and found **[result]**. I am treating the answer as **[status]**. Nothing has been reported or changed.

Do not add urgency, guilt, rewards, or any suggestion that reporting will help
the user's own matter. Never make contribution a condition of receiving the
safe part of the answer, and do not repeat the invitation after dismissal or
silence.

## Local correction candidate

Use this shape before private intake. It is an illustrative field map, not a
schema-valid fixture: angle-bracket placeholders deliberately fail validation.
Every emitted candidate must validate against the linked schema.

```yaml
schema_id: https://schemas.trace-the-law.invalid/v1/correction-report.schema.json
schema_version: "1.0"
report_id: <stable report URN>
corpus_snapshot_id: <snapshot URN>
jurisdiction_ids: [<jurisdiction URN>]
finding_status: VERIFIED_ERROR
draft_status: LOCAL_ONLY
privacy_status: PASS
public_summary: <public source-defect summary>
finding:
  issue_type: WRONG_METADATA
  target:
    entity_type: record
    entity_id: <record URN>
  field: publication_time
impact:
  level: MAY_CHANGE_ANSWER
  affected_claim_ids: [claim-1]
targets:
  - entity_type: record
    entity_id: <record URN>
public_evidence:
  - role: SUPPORTING
    official_status: VERIFIED_OFFICIAL
    authority_id: <authority URN>
    source_id: <source URN>
    capture_id: <capture URN>
    artifact_id: <artifact SHA-256 URN>
    document_identifier: <official identifier>
    official_url: https://<official-public-source>
    published_at:
      status: exact
      value: "2026-08-23"
      precision: day
    retrieved_at: "2026-08-23T12:00:00Z"
    content_digest: {algorithm: sha256, value: <64 lowercase hex characters>}
    locator: {locator_type: section, value: <stable source locator>}
    public_excerpt: <at most 500 characters>
    excerpt_digest: {algorithm: sha256, value: <SHA-256 of the exact excerpt>}
    content_verification:
      method: human_visual_match
      verified_at: "2026-08-23T12:00:00Z"
      verifier:
        producer_id: urn:trace-the-law:producer:<stable-verifier-id>
        producer_type: human
        name: <display name>
      verified_evidence_digest:
        algorithm: sha256
        value: <digest binding artifact, capture, locator, excerpt, method, time, and verifier>
verification:
  status: VERIFIED_ERROR
  method: DIRECT_OFFICIAL_FETCH
  checked_at: "2026-08-23T12:00:00Z"
  independent_fetch: true
proposed_change:
  action: UPDATE_METADATA
  entity_refs:
    - entity_type: record
      entity_id: <record URN>
  proposed_temporal_point:
    status: exact
    value: "2026-08-23"
    precision: day
privacy_attestation:
  contains_user_query: false
  contains_user_facts: false
  contains_auth_material: false
  contains_local_file_content: false
  sender_identity_forwarded: false
  submission_mode: user_reviewed_private_intake
  timing_protection: batched
agent:
  software_name: <agent client>
  software_version: <client or skill version>
  generated_at: "2026-08-23T12:00:00Z"
created_at: "2026-08-23T12:00:00Z"
```

The concrete fields inside `finding` depend on its type; use the matching
definition in
[`correction-report.schema.json`](../schemas/correction-report.schema.json).
Allowed `issue_type` values are `MISSING_DOCUMENT`, `WRONG_METADATA`,
`BAD_CONVERSION`, `WRONG_VERSION_CHAIN`, `MISSING_RELATION`, `WRONG_RELATION`,
`BROKEN_SOURCE`, `COVERAGE_GAP`, and `RIGHTS_CONCERN`.

Allowed impact levels are `BLOCKS_ANSWER`, `MAY_CHANGE_ANSWER`, `CITATION_DEGRADED`, and `COSMETIC`.

Keep `public_summary` factual and at most 240 characters; keep a
`public_excerpt` at most 500 characters. Use only the schema's typed proposed
changes rather than executable patches. `public_review_status`, `public_issue`,
and duplicate linkage are added by intake or review; a local agent must not
invent them.

A disclosed `public_excerpt` is evidence content, not decoration. It requires
the excerpt's SHA-256, the exact artifact and capture, a stable locator,
publication clearance, and a separate `content_verification` digest binding
that complete projection. Hashing the excerpt alone does not prove it occurs in
the cited official bytes. The verification must follow acquisition and cannot
postdate the report state that contains it.

`VERIFIED_ERROR` is permitted only when `verification.independent_fetch` is
`true` and `public_evidence` contains supporting, independently fetched
official evidence that reproduces the discrepancy. A second corpus lookup,
secondary-source claim, or agent-authored legal interpretation is insufficient.
`verification.checked_at` must be at or after every supporting or contrary
evidence retrieval; an observation acquired later cannot prove an earlier
verification decision.
Use `UNVERIFIED_LEAD` and `verification.status: UNVERIFIED` when the official
evidence cannot be fetched.

The local candidate's `public_summary`, evidence, and attestation are inputs to
private review, not a publishable payload. `publication_clearance`,
`privacy_review`, `public_review_status`, `public_issue`, and `application` are
project-side lifecycle fields. A client agent must not invent or pre-approve
them.

## Privacy boundary

Never include user facts, the user's question, conversation text, names,
addresses, account identifiers, transaction amounts, confidential dates, local
paths, credentials, cookies, authentication headers, signed URLs, or private
attachments. Apply this prohibition recursively to every key and value,
including summaries, identifiers, locators, excerpts, proposed changes, agent
metadata, nested objects, and arrays. Do not copy, paraphrase, summarize, hash,
encode, or otherwise transform user facts into report text.

Every free-text value must describe only the corpus defect and public official
evidence; it must not be derived from the conversation. Reject signed,
time-limited, session-bearing, identity-bearing, and tracking URLs rather than
retaining their raw form. Normalize URLs recursively, remove credentials and
parameters such as `utm_*`, `gclid`, `fbclid`, session IDs, tokens,
signatures, and expiries, and retain only document-identifying parameters
explicitly allowed by the source manifest. Never place the rejected URL in a
log, deduplication key, nested note, or excerpt.

Public judgments can themselves expose personal data. Include the minimum excerpt needed, respect sealing or redaction notices, and prefer a stable locator without an excerpt when republication would amplify sensitive information. A privacy scan is a guardrail, not proof of safety.

If sanitization would remove the evidence needed to understand the issue, do not create an intake draft. Leave a local `BLOCKED_PRIVACY` result.

## Future consent and private intake design — disabled in base V1

These requirements apply only after the launch gates, trusted intake, and
receipt verifier are implemented. They do not authorize a base V1 agent to
transmit anything.

The future host should render the local candidate with **Review correction**
and **Dismiss** actions.

- Clicking **Review correction** is consent to upload only the displayed fields as a private, expiring draft. It is not public submission.
- The review page must say **Not submitted**, allow edits, rerun privacy checks, and preview the exact public record.
- A second explicit user action submits the report to private project intake.
  It does not publish anything and requires no GitHub account.
- Before that action, require an unchecked acknowledgement that an independently
  reconstructed and reviewed report may later become a public bot-created
  issue, without the sender's identity.
- The agent must never receive repository or GitHub write credentials.

Private intake validates and deduplicates the lead. The privacy broker must then
refetch the public sources and reconstruct a new public payload; it does not
promote the submitted fields in place. A source monitor reconstructs its payload
from the monitor's own public acquisitions under the same boundary. Each public
evidence item needs separate publication clearance, and an identified human
must review the complete reconstructed payload after all evidence was retrieved.
Only then may a narrowly scoped project bot create a sanitized public GitHub
issue. The issue identifies the project bot, not the reporter. Optional contact
or credit is a separate, explicit user choice and is never copied from network
metadata. Batch or delay public issue creation so its timing cannot reveal when
a person asked a legal question. A no-account route must not call itself
anonymous if the service processes IP addresses or other identifiers.

For clients without a trusted action UI, ask one question after showing the payload: “Create a private 24-hour review link containing only the report above? **Default: no upload until you approve.**”

A private review link should use an isolated intake origin and an opaque, high-entropy token in the URL fragment, for example `https://<intake-host>/c#<token>`.

- Store no report data in the token. Encrypt the draft at rest and retain only a token hash.
- A GET returns a generic page; an explicit user action exchanges the token by POST so link-preview bots cannot consume it.
- Strip the fragment after exchange. Use a Secure, HttpOnly, SameSite session cookie.
- Expire and delete an unused draft after 24 hours; support immediate revocation.
- Set `Cache-Control: no-store`, `Referrer-Policy: no-referrer`, `X-Robots-Tag: noindex`, a strict content security policy, and no analytics or third-party assets.
- State that anyone holding the link can access the draft.
- Do not use a prefilled GitHub issue URL: query strings, browser history,
  referrers, link previews, and analytics can leak its body. Private intake may
  ask a project bot to create an issue only after reconstruction and the review
  gates below.

## Future public reconstruction gate — disabled in base V1

Before a future trusted service can request `draft_status: OPENED`, the
project-side report must use
`privacy_attestation.submission_mode: broker_sanitized` or `source_monitor`.
The broker or source monitor rebuilds the report from independently retrieved
public sources. No user-authored excerpt, summary, locator, or URL is carried
forward merely because it passed automated scanning.

Every reconstructed `public_evidence` item must contain its own
`publication_clearance` with `status: cleared`, a human or specialist review
state, `reviewed_at` at or after that evidence's `retrieved_at`, and an
identified human reviewer with a stable `producer_id`. One clearance cannot be
reused as a blanket decision for the array.

The complete public payload also requires:

```yaml
privacy_review:
  status: CLEARED_FOR_PUBLICATION
  public_payload_origin: independently_reproduced_public_sources
  reviewed_payload_digest:
    algorithm: sha256
    value: <digest of the complete canonical report excluding only this field>
  reviewed_at: <time at or after every evidence retrieval and clearance review>
  reviewer:
    producer_id: urn:trace-the-law:producer:<stable-reviewer-id>
    producer_type: human
    name: <display name>
```

This identified human privacy review is separate from each evidence item's
publication clearance. Its digest covers the exact pre-publication payload,
including reviewer identity, review time, evidence, and clearance decisions.
The projection excludes the receipt fields `draft_status`,
`public_review_status`, `public_issue`, `application`, and
`duplicate_of_report_id`, plus the digest field itself. A future trusted issue
receipt must carry the same payload digest and a publication time no earlier
than review. Any change to the pre-publication payload requires a new digest
and review. Automated scanning, the user's private-draft review, or a display
name without `producer_id` cannot satisfy it.

## Status axes

Keep these axes separate:

- Finding: `NO_ISSUE`, `UNVERIFIED_LEAD`, `VERIFIED_GAP`, `VERIFIED_ERROR`, `OFFICIAL_CONFLICT`, `ALREADY_REPORTED`
- Draft: `LOCAL_ONLY`, `AWAITING_USER_ACTION`, `PRIVATE_DRAFT`,
  `READY_TO_OPEN`, `OPENED`, `EXPIRED`, `REVOKED`
- Privacy: `PASS`, `BLOCKED_PRIVACY`
- Public review: `SUBMITTED`, `TRIAGED`, `NEEDS_EVIDENCE`, `ACCEPTED`, `REJECTED`, `DUPLICATE`, `SUPERSEDED`, `APPLIED`, `PROPAGATION_FAILED`

Only `LOCAL_ONLY` and fully gated `READY_TO_OPEN` are usable in the base V1.
All intermediate private-intake and terminal public draft states are rejected,
not merely ignored. The public-review states below are reserved until trusted
receipts are enabled.

`ACCEPTED` means maintainers accepted the report's premise. It still does not
alter the corpus. `APPLIED` requires a separately reviewed change and this
proof:

```yaml
application:
  merge_commit_url: <public URL of the merged corpus commit>
  invalidation_event_id: <stable event URN>
  snapshot_after: <content-addressed snapshot URN>
```

The invalidation event must name this correction report and the same merge
commit, its `snapshot_after` must match the application proof and resolve to the
resulting snapshot, and propagation must be `succeeded`. A label or issue close
event is not application proof. Its `occurred_at` cannot predate
`verification.checked_at`, any evidence retrieval or publication clearance, or
the complete-payload privacy review. `PROPAGATION_FAILED` records the attempted
application coordinates but requires a failed propagation event under the same
clock ordering.

`LOCAL_ONLY` means the candidate never left the client, so it cannot have a
public-review state and can never be `APPLIED`. Likewise, a report with
`finding_status: UNVERIFIED_LEAD` or `verification.status: UNVERIFIED` cannot
be `ACCEPTED` or `APPLIED`. Intake must first reconstruct and verify it from
independently fetched official evidence and record a verified finding; the
resulting separate change still requires review, merge, and successful
propagation.

## Future apply, propagation, and invalidation — disabled in base V1

An accepted report produces a separate change proposal. Preserve raw artifacts immutably: add a corrected artifact, normalized version, or versioned relationship assertion; never rewrite historical evidence in place.

On merge, traverse the dependency chain:

```text
artifact -> normalized blocks -> provision versions -> relationship assertions
         -> summaries and indexes -> saved evidence bundles
```

Immediately mark affected descendants stale, then rebuild summaries and indexes, recalculate coverage, and replay affected evidence bundles. Preserve prior results with their original corpus snapshots; do not silently rewrite historical answers. Record the report ID, change commit, invalidated objects, rebuild results, and replacement versions.

The base V1 invalidation schema accepts only a reviewed correction report as a
cause; source-monitor causes are disabled until a signed monitor-run contract
exists. A future invalidation event caused by the reviewed correction records
that report in
`cause.correction_report_ids` and records the merge in
`cause.merge_commit_url`. A source monitor may prepare a correction lead but
must not invent a correction report ID or an unsupported run receipt merely to
trigger propagation. A `LOCAL_ONLY`, `READY_TO_OPEN`, or unverified report
cannot be an invalidation cause.

Do not mark the report `APPLIED` if invalidation or rebuild fails. Use `PROPAGATION_FAILED`, keep affected outputs visibly stale, and surface the failure for repair.
