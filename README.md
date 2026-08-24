<p align="center">
  <img src="assets/brand/trace-the-law-icon.png" alt="Trace the Law logo" width="144">
</p>

<h1 align="center">Trace the Law</h1>

**Open, versioned evidence for what governs us.**

Trace the Law is an independent, unofficial, source-linked archive for public
law and public authority. It preserves exact source bytes where lawful, records
how they change, connects the authorities that affect them, and gives agents an
honest account of what the corpus covers and what it may be missing.

> Trace the Law is not an official source, does not guarantee completeness, and
> does not provide legal advice. Official publications remain authoritative.

## Status

This repository is the global core: schemas, validation, governance, and agent
contracts. The first implementation adapter will be an India GST pilot, but no
India-specific concept belongs in the global model unless it generalizes.

No production corpus is published from this repository yet.
V1 intentionally refuses positive coverage until crawler runs produce
content-addressed result manifests tied to exact source-manifest revisions.

## The evidence layers

1. **Source manifests and captures** record each official location, retrieval,
   source status, acquisition lineage, and source-specific rights assessment.
   Failed HTTP responses remain monitoring records, never legal evidence.
2. **Artifacts** are immutable byte sequences identified only by content hash.
   Identical bytes deduplicate without losing any capture event or official URL.
3. **Derivations** record reproducible, explicitly unofficial Markdown,
   extraction, translation, and summary outputs. They never replace an artifact.
4. **Assertions** connect provisions, versions, judgments, guidance, and other
   authority. Every assertion has passage-level evidence and a review state.
5. **Evidence bundles** are derived agent inputs. They include applicable time
   axes, conflicts, coverage, known gaps, and a corpus snapshot.

Git history records project activity. Legal effect is modeled explicitly; a
commit timestamp is never treated as the date on which law changed.

Read [the architecture](docs/architecture.md) for repository boundaries and
[the data model](docs/data-model.md) for the exact evidence contracts.

## Self-correction

Trace the Law does not trust crawlers, agents, or contributors as direct
writers of truth. Automated audits and agents prepare correction candidates;
once the service is enabled, a person can review the exact sanitized payload
before choosing to submit it to untrusted intake. Findings are then reproduced
against official evidence, reviewed, patched through pull requests, and
propagated to every affected timeline, graph edge, summary, index, and coverage
record.

That paragraph describes the target loop, not a live service. The base V1 can
validate a local candidate and a fully reviewed `READY_TO_OPEN` payload. It has
no trusted GitHub organization, issue bot, receipt verifier, or private intake,
so only `LOCAL_ONLY` and fully gated `READY_TO_OPEN` are accepted. It rejects
all other draft states, every public-review receipt, `application`, and every
post-genesis snapshot transition at the closed-corpus publication gate. Agents
must not offer a reporting URL or claim that anything was submitted. The
future lifecycle examples use the `.template` suffix and are deliberately
excluded from the default closed-corpus validation set.

See [the correction loop](docs/correction-loop.md) and
[the agent contract](docs/agent-contract.md).

## Repository layout

```text
assets/brand/             Logo masters and web icon exports
docs/                    Architecture and public contracts
examples/                Small examples; disabled future flows end in .template
pilots/                  Bounded implementation plans
schemas/                 JSON Schema 2020-12 contracts
skills/trace-the-law/    Agent workflow skill
src/trace_the_law/       Deterministic validators
tests/                   Contract and privacy-boundary tests
```

Country or legal-system corpora will live in separate repositories as they
grow. Subnational jurisdictions stay inside their parent corpus until scale or
independent stewardship justifies a split. Repositories are not split by legal
topic.

## Validate the contracts

Python 3.11 or newer is required.

```bash
python -m pip install -e .
python -m unittest discover -s tests -v
ttl-validate                         # one file or an open repository fragment
ttl-validate --closed-corpus         # publication gate: all references resolve
```

Fragment mode avoids false failures when a document depends on another
repository. Closed-corpus mode is the required CI and publication check over
the complete selected component set.

## Contributing

Start with [CONTRIBUTING.md](CONTRIBUTING.md). A correction report is an
untrusted local lead, not a corpus change. No reporting endpoint is live. Never
put a user's legal situation, conversation, secrets, or private files into a
report, commit, pull request, or issue.

The staged build and launch gates are in [ROADMAP.md](ROADMAP.md).

## Licence and source rights

Project-owned code, schemas, documentation, and metadata in this repository are
available under the [MIT License](LICENSE). That licence does not relicense
third-party government, court, or publisher material. Every source must carry
its own rights and attribution record; see [RIGHTS.md](RIGHTS.md).
