from __future__ import annotations

import copy
import hashlib
import unittest
from pathlib import Path

from trace_the_law.validate import (
    REPOSITORY_ROOT,
    _canonical_json_bytes,
    _bundle_context_problems,
    corpus_integrity_problems,
    load_document,
)


APPLIES_ASSERTION_ID = (
    "urn:trace-the-law:assertion:uuid:88888888-8888-4888-8888-888888888888"
)
SERVES_ASSERTION_ID = (
    "urn:trace-the-law:assertion:uuid:13131313-1313-4131-8131-131313131313"
)


class BundleContextAndConflictTests(unittest.TestCase):
    def example_documents(self) -> list[tuple[Path, dict]]:
        example_directory = REPOSITORY_ROOT / "examples"
        physical_paths = sorted(
            [*example_directory.glob("*.json"), *example_directory.glob("*.json.template")]
        )
        return [
            (
                Path(path.name.removesuffix(".template")),
                copy.deepcopy(load_document(path)),
            )
            for path in physical_paths
        ]

    @staticmethod
    def by_name(documents: list[tuple[Path, dict]]) -> dict[str, dict]:
        return {path.name: document for path, document in documents}

    @staticmethod
    def legal_interval(start: str, end: str) -> dict:
        return {
            "status": "known",
            "start": {
                "status": "exact",
                "value": start,
                "precision": "day",
                "calendar": "gregory",
            },
            "end": {
                "status": "exact",
                "value": end,
                "precision": "day",
                "calendar": "gregory",
            },
            "end_inclusive": True,
        }

    @staticmethod
    def make_reviewed(assertion: dict) -> None:
        assertion["status"] = "verified"
        assertion["producer"]["producer_id"] = (
            "urn:trace-the-law:producer:importer:bundle-semantics-fixture"
        )
        assertion["reviewed_at"] = "2026-08-23T13:00:00Z"
        assertion["reviewer"] = {
            "producer_id": (
                "urn:trace-the-law:producer:human:bundle-semantics-reviewer"
            ),
            "producer_type": "human",
            "name": "Bundle semantics reviewer",
        }
        projection = copy.deepcopy(assertion)
        projection.pop("reviewed_assertion_digest", None)
        assertion["reviewed_assertion_digest"] = {
            "algorithm": "sha256",
            "value": hashlib.sha256(_canonical_json_bytes(projection)).hexdigest(),
        }

    def make_material_supported_bundle(self, documents: list[tuple[Path, dict]]) -> dict:
        by_name = self.by_name(documents)
        bundle = by_name["india-gst-evidence-bundle.json"]
        claim = bundle["claims"][0]
        bundle["status"] = "SUPPORTED"
        bundle["coverage"][0]["status"] = "covered_for_declared_scope"
        bundle["coverage"][0]["gap_ids"] = []
        bundle["unresolved_items"] = []
        bundle["verification_tasks"] = []
        claim["content_use"] = "source_excerpt"
        claim["claim_text"] = "The provision applies during the stated period."
        claim.pop("bibliographic_facts", None)
        claim["applicability"] = self.legal_interval(
            "2017-01-01", "2017-12-31"
        )
        bundle["citations"][0]["quoted_text"] = "Section 1"
        return bundle

    def test_authority_published_after_cutoff_cannot_support_a_bundle(self) -> None:
        documents = self.example_documents()
        by_name = self.by_name(documents)
        bundle = self.make_material_supported_bundle(documents)
        assertion = by_name["india-gst-relationship-assertion.json"]
        self.make_reviewed(assertion)
        assertion["time_axes"]["effectiveness"] = self.legal_interval(
            "2017-01-01", "2017-12-31"
        )
        assertion["time_axes"]["applicability"] = self.legal_interval(
            "2017-01-01", "2017-12-31"
        )
        bundle["evaluation_context"]["authority_cutoff"] = {
            "status": "exact",
            "value": "2016-12-31",
            "precision": "day",
            "calendar": "gregory",
        }
        bundle["claims"][0]["assertion_ids"] = [APPLIES_ASSERTION_ID]
        bundle["dependencies"].append(
            {"entity_type": "assertion", "entity_id": APPLIES_ASSERTION_ID}
        )

        messages = [problem.message for problem in corpus_integrity_problems(documents)]
        self.assertTrue(
            any("may postdate authority_cutoff" in message for message in messages)
        )
        self.assertTrue(
            any("blocking unresolved item" in message for message in messages)
        )
        self.assertTrue(any("requires INSUFFICIENT_COVERAGE" in m for m in messages))

    def test_claim_outside_facts_period_cannot_claim_supported(self) -> None:
        documents = self.example_documents()
        bundle = self.make_material_supported_bundle(documents)
        bundle["claims"][0]["applicability"] = self.legal_interval(
            "2018-01-01", "2018-12-31"
        )

        messages = [problem.message for problem in corpus_integrity_problems(documents)]
        self.assertTrue(
            any(
                "claim applicability does not cover evaluation_context.facts_period"
                in message
                for message in messages
            )
        )
        self.assertTrue(
            any("blocking unresolved item" in message for message in messages)
        )
        self.assertTrue(any("requires INSUFFICIENT_COVERAGE" in m for m in messages))

    def test_context_mismatch_is_valid_only_when_fail_closed_and_blocked(self) -> None:
        documents = self.example_documents()
        by_name = self.by_name(documents)
        bundle = self.make_material_supported_bundle(documents)
        claim = bundle["claims"][0]
        claim["applicability"] = self.legal_interval(
            "2018-01-01", "2018-12-31"
        )
        version = by_name["india-gst-record.json"]["versions"][0]
        provision = version["provisions"][0]
        provision["time_axes"] = {
            "publication": {
                "status": "exact",
                "value": "2017-04-12",
                "precision": "day",
                "calendar": "gregory",
            },
            "effectiveness": self.legal_interval("2017-01-01", "2017-12-31"),
            "applicability": self.legal_interval("2017-01-01", "2017-12-31"),
            "observation": copy.deepcopy(provision["time_axes"]["observation"]),
        }
        assertion = by_name["india-gst-relationship-assertion.json"]
        self.make_reviewed(assertion)
        assertion["scope"]["extent"] = "whole_entity"
        assertion["scope"].pop("target_provision_ids", None)
        assertion["time_axes"]["effectiveness"] = self.legal_interval(
            "2017-01-01", "2017-12-31"
        )
        assertion["time_axes"]["applicability"] = self.legal_interval(
            "2017-01-01", "2017-12-31"
        )
        provision["time_axes"]["effectiveness"]["basis_assertion_ids"] = [
            APPLIES_ASSERTION_ID
        ]
        provision["time_axes"]["applicability"]["basis_assertion_ids"] = [
            APPLIES_ASSERTION_ID
        ]
        version["time_axes"] = {
            "publication": copy.deepcopy(provision["time_axes"]["publication"]),
            "effectiveness": copy.deepcopy(provision["time_axes"]["effectiveness"]),
            "applicability": copy.deepcopy(provision["time_axes"]["applicability"]),
            "observation": copy.deepcopy(version["time_axes"]["observation"]),
        }
        bundle["status"] = "INSUFFICIENT_COVERAGE"
        bundle["unresolved_items"] = [
            {
                "kind": "missing_dependency",
                "severity": "blocking",
                "related_entities": [
                    {"entity_type": "claim", "entity_id": claim["claim_id"]}
                ],
            }
        ]

        messages = [problem.message for problem in corpus_integrity_problems(documents)]
        context_messages = [
            message
            for message in messages
            if "context-ineligible" in message
            or "claim applicability does not cover" in message
            or "blocking unresolved item" in message
        ]
        self.assertEqual([], context_messages)

    def test_provision_intrinsic_clocks_must_cover_the_evaluation_context(self) -> None:
        documents = self.example_documents()
        by_name = self.by_name(documents)
        self.make_material_supported_bundle(documents)
        provision = by_name["india-gst-record.json"]["versions"][0]["provisions"][0]
        provision["time_axes"] = {
            "publication": {
                "status": "exact",
                "value": "2017-04-12",
                "precision": "day",
                "calendar": "gregory",
            },
            "effectiveness": self.legal_interval("2018-01-01", "2018-12-31"),
            "applicability": self.legal_interval("2018-01-01", "2018-12-31"),
            "observation": copy.deepcopy(provision["time_axes"]["observation"]),
        }

        messages = [problem.message for problem in corpus_integrity_problems(documents)]
        self.assertTrue(
            any(
                "legal effectiveness does not cover evaluation_context.effective_at"
                in message
                for message in messages
            )
        )
        self.assertTrue(
            any(
                "legal applicability does not cover evaluation_context.facts_period"
                in message
                for message in messages
            )
        )
        self.assertTrue(any("requires INSUFFICIENT_COVERAGE" in m for m in messages))

    def test_unused_bare_jurisdiction_subject_cannot_fake_scope_coverage(self) -> None:
        documents = self.example_documents()
        bundle = self.make_material_supported_bundle(documents)
        second_jurisdiction_id = (
            "urn:trace-the-law:jurisdiction:uuid:"
            "20202020-2020-4020-8020-202020202020"
        )
        bundle["evaluation_context"]["jurisdiction_ids"].append(
            second_jurisdiction_id
        )
        bundle["claims"][0]["jurisdiction_ids"].append(second_jurisdiction_id)
        bundle["claims"][0]["subjects"].append(
            {
                "entity_type": "jurisdiction",
                "entity_id": second_jurisdiction_id,
            }
        )
        bundle["dependencies"].append(
            {
                "entity_type": "jurisdiction",
                "entity_id": second_jurisdiction_id,
            }
        )

        messages = [problem.message for problem in corpus_integrity_problems(documents)]
        self.assertTrue(
            any(
                "eligible claim evidence does not collectively cover the claim jurisdictions"
                in message
                for message in messages
            )
        )
        self.assertTrue(any("requires INSUFFICIENT_COVERAGE" in m for m in messages))

    def test_partial_assertion_scope_cannot_fake_multi_jurisdiction_coverage(self) -> None:
        documents = self.example_documents()
        by_name = self.by_name(documents)
        bundle = self.make_material_supported_bundle(documents)
        assertion = by_name["india-gst-relationship-assertion.json"]
        self.make_reviewed(assertion)
        assertion["time_axes"]["effectiveness"] = self.legal_interval(
            "2017-01-01", "2017-12-31"
        )
        assertion["time_axes"]["applicability"] = self.legal_interval(
            "2017-01-01", "2017-12-31"
        )
        second_jurisdiction_id = (
            "urn:trace-the-law:jurisdiction:uuid:"
            "20202020-2020-4020-8020-202020202020"
        )
        bundle["evaluation_context"]["jurisdiction_ids"].append(
            second_jurisdiction_id
        )
        bundle["claims"][0]["jurisdiction_ids"].append(second_jurisdiction_id)
        bundle["claims"][0]["assertion_ids"] = [APPLIES_ASSERTION_ID]
        bundle["dependencies"].extend(
            [
                {
                    "entity_type": "jurisdiction",
                    "entity_id": second_jurisdiction_id,
                },
                {
                    "entity_type": "assertion",
                    "entity_id": APPLIES_ASSERTION_ID,
                },
            ]
        )

        messages = [problem.message for problem in corpus_integrity_problems(documents)]
        self.assertTrue(
            any(
                "eligible claim evidence does not collectively cover the claim jurisdictions"
                in message
                for message in messages
            )
        )
        self.assertTrue(any("requires INSUFFICIENT_COVERAGE" in m for m in messages))

    def test_multiple_eligible_versions_can_collectively_cover_comparative_claim(self) -> None:
        first_jurisdiction = (
            "urn:trace-the-law:jurisdiction:uuid:"
            "11111111-1111-4111-8111-111111111111"
        )
        second_jurisdiction = (
            "urn:trace-the-law:jurisdiction:uuid:"
            "20202020-2020-4020-8020-202020202020"
        )
        first_record = "urn:trace-the-law:record:uuid:41414141-4141-4141-8141-414141414141"
        second_record = "urn:trace-the-law:record:uuid:42424242-4242-4242-8242-424242424242"
        first_version = "urn:trace-the-law:version:uuid:43434343-4343-4343-8343-434343434343"
        second_version = "urn:trace-the-law:version:uuid:44444444-4444-4444-8444-444444444440"
        time_axes = {
            "publication": {
                "status": "exact",
                "value": "2016-01-01",
                "precision": "day",
                "calendar": "gregory",
            },
            "effectiveness": self.legal_interval("2017-01-01", "2017-12-31"),
            "applicability": self.legal_interval("2017-01-01", "2017-12-31"),
            "observation": {
                "status": "exact",
                "value": "2026-08-23T12:00:00Z",
                "precision": "second",
                "calendar": "gregory",
            },
        }
        claim_id = "urn:trace-the-law:claim:uuid:45454545-4545-4545-8545-454545454545"
        bundle = {
            "status": "SUPPORTED",
            "evaluation_context": {
                "jurisdiction_ids": [first_jurisdiction, second_jurisdiction],
                "facts_period": self.legal_interval("2017-01-01", "2017-12-31"),
                "effective_at": {
                    "status": "exact",
                    "value": "2017-06-01",
                    "precision": "day",
                    "calendar": "gregory",
                },
                "authority_cutoff": {
                    "status": "exact",
                    "value": "2026-08-23",
                    "precision": "day",
                    "calendar": "gregory",
                },
                "corpus_snapshot": {
                    "snapshot_id": "urn:trace-the-law:snapshot:sha256:" + "1" * 64,
                    "recorded_at": "2026-08-23T12:20:06Z",
                },
            },
            "claims": [
                {
                    "claim_id": claim_id,
                    "content_use": "source_excerpt",
                    "applicability": self.legal_interval(
                        "2017-01-01", "2017-12-31"
                    ),
                    "jurisdiction_ids": [first_jurisdiction, second_jurisdiction],
                    "subjects": [
                        {"entity_type": "version", "entity_id": first_version},
                        {"entity_type": "version", "entity_id": second_version},
                    ],
                    "assertion_ids": [],
                    "contrary_assertion_ids": [],
                }
            ],
            "unresolved_items": [],
        }
        records = {
            first_record: (Path("first-record.json"), {"jurisdiction_ids": [first_jurisdiction]}),
            second_record: (Path("second-record.json"), {"jurisdiction_ids": [second_jurisdiction]}),
        }
        first_basis_id = (
            "urn:trace-the-law:assertion:uuid:"
            "46464646-4646-4646-8646-464646464646"
        )
        second_basis_id = (
            "urn:trace-the-law:assertion:uuid:"
            "47474747-4747-4747-8747-474747474747"
        )
        versions = {}
        assertions = {}
        for record_id, version_id, jurisdiction_id, basis_id, filename in (
            (
                first_record,
                first_version,
                first_jurisdiction,
                first_basis_id,
                "first-record.json",
            ),
            (
                second_record,
                second_version,
                second_jurisdiction,
                second_basis_id,
                "second-record.json",
            ),
        ):
            version_time_axes = copy.deepcopy(time_axes)
            version_time_axes["effectiveness"]["basis_assertion_ids"] = [basis_id]
            version_time_axes["applicability"]["basis_assertion_ids"] = [basis_id]
            versions[version_id] = (
                Path(filename),
                record_id,
                {"time_axes": version_time_axes},
            )
            assertion = {
                "status": "verified",
                "reviewed_at": "2026-08-23T12:00:00Z",
                "scope": {
                    "extent": "whole_entity",
                    "jurisdiction_ids": [jurisdiction_id],
                },
                "time_axes": copy.deepcopy(time_axes),
            }
            assertions[basis_id] = (Path(f"{basis_id[-4:]}.json"), assertion)

        problems = _bundle_context_problems(
            Path("bundle.json"), bundle, assertions, {}, {}, records, versions, {}, {}
        )
        self.assertEqual([], problems)

    def test_future_observation_cannot_appear_in_older_snapshot(self) -> None:
        documents = self.example_documents()
        by_name = self.by_name(documents)
        bundle = self.make_material_supported_bundle(documents)
        provision = by_name["india-gst-record.json"]["versions"][0]["provisions"][0]
        provision["time_axes"] = {
            "publication": {
                "status": "exact",
                "value": "2017-04-12",
                "precision": "day",
                "calendar": "gregory",
            },
            "effectiveness": self.legal_interval("2017-01-01", "2017-12-31"),
            "applicability": self.legal_interval("2017-01-01", "2017-12-31"),
            "observation": {
                "status": "exact",
                "value": "2030-01-01T00:00:00Z",
                "precision": "second",
                "calendar": "gregory",
            },
        }

        messages = [problem.message for problem in corpus_integrity_problems(documents)]
        self.assertTrue(
            any(
                "observation is unknown or later than the selected corpus snapshot"
                in message
                for message in messages
            )
        )
        self.assertTrue(any("requires INSUFFICIENT_COVERAGE" in m for m in messages))

    def test_fractional_review_after_snapshot_is_not_in_the_same_second_bucket(
        self,
    ) -> None:
        documents = self.example_documents()
        by_name = self.by_name(documents)
        bundle = self.make_material_supported_bundle(documents)
        provision = by_name["india-gst-record.json"]["versions"][0]["provisions"][0]
        assertion = by_name["india-gst-relationship-assertion.json"]
        self.make_reviewed(assertion)
        assertion["reviewed_at"] = "2026-08-23T14:00:30.900Z"
        assertion["time_axes"]["effectiveness"] = self.legal_interval(
            "2017-01-01", "2017-12-31"
        )
        assertion["time_axes"]["applicability"] = self.legal_interval(
            "2017-01-01", "2017-12-31"
        )
        provision["time_axes"] = {
            "publication": copy.deepcopy(assertion["time_axes"]["publication"]),
            "effectiveness": self.legal_interval("2017-01-01", "2017-12-31"),
            "applicability": self.legal_interval("2017-01-01", "2017-12-31"),
            "observation": {
                "status": "exact",
                "value": "2026-08-23T14:00:30Z",
                "precision": "second",
                "calendar": "gregory",
            },
        }
        for axis_name in ("effectiveness", "applicability"):
            provision["time_axes"][axis_name]["basis_assertion_ids"] = [
                APPLIES_ASSERTION_ID
            ]
        bundle["dependencies"].append(
            {"entity_type": "assertion", "entity_id": APPLIES_ASSERTION_ID}
        )

        messages = [problem.message for problem in corpus_integrity_problems(documents)]
        self.assertTrue(
            any(
                "was not reviewed by the selected snapshot" in message
                for message in messages
            )
        )

    def test_bibliographic_version_observation_cannot_postdate_snapshot(self) -> None:
        documents = self.example_documents()
        by_name = self.by_name(documents)
        provision = by_name["india-gst-record.json"]["versions"][0]["provisions"][0]
        provision["time_axes"]["observation"] = {
            "status": "exact",
            "value": "2030-01-01T00:00:00Z",
            "precision": "second",
            "calendar": "gregory",
        }

        messages = [problem.message for problem in corpus_integrity_problems(documents)]
        self.assertTrue(
            any(
                "observation is unknown or later than the selected corpus snapshot"
                in message
                for message in messages
            )
        )

    def test_applies_and_serves_jurisdiction_are_not_a_semantic_conflict(self) -> None:
        documents = self.example_documents()
        by_name = self.by_name(documents)
        bundle = by_name["india-gst-evidence-bundle.json"]
        claim = bundle["claims"][0]
        claim["subjects"].extend(
            [
                {
                    "entity_type": "authority",
                    "entity_id": (
                        "urn:trace-the-law:authority:uuid:"
                        "22222222-2222-4222-8222-222222222222"
                    ),
                },
                {
                    "entity_type": "jurisdiction",
                    "entity_id": bundle["evaluation_context"]["jurisdiction_ids"][0],
                },
            ]
        )
        claim["assertion_ids"] = [APPLIES_ASSERTION_ID]
        claim["contrary_assertion_ids"] = [SERVES_ASSERTION_ID]
        bundle["conflicts"] = [
            {
                "assertion_ids": [APPLIES_ASSERTION_ID, SERVES_ASSERTION_ID],
                "resolution_state": "unresolved",
            }
        ]

        messages = [problem.message for problem in corpus_integrity_problems(documents)]
        self.assertTrue(
            any(
                "lack a reviewed disputes_assertion_ids link or semantic incompatibility"
                in message
                for message in messages
            )
        )

    def test_reviewed_dispute_link_can_establish_a_conflict_explicitly(self) -> None:
        documents = self.example_documents()
        by_name = self.by_name(documents)
        bundle = by_name["india-gst-evidence-bundle.json"]
        applies = by_name["india-gst-relationship-assertion.json"]
        self.make_reviewed(applies)
        applies["disputes_assertion_ids"] = [SERVES_ASSERTION_ID]
        claim = bundle["claims"][0]
        claim["subjects"].append(
            {
                "entity_type": "authority",
                "entity_id": (
                    "urn:trace-the-law:authority:uuid:"
                    "22222222-2222-4222-8222-222222222222"
                ),
            }
        )
        claim["assertion_ids"] = [APPLIES_ASSERTION_ID]
        claim["contrary_assertion_ids"] = [SERVES_ASSERTION_ID]
        bundle["conflicts"] = [
            {
                "assertion_ids": [APPLIES_ASSERTION_ID, SERVES_ASSERTION_ID],
                "resolution_state": "unresolved",
            }
        ]

        messages = [problem.message for problem in corpus_integrity_problems(documents)]
        self.assertFalse(
            any(
                "lack a reviewed disputes_assertion_ids link or semantic incompatibility"
                in message
                for message in messages
            )
        )


if __name__ == "__main__":
    unittest.main()
