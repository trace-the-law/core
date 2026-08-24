from __future__ import annotations

import copy
import unittest
from pathlib import Path

from trace_the_law.validate import (
    DEFAULT_SCHEMA_DIRECTORY,
    REPOSITORY_ROOT,
    corpus_integrity_problems,
    load_document,
    load_schema_registry,
    validate_document,
)


class AdversarialRegressionTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.schemas, cls.registry = load_schema_registry(DEFAULT_SCHEMA_DIRECTORY)

    @staticmethod
    def example_documents() -> list[tuple[Path, dict]]:
        return [
            (path, copy.deepcopy(load_document(path)))
            for path in sorted((REPOSITORY_ROOT / "examples").glob("*.json"))
        ]

    def test_capture_url_must_trace_to_its_exact_manifest_entrypoint(self) -> None:
        for spoofed_url in (
            "https://example.com/not-cbic",
            "https://cbic-gst.gov.in/outside-the-declared-route",
        ):
            with self.subTest(spoofed_url=spoofed_url):
                documents = self.example_documents()
                for path, document in documents:
                    if path.name == "india-gst-source-capture.json":
                        document["retrieval"]["source_url"] = spoofed_url
                messages = [
                    problem.message for problem in corpus_integrity_problems(documents)
                ]
                self.assertTrue(
                    any("exactly match its declared source entrypoint" in message for message in messages)
                )

    def test_non_complete_capture_cannot_support_citations_or_provenance(self) -> None:
        for http_status in (204, 205, 206, 404, 500):
            with self.subTest(http_status=http_status):
                documents = self.example_documents()
                for path, document in documents:
                    if path.name == "india-gst-source-capture.json":
                        document["retrieval"]["http_status"] = http_status
                messages = [
                    problem.message for problem in corpus_integrity_problems(documents)
                ]
                self.assertTrue(
                    any("complete HTTP 200 capture" in message for message in messages)
                )
                self.assertTrue(
                    any("has no capture or derivation provenance" in message for message in messages)
                )

    def test_exact_exclusive_interval_cannot_be_empty(self) -> None:
        bundle = copy.deepcopy(
            load_document(REPOSITORY_ROOT / "examples" / "india-gst-evidence-bundle.json")
        )
        facts_period = bundle["evaluation_context"]["facts_period"]
        facts_period["end"] = copy.deepcopy(facts_period["start"])
        facts_period["end_inclusive"] = False

        problems = validate_document(
            Path("bundle.json"), bundle, self.schemas, self.registry
        )
        self.assertTrue(
            any("temporal interval is empty" in problem.message for problem in problems)
        )

    def test_invalid_timezone_offset_cannot_bypass_chronology(self) -> None:
        bundle = copy.deepcopy(
            load_document(REPOSITORY_ROOT / "examples" / "india-gst-evidence-bundle.json")
        )
        bundle["generated_at"] = "2026-08-23T14:00:00+29:00"

        problems = validate_document(
            Path("bundle.json"), bundle, self.schemas, self.registry
        )
        self.assertTrue(
            any(
                "date-time cannot be normalized to a valid UTC instant"
                in problem.message
                for problem in problems
            )
        )

    def test_unknown_public_url_query_parameter_fails_closed(self) -> None:
        report = copy.deepcopy(
            load_document(REPOSITORY_ROOT / "examples" / "india-gst-correction-report.json")
        )
        report["public_evidence"][0]["official_url"] += "?share_secret=TOPSECRET"

        problems = validate_document(
            Path("report.json"), report, self.schemas, self.registry
        )
        self.assertTrue(
            any("no source-specific allowlist is modeled" in problem.message for problem in problems)
        )

    def test_positive_coverage_fails_closed_without_enumeration_manifest(self) -> None:
        original = load_document(
            REPOSITORY_ROOT / "examples" / "india-gst-coverage-ledger.json"
        )
        for discovered_count in (0, 1_000_000_000):
            with self.subTest(discovered_count=discovered_count):
                ledger = copy.deepcopy(original)
                ledger["status"] = "covered_for_declared_scope"
                ledger["known_gaps"] = []
                ledger["enumeration_runs"][0]["discovered_count"] = discovered_count
                problems = validate_document(
                    Path("coverage.json"), ledger, self.schemas, self.registry
                )
                self.assertTrue(
                    any("positive coverage is fail-closed" in problem.message for problem in problems)
                )

    def test_malformed_rights_status_reports_errors_without_crashing(self) -> None:
        manifest = copy.deepcopy(
            load_document(
                REPOSITORY_ROOT / "examples" / "india-gst-source-manifest.json"
            )
        )
        manifest["rights"]["status"] = {}

        problems = validate_document(
            Path("manifest.json"), manifest, self.schemas, self.registry
        )
        self.assertTrue(problems)
        self.assertTrue(
            any(problem.location.endswith(".status") for problem in problems)
        )

    def test_temporal_binding_requires_reviewable_source_text(self) -> None:
        record = copy.deepcopy(
            load_document(REPOSITORY_ROOT / "examples" / "india-gst-record.json")
        )
        record["versions"][0]["publication_evidence"][0].pop("quoted_text")

        problems = validate_document(
            Path("record.json"), record, self.schemas, self.registry
        )
        self.assertTrue(
            any(
                "opaque digest alone cannot establish the source expression"
                in problem.message
                for problem in problems
            )
        )

    def test_bundle_dependency_must_exist_by_selected_snapshot(self) -> None:
        documents = self.example_documents()
        for path, document in documents:
            if path.name == "india-gst-source-capture.json":
                document["retrieval"]["retrieved_at"] = "2026-08-23T14:00:31Z"
                document["created_at"] = "2026-08-23T14:00:31Z"

        problems = corpus_integrity_problems(documents)
        self.assertTrue(
            any(
                "unavailable at the selected corpus snapshot" in problem.message
                for problem in problems
            )
        )

    def test_every_truth_dependency_state_is_bounded_by_the_snapshot(self) -> None:
        mutations = (
            (
                "india-gst-source-manifest.json",
                lambda document: document["identity_review"].update(
                    {"reviewed_at": "2026-08-23T14:31:00Z"}
                ),
                "source dependency",
                "identity_review.reviewed_at",
            ),
            (
                "india-cbic-authority.json",
                lambda document: document.update(
                    {"updated_at": "2026-08-23T14:31:00Z"}
                ),
                "authority dependency",
                "updated_at",
            ),
            (
                "india-jurisdiction.json",
                lambda document: document["names"][0]["field_bindings"][0].update(
                    {"created_at": "2026-08-23T14:31:00Z"}
                ),
                "jurisdiction dependency",
                "field_bindings[0].created_at",
            ),
            (
                "india-gst-record.json",
                lambda document: document["metadata_bindings"][0].update(
                    {"created_at": "2026-08-23T14:31:00Z"}
                ),
                "record dependency",
                "metadata_bindings[0].created_at",
            ),
            (
                "india-gst-coverage-ledger.json",
                lambda document: document.update(
                    {"generated_at": "2026-08-23T14:31:00Z"}
                ),
                "coverage dependency",
                "generated_at",
            ),
        )
        for filename, mutate, dependency_label, field_location in mutations:
            with self.subTest(filename=filename):
                documents = self.example_documents()
                document = next(
                    item for path, item in documents if path.name == filename
                )
                mutate(document)
                messages = [
                    problem.message
                    for problem in corpus_integrity_problems(documents)
                ]
                self.assertTrue(
                    any(
                        dependency_label in message
                        and field_location in message
                        and "unavailable at the selected corpus snapshot" in message
                        for message in messages
                    )
                )

    def test_release_clearance_may_follow_snapshot_but_precede_bundle_release(
        self,
    ) -> None:
        documents = self.example_documents()
        capture = next(
            document
            for path, document in documents
            if path.name == "india-gst-source-capture.json"
        )
        capture["publication_clearance"]["reviewed_at"] = (
            "2026-08-23T14:00:45Z"
        )

        messages = [
            problem.message for problem in corpus_integrity_problems(documents)
        ]
        self.assertFalse(
            any(
                "capture dependency" in message
                and "publication_clearance" in message
                and "unavailable at the selected corpus snapshot" in message
                for message in messages
            )
        )

    def test_candidate_profile_names_and_adjacency_cannot_support_a_claim(
        self,
    ) -> None:
        documents = self.example_documents()
        bundle = next(
            document
            for path, document in documents
            if path.name == "india-gst-evidence-bundle.json"
        )
        claim = bundle["claims"][0]
        claim["subjects"] = [
            {
                "entity_type": "authority",
                "entity_id": (
                    "urn:trace-the-law:authority:uuid:"
                    "22222222-2222-4222-8222-222222222222"
                ),
            }
        ]
        claim["bibliographic_facts"] = [
            {
                "subject_index": 0,
                "field": "name",
                "value": "Central Board of Indirect Taxes and Customs",
            }
        ]
        claim["claim_text"] = "name=Central Board of Indirect Taxes and Customs"

        messages = [
            problem.message for problem in corpus_integrity_problems(documents)
        ]
        self.assertTrue(
            any("selected authority name was not independently verified" in message for message in messages)
        )
        self.assertTrue(
            any("authority scope cannot establish claim jurisdiction" in message for message in messages)
        )

    def test_approximate_claim_applicability_is_not_treated_as_exact(self) -> None:
        documents = self.example_documents()
        bundle = next(
            document
            for path, document in documents
            if path.name == "india-gst-evidence-bundle.json"
        )
        bundle["claims"][0]["applicability"] = {
            "status": "open_ended",
            "start": {
                "status": "approximate",
                "value": "2017",
                "precision": "year",
                "calendar": "gregory",
            },
        }

        problems = corpus_integrity_problems(documents)
        self.assertTrue(
            any(
                "claim applicability has an approximate boundary" in problem.message
                for problem in problems
            )
        )

    def test_complete_scope_attestation_cannot_override_missing_content_warnings(
        self,
    ) -> None:
        artifact = copy.deepcopy(
            load_document(
                REPOSITORY_ROOT
                / "examples"
                / "india-gst-heading-markdown-artifact.json"
            )
        )
        artifact["legal_scope_attestations"] = [{}]

        problems = validate_document(
            Path("artifact.json"), artifact, self.schemas, self.registry
        )
        self.assertTrue(
            any(
                "conflicts with unresolved missing-content warnings"
                in problem.message
                for problem in problems
            )
        )

    def test_assertion_history_edges_are_transitive_dependencies(self) -> None:
        documents = self.example_documents()
        linked_assertion_id = (
            "urn:trace-the-law:assertion:uuid:"
            "88888888-8888-4888-8888-888888888888"
        )
        for path, document in documents:
            if path.name == "india-cbic-serves-india-relationship-assertion.json":
                document["supersedes_assertion_ids"] = [linked_assertion_id]

        problems = corpus_integrity_problems(documents)
        self.assertTrue(
            any(
                "explicitly depend on assertion" in problem.message
                and linked_assertion_id in problem.message
                for problem in problems
            )
        )

    def test_reviewed_incoming_assertion_history_cannot_be_omitted(self) -> None:
        documents = self.example_documents()
        older = next(
            document
            for path, document in documents
            if path.name == "india-gst-relationship-assertion.json"
        )
        older_id = older["assertion_id"]
        newer = copy.deepcopy(older)
        newer_id = (
            "urn:trace-the-law:assertion:uuid:"
            "18181818-1818-4181-8181-181818181818"
        )
        newer["assertion_id"] = newer_id
        newer["status"] = "verified"
        newer["created_at"] = "2026-08-23T13:00:00Z"
        newer["reviewed_at"] = "2026-08-23T13:01:00Z"
        newer["reviewer"] = {
            "producer_id": "urn:trace-the-law:producer:human:history-reviewer",
            "producer_type": "human",
            "name": "History reviewer",
        }
        newer["time_axes"]["observation"]["value"] = "2026-08-23T13:00:00Z"
        newer["supersedes_assertion_ids"] = [older_id]
        documents.append((Path("incoming-history.json"), newer))

        bundle = next(
            document
            for path, document in documents
            if path.name == "india-gst-evidence-bundle.json"
        )
        claim = bundle["claims"][0]
        claim["subjects"] = [
            {"entity_type": "assertion", "entity_id": older_id}
        ]
        claim["bibliographic_facts"] = [
            {"subject_index": 0, "field": "predicate", "value": "applies"}
        ]
        claim["claim_text"] = "predicate=applies"
        bundle["dependencies"].append(
            {"entity_type": "assertion", "entity_id": older_id}
        )

        messages = [
            problem.message for problem in corpus_integrity_problems(documents)
        ]
        self.assertTrue(
            any(
                "explicitly depend on assertion" in message
                and newer_id in message
                for message in messages
            )
        )
        self.assertTrue(
            any(
                "reviewed incoming assertion supersession" in message
                and "not explicitly modeled" in message
                for message in messages
            )
        )

    def test_material_provision_claim_also_checks_containing_version_clocks(
        self,
    ) -> None:
        documents = self.example_documents()
        bundle = next(
            document
            for path, document in documents
            if path.name == "india-gst-evidence-bundle.json"
        )
        claim = bundle["claims"][0]
        claim["content_use"] = "source_excerpt"
        claim["claim_text"] = "The cited provision governs the selected period."
        claim.pop("bibliographic_facts")
        claim["applicability"] = copy.deepcopy(
            bundle["evaluation_context"]["facts_period"]
        )
        bundle["status"] = "SUPPORTED"

        problems = corpus_integrity_problems(documents)
        self.assertTrue(
            any(
                "containing_version.time_axes" in problem.location
                and "legal effectiveness is unknown" in problem.message
                for problem in problems
            )
        )

    def test_bibliographic_assertion_subject_obeys_review_and_cutoff(self) -> None:
        documents = self.example_documents()
        assertion_id = (
            "urn:trace-the-law:assertion:uuid:"
            "88888888-8888-4888-8888-888888888888"
        )
        bundle = next(
            document
            for path, document in documents
            if path.name == "india-gst-evidence-bundle.json"
        )
        claim = bundle["claims"][0]
        claim["subjects"] = [
            {"entity_type": "assertion", "entity_id": assertion_id}
        ]
        claim["bibliographic_facts"] = [
            {"subject_index": 0, "field": "predicate", "value": "applies"}
        ]
        claim["claim_text"] = "predicate=applies"
        bundle["evaluation_context"]["authority_cutoff"] = {
            "status": "exact",
            "value": "2016-12-31",
            "precision": "day",
            "calendar": "gregory",
        }

        problems = corpus_integrity_problems(documents)
        messages = [problem.message for problem in problems]
        self.assertTrue(
            any("bibliographic assertion subject was not independently reviewed" in message for message in messages)
        )
        self.assertTrue(
            any("may postdate authority_cutoff" in message for message in messages)
        )

    def test_transition_cannot_depend_on_a_future_observed_predecessor(self) -> None:
        documents = self.example_documents()
        record = next(
            document
            for path, document in documents
            if path.name == "india-gst-record.json"
        )
        current_version = record["versions"][0]
        current_provision = current_version["provisions"][0]
        predecessor = copy.deepcopy(current_version)
        predecessor["version_id"] = (
            "urn:trace-the-law:version:uuid:"
            "56565656-5656-4565-8565-565656565656"
        )
        predecessor_provision = predecessor["provisions"][0]
        predecessor_provision["provision_version_id"] = (
            "urn:trace-the-law:provision-version:uuid:"
            "78787878-7878-4787-8787-787878787878"
        )
        predecessor["time_axes"]["observation"]["value"] = (
            "2030-01-01T00:00:00Z"
        )
        predecessor_provision["time_axes"]["observation"]["value"] = (
            "2030-01-01T00:00:00Z"
        )
        predecessor.pop("supersedes_version_ids", None)
        predecessor_provision.pop("predecessor_provision_version_ids", None)
        record["versions"].append(predecessor)
        current_version["supersedes_version_ids"] = [predecessor["version_id"]]
        current_provision["predecessor_provision_version_ids"] = [
            predecessor_provision["provision_version_id"]
        ]

        messages = [
            problem.message for problem in corpus_integrity_problems(documents)
        ]
        self.assertTrue(
            any("record version cannot supersede a predecessor first observed later" in message for message in messages)
        )
        self.assertTrue(
            any("provision version cannot name a predecessor first observed later" in message for message in messages)
        )

    def test_nested_derived_evidence_requires_an_exact_derivation_dependency(
        self,
    ) -> None:
        documents = self.example_documents()
        derived_artifact_id = (
            "urn:trace-the-law:artifact:sha256:"
            "8d1751dbede747541a1d946a2348a7070c050793374aae4cdbbe01c561fe59bb"
        )
        derivation_id = (
            "urn:trace-the-law:derivation:uuid:"
            "17171717-1717-4171-8171-171717171717"
        )
        bundle = next(
            document
            for path, document in documents
            if path.name == "india-gst-evidence-bundle.json"
        )
        assertion = next(
            document
            for path, document in documents
            if path.name == "india-cbic-serves-india-relationship-assertion.json"
        )
        assertion["evidence"][0]["artifact_id"] = derived_artifact_id
        assertion["evidence"][0].pop("capture_id")
        bundle["dependencies"].append(
            {"entity_type": "artifact", "entity_id": derived_artifact_id}
        )

        problems = corpus_integrity_problems(documents)
        self.assertTrue(
            any(
                "explicitly depend on derivation" in problem.message
                and derivation_id in problem.message
                for problem in problems
            )
        )

    def test_stable_provision_cannot_supply_versioned_bibliographic_text(
        self,
    ) -> None:
        documents = self.example_documents()
        bundle = next(
            document
            for path, document in documents
            if path.name == "india-gst-evidence-bundle.json"
        )
        bundle["claims"][0]["subjects"][0] = {
            "entity_type": "provision",
            "entity_id": (
                "urn:trace-the-law:provision:uuid:"
                "66666666-6666-4666-8666-666666666666"
            ),
        }

        problems = corpus_integrity_problems(documents)
        self.assertTrue(
            any(
                "not exact whitelisted metadata on its selected subject"
                in problem.message
                for problem in problems
            )
        )

    def test_bibliographic_provision_version_checks_containing_version_time(
        self,
    ) -> None:
        documents = self.example_documents()
        record = next(
            document
            for path, document in documents
            if path.name == "india-gst-record.json"
        )
        version = record["versions"][0]
        version["time_axes"]["publication"] = {"status": "unknown"}
        version.pop("publication_evidence")
        bundle = next(
            document
            for path, document in documents
            if path.name == "india-gst-evidence-bundle.json"
        )
        bundle["status"] = "SUPPORTED"

        problems = corpus_integrity_problems(documents)
        self.assertTrue(
            any(
                "containing_version.time_axes.publication" in problem.location
                and "authority publication is unknown" in problem.message
                for problem in problems
            )
        )

    def test_artifact_dependency_selects_its_provenance_route(self) -> None:
        documents = self.example_documents()
        derived_artifact_id = (
            "urn:trace-the-law:artifact:sha256:"
            "8d1751dbede747541a1d946a2348a7070c050793374aae4cdbbe01c561fe59bb"
        )
        derivation_id = (
            "urn:trace-the-law:derivation:uuid:"
            "17171717-1717-4171-8171-171717171717"
        )
        record = next(
            document
            for path, document in documents
            if path.name == "india-gst-record.json"
        )
        record["versions"][0]["artifact_ids"].append(derived_artifact_id)
        bundle = next(
            document
            for path, document in documents
            if path.name == "india-gst-evidence-bundle.json"
        )
        bundle["dependencies"].append(
            {"entity_type": "artifact", "entity_id": derived_artifact_id}
        )

        problems = corpus_integrity_problems(documents)
        self.assertTrue(
            any(
                "explicitly depend on derivation" in problem.message
                and derivation_id in problem.message
                for problem in problems
            )
        )


if __name__ == "__main__":
    unittest.main()
