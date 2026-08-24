from __future__ import annotations

import copy
import hashlib
import json
import posixpath
import re
import tempfile
import tomllib
import unittest
import uuid
from pathlib import Path

from trace_the_law.validate import (
    DEFAULT_SCHEMA_DIRECTORY,
    REPOSITORY_ROOT,
    _canonical_json_bytes,
    _capture_acquisition_problems,
    _check_schema_references,
    _content_verification_projection,
    _dependency_availability_violations,
    _parse_datetime,
    artifact_identity_problems,
    collection_identity_problems,
    corpus_integrity_problems,
    corpus_publication_problems,
    correction_state_problems,
    coverage_ledger_problems,
    evidence_bundle_handling_problems,
    evidence_bundle_privacy_problems,
    evidence_bundle_reference_problems,
    evidence_bundle_status_problems,
    invalidation_problems,
    load_document,
    load_schema_registry,
    profile_review_problems,
    privacy_problems,
    public_url_problems,
    relationship_review_problems,
    rights_assessment_problems,
    snapshot_problems,
    storage_location_problems,
    temporal_problems,
    validate_document,
    validate_paths,
)


class ContractValidationTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.schemas, cls.registry = load_schema_registry(DEFAULT_SCHEMA_DIRECTORY)

    def mutated_example_problems(self, filename: str, mutation) -> list:
        document = copy.deepcopy(load_document(self.example_file(filename)))
        mutation(document)
        return validate_document(
            Path(filename),
            document,
            self.schemas,
            self.registry,
        )

    def example_documents(
        self, *, include_lifecycle_templates: bool = True
    ) -> list[tuple[Path, dict]]:
        example_directory = REPOSITORY_ROOT / "examples"
        physical_paths = sorted(
            [*example_directory.glob("*.json"), *example_directory.glob("*.json.template")]
        )
        documents = [
            (
                Path(path.name.removesuffix(".template")),
                copy.deepcopy(load_document(path)),
            )
            for path in physical_paths
        ]
        if include_lifecycle_templates:
            return documents
        lifecycle_names = {
            "india-gst-invalidation-event.json",
            "india-gst-snapshot-after.json",
        }
        return [item for item in documents if item[0].name not in lifecycle_names]

    @staticmethod
    def example_file(filename: str) -> Path:
        path = REPOSITORY_ROOT / "examples" / filename
        return path if path.exists() else path.with_name(path.name + ".template")

    @staticmethod
    def refresh_binding_review_digest(binding: dict) -> None:
        review = binding["normalization_review"]
        projected_binding = copy.deepcopy(binding)
        projected_binding["normalization_review"].pop(
            "reviewed_binding_digest", None
        )
        review["reviewed_binding_digest"]["value"] = hashlib.sha256(
            _canonical_json_bytes(projected_binding)
        ).hexdigest()

    @staticmethod
    def refresh_evidence_content_verification(citation: dict) -> None:
        quoted_text = citation.get("quoted_text")
        if isinstance(quoted_text, str):
            citation["quoted_text_digest"] = {
                "algorithm": "sha256",
                "value": hashlib.sha256(quoted_text.encode("utf-8")).hexdigest(),
            }
        verification = citation["content_verification"]
        verification["verified_evidence_digest"]["value"] = hashlib.sha256(
            _canonical_json_bytes(_content_verification_projection(citation))
        ).hexdigest()

    def official_translation_documents(self) -> list[tuple[Path, dict]]:
        documents = self.example_documents(include_lifecycle_templates=False)
        by_name = {path.name: document for path, document in documents}
        record = by_name["india-gst-record.json"]
        version = record["versions"][0]
        version["version_kind"] = "official_translation"
        version_kind_binding = next(
            binding
            for binding in version["metadata_bindings"]
            if binding["field"] == "version_kind"
        )
        version_kind_binding["normalized_value"] = "official_translation"
        self.refresh_binding_review_digest(version_kind_binding)

        authority_id = (
            "urn:trace-the-law:authority:uuid:"
            "22222222-2222-4222-8222-222222222222"
        )
        assertion_id = (
            "urn:trace-the-law:assertion:uuid:"
            "24242424-2424-4242-8242-242424242424"
        )
        version["authority_relationships"] = [
            {
                "authority_id": authority_id,
                "role": "issuing",
                "assertion_id": assertion_id,
            }
        ]

        assertion = copy.deepcopy(by_name["india-gst-relationship-assertion.json"])
        assertion["assertion_id"] = assertion_id
        assertion["subject"] = {
            "entity_type": "version",
            "entity_id": version["version_id"],
        }
        assertion["predicate"] = "issued_by"
        assertion["object"] = {
            "entity_type": "authority",
            "entity_id": authority_id,
        }
        assertion["interpretation_level"] = "explicit_source_text"
        assertion["scope"] = {
            "extent": "whole_entity",
            "jurisdiction_ids": copy.deepcopy(record["jurisdiction_ids"]),
        }
        assertion["time_axes"]["publication"] = {"status": "unknown"}
        assertion["time_axes"]["applicability"] = {"status": "not_applicable"}
        assertion["time_axes"]["observation"] = {
            "status": "exact",
            "value": "2026-08-23T14:00:00Z",
            "precision": "second",
            "calendar": "gregory",
        }
        assertion["status"] = "verified"
        assertion["confidence"] = "high"
        assertion["evidence"] = copy.deepcopy(version["metadata_evidence"])
        assertion["producer"] = {
            "producer_id": (
                "urn:trace-the-law:producer:importer:"
                "official-version-designation"
            ),
            "producer_type": "importer",
            "name": "Example official-version designation importer",
            "version": "0.1.0",
        }
        assertion["created_at"] = "2026-08-23T12:20:06Z"
        assertion["reviewed_at"] = "2026-08-23T14:00:00Z"
        assertion["reviewer"] = {
            "producer_id": (
                "urn:trace-the-law:producer:human:"
                "official-version-designation-reviewer"
            ),
            "producer_type": "human",
            "name": "Example official-version designation reviewer",
        }
        assertion.pop("supersedes_assertion_ids", None)
        assertion.pop("disputes_assertion_ids", None)
        assertion_projection = copy.deepcopy(assertion)
        assertion_projection.pop("reviewed_assertion_digest", None)
        assertion["reviewed_assertion_digest"] = {
            "algorithm": "sha256",
            "value": hashlib.sha256(
                _canonical_json_bytes(assertion_projection)
            ).hexdigest(),
        }
        by_name["india-gst-evidence-bundle.json"]["dependencies"].append(
            {"entity_type": "assertion", "entity_id": assertion_id}
        )
        documents.append((Path("official-translation-assertion.json"), assertion))
        return documents

    def nested_public_bundle_documents(
        self, *, declare_inner_derivation: bool
    ) -> list[tuple[Path, dict]]:
        documents = self.example_documents()
        by_name = {path.name: document for path, document in documents}
        capture = by_name["india-gst-source-capture.json"]
        bundle = by_name["india-gst-evidence-bundle.json"]
        artifact_template = by_name["india-gst-heading-markdown-artifact.json"]
        derivation_template = by_name["india-gst-heading-derivation.json"]
        self.make_rights_publishable(capture)
        capture["publication_clearance"] = self.cleared_publication()

        chain: list[tuple[Path, dict]] = []
        previous_artifact_id = capture["artifact_id"]
        derivation_ids: list[str] = []
        artifact_ids: list[str] = []
        for index, label in enumerate(("inner", "outer"), start=1):
            digest = hashlib.sha256(f"bundle-{label}-artifact".encode()).hexdigest()
            artifact_id = "urn:trace-the-law:artifact:sha256:" + digest
            derivation_id = (
                "urn:trace-the-law:derivation:uuid:"
                + ("21212121-2121-4121-8121-212121212121" if index == 1 else "23232323-2323-4232-8232-232323232323")
            )
            artifact = copy.deepcopy(artifact_template)
            artifact["artifact_id"] = artifact_id
            artifact["content_digest"]["value"] = digest
            artifact["created_at"] = (
                "2026-08-23T13:00:00Z" if index == 1 else "2026-08-23T13:30:00Z"
            )
            artifact["storage_locations"][0]["uri"] = (
                "urn:trace-the-law:test-object:sha256:" + digest
            )
            derivation = copy.deepcopy(derivation_template)
            derivation["derivation_id"] = derivation_id
            derivation["output_artifact_id"] = artifact_id
            derivation["input_artifacts"][0]["artifact_id"] = previous_artifact_id
            derivation["created_at"] = artifact["created_at"]
            if index == 2:
                derivation["publication_clearance"] = self.cleared_publication(
                    entity_type="artifact",
                    entity_id=artifact_id,
                    content_digest={"algorithm": "sha256", "value": digest},
                    source_url=None,
                )
            chain.extend(
                [
                    (Path(f"{label}-artifact.json"), artifact),
                    (Path(f"{label}-derivation.json"), derivation),
                ]
            )
            artifact_ids.append(artifact_id)
            derivation_ids.append(derivation_id)
            previous_artifact_id = artifact_id

        bundle["citations"][0]["artifact_id"] = artifact_ids[-1]
        bundle["citations"][0].pop("capture_id", None)
        bundle["citations"][0]["quoted_text"] = "Section 1"
        claim = bundle["claims"][0]
        claim["content_use"] = "source_excerpt"
        claim["claim_text"] = "Section 1"
        claim.pop("bibliographic_facts", None)
        for entity_type, entity_id in (
            ("artifact", artifact_ids[0]),
            ("artifact", artifact_ids[1]),
            ("derivation", derivation_ids[1]),
        ):
            bundle["dependencies"].append(
                {"entity_type": entity_type, "entity_id": entity_id}
            )
        if declare_inner_derivation:
            bundle["dependencies"].append(
                {"entity_type": "derivation", "entity_id": derivation_ids[0]}
            )
        documents.extend(chain)
        return documents

    @staticmethod
    def refresh_publication_clearance_digest(clearance: dict) -> None:
        projection = copy.deepcopy(clearance)
        projection.pop("reviewed_clearance_digest", None)
        clearance["reviewed_clearance_digest"] = {
            "algorithm": "sha256",
            "value": hashlib.sha256(_canonical_json_bytes(projection)).hexdigest(),
        }

    @staticmethod
    def cleared_publication(
        *,
        entity_type: str = "capture",
        entity_id: str = (
            "urn:trace-the-law:capture:uuid:"
            "12121212-1212-4121-8121-121212121212"
        ),
        content_digest: dict | None = None,
        source_url: str | None = "https://cbic-gst.gov.in/hindi/CGST-bill-e.html",
        reviewed_at: str = "2026-08-23T14:00:00Z",
    ) -> dict:
        if content_digest is None and entity_type == "capture":
            content_digest = {
                "algorithm": "sha256",
                "value": "6df796ca8d690225e62d7049df9006703d23be9641486d9f4587f565744cbaed",
            }
        target: dict = {
            "entity": {"entity_type": entity_type, "entity_id": entity_id}
        }
        if content_digest is not None:
            target["content_digest"] = copy.deepcopy(content_digest)
        if source_url is not None:
            target["source_url"] = source_url
        clearance = {
            "status": "cleared",
            "checks": {
                "personal_data": "not_present",
                "sealing_or_reporting_restrictions": "not_present",
                "official_redactions_preserved": "not_applicable",
                "sensitive_material": "not_present",
            },
            "review_state": "human_reviewed",
            "reviewed_at": reviewed_at,
            "reviewer": {
                "producer_id": "urn:trace-the-law:producer:human:publication-reviewer",
                "producer_type": "human",
                "name": "Example publication reviewer",
            },
            "reviewed_target": target,
        }
        ContractValidationTests.refresh_publication_clearance_digest(clearance)
        return clearance

    @staticmethod
    def cleared_derivation_publication(derivation: dict) -> dict:
        artifact_id = derivation["output_artifact_id"]
        return ContractValidationTests.cleared_publication(
            entity_type="artifact",
            entity_id=artifact_id,
            content_digest={
                "algorithm": "sha256",
                "value": artifact_id.rsplit(":", 1)[-1],
            },
            source_url=None,
        )

    @staticmethod
    def refresh_rights_review_digest(capture: dict) -> None:
        rights = capture["rights"]
        projection = copy.deepcopy(rights)
        projection.pop("reviewed_assessment_digest", None)
        rights["reviewed_assessment_digest"] = {
            "algorithm": "sha256",
            "value": hashlib.sha256(_canonical_json_bytes(projection)).hexdigest(),
        }

    @staticmethod
    def bind_rights_review(capture: dict) -> None:
        retrieval = capture["retrieval"]
        capture["rights"]["reviewed_target"] = {
            "entity": {
                "entity_type": "capture",
                "entity_id": capture["capture_id"],
            },
            "content_digest": {
                "algorithm": "sha256",
                "value": capture["artifact_id"].rsplit(":", 1)[-1],
            },
            "source_url": retrieval["source_url"],
        }
        ContractValidationTests.refresh_rights_review_digest(capture)

    @staticmethod
    def make_rights_publishable(capture: dict) -> None:
        capture["rights"].update(
            {
                "status": "public-domain",
                "legal_basis": "Example jurisdiction public-domain rule",
                "terms_url": "https://example.gov/public-domain-terms",
                "review_state": "human_reviewed",
                "reviewed_at": "2026-08-23T14:00:00Z",
                "reviewer": {
                    "producer_id": "urn:trace-the-law:producer:human:rights-reviewer",
                    "producer_type": "human",
                    "name": "Example rights reviewer",
                },
            }
        )
        for use in capture["rights"]["permitted_uses"]:
            capture["rights"]["permitted_uses"][use] = "permitted"
        ContractValidationTests.bind_rights_review(capture)

    @staticmethod
    def make_verified_report(report: dict) -> None:
        report["finding_status"] = "VERIFIED_ERROR"
        report["verification"]["status"] = "VERIFIED_ERROR"
        report["verification"]["independent_fetch"] = True
        evidence = report["public_evidence"][0]
        evidence.update(
            {
                "role": "SUPPORTING",
                "official_status": "VERIFIED_OFFICIAL",
                "source_id": (
                    "urn:trace-the-law:source:uuid:"
                    "33333333-3333-4333-8333-333333333333"
                ),
                "capture_id": (
                    "urn:trace-the-law:capture:uuid:"
                    "12121212-1212-4121-8121-121212121212"
                ),
                "artifact_id": (
                    "urn:trace-the-law:artifact:sha256:"
                    "6df796ca8d690225e62d7049df9006703d23be9641486d9f4587f565744cbaed"
                ),
            }
        )
        evidence["publication_clearance"] = (
            ContractValidationTests.cleared_publication(
                entity_type="report",
                entity_id=report["report_id"],
                content_digest=evidence["content_digest"],
                source_url=evidence["official_url"],
            )
        )

    @staticmethod
    def clear_report_public_evidence(report: dict) -> None:
        evidence = report["public_evidence"][0]
        evidence["publication_clearance"] = (
            ContractValidationTests.cleared_publication(
                entity_type="report",
                entity_id=report["report_id"],
                content_digest=evidence["content_digest"],
                source_url=evidence["official_url"],
            )
        )

    @staticmethod
    def open_report_for_public_review(report: dict) -> None:
        report["draft_status"] = "READY_TO_OPEN"
        report["privacy_attestation"]["submission_mode"] = "broker_sanitized"
        report["privacy_attestation"]["timing_protection"] = "batched"
        report["privacy_review"] = {
            "status": "CLEARED_FOR_PUBLICATION",
            "public_payload_origin": "independently_reproduced_public_sources",
            "reviewed_at": "2026-08-23T14:00:00Z",
            "reviewer": {
                "producer_id": "urn:trace-the-law:producer:human:privacy-reviewer",
                "producer_type": "human",
                "name": "Example correction privacy reviewer",
            },
        }

    @staticmethod
    def bind_correction_privacy_review(report: dict) -> None:
        projection = copy.deepcopy(report)
        for field in (
            "draft_status",
            "public_review_status",
            "public_issue",
            "application",
            "duplicate_of_report_id",
        ):
            projection.pop(field, None)
        projection["privacy_review"].pop("reviewed_payload_digest", None)
        report["privacy_review"]["reviewed_payload_digest"] = {
            "algorithm": "sha256",
            "value": hashlib.sha256(_canonical_json_bytes(projection)).hexdigest(),
        }

    @staticmethod
    def add_spoofed_public_issue(
        report: dict, review_status: str = "SUBMITTED"
    ) -> None:
        report["draft_status"] = "OPENED"
        report["public_review_status"] = review_status
        reviewed_digest = copy.deepcopy(
            report["privacy_review"]["reviewed_payload_digest"]
        )
        report["public_issue"] = {
            "url": "https://github.com/trace-the-law/core/issues/1",
            "created_by_project_bot": True,
            "published_at": "2026-08-23T14:01:00Z",
            "published_payload_digest": reviewed_digest,
        }

    def test_repository_contains_schema_contracts(self) -> None:
        expected_names = {
            "artifact",
            "authority",
            "capture",
            "common",
            "correction-report",
            "coverage-ledger",
            "derivation",
            "evidence-bundle",
            "invalidation-event",
            "jurisdiction",
            "record",
            "relationship-assertion",
            "snapshot",
            "source-manifest",
        }
        expected_ids = {
            f"https://schemas.trace-the-law.invalid/v1/{name}.schema.json"
            for name in expected_names
        }
        self.assertEqual(expected_ids, set(self.schemas))

    def test_wheel_declares_runtime_contract_data(self) -> None:
        with (REPOSITORY_ROOT / "pyproject.toml").open("rb") as handle:
            project = tomllib.load(handle)
        self.assertEqual(["setuptools>=77"], project["build-system"]["requires"])
        self.assertEqual("MIT", project["project"]["license"])
        self.assertEqual(["LICENSE"], project["project"]["license-files"])
        data_files = project["tool"]["setuptools"]["data-files"]
        self.assertEqual(["schemas/*.schema.json"], data_files["share/trace-the-law/schemas"])
        self.assertEqual(
            ["examples/*.json", "examples/*.json.template"],
            data_files["share/trace-the-law/examples"],
        )
        self.assertEqual(
            [
                "docs/agent-contract.md",
                "docs/architecture.md",
                "docs/correction-loop.md",
                "docs/data-model.md",
                "docs/organization-setup.md",
            ],
            data_files["share/trace-the-law/docs"],
        )
        self.assertEqual(
            [
                "CHARTER.md",
                "CONTRIBUTING.md",
                "GOVERNANCE.md",
                "LICENSE",
                "PRIVACY.md",
                "README.md",
                "RIGHTS.md",
                "ROADMAP.md",
                "SECURITY.md",
                "THIRD_PARTY_NOTICES.md",
            ],
            data_files["share/trace-the-law"],
        )
        self.assertEqual(
            ["skills/trace-the-law/SKILL.md"],
            data_files["share/trace-the-law/skills/trace-the-law"],
        )

        installed_skill = "share/trace-the-law/skills/trace-the-law/SKILL.md"
        installed_files = {
            "share/trace-the-law/docs/agent-contract.md",
            "share/trace-the-law/docs/architecture.md",
            "share/trace-the-law/docs/correction-loop.md",
            "share/trace-the-law/docs/data-model.md",
            "share/trace-the-law/RIGHTS.md",
            "share/trace-the-law/THIRD_PARTY_NOTICES.md",
            installed_skill,
        }
        skill_text = (REPOSITORY_ROOT / "skills" / "trace-the-law" / "SKILL.md").read_text(
            encoding="utf-8"
        )
        routed_docs = re.findall(r"\]\((\.\./\.\./docs/[^)]+)\)", skill_text)
        self.assertEqual(
            {"../../docs/agent-contract.md", "../../docs/correction-loop.md"},
            set(routed_docs),
        )
        for target in routed_docs:
            resolved = posixpath.normpath(
                posixpath.join(posixpath.dirname(installed_skill), target)
            )
            self.assertIn(resolved, installed_files)

    def test_dangling_schema_reference_is_rejected(self) -> None:
        schemas = {
            "https://schemas.example.invalid/example.schema.json": {
                "$id": "https://schemas.example.invalid/example.schema.json",
                "$ref": "missing.schema.json#/$defs/value",
            }
        }
        with self.assertRaisesRegex(ValueError, "not in the local registry"):
            _check_schema_references(schemas)

    def test_all_examples_validate(self) -> None:
        examples = REPOSITORY_ROOT / "examples"
        self.assertTrue(examples.is_dir())
        problems = validate_paths((examples,), closed_corpus=True)
        self.assertEqual([], [problem.render() for problem in problems])

    def test_yaml_dates_remain_strings(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "date.yaml"
            path.write_text("published_at: 2026-08-23\n", encoding="utf-8")
            document = load_document(path)
        self.assertEqual("2026-08-23", document["published_at"])

    def test_duplicate_json_and_yaml_keys_are_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            json_path = Path(directory) / "duplicate.json"
            yaml_path = Path(directory) / "duplicate.yaml"
            json_path.write_text('{"status":"first","status":"second"}', encoding="utf-8")
            yaml_path.write_text("status: first\nstatus: second\n", encoding="utf-8")
            with self.assertRaisesRegex(ValueError, "duplicate object key"):
                load_document(json_path)
            with self.assertRaisesRegex(Exception, "duplicate key"):
                load_document(yaml_path)

    def test_recursive_yaml_alias_is_reported_as_a_parse_problem(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            yaml_path = Path(directory) / "recursive.yaml"
            yaml_path.write_text(
                "schema_id: example\nloop: &recursive [*recursive]\n",
                encoding="utf-8",
            )
            problems = validate_paths((yaml_path,))

        self.assertEqual(1, len(problems))
        self.assertIn("cannot parse", problems[0].message)
        self.assertIn("YAML aliases are not supported", problems[0].message)

    def test_yaml_alias_expansion_is_rejected_before_construction(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            yaml_path = Path(directory) / "alias-expansion.yaml"
            yaml_path.write_text(
                "a: &a [x, x, x, x, x, x, x, x, x]\n"
                "b: &b [*a, *a, *a, *a, *a, *a, *a, *a, *a]\n"
                "z: *b\n",
                encoding="utf-8",
            )
            problems = validate_paths((yaml_path,))

        self.assertEqual(1, len(problems))
        self.assertIn("YAML aliases are not supported", problems[0].message)

    def test_deep_in_memory_and_json_documents_fail_cleanly(self) -> None:
        nested: object = []
        for _ in range(1_500):
            nested = [nested]
        document = {
            "schema_id": "https://schemas.trace-the-law.invalid/v1/authority.schema.json",
            "x": nested,
        }
        problems = validate_document(
            Path("deep.json"), document, self.schemas, self.registry
        )
        self.assertTrue(
            any("document nesting exceeds" in problem.message for problem in problems)
        )

        with tempfile.TemporaryDirectory() as directory:
            json_path = Path(directory) / "deep.json"
            json_path.write_text(
                '{"schema_id":"https://schemas.trace-the-law.invalid/v1/authority.schema.json","x":'
                + "[" * 1_500
                + "0"
                + "]" * 1_500
                + "}",
                encoding="utf-8",
            )
            path_problems = validate_paths((json_path,))
        self.assertTrue(path_problems)
        self.assertIn("cannot parse", path_problems[0].message)

    def test_privacy_guard_rejects_user_context(self) -> None:
        report = {
            "schema_id": "https://schemas.trace-the-law.invalid/v1/correction-report.schema.json",
            "user_question": "How much tax do I owe?",
        }
        problems = privacy_problems(Path("report.json"), report)
        self.assertTrue(any("forbidden" in problem.message for problem in problems))

    def test_privacy_guard_rejects_credentials_in_urls(self) -> None:
        report = {
            "schema_id": "https://schemas.trace-the-law.invalid/v1/correction-report.schema.json",
            "evidence": [{"official_url": "https://user:secret@example.gov/document"}],
        }
        problems = privacy_problems(Path("report.json"), report)
        self.assertTrue(any("credentials" in problem.message for problem in problems))

    def test_privacy_guard_rejects_signed_and_tracking_urls(self) -> None:
        report = {
            "schema_id": "https://schemas.trace-the-law.invalid/v1/correction-report.schema.json",
            "evidence": [
                {
                    "official_url": (
                        "https://example.gov/document?utm_source=chat&X-Amz-Signature=secret"
                    )
                }
            ],
        }
        problems = privacy_problems(Path("report.json"), report)
        self.assertTrue(any("parameters" in problem.message for problem in problems))

    def test_privacy_guard_rejects_embedded_signed_url_and_user_amount(self) -> None:
        report = {
            "schema_id": "https://schemas.trace-the-law.invalid/v1/correction-report.schema.json",
            "public_summary": (
                "User transaction INR 1,234,567; source "
                "https://example.gov/c?X-Amz-Signature=secret"
            ),
        }
        problems = privacy_problems(Path("report.json"), report)
        messages = [problem.message for problem in problems]
        self.assertTrue(any("currency amounts" in message for message in messages))
        self.assertTrue(any("embedded" in message for message in messages))
        self.assertTrue(any("parameters" in message for message in messages))

    def test_privacy_guard_rejects_word_currency_and_personal_case_fact(self) -> None:
        report = {
            "schema_id": "https://schemas.trace-the-law.invalid/v1/correction-report.schema.json",
            "public_summary": (
                "The user Sudhanshu paid a transaction amount of "
                "1,234,567 rupees."
            ),
        }
        messages = [
            problem.message for problem in privacy_problems(Path("report.json"), report)
        ]
        self.assertTrue(any("currency amounts" in message for message in messages))
        self.assertTrue(any("personal case facts" in message for message in messages))

    def test_privacy_guard_rejects_cloudfront_style_authentication_keys(self) -> None:
        report = {
            "schema_id": "https://schemas.trace-the-law.invalid/v1/correction-report.schema.json",
            "public_evidence": [
                {
                    "official_url": (
                        "https://example.gov/document?Expires=1&"
                        "Key-Pair-Id=example&HMAC=secret"
                    )
                }
            ],
        }
        messages = [
            problem.message for problem in privacy_problems(Path("report.json"), report)
        ]
        for key in ("expires", "hmac", "key-pair-id"):
            self.assertTrue(any(key in message for message in messages), key)

    def test_privacy_guard_handles_malformed_embedded_url(self) -> None:
        report = {
            "schema_id": "https://schemas.trace-the-law.invalid/v1/correction-report.schema.json",
            "public_summary": "Bad source http://[::1",
        }
        problems = privacy_problems(Path("report.json"), report)
        self.assertTrue(any("malformed" in problem.message for problem in problems))

    def test_signed_url_is_rejected_outside_correction_reports(self) -> None:
        capture = copy.deepcopy(
            load_document(REPOSITORY_ROOT / "examples" / "india-gst-source-capture.json")
        )
        capture["retrieval"]["source_url"] = (
            "https://example.gov/document?X-Amz-Signature=secret"
        )
        problems = public_url_problems(Path("capture.json"), capture)
        self.assertTrue(any("authentication" in problem.message for problem in problems))

    def test_authentication_fragment_is_rejected(self) -> None:
        capture = copy.deepcopy(
            load_document(REPOSITORY_ROOT / "examples" / "india-gst-source-capture.json")
        )
        capture["retrieval"]["source_url"] = "https://example.gov/document#access_token=secret"
        problems = public_url_problems(Path("capture.json"), capture)
        self.assertTrue(any("authentication" in problem.message for problem in problems))

    def test_public_urls_reject_impossible_network_ports(self) -> None:
        capture = copy.deepcopy(
            load_document(REPOSITORY_ROOT / "examples" / "india-gst-source-capture.json")
        )
        for port in ("0", "65536", "99999"):
            with self.subTest(port=port):
                capture["retrieval"]["source_url"] = (
                    f"https://cbic-gst.gov.in:{port}/hindi/CGST-bill-e.html"
                )
                messages = [
                    problem.message
                    for problem in public_url_problems(Path("capture.json"), capture)
                ]
                self.assertTrue(
                    any("invalid network port" in message for message in messages)
                )

        report = {
            "schema_id": "https://schemas.trace-the-law.invalid/v1/correction-report.schema.json",
            "public_evidence": [
                {"official_url": "https://example.gov:0/document"}
            ],
        }
        self.assertTrue(
            any(
                "invalid network port" in problem.message
                for problem in privacy_problems(Path("report.json"), report)
            )
        )

    def test_public_urls_reject_legacy_private_ipv4_and_backslash_authorities(self) -> None:
        capture = copy.deepcopy(
            load_document(REPOSITORY_ROOT / "examples" / "india-gst-source-capture.json")
        )
        unsafe_urls = (
            "https://127.1/document",
            "https://127.0.1/document",
            "https://0177.0.0.1/document",
            "https://0x7f.0.0.1/document",
            "https://169.254.1/document",
            "https://0300.0250.0001.0001/document",
            "https://example.gov\\evil/document",
            "https://example.gov%5c@127.0.0.1/document",
            "https://example.gov:/document",
        )
        for source_url in unsafe_urls:
            with self.subTest(source_url=source_url):
                capture["retrieval"]["source_url"] = source_url
                self.assertTrue(
                    public_url_problems(Path("capture.json"), capture),
                    source_url,
                )

    def test_privacy_guard_rejects_non_public_urls(self) -> None:
        report = {
            "schema_id": "https://schemas.trace-the-law.invalid/v1/correction-report.schema.json",
            "public_evidence": [
                {"official_url": "http://127.0.0.1/private"},
                {"official_url": "http://metadata.internal/credentials"},
            ],
        }
        problems = privacy_problems(Path("report.json"), report)
        self.assertEqual(
            2,
            sum("public host" in problem.message for problem in problems),
        )

    def test_privacy_declarations_must_all_be_false(self) -> None:
        safe_report = {
            "schema_id": "https://schemas.trace-the-law.invalid/v1/correction-report.schema.json",
            "privacy": {"case_facts": False, "conversation_text": False},
        }
        unsafe_report = {
            "schema_id": "https://schemas.trace-the-law.invalid/v1/correction-report.schema.json",
            "privacy": {"case_facts": True},
        }
        self.assertEqual([], privacy_problems(Path("safe.json"), safe_report))
        self.assertTrue(privacy_problems(Path("unsafe.json"), unsafe_report))

    def test_json_and_yaml_nonfinite_numbers_are_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            json_path = Path(directory) / "nonfinite.json"
            yaml_path = Path(directory) / "nonfinite.yaml"
            json_path.write_text('{"ocr_confidence": NaN}', encoding="utf-8")
            yaml_path.write_text("ocr_confidence: .nan\n", encoding="utf-8")

            with self.assertRaisesRegex(ValueError, "non-JSON numeric constant"):
                load_document(json_path)
            with self.assertRaisesRegex(ValueError, "non-finite number"):
                load_document(yaml_path)

    def test_programmatic_validation_rejects_nonfinite_numbers(self) -> None:
        artifact = copy.deepcopy(
            load_document(
                REPOSITORY_ROOT / "examples" / "india-gst-heading-markdown-artifact.json"
            )
        )
        artifact["quality"]["ocr_confidence"] = float("nan")
        problems = validate_document(
            Path("artifact.json"), artifact, self.schemas, self.registry
        )
        self.assertTrue(any("non-finite" in problem.message for problem in problems))

    def test_artifact_id_must_match_content_digest(self) -> None:
        document = {
            "schema_id": "https://schemas.trace-the-law.invalid/v1/artifact.schema.json",
            "artifact_id": "urn:trace-the-law:artifact:sha256:" + "a" * 64,
            "content_digest": {"algorithm": "sha256", "value": "b" * 64},
        }
        problems = artifact_identity_problems(Path("artifact.json"), document)
        self.assertTrue(any("must equal" in problem.message for problem in problems))

    def test_duplicate_nested_ids_are_rejected(self) -> None:
        document = {
            "schema_id": "https://schemas.trace-the-law.invalid/v1/source-manifest.schema.json",
            "entrypoints": [
                {"entrypoint_id": "gazette", "url": "https://one.example.gov"},
                {"entrypoint_id": "gazette", "url": "https://two.example.gov"},
            ],
        }
        problems = collection_identity_problems(Path("source.yaml"), document)
        self.assertTrue(any("duplicates" in problem.message for problem in problems))

    def test_evidence_bundle_citation_indexes_must_resolve(self) -> None:
        document = {
            "schema_id": "https://schemas.trace-the-law.invalid/v1/evidence-bundle.schema.json",
            "citations": [{}],
            "claims": [{"citation_indexes": [0, 1]}],
        }
        problems = evidence_bundle_reference_problems(Path("bundle.yaml"), document)
        self.assertEqual(1, len(problems))

    def test_public_mirror_requires_a_publication_basis(self) -> None:
        def mutate(document) -> None:
            document["availability"] = "public_mirror"
            document["storage_locations"] = [
                {
                    "role": "primary",
                    "uri": "https://mirror.example.org/artifact",
                    "access": "public",
                }
            ]

        problems = self.mutated_example_problems(
            "india-gst-source-artifact.json", mutate
        )
        self.assertTrue(any("publication_basis" in problem.message for problem in problems))

    def test_public_storage_cannot_be_a_local_file(self) -> None:
        artifact = copy.deepcopy(
            load_document(
                REPOSITORY_ROOT / "examples" / "india-gst-heading-markdown-artifact.json"
            )
        )
        artifact["storage_locations"][0] = {
            "role": "primary",
            "uri": "file:///tmp/private-copy.md",
            "access": "public",
        }
        problems = storage_location_problems(Path("artifact.json"), artifact)
        self.assertTrue(any("local file" in problem.message for problem in problems))
        self.assertTrue(any("public storage" in problem.message for problem in problems))

    def test_publication_basis_can_clear_rights_but_v1_mirrors_stay_disabled(self) -> None:
        artifact_path = Path("artifact.json")
        capture_path = Path("capture.json")
        source_path = Path("source.json")
        artifact = copy.deepcopy(
            load_document(REPOSITORY_ROOT / "examples" / "india-gst-source-artifact.json")
        )
        capture = copy.deepcopy(
            load_document(REPOSITORY_ROOT / "examples" / "india-gst-source-capture.json")
        )
        source = copy.deepcopy(
            load_document(REPOSITORY_ROOT / "examples" / "india-gst-source-manifest.json")
        )
        publication_documents = [
            (artifact_path, artifact),
            (capture_path, capture),
            (source_path, source),
        ]
        artifact["availability"] = "public_mirror"
        artifact["storage_locations"] = [
            {
                "role": "primary",
                "uri": "https://mirror.example.org/artifact",
                "access": "public",
            }
        ]
        artifact["publication_basis"] = [
            {"basis_type": "capture", "basis_id": capture["capture_id"]}
        ]
        capture["rights"]["status"] = "restricted"
        capture["rights"]["review_state"] = "human_reviewed"
        capture["rights"]["reviewed_at"] = "2026-08-23T14:00:00Z"
        capture["rights"]["reviewer"] = {
            "producer_id": "urn:trace-the-law:producer:human:rights-reviewer",
            "producer_type": "human",
            "name": "Example rights reviewer",
        }
        capture["rights"]["permitted_uses"]["public_mirroring"] = "permitted"
        capture["rights"]["permitted_uses"]["redistribution"] = "permitted"

        problems = corpus_publication_problems(publication_documents)
        self.assertTrue(any("publishable rights" in problem.message for problem in problems))

        capture["rights"].update(
            {
                "status": "open-license",
                "license_name": "Example Open Licence",
                "license_version": "1.0",
                "license_jurisdiction": "example",
                "license_url": "https://example.gov/open-licence",
                "attribution": "Example Authority",
            }
        )
        capture["rights"]["permitted_uses"]["capture"] = "permitted"
        self.bind_rights_review(capture)
        capture["publication_clearance"] = {
            "status": "not_reviewed",
            "checks": {
                "personal_data": "unknown",
                "sealing_or_reporting_restrictions": "unknown",
                "official_redactions_preserved": "unknown",
                "sensitive_material": "unknown",
            },
            "review_state": "unreviewed",
        }
        self.assertEqual([], rights_assessment_problems(capture_path, capture))
        problems = corpus_publication_problems(publication_documents)
        self.assertTrue(
            any("privacy and publication clearance" in problem.message for problem in problems)
        )

        capture["publication_clearance"] = self.cleared_publication()
        messages = [
            problem.message
            for problem in corpus_publication_problems(publication_documents)
        ]
        self.assertTrue(
            any("public mirrors are disabled in V1" in message for message in messages)
        )
        self.assertFalse(
            any(
                phrase in message
                for message in messages
                for phrase in (
                    "does not establish publishable rights",
                    "does not permit",
                    "lacks independent privacy and publication clearance",
                )
            )
        )

    def test_publication_rejects_an_expired_rights_review(self) -> None:
        artifact = copy.deepcopy(
            load_document(REPOSITORY_ROOT / "examples" / "india-gst-source-artifact.json")
        )
        capture = copy.deepcopy(
            load_document(REPOSITORY_ROOT / "examples" / "india-gst-source-capture.json")
        )
        artifact["availability"] = "public_mirror"
        artifact["storage_locations"] = [
            {
                "role": "primary",
                "uri": "https://mirror.example.org/source.html",
                "access": "public",
            }
        ]
        artifact["publication_basis"] = [
            {"basis_type": "capture", "basis_id": capture["capture_id"]}
        ]
        self.make_rights_publishable(capture)
        capture["rights"]["next_review_at"] = "2026-01-01T00:00:00Z"

        messages = [
            problem.message
            for problem in corpus_publication_problems(
                [(Path("artifact.json"), artifact), (Path("capture.json"), capture)]
            )
        ]
        self.assertTrue(any("expired rights review" in message for message in messages))

    def test_derivation_publication_requires_output_clearance(self) -> None:
        output = copy.deepcopy(
            load_document(
                REPOSITORY_ROOT / "examples" / "india-gst-heading-markdown-artifact.json"
            )
        )
        derivation = copy.deepcopy(
            load_document(
                REPOSITORY_ROOT / "examples" / "india-gst-heading-derivation.json"
            )
        )
        capture = copy.deepcopy(
            load_document(REPOSITORY_ROOT / "examples" / "india-gst-source-capture.json")
        )
        output["availability"] = "public_mirror"
        output["storage_locations"] = [
            {
                "role": "primary",
                "uri": "https://mirror.example.org/heading.md",
                "access": "public",
            }
        ]
        output["publication_basis"] = [
            {"basis_type": "derivation", "basis_id": derivation["derivation_id"]}
        ]
        self.make_rights_publishable(capture)
        capture["publication_clearance"] = self.cleared_publication()

        problems = corpus_publication_problems(
            [
                (Path("output.json"), output),
                (Path("derivation.json"), derivation),
                (Path("capture.json"), capture),
            ]
        )
        self.assertTrue(
            any("output privacy and publication clearance" in p.message for p in problems)
        )

    def test_derivation_rights_basis_must_cover_every_actual_input(self) -> None:
        output = copy.deepcopy(
            load_document(
                REPOSITORY_ROOT / "examples" / "india-gst-heading-markdown-artifact.json"
            )
        )
        derivation = copy.deepcopy(
            load_document(
                REPOSITORY_ROOT / "examples" / "india-gst-heading-derivation.json"
            )
        )
        capture = copy.deepcopy(
            load_document(REPOSITORY_ROOT / "examples" / "india-gst-source-capture.json")
        )
        settings = load_document(
            REPOSITORY_ROOT / "examples" / "india-gst-heading-settings-artifact.json"
        )
        output["availability"] = "public_mirror"
        output["storage_locations"] = [
            {
                "role": "primary",
                "uri": "https://mirror.example.org/heading.md",
                "access": "public",
            }
        ]
        output["publication_basis"] = [
            {"basis_type": "derivation", "basis_id": derivation["derivation_id"]}
        ]
        derivation["input_artifacts"][0]["artifact_id"] = settings["artifact_id"]
        derivation["publication_clearance"] = self.cleared_derivation_publication(
            derivation
        )
        self.make_rights_publishable(capture)
        capture["publication_clearance"] = self.cleared_publication()

        problems = corpus_publication_problems(
            [
                (Path("output.json"), output),
                (Path("derivation.json"), derivation),
                (Path("capture.json"), capture),
            ]
        )
        self.assertTrue(
            any("do not cover input_artifacts[0]" in problem.message for problem in problems)
        )

    def test_publication_clearance_cannot_predate_the_captured_bytes(self) -> None:
        artifact = copy.deepcopy(
            load_document(REPOSITORY_ROOT / "examples" / "india-gst-source-artifact.json")
        )
        capture = copy.deepcopy(
            load_document(REPOSITORY_ROOT / "examples" / "india-gst-source-capture.json")
        )
        artifact["availability"] = "public_mirror"
        artifact["storage_locations"] = [
            {
                "role": "primary",
                "uri": "https://mirror.example.org/source.html",
                "access": "public",
            }
        ]
        artifact["publication_basis"] = [
            {"basis_type": "capture", "basis_id": capture["capture_id"]}
        ]
        self.make_rights_publishable(capture)
        capture["publication_clearance"] = self.cleared_publication()
        capture["publication_clearance"]["reviewed_at"] = "2000-01-01T00:00:00Z"
        self.refresh_publication_clearance_digest(capture["publication_clearance"])

        problems = corpus_publication_problems(
            [(Path("artifact.json"), artifact), (Path("capture.json"), capture)]
        )
        self.assertTrue(any("older than the captured bytes" in p.message for p in problems))

    def test_capture_and_derivation_references_resolve(self) -> None:
        documents = [
            (path, load_document(path))
            for path in sorted((REPOSITORY_ROOT / "examples").glob("*.json"))
        ]
        derivation_path = REPOSITORY_ROOT / "examples" / "india-gst-heading-derivation.json"
        mutated_documents = [
            (
                path,
                (
                    {
                        **copy.deepcopy(document),
                        "settings_artifact_id": "urn:trace-the-law:artifact:sha256:" + "f" * 64,
                    }
                    if path == derivation_path
                    else copy.deepcopy(document)
                ),
            )
            for path, document in documents
        ]
        problems = corpus_integrity_problems(mutated_documents)
        self.assertTrue(any("settings artifact" in problem.message for problem in problems))

    def test_discovered_capture_rejects_malformed_and_distinct_origins(self) -> None:
        source = copy.deepcopy(
            load_document(
                REPOSITORY_ROOT / "examples" / "india-gst-source-manifest.json"
            )
        )
        parent = copy.deepcopy(
            load_document(
                REPOSITORY_ROOT / "examples" / "india-gst-source-capture.json"
            )
        )

        def problems_for(
            source_url: str,
            *,
            retrieved_at: str = "2026-08-23T12:20:07Z",
        ) -> list:
            child = copy.deepcopy(parent)
            child["capture_id"] = (
                "urn:trace-the-law:capture:uuid:"
                "98989898-9898-4989-8989-989898989898"
            )
            child["retrieval"]["source_url"] = source_url
            child["retrieval"]["retrieved_at"] = retrieved_at
            child["created_at"] = retrieved_at
            child["acquisition"] = {
                "entrypoint_id": parent["acquisition"]["entrypoint_id"],
                "route": "discovered_link",
                "discovered_value": source_url,
                "resolution_method": "rfc3986_urljoin",
                "discovery_evidence": {
                    "artifact_id": parent["artifact_id"],
                    "capture_id": parent["capture_id"],
                    "quoted_text": source_url,
                },
            }
            return _capture_acquisition_problems(
                {
                    parent["capture_id"]: (Path("parent.json"), parent),
                    child["capture_id"]: (Path("child.json"), child),
                },
                {source["source_id"]: (Path("source.json"), source)},
            )

        for source_url in (
            "https://cbic-gst.gov.in:99999/legal.pdf",
            "https://[bad/legal.pdf",
        ):
            with self.subTest(source_url=source_url):
                messages = [problem.message for problem in problems_for(source_url)]
                self.assertTrue(any("origin is malformed" in message for message in messages))

        zero_port_messages = [
            problem.message
            for problem in problems_for("https://cbic-gst.gov.in:0/legal.pdf")
        ]
        self.assertTrue(
            any("must remain on the reviewed source origin" in message for message in zero_port_messages)
        )

        chronology_messages = [
            problem.message
            for problem in problems_for(
                "https://cbic-gst.gov.in/legal.pdf",
                retrieved_at="2020-01-01T00:00:00Z",
            )
        ]
        self.assertTrue(
            any("cannot predate the parent capture evidence" in message for message in chronology_messages)
        )

    def test_record_authority_role_must_match_the_exact_assertion(self) -> None:
        documents = self.example_documents()
        for path, document in documents:
            if path.name == "india-gst-record.json":
                document["authority_relationships"] = [
                    {
                        "authority_id": (
                            "urn:trace-the-law:authority:uuid:"
                            "22222222-2222-4222-8222-222222222222"
                        ),
                        "role": "issuing",
                        "assertion_id": (
                            "urn:trace-the-law:assertion:uuid:"
                            "13131313-1313-4131-8131-131313131313"
                        ),
                    }
                ]

        messages = [problem.message for problem in corpus_integrity_problems(documents)]
        self.assertTrue(any("subject does not match this record" in m for m in messages))
        self.assertTrue(any("object does not match authority_id" in m for m in messages))
        self.assertTrue(any("role does not match" in m for m in messages))

    def test_record_authority_and_assertion_ids_must_resolve(self) -> None:
        documents = self.example_documents()
        for path, document in documents:
            if path.name == "india-gst-record.json":
                document["authority_relationships"] = [
                    {
                        "authority_id": (
                            "urn:trace-the-law:authority:uuid:"
                            "90909090-9090-4090-8090-909090909090"
                        ),
                        "role": "issuing",
                        "assertion_id": (
                            "urn:trace-the-law:assertion:uuid:"
                            "91919191-9191-4191-8191-919191919191"
                        ),
                    }
                ]

        messages = [problem.message for problem in corpus_integrity_problems(documents)]
        self.assertTrue(any("record authority does not resolve" in m for m in messages))
        self.assertTrue(
            any("record authority assertion does not resolve" in m for m in messages)
        )

    def test_positive_coverage_rejects_an_open_gap(self) -> None:
        problems = self.mutated_example_problems(
            "india-gst-coverage-ledger.json",
            lambda document: document.__setitem__(
                "status", "covered_for_declared_scope"
            ),
        )
        self.assertTrue(problems)

    def test_covered_scope_requires_exhaustive_entrypoints_and_latest_success(self) -> None:
        documents = self.example_documents()
        for path, document in documents:
            if path.name == "india-gst-coverage-ledger.json":
                document["status"] = "covered_for_declared_scope"
                document["known_gaps"] = []
                document["enumeration_runs"].append(
                    {
                        "run_id": "example-20260823-later-failure",
                        "entrypoint_id": "cgst-act-html",
                        "independent_group": "cbic-html",
                        "started_at": "2026-08-23T12:20:07Z",
                        "completed_at": "2026-08-23T12:20:08Z",
                        "outcome": "failed",
                        "discovered_count": 0,
                        "failure_code": "parser_error",
                    }
                )
                document["generated_at"] = "2026-08-23T12:20:09Z"
        messages = [problem.message for problem in corpus_integrity_problems(documents)]
        self.assertTrue(any("declared exhaustive" in message for message in messages))
        ledger = next(
            document
            for path, document in documents
            if path.name == "india-gst-coverage-ledger.json"
        )
        messages = [
            problem.message
            for problem in validate_document(
                Path("coverage.json"), ledger, self.schemas, self.registry
            )
        ]
        self.assertTrue(any("latest run" in message for message in messages))

    def test_bundle_cannot_invent_a_better_coverage_result_than_ledger(self) -> None:
        documents = self.example_documents()
        for path, document in documents:
            if path.name == "india-gst-evidence-bundle.json":
                document["coverage"][0].update(
                    {
                        "status": "covered_for_declared_scope",
                        "gap_ids": [],
                    }
                )
        messages = [problem.message for problem in corpus_integrity_problems(documents)]
        self.assertTrue(any("does not match the resolved ledger" in m for m in messages))
        self.assertTrue(any("do not match unresolved gaps" in m for m in messages))

    def test_bundle_cannot_select_coverage_superseded_before_snapshot(self) -> None:
        documents = self.example_documents()
        coverage = next(
            document
            for path, document in documents
            if path.name == "india-gst-coverage-ledger.json"
        )
        successor = copy.deepcopy(coverage)
        successor["coverage_id"] = (
            "urn:trace-the-law:coverage:uuid:"
            "28282828-2828-4282-8282-282828282828"
        )
        successor["supersedes_coverage_id"] = coverage["coverage_id"]
        successor["status"] = "blocked"
        successor["generated_at"] = "2026-08-23T13:00:00Z"
        documents.append((Path("successor-coverage.json"), successor))

        messages = [
            problem.message for problem in corpus_integrity_problems(documents)
        ]
        self.assertTrue(
            any(
                "coverage ledger superseded by a ledger visible" in message
                and successor["coverage_id"] in message
                for message in messages
            )
        )

    def test_bundle_closes_incoming_version_and_provision_history(self) -> None:
        documents = self.example_documents()
        by_name = {path.name: document for path, document in documents}
        record = by_name["india-gst-record.json"]
        bundle = by_name["india-gst-evidence-bundle.json"]
        old_version = record["versions"][0]
        old_provision = old_version["provisions"][0]

        successor_version = copy.deepcopy(old_version)
        successor_version["version_id"] = (
            "urn:trace-the-law:version:uuid:"
            "26262626-2626-4262-8262-262626262626"
        )
        successor_version["supersedes_version_ids"] = [old_version["version_id"]]
        successor_version["derived_from_assertion_ids"] = []
        successor_version["provisions"] = []
        record["versions"].append(successor_version)

        messages = [
            problem.message for problem in corpus_integrity_problems(documents)
        ]
        self.assertTrue(
            any(
                "explicitly depend on version" in message
                and successor_version["version_id"] in message
                for message in messages
            )
        )

        claim = bundle["claims"][0]
        claim["classification"] = "DERIVED"
        claim["content_use"] = "summary"
        claim["claim_text"] = "The selected version states the rule."
        claim.pop("bibliographic_facts")
        claim["subjects"] = [
            {"entity_type": "version", "entity_id": old_version["version_id"]}
        ]
        claim["applicability"] = copy.deepcopy(
            bundle["evaluation_context"]["facts_period"]
        )
        messages = [
            problem.message for problem in corpus_integrity_problems(documents)
        ]
        self.assertTrue(
            any(
                "successor" in message
                and "not a claim subject" in message
                and successor_version["version_id"] in message
                for message in messages
            )
        )

        successor_provision = copy.deepcopy(old_provision)
        successor_provision["provision_version_id"] = (
            "urn:trace-the-law:provision-version:uuid:"
            "34343434-3434-4343-8343-343434343434"
        )
        successor_provision["predecessor_provision_version_ids"] = [
            old_provision["provision_version_id"]
        ]
        successor_provision["derived_from_assertion_ids"] = []
        successor_version["provisions"] = [successor_provision]
        messages = [
            problem.message for problem in corpus_integrity_problems(documents)
        ]
        self.assertTrue(
            any(
                "explicitly depend on provision_version" in message
                and successor_provision["provision_version_id"] in message
                for message in messages
            )
        )

    def test_privacy_block_cannot_have_a_public_issue(self) -> None:
        def mutate(document) -> None:
            document["privacy_status"] = "BLOCKED_PRIVACY"
            document["public_review_status"] = "SUBMITTED"
            document["public_issue"] = {
                "url": "https://github.com/example/project/issues/1",
                "created_by_project_bot": True,
            }

        problems = self.mutated_example_problems(
            "india-gst-correction-report.json", mutate
        )
        self.assertTrue(problems)

    def test_verified_correction_requires_independent_fetch(self) -> None:
        report = copy.deepcopy(
            load_document(REPOSITORY_ROOT / "examples" / "india-gst-correction-report.json")
        )
        report["finding_status"] = "VERIFIED_ERROR"
        report["verification"]["status"] = "VERIFIED_ERROR"
        problems = correction_state_problems(Path("report.json"), report)
        self.assertTrue(any("independent" in problem.message for problem in problems))

    def test_disabled_private_correction_states_fail_closed(self) -> None:
        for draft_status in (
            "AWAITING_USER_ACTION",
            "PRIVATE_DRAFT",
            "EXPIRED",
            "REVOKED",
        ):
            with self.subTest(draft_status=draft_status):
                report = copy.deepcopy(
                    load_document(
                        REPOSITORY_ROOT
                        / "examples"
                        / "india-gst-correction-report.json"
                    )
                )
                report["draft_status"] = draft_status
                messages = [
                    problem.message
                    for problem in correction_state_problems(
                        Path("report.json"), report
                    )
                ]
                self.assertTrue(
                    any("private-draft states" in message for message in messages)
                )

    def test_correction_excerpt_requires_independent_content_verification(self) -> None:
        report = copy.deepcopy(
            load_document(
                REPOSITORY_ROOT / "examples" / "india-gst-correction-report.json"
            )
        )
        self.make_verified_report(report)
        evidence = report["public_evidence"][0]
        evidence["public_excerpt"] = "Fabricated official passage"
        evidence["excerpt_digest"] = {
            "algorithm": "sha256",
            "value": hashlib.sha256(
                evidence["public_excerpt"].encode("utf-8")
            ).hexdigest(),
        }
        messages = [
            problem.message
            for problem in validate_document(
                Path("report.json"), report, self.schemas, self.registry
            )
        ]
        self.assertTrue(
            any(
                "content_verification" in message and "required" in message
                for message in messages
            )
        )

        evidence["content_verification"] = {
            "method": "human_visual_match",
            "verified_at": "2026-08-23T12:20:06Z",
            "verifier": {
                "producer_id": (
                    "urn:trace-the-law:producer:human:"
                    "correction-content-verifier"
                ),
                "producer_type": "human",
                "name": "Example correction content verifier",
            },
            "verified_evidence_digest": {
                "algorithm": "sha256",
                "value": "0" * 64,
            },
        }
        self.refresh_evidence_content_verification(evidence)
        messages = [
            problem.message
            for problem in validate_document(
                Path("report.json"), report, self.schemas, self.registry
            )
        ]
        self.assertFalse(
            any("content verification" in message for message in messages)
        )

        evidence["public_excerpt"] = "Different fabricated official passage"
        evidence["excerpt_digest"]["value"] = hashlib.sha256(
            evidence["public_excerpt"].encode("utf-8")
        ).hexdigest()
        messages = [
            problem.message
            for problem in validate_document(
                Path("report.json"), report, self.schemas, self.registry
            )
        ]
        self.assertTrue(
            any("content verification digest" in message for message in messages)
        )

    def test_verified_correction_requires_digest_bound_supporting_evidence(self) -> None:
        report = copy.deepcopy(
            load_document(REPOSITORY_ROOT / "examples" / "india-gst-correction-report.json")
        )
        report["finding_status"] = "VERIFIED_ERROR"
        report["verification"]["status"] = "VERIFIED_ERROR"
        report["verification"]["independent_fetch"] = True

        messages = [
            problem.message
            for problem in correction_state_problems(Path("report.json"), report)
        ]
        self.assertTrue(any("supporting evidence" in message for message in messages))
        self.assertTrue(any("bind the observed digest" in message for message in messages))

    def test_official_conflict_requires_distinct_contrary_official_evidence(self) -> None:
        report = copy.deepcopy(
            load_document(REPOSITORY_ROOT / "examples" / "india-gst-correction-report.json")
        )
        self.make_verified_report(report)
        report["finding_status"] = "OFFICIAL_CONFLICT"
        report["verification"]["status"] = "OFFICIAL_CONFLICT"

        messages = [
            problem.message
            for problem in correction_state_problems(Path("report.json"), report)
        ]
        self.assertTrue(any("contrary" in message for message in messages))

        contrary = copy.deepcopy(report["public_evidence"][0])
        contrary["role"] = "CONTRARY"
        report["public_evidence"].append(contrary)
        messages = [
            problem.message
            for problem in correction_state_problems(Path("report.json"), report)
        ]
        self.assertTrue(any("two distinct" in message for message in messages))

    def test_local_unverified_report_cannot_be_applied(self) -> None:
        report = copy.deepcopy(
            load_document(REPOSITORY_ROOT / "examples" / "india-gst-correction-report.json")
        )
        report["public_review_status"] = "APPLIED"
        report["public_issue"] = {
            "url": "https://github.com/example/project/issues/1",
            "created_by_project_bot": True,
        }
        problems = correction_state_problems(Path("report.json"), report)
        self.assertTrue(any("only after" in problem.message for problem in problems))
        self.assertTrue(any("verified first" in problem.message for problem in problems))

    def test_ready_to_open_correction_validates_end_to_end(self) -> None:
        report = copy.deepcopy(
            load_document(REPOSITORY_ROOT / "examples" / "india-gst-correction-report.json")
        )
        self.open_report_for_public_review(report)
        self.clear_report_public_evidence(report)
        self.bind_correction_privacy_review(report)

        self.assertEqual(
            [],
            validate_document(
                Path("ready-correction.json"), report, self.schemas, self.registry
            ),
        )

    def test_spoofed_opened_correction_receipt_fails_closed(self) -> None:
        report = copy.deepcopy(
            load_document(REPOSITORY_ROOT / "examples" / "india-gst-correction-report.json")
        )
        self.open_report_for_public_review(report)
        self.clear_report_public_evidence(report)
        self.bind_correction_privacy_review(report)
        self.add_spoofed_public_issue(report)

        messages = [
            problem.message
            for problem in validate_document(
                Path("opened-correction.json"), report, self.schemas, self.registry
            )
        ]
        self.assertEqual(1, len(messages))
        self.assertIn("public correction receipts are disabled", messages[0])

    def test_spoofed_applied_correction_receipt_fails_closed(self) -> None:
        report = copy.deepcopy(
            load_document(REPOSITORY_ROOT / "examples" / "india-gst-correction-report.json")
        )
        self.make_verified_report(report)
        self.open_report_for_public_review(report)
        report["application"] = {
            "merge_commit_url": (
                "https://github.com/trace-the-law/core/commit/" + "a" * 40
            ),
            "invalidation_event_id": (
                "urn:trace-the-law:event:uuid:"
                "cccccccc-cccc-4ccc-8ccc-cccccccccccc"
            ),
            "snapshot_after": "urn:trace-the-law:snapshot:sha256:" + "d" * 64,
        }
        self.bind_correction_privacy_review(report)
        self.add_spoofed_public_issue(report, "APPLIED")

        messages = [
            problem.message
            for problem in validate_document(
                Path("applied-correction.json"), report, self.schemas, self.registry
            )
        ]
        self.assertEqual(1, len(messages))
        self.assertIn("public correction receipts are disabled", messages[0])

    def test_correction_privacy_review_binds_exact_public_payload(self) -> None:
        report = copy.deepcopy(
            load_document(REPOSITORY_ROOT / "examples" / "india-gst-correction-report.json")
        )
        self.open_report_for_public_review(report)
        self.clear_report_public_evidence(report)
        self.bind_correction_privacy_review(report)
        report["public_summary"] = "Changed after the human privacy review."

        messages = [
            problem.message
            for problem in validate_document(
                Path("opened-correction.json"), report, self.schemas, self.registry
            )
        ]
        self.assertTrue(
            any(
                "exact pre-publication correction payload" in message
                for message in messages
            )
        )

    def test_correction_evidence_cannot_postdate_clearance_or_verification(self) -> None:
        for role in ("SUPPORTING", "CONTRARY"):
            with self.subTest(role=role):
                report = copy.deepcopy(
                    load_document(
                        REPOSITORY_ROOT
                        / "examples"
                        / "india-gst-correction-report.json"
                    )
                )
                self.make_verified_report(report)
                evidence = report["public_evidence"][0]
                evidence["role"] = role
                evidence["retrieved_at"] = "2026-08-23T15:00:00Z"
                evidence["publication_clearance"]["reviewed_at"] = (
                    "2026-08-23T14:00:00Z"
                )
                report["verification"]["checked_at"] = "2026-08-23T14:30:00Z"

                messages = [
                    problem.message
                    for problem in correction_state_problems(Path("report.json"), report)
                ]
                self.assertIn(
                    "publication clearance cannot predate correction evidence retrieval",
                    messages,
                )
                self.assertIn(
                    "correction verification cannot predate supporting or contrary evidence retrieval",
                    messages,
                )

    def test_correction_privacy_review_cannot_predate_evidence_clearance(self) -> None:
        report = copy.deepcopy(
            load_document(
                REPOSITORY_ROOT / "examples" / "india-gst-correction-report.json"
            )
        )
        self.open_report_for_public_review(report)
        self.clear_report_public_evidence(report)
        report["public_evidence"][0]["publication_clearance"]["reviewed_at"] = (
            "2026-08-23T14:30:00Z"
        )
        self.refresh_publication_clearance_digest(
            report["public_evidence"][0]["publication_clearance"]
        )
        self.bind_correction_privacy_review(report)

        messages = [
            problem.message
            for problem in validate_document(
                Path("opened-correction.json"), report, self.schemas, self.registry
            )
        ]
        self.assertIn(
            "privacy review cannot predate public evidence publication clearance",
            messages,
        )
        self.assertNotIn(
            "privacy review digest does not match the exact pre-publication correction payload",
            messages,
        )

    def test_correction_invalidation_event_cannot_predate_lifecycle_proof(self) -> None:
        lifecycle_states = (
            ("APPLIED", "succeeded"),
            ("PROPAGATION_FAILED", "failed"),
        )
        for review_status, propagation_status in lifecycle_states:
            with self.subTest(review_status=review_status):
                documents = self.example_documents()
                report_id = (
                    "urn:trace-the-law:report:uuid:"
                    "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb"
                )
                merge_url = (
                    "https://github.com/trace-the-law/core/commit/" + "a" * 40
                )
                event = next(
                    document
                    for path, document in documents
                    if path.name == "india-gst-invalidation-event.json"
                )
                event["cause"] = {
                    "correction_report_ids": [report_id],
                    "merge_commit_url": merge_url,
                }
                event["propagation_status"] = propagation_status
                event["occurred_at"] = "2026-08-23T12:00:00Z"
                for path, document in documents:
                    if path.name != "india-gst-correction-report.json":
                        continue
                    self.make_verified_report(document)
                    self.open_report_for_public_review(document)
                    document["public_review_status"] = review_status
                    document["public_issue"] = {
                        "url": "https://github.com/trace-the-law/core/issues/1",
                        "created_by_project_bot": True,
                    }
                    document["verification"]["checked_at"] = (
                        "2026-08-23T14:02:00Z"
                    )
                    document["public_evidence"][0]["publication_clearance"][
                        "reviewed_at"
                    ] = "2026-08-23T14:03:00Z"
                    document["privacy_review"]["reviewed_at"] = (
                        "2026-08-23T14:04:00Z"
                    )
                    document["application"] = {
                        "merge_commit_url": merge_url,
                        "invalidation_event_id": event["event_id"],
                        "snapshot_after": event["snapshot_after"],
                    }
                    self.bind_correction_privacy_review(document)

                messages = [
                    problem.message
                    for problem in corpus_integrity_problems(documents)
                ]
                for prerequisite in (
                    "verification.checked_at",
                    "public_evidence[0].retrieved_at",
                    "public_evidence[0].publication_clearance.reviewed_at",
                    "privacy_review.reviewed_at",
                ):
                    self.assertIn(
                        "correction application invalidation event occurred_at "
                        f"cannot predate {prerequisite}",
                        messages,
                    )

    def test_applied_report_rejects_unresolved_event_and_snapshot_proof(self) -> None:
        documents = self.example_documents()
        for path, document in documents:
            if path.name != "india-gst-correction-report.json":
                continue
            self.make_verified_report(document)
            self.open_report_for_public_review(document)
            document["public_evidence"][0]["publication_clearance"][
                "reviewed_at"
            ] = "2026-08-23T13:00:00Z"
            document["privacy_review"]["reviewed_at"] = "2026-08-23T13:10:00Z"
            document["public_review_status"] = "APPLIED"
            document["public_issue"] = {
                "url": "https://github.com/trace-the-law/core/issues/1",
                "created_by_project_bot": True,
            }
            document["application"] = {
                "merge_commit_url": (
                    "https://github.com/trace-the-law/core/commit/" + "a" * 40
                ),
                "invalidation_event_id": (
                    "urn:trace-the-law:event:uuid:"
                    "92929292-9292-4292-8292-929292929292"
                ),
                "snapshot_after": "urn:trace-the-law:snapshot:sha256:" + "f" * 64,
            }

        messages = [problem.message for problem in corpus_integrity_problems(documents)]
        self.assertTrue(
            any("application invalidation event does not resolve" in m for m in messages)
        )

        event_id = next(
            document["event_id"]
            for path, document in documents
            if path.name == "india-gst-invalidation-event.json"
        )
        for path, document in documents:
            if path.name == "india-gst-correction-report.json":
                document["application"]["invalidation_event_id"] = event_id
        messages = [problem.message for problem in corpus_integrity_problems(documents)]
        self.assertTrue(
            any("correction application snapshot does not resolve" in m for m in messages)
        )

    def test_applied_report_proof_must_match_successful_causal_event(self) -> None:
        documents = self.example_documents()
        report_id = "urn:trace-the-law:report:uuid:bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb"
        merge_url = "https://github.com/trace-the-law/core/commit/" + "a" * 40
        event = next(
            document
            for path, document in documents
            if path.name == "india-gst-invalidation-event.json"
        )
        event_id = event["event_id"]
        valid_snapshot_after = event["snapshot_after"]
        for path, document in documents:
            if path.name == "india-gst-correction-report.json":
                self.make_verified_report(document)
                self.open_report_for_public_review(document)
                document["public_evidence"][0]["publication_clearance"][
                    "reviewed_at"
                ] = "2026-08-23T13:00:00Z"
                document["privacy_review"]["reviewed_at"] = "2026-08-23T13:10:00Z"
                document["public_review_status"] = "APPLIED"
                document["public_issue"] = {
                    "url": "https://github.com/trace-the-law/core/issues/1",
                    "created_by_project_bot": True,
                }
                document["application"] = {
                    "merge_commit_url": merge_url,
                    "invalidation_event_id": event_id,
                    "snapshot_after": valid_snapshot_after,
                }
            elif path.name == "india-gst-invalidation-event.json":
                document["cause"] = {
                    "correction_report_ids": [],
                    "merge_commit_url": (
                        "https://github.com/trace-the-law/core/commit/" + "b" * 40
                    ),
                }
                document["propagation_status"] = "failed"
                document["snapshot_after"] = document["snapshot_before"]

        messages = [problem.message for problem in corpus_integrity_problems(documents)]
        self.assertTrue(any("does not name this correction report" in m for m in messages))
        self.assertTrue(any("merge commit does not match" in m for m in messages))
        self.assertTrue(any("propagation_status 'succeeded'" in m for m in messages))
        self.assertTrue(
            any("snapshot does not match the invalidation event" in m for m in messages)
        )

        # The same proof chain is accepted when all four links agree.
        for path, document in documents:
            if path.name == "india-gst-invalidation-event.json":
                document["cause"] = {
                    "correction_report_ids": [report_id],
                    "merge_commit_url": merge_url,
                }
                document["propagation_status"] = "succeeded"
                document["snapshot_after"] = valid_snapshot_after
        messages = [problem.message for problem in corpus_integrity_problems(documents)]
        application_messages = [
            message
            for message in messages
            if "application" in message
            or "does not name this correction report" in message
            or "merge commit" in message
            or "propagation_status" in message
        ]
        self.assertEqual([], application_messages)

    def test_supported_bundle_rejects_known_coverage_gap(self) -> None:
        problems = self.mutated_example_problems(
            "india-gst-evidence-bundle.json",
            lambda document: document.__setitem__("status", "SUPPORTED"),
        )
        self.assertTrue(problems)

    def test_stale_coverage_cannot_claim_supported(self) -> None:
        bundle = copy.deepcopy(
            load_document(REPOSITORY_ROOT / "examples" / "india-gst-evidence-bundle.json")
        )
        bundle["status"] = "SUPPORTED"
        bundle["coverage"][0]["status"] = "covered_for_declared_scope"
        bundle["coverage"][0]["gap_ids"] = []
        bundle["coverage"][0]["fresh_until"] = "2020-01-01T00:00:00Z"
        bundle["unresolved_items"] = []
        bundle["verification_tasks"] = []
        problems = evidence_bundle_status_problems(Path("bundle.json"), bundle)
        self.assertTrue(any("expired coverage" in problem.message for problem in problems))
        self.assertTrue(any("INSUFFICIENT_COVERAGE" in problem.message for problem in problems))

    def test_coverage_gap_outranks_conflict_or_missing_facts(self) -> None:
        bundle = load_document(
            REPOSITORY_ROOT / "examples" / "india-gst-evidence-bundle.json"
        )
        for status in ("CONFLICTED", "MISSING_FACTS"):
            mutated = copy.deepcopy(bundle)
            mutated["status"] = status
            if status == "CONFLICTED":
                mutated["conflicts"] = [
                    {
                        "assertion_ids": [
                            "urn:trace-the-law:assertion:uuid:88888888-8888-4888-8888-888888888888",
                            "urn:trace-the-law:assertion:uuid:13131313-1313-4131-8131-131313131313",
                        ],
                        "resolution_state": "unresolved",
                    }
                ]
            problems = evidence_bundle_status_problems(Path("bundle.json"), mutated)
            self.assertTrue(
                any("INSUFFICIENT_COVERAGE" in problem.message for problem in problems),
                status,
            )

    def test_missing_facts_requires_an_explicit_blocking_missing_fact(self) -> None:
        bundle = copy.deepcopy(
            load_document(REPOSITORY_ROOT / "examples" / "india-gst-evidence-bundle.json")
        )
        bundle["status"] = "MISSING_FACTS"
        bundle["coverage"][0]["status"] = "covered_for_declared_scope"
        bundle["coverage"][0]["gap_ids"] = []
        bundle["unresolved_items"] = []
        bundle["verification_tasks"] = []

        problems = validate_document(
            Path("bundle.json"), bundle, self.schemas, self.registry
        )
        self.assertTrue(
            any("blocking missing_fact" in problem.message for problem in problems)
        )

    def test_conflicted_requires_evidence_and_an_unresolved_conflict(self) -> None:
        bundle = copy.deepcopy(
            load_document(REPOSITORY_ROOT / "examples" / "india-gst-evidence-bundle.json")
        )
        bundle["status"] = "CONFLICTED"
        bundle["coverage"][0]["status"] = "covered_for_declared_scope"
        bundle["coverage"][0]["gap_ids"] = []
        bundle["claims"] = []
        bundle["citations"] = []
        bundle["conflicts"] = [
            {
                "assertion_ids": [
                    "urn:trace-the-law:assertion:uuid:88888888-8888-4888-8888-888888888888",
                    "urn:trace-the-law:assertion:uuid:13131313-1313-4131-8131-131313131313",
                ],
                "resolution_state": "hierarchy_resolved",
            }
        ]
        bundle["unresolved_items"] = []
        bundle["verification_tasks"] = []

        messages = [
            problem.message
            for problem in validate_document(
                Path("bundle.json"), bundle, self.schemas, self.registry
            )
        ]
        self.assertTrue(any("at least one claim" in message for message in messages))
        self.assertTrue(any("at least one citation" in message for message in messages))
        self.assertTrue(any("unresolved conflict" in message for message in messages))
        self.assertTrue(
            any("blocking conflicting_assertions" in message for message in messages)
        )

    def test_conflicted_requires_one_exact_claim_blocker_task_chain(self) -> None:
        bundle = copy.deepcopy(
            load_document(REPOSITORY_ROOT / "examples" / "india-gst-evidence-bundle.json")
        )
        first_assertion = (
            "urn:trace-the-law:assertion:uuid:"
            "88888888-8888-4888-8888-888888888888"
        )
        second_assertion = (
            "urn:trace-the-law:assertion:uuid:"
            "13131313-1313-4131-8131-131313131313"
        )
        claim_id = bundle["claims"][0]["claim_id"]
        bundle["status"] = "CONFLICTED"
        bundle["coverage"][0]["status"] = "covered_for_declared_scope"
        bundle["coverage"][0]["gap_ids"] = []
        bundle["claims"][0]["assertion_ids"] = [first_assertion]
        bundle["claims"][0]["contrary_assertion_ids"] = [second_assertion]
        bundle["conflicts"] = [
            {
                "assertion_ids": [first_assertion, second_assertion],
                "resolution_state": "unresolved",
            }
        ]
        exact_targets = [
            {"entity_type": "assertion", "entity_id": first_assertion},
            {"entity_type": "assertion", "entity_id": second_assertion},
            {"entity_type": "claim", "entity_id": claim_id},
        ]
        bundle["unresolved_items"] = [
            {
                "kind": "conflicting_assertions",
                "severity": "blocking",
                "related_entities": copy.deepcopy(exact_targets),
            }
        ]
        bundle["verification_tasks"] = [
            {
                "verification_task_id": (
                    "urn:trace-the-law:verification-task:uuid:"
                    "ffffffff-ffff-4fff-8fff-ffffffffffff"
                ),
                "task_type": "check_later_authority",
                "reason": "conflicting",
                "targets": copy.deepcopy(exact_targets),
                "official_entrypoints": [
                    "https://cbic-gst.gov.in/hindi/CGST-bill-e.html"
                ],
            }
        ]

        self.assertEqual(
            [], evidence_bundle_status_problems(Path("bundle.json"), bundle)
        )

        bundle["unresolved_items"][0]["related_entities"] = [
            {"entity_type": "source", "entity_id": bundle["dependencies"][-1]["entity_id"]}
        ]
        messages = [
            problem.message
            for problem in evidence_bundle_status_problems(Path("bundle.json"), bundle)
        ]
        self.assertTrue(
            any("exactly one blocking item" in message for message in messages)
        )
        self.assertTrue(
            any("does not match one exact unresolved conflict" in message for message in messages)
        )

    def test_conflict_assertions_must_concern_the_affected_claim_subject(self) -> None:
        documents = self.example_documents()
        first_assertion = (
            "urn:trace-the-law:assertion:uuid:"
            "88888888-8888-4888-8888-888888888888"
        )
        unrelated_assertion = (
            "urn:trace-the-law:assertion:uuid:"
            "13131313-1313-4131-8131-131313131313"
        )
        for path, document in documents:
            if path.name != "india-gst-evidence-bundle.json":
                continue
            claim = document["claims"][0]
            claim["assertion_ids"] = [first_assertion]
            claim["contrary_assertion_ids"] = [unrelated_assertion]
            document["conflicts"] = [
                {
                    "assertion_ids": [first_assertion, unrelated_assertion],
                    "resolution_state": "unresolved",
                }
            ]

        messages = [problem.message for problem in corpus_integrity_problems(documents)]
        self.assertTrue(
            any("does not concern a non-assertion subject" in message for message in messages)
        )

    def test_missing_facts_cannot_mask_a_blocking_coverage_gap(self) -> None:
        bundle = copy.deepcopy(
            load_document(REPOSITORY_ROOT / "examples" / "india-gst-evidence-bundle.json")
        )
        bundle["status"] = "MISSING_FACTS"
        bundle["coverage"][0]["status"] = "covered_for_declared_scope"
        bundle["coverage"][0]["gap_ids"] = []
        bundle["unresolved_items"] = [
            {
                "kind": "missing_fact",
                "severity": "blocking",
                "related_entities": [],
            },
            {
                "kind": "coverage_gap",
                "severity": "blocking",
                "related_entities": [],
            },
        ]
        bundle["verification_tasks"] = []

        problems = evidence_bundle_status_problems(Path("bundle.json"), bundle)
        self.assertTrue(
            any("cannot mask" in problem.message for problem in problems)
        )

    def test_bundle_rejects_uncited_sensitive_claim_detail(self) -> None:
        bundle = copy.deepcopy(
            load_document(REPOSITORY_ROOT / "examples" / "india-gst-evidence-bundle.json")
        )
        bundle["claims"][0]["claim_text"] = "Alice paid INR 1,234,567."
        problems = evidence_bundle_privacy_problems(Path("bundle.json"), bundle)
        self.assertTrue(any("uncited currency" in problem.message for problem in problems))

    def test_succeeded_propagation_rejects_a_failed_rebuild(self) -> None:
        def mutate(document) -> None:
            document["rebuilds"][0]["status"] = "failed"
            document["rebuilds"][0]["failure_code"] = "build_failed"

        problems = self.mutated_example_problems(
            "india-gst-invalidation-event.json", mutate
        )
        self.assertTrue(problems)

    def test_invalidation_rejects_an_empty_structured_cause(self) -> None:
        event = copy.deepcopy(
            load_document(self.example_file("india-gst-invalidation-event.json"))
        )
        event["cause"] = {"correction_report_ids": []}
        problems = invalidation_problems(Path("event.json"), event)
        self.assertTrue(any("non-empty recorded cause" in p.message for p in problems))

    def test_succeeded_coverage_change_requires_coverage_rebuilds(self) -> None:
        event = copy.deepcopy(
            load_document(self.example_file("india-gst-invalidation-event.json"))
        )
        for rebuild in event["rebuilds"]:
            if rebuild["component"] in {"coverage_ledgers", "evidence_bundles"}:
                rebuild["status"] = "not_required"
        problems = invalidation_problems(Path("event.json"), event)
        message = next(
            problem.message
            for problem in problems
            if "affected downstream components" in problem.message
        )
        self.assertIn("coverage_ledgers", message)
        self.assertIn("evidence_bundles", message)

    def test_event_type_cannot_bypass_rebuilds_with_an_unmapped_entity(self) -> None:
        event = copy.deepcopy(
            load_document(self.example_file("india-gst-invalidation-event.json"))
        )
        event["affected_entities"] = [
            {
                "entity": {
                    "entity_type": "report",
                    "entity_id": (
                        "urn:trace-the-law:report:uuid:"
                        "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb"
                    ),
                },
                "change_kind": "updated",
            }
        ]
        for rebuild in event["rebuilds"]:
            rebuild["status"] = "not_required"
        problems = invalidation_problems(Path("event.json"), event)
        self.assertTrue(
            any("event type and affected entities" in problem.message for problem in problems)
        )

    def test_known_legal_effect_requires_a_basis_assertion(self) -> None:
        def mutate(document) -> None:
            document["versions"][0]["time_axes"]["effectiveness"] = {
                "status": "open_ended",
                "start": {
                    "status": "exact",
                    "value": "2017-06-22",
                    "precision": "day",
                },
            }

        problems = self.mutated_example_problems("india-gst-record.json", mutate)
        self.assertTrue(problems)

    def test_reviewed_assertion_state_requires_review_time(self) -> None:
        problems = self.mutated_example_problems(
            "india-gst-relationship-assertion.json",
            lambda document: document.__setitem__("status", "verified"),
        )
        self.assertTrue(problems)

    def test_agent_legal_interpretation_cannot_self_verify(self) -> None:
        assertion = copy.deepcopy(
            load_document(
                REPOSITORY_ROOT / "examples" / "india-gst-relationship-assertion.json"
            )
        )
        assertion["status"] = "verified"
        assertion["reviewed_at"] = "2026-08-23T12:30:00Z"
        assertion["interpretation_level"] = "legal_interpretation"
        assertion["producer"] = {
            "producer_type": "agent",
            "name": "self-verifying-agent",
        }
        assertion["reviewer"] = {
            "producer_type": "agent",
            "name": "self-verifying-agent",
        }
        problems = relationship_review_problems(Path("assertion.json"), assertion)
        self.assertTrue(any("human reviewer" in problem.message for problem in problems))

    def test_structural_assertion_cannot_hide_self_review_in_version_metadata(self) -> None:
        assertion = copy.deepcopy(
            load_document(
                REPOSITORY_ROOT / "examples" / "india-gst-relationship-assertion.json"
            )
        )
        assertion["status"] = "verified"
        assertion["reviewed_at"] = "2026-08-23T13:00:00Z"
        assertion["interpretation_level"] = "structural_inference"
        assertion["producer"] = {
            "producer_type": "agent",
            "name": "same-agent",
            "version": "1.0",
        }
        assertion["reviewer"] = {
            "producer_type": "agent",
            "name": " SAME-AGENT ",
            "version": "2.0",
        }
        problems = relationship_review_problems(Path("assertion.json"), assertion)
        self.assertTrue(any("producer may not review" in p.message for p in problems))

    def test_disputed_legal_interpretation_still_requires_human_review(self) -> None:
        assertion = copy.deepcopy(
            load_document(
                REPOSITORY_ROOT / "examples" / "india-gst-relationship-assertion.json"
            )
        )
        assertion["status"] = "disputed"
        assertion["reviewed_at"] = "2026-08-23T13:00:00Z"
        assertion["interpretation_level"] = "legal_interpretation"
        assertion["producer"] = {"producer_type": "agent", "name": "producer"}
        assertion["reviewer"] = {"producer_type": "agent", "name": "reviewer"}
        problems = relationship_review_problems(Path("assertion.json"), assertion)
        self.assertTrue(any("human reviewer" in problem.message for problem in problems))

    def test_authority_and_jurisdiction_claims_cannot_be_self_reviewed(self) -> None:
        cases = (
            ("india-cbic-authority.json", "profile"),
            ("india-jurisdiction.json", "name"),
        )
        for filename, claim_kind in cases:
            with self.subTest(filename=filename, claim_kind=claim_kind):
                document = copy.deepcopy(
                    load_document(REPOSITORY_ROOT / "examples" / filename)
                )
                if claim_kind == "profile":
                    document["profile_review_state"] = "verified"
                    document["reviewed_at"] = "2026-08-23T13:00:00Z"
                    document["reviewer"] = {
                        **document["producer"],
                        "version": "different-version",
                    }
                else:
                    name = document["names"][0]
                    name["status"] = "disputed"
                    name["reviewed_at"] = "2026-08-23T13:00:00Z"
                    name["reviewer"] = {
                        **name["producer"],
                        "version": "different-version",
                    }
                problems = validate_document(
                    Path(filename), document, self.schemas, self.registry
                )
                self.assertTrue(
                    any("profile claim producer" in problem.message for problem in problems)
                )

    def test_authority_profile_classifications_are_field_bound(self) -> None:
        mutations = (
            ("authority_kind", lambda document: document.__setitem__("authority_kind", "court")),
            ("branch", lambda document: document["branches"].__setitem__(0, "judicial")),
            (
                "lifecycle_status",
                lambda document: document.__setitem__(
                    "lifecycle_status", "abolished"
                ),
            ),
        )
        for field, mutate in mutations:
            with self.subTest(field=field):
                authority = copy.deepcopy(
                    load_document(
                        REPOSITORY_ROOT / "examples" / "india-cbic-authority.json"
                    )
                )
                self.assertEqual(
                    [],
                    validate_document(
                        Path("authority.json"),
                        authority,
                        self.schemas,
                        self.registry,
                    ),
                )
                mutate(authority)
                messages = [
                    problem.message
                    for problem in validate_document(
                        Path("authority.json"),
                        authority,
                        self.schemas,
                        self.registry,
                    )
                ]
                self.assertIn(
                    "profile field does not match its binding's normalized value",
                    messages,
                )

        jurisdiction = copy.deepcopy(
            load_document(
                REPOSITORY_ROOT / "examples" / "india-jurisdiction.json"
            )
        )
        name = jurisdiction["names"][0]
        name["text"] = "Supreme Court of India"
        text_binding = next(
            binding
            for binding in name["field_bindings"]
            if binding["field"] == "text"
        )
        text_binding["normalized_value"] = name["text"]
        text_binding["method"] = "human_reviewed"
        text_binding["normalization_review"] = copy.deepcopy(
            next(
                binding["normalization_review"]
                for binding in name["field_bindings"]
                if binding["field"] == "language"
            )
        )
        projection = copy.deepcopy(text_binding)
        projection["normalization_review"].pop("reviewed_binding_digest", None)
        text_binding["normalization_review"]["reviewed_binding_digest"] = {
            "algorithm": "sha256",
            "value": hashlib.sha256(_canonical_json_bytes(projection)).hexdigest(),
        }
        messages = [
            problem.message
            for problem in validate_document(
                Path("jurisdiction.json"),
                jurisdiction,
                self.schemas,
                self.registry,
            )
        ]
        self.assertIn(
            "sourced-name text must be copied exactly from its selected evidence",
            messages,
        )

    def test_jurisdiction_and_sourced_name_fields_are_field_bound(self) -> None:
        mutations = (
            (
                "jurisdiction_kind",
                lambda document: document.__setitem__(
                    "jurisdiction_kind", "judicial_district"
                ),
            ),
            (
                "lifecycle_status",
                lambda document: document.__setitem__(
                    "lifecycle_status", "abolished"
                ),
            ),
            (
                "name_text",
                lambda document: document["names"][0].__setitem__(
                    "text", "Supreme Court of India"
                ),
            ),
            (
                "name_language",
                lambda document: document["names"][0].__setitem__("language", "zh"),
            ),
            (
                "name_type",
                lambda document: document["names"][0].__setitem__(
                    "name_type", "translated"
                ),
            ),
            (
                "name_valid_during",
                lambda document: document["names"][0].__setitem__(
                    "valid_during",
                    {
                        "status": "open_ended",
                        "start": {
                            "status": "exact",
                            "value": "1950-01-26",
                            "precision": "day",
                            "calendar": "gregory",
                        },
                    },
                ),
            ),
        )
        for field, mutate in mutations:
            with self.subTest(field=field):
                jurisdiction = copy.deepcopy(
                    load_document(
                        REPOSITORY_ROOT / "examples" / "india-jurisdiction.json"
                    )
                )
                mutate(jurisdiction)
                messages = [
                    problem.message
                    for problem in validate_document(
                        Path("jurisdiction.json"),
                        jurisdiction,
                        self.schemas,
                        self.registry,
                    )
                ]
                self.assertIn(
                    "profile field does not match its binding's normalized value",
                    messages,
                )

    def test_profile_bindings_are_complete_unique_and_indexed_locally(self) -> None:
        authority = copy.deepcopy(
            load_document(
                REPOSITORY_ROOT / "examples" / "india-cbic-authority.json"
            )
        )
        authority["branches"].append("judicial")
        messages = [
            problem.message
            for problem in profile_review_problems(Path("authority.json"), authority)
        ]
        self.assertTrue(any("branch[1]" in message for message in messages))

        authority = copy.deepcopy(
            load_document(
                REPOSITORY_ROOT / "examples" / "india-cbic-authority.json"
            )
        )
        authority["profile_bindings"].append(
            copy.deepcopy(authority["profile_bindings"][0])
        )
        messages = [
            problem.message
            for problem in profile_review_problems(Path("authority.json"), authority)
        ]
        self.assertIn("profile field has more than one evidence binding", messages)

        authority = copy.deepcopy(
            load_document(
                REPOSITORY_ROOT / "examples" / "india-cbic-authority.json"
            )
        )
        branch_binding = next(
            binding
            for binding in authority["profile_bindings"]
            if binding["field"] == "branch"
        )
        branch_binding["branch_index"] = True
        branch_binding["evidence_indexes"] = [True]
        messages = [
            problem.message
            for problem in profile_review_problems(Path("authority.json"), authority)
        ]
        self.assertIn("profile branch index is outside branches", messages)
        self.assertIn(
            "profile evidence index is outside the binding's evidence array",
            messages,
        )

        jurisdiction = copy.deepcopy(
            load_document(
                REPOSITORY_ROOT / "examples" / "india-jurisdiction.json"
            )
        )
        name = jurisdiction["names"][0]
        name["field_bindings"] = [
            binding
            for binding in name["field_bindings"]
            if binding["field"] != "language"
        ]
        messages = [
            problem.message
            for problem in profile_review_problems(
                Path("jurisdiction.json"), jurisdiction
            )
        ]
        self.assertTrue(any("language" in message for message in messages))

    def test_profile_source_matching_is_whole_field_and_language_agnostic(self) -> None:
        jurisdiction = copy.deepcopy(
            load_document(
                REPOSITORY_ROOT / "examples" / "india-jurisdiction.json"
            )
        )
        jurisdiction["names"][0]["evidence"][0]["quoted_text"] = "Indian"
        messages = [
            problem.message
            for problem in profile_review_problems(
                Path("jurisdiction.json"), jurisdiction
            )
        ]
        self.assertIn(
            "profile source value is not present at an exact whole-field boundary in its selected evidence",
            messages,
        )

        jurisdiction = copy.deepcopy(
            load_document(
                REPOSITORY_ROOT / "examples" / "india-jurisdiction.json"
            )
        )
        name = jurisdiction["names"][0]
        name["text"] = "भारत"
        name["language"] = "hi"
        name["evidence"][0]["quoted_text"] = "भारत"
        self.refresh_evidence_content_verification(name["evidence"][0])
        for binding in name["field_bindings"]:
            binding["source_value"] = "भारत"
            if binding["field"] == "text":
                binding["normalized_value"] = "भारत"
            elif binding["field"] == "language":
                binding["normalized_value"] = "hi"
            review = binding.get("normalization_review")
            if not isinstance(review, dict):
                continue
            projection = copy.deepcopy(binding)
            projection["normalization_review"].pop(
                "reviewed_binding_digest", None
            )
            review["reviewed_binding_digest"] = {
                "algorithm": "sha256",
                "value": hashlib.sha256(
                    _canonical_json_bytes(projection)
                ).hexdigest(),
            }
        self.assertEqual(
            [],
            validate_document(
                Path("jurisdiction.json"),
                jurisdiction,
                self.schemas,
                self.registry,
            ),
        )

    def test_profile_normalization_review_is_independent_and_digest_bound(self) -> None:
        authority = copy.deepcopy(
            load_document(
                REPOSITORY_ROOT / "examples" / "india-cbic-authority.json"
            )
        )
        binding = authority["profile_bindings"][0]
        review = binding["normalization_review"]
        review["reviewer"] = copy.deepcopy(binding["producer"])
        review["reviewer"]["producer_type"] = "human"
        projection = copy.deepcopy(binding)
        projection["normalization_review"].pop("reviewed_binding_digest", None)
        review["reviewed_binding_digest"] = {
            "algorithm": "sha256",
            "value": hashlib.sha256(_canonical_json_bytes(projection)).hexdigest(),
        }
        messages = [
            problem.message
            for problem in profile_review_problems(Path("authority.json"), authority)
        ]
        self.assertIn(
            "profile binding producer may not approve its own normalization",
            messages,
        )

        authority = copy.deepcopy(
            load_document(
                REPOSITORY_ROOT / "examples" / "india-cbic-authority.json"
            )
        )
        authority["profile_bindings"][0]["normalization_review"]["reviewer"][
            "name"
        ] = "Changed after review"
        messages = [
            problem.message
            for problem in profile_review_problems(Path("authority.json"), authority)
        ]
        self.assertIn(
            "profile normalization review digest does not match the exact field binding",
            messages,
        )

    def test_profile_binding_and_review_clocks_are_bounded(self) -> None:
        authority = copy.deepcopy(
            load_document(
                REPOSITORY_ROOT / "examples" / "india-cbic-authority.json"
            )
        )
        authority["profile_bindings"][0]["created_at"] = "2026-08-23T12:00:00Z"
        name_binding = authority["names"][0]["field_bindings"][1]
        name_binding["normalization_review"]["reviewed_at"] = (
            "2026-08-23T13:00:00Z"
        )
        projection = copy.deepcopy(name_binding)
        projection["normalization_review"].pop("reviewed_binding_digest", None)
        name_binding["normalization_review"]["reviewed_binding_digest"] = {
            "algorithm": "sha256",
            "value": hashlib.sha256(_canonical_json_bytes(projection)).hexdigest(),
        }
        messages = [
            problem.message
            for problem in profile_review_problems(Path("authority.json"), authority)
        ]
        self.assertIn(
            "profile field binding cannot predate its profile or name", messages
        )
        self.assertIn(
            "profile normalization review cannot postdate profile updated_at",
            messages,
        )

        authority = copy.deepcopy(
            load_document(
                REPOSITORY_ROOT / "examples" / "india-cbic-authority.json"
            )
        )
        authority["names"][0]["created_at"] = "2026-08-23T12:30:00Z"
        authority["updated_at"] = "2026-08-23T13:00:00Z"
        messages = [
            problem.message
            for problem in profile_review_problems(Path("authority.json"), authority)
        ]
        self.assertIn(
            "profile field binding cannot predate its profile or name", messages
        )
        self.assertIn(
            "profile normalization review cannot predate its binding, profile, or name",
            messages,
        )

        documents = self.example_documents()
        for path, document in documents:
            if path.name == "india-gst-source-artifact.json":
                document["created_at"] = "2026-08-23T13:00:00Z"
            elif path.name == "india-gst-source-capture.json":
                document["retrieval"]["retrieved_at"] = "2026-08-23T13:00:00Z"
        chronology = [
            problem
            for problem in corpus_integrity_problems(documents)
            if problem.path.name
            in {"india-cbic-authority.json", "india-jurisdiction.json"}
        ]
        chronology_messages = [problem.message for problem in chronology]
        self.assertIn(
            "profile field binding cannot predate its selected artifact creation or capture retrieval",
            chronology_messages,
        )
        self.assertIn(
            "profile normalization review cannot predate its selected artifact creation or capture retrieval",
            chronology_messages,
        )

    def test_normalized_temporal_points_require_gregorian_calendar(self) -> None:
        assertion = copy.deepcopy(
            load_document(
                REPOSITORY_ROOT
                / "examples"
                / "india-gst-relationship-assertion.json"
            )
        )
        assertion["time_axes"]["publication"]["calendar"] = "buddhist"
        messages = [
            problem.message
            for problem in validate_document(
                Path("assertion.json"), assertion, self.schemas, self.registry
            )
        ]
        self.assertTrue(any("gregory" in message for message in messages))

    def test_temporal_precision_and_interval_order_are_checked(self) -> None:
        bundle = copy.deepcopy(
            load_document(REPOSITORY_ROOT / "examples" / "india-gst-evidence-bundle.json")
        )
        bundle["evaluation_context"]["effective_at"]["precision"] = "year"
        bundle["evaluation_context"]["facts_period"]["start"]["value"] = "2020-01-01"
        bundle["evaluation_context"]["facts_period"]["end"]["value"] = "2019-01-01"
        problems = temporal_problems(Path("bundle.json"), bundle)
        self.assertTrue(any("does not match" in problem.message for problem in problems))
        self.assertTrue(any("after its end" in problem.message for problem in problems))

    def test_extreme_offsets_that_overflow_utc_are_rejected(self) -> None:
        for value in (
            "9999-12-31T23:59:59-23:59",
            "0001-01-01T00:00:00+23:59",
        ):
            with self.subTest(value=value):
                problems = temporal_problems(
                    Path("extreme.json"),
                    {"created_at": value},
                )
                self.assertEqual(1, len(problems))
                self.assertIn(
                    "cannot be normalized to a valid UTC instant",
                    problems[0].message,
                )

    def test_invalidation_requires_distinct_snapshots_cause_and_full_ledger(self) -> None:
        event = copy.deepcopy(
            load_document(self.example_file("india-gst-invalidation-event.json"))
        )
        event["snapshot_after"] = event["snapshot_before"]
        event.pop("cause")
        event["rebuilds"] = [{"component": "search_index", "status": "succeeded"}]
        problems = invalidation_problems(Path("event.json"), event)
        messages = [problem.message for problem in problems]
        self.assertTrue(any("distinct" in message for message in messages))
        self.assertTrue(any("cause" in message for message in messages))
        self.assertTrue(any("every component" in message for message in messages))

    def test_local_unverified_report_cannot_cause_an_invalidation(self) -> None:
        documents = self.example_documents()
        report_id = "urn:trace-the-law:report:uuid:bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb"
        for path, document in documents:
            if path.name == "india-gst-invalidation-event.json":
                document["cause"] = {"correction_report_ids": [report_id]}
        problems = corpus_integrity_problems(documents)
        self.assertTrue(
            any(
                "only after the corresponding reviewed lifecycle state"
                in problem.message
                for problem in problems
            )
        )

    def test_open_license_requires_named_public_terms(self) -> None:
        source = copy.deepcopy(
            load_document(REPOSITORY_ROOT / "examples" / "india-gst-source-manifest.json")
        )
        source["rights"]["status"] = "open-license"
        for use in source["rights"]["permitted_uses"]:
            source["rights"]["permitted_uses"][use] = "permitted"
        problems = rights_assessment_problems(Path("source.json"), source)
        self.assertTrue(any("license_name" in problem.message for problem in problems))
        self.assertTrue(any("license_url" in problem.message for problem in problems))

    def test_snapshot_identity_and_order_are_checked(self) -> None:
        snapshot = copy.deepcopy(
            load_document(REPOSITORY_ROOT / "examples" / "india-gst-snapshot-before.json")
        )
        snapshot["components"].reverse()
        snapshot["schema_catalog"].append(
            copy.deepcopy(snapshot["schema_catalog"][-1])
        )
        problems = snapshot_problems(Path("snapshot.json"), snapshot)
        self.assertTrue(any("sorted" in problem.message for problem in problems))
        self.assertTrue(
            any("duplicate schema_id" in problem.message for problem in problems)
        )
        self.assertTrue(any("digest" in problem.message for problem in problems))

    def test_closed_corpus_snapshot_catalog_covers_selected_schema_closure(
        self,
    ) -> None:
        documents = self.example_documents()
        by_name = {path.name: document for path, document in documents}
        record_schema_id = (
            "https://schemas.trace-the-law.invalid/v1/record.schema.json"
        )
        snapshots = [
            by_name["india-gst-snapshot-before.json"],
            by_name["india-gst-snapshot-after.json"],
        ]
        for snapshot in snapshots:
            snapshot["schema_catalog"] = [
                contract
                for contract in snapshot["schema_catalog"]
                if contract["schema_id"] != record_schema_id
            ]

        def replace_identity(value, old: str, new: str) -> None:
            if isinstance(value, dict):
                for key, child in value.items():
                    if child == old:
                        value[key] = new
                    else:
                        replace_identity(child, old, new)
            elif isinstance(value, list):
                for index, child in enumerate(value):
                    if child == old:
                        value[index] = new
                    else:
                        replace_identity(child, old, new)

        def rehash_snapshot(snapshot: dict) -> tuple[str, str]:
            old_snapshot_id = snapshot["snapshot_id"]
            projection = copy.deepcopy(snapshot)
            projection.pop("snapshot_id")
            new_snapshot_id = (
                "urn:trace-the-law:snapshot:sha256:"
                + hashlib.sha256(_canonical_json_bytes(projection)).hexdigest()
            )
            snapshot["snapshot_id"] = new_snapshot_id
            return old_snapshot_id, new_snapshot_id

        for snapshot in snapshots:
            old_snapshot_id, new_snapshot_id = rehash_snapshot(snapshot)
            for _, document in documents:
                replace_identity(document, old_snapshot_id, new_snapshot_id)

        bundle = by_name["india-gst-evidence-bundle.json"]
        bundle_projection = copy.deepcopy(bundle)
        bundle_projection["handling"]["public_release"].pop(
            "reviewed_payload_digest"
        )
        bundle["handling"]["public_release"]["reviewed_payload_digest"][
            "value"
        ] = hashlib.sha256(_canonical_json_bytes(bundle_projection)).hexdigest()

        targeted_messages = [
            problem.message
            for path, document in documents
            for problem in validate_document(
                path, document, self.schemas, self.registry
            )
            if "snapshot ID digest" in problem.message
            or "public release digest" in problem.message
        ]
        self.assertEqual([], targeted_messages)
        snapshot_reference_messages = [
            problem.message
            for problem in corpus_integrity_problems(documents)
            if "snapshot" in problem.message
            and (
                "does not resolve" in problem.message
                or "does not name snapshot_before" in problem.message
                or "time does not match" in problem.message
            )
        ]
        self.assertEqual([], snapshot_reference_messages)

        with tempfile.TemporaryDirectory() as directory:
            selected = Path(directory)
            for path, document in documents:
                (selected / path.name).write_text(
                    json.dumps(document, ensure_ascii=False, indent=2) + "\n",
                    encoding="utf-8",
                )
            fragment_problems = validate_paths((selected,))
            closed_problems = validate_paths((selected,), closed_corpus=True)

        self.assertFalse(
            any(
                "missing contracts used by the selected document schema closure"
                in problem.message
                for problem in fragment_problems
            )
        )
        missing_contract_problems = [
            problem
            for problem in closed_problems
            if "missing contracts used by the selected document schema closure"
            in problem.message
        ]
        self.assertEqual(2, len(missing_contract_problems))
        self.assertTrue(
            all(
                record_schema_id in problem.message
                for problem in missing_contract_problems
            )
        )

    def test_closed_corpus_snapshot_catalog_rejects_extraneous_contracts(
        self,
    ) -> None:
        selected_names = {
            "india-gst-capture.json",
            "india-gst-snapshot-before.json",
        }
        documents = [
            (path, document)
            for path, document in self.example_documents()
            if path.name in selected_names
        ]
        with tempfile.TemporaryDirectory() as directory:
            selected = Path(directory)
            for path, document in documents:
                (selected / path.name).write_text(
                    json.dumps(document, ensure_ascii=False, indent=2) + "\n",
                    encoding="utf-8",
                )
            problems = validate_paths((selected,), closed_corpus=True)

        record_schema_id = (
            "https://schemas.trace-the-law.invalid/v1/record.schema.json"
        )
        self.assertTrue(
            any(
                "outside the selected document schema closure" in problem.message
                and record_schema_id in problem.message
                for problem in problems
            )
        )

    def test_snapshot_schema_closure_uses_the_custom_schema_registry(self) -> None:
        shared_schema_id = "https://custom.example/contracts/shared.schema.json"
        payload_schema_id = "https://custom.example/contracts/payload.schema.json"
        snapshot_schema_id = "https://custom.example/contracts/snapshot.schema.json"
        custom_schemas = {
            "shared.json": {
                "$schema": "https://json-schema.org/draft/2020-12/schema",
                "$id": shared_schema_id,
                "$defs": {"value": {"type": "string"}},
            },
            "payload.json": {
                "$schema": "https://json-schema.org/draft/2020-12/schema",
                "$id": payload_schema_id,
                "type": "object",
                "additionalProperties": False,
                "required": ["schema_id", "value"],
                "properties": {
                    "schema_id": {"const": payload_schema_id},
                    "value": {"$ref": "shared.schema.json#/$defs/value"},
                },
            },
            "snapshot.json": {
                "$schema": "https://json-schema.org/draft/2020-12/schema",
                "$id": snapshot_schema_id,
                "type": "object",
                "additionalProperties": False,
                "required": ["schema_id", "snapshot_id", "schema_catalog"],
                "properties": {
                    "schema_id": {"const": snapshot_schema_id},
                    "snapshot_id": {"type": "string"},
                    "schema_catalog": {
                        "type": "array",
                        "items": {"type": "object"},
                    },
                },
            },
        }
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            schema_directory = root / "custom-schemas"
            selected = root / "selected"
            schema_directory.mkdir()
            selected.mkdir()
            schema_digests: dict[str, str] = {}
            for filename, schema in custom_schemas.items():
                schema_path = schema_directory / filename
                schema_path.write_text(
                    json.dumps(schema, ensure_ascii=False, indent=2) + "\n",
                    encoding="utf-8",
                )
                schema_digests[schema["$id"]] = hashlib.sha256(
                    schema_path.read_bytes()
                ).hexdigest()

            payload = {"schema_id": payload_schema_id, "value": "selected"}
            snapshot = {
                "schema_id": snapshot_schema_id,
                "schema_catalog": [
                    {
                        "schema_id": schema_id,
                        "content_digest": {"value": schema_digests[schema_id]},
                    }
                    for schema_id in sorted(schema_digests)
                ],
            }
            snapshot["snapshot_id"] = (
                "urn:trace-the-law:snapshot:sha256:"
                + hashlib.sha256(_canonical_json_bytes(snapshot)).hexdigest()
            )
            (selected / "payload.json").write_text(
                json.dumps(payload, ensure_ascii=False, indent=2) + "\n",
                encoding="utf-8",
            )
            (selected / "snapshot.json").write_text(
                json.dumps(snapshot, ensure_ascii=False, indent=2) + "\n",
                encoding="utf-8",
            )
            problems = validate_paths(
                (selected,),
                schema_directory=schema_directory,
                closed_corpus=True,
            )

        self.assertEqual([], [problem.render() for problem in problems])

    def test_all_cross_document_snapshot_references_must_resolve(self) -> None:
        documents = self.example_documents()
        for path, document in documents:
            if path.name == "india-gst-correction-report.json":
                document["corpus_snapshot_id"] = (
                    "urn:trace-the-law:snapshot:sha256:" + "e" * 64
                )
            elif path.name == "india-gst-evidence-bundle.json":
                document["evaluation_context"]["corpus_snapshot"]["snapshot_id"] = (
                    "urn:trace-the-law:snapshot:sha256:" + "d" * 64
                )
            elif path.name == "india-gst-invalidation-event.json":
                document["snapshot_before"] = (
                    "urn:trace-the-law:snapshot:sha256:" + "c" * 64
                )
            elif path.name == "india-gst-snapshot-after.json":
                document["predecessor_snapshot_id"] = (
                    "urn:trace-the-law:snapshot:sha256:" + "b" * 64
                )

        messages = [problem.message for problem in corpus_integrity_problems(documents)]
        self.assertTrue(
            any("correction report corpus snapshot does not resolve" in m for m in messages)
        )
        self.assertTrue(
            any(
                "evidence bundle" in m and "corpus snapshot does not resolve" in m
                for m in messages
            )
        )
        self.assertTrue(
            any(
                "invalidation event" in m and "before snapshot does not resolve" in m
                for m in messages
            )
        )
        self.assertTrue(
            any("predecessor does not resolve" in m for m in messages)
        )

    def test_invalidation_transition_must_follow_the_snapshot_predecessor(self) -> None:
        documents = self.example_documents()
        snapshot_before = next(
            document["snapshot_id"]
            for path, document in documents
            if path.name == "india-gst-snapshot-before.json"
        )
        for path, document in documents:
            if path.name == "india-gst-snapshot-after.json":
                document["predecessor_snapshot_id"] = document["snapshot_id"]
            elif path.name == "india-gst-invalidation-event.json":
                document["snapshot_before"] = snapshot_before

        problems = corpus_integrity_problems(documents)
        self.assertTrue(
            any(
                "after snapshot does not name snapshot_before as its predecessor"
                in p.message
                for p in problems
            )
        )

    def test_record_metadata_partial_text_and_publication_time_are_evidence_bound(
        self,
    ) -> None:
        title_problems = self.mutated_example_problems(
            "india-gst-record.json",
            lambda document: document.__setitem__("canonical_title", "Invented title"),
        )
        self.assertTrue(
            any(
                "does not match its evidence binding's normalized value" in p.message
                for p in title_problems
            )
        )

        def alter_partial_text(document) -> None:
            document["versions"][0]["provisions"][0]["text_citations"][0][
                "quoted_text_digest"
            ]["value"] = "0" * 64

        digest_problems = self.mutated_example_problems(
            "india-gst-record.json", alter_partial_text
        )
        self.assertTrue(
            any("partial provision digest" in p.message for p in digest_problems)
        )

        def invent_publication_time(document) -> None:
            version = document["versions"][0]
            version["time_axes"]["publication"] = {
                "status": "exact",
                "value": "2017-04-12",
                "precision": "day",
                "calendar": "gregory",
                "verbatim_value": "12 April 2017",
            }
            version["publication_evidence"] = [copy.deepcopy(document["metadata_evidence"][0])]

        publication_problems = self.mutated_example_problems(
            "india-gst-record.json", invent_publication_time
        )
        self.assertTrue(
            any("temporal binding" in p.message for p in publication_problems)
        )

    def test_record_metadata_changes_require_matching_bound_values(
        self,
    ) -> None:
        record = copy.deepcopy(
            load_document(REPOSITORY_ROOT / "examples" / "india-gst-record.json")
        )
        self.assertEqual(
            [],
            validate_document(
                Path("record.json"), record, self.schemas, self.registry
            ),
        )

        def shorten_title(document) -> None:
            document["canonical_title"] = "Goods and Services Tax Act"

        title_problems = self.mutated_example_problems(
            "india-gst-record.json", shorten_title
        )
        self.assertTrue(
            any(
                problem.location == "$.metadata_bindings[0]"
                or (
                    problem.location == "$.metadata_bindings[0].normalized_value"
                    and "does not match" in problem.message
                )
                for problem in title_problems
            )
        )

        def shorten_identifier(document) -> None:
            document["identifiers"][0]["value"] = "Goods and Services Tax Act"

        identifier_problems = self.mutated_example_problems(
            "india-gst-record.json", shorten_identifier
        )
        self.assertTrue(
            any(
                problem.location == "$.metadata_bindings[1].normalized_value"
                and "does not match" in problem.message
                for problem in identifier_problems
            )
        )

        def change_designation(document) -> None:
            provision = document["versions"][0]["provisions"][0]
            provision["designation"] = "Section 99"

        designation_problems = self.mutated_example_problems(
            "india-gst-record.json", change_designation
        )
        self.assertTrue(
            any(
                problem.location
                == "$.versions[0].provisions[0].metadata_bindings[0].normalized_value"
                and "does not match" in problem.message
                for problem in designation_problems
            )
        )

    def test_record_metadata_binding_cannot_predate_selected_artifact_or_capture(
        self,
    ) -> None:
        self.assertEqual(
            [],
            corpus_integrity_problems(
                self.example_documents(include_lifecycle_templates=False)
            ),
        )
        mutations = (
            ("india-gst-source-artifact.json", "created_at"),
            ("india-gst-source-capture.json", "retrieved_at"),
        )
        for filename, time_field in mutations:
            with self.subTest(filename=filename):
                documents = self.example_documents()
                for path, document in documents:
                    if path.name != filename:
                        continue
                    if time_field == "created_at":
                        document["created_at"] = "2026-08-23T12:30:00Z"
                    else:
                        document["retrieval"]["retrieved_at"] = (
                            "2026-08-23T12:30:00Z"
                        )
                problems = corpus_integrity_problems(documents)
                chronology_locations = {
                    problem.location
                    for problem in problems
                    if problem.message
                    == "metadata binding cannot predate its selected artifact creation or capture retrieval"
                }
                self.assertIn("$.metadata_bindings[2].created_at", chronology_locations)
                self.assertIn(
                    "$.versions[0].metadata_bindings[0].created_at",
                    chronology_locations,
                )
                self.assertIn(
                    "$.versions[0].provisions[0].metadata_bindings[0].created_at",
                    chronology_locations,
                )

    def test_record_metadata_review_cannot_predate_selected_evidence(self) -> None:
        documents = self.example_documents()
        for path, document in documents:
            if path.name == "india-gst-source-artifact.json":
                document["created_at"] = "2026-08-23T14:30:00Z"
            elif path.name == "india-gst-source-capture.json":
                document["retrieval"]["retrieved_at"] = "2026-08-23T14:30:00Z"
        problems = corpus_integrity_problems(documents)
        review_locations = {
            problem.location
            for problem in problems
            if problem.message
            == "metadata normalization review cannot predate its selected artifact creation or capture retrieval"
        }
        self.assertIn(
            "$.metadata_bindings[2].normalization_review.reviewed_at",
            review_locations,
        )
        self.assertIn(
            "$.versions[0].metadata_bindings[0].normalization_review.reviewed_at",
            review_locations,
        )
        self.assertIn(
            "$.versions[0].provisions[0].metadata_bindings[0].normalization_review.reviewed_at",
            review_locations,
        )

    def test_record_version_material_metadata_is_evidence_bound(self) -> None:
        mutations = (
            ("version_kind", "corrected"),
            ("language", "fr"),
            ("publication_state", "withdrawn"),
        )
        for binding_index, (field, changed_value) in enumerate(mutations):
            with self.subTest(field=field):
                record = copy.deepcopy(
                    load_document(
                        REPOSITORY_ROOT / "examples" / "india-gst-record.json"
                    )
                )
                version = record["versions"][0]
                version[field] = changed_value
                binding = next(
                    item
                    for item in version["metadata_bindings"]
                    if item["field"] == field
                )
                binding["normalized_value"] = changed_value
                binding["source_value"] = "Goods and Services"
                self.refresh_binding_review_digest(binding)
                problems = validate_document(
                    Path("record.json"), record, self.schemas, self.registry
                )
                self.assertTrue(
                    any(
                        problem.location
                        == (
                            f"$.versions[0].metadata_bindings[{binding_index}]"
                            ".source_value"
                        )
                        and "exact field boundary" in problem.message
                        for problem in problems
                    )
                )

        record = copy.deepcopy(
            load_document(REPOSITORY_ROOT / "examples" / "india-gst-record.json")
        )
        record["versions"][0]["metadata_bindings"] = [
            binding
            for binding in record["versions"][0]["metadata_bindings"]
            if binding["field"] != "language"
        ]
        messages = [
            problem.message
            for problem in validate_document(
                Path("record.json"), record, self.schemas, self.registry
            )
        ]
        self.assertTrue(
            any("lacks evidence bindings for: language" in message for message in messages)
        )

    def test_source_exact_version_binding_cannot_postdate_record(self) -> None:
        record = copy.deepcopy(
            load_document(REPOSITORY_ROOT / "examples" / "india-gst-record.json")
        )
        version = record["versions"][0]
        exact_language_evidence = copy.deepcopy(version["metadata_evidence"][0])
        exact_language_evidence["quoted_text"] = "en"
        version["metadata_evidence"].append(exact_language_evidence)
        binding = next(
            item
            for item in version["metadata_bindings"]
            if item["field"] == "language"
        )
        binding["source_value"] = "en"
        binding["evidence_indexes"] = [1]
        binding["method"] = "source_exact"
        binding["created_at"] = "2026-08-23T14:30:00Z"
        binding.pop("normalization_review")

        problems = validate_document(
            Path("record.json"), record, self.schemas, self.registry
        )
        self.assertTrue(
            any(
                problem.location == "$.updated_at"
                and "version metadata binding" in problem.message
                for problem in problems
            )
        )

    def test_official_translation_requires_reviewed_version_issuance(self) -> None:
        documents = self.official_translation_documents()
        for path, document in documents:
            if path.name in {
                "india-gst-record.json",
                "official-translation-assertion.json",
            }:
                self.assertEqual(
                    [],
                    validate_document(path, document, self.schemas, self.registry),
                )
        self.assertEqual([], corpus_integrity_problems(documents))

        documents = self.official_translation_documents()
        for path, document in documents:
            if path.name == "india-gst-record.json":
                document["versions"][0].pop("authority_relationships")
        problems = corpus_integrity_problems(documents)
        self.assertTrue(
            any(
                "official_translation requires a verified" in problem.message
                for problem in problems
            )
        )

        documents = self.official_translation_documents()
        for path, document in documents:
            if path.name == "official-translation-assertion.json":
                document["status"] = "candidate"
        problems = corpus_integrity_problems(documents)
        self.assertTrue(
            any(
                "official_translation requires a verified" in problem.message
                for problem in problems
            )
        )

        documents = self.official_translation_documents()
        for path, document in documents:
            if path.name == "india-gst-record.json":
                version = document["versions"][0]
                document["authority_relationships"] = version.pop(
                    "authority_relationships"
                )
            elif path.name == "official-translation-assertion.json":
                record_id = next(
                    candidate["record_id"]
                    for candidate_path, candidate in documents
                    if candidate_path.name == "india-gst-record.json"
                )
                document["subject"] = {
                    "entity_type": "record",
                    "entity_id": record_id,
                }
        problems = corpus_integrity_problems(documents)
        self.assertTrue(
            any(
                "official_translation requires a verified" in problem.message
                for problem in problems
            )
        )

        documents = self.official_translation_documents()
        derived_artifact_id = next(
            document["artifact_id"]
            for path, document in documents
            if path.name == "india-gst-heading-markdown-artifact.json"
        )
        for path, document in documents:
            if path.name != "india-gst-record.json":
                continue
            version = document["versions"][0]
            version["artifact_ids"] = [derived_artifact_id]
            version["metadata_evidence"][0]["artifact_id"] = derived_artifact_id
            version["metadata_evidence"][0].pop("capture_id", None)
            for binding in version["metadata_bindings"]:
                binding["created_at"] = "2026-08-23T13:30:00Z"
                self.refresh_binding_review_digest(binding)
        problems = corpus_integrity_problems(documents)
        self.assertTrue(
            any(
                "not only project derivations" in problem.message
                for problem in problems
            )
        )

    def test_record_artifacts_require_provenance_and_complete_text_digest(self) -> None:
        documents = self.example_documents()
        fake_digest = "a" * 64
        fake_id = "urn:trace-the-law:artifact:sha256:" + fake_digest
        fake_artifact = copy.deepcopy(
            load_document(
                REPOSITORY_ROOT
                / "examples"
                / "india-gst-heading-settings-artifact.json"
            )
        )
        fake_artifact["artifact_id"] = fake_id
        fake_artifact["content_digest"]["value"] = fake_digest
        documents.append((Path("fake-artifact.json"), fake_artifact))
        for path, document in documents:
            if path.name == "india-gst-record.json":
                document["versions"][0]["artifact_ids"].append(fake_id)

        messages = [p.message for p in corpus_integrity_problems(documents)]
        self.assertTrue(any("no capture or derivation provenance" in m for m in messages))

        documents = self.example_documents()
        for path, document in documents:
            if path.name != "india-gst-record.json":
                continue
            provision = document["versions"][0]["provisions"][0]
            provision["text_completeness"] = "complete"
            provision["content_artifact_id"] = document["versions"][0]["artifact_ids"][0]
            provision["digest_scope"] = {
                "covered_content": "complete_provision_text",
                "canonicalization": "utf8_exact",
            }
        messages = [p.message for p in corpus_integrity_problems(documents)]
        self.assertTrue(any("does not match its content artifact" in m for m in messages))

    def test_complete_provision_attestation_review_uses_the_exact_instant(self) -> None:
        documents = self.example_documents()
        by_name = {path.name: document for path, document in documents}
        record = by_name["india-gst-record.json"]
        version = record["versions"][0]
        provision = version["provisions"][0]
        artifact = by_name["india-gst-source-artifact.json"]
        provision.update(
            {
                "text_completeness": "complete",
                "content_artifact_id": artifact["artifact_id"],
                "content_digest": copy.deepcopy(artifact["content_digest"]),
                "digest_scope": {
                    "covered_content": "complete_provision_text",
                    "canonicalization": "utf8_exact",
                },
            }
        )
        attestation = {
            "record_id": record["record_id"],
            "version_id": version["version_id"],
            "provision_id": provision["provision_id"],
            "provision_version_id": provision["provision_version_id"],
            "scope": "complete_provision_text",
            "content_digest": copy.deepcopy(artifact["content_digest"]),
            "producer": {
                "producer_id": "urn:trace-the-law:producer:importer:scope-check",
                "producer_type": "importer",
                "name": "Scope check",
            },
            "created_at": "2026-08-23T13:59:59Z",
            "review": {
                "reviewed_at": "2026-08-23T14:00:00.900Z",
                "reviewer": {
                    "producer_id": (
                        "urn:trace-the-law:producer:human:scope-reviewer"
                    ),
                    "producer_type": "human",
                    "name": "Scope reviewer",
                },
            },
        }

        def bind_attestation_review() -> None:
            projection = copy.deepcopy(attestation)
            projection["review"].pop("reviewed_attestation_digest", None)
            attestation["review"]["reviewed_attestation_digest"] = {
                "algorithm": "sha256",
                "value": hashlib.sha256(
                    _canonical_json_bytes(projection)
                ).hexdigest(),
            }

        bind_attestation_review()
        artifact["legal_scope_attestations"] = [attestation]
        messages = [problem.message for problem in corpus_integrity_problems(documents)]
        self.assertIn(
            "complete provision text requires an exact independently reviewed artifact-scope attestation",
            messages,
        )

        attestation["review"]["reviewed_at"] = "2026-08-23T14:00:00Z"
        bind_attestation_review()
        messages = [problem.message for problem in corpus_integrity_problems(documents)]
        self.assertNotIn(
            "complete provision text requires an exact independently reviewed artifact-scope attestation",
            messages,
        )

    def test_provenance_chronology_and_derivation_roles_are_checked(self) -> None:
        documents = self.example_documents()
        for path, document in documents:
            if path.name == "india-gst-source-capture.json":
                document["created_at"] = "2000-01-01T00:00:00Z"
        messages = [p.message for p in corpus_integrity_problems(documents)]
        self.assertTrue(any("capture creation cannot predate retrieval" in m for m in messages))

        def duplicate_role(document) -> None:
            document["input_artifacts"].append(
                {
                    "role": document["input_artifacts"][0]["role"],
                    "artifact_id": document["settings_artifact_id"],
                }
            )

        role_problems = self.mutated_example_problems(
            "india-gst-heading-derivation.json", duplicate_role
        )
        self.assertTrue(any("duplicates" in p.message for p in role_problems))

    def test_review_cannot_predate_the_cited_artifact(self) -> None:
        documents = self.example_documents()
        for path, document in documents:
            if path.name != "india-gst-relationship-assertion.json":
                continue
            document["status"] = "verified"
            document["producer"]["producer_id"] = (
                "urn:trace-the-law:producer:importer:example"
            )
            document["created_at"] = "1999-01-01T00:00:00Z"
            document["reviewed_at"] = "2000-01-01T00:00:00Z"
            document["reviewer"] = {
                "producer_id": "urn:trace-the-law:producer:human:reviewer",
                "producer_type": "human",
                "name": "Example reviewer",
            }
        messages = [p.message for p in corpus_integrity_problems(documents)]
        self.assertTrue(any("review cannot predate its cited evidence" in m for m in messages))

    def test_version_and_provision_parent_cycles_are_rejected(self) -> None:
        documents = self.example_documents()
        record = next(
            document
            for path, document in documents
            if path.name == "india-gst-record.json"
        )
        first_version = record["versions"][0]
        second_version = copy.deepcopy(first_version)
        second_version_id = (
            "urn:trace-the-law:version:uuid:56565656-5656-4565-8565-565656565656"
        )
        second_provision_version_id = (
            "urn:trace-the-law:provision-version:uuid:78787878-7878-4787-8787-787878787878"
        )
        second_version["version_id"] = second_version_id
        second_version["provisions"][0][
            "provision_version_id"
        ] = second_provision_version_id

        first_assertion_id = (
            "urn:trace-the-law:assertion:uuid:81818181-8181-4181-8181-818181818181"
        )
        second_assertion_id = (
            "urn:trace-the-law:assertion:uuid:82828282-8282-4282-8282-828282828282"
        )
        first_version["supersedes_version_ids"] = [second_version_id]
        first_version["derived_from_assertion_ids"] = [first_assertion_id]
        second_version["supersedes_version_ids"] = [first_version["version_id"]]
        second_version["derived_from_assertion_ids"] = [second_assertion_id]
        record["versions"].append(second_version)

        assertion_template = copy.deepcopy(
            load_document(
                REPOSITORY_ROOT / "examples" / "india-gst-relationship-assertion.json"
            )
        )
        for assertion_id, current, predecessor in (
            (first_assertion_id, first_version["version_id"], second_version_id),
            (second_assertion_id, second_version_id, first_version["version_id"]),
        ):
            assertion = copy.deepcopy(assertion_template)
            assertion["assertion_id"] = assertion_id
            assertion["subject"] = {"entity_type": "version", "entity_id": current}
            assertion["predicate"] = "supersedes"
            assertion["object"] = {
                "entity_type": "version",
                "entity_id": predecessor,
            }
            documents.append((Path(f"{assertion_id[-4:]}.json"), assertion))

        messages = [p.message for p in corpus_integrity_problems(documents)]
        self.assertTrue(any("supersession chain contains a cycle" in m for m in messages))

        documents = self.example_documents()
        record = next(
            document
            for path, document in documents
            if path.name == "india-gst-record.json"
        )
        first = record["versions"][0]["provisions"][0]
        second = copy.deepcopy(first)
        second["provision_id"] = (
            "urn:trace-the-law:provision:uuid:67676767-6767-4676-8676-676767676767"
        )
        second["provision_version_id"] = (
            "urn:trace-the-law:provision-version:uuid:79797979-7979-4797-8797-797979797979"
        )
        first["parent_provision_id"] = second["provision_id"]
        second["parent_provision_id"] = first["provision_id"]
        record["versions"][0]["provisions"].append(second)
        messages = [p.message for p in corpus_integrity_problems(documents)]
        self.assertTrue(any("parent hierarchy contains a cycle" in m for m in messages))

    def test_verified_correction_status_must_match_the_finding(self) -> None:
        report = copy.deepcopy(
            load_document(REPOSITORY_ROOT / "examples" / "india-gst-correction-report.json")
        )
        report["verification"]["status"] = "VERIFIED_GAP"
        messages = [
            p.message for p in correction_state_problems(Path("report.json"), report)
        ]
        self.assertTrue(any("exactly match finding_status" in m for m in messages))

    def test_google_and_firebase_signed_url_parameters_are_rejected(self) -> None:
        capture = copy.deepcopy(
            load_document(REPOSITORY_ROOT / "examples" / "india-gst-source-capture.json")
        )
        capture["retrieval"]["source_url"] = (
            "https://example.gov/document?X-Goog-Expires=60&downloadToken=secret&key=secret"
        )
        messages = [p.message for p in public_url_problems(Path("capture.json"), capture)]
        for key in ("x-goog-expires", "downloadtoken", "key"):
            self.assertTrue(any(key in message for message in messages), key)

    def test_direct_identifier_arrays_cannot_dangle(self) -> None:
        documents = self.example_documents()
        for path, document in documents:
            if path.name == "india-gst-coverage-ledger.json":
                document["enumeration_runs"][0]["index_artifact_ids"] = [
                    "urn:trace-the-law:artifact:sha256:" + "f" * 64
                ]
        messages = [p.message for p in corpus_integrity_problems(documents)]
        self.assertTrue(any("artifact reference does not resolve" in m for m in messages))

    def test_bundle_dependencies_include_snapshot_source_and_subject_chain(self) -> None:
        documents = self.example_documents()
        for path, document in documents:
            if path.name == "india-gst-evidence-bundle.json":
                document["dependencies"] = [
                    dependency
                    for dependency in document["dependencies"]
                    if dependency["entity_type"] not in {"snapshot", "source", "version"}
                ]
        messages = [p.message for p in corpus_integrity_problems(documents)]
        for entity_type in ("snapshot", "source", "version"):
            self.assertTrue(
                any(f"explicitly depend on {entity_type}" in m for m in messages),
                entity_type,
            )

    def test_supported_bundle_cannot_use_a_candidate_assertion(self) -> None:
        documents = self.example_documents()
        candidate_id = (
            "urn:trace-the-law:assertion:uuid:88888888-8888-4888-8888-888888888888"
        )
        for path, document in documents:
            if path.name != "india-gst-evidence-bundle.json":
                continue
            document["status"] = "SUPPORTED"
            document["claims"][0]["assertion_ids"] = [candidate_id]
            document["coverage"][0]["status"] = "covered_for_declared_scope"
            document["coverage"][0]["gap_ids"] = []
            document["conflicts"] = []
            document["unresolved_items"] = []
            document["verification_tasks"] = []
            document["dependencies"].append(
                {"entity_type": "assertion", "entity_id": candidate_id}
            )
        messages = [p.message for p in corpus_integrity_problems(documents)]
        self.assertTrue(
            any("candidate or retracted supporting assertion" in m for m in messages)
        )

    def test_bundle_rejects_unused_citations(self) -> None:
        bundle = copy.deepcopy(
            load_document(REPOSITORY_ROOT / "examples" / "india-gst-evidence-bundle.json")
        )
        bundle["citations"].append(copy.deepcopy(bundle["citations"][0]))
        bundle["citations"][1]["locator"]["value"] = "unused"
        messages = [
            p.message for p in evidence_bundle_reference_problems(Path("bundle.json"), bundle)
        ]
        self.assertTrue(any("unused by every claim" in m for m in messages))

    def test_record_kind_binding_cannot_silently_change_meaning(self) -> None:
        record = copy.deepcopy(
            load_document(REPOSITORY_ROOT / "examples" / "india-gst-record.json")
        )
        record["record_kind"] = "judgment"
        binding = next(
            item for item in record["metadata_bindings"] if item["field"] == "record_kind"
        )
        binding["normalized_value"] = "judgment"
        problems = validate_document(
            Path("record.json"), record, self.schemas, self.registry
        )
        self.assertTrue(
            any("review digest" in problem.message for problem in problems)
        )

    def test_provision_designation_binding_cannot_silently_change_meaning(self) -> None:
        record = copy.deepcopy(
            load_document(REPOSITORY_ROOT / "examples" / "india-gst-record.json")
        )
        provision = record["versions"][0]["provisions"][0]
        provision["designation"] = "Section 99"
        binding = next(
            item
            for item in provision["metadata_bindings"]
            if item["field"] == "designation"
        )
        binding["normalized_value"] = "Section 99"
        messages = [
            problem.message
            for problem in validate_document(
                Path("record.json"), record, self.schemas, self.registry
            )
        ]
        self.assertTrue(any("provision metadata review digest" in m for m in messages))

    def test_publication_normalization_is_bound_to_source_and_normalized_value(
        self,
    ) -> None:
        record = copy.deepcopy(
            load_document(REPOSITORY_ROOT / "examples" / "india-gst-record.json")
        )
        version = record["versions"][0]
        version["time_axes"]["publication"] = {
            "status": "exact",
            "value": "2017-04-12",
            "precision": "day",
            "calendar": "gregory",
            "verbatim_value": "12 April 2017",
        }
        citation = copy.deepcopy(record["metadata_evidence"][0])
        citation["quoted_text"] = "Published on 12 April 2017."
        self.refresh_evidence_content_verification(citation)
        citation["temporal_value_binding"] = {
            "source_value": "12 April 2017",
            "normalized_value": "2017-04-12",
            "method": "human_reviewed",
            "producer": {
                "producer_id": "urn:trace-the-law:producer:importer:date-normalizer",
                "producer_type": "importer",
                "name": "Example date normalizer",
            },
            "created_at": "2026-08-23T13:00:00Z",
            "reviewed_at": "2026-08-23T14:00:00Z",
            "reviewer": {
                "producer_id": "urn:trace-the-law:producer:human:date-reviewer",
                "producer_type": "human",
                "name": "Example date reviewer",
            },
        }
        version["publication_evidence"] = [citation]
        self.assertEqual(
            [],
            validate_document(Path("record.json"), record, self.schemas, self.registry),
        )

        version["time_axes"]["publication"]["value"] = "1999-01-01"
        messages = [
            problem.message
            for problem in validate_document(
                Path("record.json"), record, self.schemas, self.registry
            )
        ]
        self.assertTrue(any("normalized_value" in message for message in messages))

    def test_quoted_evidence_requires_independent_content_verification(self) -> None:
        record = copy.deepcopy(
            load_document(REPOSITORY_ROOT / "examples" / "india-gst-record.json")
        )
        citation = record["versions"][0]["publication_evidence"][0]
        citation.pop("content_verification")
        messages = [
            problem.message
            for problem in validate_document(
                Path("record.json"), record, self.schemas, self.registry
            )
        ]
        self.assertTrue(
            any("content_verification" in message and "required" in message for message in messages)
        )

        record = copy.deepcopy(
            load_document(REPOSITORY_ROOT / "examples" / "india-gst-record.json")
        )
        citation = record["versions"][0]["publication_evidence"][0]
        citation["content_verification"]["verifier"] = copy.deepcopy(
            citation["temporal_value_binding"]["producer"]
        )
        messages = [
            problem.message
            for problem in validate_document(
                Path("record.json"), record, self.schemas, self.registry
            )
        ]
        self.assertTrue(
            any("independent of temporal normalization" in message for message in messages)
        )

    def test_content_verification_digest_and_chronology_are_checked(self) -> None:
        record = copy.deepcopy(
            load_document(REPOSITORY_ROOT / "examples" / "india-gst-record.json")
        )
        citation = record["versions"][0]["publication_evidence"][0]
        citation["quoted_text"] = "1900-01-01"
        citation["quoted_text_digest"] = {
            "algorithm": "sha256",
            "value": hashlib.sha256(b"1900-01-01").hexdigest(),
        }
        messages = [
            problem.message
            for problem in validate_document(
                Path("record.json"), record, self.schemas, self.registry
            )
        ]
        self.assertTrue(
            any("content verification digest" in message for message in messages)
        )

        documents = self.example_documents()
        record = next(
            document
            for path, document in documents
            if path.name == "india-gst-record.json"
        )
        record["versions"][0]["publication_evidence"][0][
            "content_verification"
        ]["verified_at"] = "2026-08-23T12:20:05Z"
        messages = [
            problem.message for problem in corpus_integrity_problems(documents)
        ]
        self.assertTrue(
            any("cannot predate its cited bytes or capture" in message for message in messages)
        )

        record = copy.deepcopy(
            load_document(REPOSITORY_ROOT / "examples" / "india-gst-record.json")
        )
        citation = record["versions"][0]["provisions"][0]["text_citations"][0]
        citation["content_verification"]["verified_at"] = (
            "2026-08-23T14:00:20Z"
        )
        self.refresh_evidence_content_verification(citation)
        messages = [
            problem.message
            for problem in validate_document(
                Path("record.json"), record, self.schemas, self.registry
            )
        ]
        self.assertTrue(
            any("enclosing document updated_at" in message for message in messages)
        )

    def test_bundle_content_verification_is_snapshot_and_generation_bound(self) -> None:
        documents = self.example_documents()
        bundle = next(
            document
            for path, document in documents
            if path.name == "india-gst-evidence-bundle.json"
        )
        record = next(
            document
            for path, document in documents
            if path.name == "india-gst-record.json"
        )
        bundle["citations"][0] = copy.deepcopy(
            record["versions"][0]["publication_evidence"][0]
        )
        citation = bundle["citations"][0]
        citation["content_verification"]["verified_at"] = (
            "2026-08-23T14:00:45Z"
        )
        self.refresh_evidence_content_verification(citation)
        messages = [
            problem.message for problem in corpus_integrity_problems(documents)
        ]
        self.assertTrue(
            any("unavailable at the selected corpus snapshot" in message for message in messages)
        )

        citation["content_verification"]["verified_at"] = (
            "2026-08-23T14:02:00Z"
        )
        self.refresh_evidence_content_verification(citation)
        messages = [
            problem.message for problem in corpus_integrity_problems(documents)
        ]
        self.assertTrue(
            any("cannot postdate bundle generation" in message for message in messages)
        )

        snapshot_instant = _parse_datetime("2026-08-23T14:00:30Z")
        self.assertIsNotNone(snapshot_instant)
        availability_violations = _dependency_availability_violations(
            "capture",
            {
                "created_at": "2026-08-23T14:00:00Z",
                "retrieval": {"retrieved_at": "2026-08-23T14:00:00Z"},
                "acquisition": {
                    "discovery_evidence": {
                        "content_verification": {
                            "verified_at": "2026-08-23T14:00:45Z"
                        }
                    }
                },
            },
            snapshot_instant,
            {
                "status": "exact",
                "value": "2026-08-23T14:00:30Z",
                "precision": "second",
                "calendar": "gregory",
            },
        )
        self.assertIn(
            "$.acquisition.discovery_evidence.content_verification.verified_at",
            availability_violations,
        )

    def test_public_bundle_pins_post_snapshot_delivery_state(self) -> None:
        documents = self.example_documents()
        by_name = {path.name: document for path, document in documents}
        capture = by_name["india-gst-source-capture.json"]
        bundle = by_name["india-gst-evidence-bundle.json"]
        capture["publication_clearance"]["reviewed_at"] = (
            "2026-08-23T14:00:45Z"
        )
        self.refresh_publication_clearance_digest(
            capture["publication_clearance"]
        )

        messages = [
            problem.message for problem in corpus_integrity_problems(documents)
        ]
        self.assertTrue(
            any("exact resolved publication-clearance review" in message for message in messages)
        )

        bundle["handling"]["public_release"]["delivery_bases"][0][
            "publication_clearance_digest"
        ] = copy.deepcopy(
            capture["publication_clearance"]["reviewed_clearance_digest"]
        )
        messages = [
            problem.message for problem in corpus_integrity_problems(documents)
        ]
        self.assertFalse(
            any("exact resolved publication-clearance review" in message for message in messages)
        )

    def test_public_bundle_pins_every_selected_delivery_dependency(self) -> None:
        documents = self.example_documents()
        by_name = {path.name: document for path, document in documents}
        bundle = by_name["india-gst-evidence-bundle.json"]
        record = by_name["india-gst-record.json"]
        derivation = by_name["india-gst-heading-derivation.json"]
        output_artifact = by_name["india-gst-heading-markdown-artifact.json"]
        settings_artifact = by_name["india-gst-heading-settings-artifact.json"]

        record["versions"][0]["artifact_ids"].append(
            output_artifact["artifact_id"]
        )
        for entity_type, entity_id in (
            ("artifact", output_artifact["artifact_id"]),
            ("artifact", settings_artifact["artifact_id"]),
            ("derivation", derivation["derivation_id"]),
        ):
            bundle["dependencies"].append(
                {"entity_type": entity_type, "entity_id": entity_id}
            )

        messages = [
            problem.message for problem in corpus_integrity_problems(documents)
        ]
        self.assertTrue(
            any(
                "valid independent publication clearance for derivation" in message
                for message in messages
            )
        )
        self.assertTrue(
            any(
                "pin the publication-clearance review for derivation" in message
                for message in messages
            )
        )

        settings_artifact["availability"] = "quarantined"
        messages = [
            problem.message for problem in corpus_integrity_problems(documents)
        ]
        self.assertTrue(
            any(
                "publication route traverses quarantined artifact" in message
                and settings_artifact["artifact_id"] in message
                for message in messages
            )
        )

        source_capture = by_name["india-gst-source-capture.json"]
        nested_capture = copy.deepcopy(source_capture)
        nested_capture["capture_id"] = (
            "urn:trace-the-law:capture:uuid:"
            "23232323-2323-4232-8232-232323232323"
        )
        nested_capture["publication_clearance"] = {
            "status": "not_reviewed",
            "checks": {
                "personal_data": "unknown",
                "sealing_or_reporting_restrictions": "unknown",
                "official_redactions_preserved": "unknown",
                "sensitive_material": "unknown",
            },
            "review_state": "unreviewed",
        }
        documents.append((Path("nested-capture.json"), nested_capture))
        bundle["dependencies"].append(
            {
                "entity_type": "capture",
                "entity_id": nested_capture["capture_id"],
            }
        )
        messages = [
            problem.message for problem in corpus_integrity_problems(documents)
        ]
        self.assertTrue(
            any(
                "valid independent publication clearance for capture" in message
                and nested_capture["capture_id"] in message
                for message in messages
            )
        )
        self.assertTrue(
            any(
                "pin the publication-clearance review for capture" in message
                and nested_capture["capture_id"] in message
                for message in messages
            )
        )

        derivation["publication_clearance"] = self.cleared_derivation_publication(
            derivation
        )
        messages = [
            problem.message for problem in corpus_integrity_problems(documents)
        ]
        self.assertFalse(
            any(
                "valid independent publication clearance for derivation" in message
                for message in messages
            )
        )
        self.assertTrue(
            any(
                "pin the publication-clearance review for derivation" in message
                for message in messages
            )
        )

    def test_public_release_requires_delivery_bases(self) -> None:
        bundle = copy.deepcopy(
            load_document(
                REPOSITORY_ROOT / "examples" / "india-gst-evidence-bundle.json"
            )
        )
        bundle["handling"]["public_release"].pop("delivery_bases")
        messages = [
            problem.message
            for problem in validate_document(
                Path("bundle.json"), bundle, self.schemas, self.registry
            )
        ]
        self.assertTrue(
            any("delivery_bases" in message and "required" in message for message in messages)
        )

    def test_unrelated_candidate_assertion_cannot_establish_legal_time(self) -> None:
        documents = self.example_documents()
        candidate_id = (
            "urn:trace-the-law:assertion:uuid:88888888-8888-4888-8888-888888888888"
        )
        for path, document in documents:
            if path.name == "india-gst-record.json":
                document["versions"][0]["time_axes"]["effectiveness"] = {
                    "status": "open_ended",
                    "start": {
                        "status": "exact",
                        "value": "2017-07-01",
                        "precision": "day",
                        "calendar": "gregory",
                    },
                    "basis_assertion_ids": [candidate_id],
                }
        messages = [problem.message for problem in corpus_integrity_problems(documents)]
        self.assertTrue(any("reviewed verified or superseded" in m for m in messages))
        self.assertTrue(any("cannot establish effectiveness" in m for m in messages))
        self.assertTrue(any("scope does not cover the record or provision" in m for m in messages))

    def test_long_acyclic_provenance_does_not_recurse_or_false_fail(self) -> None:
        documents = self.example_documents()
        artifact_template = copy.deepcopy(
            load_document(
                REPOSITORY_ROOT / "examples" / "india-gst-heading-markdown-artifact.json"
            )
        )
        derivation_template = copy.deepcopy(
            load_document(
                REPOSITORY_ROOT / "examples" / "india-gst-heading-derivation.json"
            )
        )
        previous_artifact_id = artifact_template["artifact_id"]
        for index in range(1050):
            digest = hashlib.sha256(f"long-chain-{index}".encode()).hexdigest()
            artifact_id = "urn:trace-the-law:artifact:sha256:" + digest
            artifact = copy.deepcopy(artifact_template)
            artifact["artifact_id"] = artifact_id
            artifact["content_digest"]["value"] = digest
            artifact["storage_locations"][0]["uri"] = (
                "urn:trace-the-law:test-object:sha256:" + digest
            )
            derivation = copy.deepcopy(derivation_template)
            derivation["derivation_id"] = (
                "urn:trace-the-law:derivation:uuid:"
                + str(uuid.UUID(int=index + 10000, version=4))
            )
            derivation["output_artifact_id"] = artifact_id
            derivation["input_artifacts"][0]["artifact_id"] = previous_artifact_id
            documents.append((Path(f"chain-artifact-{index}.json"), artifact))
            documents.append((Path(f"chain-derivation-{index}.json"), derivation))
            previous_artifact_id = artifact_id

        messages = [problem.message for problem in corpus_integrity_problems(documents)]
        self.assertFalse(any("dependency cycle" in message for message in messages))
        self.assertFalse(
            any("rights-basis captures do not cover" in message for message in messages)
        )

    def test_target_provision_ids_must_resolve(self) -> None:
        documents = self.example_documents()
        fake_provision_id = (
            "urn:trace-the-law:provision:uuid:ffffffff-ffff-4fff-8fff-ffffffffffff"
        )
        for path, document in documents:
            if path.name == "india-gst-relationship-assertion.json":
                document["scope"]["target_provision_ids"] = [fake_provision_id]
        messages = [problem.message for problem in corpus_integrity_problems(documents)]
        self.assertTrue(any("provision reference does not resolve" in m for m in messages))

    def test_covered_scope_requires_a_defined_date_envelope(self) -> None:
        coverage = copy.deepcopy(
            load_document(REPOSITORY_ROOT / "examples" / "india-gst-coverage-ledger.json")
        )
        coverage["status"] = "covered_for_declared_scope"
        coverage["declared_scope"]["date_interval"] = {"status": "unknown"}
        messages = [
            problem.message
            for problem in coverage_ledger_problems(Path("coverage.json"), coverage)
        ]
        self.assertTrue(any("defined known or open-ended" in m for m in messages))

    def test_coverage_cannot_supersede_a_future_ledger(self) -> None:
        documents = self.example_documents()
        current = next(
            document
            for path, document in documents
            if path.name == "india-gst-coverage-ledger.json"
        )
        predecessor = copy.deepcopy(current)
        predecessor_id = (
            "urn:trace-the-law:coverage:uuid:98989898-9898-4989-8989-989898989898"
        )
        predecessor["coverage_id"] = predecessor_id
        predecessor["generated_at"] = "2030-08-23T12:20:06Z"
        predecessor["fresh_until"] = "2030-09-23T12:20:06Z"
        predecessor.pop("supersedes_coverage_id", None)
        current["supersedes_coverage_id"] = predecessor_id
        documents.append((Path("future-coverage.json"), predecessor))
        messages = [problem.message for problem in corpus_integrity_problems(documents)]
        self.assertTrue(any("generated after the ledger it supersedes" in m for m in messages))

    def test_fragment_mode_does_not_require_unselected_global_documents(self) -> None:
        capture_path = REPOSITORY_ROOT / "examples" / "india-gst-source-capture.json"
        self.assertEqual([], validate_paths((capture_path,)))
        closed_messages = [
            problem.message
            for problem in validate_paths((capture_path,), closed_corpus=True)
        ]
        self.assertTrue(any("unresolved artifact" in m for m in closed_messages))
        self.assertTrue(any("source manifest" in m for m in closed_messages))

    def test_public_bundle_release_is_bound_to_exact_reviewed_payload(self) -> None:
        bundle = copy.deepcopy(
            load_document(REPOSITORY_ROOT / "examples" / "india-gst-evidence-bundle.json")
        )
        self.assertEqual(
            [], evidence_bundle_handling_problems(Path("bundle.json"), bundle)
        )
        bundle["claims"][0]["claim_text"] += " Changed after review."
        messages = [
            problem.message
            for problem in validate_document(
                Path("bundle.json"), bundle, self.schemas, self.registry
            )
        ]
        self.assertTrue(any("exact bundle payload" in message for message in messages))

    def test_public_bundle_release_digest_binds_the_reviewer(self) -> None:
        bundle = copy.deepcopy(
            load_document(REPOSITORY_ROOT / "examples" / "india-gst-evidence-bundle.json")
        )
        self.assertEqual(
            [], evidence_bundle_handling_problems(Path("bundle.json"), bundle)
        )
        bundle["handling"]["public_release"]["publication_clearance"]["reviewer"][
            "name"
        ] = "Substituted reviewer"
        messages = [
            problem.message
            for problem in evidence_bundle_handling_problems(Path("bundle.json"), bundle)
        ]
        self.assertTrue(any("exact bundle payload" in message for message in messages))

    def test_public_bibliographic_label_cannot_hide_free_text(self) -> None:
        documents = self.example_documents()
        for path, document in documents:
            if path.name != "india-gst-evidence-bundle.json":
                continue
            fact = document["claims"][0]["bibliographic_facts"][0]
            fact["value"] = "A copied passage falsely labelled as metadata"
            document["claims"][0]["claim_text"] = (
                "designation=A copied passage falsely labelled as metadata"
            )
        messages = [problem.message for problem in corpus_integrity_problems(documents)]
        self.assertTrue(any("not exact whitelisted metadata" in message for message in messages))

    def test_sensitive_value_must_appear_in_one_cited_quote(self) -> None:
        bundle = copy.deepcopy(
            load_document(REPOSITORY_ROOT / "examples" / "india-gst-evidence-bundle.json")
        )
        bundle["claims"][0]["claim_text"] = "Contact person@example.com"
        bundle["claims"][0]["citation_indexes"] = [0, 1]
        bundle["citations"][0]["quoted_text"] = "person@"
        second = copy.deepcopy(bundle["citations"][0])
        second["quoted_text"] = "example.com"
        bundle["citations"].append(second)
        messages = [
            problem.message
            for problem in evidence_bundle_privacy_problems(Path("bundle.json"), bundle)
        ]
        self.assertTrue(any("uncited email address" in message for message in messages))

    def test_public_bundle_rejects_an_orphan_artifact_route(self) -> None:
        documents = self.example_documents()
        orphan = copy.deepcopy(
            load_document(
                REPOSITORY_ROOT / "examples" / "india-gst-heading-markdown-artifact.json"
            )
        )
        digest = hashlib.sha256(b"orphan-public-citation").hexdigest()
        orphan["artifact_id"] = "urn:trace-the-law:artifact:sha256:" + digest
        orphan["content_digest"]["value"] = digest
        orphan["storage_locations"][0]["uri"] = (
            "urn:trace-the-law:test-object:sha256:" + digest
        )
        for path, document in documents:
            if path.name == "india-gst-evidence-bundle.json":
                document["citations"][0]["artifact_id"] = orphan["artifact_id"]
                document["citations"][0].pop("capture_id", None)
                document["dependencies"].append(
                    {"entity_type": "artifact", "entity_id": orphan["artifact_id"]}
                )
        documents.append((Path("orphan-artifact.json"), orphan))
        messages = [problem.message for problem in corpus_integrity_problems(documents)]
        self.assertTrue(any("explicit capture or selected derivation route" in m for m in messages))

    def test_public_bundle_requires_every_nested_derivation_dependency(self) -> None:
        messages = [
            problem.message
            for problem in corpus_integrity_problems(
                self.nested_public_bundle_documents(declare_inner_derivation=False)
            )
        ]
        self.assertTrue(
            any("rights bases do not cover every cited input" in message for message in messages)
        )

    def test_public_bundle_requires_clearance_on_every_derivative_hop(self) -> None:
        messages = [
            problem.message
            for problem in corpus_integrity_problems(
                self.nested_public_bundle_documents(declare_inner_derivation=True)
            )
        ]
        self.assertTrue(
            any(
                "lacks independent output privacy and publication clearance" in message
                and "21212121-2121-4121-8121-212121212121" in message
                for message in messages
            )
        )

    def test_publication_route_rejects_a_removed_source_hidden_by_derivation(
        self,
    ) -> None:
        documents = self.example_documents()
        by_name = {path.name: document for path, document in documents}
        source_artifact = by_name["india-gst-source-artifact.json"]
        output_artifact = by_name["india-gst-heading-markdown-artifact.json"]
        capture = by_name["india-gst-source-capture.json"]
        derivation = by_name["india-gst-heading-derivation.json"]
        bundle = by_name["india-gst-evidence-bundle.json"]

        source_artifact["availability"] = "removed_with_tombstone"
        self.make_rights_publishable(capture)
        derivation["publication_clearance"] = self.cleared_derivation_publication(
            derivation
        )
        bundle["citations"][0] = {
            "artifact_id": output_artifact["artifact_id"],
            "locator": {"locator_type": "line_range", "value": "1"},
            "quoted_text": "Section 1",
        }
        bundle["claims"][0].update(
            {
                "content_use": "source_excerpt",
                "claim_text": "Section 1",
            }
        )
        bundle["claims"][0].pop("bibliographic_facts", None)
        for entity_type, entity_id in (
            ("artifact", output_artifact["artifact_id"]),
            ("artifact", derivation["settings_artifact_id"]),
            ("derivation", derivation["derivation_id"]),
        ):
            bundle["dependencies"].append(
                {"entity_type": entity_type, "entity_id": entity_id}
            )

        messages = [problem.message for problem in corpus_integrity_problems(documents)]
        self.assertTrue(
            any("publication route traverses removed_with_tombstone" in message for message in messages)
        )

        output_artifact["availability"] = "public_mirror"
        output_artifact["storage_locations"] = [
            {
                "role": "primary",
                "uri": "https://mirror.example.org/heading.md",
                "access": "public",
            }
        ]
        output_artifact["publication_basis"] = [
            {"basis_type": "derivation", "basis_id": derivation["derivation_id"]}
        ]
        publication_messages = [
            problem.message for problem in corpus_publication_problems(documents)
        ]
        self.assertTrue(
            any(
                "publication route traverses removed_with_tombstone" in message
                for message in publication_messages
            )
        )

    def test_public_summary_cannot_hide_known_source_text(self) -> None:
        documents = self.example_documents()
        by_name = {path.name: document for path, document in documents}
        bundle = by_name["india-gst-evidence-bundle.json"]
        claim = bundle["claims"][0]
        source_text = "1. Short title, extent and commencement."
        bundle["citations"][0]["quoted_text"] = source_text
        claim.update(
            {
                "content_use": "summary",
                "claim_text": source_text,
            }
        )
        claim.pop("bibliographic_facts", None)

        direct_messages = [
            problem.message
            for problem in validate_document(
                Path("bundle.json"), bundle, self.schemas, self.registry
            )
        ]
        self.assertTrue(
            any("cannot be classified DIRECT" in message for message in direct_messages)
        )

        claim["classification"] = "DERIVED"
        claim["assertion_ids"] = [
            "urn:trace-the-law:assertion:uuid:13131313-1313-4131-8131-131313131313"
        ]
        corpus_messages = [
            problem.message for problem in corpus_integrity_problems(documents)
        ]
        self.assertTrue(
            any("reproduces known source text verbatim" in message for message in corpus_messages)
        )

        claim["claim_text"] = "\u200b".join(
            source_text[index : index + 8]
            for index in range(0, len(source_text), 8)
        )
        invisible_character_messages = [
            problem.message for problem in corpus_integrity_problems(documents)
        ]
        self.assertTrue(
            any(
                "reproduces known source text verbatim" in message
                for message in invisible_character_messages
            )
        )

    def test_public_bundle_inputs_must_be_cleared_before_generation(self) -> None:
        documents = self.example_documents()
        for path, document in documents:
            if path.name == "india-gst-source-capture.json":
                document["publication_clearance"]["reviewed_at"] = (
                    "2030-01-01T00:00:00Z"
                )
        messages = [problem.message for problem in corpus_integrity_problems(documents)]
        self.assertTrue(any("after bundle generation" in message for message in messages))

    def test_direct_legal_endpoint_cannot_bypass_partial_scope(self) -> None:
        documents = self.example_documents()
        assertion_id = (
            "urn:trace-the-law:assertion:uuid:88888888-8888-4888-8888-888888888888"
        )
        legal_interval = {
            "status": "known",
            "start": {
                "status": "exact",
                "value": "2017-07-01",
                "precision": "day",
                "calendar": "gregory",
            },
            "end": {
                "status": "exact",
                "value": "2018-06-30",
                "precision": "day",
                "calendar": "gregory",
            },
            "end_inclusive": True,
        }
        for path, document in documents:
            if path.name == "india-gst-relationship-assertion.json":
                document["status"] = "verified"
                document["scope"]["extent"] = "partial"
                document["scope"].pop("target_provision_ids", None)
                document["time_axes"]["applicability"] = copy.deepcopy(legal_interval)
            elif path.name == "india-gst-record.json":
                provision_interval = copy.deepcopy(legal_interval)
                provision_interval["basis_assertion_ids"] = [assertion_id]
                document["versions"][0]["provisions"][0]["time_axes"][
                    "applicability"
                ] = provision_interval
        messages = [problem.message for problem in corpus_integrity_problems(documents)]
        self.assertTrue(any("scope does not cover the record or provision" in m for m in messages))

    def test_invalidation_clock_is_between_strictly_ordered_snapshots(self) -> None:
        documents = self.example_documents()
        for path, document in documents:
            if path.name == "india-gst-invalidation-event.json":
                document["occurred_at"] = "2030-01-01T00:00:00Z"
        messages = [problem.message for problem in corpus_integrity_problems(documents)]
        self.assertTrue(any("cannot postdate snapshot_after" in m for m in messages))

        documents = self.example_documents()
        for path, document in documents:
            if path.name == "india-gst-snapshot-after.json":
                document["generated_at"] = "2000-01-01T00:00:00Z"
        messages = [problem.message for problem in corpus_integrity_problems(documents)]
        self.assertTrue(any("must be generated after snapshot_before" in m for m in messages))

    def test_snapshot_predecessor_is_strictly_earlier_without_an_event(self) -> None:
        snapshot_paths = (
            REPOSITORY_ROOT / "examples" / "india-gst-snapshot-before.json",
            self.example_file("india-gst-snapshot-after.json"),
        )
        documents = [
            (path, copy.deepcopy(load_document(path))) for path in snapshot_paths
        ]
        predecessor_time = documents[0][1]["generated_at"]
        documents[1][1]["generated_at"] = predecessor_time

        messages = [problem.message for problem in corpus_integrity_problems(documents)]
        self.assertTrue(
            any("snapshot must be generated after its predecessor" in message for message in messages)
        )

    def test_closed_corpus_rejects_a_second_genesis_snapshot(self) -> None:
        documents = self.example_documents()
        for path, document in documents:
            if path.name == "india-gst-snapshot-after.json":
                document.pop("predecessor_snapshot_id", None)
                document.pop("transition_event_id", None)
        messages = [problem.message for problem in corpus_integrity_problems(documents)]
        self.assertIn(
            "a closed corpus must contain exactly one genesis snapshot; every other snapshot must remain on that event-bound lineage",
            messages,
        )

    def test_post_genesis_snapshot_requires_its_exact_transition_event(self) -> None:
        documents = self.example_documents()
        for path, document in documents:
            if path.name == "india-gst-snapshot-after.json":
                document.pop("transition_event_id", None)
        messages = [problem.message for problem in corpus_integrity_problems(documents)]
        self.assertIn(
            "post-genesis snapshot transition event does not resolve",
            messages,
        )

    def test_failed_invalidation_blocks_descendants_until_a_later_repair(self) -> None:
        documents = self.example_documents()
        by_name = {path.name: document for path, document in documents}
        failed_event = by_name["india-gst-invalidation-event.json"]
        first_after = by_name["india-gst-snapshot-after.json"]
        bundle = by_name["india-gst-evidence-bundle.json"]
        failed_event["propagation_status"] = "failed"
        failed_event["rebuilds"][0].update(
            {"status": "failed", "failure_code": "build_failed"}
        )

        def select_snapshot(snapshot: dict, generated_at: str) -> None:
            old_id = bundle["evaluation_context"]["corpus_snapshot"]["snapshot_id"]
            new_id = snapshot["snapshot_id"]
            bundle["evaluation_context"]["corpus_snapshot"] = {
                "snapshot_id": new_id,
                "recorded_at": generated_at,
            }
            for dependency in bundle["dependencies"]:
                if dependency == {"entity_type": "snapshot", "entity_id": old_id}:
                    dependency["entity_id"] = new_id

        select_snapshot(first_after, first_after["generated_at"])
        messages = [problem.message for problem in corpus_integrity_problems(documents)]
        self.assertTrue(
            any(
                "bundle snapshot is blocked by pending or failed invalidation propagation"
                in message
                for message in messages
            )
        )

        repaired_snapshot = copy.deepcopy(first_after)
        repaired_snapshot["snapshot_id"] = (
            "urn:trace-the-law:snapshot:sha256:" + "2" * 64
        )
        repaired_snapshot["predecessor_snapshot_id"] = first_after["snapshot_id"]
        repaired_snapshot["transition_event_id"] = (
            "urn:trace-the-law:event:uuid:"
            "29292929-2929-4929-8929-292929292929"
        )
        repaired_snapshot["generated_at"] = "2026-08-23T14:06:00Z"
        repair_event = copy.deepcopy(failed_event)
        repair_event["event_id"] = repaired_snapshot["transition_event_id"]
        repair_event["snapshot_before"] = first_after["snapshot_id"]
        repair_event["snapshot_after"] = repaired_snapshot["snapshot_id"]
        repair_event["occurred_at"] = "2026-08-23T14:05:00Z"
        repair_event["propagation_status"] = "succeeded"
        for rebuild in repair_event["rebuilds"]:
            rebuild["status"] = "succeeded"
            rebuild.pop("failure_code", None)
        documents.extend(
            [
                (Path("repair-event.json"), repair_event),
                (Path("repaired-snapshot.json"), repaired_snapshot),
            ]
        )
        select_snapshot(repaired_snapshot, repaired_snapshot["generated_at"])
        messages = [problem.message for problem in corpus_integrity_problems(documents)]
        self.assertFalse(
            any(
                "bundle snapshot is blocked by pending or failed invalidation propagation"
                in message
                for message in messages
            )
        )

    @staticmethod
    def relationship_window(start: str, end: str | None = None) -> dict:
        interval = {
            "status": "open_ended" if end is None else "known",
            "start": {
                "status": "exact",
                "value": start,
                "precision": "day",
                "calendar": "gregory",
            },
        }
        if end is not None:
            interval.update(
                {
                    "end": {
                        "status": "exact",
                        "value": end,
                        "precision": "day",
                        "calendar": "gregory",
                    },
                    "end_inclusive": True,
                }
            )
        return interval

    def test_authority_cycles_require_overlapping_reviewed_relationships(self) -> None:
        documents = self.example_documents()
        by_name = {path.name: document for path, document in documents}
        first = by_name["india-cbic-authority.json"]
        second = copy.deepcopy(first)
        second_id = (
            "urn:trace-the-law:authority:uuid:24242424-2424-4242-8242-242424242424"
        )
        second["authority_id"] = second_id
        assertion_template = by_name["india-cbic-serves-india-relationship-assertion.json"]
        assertions = []
        for index, (subject_id, object_id, start, end) in enumerate(
            (
                (first["authority_id"], second_id, "2000-01-01", "2005-12-31"),
                (second_id, first["authority_id"], "2010-01-01", None),
            ),
            start=1,
        ):
            assertion = copy.deepcopy(assertion_template)
            assertion["assertion_id"] = (
                "urn:trace-the-law:assertion:uuid:"
                + ("25252525-2525-4252-8252-252525252525" if index == 1 else "26262626-2626-4262-8262-262626262626")
            )
            assertion["subject"] = {
                "entity_type": "authority",
                "entity_id": subject_id,
            }
            assertion["predicate"] = "institutionally_part_of"
            assertion["object"] = {
                "entity_type": "authority",
                "entity_id": object_id,
            }
            assertion["scope"] = {
                "extent": "whole_entity",
                "jurisdiction_ids": [
                    "urn:trace-the-law:jurisdiction:uuid:11111111-1111-4111-8111-111111111111"
                ],
            }
            assertion["status"] = "verified"
            assertion["time_axes"]["effectiveness"] = self.relationship_window(start, end)
            assertions.append(assertion)
        first["parent_relationships"] = [
            {
                "parent_authority_id": second_id,
                "assertion_id": assertions[0]["assertion_id"],
            }
        ]
        second["parent_relationships"] = [
            {
                "parent_authority_id": first["authority_id"],
                "assertion_id": assertions[1]["assertion_id"],
            }
        ]
        documents.extend(
            [
                (Path("second-authority.json"), second),
                (Path("first-parent.json"), assertions[0]),
                (Path("second-parent.json"), assertions[1]),
            ]
        )
        messages = [problem.message for problem in corpus_integrity_problems(documents)]
        self.assertFalse(any("authority parent hierarchy contains a cycle" in m for m in messages))

        assertions[1]["time_axes"]["effectiveness"] = self.relationship_window(
            "2004-01-01"
        )
        messages = [problem.message for problem in corpus_integrity_problems(documents)]
        self.assertTrue(any("authority parent hierarchy contains a cycle" in m for m in messages))
        assertions[1]["status"] = "retracted"
        messages = [problem.message for problem in corpus_integrity_problems(documents)]
        self.assertFalse(any("authority parent hierarchy contains a cycle" in m for m in messages))

    def test_jurisdiction_cycles_require_overlapping_reviewed_relationships(self) -> None:
        documents = self.example_documents()
        by_name = {path.name: document for path, document in documents}
        first = by_name["india-jurisdiction.json"]
        second = copy.deepcopy(first)
        second_id = (
            "urn:trace-the-law:jurisdiction:uuid:27272727-2727-4272-8272-272727272727"
        )
        second["jurisdiction_id"] = second_id
        assertion_template = by_name["india-cbic-serves-india-relationship-assertion.json"]
        assertions = []
        for index, (subject_id, object_id, start, end) in enumerate(
            (
                (first["jurisdiction_id"], second_id, "2000-01-01", "2005-12-31"),
                (second_id, first["jurisdiction_id"], "2010-01-01", None),
            ),
            start=1,
        ):
            assertion = copy.deepcopy(assertion_template)
            assertion["assertion_id"] = (
                "urn:trace-the-law:assertion:uuid:"
                + ("28282828-2828-4282-8282-282828282828" if index == 1 else "29292929-2929-4292-8292-292929292929")
            )
            assertion["subject"] = {
                "entity_type": "jurisdiction",
                "entity_id": subject_id,
            }
            assertion["predicate"] = "territorially_within"
            assertion["object"] = {
                "entity_type": "jurisdiction",
                "entity_id": object_id,
            }
            assertion["scope"] = {
                "extent": "whole_entity",
                "jurisdiction_ids": [first["jurisdiction_id"]],
            }
            assertion["status"] = "verified"
            assertion["time_axes"]["effectiveness"] = self.relationship_window(start, end)
            assertions.append(assertion)
        first["territorial_relationships"] = [
            {
                "related_jurisdiction_id": second_id,
                "assertion_id": assertions[0]["assertion_id"],
            }
        ]
        second["territorial_relationships"] = [
            {
                "related_jurisdiction_id": first["jurisdiction_id"],
                "assertion_id": assertions[1]["assertion_id"],
            }
        ]
        documents.extend(
            [
                (Path("second-jurisdiction.json"), second),
                (Path("first-within.json"), assertions[0]),
                (Path("second-within.json"), assertions[1]),
            ]
        )
        messages = [problem.message for problem in corpus_integrity_problems(documents)]
        self.assertFalse(any("territorial containment contains a cycle" in m for m in messages))
        assertions[1]["time_axes"]["effectiveness"] = self.relationship_window(
            "2004-01-01"
        )
        messages = [problem.message for problem in corpus_integrity_problems(documents)]
        self.assertTrue(any("territorial containment contains a cycle" in m for m in messages))

    def test_public_source_excerpt_requires_reviewed_reuse_rights(self) -> None:
        documents = self.example_documents()
        for path, document in documents:
            if path.name == "india-gst-evidence-bundle.json":
                document["claims"][0]["content_use"] = "source_excerpt"
                document["citations"][0]["quoted_text"] = (
                    "1. Short title, extent and commencement."
                )
        messages = [problem.message for problem in corpus_integrity_problems(documents)]
        self.assertTrue(any("publishable rights" in message for message in messages))
        self.assertTrue(any("does not permit" in message for message in messages))

    def test_closed_public_corpus_rejects_ephemeral_bundle(self) -> None:
        documents = self.example_documents()
        for path, document in documents:
            if path.name == "india-gst-evidence-bundle.json":
                document["handling"] = {
                    "persistence": "client_ephemeral",
                    "privacy_classification": "confidential_query_context",
                }
        messages = [problem.message for problem in corpus_integrity_problems(documents)]
        self.assertTrue(any("closed public corpus" in message for message in messages))

    def test_resolved_conflict_requires_reviewed_resolution_assertions(self) -> None:
        bundle = copy.deepcopy(
            load_document(REPOSITORY_ROOT / "examples" / "india-gst-evidence-bundle.json")
        )
        bundle["conflicts"] = [
            {
                "assertion_ids": [
                    "urn:trace-the-law:assertion:uuid:88888888-8888-4888-8888-888888888888",
                    "urn:trace-the-law:assertion:uuid:13131313-1313-4131-8131-131313131313",
                ],
                "resolution_state": "time_resolved",
            }
        ]
        messages = [
            problem.message
            for problem in validate_document(
                Path("bundle.json"), bundle, self.schemas, self.registry
            )
        ]
        self.assertTrue(any("resolution_assertion_ids" in message for message in messages))

    def test_corpus_integrity_tolerates_schema_invalid_collection_shapes(self) -> None:
        documents = self.example_documents()
        for path, document in documents:
            if path.name == "india-gst-evidence-bundle.json":
                document["dependencies"] = [{}, None]
            elif path.name == "india-gst-heading-derivation.json":
                document["input_artifacts"] = None
        problems = corpus_integrity_problems(documents)
        self.assertIsInstance(problems, list)

    def test_repository_has_no_direct_public_correction_form(self) -> None:
        correction_form = (
            REPOSITORY_ROOT / ".github" / "ISSUE_TEMPLATE" / "correction.yml"
        )
        self.assertFalse(
            correction_form.exists(),
            "correction candidates must use private broker intake, not a public form",
        )


if __name__ == "__main__":
    unittest.main()
