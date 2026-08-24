"""Validate Trace the Law schemas and structured records."""

from __future__ import annotations

import argparse
import hashlib
import ipaddress
import json
import math
import re
import sys
import sysconfig
import unicodedata
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any, Iterable
from urllib.parse import parse_qsl, unquote, urldefrag, urljoin, urlsplit

import yaml
from jsonschema import Draft202012Validator
from referencing import Registry, Resource
from yaml.constructor import ConstructorError
from yaml.nodes import MappingNode


REPOSITORY_ROOT = Path(__file__).resolve().parents[2]
SOURCE_DATA_ROOT = REPOSITORY_ROOT
INSTALLED_DATA_ROOT = Path(sysconfig.get_path("data")) / "share" / "trace-the-law"


def _find_default_data_root() -> Path:
    candidates = [SOURCE_DATA_ROOT, INSTALLED_DATA_ROOT]
    candidates.extend(
        parent / "share" / "trace-the-law"
        for parent in Path(__file__).resolve().parents
    )
    for candidate in candidates:
        if (candidate / "schemas").is_dir():
            return candidate
    # Preserve a deterministic, actionable failure path when distribution data
    # was omitted from a broken installation.
    return INSTALLED_DATA_ROOT


DEFAULT_DATA_ROOT = _find_default_data_root()
DEFAULT_SCHEMA_DIRECTORY = DEFAULT_DATA_ROOT / "schemas"
DEFAULT_DATA_DIRECTORIES = (DEFAULT_DATA_ROOT / "examples",)

STRUCTURED_SUFFIXES = {".json", ".yaml", ".yml"}
FORBIDDEN_REPORT_KEYS = {
    "api_key",
    "attachment",
    "authorization",
    "chat",
    "conversation",
    "cookie",
    "credentials",
    "local_path",
    "prompt",
    "signed_url",
    "transcript",
    "user_facts",
    "user_question",
}
PRIVACY_DECLARATION_KEYS = {
    "case_facts",
    "conversation_text",
    "personal_data",
    "private_urls",
    "secrets",
}
SENSITIVE_URL_QUERY_KEYS = {
    "access_token",
    "api_key",
    "apikey",
    "auth",
    "authorization",
    "code",
    "credential",
    "downloadtoken",
    "expires",
    "hmac",
    "jwt",
    "key",
    "key-pair-id",
    "policy",
    "session",
    "sig",
    "signature",
    "token",
    "x-amz-credential",
    "x-amz-expires",
    "x-amz-security-token",
    "x-amz-signature",
    "x-goog-credential",
    "x-goog-expires",
    "x-goog-signature",
}
TRACKING_URL_QUERY_KEYS = {
    "dclid",
    "fbclid",
    "gclid",
    "mc_cid",
    "mc_eid",
    "msclkid",
}
NON_PUBLIC_HOST_SUFFIXES = (
    ".home",
    ".internal",
    ".invalid",
    ".lan",
    ".local",
    ".localhost",
    ".onion",
    ".test",
)
URL_IN_TEXT_PATTERN = re.compile(r"https?://[^\s<>\"'`]+", re.IGNORECASE)
DEPENDENCY_AVAILABILITY_TIMESTAMP_FIELDS = {
    "checked_at",
    "completed_at",
    "created_at",
    "evidence_retrieved_at",
    "first_detected_at",
    "generated_at",
    "last_checked_at",
    "last_successful_enumeration_at",
    "last_verified_at",
    "occurred_at",
    "published_at",
    "recorded_at",
    "resolved_at",
    "retrieved_at",
    "reviewed_at",
    "started_at",
    "updated_at",
    "verified_at",
}
VERSION_TRANSITION_PREDICATES = frozenset(
    {
        "amends",
        "corrects",
        "inserts",
        "renumbers",
        "substitutes",
        "supersedes",
    }
)
MAX_DOCUMENT_DEPTH = 128
MAX_WALK_NODES = 250_000
CURRENCY_AMOUNT_PATTERN = re.compile(
    r"(?i)(?:\b(?:AED|AUD|CAD|CHF|CNY|EUR|GBP|HKD|INR|JPY|RMB|SGD|USD)\b|[₹$€£¥])"
    r"\s*[-+]?\d[\d,]*(?:\.\d+)?"
    r"|[-+]?\d[\d,]*(?:\.\d+)?\s*"
    r"\b(?:dirhams?|dollars?|euros?|pounds?|rupees?|yen)\b"
)
EMAIL_ADDRESS_PATTERN = re.compile(
    r"(?i)(?<![A-Z0-9._%+-])[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}(?![A-Z0-9.-])"
)
PERSONAL_FACT_PATTERN = re.compile(
    r"(?i)\b(?:I|we|my|our|user|client|customer)\b.{0,60}"
    r"\b(?:earned|filed|lives?|owes?|paid|received|resides?|works?)\b"
)
PRECISION_PATTERNS = {
    "year": re.compile(r"^[0-9]{4}$"),
    "month": re.compile(r"^[0-9]{4}-(0[1-9]|1[0-2])$"),
    "day": re.compile(r"^[0-9]{4}-(0[1-9]|1[0-2])-(0[1-9]|[12][0-9]|3[01])$"),
    "second": re.compile(
        r"^[0-9]{4}-(0[1-9]|1[0-2])-(0[1-9]|[12][0-9]|3[01])"
        r"T([01][0-9]|2[0-3]):[0-5][0-9]:[0-5][0-9](?:Z|[+-](?:[01][0-9]|2[0-3]):[0-5][0-9])$"
    ),
}
DATETIME_FIELD_NAMES = {
    "checked_at",
    "completed_at",
    "created_at",
    "evidence_retrieved_at",
    "first_detected_at",
    "fresh_until",
    "generated_at",
    "last_checked_at",
    "last_successful_enumeration_at",
    "last_verified_at",
    "next_review_at",
    "occurred_at",
    "recorded_at",
    "resolved_at",
    "retention_until",
    "retrieved_at",
    "reviewed_at",
    "source_last_modified",
    "started_at",
    "updated_at",
    "verified_at",
}


class StringSafeLoader(yaml.SafeLoader):
    """Load YAML dates as strings so YAML and JSON obey the same schemas."""

    def compose_node(self, parent: Any, index: Any) -> Any:
        if self.check_event(yaml.AliasEvent):
            event = self.peek_event()
            raise ConstructorError(
                None,
                None,
                "YAML aliases are not supported in corpus documents",
                event.start_mark,
            )
        return super().compose_node(parent, index)


StringSafeLoader.yaml_implicit_resolvers = {
    key: list(value) for key, value in yaml.SafeLoader.yaml_implicit_resolvers.items()
}
for first_character, resolvers in list(StringSafeLoader.yaml_implicit_resolvers.items()):
    StringSafeLoader.yaml_implicit_resolvers[first_character] = [
        resolver
        for resolver in resolvers
        if resolver[0] != "tag:yaml.org,2002:timestamp"
    ]


def _reject_duplicate_json_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError(f"duplicate object key {key!r}")
        result[key] = value
    return result


def _construct_unique_yaml_mapping(
    loader: StringSafeLoader, node: MappingNode, deep: bool = False
) -> dict[Any, Any]:
    if not isinstance(node, MappingNode):
        raise ConstructorError(None, None, "expected a mapping node", node.start_mark)
    mapping: dict[Any, Any] = {}
    for key_node, value_node in node.value:
        key = loader.construct_object(key_node, deep=deep)
        try:
            duplicate = key in mapping
        except TypeError as error:
            raise ConstructorError(
                "while constructing a mapping",
                node.start_mark,
                "found an unhashable key",
                key_node.start_mark,
            ) from error
        if duplicate:
            raise ConstructorError(
                "while constructing a mapping",
                node.start_mark,
                f"found duplicate key {key!r}",
                key_node.start_mark,
            )
        mapping[key] = loader.construct_object(value_node, deep=deep)
    return mapping


StringSafeLoader.add_constructor(
    yaml.resolver.BaseResolver.DEFAULT_MAPPING_TAG,
    _construct_unique_yaml_mapping,
)


@dataclass(frozen=True)
class ValidationProblem:
    path: Path
    location: str
    message: str

    def render(self) -> str:
        suffix = f" at {self.location}" if self.location else ""
        return f"{self.path}{suffix}: {self.message}"


def _reject_json_constant(value: str) -> None:
    raise ValueError(f"non-JSON numeric constant {value!r}")


def _reject_non_finite_numbers(value: Any) -> None:
    for location, child in _walk(value):
        if isinstance(child, float) and not math.isfinite(child):
            raise ValueError(
                f"non-finite number at {_json_location(location)} is outside the JSON data model"
            )


def load_document(path: Path) -> Any:
    with path.open("r", encoding="utf-8") as handle:
        if path.suffix == ".json":
            document = json.load(
                handle,
                object_pairs_hook=_reject_duplicate_json_keys,
                parse_constant=_reject_json_constant,
            )
        else:
            document = yaml.load(handle, Loader=StringSafeLoader)
    _reject_non_finite_numbers(document)
    return document


def iter_structured_files(paths: Iterable[Path]) -> Iterable[Path]:
    for path in paths:
        if path.is_file() and path.suffix in STRUCTURED_SUFFIXES:
            yield path
        elif path.is_dir():
            yield from sorted(
                candidate
                for candidate in path.rglob("*")
                if candidate.is_file() and candidate.suffix in STRUCTURED_SUFFIXES
            )


def load_schema_registry(schema_directory: Path) -> tuple[dict[str, dict[str, Any]], Registry]:
    schemas: dict[str, dict[str, Any]] = {}
    resources: list[tuple[str, Resource[Any]]] = []

    for path in iter_structured_files((schema_directory,)):
        schema = load_document(path)
        if not isinstance(schema, dict):
            raise ValueError(f"{path}: schema root must be an object")
        Draft202012Validator.check_schema(schema)
        schema_id = schema.get("$id")
        if not isinstance(schema_id, str) or not schema_id:
            raise ValueError(f"{path}: schema requires a non-empty $id")
        if schema_id in schemas:
            raise ValueError(f"{path}: duplicate schema $id {schema_id}")
        schemas[schema_id] = schema
        resources.append((schema_id, Resource.from_contents(schema)))

    if not schemas:
        raise ValueError(f"{schema_directory}: no schemas found")

    _check_schema_references(schemas)

    return schemas, Registry().with_resources(resources)


def _resolve_json_pointer(document: Any, fragment: str) -> Any:
    if not fragment:
        return document
    if not fragment.startswith("/"):
        raise KeyError("only JSON Pointer fragments are supported")
    current = document
    for raw_part in fragment[1:].split("/"):
        part = unquote(raw_part).replace("~1", "/").replace("~0", "~")
        if isinstance(current, dict):
            current = current[part]
        elif isinstance(current, list):
            current = current[int(part)]
        else:
            raise KeyError(part)
    return current


def _check_schema_references(schemas: dict[str, dict[str, Any]]) -> None:
    for schema_id, schema in schemas.items():
        for location, value in _walk(schema):
            if not location or location[-1] != "$ref" or not isinstance(value, str):
                continue
            resolved = urljoin(schema_id, value)
            target_id, fragment = urldefrag(resolved)
            if target_id not in schemas:
                raise ValueError(
                    f"{schema_id} at {_json_location(location)}: "
                    f"reference target {target_id!r} is not in the local registry"
                )
            try:
                _resolve_json_pointer(schemas[target_id], fragment)
            except (KeyError, IndexError, ValueError) as error:
                raise ValueError(
                    f"{schema_id} at {_json_location(location)}: "
                    f"unresolved reference fragment {fragment!r}"
                ) from error


def _json_location(parts: Iterable[Any]) -> str:
    rendered = "$"
    for part in parts:
        rendered += f"[{part}]" if isinstance(part, int) else f".{part}"
    return rendered


def _walk(
    value: Any,
    path: tuple[Any, ...] = (),
    _ancestors: frozenset[int] = frozenset(),
) -> Iterable[tuple[tuple[Any, ...], Any]]:
    stack: list[tuple[Any, tuple[Any, ...], frozenset[int]]] = [
        (value, path, _ancestors)
    ]
    visited = 0
    while stack:
        current, current_path, ancestors = stack.pop()
        visited += 1
        if visited > MAX_WALK_NODES:
            raise ValueError(
                f"expanded document exceeds {MAX_WALK_NODES} nodes"
            )
        if len(current_path) > MAX_DOCUMENT_DEPTH:
            raise ValueError(
                f"document nesting exceeds {MAX_DOCUMENT_DEPTH} levels at "
                f"{_json_location(current_path)}"
            )
        if isinstance(current, (dict, list)):
            identity = id(current)
            if identity in ancestors:
                raise ValueError(
                    f"recursive container structure at {_json_location(current_path)} "
                    "is outside the JSON data model"
                )
            child_ancestors = ancestors | {identity}
        else:
            child_ancestors = ancestors
        yield current_path, current
        if isinstance(current, dict):
            for key, child in reversed(tuple(current.items())):
                stack.append((child, (*current_path, key), child_ancestors))
        elif isinstance(current, list):
            for child_index in range(len(current) - 1, -1, -1):
                stack.append(
                    (
                        current[child_index],
                        (*current_path, child_index),
                        child_ancestors,
                    )
                )


def _list_or_empty(value: Any) -> list[Any]:
    return value if isinstance(value, list) else []


def _canonical_json_bytes(value: Any) -> bytes:
    """Encode the no-float JSON subset used by content-addressed contracts."""

    return json.dumps(
        value,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
        allow_nan=False,
    ).encode("utf-8")


def _normalized_comparable_text(value: str) -> str:
    """Normalize human-readable text for conservative verbatim checks."""

    normalized = unicodedata.normalize("NFKC", value)
    visible = "".join(
        character
        for character in normalized
        if unicodedata.category(character) != "Cf"
        and not 0xFE00 <= ord(character) <= 0xFE0F
        and not 0xE0100 <= ord(character) <= 0xE01EF
        and ord(character) != 0x034F
    )
    return " ".join(visible.casefold().split())


def _has_material_verbatim_overlap(left: str, right: str) -> bool:
    """Return true when either text reproduces a material exact passage."""

    normalized_left = _normalized_comparable_text(left)
    normalized_right = _normalized_comparable_text(right)
    if min(len(normalized_left), len(normalized_right)) < 24:
        return False
    return normalized_left in normalized_right or normalized_right in normalized_left


def _direct_citation_key(value: Any) -> tuple[str, str, bytes] | None:
    """Identify one exact source-acquired citation location."""

    if not isinstance(value, dict):
        return None
    artifact_id = value.get("artifact_id")
    capture_id = value.get("capture_id")
    locator = value.get("locator")
    if (
        not isinstance(artifact_id, str)
        or not isinstance(capture_id, str)
        or not isinstance(locator, dict)
    ):
        return None
    try:
        locator_key = _canonical_json_bytes(locator)
    except (TypeError, UnicodeEncodeError, ValueError):
        return None
    return artifact_id, capture_id, locator_key


def _evidence_content_projection(citation: dict[str, Any]) -> dict[str, Any]:
    """Return the exact citation fields covered by content verification."""

    return {
        field: citation[field]
        for field in (
            "artifact_id",
            "capture_id",
            "locator",
            "quoted_text_digest",
            "excerpt_digest",
        )
        if field in citation
    }


def _content_verification_projection(citation: dict[str, Any]) -> dict[str, Any]:
    """Bind the checked evidence and the complete verifier decision."""

    projection = _evidence_content_projection(citation)
    verification = citation.get("content_verification")
    if isinstance(verification, dict):
        for field in ("method", "verified_at", "verifier"):
            if field in verification:
                projection[field] = verification[field]
    return projection


def _parse_datetime(value: str) -> datetime | None:
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
        if parsed.tzinfo is None:
            return None
        return parsed.astimezone(UTC)
    except (OverflowError, ValueError):
        return None


def _capture_http_succeeded(capture: Any) -> bool:
    """Return true only for a complete final HTTP representation modeled by v1."""

    retrieval = capture.get("retrieval") if isinstance(capture, dict) else None
    status = retrieval.get("http_status") if isinstance(retrieval, dict) else None
    # V1 has no semantics for empty 204/205 responses, partial 206 responses,
    # WebDAV multi-status bodies, or delta representations. Treat those as
    # monitoring observations until the capture model can prove exact bytes.
    return isinstance(status, int) and not isinstance(status, bool) and status == 200


def _dependency_availability_violations(
    entity_type: str,
    state: Any,
    snapshot_instant: datetime,
    snapshot_point: dict[str, Any],
) -> list[str]:
    """Return state/review clocks that were unavailable at a snapshot."""

    violations: list[str] = []
    for location, value in _walk(state):
        field = location[-1] if location else None
        timestamp_is_snapshot_bound = False
        if entity_type == "artifact":
            timestamp_is_snapshot_bound = location == ("created_at",) or (
                bool(location)
                and location[0] == "legal_scope_attestations"
                and field in {"created_at", "reviewed_at"}
            )
        elif entity_type == "capture":
            timestamp_is_snapshot_bound = location in {
                ("created_at",),
                ("retrieval", "retrieved_at"),
            } or (
                bool(location)
                and location[0] == "acquisition"
                and field in DEPENDENCY_AVAILABILITY_TIMESTAMP_FIELDS
            )
        elif entity_type == "derivation":
            timestamp_is_snapshot_bound = location == ("created_at",)
        elif entity_type == "source":
            timestamp_is_snapshot_bound = location in {
                ("created_at",),
                ("updated_at",),
                ("identity_review", "reviewed_at"),
            } or (
                bool(location)
                and location[0] == "identity_evidence"
                and field in DEPENDENCY_AVAILABILITY_TIMESTAMP_FIELDS
            )
        else:
            timestamp_is_snapshot_bound = (
                field in DEPENDENCY_AVAILABILITY_TIMESTAMP_FIELDS
            )
        if timestamp_is_snapshot_bound and isinstance(value, str):
            instant = _parse_datetime(value)
            if instant is None or instant > snapshot_instant:
                violations.append(_json_location(location))
        if (
            entity_type not in {"artifact", "capture", "derivation", "source"}
            and field == "observation"
            and isinstance(value, dict)
            and not _temporal_point_not_after(value, snapshot_point)
        ):
            violations.append(_json_location(location))
    return violations


def _temporal_point_bounds(point: dict[str, Any]) -> tuple[datetime, datetime] | None:
    value = point.get("value")
    precision = point.get("precision")
    if not isinstance(value, str) or not isinstance(precision, str):
        return None
    try:
        if precision == "year":
            lower = datetime(int(value), 1, 1, tzinfo=UTC)
            upper = datetime(int(value) + 1, 1, 1, tzinfo=UTC)
        elif precision == "month":
            lower = datetime.strptime(value, "%Y-%m").replace(tzinfo=UTC)
            upper = (
                datetime(lower.year + 1, 1, 1, tzinfo=UTC)
                if lower.month == 12
                else datetime(lower.year, lower.month + 1, 1, tzinfo=UTC)
            )
        elif precision == "day":
            lower = datetime.strptime(value, "%Y-%m-%d").replace(tzinfo=UTC)
            upper = lower + timedelta(days=1)
        elif precision == "second":
            lower = _parse_datetime(value)
            if lower is None:
                return None
            upper = lower + timedelta(seconds=1)
        else:
            return None
    except (OverflowError, ValueError):
        return None
    return lower, upper


def _temporal_interval_bounds(
    interval: Any,
) -> tuple[datetime, datetime | None] | None:
    """Return conservative half-open bounds for a usable legal interval."""

    if not isinstance(interval, dict) or interval.get("status") not in {
        "known",
        "open_ended",
    }:
        return None
    start = interval.get("start")
    start_bounds = _temporal_point_bounds(start) if isinstance(start, dict) else None
    if start_bounds is None:
        return None
    if interval.get("status") == "open_ended":
        return start_bounds[0], None
    end = interval.get("end")
    end_bounds = _temporal_point_bounds(end) if isinstance(end, dict) else None
    if end_bounds is None:
        return None
    upper = end_bounds[1] if interval.get("end_inclusive") is True else end_bounds[0]
    return start_bounds[0], upper


def _temporal_interval_has_approximate_boundary(interval: Any) -> bool:
    if not isinstance(interval, dict):
        return False
    return any(
        isinstance(interval.get(field), dict)
        and interval[field].get("status") == "approximate"
        for field in ("start", "end")
    )


def _temporal_interval_covers_interval(container: Any, requested: Any) -> bool:
    """Return true only when the container covers the complete requested period."""

    container_bounds = _temporal_interval_bounds(container)
    requested_bounds = _temporal_interval_bounds(requested)
    if container_bounds is None or requested_bounds is None:
        return False
    container_start, container_end = container_bounds
    requested_start, requested_end = requested_bounds
    if container_start > requested_start:
        return False
    if requested_end is None:
        return container_end is None
    return container_end is None or container_end >= requested_end


def _temporal_interval_covers_point(interval: Any, point: Any) -> bool:
    """Return true only when a legal interval covers the point's full precision bucket."""

    interval_bounds = _temporal_interval_bounds(interval)
    point_bounds = _temporal_point_bounds(point) if isinstance(point, dict) else None
    if interval_bounds is None or point_bounds is None:
        return False
    interval_start, interval_end = interval_bounds
    return interval_start <= point_bounds[0] and (
        interval_end is None or interval_end >= point_bounds[1]
    )


def _temporal_intervals_overlap(left: Any, right: Any) -> bool:
    """Return true only for demonstrably overlapping legal intervals."""

    if isinstance(left, dict) and isinstance(right, dict):
        if left.get("status") == right.get("status") == "not_applicable":
            return True
    left_bounds = _temporal_interval_bounds(left)
    right_bounds = _temporal_interval_bounds(right)
    if left_bounds is None or right_bounds is None:
        return False
    left_start, left_end = left_bounds
    right_start, right_end = right_bounds
    return (left_end is None or right_start < left_end) and (
        right_end is None or left_start < right_end
    )


def _temporal_point_not_after(candidate: Any, cutoff: Any) -> bool:
    """Prove that a publication point does not extend beyond the cutoff bucket."""

    candidate_bounds = (
        _temporal_point_bounds(candidate) if isinstance(candidate, dict) else None
    )
    cutoff_bounds = _temporal_point_bounds(cutoff) if isinstance(cutoff, dict) else None
    return (
        candidate_bounds is not None
        and cutoff_bounds is not None
        and candidate_bounds[1] <= cutoff_bounds[1]
    )


def temporal_problems(path: Path, document: dict[str, Any]) -> list[ValidationProblem]:
    """Reject temporal values whose precision or ordering is contradictory."""

    problems: list[ValidationProblem] = []
    for location, value in _walk(document):
        if not isinstance(value, dict):
            continue

        if isinstance(value.get("temporal_value_binding"), dict) and not (
            isinstance(value.get("quoted_text"), str) and value["quoted_text"].strip()
        ):
            problems.append(
                ValidationProblem(
                    path,
                    _json_location((*location, "quoted_text")),
                    "a temporal value binding requires reviewable quoted_text; an opaque digest alone cannot establish the source expression",
                )
            )

        for field in DATETIME_FIELD_NAMES:
            candidate = value.get(field)
            if isinstance(candidate, str) and _parse_datetime(candidate) is None:
                problems.append(
                    ValidationProblem(
                        path,
                        _json_location((*location, field)),
                        "date-time cannot be normalized to a valid UTC instant",
                    )
                )

        for earlier_field, later_field, message in (
            ("created_at", "reviewed_at", "review cannot predate creation"),
            ("created_at", "updated_at", "update cannot predate creation"),
        ):
            earlier = value.get(earlier_field)
            later = value.get(later_field)
            earlier_time = _parse_datetime(earlier) if isinstance(earlier, str) else None
            later_time = _parse_datetime(later) if isinstance(later, str) else None
            if earlier_time is not None and later_time is not None and later_time < earlier_time:
                problems.append(
                    ValidationProblem(
                        path,
                        _json_location((*location, later_field)),
                        message,
                    )
                )

        point_value = value.get("value")
        precision = value.get("precision")
        if isinstance(point_value, str) and isinstance(precision, str):
            expected_pattern = PRECISION_PATTERNS.get(precision)
            if expected_pattern is not None and not expected_pattern.fullmatch(point_value):
                problems.append(
                    ValidationProblem(
                        path,
                        _json_location((*location, "precision")),
                        f"precision {precision!r} does not match temporal value {point_value!r}",
                    )
                )
            if precision == "second" and _parse_datetime(point_value) is None:
                problems.append(
                    ValidationProblem(
                        path,
                        _json_location((*location, "value")),
                        "second-precision temporal value cannot be normalized to a valid UTC instant",
                    )
                )

        if value.get("status") == "unknown" and "precision" in value:
            problems.append(
                ValidationProblem(
                    path,
                    _json_location((*location, "precision")),
                    "an unknown temporal point may not declare precision",
                )
            )

        if value.get("status") != "known":
            continue
        start = value.get("start")
        end = value.get("end")
        if not isinstance(start, dict) or not isinstance(end, dict):
            continue
        start_bounds = _temporal_point_bounds(start)
        end_bounds = _temporal_point_bounds(end)
        if start_bounds is not None and end_bounds is not None:
            # A coarse point denotes its whole precision bucket. Only reject an
            # interval when the buckets cannot overlap in chronological order.
            exact_exclusive_end_is_empty = (
                value.get("end_inclusive") is False
                and start.get("status") == "exact"
                and end.get("status") == "exact"
                and start_bounds[0] >= end_bounds[0]
            )
            if start_bounds[0] >= end_bounds[1] or exact_exclusive_end_is_empty:
                problems.append(
                    ValidationProblem(
                        path,
                        _json_location(location),
                        "temporal interval is empty or starts after its end",
                    )
                )
    return problems


NUMERIC_HOST_LABEL_PATTERN = re.compile(r"(?:0x[0-9a-f]+|[0-9]+)", re.IGNORECASE)
DNS_HOST_LABEL_PATTERN = re.compile(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?", re.IGNORECASE)


def _split_public_http_url(candidate: str) -> tuple[Any | None, str | None]:
    """Parse a public HTTP URL without browser/libc authority ambiguities."""

    if any(ord(character) <= 0x20 for character in candidate) or "\\" in candidate:
        return None, "invalid_authority"
    try:
        parsed = urlsplit(candidate)
        hostname = parsed.hostname
        decoded_authority = unquote(parsed.netloc, errors="strict")
    except (UnicodeError, ValueError):
        return None, "malformed"
    try:
        port = parsed.port
    except ValueError:
        return None, "invalid_port"
    if parsed.scheme.casefold() not in {"http", "https"} or not parsed.netloc or not hostname:
        return None, "invalid_authority"
    if "\\" in decoded_authority or "/" in decoded_authority:
        return None, "invalid_authority"
    host_port = parsed.netloc.rpartition("@")[2]
    if host_port.endswith(":"):
        return None, "invalid_port"
    if port == 0:
        return None, "invalid_port"
    return parsed, None


def _is_non_public_hostname(hostname: str | None) -> bool:
    if not hostname:
        return True
    normalized = hostname.rstrip(".").lower()
    if normalized == "localhost" or normalized.endswith(NON_PUBLIC_HOST_SUFFIXES):
        return True
    try:
        return not ipaddress.ip_address(normalized).is_global
    except ValueError:
        pass
    try:
        ascii_hostname = normalized.encode("idna").decode("ascii")
    except UnicodeError:
        return True
    labels = ascii_hostname.split(".")
    if (
        len(ascii_hostname) > 253
        or len(labels) < 2
        or any(not DNS_HOST_LABEL_PATTERN.fullmatch(label) for label in labels)
    ):
        return True
    # libc and browsers can reinterpret legacy dotted numbers as IPv4. Reject
    # them instead of letting an apparently public hostname resolve privately.
    return all(NUMERIC_HOST_LABEL_PATTERN.fullmatch(label) for label in labels)


def privacy_problems(path: Path, document: dict[str, Any]) -> list[ValidationProblem]:
    """Apply semantic guardrails that JSON Schema alone cannot express."""

    if "correction-report" not in str(document.get("schema_id", "")):
        return []

    problems: list[ValidationProblem] = []
    for location, value in _walk(document):
        if location and isinstance(location[-1], str):
            key = location[-1].lower()
            is_publication_clearance_check = (
                len(location) >= 3
                and location[-2] == "checks"
                and location[-3] == "publication_clearance"
            )
            if key in FORBIDDEN_REPORT_KEYS:
                problems.append(
                    ValidationProblem(
                        path,
                        _json_location(location),
                        "field is forbidden in correction reports",
                    )
                )
            if (
                key in PRIVACY_DECLARATION_KEYS
                and not is_publication_clearance_check
                and value is not False
            ):
                problems.append(
                    ValidationProblem(
                        path,
                        _json_location(location),
                        "privacy declaration must be false",
                    )
                )
        if not isinstance(value, str):
            continue

        if CURRENCY_AMOUNT_PATTERN.search(value):
            problems.append(
                ValidationProblem(
                    path,
                    _json_location(location),
                    "correction-report text may not contain currency amounts",
                )
            )
        if EMAIL_ADDRESS_PATTERN.search(value):
            problems.append(
                ValidationProblem(
                    path,
                    _json_location(location),
                    "correction-report text may not contain email addresses",
                )
            )
        if PERSONAL_FACT_PATTERN.search(value):
            problems.append(
                ValidationProblem(
                    path,
                    _json_location(location),
                    "correction-report text may not contain personal case facts",
                )
            )

        if location == ("schema_id",):
            continue
        for match in URL_IN_TEXT_PATTERN.finditer(value):
            candidate = match.group(0)
            if match.span() != (0, len(value)):
                problems.append(
                    ValidationProblem(
                        path,
                        _json_location(location),
                        "URLs must be isolated in typed URL fields, not embedded in text",
                    )
                )
            parsed, url_error = _split_public_http_url(candidate)
            if parsed is None:
                message = (
                    "correction-report URL has an invalid network port"
                    if url_error == "invalid_port"
                    else "correction-report URL is malformed or has an invalid network authority"
                )
                problems.append(
                    ValidationProblem(
                        path,
                        _json_location(location),
                        message,
                    )
                )
                continue
            if parsed.username is not None or parsed.password is not None:
                problems.append(
                    ValidationProblem(
                        path,
                        _json_location(location),
                        "URLs may not contain credentials",
                    )
                )
            if _is_non_public_hostname(parsed.hostname):
                problems.append(
                    ValidationProblem(
                        path,
                        _json_location(location),
                        "correction-report URLs must use a public host",
                    )
                )
            query_keys = {
                key.lower()
                for field in (parsed.query, parsed.fragment)
                for key, _ in parse_qsl(field, keep_blank_values=True)
            }
            unsafe_keys = {
                key
                for key in query_keys
                if key in SENSITIVE_URL_QUERY_KEYS
                or key in TRACKING_URL_QUERY_KEYS
                or key.startswith("utm_")
            }
            if unsafe_keys:
                problems.append(
                    ValidationProblem(
                        path,
                        _json_location(location),
                        "URL contains authentication or tracking parameters: "
                        + ", ".join(sorted(unsafe_keys)),
                    )
                )
    return problems


def public_url_problems(path: Path, document: dict[str, Any]) -> list[ValidationProblem]:
    """Reject ephemeral or credential-bearing URLs in every public record type."""

    problems: list[ValidationProblem] = []
    for location, value in _walk(document):
        if not isinstance(value, str):
            continue
        if (
            location
            and location[-1] == "schema_id"
            and value.startswith("https://schemas.trace-the-law.invalid/")
        ):
            continue
        for match in URL_IN_TEXT_PATTERN.finditer(value):
            candidate = match.group(0)
            parsed, url_error = _split_public_http_url(candidate)
            if parsed is None:
                message = (
                    "public URL has an invalid network port"
                    if url_error == "invalid_port"
                    else "public URL is malformed or has an invalid network authority"
                )
                problems.append(
                    ValidationProblem(
                        path,
                        _json_location(location),
                        message,
                    )
                )
                continue
            username = parsed.username
            password = parsed.password
            query_keys = {
                key.lower()
                for field in (parsed.query, parsed.fragment)
                for key, _ in parse_qsl(field, keep_blank_values=True)
            }
            unsafe_keys = {
                key
                for key in query_keys
                if key in SENSITIVE_URL_QUERY_KEYS
                or key in TRACKING_URL_QUERY_KEYS
                or key.startswith("utm_")
            }
            if username is not None or password is not None:
                problems.append(
                    ValidationProblem(
                        path,
                        _json_location(location),
                        "public URLs may not contain credentials",
                    )
                )
            if _is_non_public_hostname(parsed.hostname):
                problems.append(
                    ValidationProblem(
                        path,
                        _json_location(location),
                        "public records may reference only public URL hosts",
                    )
                )
            if parsed.query or parsed.fragment:
                problems.append(
                    ValidationProblem(
                        path,
                        _json_location(location),
                        "v1 public URLs may not contain query strings or fragments because no source-specific allowlist is modeled",
                    )
                )
            if unsafe_keys:
                problems.append(
                    ValidationProblem(
                        path,
                        _json_location(location),
                        "public URL contains authentication or tracking parameters: "
                        + ", ".join(sorted(unsafe_keys)),
                    )
                )
    return problems


def artifact_identity_problems(
    path: Path, document: dict[str, Any]
) -> list[ValidationProblem]:
    """Ensure a content-addressed artifact ID agrees with its declared digest."""

    if not str(document.get("schema_id", "")).endswith("/artifact.schema.json"):
        return []

    artifact_id = document.get("artifact_id")
    digest = document.get("content_digest")
    if not isinstance(artifact_id, str) or not isinstance(digest, dict):
        return []
    problems: list[ValidationProblem] = []
    digest_value = digest.get("value")
    if isinstance(digest_value, str) and artifact_id.rsplit(":", 1)[-1] != digest_value:
        problems.append(
            ValidationProblem(
                path,
                "$.artifact_id",
                "artifact ID digest must equal content_digest.value",
            )
        )
    artifact_created_at = (
        _parse_datetime(document.get("created_at"))
        if isinstance(document.get("created_at"), str)
        else None
    )
    for index, attestation in enumerate(
        _list_or_empty(document.get("legal_scope_attestations"))
    ):
        if not isinstance(attestation, dict):
            continue
        location = f"$.legal_scope_attestations[{index}]"
        quality = document.get("quality")
        warnings = quality.get("warnings") if isinstance(quality, dict) else None
        contradictory_warnings = sorted(
            warning
            for warning in _list_or_empty(warnings)
            if isinstance(warning, str) and warning.startswith("possible_missing_")
        )
        if contradictory_warnings:
            problems.append(
                ValidationProblem(
                    path,
                    "$.quality.warnings",
                    "complete legal-scope attestation conflicts with unresolved missing-content warnings: "
                    + ", ".join(contradictory_warnings),
                )
            )
        if attestation.get("content_digest") != digest:
            problems.append(
                ValidationProblem(
                    path,
                    f"{location}.content_digest",
                    "legal-scope attestation must bind the exact artifact digest",
                )
            )
        producer = attestation.get("producer")
        review = attestation.get("review")
        reviewer = review.get("reviewer") if isinstance(review, dict) else None
        if (
            not isinstance(producer, dict)
            or not isinstance(producer.get("producer_id"), str)
            or not isinstance(reviewer, dict)
            or reviewer.get("producer_type") != "human"
            or not isinstance(reviewer.get("producer_id"), str)
            or _same_producer_identity(producer, reviewer)
        ):
            problems.append(
                ValidationProblem(
                    path,
                    f"{location}.review.reviewer",
                    "legal-scope attestation requires an independent identified human reviewer",
                )
            )
        created_at = (
            _parse_datetime(attestation.get("created_at"))
            if isinstance(attestation.get("created_at"), str)
            else None
        )
        reviewed_at = (
            _parse_datetime(review.get("reviewed_at"))
            if isinstance(review, dict)
            and isinstance(review.get("reviewed_at"), str)
            else None
        )
        if (
            created_at is None
            or reviewed_at is None
            or (artifact_created_at is not None and created_at < artifact_created_at)
            or reviewed_at < created_at
        ):
            problems.append(
                ValidationProblem(
                    path,
                    f"{location}.review.reviewed_at",
                    "legal-scope attestation cannot predate its artifact or producer decision",
                )
            )
        projection = dict(attestation)
        projected_review = dict(review) if isinstance(review, dict) else {}
        projected_review.pop("reviewed_attestation_digest", None)
        projection["review"] = projected_review
        try:
            expected_digest = hashlib.sha256(
                _canonical_json_bytes(projection)
            ).hexdigest()
        except (TypeError, UnicodeEncodeError, ValueError):
            expected_digest = None
        reviewed_digest = (
            review.get("reviewed_attestation_digest")
            if isinstance(review, dict)
            else None
        )
        if (
            not isinstance(reviewed_digest, dict)
            or reviewed_digest.get("value") != expected_digest
        ):
            problems.append(
                ValidationProblem(
                    path,
                    f"{location}.review.reviewed_attestation_digest.value",
                    "legal-scope review digest does not match the exact attestation",
                )
            )
    return problems


def storage_location_problems(
    path: Path, document: dict[str, Any]
) -> list[ValidationProblem]:
    """Prevent local or credential-bearing storage locators from appearing public."""

    if not str(document.get("schema_id", "")).endswith("/artifact.schema.json"):
        return []
    locations = document.get("storage_locations")
    if not isinstance(locations, list):
        return []
    problems: list[ValidationProblem] = []
    for index, location in enumerate(locations):
        if not isinstance(location, dict) or not isinstance(location.get("uri"), str):
            continue
        raw_uri = location["uri"]
        try:
            parsed = urlsplit(raw_uri)
            username = parsed.username
            password = parsed.password
            hostname = parsed.hostname
        except ValueError:
            problems.append(
                ValidationProblem(
                    path,
                    f"$.storage_locations[{index}].uri",
                    "storage URI is malformed",
                )
            )
            continue
        if username is not None or password is not None:
            problems.append(
                ValidationProblem(
                    path,
                    f"$.storage_locations[{index}].uri",
                    "storage URI may not contain credentials",
                )
            )
        query_keys = {
            key.lower()
            for field in (parsed.query, parsed.fragment)
            for key, _ in parse_qsl(field, keep_blank_values=True)
        }
        unsafe_keys = {
            key
            for key in query_keys
            if key in SENSITIVE_URL_QUERY_KEYS
            or key in TRACKING_URL_QUERY_KEYS
            or key.startswith("utm_")
        }
        if unsafe_keys:
            problems.append(
                ValidationProblem(
                    path,
                    f"$.storage_locations[{index}].uri",
                    "storage URI contains authentication or tracking parameters: "
                    + ", ".join(sorted(unsafe_keys)),
                )
            )
        if parsed.scheme == "file":
            problems.append(
                ValidationProblem(
                    path,
                    f"$.storage_locations[{index}].uri",
                    "storage URI may not expose a local file path",
                )
            )
        if location.get("access") == "public":
            if parsed.scheme not in {"http", "https", "ipfs"}:
                problems.append(
                    ValidationProblem(
                        path,
                        f"$.storage_locations[{index}].uri",
                        "public storage must use an externally retrievable HTTP(S) or IPFS URI",
                    )
                )
            elif parsed.scheme in {"http", "https"} and _is_non_public_hostname(hostname):
                problems.append(
                    ValidationProblem(
                        path,
                        f"$.storage_locations[{index}].uri",
                        "public storage URI must use a public host",
                    )
                )
    return problems


def _duplicate_value_problems(
    path: Path,
    items: Any,
    field: str,
    location: str,
) -> list[ValidationProblem]:
    if not isinstance(items, list):
        return []
    first_index: dict[Any, int] = {}
    problems: list[ValidationProblem] = []
    for index, item in enumerate(items):
        if not isinstance(item, dict) or field not in item:
            continue
        value = item[field]
        try:
            earlier = first_index.get(value)
        except TypeError:
            continue
        if earlier is None:
            first_index[value] = index
            continue
        problems.append(
            ValidationProblem(
                path,
                f"{location}[{index}].{field}",
                f"duplicates {location}[{earlier}].{field}",
            )
        )
    return problems


def collection_identity_problems(
    path: Path, document: dict[str, Any]
) -> list[ValidationProblem]:
    """Reject duplicate stable identities hidden inside different objects."""

    schema_id = str(document.get("schema_id", ""))
    checks: list[tuple[Any, str, str]] = []
    if schema_id.endswith("/source-manifest.schema.json"):
        checks.append((document.get("entrypoints"), "entrypoint_id", "$.entrypoints"))
    elif schema_id.endswith("/record.schema.json"):
        versions = document.get("versions")
        checks.append(
            (
                document.get("authority_relationships"),
                "assertion_id",
                "$.authority_relationships",
            )
        )
        checks.append((versions, "version_id", "$.versions"))
        if isinstance(versions, list):
            provision_versions: list[Any] = []
            for version_index, version in enumerate(versions):
                if not isinstance(version, dict):
                    continue
                provisions = version.get("provisions")
                checks.append(
                    (
                        provisions,
                        "provision_id",
                        f"$.versions[{version_index}].provisions",
                    )
                )
                if isinstance(provisions, list):
                    provision_versions.extend(provisions)
            checks.append(
                (provision_versions, "provision_version_id", "$.versions[*].provisions")
            )
    elif schema_id.endswith("/coverage-ledger.schema.json"):
        checks.extend(
            [
                (document.get("enumeration_runs"), "run_id", "$.enumeration_runs"),
                (document.get("known_gaps"), "gap_id", "$.known_gaps"),
            ]
        )
    elif schema_id.endswith("/evidence-bundle.schema.json"):
        checks.extend(
            [
                (document.get("claims"), "claim_id", "$.claims"),
                (document.get("coverage"), "coverage_id", "$.coverage"),
                (
                    document.get("verification_tasks"),
                    "verification_task_id",
                    "$.verification_tasks",
                ),
            ]
        )
    elif schema_id.endswith("/invalidation-event.schema.json"):
        checks.append((document.get("rebuilds"), "component", "$.rebuilds"))
    elif schema_id.endswith("/derivation.schema.json"):
        checks.append((document.get("input_artifacts"), "role", "$.input_artifacts"))

    problems: list[ValidationProblem] = []
    for items, field, location in checks:
        problems.extend(_duplicate_value_problems(path, items, field, location))
    return problems


def _field_text_variants(value: str) -> set[str]:
    """Return normalized whole-field forms without exposing substring matches."""

    wrapper_pairs = {
        "\"": "\"",
        "'": "'",
        "\u2018": "\u2019",
        "\u201c": "\u201d",
        "(": ")",
        "[": "]",
        "{": "}",
    }
    terminal_punctuation = ".;!?\u2026\u3002\u0964\u061b"
    candidates: set[str] = set()
    pending = [value.strip()]
    while pending:
        candidate = pending.pop()
        if candidate in candidates:
            continue
        candidates.add(candidate)
        if candidate and candidate[-1] in terminal_punctuation:
            pending.append(candidate[:-1].rstrip())
        if (
            len(candidate) >= 2
            and candidate[0] in wrapper_pairs
            and candidate[-1] == wrapper_pairs[candidate[0]]
        ):
            pending.append(candidate[1:-1].strip())
    return {" ".join(candidate.casefold().split()) for candidate in candidates}


def _quote_has_exact_field_value(
    quoted_text: str,
    expected_text: str,
    *,
    field: str,
    source_prefixes: Iterable[str] = (),
) -> bool:
    """Require a whole cited field, not an arbitrary substring of one."""

    expected = " ".join(expected_text.casefold().split())
    if not expected:
        return False
    labels = {
        "canonical_title": ("canonical title", "short title", "title"),
        "identifier": ("identifier", "short title", "title"),
        "heading": ("heading",),
    }.get(field, ())
    normalized_prefixes = [
        prefix.strip()
        for prefix in source_prefixes
        if isinstance(prefix, str) and prefix.strip()
    ]

    for line in quoted_text.splitlines():
        line = line.strip()
        if not line:
            continue
        candidates = {line}
        for label in labels:
            match = re.match(
                rf"^{re.escape(label)}\s*[:=\t]\s*(?P<value>.+)$",
                line,
                re.IGNORECASE,
            )
            if match is not None:
                candidates.add(match.group("value"))
        if field == "heading":
            for prefix in normalized_prefixes:
                if not line.startswith(prefix):
                    continue
                remainder = line[len(prefix) :]
                if not remainder:
                    candidates.add(remainder)
                elif remainder[0].isspace() or remainder[0] in ".:)-\u2014":
                    candidates.add(remainder.lstrip(" \t.:)-\u2014"))
        if any(expected in _field_text_variants(candidate) for candidate in candidates):
            return True
    return False


def _is_minimal_public_temporal_fact_quote(citation: dict[str, Any]) -> bool:
    """Recognize a canonical date token, not a copied source passage."""

    binding = citation.get("temporal_value_binding")
    quoted_text = citation.get("quoted_text")
    if not isinstance(binding, dict) or not isinstance(quoted_text, str):
        return False
    source_value = binding.get("source_value")
    normalized_value = binding.get("normalized_value")
    if (
        binding.get("method") != "source_exact"
        or not isinstance(source_value, str)
        or source_value != normalized_value
        or quoted_text.strip() != source_value
    ):
        return False
    return any(
        pattern.fullmatch(source_value) is not None
        for pattern in PRECISION_PATTERNS.values()
    )


def record_semantic_problems(
    path: Path, document: dict[str, Any]
) -> list[ValidationProblem]:
    """Bind record metadata and provision digests to their declared passages."""

    if not str(document.get("schema_id", "")).endswith("/record.schema.json"):
        return []
    problems: list[ValidationProblem] = []
    evidence = document.get("metadata_evidence")
    bindings = document.get("metadata_bindings")
    identifiers = document.get("identifiers")
    evidence_items = evidence if isinstance(evidence, list) else []
    binding_items = bindings if isinstance(bindings, list) else []
    identifier_items = identifiers if isinstance(identifiers, list) else []

    covered_fields: set[str] = set()
    covered_identifier_indexes: set[int] = set()
    used_evidence_indexes: set[int] = set()
    seen_binding_keys: set[tuple[Any, Any]] = set()

    declared_jurisdictions = {
        jurisdiction_id
        for jurisdiction_id in _list_or_empty(document.get("jurisdiction_ids"))
        if isinstance(jurisdiction_id, str)
    }
    reviewed_jurisdictions: set[str] = set()
    seen_jurisdiction_bindings: set[str] = set()
    for index, binding in enumerate(
        _list_or_empty(document.get("jurisdiction_bindings"))
    ):
        if not isinstance(binding, dict):
            continue
        location = f"$.jurisdiction_bindings[{index}]"
        jurisdiction_id = binding.get("jurisdiction_id")
        if isinstance(jurisdiction_id, str):
            if jurisdiction_id in seen_jurisdiction_bindings:
                problems.append(
                    ValidationProblem(
                        path,
                        f"{location}.jurisdiction_id",
                        "record jurisdiction has more than one jurisdiction binding",
                    )
                )
            seen_jurisdiction_bindings.add(jurisdiction_id)
            if jurisdiction_id not in declared_jurisdictions:
                problems.append(
                    ValidationProblem(
                        path,
                        f"{location}.jurisdiction_id",
                        "jurisdiction binding does not match a declared record jurisdiction",
                    )
                )
        selected_evidence_times: list[datetime] = []
        evidence_is_resolved = True
        for evidence_position, evidence_index in enumerate(
            _list_or_empty(binding.get("evidence_indexes"))
        ):
            if (
                not isinstance(evidence_index, int)
                or isinstance(evidence_index, bool)
                or not 0 <= evidence_index < len(evidence_items)
            ):
                evidence_is_resolved = False
                problems.append(
                    ValidationProblem(
                        path,
                        f"{location}.evidence_indexes[{evidence_position}]",
                        "jurisdiction evidence index is outside metadata_evidence",
                    )
                )
                continue
            used_evidence_indexes.add(evidence_index)
            citation = evidence_items[evidence_index]
            if not isinstance(citation, dict):
                evidence_is_resolved = False
                continue
            # Cross-document validation later proves the citation comes from a
            # reviewed official source for this same jurisdiction.
        producer = binding.get("producer")
        review = binding.get("normalization_review")
        reviewer = review.get("reviewer") if isinstance(review, dict) else None
        independently_reviewed = (
            isinstance(producer, dict)
            and isinstance(producer.get("producer_id"), str)
            and isinstance(reviewer, dict)
            and reviewer.get("producer_type") == "human"
            and isinstance(reviewer.get("producer_id"), str)
            and not _same_producer_identity(producer, reviewer)
        )
        created_at = (
            _parse_datetime(binding.get("created_at"))
            if isinstance(binding.get("created_at"), str)
            else None
        )
        reviewed_at = (
            _parse_datetime(review.get("reviewed_at"))
            if isinstance(review, dict)
            and isinstance(review.get("reviewed_at"), str)
            else None
        )
        record_created_at = (
            _parse_datetime(document.get("created_at"))
            if isinstance(document.get("created_at"), str)
            else None
        )
        record_updated_at = (
            _parse_datetime(document.get("updated_at"))
            if isinstance(document.get("updated_at"), str)
            else None
        )
        chronology_valid = (
            created_at is not None
            and reviewed_at is not None
            and (record_created_at is None or created_at >= record_created_at)
            and reviewed_at >= created_at
            and (record_updated_at is None or record_updated_at >= reviewed_at)
            and all(reviewed_at >= value for value in selected_evidence_times)
        )
        projection = dict(binding)
        projected_review = dict(review) if isinstance(review, dict) else {}
        projected_review.pop("reviewed_binding_digest", None)
        projection["normalization_review"] = projected_review
        try:
            expected_digest = hashlib.sha256(
                _canonical_json_bytes(projection)
            ).hexdigest()
        except (TypeError, UnicodeEncodeError, ValueError):
            expected_digest = None
        reviewed_digest = (
            review.get("reviewed_binding_digest")
            if isinstance(review, dict)
            else None
        )
        digest_valid = (
            isinstance(reviewed_digest, dict)
            and reviewed_digest.get("algorithm") == "sha256"
            and reviewed_digest.get("value") == expected_digest
        )
        if not independently_reviewed:
            problems.append(
                ValidationProblem(
                    path,
                    f"{location}.normalization_review.reviewer",
                    "record jurisdiction mapping requires an independent identified human reviewer",
                )
            )
        if not chronology_valid:
            problems.append(
                ValidationProblem(
                    path,
                    f"{location}.normalization_review.reviewed_at",
                    "record jurisdiction mapping review chronology is invalid",
                )
            )
        if not digest_valid:
            problems.append(
                ValidationProblem(
                    path,
                    f"{location}.normalization_review.reviewed_binding_digest.value",
                    "record jurisdiction review digest does not match the exact binding",
                )
            )
        if (
            isinstance(jurisdiction_id, str)
            and evidence_is_resolved
            and independently_reviewed
            and chronology_valid
            and digest_valid
        ):
            reviewed_jurisdictions.add(jurisdiction_id)

    missing_jurisdiction_bindings = sorted(
        declared_jurisdictions - reviewed_jurisdictions
    )
    if missing_jurisdiction_bindings:
        problems.append(
            ValidationProblem(
                path,
                "$.jurisdiction_bindings",
                "record jurisdictions lack exact independently reviewed bindings: "
                + ", ".join(missing_jurisdiction_bindings),
            )
        )

    def validate_non_kind_record_binding_review(
        index: int, binding: dict[str, Any]
    ) -> None:
        normalization_review = binding.get("normalization_review")
        location = f"$.metadata_bindings[{index}]"
        if not isinstance(normalization_review, dict):
            return
        producer = binding.get("producer")
        reviewer = normalization_review.get("reviewer")
        if (
            not isinstance(reviewer, dict)
            or reviewer.get("producer_type") != "human"
            or not isinstance(reviewer.get("producer_id"), str)
            or _same_producer_identity(producer, reviewer)
        ):
            problems.append(
                ValidationProblem(
                    path,
                    f"{location}.normalization_review.reviewer",
                    "record metadata binding requires an independent identified human reviewer",
                )
            )
        binding_created_at = (
            _parse_datetime(binding.get("created_at"))
            if isinstance(binding.get("created_at"), str)
            else None
        )
        reviewed_at = (
            _parse_datetime(normalization_review.get("reviewed_at"))
            if isinstance(normalization_review.get("reviewed_at"), str)
            else None
        )
        record_created_at = (
            _parse_datetime(document.get("created_at"))
            if isinstance(document.get("created_at"), str)
            else None
        )
        record_updated_at = (
            _parse_datetime(document.get("updated_at"))
            if isinstance(document.get("updated_at"), str)
            else None
        )
        if (
            binding_created_at is None
            or reviewed_at is None
            or (record_created_at is not None and binding_created_at < record_created_at)
            or reviewed_at < binding_created_at
            or (record_updated_at is not None and record_updated_at < reviewed_at)
        ):
            problems.append(
                ValidationProblem(
                    path,
                    f"{location}.normalization_review.reviewed_at",
                    "record metadata review chronology is invalid",
                )
            )
        projection = dict(binding)
        projected_review = dict(normalization_review)
        projected_review.pop("reviewed_binding_digest", None)
        projection["normalization_review"] = projected_review
        try:
            actual_digest = hashlib.sha256(
                _canonical_json_bytes(projection)
            ).hexdigest()
        except (TypeError, UnicodeEncodeError, ValueError):
            actual_digest = None
        reviewed_digest = normalization_review.get("reviewed_binding_digest")
        if (
            not isinstance(reviewed_digest, dict)
            or reviewed_digest.get("value") != actual_digest
        ):
            problems.append(
                ValidationProblem(
                    path,
                    f"{location}.normalization_review.reviewed_binding_digest.value",
                    "record metadata review digest does not match the exact binding",
                )
            )

    for index, binding in enumerate(binding_items):
        if not isinstance(binding, dict):
            continue
        field = binding.get("field")
        evidence_indexes = binding.get("evidence_indexes")
        if isinstance(field, str):
            covered_fields.add(field)
        identifier_index = binding.get("identifier_index")
        binding_key = (
            field,
            identifier_index if field == "identifier" else None,
        )
        if binding_key in seen_binding_keys:
            problems.append(
                ValidationProblem(
                    path,
                    f"$.metadata_bindings[{index}]",
                    "record metadata field has more than one evidence binding",
                )
            )
        else:
            seen_binding_keys.add(binding_key)
        if field == "identifier" and isinstance(identifier_index, int):
            if 0 <= identifier_index < len(identifier_items):
                covered_identifier_indexes.add(identifier_index)
            else:
                problems.append(
                    ValidationProblem(
                        path,
                        f"$.metadata_bindings[{index}].identifier_index",
                        "metadata identifier index is outside identifiers",
                    )
                )
        selected_quotes: list[str] = []
        selected_digest_bound = False
        selected_digest_values: set[str] = set()
        if isinstance(evidence_indexes, list):
            for evidence_index_index, evidence_index in enumerate(evidence_indexes):
                if not isinstance(evidence_index, int) or not 0 <= evidence_index < len(
                    evidence_items
                ):
                    problems.append(
                        ValidationProblem(
                            path,
                            f"$.metadata_bindings[{index}].evidence_indexes[{evidence_index_index}]",
                            "metadata evidence index is outside metadata_evidence",
                        )
                    )
                    continue
                citation = evidence_items[evidence_index]
                used_evidence_indexes.add(evidence_index)
                quoted_text = (
                    citation.get("quoted_text") if isinstance(citation, dict) else None
                )
                if isinstance(quoted_text, str):
                    selected_quotes.append(quoted_text)
                elif isinstance(citation, dict) and isinstance(
                    citation.get("quoted_text_digest"), dict
                ):
                    digest_value = citation["quoted_text_digest"].get("value")
                    if isinstance(digest_value, str):
                        selected_digest_values.add(digest_value)
        expected_text: Any = None
        if field == "canonical_title":
            expected_text = document.get("canonical_title")
        elif (
            field == "identifier"
            and isinstance(identifier_index, int)
            and 0 <= identifier_index < len(identifier_items)
            and isinstance(identifier_items[identifier_index], dict)
        ):
            expected_text = identifier_items[identifier_index].get("value")
        elif field == "record_kind":
            source_value = binding.get("source_value")
            selected_digest_bound = (
                isinstance(source_value, str)
                and hashlib.sha256(source_value.encode("utf-8")).hexdigest()
                in selected_digest_values
            )
            normalized_value = binding.get("normalized_value")
            if normalized_value != document.get("record_kind"):
                problems.append(
                    ValidationProblem(
                        path,
                        f"$.metadata_bindings[{index}].normalized_value",
                        "record_kind does not match its evidence binding's normalized value",
                    )
                )
            if isinstance(source_value, str):
                normalized_source = " ".join(source_value.casefold().split())
                if not normalized_source or not (
                    selected_digest_bound
                    or any(
                    normalized_source in " ".join(quote.casefold().split())
                    for quote in selected_quotes
                    )
                ):
                    problems.append(
                        ValidationProblem(
                            path,
                            f"$.metadata_bindings[{index}].source_value",
                            "record_kind source value is not present in its cited public text",
                        )
                    )
            binding_created_at = (
                _parse_datetime(binding.get("created_at"))
                if isinstance(binding.get("created_at"), str)
                else None
            )
            normalization_review = binding.get("normalization_review")
            if isinstance(normalization_review, dict):
                reviewed_at = (
                    _parse_datetime(normalization_review.get("reviewed_at"))
                    if isinstance(normalization_review.get("reviewed_at"), str)
                    else None
                )
                producer = binding.get("producer")
                reviewer = normalization_review.get("reviewer")
                producer_id = (
                    producer.get("producer_id")
                    if isinstance(producer, dict)
                    else None
                )
                reviewer_id = (
                    reviewer.get("producer_id")
                    if isinstance(reviewer, dict)
                    else None
                )
                if (
                    isinstance(producer_id, str)
                    and isinstance(reviewer_id, str)
                    and producer_id == reviewer_id
                ):
                    problems.append(
                        ValidationProblem(
                            path,
                            f"$.metadata_bindings[{index}].normalization_review.reviewer",
                            "record-kind producer may not approve its own normalization",
                        )
                    )
                if (
                    binding_created_at is not None
                    and reviewed_at is not None
                    and reviewed_at < binding_created_at
                ):
                    problems.append(
                        ValidationProblem(
                            path,
                            f"$.metadata_bindings[{index}].normalization_review.reviewed_at",
                            "record-kind normalization review cannot predate the binding",
                        )
                    )
                record_created_at = (
                    _parse_datetime(document.get("created_at"))
                    if isinstance(document.get("created_at"), str)
                    else None
                )
                record_updated_at = (
                    _parse_datetime(document.get("updated_at"))
                    if isinstance(document.get("updated_at"), str)
                    else None
                )
                if (
                    record_created_at is not None
                    and binding_created_at is not None
                    and binding_created_at < record_created_at
                ):
                    problems.append(
                        ValidationProblem(
                            path,
                            f"$.metadata_bindings[{index}].created_at",
                            "record-kind normalization cannot predate the record",
                        )
                    )
                if (
                    record_updated_at is not None
                    and reviewed_at is not None
                    and record_updated_at < reviewed_at
                ):
                    problems.append(
                        ValidationProblem(
                            path,
                            "$.updated_at",
                            "record update time cannot predate its normalization review",
                        )
                    )
                projected_binding = dict(binding)
                projected_review = dict(normalization_review)
                projected_review.pop("reviewed_binding_digest", None)
                projected_binding["normalization_review"] = projected_review
                try:
                    actual_digest = hashlib.sha256(
                        _canonical_json_bytes(projected_binding)
                    ).hexdigest()
                except (TypeError, UnicodeEncodeError, ValueError) as error:
                    problems.append(
                        ValidationProblem(
                            path,
                            f"$.metadata_bindings[{index}].normalization_review.reviewed_binding_digest",
                            f"record-kind binding cannot be canonicalized: {error}",
                        )
                    )
                else:
                    reviewed_digest = normalization_review.get(
                        "reviewed_binding_digest"
                    )
                    declared_digest = (
                        reviewed_digest.get("value")
                        if isinstance(reviewed_digest, dict)
                        else None
                    )
                    if declared_digest != actual_digest:
                        problems.append(
                            ValidationProblem(
                                path,
                                f"$.metadata_bindings[{index}].normalization_review.reviewed_binding_digest.value",
                                "record-kind review digest does not match the exact normalized binding",
                            )
                        )
        if field != "record_kind":
            source_value = binding.get("source_value")
            selected_digest_bound = (
                isinstance(source_value, str)
                and hashlib.sha256(source_value.encode("utf-8")).hexdigest()
                in selected_digest_values
            )
            if isinstance(expected_text, str) and binding.get(
                "normalized_value"
            ) != expected_text:
                problems.append(
                    ValidationProblem(
                        path,
                        f"$.metadata_bindings[{index}].normalized_value",
                        f"{field} does not match its evidence binding's normalized value",
                    )
                )
            validate_non_kind_record_binding_review(index, binding)
        if isinstance(expected_text, str):
            if not selected_digest_bound and not any(
                _quote_has_exact_field_value(
                    quote,
                    expected_text,
                    field=field,
                )
                for quote in selected_quotes
            ):
                problems.append(
                    ValidationProblem(
                        path,
                        f"$.metadata_bindings[{index}]",
                        f"{field} value is not present in its cited public text at an exact field boundary",
                    )
                )
        elif field == "record_kind" and not selected_quotes and not selected_digest_bound:
            problems.append(
                ValidationProblem(
                    path,
                    f"$.metadata_bindings[{index}]",
                    "record_kind evidence binding requires quoted public text",
                )
            )

    for field in ("canonical_title", "record_kind"):
        if field not in covered_fields:
            problems.append(
                ValidationProblem(
                    path,
                    "$.metadata_bindings",
                    f"record metadata has no evidence binding for {field}",
                )
            )
    missing_identifiers = sorted(set(range(len(identifier_items))) - covered_identifier_indexes)
    if missing_identifiers:
        problems.append(
            ValidationProblem(
                path,
                "$.metadata_bindings",
                "record identifiers lack evidence bindings at indexes: "
                + ", ".join(map(str, missing_identifiers)),
            )
        )
    unused_evidence = sorted(set(range(len(evidence_items))) - used_evidence_indexes)
    if unused_evidence:
        problems.append(
            ValidationProblem(
                path,
                "$.metadata_evidence",
                "record contains metadata evidence unused by every binding at indexes: "
                + ", ".join(map(str, unused_evidence)),
            )
        )

    versions = document.get("versions")
    if not isinstance(versions, list):
        return problems

    def check_publication_evidence(
        base_location: str,
        time_axes: Any,
        publication_evidence: Any,
    ) -> None:
        publication = time_axes.get("publication") if isinstance(time_axes, dict) else None
        if not isinstance(publication, dict) or publication.get("status") not in {
            "exact",
            "approximate",
        }:
            return
        verbatim = publication.get("verbatim_value")
        normalized_value = publication.get("value")
        citations = publication_evidence if isinstance(publication_evidence, list) else []
        matching_binding = False
        for evidence_index, citation in enumerate(citations):
            if not isinstance(citation, dict):
                continue
            binding = citation.get("temporal_value_binding")
            if not isinstance(binding, dict):
                continue
            source_value = binding.get("source_value")
            binding_value = binding.get("normalized_value")
            quoted_text = citation.get("quoted_text")
            quoted_digest = citation.get("quoted_text_digest")
            location = (
                f"{base_location}.publication_evidence[{evidence_index}]"
                ".temporal_value_binding"
            )
            source_matches = source_value == verbatim
            normalized_matches = binding_value == normalized_value
            if isinstance(source_value, str) and isinstance(quoted_text, str):
                content_matches = " ".join(source_value.casefold().split()) in " ".join(
                    quoted_text.casefold().split()
                )
            elif isinstance(source_value, str) and isinstance(quoted_digest, dict):
                content_matches = quoted_digest.get("value") == hashlib.sha256(
                    source_value.encode("utf-8")
                ).hexdigest()
            else:
                content_matches = False
            if not source_matches:
                problems.append(
                    ValidationProblem(
                        path,
                        f"{location}.source_value",
                        "publication temporal binding must match time_axes.publication.verbatim_value",
                    )
                )
            if not normalized_matches:
                problems.append(
                    ValidationProblem(
                        path,
                        f"{location}.normalized_value",
                        "publication temporal binding normalized_value must match time_axes.publication.value",
                    )
                )
            if not content_matches:
                problems.append(
                    ValidationProblem(
                        path,
                        f"{location}.source_value",
                        "publication temporal source value is not bound to its cited text or exact text digest",
                    )
                )
            if (
                binding.get("method") == "source_exact"
                and source_value != binding_value
            ):
                problems.append(
                    ValidationProblem(
                        path,
                        f"{location}.method",
                        "source_exact temporal normalization requires identical source and normalized values",
                    )
                )
            producer = binding.get("producer")
            reviewer = binding.get("reviewer")
            if (
                isinstance(producer, dict)
                and isinstance(reviewer, dict)
                and _producer_identity(producer) is not None
                and _producer_identity(producer) == _producer_identity(reviewer)
            ):
                problems.append(
                    ValidationProblem(
                        path,
                        f"{location}.reviewer",
                        "a temporal normalization producer may not approve the same normalization",
                    )
                )
            created_at = (
                _parse_datetime(binding.get("created_at"))
                if isinstance(binding.get("created_at"), str)
                else None
            )
            reviewed_at = (
                _parse_datetime(binding.get("reviewed_at"))
                if isinstance(binding.get("reviewed_at"), str)
                else None
            )
            if (
                created_at is not None
                and reviewed_at is not None
                and reviewed_at < created_at
            ):
                problems.append(
                    ValidationProblem(
                        path,
                        f"{location}.reviewed_at",
                        "temporal normalization review cannot predate its creation",
                    )
                )
            matching_binding = matching_binding or (
                source_matches and normalized_matches and content_matches
            )
        if not matching_binding:
            problems.append(
                ValidationProblem(
                    path,
                    f"{base_location}.publication_evidence",
                    "publication time lacks an exact source-to-normalized temporal binding",
                )
            )

    def check_version_metadata(
        version_location: str,
        version: dict[str, Any],
    ) -> None:
        version_evidence = version.get("metadata_evidence")
        evidence_items = version_evidence if isinstance(version_evidence, list) else []
        version_bindings = version.get("metadata_bindings")
        binding_items = version_bindings if isinstance(version_bindings, list) else []
        artifact_ids = {
            artifact_id
            for artifact_id in _list_or_empty(version.get("artifact_ids"))
            if isinstance(artifact_id, str)
        }
        covered_fields: set[str] = set()
        used_evidence_indexes: set[int] = set()
        record_created_at = (
            _parse_datetime(document.get("created_at"))
            if isinstance(document.get("created_at"), str)
            else None
        )
        record_updated_at = (
            _parse_datetime(document.get("updated_at"))
            if isinstance(document.get("updated_at"), str)
            else None
        )
        for binding_index, binding in enumerate(binding_items):
            if not isinstance(binding, dict):
                continue
            binding_location = (
                f"{version_location}.metadata_bindings[{binding_index}]"
            )
            field = binding.get("field")
            if isinstance(field, str):
                if field in covered_fields:
                    problems.append(
                        ValidationProblem(
                            path,
                            binding_location,
                            "record-version metadata field has more than one evidence binding",
                        )
                    )
                covered_fields.add(field)
            selected_quotes: list[str] = []
            selected_digest_bound = False
            selected_digest_values: set[str] = set()
            for evidence_index_index, evidence_index in enumerate(
                _list_or_empty(binding.get("evidence_indexes"))
            ):
                if (
                    not isinstance(evidence_index, int)
                    or isinstance(evidence_index, bool)
                    or not 0 <= evidence_index < len(evidence_items)
                ):
                    problems.append(
                        ValidationProblem(
                            path,
                            f"{binding_location}.evidence_indexes[{evidence_index_index}]",
                            "record-version metadata evidence index is outside metadata_evidence",
                        )
                    )
                    continue
                citation = evidence_items[evidence_index]
                used_evidence_indexes.add(evidence_index)
                if not isinstance(citation, dict):
                    continue
                if citation.get("artifact_id") not in artifact_ids:
                    problems.append(
                        ValidationProblem(
                            path,
                            f"{binding_location}.evidence_indexes[{evidence_index_index}]",
                            "record-version metadata must cite an artifact of this exact version",
                        )
                    )
                quoted_text = citation.get("quoted_text")
                if isinstance(quoted_text, str):
                    selected_quotes.append(quoted_text)
                elif isinstance(citation.get("quoted_text_digest"), dict):
                    digest_value = citation["quoted_text_digest"].get("value")
                    if isinstance(digest_value, str):
                        selected_digest_values.add(digest_value)

            source_value = binding.get("source_value")
            selected_digest_bound = (
                isinstance(source_value, str)
                and hashlib.sha256(source_value.encode("utf-8")).hexdigest()
                in selected_digest_values
            )
            normalized_value = binding.get("normalized_value")
            if isinstance(field, str) and normalized_value != version.get(field):
                problems.append(
                    ValidationProblem(
                        path,
                        f"{binding_location}.normalized_value",
                        "record-version metadata does not match its binding's normalized value",
                    )
                )
            if not isinstance(source_value, str) or not (
                selected_digest_bound
                or any(
                    _quote_has_exact_field_value(
                        quote,
                        source_value,
                        field="version_metadata",
                    )
                    for quote in selected_quotes
                )
            ):
                problems.append(
                    ValidationProblem(
                        path,
                        f"{binding_location}.source_value",
                        "record-version metadata source value is not present at an exact field boundary in its selected quoted text",
                    )
                )
            if (
                binding.get("method") == "source_exact"
                and source_value != normalized_value
            ):
                problems.append(
                    ValidationProblem(
                        path,
                        f"{binding_location}.method",
                        "source_exact record-version metadata requires identical source and normalized values",
                    )
                )
            binding_created_at = (
                _parse_datetime(binding.get("created_at"))
                if isinstance(binding.get("created_at"), str)
                else None
            )
            if (
                binding_created_at is not None
                and record_created_at is not None
                and binding_created_at < record_created_at
            ):
                problems.append(
                    ValidationProblem(
                        path,
                        f"{binding_location}.created_at",
                        "record-version metadata binding cannot predate the record",
                    )
                )
            if (
                binding_created_at is not None
                and record_updated_at is not None
                and record_updated_at < binding_created_at
            ):
                problems.append(
                    ValidationProblem(
                        path,
                        "$.updated_at",
                        "record update time cannot predate its version metadata binding",
                    )
                )
            normalization_review = binding.get("normalization_review")
            if not isinstance(normalization_review, dict):
                continue
            reviewer = normalization_review.get("reviewer")
            if _same_producer_identity(binding.get("producer"), reviewer):
                problems.append(
                    ValidationProblem(
                        path,
                        f"{binding_location}.normalization_review.reviewer",
                        "record-version metadata producer may not approve its own normalization",
                    )
                )
            reviewed_at = (
                _parse_datetime(normalization_review.get("reviewed_at"))
                if isinstance(normalization_review.get("reviewed_at"), str)
                else None
            )
            if (
                binding_created_at is not None
                and reviewed_at is not None
                and reviewed_at < binding_created_at
            ):
                problems.append(
                    ValidationProblem(
                        path,
                        f"{binding_location}.normalization_review.reviewed_at",
                        "record-version metadata review cannot predate its binding",
                    )
                )
            if (
                record_updated_at is not None
                and reviewed_at is not None
                and record_updated_at < reviewed_at
            ):
                problems.append(
                    ValidationProblem(
                        path,
                        "$.updated_at",
                        "record update time cannot predate its version metadata review",
                    )
                )
            projected_binding = dict(binding)
            projected_review = dict(normalization_review)
            projected_review.pop("reviewed_binding_digest", None)
            projected_binding["normalization_review"] = projected_review
            try:
                actual_digest = hashlib.sha256(
                    _canonical_json_bytes(projected_binding)
                ).hexdigest()
            except (TypeError, UnicodeEncodeError, ValueError) as error:
                problems.append(
                    ValidationProblem(
                        path,
                        f"{binding_location}.normalization_review.reviewed_binding_digest",
                        f"record-version metadata binding cannot be canonicalized: {error}",
                    )
                )
            else:
                reviewed_digest = normalization_review.get(
                    "reviewed_binding_digest"
                )
                declared_digest = (
                    reviewed_digest.get("value")
                    if isinstance(reviewed_digest, dict)
                    else None
                )
                if declared_digest != actual_digest:
                    problems.append(
                        ValidationProblem(
                            path,
                            f"{binding_location}.normalization_review.reviewed_binding_digest.value",
                            "record-version metadata review digest does not match the exact binding",
                        )
                    )

        missing_fields = sorted(
            {"version_kind", "language", "publication_state"} - covered_fields
        )
        if missing_fields:
            problems.append(
                ValidationProblem(
                    path,
                    f"{version_location}.metadata_bindings",
                    "record-version metadata lacks evidence bindings for: "
                    + ", ".join(missing_fields),
                )
            )
        unused_evidence = sorted(
            set(range(len(evidence_items))) - used_evidence_indexes
        )
        if unused_evidence:
            problems.append(
                ValidationProblem(
                    path,
                    f"{version_location}.metadata_evidence",
                    "record-version contains metadata evidence unused by every binding at indexes: "
                    + ", ".join(map(str, unused_evidence)),
                )
            )

    for version_index, version in enumerate(versions):
        if not isinstance(version, dict):
            continue
        version_location = f"$.versions[{version_index}]"
        check_version_metadata(version_location, version)
        check_publication_evidence(
            version_location,
            version.get("time_axes"),
            version.get("publication_evidence"),
        )
        provisions = version.get("provisions")
        if not isinstance(provisions, list):
            continue
        for provision_index, provision in enumerate(provisions):
            if not isinstance(provision, dict):
                continue
            provision_location = f"{version_location}.provisions[{provision_index}]"
            check_publication_evidence(
                provision_location,
                provision.get("time_axes"),
                provision.get("publication_evidence"),
            )
            text_citations = provision.get("text_citations")
            citation_items = (
                text_citations if isinstance(text_citations, list) else []
            )
            provision_bindings = provision.get("metadata_bindings")
            binding_items = (
                provision_bindings if isinstance(provision_bindings, list) else []
            )
            designation_prefixes: list[str] = []
            for candidate in binding_items:
                if (
                    not isinstance(candidate, dict)
                    or candidate.get("field") != "designation"
                ):
                    continue
                source_designation = candidate.get("source_value")
                normalized_designation = candidate.get("normalized_value")
                if not isinstance(source_designation, str) or not isinstance(
                    normalized_designation, str
                ):
                    continue
                source_words = re.findall(r"[\w\u00a7]+", source_designation.casefold())
                normalized_words = re.findall(
                    r"[\w\u00a7]+", normalized_designation.casefold()
                )
                if source_words == normalized_words or (
                    normalized_words and source_words == normalized_words[-1:]
                ):
                    designation_prefixes.append(source_designation)
            covered_provision_fields: set[str] = set()
            used_provision_citation_indexes: set[int] = set()
            for binding_index, binding in enumerate(binding_items):
                if not isinstance(binding, dict):
                    continue
                binding_location = (
                    f"{provision_location}.metadata_bindings[{binding_index}]"
                )
                field = binding.get("field")
                if isinstance(field, str):
                    if field in covered_provision_fields:
                        problems.append(
                            ValidationProblem(
                                path,
                                binding_location,
                                "provision metadata field has more than one evidence binding",
                            )
                        )
                    covered_provision_fields.add(field)
                selected_quotes: list[str] = []
                selected_digest_bound = False
                selected_digest_values: set[str] = set()
                for evidence_index_index, evidence_index in enumerate(
                    _list_or_empty(binding.get("evidence_indexes"))
                ):
                    if (
                        not isinstance(evidence_index, int)
                        or not 0 <= evidence_index < len(citation_items)
                    ):
                        problems.append(
                            ValidationProblem(
                                path,
                                f"{binding_location}.evidence_indexes[{evidence_index_index}]",
                                "provision metadata evidence index is outside text_citations",
                            )
                        )
                        continue
                    citation = citation_items[evidence_index]
                    used_provision_citation_indexes.add(evidence_index)
                    quoted_text = (
                        citation.get("quoted_text")
                        if isinstance(citation, dict)
                        else None
                    )
                    if isinstance(quoted_text, str):
                        selected_quotes.append(quoted_text)
                    elif isinstance(citation, dict) and isinstance(
                        citation.get("quoted_text_digest"), dict
                    ):
                        digest_value = citation["quoted_text_digest"].get("value")
                        if isinstance(digest_value, str):
                            selected_digest_values.add(digest_value)
                source_value = binding.get("source_value")
                selected_digest_bound = (
                    isinstance(source_value, str)
                    and hashlib.sha256(source_value.encode("utf-8")).hexdigest()
                    in selected_digest_values
                )
                normalized_value = binding.get("normalized_value")
                if isinstance(field, str) and normalized_value != provision.get(field):
                    problems.append(
                        ValidationProblem(
                            path,
                            f"{binding_location}.normalized_value",
                            "provision metadata does not match its binding's normalized value",
                        )
                    )
                if isinstance(source_value, str):
                    normalized_source = " ".join(source_value.casefold().split())
                    if not normalized_source or not (
                        selected_digest_bound
                        or any(
                        normalized_source in " ".join(quote.casefold().split())
                        for quote in selected_quotes
                        )
                    ):
                        problems.append(
                            ValidationProblem(
                                path,
                                f"{binding_location}.source_value",
                                "provision metadata source value is not present in its cited public text",
                            )
                        )
                if (
                    binding.get("method") == "source_exact"
                    and source_value != normalized_value
                ):
                    problems.append(
                        ValidationProblem(
                            path,
                            f"{binding_location}.method",
                            "source_exact provision metadata requires identical source and normalized values",
                        )
                    )
                if (
                    field == "heading"
                    and binding.get("method") == "source_exact"
                    and isinstance(source_value, str)
                    and not selected_digest_bound
                    and not any(
                        _quote_has_exact_field_value(
                            quote,
                            source_value,
                            field="heading",
                            source_prefixes=designation_prefixes,
                        )
                        for quote in selected_quotes
                    )
                ):
                    problems.append(
                        ValidationProblem(
                            path,
                            f"{binding_location}.source_value",
                            "source_exact provision heading is not present in its cited public text at an exact field boundary",
                        )
                    )
                binding_created_at = (
                    _parse_datetime(binding.get("created_at"))
                    if isinstance(binding.get("created_at"), str)
                    else None
                )
                record_created_at = (
                    _parse_datetime(document.get("created_at"))
                    if isinstance(document.get("created_at"), str)
                    else None
                )
                if (
                    binding_created_at is not None
                    and record_created_at is not None
                    and binding_created_at < record_created_at
                ):
                    problems.append(
                        ValidationProblem(
                            path,
                            f"{binding_location}.created_at",
                            "provision metadata binding cannot predate the record",
                        )
                    )
                normalization_review = binding.get("normalization_review")
                if isinstance(normalization_review, dict):
                    producer = binding.get("producer")
                    reviewer = normalization_review.get("reviewer")
                    if (
                        isinstance(producer, dict)
                        and isinstance(reviewer, dict)
                        and _producer_identity(producer) is not None
                        and _producer_identity(producer)
                        == _producer_identity(reviewer)
                    ):
                        problems.append(
                            ValidationProblem(
                                path,
                                f"{binding_location}.normalization_review.reviewer",
                                "provision metadata producer may not approve its own normalization",
                            )
                        )
                    created_at = binding_created_at
                    reviewed_at = (
                        _parse_datetime(normalization_review.get("reviewed_at"))
                        if isinstance(normalization_review.get("reviewed_at"), str)
                        else None
                    )
                    if (
                        created_at is not None
                        and reviewed_at is not None
                        and reviewed_at < created_at
                    ):
                        problems.append(
                            ValidationProblem(
                                path,
                                f"{binding_location}.normalization_review.reviewed_at",
                                "provision metadata review cannot predate its binding",
                            )
                        )
                    record_updated_at = (
                        _parse_datetime(document.get("updated_at"))
                        if isinstance(document.get("updated_at"), str)
                        else None
                    )
                    if (
                        record_updated_at is not None
                        and reviewed_at is not None
                        and record_updated_at < reviewed_at
                    ):
                        problems.append(
                            ValidationProblem(
                                path,
                                "$.updated_at",
                                "record update time cannot predate its provision metadata review",
                            )
                        )
                    projected_binding = dict(binding)
                    projected_review = dict(normalization_review)
                    projected_review.pop("reviewed_binding_digest", None)
                    projected_binding["normalization_review"] = projected_review
                    try:
                        actual_digest = hashlib.sha256(
                            _canonical_json_bytes(projected_binding)
                        ).hexdigest()
                    except (TypeError, UnicodeEncodeError, ValueError) as error:
                        problems.append(
                            ValidationProblem(
                                path,
                                f"{binding_location}.normalization_review.reviewed_binding_digest",
                                f"provision metadata binding cannot be canonicalized: {error}",
                            )
                        )
                    else:
                        reviewed_digest = normalization_review.get(
                            "reviewed_binding_digest"
                        )
                        declared_digest = (
                            reviewed_digest.get("value")
                            if isinstance(reviewed_digest, dict)
                            else None
                        )
                        if declared_digest != actual_digest:
                            problems.append(
                                ValidationProblem(
                                    path,
                                    f"{binding_location}.normalization_review.reviewed_binding_digest.value",
                                    "provision metadata review digest does not match the exact binding",
                                )
                            )
            required_provision_fields = {"designation"}
            if isinstance(provision.get("heading"), str):
                required_provision_fields.add("heading")
            missing_provision_fields = sorted(
                required_provision_fields - covered_provision_fields
            )
            if missing_provision_fields:
                problems.append(
                    ValidationProblem(
                        path,
                        f"{provision_location}.metadata_bindings",
                        "provision metadata lacks evidence bindings for: "
                        + ", ".join(missing_provision_fields),
                    )
                )
            if provision.get("text_completeness") != "partial":
                continue
            digest_scope = provision.get("digest_scope")
            citations = text_citations
            content_digest = provision.get("content_digest")
            if (
                not isinstance(digest_scope, dict)
                or not isinstance(citations, list)
                or not isinstance(content_digest, dict)
            ):
                continue
            citation_indexes = digest_scope.get("citation_indexes")
            if not isinstance(citation_indexes, list):
                continue
            text_parts: list[str] = []
            selected_text_digest: dict[str, Any] | None = None
            valid = True
            for citation_index_index, citation_index in enumerate(citation_indexes):
                if not isinstance(citation_index, int) or not 0 <= citation_index < len(
                    citations
                ):
                    problems.append(
                        ValidationProblem(
                            path,
                            f"{provision_location}.digest_scope.citation_indexes[{citation_index_index}]",
                            "provision digest citation index is outside text_citations",
                        )
                    )
                    valid = False
                    continue
                used_provision_citation_indexes.add(citation_index)
                citation = citations[citation_index]
                quoted_text = (
                    citation.get("quoted_text") if isinstance(citation, dict) else None
                )
                if not isinstance(quoted_text, str):
                    quoted_text_digest = (
                        citation.get("quoted_text_digest")
                        if isinstance(citation, dict)
                        else None
                    )
                    if (
                        len(citation_indexes) == 1
                        and isinstance(quoted_text_digest, dict)
                        and digest_scope.get("canonicalization") == "utf8_exact"
                    ):
                        selected_text_digest = quoted_text_digest
                        continue
                    problems.append(
                        ValidationProblem(
                            path,
                            f"{provision_location}.text_citations[{citation_index}]",
                            "a partial provision requires one exact quoted-text digest, or copied text only when publication rights permit it",
                        )
                    )
                    valid = False
                    continue
                text_parts.append(quoted_text)
            if not valid:
                continue
            if selected_text_digest is not None:
                digest_matches = content_digest == selected_text_digest
            else:
                covered_text = "".join(text_parts)
                if digest_scope.get("canonicalization") == "unicode_nfc_lf":
                    covered_text = unicodedata.normalize(
                        "NFC", covered_text.replace("\r\n", "\n").replace("\r", "\n")
                    )
                actual = hashlib.sha256(covered_text.encode("utf-8")).hexdigest()
                digest_matches = content_digest.get("value") == actual
            if not digest_matches:
                problems.append(
                    ValidationProblem(
                        path,
                        f"{provision_location}.content_digest.value",
                        "partial provision digest does not match its selected citation text",
                    )
                )
            unused_citations = sorted(
                set(range(len(citation_items))) - used_provision_citation_indexes
            )
            if unused_citations:
                problems.append(
                    ValidationProblem(
                        path,
                        f"{provision_location}.text_citations",
                        "partial provision contains citations unused by metadata bindings and digest scope at indexes: "
                        + ", ".join(map(str, unused_citations)),
                    )
                )
    return problems


def _record_metadata_evidence_chronology_problems(
    path: Path,
    document: dict[str, Any],
    artifacts: dict[str, tuple[Path, dict[str, Any]]],
    captures: dict[str, tuple[Path, dict[str, Any]]],
) -> list[ValidationProblem]:
    """Keep metadata creation and review times behind their selected evidence."""

    problems: list[ValidationProblem] = []

    def evidence_times(
        binding: dict[str, Any], citations: list[Any]
    ) -> list[datetime]:
        selected_times: list[datetime] = []
        for evidence_index in _list_or_empty(binding.get("evidence_indexes")):
            if (
                not isinstance(evidence_index, int)
                or isinstance(evidence_index, bool)
                or not 0 <= evidence_index < len(citations)
            ):
                continue
            citation = citations[evidence_index]
            if not isinstance(citation, dict):
                continue
            artifact_id = citation.get("artifact_id")
            artifact_entry = (
                artifacts.get(artifact_id) if isinstance(artifact_id, str) else None
            )
            artifact_created_at = (
                artifact_entry[1].get("created_at")
                if artifact_entry is not None
                else None
            )
            if isinstance(artifact_created_at, str):
                parsed_artifact_time = _parse_datetime(artifact_created_at)
                if parsed_artifact_time is not None:
                    selected_times.append(parsed_artifact_time)
            capture_id = citation.get("capture_id")
            capture_entry = (
                captures.get(capture_id) if isinstance(capture_id, str) else None
            )
            retrieval = (
                capture_entry[1].get("retrieval")
                if capture_entry is not None
                else None
            )
            retrieved_at = (
                retrieval.get("retrieved_at") if isinstance(retrieval, dict) else None
            )
            if isinstance(retrieved_at, str):
                parsed_retrieval_time = _parse_datetime(retrieved_at)
                if parsed_retrieval_time is not None:
                    selected_times.append(parsed_retrieval_time)
        return selected_times

    def check_bindings(
        bindings: Any,
        citations: Any,
        base_location: str,
    ) -> None:
        binding_items = bindings if isinstance(bindings, list) else []
        citation_items = citations if isinstance(citations, list) else []
        for binding_index, binding in enumerate(binding_items):
            if not isinstance(binding, dict):
                continue
            binding_location = f"{base_location}[{binding_index}]"
            selected_times = evidence_times(binding, citation_items)
            binding_created_at = (
                _parse_datetime(binding.get("created_at"))
                if isinstance(binding.get("created_at"), str)
                else None
            )
            if binding_created_at is not None and any(
                binding_created_at < selected_time
                for selected_time in selected_times
            ):
                problems.append(
                    ValidationProblem(
                        path,
                        f"{binding_location}.created_at",
                        "metadata binding cannot predate its selected artifact creation or capture retrieval",
                    )
                )
            normalization_review = binding.get("normalization_review")
            reviewed_at = (
                _parse_datetime(normalization_review.get("reviewed_at"))
                if isinstance(normalization_review, dict)
                and isinstance(normalization_review.get("reviewed_at"), str)
                else None
            )
            if reviewed_at is not None and any(
                reviewed_at < selected_time for selected_time in selected_times
            ):
                problems.append(
                    ValidationProblem(
                        path,
                        f"{binding_location}.normalization_review.reviewed_at",
                        "metadata normalization review cannot predate its selected artifact creation or capture retrieval",
                    )
                )

    check_bindings(
        document.get("metadata_bindings"),
        document.get("metadata_evidence"),
        "$.metadata_bindings",
    )
    check_bindings(
        document.get("jurisdiction_bindings"),
        document.get("metadata_evidence"),
        "$.jurisdiction_bindings",
    )
    versions = document.get("versions")
    if not isinstance(versions, list):
        return problems
    for version_index, version in enumerate(versions):
        if not isinstance(version, dict):
            continue
        check_bindings(
            version.get("metadata_bindings"),
            version.get("metadata_evidence"),
            f"$.versions[{version_index}].metadata_bindings",
        )
        provisions = version.get("provisions")
        if not isinstance(provisions, list):
            continue
        for provision_index, provision in enumerate(provisions):
            if not isinstance(provision, dict):
                continue
            check_bindings(
                provision.get("metadata_bindings"),
                provision.get("text_citations"),
                f"$.versions[{version_index}].provisions[{provision_index}].metadata_bindings",
            )
    return problems


def _profile_binding_evidence_chronology_problems(
    path: Path,
    document: dict[str, Any],
    artifacts: dict[str, tuple[Path, dict[str, Any]]],
    captures: dict[str, tuple[Path, dict[str, Any]]],
) -> list[ValidationProblem]:
    """Keep profile field bindings and reviews behind their selected evidence."""

    schema_id = str(document.get("schema_id", ""))
    if not schema_id.endswith(("/authority.schema.json", "/jurisdiction.schema.json")):
        return []
    problems: list[ValidationProblem] = []

    def selected_evidence_times(
        binding: dict[str, Any], citations: list[Any]
    ) -> list[datetime]:
        evidence_times: list[datetime] = []
        for evidence_index in _list_or_empty(binding.get("evidence_indexes")):
            if (
                not isinstance(evidence_index, int)
                or isinstance(evidence_index, bool)
                or not 0 <= evidence_index < len(citations)
            ):
                continue
            citation = citations[evidence_index]
            if not isinstance(citation, dict):
                continue
            artifact_id = citation.get("artifact_id")
            artifact_entry = (
                artifacts.get(artifact_id) if isinstance(artifact_id, str) else None
            )
            artifact_created_at = (
                artifact_entry[1].get("created_at")
                if artifact_entry is not None
                else None
            )
            if isinstance(artifact_created_at, str):
                artifact_time = _parse_datetime(artifact_created_at)
                if artifact_time is not None:
                    evidence_times.append(artifact_time)
            capture_id = citation.get("capture_id")
            capture_entry = (
                captures.get(capture_id) if isinstance(capture_id, str) else None
            )
            retrieval = (
                capture_entry[1].get("retrieval")
                if capture_entry is not None
                else None
            )
            retrieved_at = (
                retrieval.get("retrieved_at") if isinstance(retrieval, dict) else None
            )
            if isinstance(retrieved_at, str):
                retrieval_time = _parse_datetime(retrieved_at)
                if retrieval_time is not None:
                    evidence_times.append(retrieval_time)
        return evidence_times

    def check_binding_array(
        bindings: Any,
        citations: Any,
        base_location: str,
    ) -> None:
        binding_items = bindings if isinstance(bindings, list) else []
        citation_items = citations if isinstance(citations, list) else []
        for binding_index, binding in enumerate(binding_items):
            if not isinstance(binding, dict):
                continue
            binding_location = f"{base_location}[{binding_index}]"
            evidence_times = selected_evidence_times(binding, citation_items)
            binding_created_at = (
                _parse_datetime(binding.get("created_at"))
                if isinstance(binding.get("created_at"), str)
                else None
            )
            if binding_created_at is not None and any(
                binding_created_at < evidence_time for evidence_time in evidence_times
            ):
                problems.append(
                    ValidationProblem(
                        path,
                        f"{binding_location}.created_at",
                        "profile field binding cannot predate its selected artifact creation or capture retrieval",
                    )
                )
            normalization_review = binding.get("normalization_review")
            reviewed_at = (
                _parse_datetime(normalization_review.get("reviewed_at"))
                if isinstance(normalization_review, dict)
                and isinstance(normalization_review.get("reviewed_at"), str)
                else None
            )
            if reviewed_at is not None and any(
                reviewed_at < evidence_time for evidence_time in evidence_times
            ):
                problems.append(
                    ValidationProblem(
                        path,
                        f"{binding_location}.normalization_review.reviewed_at",
                        "profile normalization review cannot predate its selected artifact creation or capture retrieval",
                    )
                )

    check_binding_array(
        document.get("profile_bindings"),
        document.get("profile_evidence"),
        "$.profile_bindings",
    )
    for name_index, name in enumerate(_list_or_empty(document.get("names"))):
        if not isinstance(name, dict):
            continue
        check_binding_array(
            name.get("field_bindings"),
            name.get("evidence"),
            f"$.names[{name_index}].field_bindings",
        )
    return problems


def evidence_content_verification_problems(
    path: Path, document: dict[str, Any]
) -> list[ValidationProblem]:
    """Bind every disclosed quote digest to an independent content check."""

    problems: list[ValidationProblem] = []
    state_clock_field: str | None = None
    state_clock: datetime | None = None
    for candidate_field in (
        "updated_at",
        "generated_at",
        "reviewed_at",
        "created_at",
    ):
        candidate_value = document.get(candidate_field)
        if not isinstance(candidate_value, str):
            continue
        candidate_clock = _parse_datetime(candidate_value)
        if candidate_clock is not None:
            state_clock_field = candidate_field
            state_clock = candidate_clock
            break
    for location, value in _walk(document):
        if not isinstance(value, dict) or not {
            "artifact_id",
            "locator",
        }.issubset(value):
            continue
        text_field = (
            "quoted_text"
            if "quoted_text" in value
            else "public_excerpt"
            if "public_excerpt" in value
            else None
        )
        digest_field = (
            "quoted_text_digest"
            if "quoted_text_digest" in value
            else "excerpt_digest"
            if "excerpt_digest" in value
            else None
        )
        disclosed_text = value.get(text_field) if text_field is not None else None
        disclosed_digest = (
            value.get(digest_field) if digest_field is not None else None
        )
        if not isinstance(disclosed_text, str) and not isinstance(
            disclosed_digest, dict
        ):
            continue
        if isinstance(disclosed_text, str) and isinstance(disclosed_digest, dict):
            actual_quote_digest = hashlib.sha256(
                disclosed_text.encode("utf-8")
            ).hexdigest()
            if disclosed_digest.get("value") != actual_quote_digest:
                problems.append(
                    ValidationProblem(
                        path,
                        _json_location((*location, digest_field, "value")),
                        "disclosed text digest does not match its text",
                    )
                )
        verification = value.get("content_verification")
        if not isinstance(disclosed_digest, dict) or not isinstance(
            verification, dict
        ):
            continue
        try:
            expected_digest = hashlib.sha256(
                _canonical_json_bytes(_content_verification_projection(value))
            ).hexdigest()
        except (TypeError, UnicodeEncodeError, ValueError) as error:
            problems.append(
                ValidationProblem(
                    path,
                    _json_location((*location, "content_verification")),
                    f"citation content verification cannot be canonicalized: {error}",
                )
            )
            continue
        declared_digest = verification.get("verified_evidence_digest")
        if (
            not isinstance(declared_digest, dict)
            or declared_digest.get("value") != expected_digest
        ):
            problems.append(
                ValidationProblem(
                    path,
                    _json_location(
                        (
                            *location,
                            "content_verification",
                            "verified_evidence_digest",
                            "value",
                        )
                    ),
                    "content verification digest does not match the exact evidence coordinates and verifier decision",
                )
            )
        verified_at = (
            _parse_datetime(verification.get("verified_at"))
            if isinstance(verification.get("verified_at"), str)
            else None
        )
        if (
            verified_at is not None
            and state_clock is not None
            and verified_at > state_clock
        ):
            problems.append(
                ValidationProblem(
                    path,
                    _json_location((*location, "content_verification", "verified_at")),
                    "content verification cannot postdate the enclosing document "
                    f"{state_clock_field}",
                )
            )
        temporal_binding = value.get("temporal_value_binding")
        if not isinstance(temporal_binding, dict):
            continue
        verifier = verification.get("verifier")
        binding_producer = temporal_binding.get("producer")
        verifier_id = (
            verifier.get("producer_id") if isinstance(verifier, dict) else None
        )
        binding_producer_id = (
            binding_producer.get("producer_id")
            if isinstance(binding_producer, dict)
            else None
        )
        if (
            isinstance(verifier_id, str)
            and verifier_id
            and verifier_id == binding_producer_id
        ):
            problems.append(
                ValidationProblem(
                    path,
                    _json_location((*location, "content_verification", "verifier")),
                    "source-content verification must be independent of temporal normalization",
                )
            )
        for field in ("created_at", "reviewed_at"):
            binding_time = (
                _parse_datetime(temporal_binding.get(field))
                if isinstance(temporal_binding.get(field), str)
                else None
            )
            if (
                verified_at is not None
                and binding_time is not None
                and binding_time < verified_at
            ):
                problems.append(
                    ValidationProblem(
                        path,
                        _json_location(
                            (*location, "temporal_value_binding", field)
                        ),
                        "temporal normalization cannot predate independent source-content verification",
                    )
                )
    return problems


def evidence_bundle_reference_problems(
    path: Path, document: dict[str, Any]
) -> list[ValidationProblem]:
    """Ensure claim citation indexes resolve inside the same evidence bundle."""

    if not str(document.get("schema_id", "")).endswith("/evidence-bundle.schema.json"):
        return []
    citations = document.get("citations")
    claims = document.get("claims")
    if not isinstance(citations, list) or not isinstance(claims, list):
        return []

    problems: list[ValidationProblem] = []
    used_citation_indexes: set[int] = set()
    for claim_index, claim in enumerate(claims):
        if not isinstance(claim, dict) or not isinstance(claim.get("citation_indexes"), list):
            continue
        if (
            claim.get("classification") == "DIRECT"
            and claim.get("content_use") in {"summary", "translation"}
        ):
            problems.append(
                ValidationProblem(
                    path,
                    f"$.claims[{claim_index}].classification",
                    "summary and translation claims are transformations and cannot be classified DIRECT",
                )
            )
        if claim.get("content_use") == "bibliographic_fact":
            facts = claim.get("bibliographic_facts")
            if isinstance(facts, list) and all(
                isinstance(fact, dict)
                and isinstance(fact.get("field"), str)
                and isinstance(fact.get("value"), str)
                for fact in facts
            ):
                rendered = "; ".join(
                    f"{fact['field']}={fact['value']}" for fact in facts
                )
                if claim.get("claim_text") != rendered:
                    problems.append(
                        ValidationProblem(
                            path,
                            f"$.claims[{claim_index}].claim_text",
                            "bibliographic claim text must exactly match its structured fact rendering",
                        )
                    )
        for index_index, citation_index in enumerate(claim["citation_indexes"]):
            if isinstance(citation_index, int):
                if 0 <= citation_index < len(citations):
                    used_citation_indexes.add(citation_index)
                    citation = citations[citation_index]
                    quoted_text = (
                        citation.get("quoted_text")
                        if isinstance(citation, dict)
                        and isinstance(citation.get("capture_id"), str)
                        else None
                    )
                    claim_text = claim.get("claim_text")
                    if (
                        claim.get("content_use") in {"summary", "translation"}
                        and isinstance(claim_text, str)
                        and isinstance(quoted_text, str)
                        and _has_material_verbatim_overlap(claim_text, quoted_text)
                    ):
                        problems.append(
                            ValidationProblem(
                                path,
                                f"$.claims[{claim_index}].content_use",
                                "a transformed claim reproduces cited source text verbatim; classify copied text as source_excerpt",
                            )
                        )
                else:
                    problems.append(
                        ValidationProblem(
                            path,
                            f"$.claims[{claim_index}].citation_indexes[{index_index}]",
                            f"citation index {citation_index} is outside citations[0:{len(citations)}]",
                        )
                    )
    unused = sorted(set(range(len(citations))) - used_citation_indexes)
    if unused:
        problems.append(
            ValidationProblem(
                path,
                "$.citations",
                "bundle contains citations unused by every claim at indexes: "
                + ", ".join(map(str, unused)),
            )
        )
    return problems


def coverage_ledger_problems(
    path: Path, document: dict[str, Any]
) -> list[ValidationProblem]:
    """Keep source-envelope coverage claims tied to complete, ordered runs."""

    if not str(document.get("schema_id", "")).endswith(
        "/coverage-ledger.schema.json"
    ):
        return []
    problems: list[ValidationProblem] = []
    generated = (
        _parse_datetime(document.get("generated_at"))
        if isinstance(document.get("generated_at"), str)
        else None
    )
    fresh_until = (
        _parse_datetime(document.get("fresh_until"))
        if isinstance(document.get("fresh_until"), str)
        else None
    )
    if generated is not None and fresh_until is not None and fresh_until < generated:
        problems.append(
            ValidationProblem(
                path,
                "$.fresh_until",
                "coverage freshness cannot expire before the ledger is generated",
            )
        )

    runs = document.get("enumeration_runs")
    successful_times: list[datetime] = []
    latest_by_entrypoint: dict[str, tuple[datetime, str]] = {}
    if isinstance(runs, list):
        for index, run in enumerate(runs):
            if not isinstance(run, dict):
                continue
            started = (
                _parse_datetime(run.get("started_at"))
                if isinstance(run.get("started_at"), str)
                else None
            )
            completed = (
                _parse_datetime(run.get("completed_at"))
                if isinstance(run.get("completed_at"), str)
                else None
            )
            if started is not None and completed is not None and started > completed:
                problems.append(
                    ValidationProblem(
                        path,
                        f"$.enumeration_runs[{index}]",
                        "enumeration run starts after it completes",
                    )
                )
            if generated is not None and completed is not None and completed > generated:
                problems.append(
                    ValidationProblem(
                        path,
                        f"$.enumeration_runs[{index}].completed_at",
                        "enumeration run cannot complete after its coverage ledger is generated",
                    )
                )
            if completed is not None and run.get("outcome") == "success":
                successful_times.append(completed)
            entrypoint_id = run.get("entrypoint_id")
            if isinstance(entrypoint_id, str) and completed is not None:
                earlier = latest_by_entrypoint.get(entrypoint_id)
                if earlier is None or completed > earlier[0]:
                    latest_by_entrypoint[entrypoint_id] = (
                        completed,
                        str(run.get("outcome")),
                    )

    last_successful = (
        _parse_datetime(document.get("last_successful_enumeration_at"))
        if isinstance(document.get("last_successful_enumeration_at"), str)
        else None
    )
    if successful_times:
        if last_successful != max(successful_times):
            problems.append(
                ValidationProblem(
                    path,
                    "$.last_successful_enumeration_at",
                    "last successful enumeration must equal the latest successful run",
                )
            )
    elif last_successful is not None:
        problems.append(
            ValidationProblem(
                path,
                "$.last_successful_enumeration_at",
                "last successful enumeration is declared without a successful run",
            )
        )

    if document.get("status") == "covered_for_declared_scope":
        problems.append(
            ValidationProblem(
                path,
                "$.status",
                "positive coverage is fail-closed until each successful enumeration run resolves to a content-addressed result manifest and the exact source-manifest revision",
            )
        )
        scope = document.get("declared_scope")
        date_interval = scope.get("date_interval") if isinstance(scope, dict) else None
        if not isinstance(date_interval, dict) or date_interval.get("status") not in {
            "known",
            "open_ended",
        }:
            problems.append(
                ValidationProblem(
                    path,
                    "$.declared_scope.date_interval.status",
                    "covered scope requires a defined known or open-ended date interval",
                )
            )
        entrypoint_ids = scope.get("entrypoint_ids") if isinstance(scope, dict) else None
        if isinstance(entrypoint_ids, list):
            incomplete = sorted(
                repr(entrypoint_id)
                for entrypoint_id in entrypoint_ids
                if not isinstance(entrypoint_id, str)
                or entrypoint_id not in latest_by_entrypoint
                or latest_by_entrypoint[entrypoint_id][1] != "success"
            )
            if incomplete:
                problems.append(
                    ValidationProblem(
                        path,
                        "$.enumeration_runs",
                        "covered scope requires the latest run for every declared entrypoint to succeed: "
                        + ", ".join(incomplete),
                    )
                )

    gaps = document.get("known_gaps")
    if isinstance(gaps, list):
        for index, gap in enumerate(gaps):
            if not isinstance(gap, dict):
                continue
            first = (
                _parse_datetime(gap.get("first_detected_at"))
                if isinstance(gap.get("first_detected_at"), str)
                else None
            )
            checked = (
                _parse_datetime(gap.get("last_checked_at"))
                if isinstance(gap.get("last_checked_at"), str)
                else None
            )
            resolved = (
                _parse_datetime(gap.get("resolved_at"))
                if isinstance(gap.get("resolved_at"), str)
                else None
            )
            if first is not None and checked is not None and first > checked:
                problems.append(
                    ValidationProblem(
                        path,
                        f"$.known_gaps[{index}].last_checked_at",
                        "coverage gap cannot be checked before it is first detected",
                    )
                )
            if checked is not None and resolved is not None and checked > resolved:
                problems.append(
                    ValidationProblem(
                        path,
                        f"$.known_gaps[{index}].resolved_at",
                        "coverage gap resolution cannot predate its last check",
                    )
                )
            if generated is not None and checked is not None and checked > generated:
                problems.append(
                    ValidationProblem(
                        path,
                        f"$.known_gaps[{index}].last_checked_at",
                        "coverage gap check cannot postdate the ledger generation",
                    )
                )
    return problems


def _claim_conflict_assertion_sets(claim: Any) -> tuple[set[str], set[str]]:
    if not isinstance(claim, dict):
        return set(), set()
    supporting = {
        assertion_id
        for assertion_id in _list_or_empty(claim.get("assertion_ids"))
        if isinstance(assertion_id, str)
    }
    contrary = {
        assertion_id
        for assertion_id in _list_or_empty(claim.get("contrary_assertion_ids"))
        if isinstance(assertion_id, str)
    }
    return supporting, contrary


CONFLICT_PREDICATE_POLARITY: dict[str, tuple[str, int]] = {
    # These are controlled global predicates, not source-language inference.
    "commences": ("legal_operation", 1),
    "revives": ("legal_operation", 1),
    "expires": ("legal_operation", -1),
    "invalidates": ("legal_operation", -1),
    "repeals": ("legal_operation", -1),
    "stays": ("legal_operation", -1),
    "applies": ("applicability", 1),
    "extends": ("applicability", 1),
    "distinguishes": ("applicability", -1),
    "limits": ("applicability", -1),
}


def _entity_reference_key(value: Any) -> tuple[str, str] | None:
    if not isinstance(value, dict):
        return None
    entity_type = value.get("entity_type")
    entity_id = value.get("entity_id")
    if not isinstance(entity_type, str) or not isinstance(entity_id, str):
        return None
    return entity_type, entity_id


def _assertion_has_reviewed_dispute_link(left: Any, right: Any) -> bool:
    """Recognize only a dispute edge carried by an assertion that was reviewed."""

    if not isinstance(left, dict) or not isinstance(right, dict):
        return False
    right_id = right.get("assertion_id")
    reviewer = left.get("reviewer")
    return (
        isinstance(right_id, str)
        and right_id in _list_or_empty(left.get("disputes_assertion_ids"))
        and left.get("status") in {"verified", "disputed", "superseded"}
        and isinstance(left.get("reviewed_at"), str)
        and isinstance(reviewer, dict)
        and isinstance(reviewer.get("producer_id"), str)
    )


def _assertion_scopes_overlap(left: Any, right: Any) -> bool:
    if not isinstance(left, dict) or not isinstance(right, dict):
        return False
    left_extent = left.get("extent")
    right_extent = right.get("extent")
    if left_extent in {None, "unknown", "partial"} or right_extent in {
        None,
        "unknown",
        "partial",
    }:
        return False
    left_jurisdictions = {
        item for item in _list_or_empty(left.get("jurisdiction_ids")) if isinstance(item, str)
    }
    right_jurisdictions = {
        item for item in _list_or_empty(right.get("jurisdiction_ids")) if isinstance(item, str)
    }
    if not left_jurisdictions.intersection(right_jurisdictions):
        return False
    if "whole_entity" in {left_extent, right_extent}:
        return True
    left_targets = {
        item
        for item in _list_or_empty(left.get("target_provision_ids"))
        if isinstance(item, str)
    }
    right_targets = {
        item
        for item in _list_or_empty(right.get("target_provision_ids"))
        if isinstance(item, str)
    }
    return bool(left_targets.intersection(right_targets))


def _assertions_are_semantically_incompatible(left: Any, right: Any) -> bool:
    """Conservatively recognize an implicit conflict over one proposition."""

    if not isinstance(left, dict) or not isinstance(right, dict):
        return False
    if left.get("status") not in {"verified", "disputed", "superseded"} or right.get(
        "status"
    ) not in {"verified", "disputed", "superseded"}:
        return False
    if _entity_reference_key(left.get("subject")) != _entity_reference_key(
        right.get("subject")
    ) or _entity_reference_key(left.get("object")) != _entity_reference_key(
        right.get("object")
    ):
        return False
    left_predicate = CONFLICT_PREDICATE_POLARITY.get(left.get("predicate"))
    right_predicate = CONFLICT_PREDICATE_POLARITY.get(right.get("predicate"))
    if (
        left_predicate is None
        or right_predicate is None
        or left_predicate[0] != right_predicate[0]
        or left_predicate[1] == right_predicate[1]
    ):
        return False
    if not _assertion_scopes_overlap(left.get("scope"), right.get("scope")):
        return False
    left_time_axes = left.get("time_axes")
    right_time_axes = right.get("time_axes")
    if not isinstance(left_time_axes, dict) or not isinstance(right_time_axes, dict):
        return False
    return all(
        _temporal_intervals_overlap(
            left_time_axes.get(axis_name), right_time_axes.get(axis_name)
        )
        for axis_name in ("effectiveness", "applicability")
    )


def _assertions_form_a_conflict(left: Any, right: Any) -> bool:
    return (
        _assertion_has_reviewed_dispute_link(left, right)
        or _assertion_has_reviewed_dispute_link(right, left)
        or _assertions_are_semantically_incompatible(left, right)
    )


def _assertions_share_history_proposition(
    newer: Any, older: Any, relation_field: str
) -> bool:
    """Reject history edges between unrelated legal propositions."""

    if not isinstance(newer, dict) or not isinstance(older, dict):
        return False
    if _entity_reference_key(newer.get("subject")) != _entity_reference_key(
        older.get("subject")
    ) or _entity_reference_key(newer.get("object")) != _entity_reference_key(
        older.get("object")
    ):
        return False
    if not _assertion_scopes_overlap(newer.get("scope"), older.get("scope")):
        return False
    newer_predicate = newer.get("predicate")
    older_predicate = older.get("predicate")
    if relation_field == "supersedes_assertion_ids":
        return newer_predicate == older_predicate
    if relation_field != "disputes_assertion_ids":
        return False
    if newer_predicate == older_predicate:
        return True
    newer_family = CONFLICT_PREDICATE_POLARITY.get(newer_predicate)
    older_family = CONFLICT_PREDICATE_POLARITY.get(older_predicate)
    return (
        newer_family is not None
        and older_family is not None
        and newer_family[0] == older_family[0]
    )


def _temporal_point_definitely_after(candidate: Any, cutoff: Any) -> bool:
    candidate_bounds = (
        _temporal_point_bounds(candidate) if isinstance(candidate, dict) else None
    )
    cutoff_bounds = _temporal_point_bounds(cutoff) if isinstance(cutoff, dict) else None
    return (
        candidate_bounds is not None
        and cutoff_bounds is not None
        and candidate_bounds[0] >= cutoff_bounds[1]
    )


NON_APPLICABILITY_ASSERTION_PREDICATES = {
    "adopted_by",
    "administered_by",
    "assented_by",
    "consolidated_by",
    "decided_by",
    "enacted_by",
    "held_by_custodian",
    "institutionally_part_of",
    "issued_by",
    "made_by",
    "published_by",
    "reviews_decisions_of",
    "serves_jurisdiction",
    "territorially_overlaps",
    "territorially_within",
    "translated_by",
}


def _bundle_context_problems(
    path: Path,
    bundle: dict[str, Any],
    assertions: dict[str, tuple[Path, dict[str, Any]]],
    authorities: dict[str, tuple[Path, dict[str, Any]]],
    jurisdiction_profiles: dict[str, tuple[Path, dict[str, Any]]],
    records: dict[str, tuple[Path, dict[str, Any]]],
    record_versions: dict[str, tuple[Path, str, dict[str, Any]]],
    provision_versions: dict[str, tuple[Path, str, str, dict[str, Any]]],
    provision_records: dict[str, set[str]],
) -> list[ValidationProblem]:
    """Fail closed when legal evidence does not fit the bundle's four clocks."""

    context = bundle.get("evaluation_context")
    if not isinstance(context, dict):
        return []
    facts_period = context.get("facts_period")
    effective_at = context.get("effective_at")
    authority_cutoff = context.get("authority_cutoff")
    snapshot_context = context.get("corpus_snapshot")
    snapshot_recorded_at = (
        snapshot_context.get("recorded_at")
        if isinstance(snapshot_context, dict)
        else None
    )
    snapshot_recorded_point = (
        {
            "status": "exact",
            "value": snapshot_recorded_at,
            "precision": "second",
            "calendar": "gregory",
        }
        if isinstance(snapshot_recorded_at, str)
        else None
    )
    context_jurisdictions = {
        item
        for item in _list_or_empty(context.get("jurisdiction_ids"))
        if isinstance(item, str)
    }
    unresolved = [
        item
        for item in _list_or_empty(bundle.get("unresolved_items"))
        if isinstance(item, dict)
    ]
    problems: list[ValidationProblem] = []
    reported_defects: set[
        tuple[str, str, str, tuple[tuple[str, str], ...]]
    ] = set()
    reported_status = False

    def has_blocker(kind: str, required_refs: set[tuple[str, str]]) -> bool:
        return any(
            item.get("kind") == kind
            and item.get("severity") == "blocking"
            and required_refs
            <= {
                key
                for reference in _list_or_empty(item.get("related_entities"))
                if (key := _entity_reference_key(reference)) is not None
            }
            for item in unresolved
        )

    def report_defect(
        claim_id: str,
        kind: str,
        required_refs: set[tuple[str, str]],
        location: str,
        message: str,
    ) -> None:
        nonlocal reported_status
        signature = (claim_id, kind, location, tuple(sorted(required_refs)))
        if signature in reported_defects:
            return
        reported_defects.add(signature)
        if bundle.get("status") != "INSUFFICIENT_COVERAGE":
            problems.append(ValidationProblem(path, location, message))
            if not reported_status:
                reported_status = True
                problems.append(
                    ValidationProblem(
                        path,
                        "$.status",
                        "context-ineligible or temporally unresolved evidence requires INSUFFICIENT_COVERAGE",
                    )
                )
        if not has_blocker(kind, required_refs):
            problems.append(
                ValidationProblem(
                    path,
                    "$.unresolved_items",
                    f"{message}; {kind} requires a blocking unresolved item naming the affected claim and evidence",
                )
            )

    incoming_history: dict[str, list[tuple[str, str]]] = {}
    for newer_id, (_, newer_assertion) in assertions.items():
        for relation_field in (
            "supersedes_assertion_ids",
            "disputes_assertion_ids",
        ):
            for older_id in _list_or_empty(newer_assertion.get(relation_field)):
                if isinstance(older_id, str):
                    incoming_history.setdefault(older_id, []).append(
                        (newer_id, relation_field)
                    )

    incoming_versions: dict[str, list[str]] = {}
    for newer_id, (_, _, newer_version) in record_versions.items():
        for older_id in _list_or_empty(
            newer_version.get("supersedes_version_ids")
        ):
            if isinstance(older_id, str):
                incoming_versions.setdefault(older_id, []).append(newer_id)

    incoming_provision_versions: dict[str, list[str]] = {}
    for newer_id, (_, _, _, newer_provision) in provision_versions.items():
        for older_id in _list_or_empty(
            newer_provision.get("predecessor_provision_version_ids")
        ):
            if isinstance(older_id, str):
                incoming_provision_versions.setdefault(older_id, []).append(
                    newer_id
                )

    snapshot_instant = (
        _parse_datetime(snapshot_recorded_at)
        if isinstance(snapshot_recorded_at, str)
        else None
    )

    def incoming_history_is_visible(
        newer_id: str, older_id: str, relation_field: str
    ) -> bool:
        newer_entry = assertions.get(newer_id)
        older_entry = assertions.get(older_id)
        if newer_entry is None or older_entry is None or snapshot_instant is None:
            return False
        newer = newer_entry[1]
        if newer.get("status") not in {
            "verified",
            "disputed",
            "superseded",
        } or not _assertions_share_history_proposition(
            newer, older_entry[1], relation_field
        ):
            return False
        created_at = (
            _parse_datetime(newer.get("created_at"))
            if isinstance(newer.get("created_at"), str)
            else None
        )
        reviewed_at = (
            _parse_datetime(newer.get("reviewed_at"))
            if isinstance(newer.get("reviewed_at"), str)
            else None
        )
        if (
            created_at is None
            or reviewed_at is None
            or created_at > snapshot_instant
            or reviewed_at > snapshot_instant
        ):
            return False
        time_axes = newer.get("time_axes")
        observation = (
            time_axes.get("observation") if isinstance(time_axes, dict) else None
        )
        return not _temporal_point_definitely_after(
            observation, snapshot_recorded_point
        )

    def incoming_history_may_affect_context(
        newer: dict[str, Any], *, bibliographic_only: bool
    ) -> bool:
        time_axes = newer.get("time_axes")
        if not isinstance(time_axes, dict):
            return True
        if _temporal_point_definitely_after(
            time_axes.get("publication"), authority_cutoff
        ):
            return False
        if bibliographic_only:
            return True
        effectiveness = time_axes.get("effectiveness")
        if (
            isinstance(effectiveness, dict)
            and effectiveness.get("status") in {"known", "open_ended"}
            and not _temporal_interval_covers_point(effectiveness, effective_at)
        ):
            return False
        applicability = time_axes.get("applicability")
        if (
            newer.get("predicate") in NON_APPLICABILITY_ASSERTION_PREDICATES
            and isinstance(applicability, dict)
            and applicability.get("status") == "not_applicable"
        ):
            return True
        if (
            isinstance(applicability, dict)
            and applicability.get("status") in {"known", "open_ended"}
            and not _temporal_interval_covers_interval(applicability, facts_period)
        ):
            return False
        # Unknown clocks cannot prove irrelevance, so they block optimistic use.
        return True

    def legal_state_snapshot_visible(
        entity_type: str, entity_id: str
    ) -> bool:
        if snapshot_instant is None or snapshot_recorded_point is None:
            return False
        if entity_type == "version":
            state_entry = record_versions.get(entity_id)
            record_id = state_entry[1] if state_entry is not None else None
            state = state_entry[2] if state_entry is not None else None
        elif entity_type == "provision_version":
            state_entry = provision_versions.get(entity_id)
            record_id = state_entry[1] if state_entry is not None else None
            state = state_entry[3] if state_entry is not None else None
        else:
            return False
        record_entry = records.get(record_id) if isinstance(record_id, str) else None
        record_updated_at = (
            _parse_datetime(record_entry[1].get("updated_at"))
            if record_entry is not None
            and isinstance(record_entry[1].get("updated_at"), str)
            else None
        )
        if record_updated_at is None or record_updated_at > snapshot_instant:
            return False
        time_axes = state.get("time_axes") if isinstance(state, dict) else None
        observation = (
            time_axes.get("observation") if isinstance(time_axes, dict) else None
        )
        return not _temporal_point_definitely_after(
            observation, snapshot_recorded_point
        )

    def legal_state_may_affect_context(state: Any) -> bool:
        time_axes = state.get("time_axes") if isinstance(state, dict) else None
        if not isinstance(time_axes, dict):
            return True
        if _temporal_point_definitely_after(
            time_axes.get("publication"), authority_cutoff
        ):
            return False
        effectiveness = time_axes.get("effectiveness")
        if isinstance(effectiveness, dict):
            if effectiveness.get("status") == "not_applicable":
                return False
            if effectiveness.get("status") in {"known", "open_ended"} and not (
                _temporal_interval_covers_point(effectiveness, effective_at)
            ):
                return False
        applicability = time_axes.get("applicability")
        if isinstance(applicability, dict):
            if applicability.get("status") == "not_applicable":
                return False
            if applicability.get("status") in {"known", "open_ended"} and not (
                _temporal_interval_covers_interval(applicability, facts_period)
            ):
                return False
        return True

    def transition_assertion_ids(
        entity_type: str,
        newer_id: str,
        older_id: str,
        state: Any,
    ) -> set[str]:
        return {
            assertion_id
            for assertion_id in _list_or_empty(
                state.get("derived_from_assertion_ids")
                if isinstance(state, dict)
                else None
            )
            if isinstance(assertion_id, str)
            and (assertion_entry := assertions.get(assertion_id)) is not None
            and assertion_entry[1].get("subject")
            == {"entity_type": entity_type, "entity_id": newer_id}
            and assertion_entry[1].get("object")
            == {"entity_type": entity_type, "entity_id": older_id}
            and assertion_entry[1].get("predicate")
            in VERSION_TRANSITION_PREDICATES
            and assertion_entry[1].get("status") in {"verified", "superseded"}
            and isinstance(assertion_entry[1].get("reviewed_at"), str)
            and (reviewed_at := _parse_datetime(assertion_entry[1]["reviewed_at"]))
            is not None
            and snapshot_instant is not None
            and reviewed_at <= snapshot_instant
        }

    def assertion_basis_ids(time_axes: Any) -> set[str]:
        if not isinstance(time_axes, dict):
            return set()
        return {
            assertion_id
            for _, value in _walk(time_axes)
            if isinstance(value, dict)
            for assertion_id in _list_or_empty(value.get("basis_assertion_ids"))
            if isinstance(assertion_id, str)
        }

    def record_jurisdictions(record_id: str | None) -> set[str]:
        entry = records.get(record_id) if isinstance(record_id, str) else None
        record = entry[1] if entry is not None else None
        return {
            item
            for item in _list_or_empty(
                record.get("jurisdiction_ids") if isinstance(record, dict) else None
            )
            if isinstance(item, str)
        }

    def subject_jurisdictions(reference: tuple[str, str]) -> set[str] | None:
        entity_type, entity_id = reference
        if entity_type == "jurisdiction":
            return {entity_id}
        if entity_type == "record":
            return record_jurisdictions(entity_id)
        if entity_type == "version":
            entry = record_versions.get(entity_id)
            return record_jurisdictions(entry[1]) if entry is not None else set()
        if entity_type == "provision":
            return set().union(
                *(record_jurisdictions(record_id) for record_id in provision_records.get(entity_id, set()))
            ) if provision_records.get(entity_id) else set()
        if entity_type == "provision_version":
            entry = provision_versions.get(entity_id)
            return record_jurisdictions(entry[1]) if entry is not None else set()
        if entity_type == "assertion":
            entry = assertions.get(entity_id)
            scope = entry[1].get("scope") if entry is not None else None
            return {
                item
                for item in _list_or_empty(
                    scope.get("jurisdiction_ids") if isinstance(scope, dict) else None
                )
                if isinstance(item, str)
            }
        if entity_type == "authority":
            # Adjacency on the authority profile is discovery-only. A claim
            # must separately establish scope through a reviewed relationship.
            return set()
        return None

    def subject_time_axes(reference: tuple[str, str]) -> dict[str, Any] | None:
        entity_type, entity_id = reference
        if entity_type == "version":
            entry = record_versions.get(entity_id)
            value = entry[2].get("time_axes") if entry is not None else None
            return value if isinstance(value, dict) else None
        if entity_type == "provision_version":
            entry = provision_versions.get(entity_id)
            value = entry[3].get("time_axes") if entry is not None else None
            return value if isinstance(value, dict) else None
        if entity_type == "assertion":
            entry = assertions.get(entity_id)
            value = entry[1].get("time_axes") if entry is not None else None
            return value if isinstance(value, dict) else None
        return None

    def check_time_axes(
        claim_id: str,
        reference: tuple[str, str],
        time_axes: Any,
        location: str,
        *,
        applicability_not_applicable: bool = False,
        legal_clocks_required: bool = True,
    ) -> bool:
        required = {("claim", claim_id), reference}
        if not isinstance(time_axes, dict):
            report_defect(
                claim_id,
                "unknown_effective_time",
                required,
                location,
                "material evidence has no resolvable intrinsic legal clocks",
            )
            return False
        eligible = True
        observation = time_axes.get("observation")
        if not _temporal_point_not_after(observation, snapshot_recorded_point):
            report_defect(
                claim_id,
                "missing_dependency",
                required,
                f"{location}.observation",
                "relied-on evidence observation is unknown or later than the selected corpus snapshot",
            )
            eligible = False

        publication = time_axes.get("publication")
        if not _temporal_point_not_after(publication, authority_cutoff):
            report_defect(
                claim_id,
                "missing_dependency",
                required,
                f"{location}.publication",
                "relied-on authority publication is unknown or may postdate authority_cutoff",
            )
            eligible = False
        if not legal_clocks_required:
            return eligible
        effectiveness = time_axes.get("effectiveness")
        if not isinstance(effectiveness, dict) or effectiveness.get("status") not in {
            "known",
            "open_ended",
        }:
            report_defect(
                claim_id,
                "unknown_effective_time",
                required,
                f"{location}.effectiveness",
                "relied-on legal effectiveness is unknown",
            )
            eligible = False
        elif _temporal_interval_has_approximate_boundary(effectiveness):
            report_defect(
                claim_id,
                "unknown_effective_time",
                required,
                f"{location}.effectiveness",
                "material evidence has an approximate effectiveness boundary; V1 cannot prove the requested as-of instant",
            )
            eligible = False
        elif not _temporal_interval_covers_point(effectiveness, effective_at):
            report_defect(
                claim_id,
                "missing_dependency",
                required,
                f"{location}.effectiveness",
                "relied-on legal effectiveness does not cover evaluation_context.effective_at",
            )
            eligible = False
        applicability = time_axes.get("applicability")
        if applicability_not_applicable and isinstance(applicability, dict) and applicability.get(
            "status"
        ) == "not_applicable":
            return eligible
        if not isinstance(applicability, dict) or applicability.get("status") not in {
            "known",
            "open_ended",
        }:
            report_defect(
                claim_id,
                "unknown_applicability",
                required,
                f"{location}.applicability",
                "relied-on legal applicability is unknown or not applicable to a material claim",
            )
            eligible = False
        elif _temporal_interval_has_approximate_boundary(applicability):
            report_defect(
                claim_id,
                "unknown_applicability",
                required,
                f"{location}.applicability",
                "material evidence has an approximate applicability boundary; V1 cannot prove coverage of the facts period",
            )
            eligible = False
        elif not _temporal_interval_covers_interval(applicability, facts_period):
            report_defect(
                claim_id,
                "missing_dependency",
                required,
                f"{location}.applicability",
                "relied-on legal applicability does not cover evaluation_context.facts_period",
            )
            eligible = False

        if reference[0] in {"version", "provision_version"}:
            def validate_basis_assertions(
                axis_name: str,
                owner_interval: Any,
                visited: set[str],
            ) -> bool:
                basis_ids = (
                    owner_interval.get("basis_assertion_ids")
                    if isinstance(owner_interval, dict)
                    else None
                )
                if not isinstance(basis_ids, list) or not basis_ids:
                    report_defect(
                        claim_id,
                        "missing_dependency",
                        required,
                        f"{location}.{axis_name}.basis_assertion_ids",
                        f"known {axis_name} has no reviewed basis assertion",
                    )
                    return False
                bases_eligible = True
                for basis_index, basis_id in enumerate(basis_ids):
                    basis_reference = (
                        ("assertion", basis_id)
                        if isinstance(basis_id, str)
                        else None
                    )
                    basis_required = set(required)
                    if basis_reference is not None:
                        basis_required.add(basis_reference)
                    basis_location = (
                        f"{location}.{axis_name}.basis_assertion_ids[{basis_index}]"
                    )
                    if not isinstance(basis_id, str) or basis_id in visited:
                        report_defect(
                            claim_id,
                            "unverified_assertion",
                            basis_required,
                            basis_location,
                            "legal-status basis assertion chain is invalid or cyclic",
                        )
                        bases_eligible = False
                        continue
                    assertion_entry = assertions.get(basis_id)
                    if assertion_entry is None:
                        report_defect(
                            claim_id,
                            "missing_dependency",
                            basis_required,
                            basis_location,
                            "legal-status basis assertion does not resolve",
                        )
                        bases_eligible = False
                        continue
                    assertion = assertion_entry[1]
                    assertion_time_axes = assertion.get("time_axes")
                    if assertion.get("status") not in {
                        "verified",
                        "disputed",
                        "superseded",
                    }:
                        report_defect(
                            claim_id,
                            "unverified_assertion",
                            basis_required,
                            basis_location,
                            "legal-status basis assertion is not independently reviewed",
                        )
                        bases_eligible = False
                    assertion_observation = (
                        assertion_time_axes.get("observation")
                        if isinstance(assertion_time_axes, dict)
                        else None
                    )
                    assertion_publication = (
                        assertion_time_axes.get("publication")
                        if isinstance(assertion_time_axes, dict)
                        else None
                    )
                    if not _temporal_point_not_after(
                        assertion_observation, snapshot_recorded_point
                    ) or not _temporal_point_not_after(
                        assertion_publication, authority_cutoff
                    ):
                        report_defect(
                            claim_id,
                            "missing_dependency",
                            basis_required,
                            basis_location,
                            "legal-status basis assertion was not available within the selected snapshot and authority cutoff",
                        )
                        bases_eligible = False
                    snapshot_instant = _parse_datetime(snapshot_recorded_at)
                    reviewed_at = (
                        _parse_datetime(assertion.get("reviewed_at"))
                        if isinstance(assertion.get("reviewed_at"), str)
                        else None
                    )
                    if (
                        reviewed_at is None
                        or snapshot_instant is None
                        or reviewed_at > snapshot_instant
                    ):
                        report_defect(
                            claim_id,
                            "unverified_assertion",
                            basis_required,
                            f"{basis_location}.reviewed_at",
                            "legal-status basis assertion was not reviewed by the selected snapshot",
                        )
                        bases_eligible = False
                    scope = assertion.get("scope")
                    scope_jurisdictions = {
                        item
                        for item in _list_or_empty(
                            scope.get("jurisdiction_ids")
                            if isinstance(scope, dict)
                            else None
                        )
                        if isinstance(item, str)
                    }
                    owner_jurisdictions = subject_jurisdictions(reference) or set()
                    if (
                        not owner_jurisdictions
                        or not owner_jurisdictions <= scope_jurisdictions
                    ):
                        report_defect(
                            claim_id,
                            "missing_dependency",
                            basis_required,
                            f"{basis_location}.scope.jurisdiction_ids",
                            "legal-status basis assertion does not cover its owning legal state's jurisdictions",
                        )
                        bases_eligible = False
                    extent = scope.get("extent") if isinstance(scope, dict) else None
                    if reference[0] == "version" and extent != "whole_entity":
                        report_defect(
                            claim_id,
                            "missing_dependency",
                            basis_required,
                            f"{basis_location}.scope.extent",
                            "version legal-status basis must cover the whole entity",
                        )
                        bases_eligible = False
                    if reference[0] == "provision_version":
                        provision_entry = provision_versions.get(reference[1])
                        provision_id = (
                            provision_entry[3].get("provision_id")
                            if provision_entry is not None
                            else None
                        )
                        targets = {
                            item
                            for item in _list_or_empty(
                                scope.get("target_provision_ids")
                                if isinstance(scope, dict)
                                else None
                            )
                            if isinstance(item, str)
                        }
                        if extent != "whole_entity" and not (
                            extent == "selected_provisions"
                            and isinstance(provision_id, str)
                            and provision_id in targets
                        ):
                            report_defect(
                                claim_id,
                                "missing_dependency",
                                basis_required,
                                f"{basis_location}.scope.extent",
                                "provision legal-status basis does not cover the selected provision",
                            )
                            bases_eligible = False
                    assertion_interval = (
                        assertion_time_axes.get(axis_name)
                        if isinstance(assertion_time_axes, dict)
                        else None
                    )
                    if _temporal_interval_has_approximate_boundary(
                        assertion_interval
                    ):
                        report_defect(
                            claim_id,
                            (
                                "unknown_effective_time"
                                if axis_name == "effectiveness"
                                else "unknown_applicability"
                            ),
                            basis_required,
                            f"{basis_location}.time_axes.{axis_name}",
                            f"legal-status basis assertion has an approximate {axis_name} boundary",
                        )
                        bases_eligible = False
                    interval_covers_context = (
                        _temporal_interval_covers_point(
                            assertion_interval, effective_at
                        )
                        if axis_name == "effectiveness"
                        else _temporal_interval_covers_interval(
                            assertion_interval, facts_period
                        )
                    )
                    if not interval_covers_context:
                        report_defect(
                            claim_id,
                            "missing_dependency",
                            basis_required,
                            f"{basis_location}.time_axes.{axis_name}",
                            f"legal-status basis assertion {axis_name} does not cover the evaluation context",
                        )
                        bases_eligible = False
                    nested_ids = (
                        assertion_interval.get("basis_assertion_ids")
                        if isinstance(assertion_interval, dict)
                        else None
                    )
                    if isinstance(nested_ids, list) and nested_ids:
                        if not validate_basis_assertions(
                            axis_name,
                            assertion_interval,
                            visited | {basis_id},
                        ):
                            bases_eligible = False
                return bases_eligible

            if not validate_basis_assertions("effectiveness", effectiveness, set()):
                eligible = False
            if not validate_basis_assertions("applicability", applicability, set()):
                eligible = False
        return eligible

    def authority_jurisdictions_for_claim(
        authority_id: str,
        claim_id: str,
        claim_ref: tuple[str, str],
        claim_location: str,
        requested_jurisdictions: set[str],
    ) -> tuple[set[str], set[tuple[str, str]]]:
        """Resolve authority scope only through eligible relationship claims."""

        authority_entry = authorities.get(authority_id)
        authority = authority_entry[1] if authority_entry is not None else None
        if not isinstance(authority, dict):
            return set(), set()
        eligible_jurisdictions: set[str] = set()
        eligible_assertions: set[tuple[str, str]] = set()
        snapshot_instant = _parse_datetime(snapshot_recorded_at)
        for relationship_index, relationship in enumerate(
            _list_or_empty(authority.get("jurisdictions_served"))
        ):
            if not isinstance(relationship, dict):
                continue
            jurisdiction_id = relationship.get("jurisdiction_id")
            if (
                not isinstance(jurisdiction_id, str)
                or jurisdiction_id not in requested_jurisdictions
            ):
                continue
            assertion_id = relationship.get("assertion_id")
            assertion_ref = (
                ("assertion", assertion_id)
                if isinstance(assertion_id, str)
                else None
            )
            required = {claim_ref, ("authority", authority_id)}
            if assertion_ref is not None:
                required.add(assertion_ref)
            location = (
                f"{claim_location}.subjects.authority_scope"
                f"[{relationship_index}]"
            )
            assertion_entry = (
                assertions.get(assertion_id)
                if isinstance(assertion_id, str)
                else None
            )
            if assertion_entry is None:
                report_defect(
                    claim_id,
                    "missing_dependency",
                    required,
                    location,
                    "authority jurisdiction scope relationship does not resolve",
                )
                continue
            assertion = assertion_entry[1]
            relationship_eligible = True
            if not (
                _entity_reference_key(assertion.get("subject"))
                == ("authority", authority_id)
                and assertion.get("predicate") == "serves_jurisdiction"
                and _entity_reference_key(assertion.get("object"))
                == ("jurisdiction", jurisdiction_id)
            ):
                report_defect(
                    claim_id,
                    "missing_dependency",
                    required,
                    location,
                    "authority adjacency does not resolve to its exact jurisdiction relationship assertion",
                )
                relationship_eligible = False
            if assertion.get("status") not in {"verified", "superseded"}:
                report_defect(
                    claim_id,
                    "unverified_assertion",
                    required,
                    location,
                    "candidate, disputed, or retracted authority scope cannot establish claim jurisdiction",
                )
                relationship_eligible = False
            reviewed_at = (
                _parse_datetime(assertion.get("reviewed_at"))
                if isinstance(assertion.get("reviewed_at"), str)
                else None
            )
            if (
                assertion.get("status") in {"verified", "superseded"}
                and (
                    reviewed_at is None
                    or snapshot_instant is None
                    or reviewed_at > snapshot_instant
                )
            ):
                report_defect(
                    claim_id,
                    "unverified_assertion",
                    required,
                    f"{location}.reviewed_at",
                    "authority scope relationship was not reviewed by the selected corpus snapshot",
                )
                relationship_eligible = False
            scope = assertion.get("scope")
            scope_jurisdictions = {
                item
                for item in _list_or_empty(
                    scope.get("jurisdiction_ids")
                    if isinstance(scope, dict)
                    else None
                )
                if isinstance(item, str)
            }
            if (
                not isinstance(scope, dict)
                or scope.get("extent") != "whole_entity"
                or jurisdiction_id not in scope_jurisdictions
            ):
                report_defect(
                    claim_id,
                    "missing_dependency",
                    required,
                    f"{location}.scope",
                    "authority scope relationship does not cover the exact authority and jurisdiction",
                )
                relationship_eligible = False
            clocks_eligible = check_time_axes(
                claim_id,
                assertion_ref,
                assertion.get("time_axes"),
                f"{location}.time_axes",
                applicability_not_applicable=True,
            )
            if relationship_eligible and clocks_eligible and assertion_ref is not None:
                eligible_jurisdictions.add(jurisdiction_id)
                eligible_assertions.add(assertion_ref)
        return eligible_jurisdictions, eligible_assertions

    for claim_index, claim in enumerate(_list_or_empty(bundle.get("claims"))):
        if not isinstance(claim, dict) or not isinstance(claim.get("claim_id"), str):
            continue
        claim_id = claim["claim_id"]
        claim_ref = ("claim", claim_id)
        claim_location = f"$.claims[{claim_index}]"
        bibliographic_only = claim.get("content_use") == "bibliographic_fact"
        claim_applicability = claim.get("applicability")
        applicability_status = (
            claim_applicability.get("status")
            if isinstance(claim_applicability, dict)
            else None
        )
        if applicability_status == "unknown" or applicability_status is None or (
            applicability_status == "not_applicable" and not bibliographic_only
        ):
            report_defect(
                claim_id,
                "unknown_applicability",
                {claim_ref},
                f"{claim_location}.applicability",
                "a material claim needs known applicability; only a bibliographic-only claim may use explicit not_applicable",
            )
        elif applicability_status in {"known", "open_ended"}:
            if _temporal_interval_has_approximate_boundary(claim_applicability):
                report_defect(
                    claim_id,
                    "unknown_applicability",
                    {claim_ref},
                    f"{claim_location}.applicability",
                    "claim applicability has an approximate boundary; V1 cannot prove coverage of the facts period",
                )
            elif not _temporal_interval_covers_interval(
                claim_applicability, facts_period
            ):
                report_defect(
                    claim_id,
                    "missing_dependency",
                    {claim_ref},
                    f"{claim_location}.applicability",
                    "claim applicability does not cover evaluation_context.facts_period",
                )

        claim_jurisdictions = {
            item
            for item in _list_or_empty(claim.get("jurisdiction_ids"))
            if isinstance(item, str)
        }
        if not context_jurisdictions.issubset(claim_jurisdictions):
            report_defect(
                claim_id,
                "missing_dependency",
                {claim_ref},
                f"{claim_location}.jurisdiction_ids",
                "claim jurisdictions do not cover evaluation_context.jurisdiction_ids",
            )

        subject_refs: set[tuple[str, str]] = set()
        claim_provision_ids: set[str] = set()
        time_bearing_references: set[tuple[str, str]] = set()
        eligible_scope_references: set[tuple[str, str]] = set()
        eligible_evidence_jurisdictions: set[str] = set()
        bibliographic_facts_by_subject: dict[int, list[dict[str, Any]]] = {}
        for item in _list_or_empty(claim.get("bibliographic_facts")):
            subject_index = item.get("subject_index") if isinstance(item, dict) else None
            if bibliographic_only and isinstance(subject_index, int):
                bibliographic_facts_by_subject.setdefault(subject_index, []).append(item)
        bibliographic_subject_indexes = set(bibliographic_facts_by_subject)
        for subject_index, subject in enumerate(_list_or_empty(claim.get("subjects"))):
            reference = _entity_reference_key(subject)
            if reference is None:
                continue
            subject_refs.add(reference)
            entity_type, entity_id = reference
            if entity_type == "provision":
                claim_provision_ids.add(entity_id)
            elif entity_type == "provision_version":
                entry = provision_versions.get(entity_id)
                provision_id = entry[3].get("provision_id") if entry is not None else None
                if isinstance(provision_id, str):
                    claim_provision_ids.add(provision_id)
            jurisdictions = subject_jurisdictions(reference)
            if entity_type == "authority":
                jurisdictions, authority_scope_assertions = (
                    authority_jurisdictions_for_claim(
                        entity_id,
                        claim_id,
                        claim_ref,
                        f"{claim_location}.subjects[{subject_index}]",
                        claim_jurisdictions,
                    )
                )
                eligible_scope_references.update(authority_scope_assertions)
            if jurisdictions is not None and not jurisdictions.intersection(
                context_jurisdictions
            ):
                report_defect(
                    claim_id,
                    "missing_dependency",
                    {claim_ref, reference},
                    f"{claim_location}.subjects[{subject_index}]",
                    "claim subject is outside the evaluation-context jurisdictions",
                )
            if bibliographic_only and subject_index in bibliographic_subject_indexes:
                observation_eligible = True
                if entity_type in {"authority", "jurisdiction"}:
                    profile_entry = (
                        authorities.get(entity_id)
                        if entity_type == "authority"
                        else jurisdiction_profiles.get(entity_id)
                    )
                    profile = profile_entry[1] if profile_entry is not None else None
                    selected_name_values = {
                        fact.get("value")
                        for fact in bibliographic_facts_by_subject[subject_index]
                        if fact.get("field") == "name"
                        and isinstance(fact.get("value"), str)
                    }
                    snapshot_instant = _parse_datetime(snapshot_recorded_at)
                    for selected_name in selected_name_values:
                        matching_names = [
                            name
                            for name in _list_or_empty(
                                profile.get("names")
                                if isinstance(profile, dict)
                                else None
                            )
                            if isinstance(name, dict)
                            and name.get("text") == selected_name
                        ]
                        eligible_name = False
                        for name in matching_names:
                            created_at = (
                                _parse_datetime(name.get("created_at"))
                                if isinstance(name.get("created_at"), str)
                                else None
                            )
                            reviewed_at = (
                                _parse_datetime(name.get("reviewed_at"))
                                if isinstance(name.get("reviewed_at"), str)
                                else None
                            )
                            if (
                                name.get("status") in {"verified", "superseded"}
                                and created_at is not None
                                and reviewed_at is not None
                                and snapshot_instant is not None
                                and created_at <= snapshot_instant
                                and reviewed_at <= snapshot_instant
                            ):
                                eligible_name = True
                                break
                        if not eligible_name:
                            report_defect(
                                claim_id,
                                "unverified_assertion",
                                {claim_ref, reference},
                                f"{claim_location}.subjects[{subject_index}]",
                                f"selected {entity_type} name was not independently verified by the selected corpus snapshot",
                            )
                            observation_eligible = False
                if entity_type == "assertion":
                    assertion_entry = assertions.get(entity_id)
                    assertion = (
                        assertion_entry[1] if assertion_entry is not None else None
                    )
                    reviewed_at = (
                        _parse_datetime(assertion.get("reviewed_at"))
                        if isinstance(assertion, dict)
                        and isinstance(assertion.get("reviewed_at"), str)
                        else None
                    )
                    snapshot_instant = (
                        _parse_datetime(snapshot_recorded_at)
                        if isinstance(snapshot_recorded_at, str)
                        else None
                    )
                    if (
                        not isinstance(assertion, dict)
                        or assertion.get("status")
                        not in {"verified", "disputed", "superseded"}
                        or reviewed_at is None
                        or snapshot_instant is None
                        or reviewed_at > snapshot_instant
                    ):
                        report_defect(
                            claim_id,
                            "unverified_assertion",
                            {claim_ref, reference},
                            f"{claim_location}.subjects[{subject_index}]",
                            "a bibliographic assertion subject was not independently reviewed by the selected corpus snapshot",
                        )
                        observation_eligible = False
                bibliographic_state_references = [reference]
                if entity_type == "provision_version":
                    provision_entry = provision_versions.get(entity_id)
                    parent_version_id = (
                        provision_entry[2] if provision_entry is not None else None
                    )
                    if isinstance(parent_version_id, str) and parent_version_id:
                        bibliographic_state_references.append(
                            ("version", parent_version_id)
                        )
                if entity_type in {"version", "provision_version", "assertion"}:
                    for state_index, state_reference in enumerate(
                        bibliographic_state_references
                    ):
                        if not check_time_axes(
                            claim_id,
                            state_reference,
                            subject_time_axes(state_reference),
                            (
                                f"{claim_location}.subjects[{subject_index}].time_axes"
                                if state_index == 0
                                else f"{claim_location}.subjects[{subject_index}].containing_version.time_axes"
                            ),
                            legal_clocks_required=False,
                        ):
                            observation_eligible = False
                if observation_eligible and jurisdictions is not None:
                    eligible_scope_references.update(
                        bibliographic_state_references
                    )
                    eligible_evidence_jurisdictions.update(jurisdictions)
            elif not bibliographic_only and entity_type in {
                "version",
                "provision_version",
            }:
                legal_state_references = [reference]
                if entity_type == "provision_version":
                    provision_entry = provision_versions.get(entity_id)
                    parent_version_id = (
                        provision_entry[2] if provision_entry is not None else None
                    )
                    if isinstance(parent_version_id, str) and parent_version_id:
                        legal_state_references.append(("version", parent_version_id))
                legal_state_eligible = True
                for legal_state_index, legal_state_reference in enumerate(
                    legal_state_references
                ):
                    time_axes = subject_time_axes(legal_state_reference)
                    time_bearing_references.add(legal_state_reference)
                    if not check_time_axes(
                        claim_id,
                        legal_state_reference,
                        time_axes,
                        (
                            f"{claim_location}.subjects[{subject_index}].time_axes"
                            if legal_state_index == 0
                            else f"{claim_location}.subjects[{subject_index}].containing_version.time_axes"
                        ),
                    ):
                        legal_state_eligible = False
                if legal_state_eligible and jurisdictions is not None:
                    eligible_scope_references.update(legal_state_references)
                    eligible_evidence_jurisdictions.update(jurisdictions)

        checked_assertions: set[str] = set()
        for field in ("assertion_ids", "contrary_assertion_ids"):
            for assertion_index, assertion_id in enumerate(
                _list_or_empty(claim.get(field))
            ):
                if not isinstance(assertion_id, str) or assertion_id in checked_assertions:
                    continue
                checked_assertions.add(assertion_id)
                reference = ("assertion", assertion_id)
                required = {claim_ref, reference}
                location = f"{claim_location}.{field}[{assertion_index}]"
                assertion_entry = assertions.get(assertion_id)
                if assertion_entry is None:
                    continue
                assertion = assertion_entry[1]
                time_bearing_references.add(reference)
                assertion_eligible = True
                if assertion.get("status") in {"candidate", "retracted"}:
                    report_defect(
                        claim_id,
                        "unverified_assertion",
                        required,
                        location,
                        "a relied-on candidate or retracted assertion is not eligible evidence",
                    )
                    assertion_eligible = False
                snapshot_instant = _parse_datetime(snapshot_recorded_at)
                reviewed_at = (
                    _parse_datetime(assertion.get("reviewed_at"))
                    if isinstance(assertion.get("reviewed_at"), str)
                    else None
                )
                if (
                    assertion.get("status")
                    in {"verified", "disputed", "superseded"}
                    and (
                        reviewed_at is None
                        or snapshot_instant is None
                        or reviewed_at > snapshot_instant
                    )
                ):
                    report_defect(
                        claim_id,
                        "unverified_assertion",
                        required,
                        f"{location}.reviewed_at",
                        "relied-on assertion was not independently reviewed by the selected corpus snapshot",
                    )
                    assertion_eligible = False
                scope = assertion.get("scope")
                scope_jurisdictions = {
                    item
                    for item in _list_or_empty(
                        scope.get("jurisdiction_ids")
                        if isinstance(scope, dict)
                        else None
                    )
                    if isinstance(item, str)
                }
                if not scope_jurisdictions.intersection(context_jurisdictions):
                    report_defect(
                        claim_id,
                        "missing_dependency",
                        required,
                        f"{location}.scope.jurisdiction_ids",
                        "relied-on assertion scope is outside the evaluation-context jurisdictions",
                    )
                    assertion_eligible = False
                extent = scope.get("extent") if isinstance(scope, dict) else None
                if extent in {None, "unknown", "partial"}:
                    report_defect(
                        claim_id,
                        "missing_dependency",
                        required,
                        f"{location}.scope.extent",
                        "relied-on assertion scope is not specific enough for the claim",
                    )
                    assertion_eligible = False
                elif extent == "selected_provisions" and claim_provision_ids:
                    assertion_targets = {
                        item
                        for item in _list_or_empty(scope.get("target_provision_ids"))
                        if isinstance(item, str)
                    }
                    if not assertion_targets.intersection(claim_provision_ids):
                        report_defect(
                            claim_id,
                            "missing_dependency",
                            required,
                            f"{location}.scope.target_provision_ids",
                            "relied-on assertion scope does not cover a provision subject of the claim",
                        )
                        assertion_eligible = False
                endpoints = {
                    key
                    for endpoint in (assertion.get("subject"), assertion.get("object"))
                    if (key := _entity_reference_key(endpoint)) is not None
                }
                if subject_refs and not endpoints.intersection(subject_refs):
                    report_defect(
                        claim_id,
                        "missing_dependency",
                        required,
                        location,
                        "relied-on assertion does not concern a subject of the claim",
                    )
                    assertion_eligible = False
                clocks_eligible = check_time_axes(
                    claim_id,
                    reference,
                    assertion.get("time_axes"),
                    f"{location}.time_axes",
                    applicability_not_applicable=(
                        assertion.get("predicate")
                        in NON_APPLICABILITY_ASSERTION_PREDICATES
                    ),
                )
                if assertion_eligible and clocks_eligible:
                    eligible_scope_references.add(reference)
                    eligible_evidence_jurisdictions.update(scope_jurisdictions)

        if not bibliographic_only:
            modeled_state_refs = set(subject_refs)
            for entity_type, entity_id in list(subject_refs):
                if entity_type != "provision_version":
                    continue
                provision_entry = provision_versions.get(entity_id)
                containing_version_id = (
                    provision_entry[2] if provision_entry is not None else None
                )
                if isinstance(containing_version_id, str):
                    modeled_state_refs.add(("version", containing_version_id))
            modeled_assertion_ids = {
                assertion_id
                for field in ("assertion_ids", "contrary_assertion_ids")
                for assertion_id in _list_or_empty(claim.get(field))
                if isinstance(assertion_id, str)
            }
            legal_history_queue = [
                reference
                for reference in modeled_state_refs
                if reference[0] in {"version", "provision_version"}
            ]
            seen_legal_history_edges: set[
                tuple[tuple[str, str], tuple[str, str]]
            ] = set()
            while legal_history_queue:
                older_type, older_id = legal_history_queue.pop()
                incoming_map = (
                    incoming_versions
                    if older_type == "version"
                    else incoming_provision_versions
                )
                for newer_id in incoming_map.get(older_id, []):
                    newer_ref = (older_type, newer_id)
                    edge = ((older_type, older_id), newer_ref)
                    if edge in seen_legal_history_edges:
                        continue
                    seen_legal_history_edges.add(edge)
                    if not legal_state_snapshot_visible(older_type, newer_id):
                        continue
                    legal_history_queue.append(newer_ref)
                    if older_type == "version":
                        newer_entry = record_versions.get(newer_id)
                        newer_state = newer_entry[2] if newer_entry is not None else None
                    else:
                        newer_entry = provision_versions.get(newer_id)
                        newer_state = newer_entry[3] if newer_entry is not None else None
                    if not legal_state_may_affect_context(newer_state):
                        continue
                    transition_ids = transition_assertion_ids(
                        older_type, newer_id, older_id, newer_state
                    )
                    required = {
                        claim_ref,
                        (older_type, older_id),
                        newer_ref,
                        *(("assertion", item) for item in transition_ids),
                    }
                    if newer_ref not in modeled_state_refs:
                        report_defect(
                            claim_id,
                            "missing_dependency",
                            required,
                            f"{claim_location}.version_history",
                            f"snapshot-visible {older_type} successor {newer_id!r} may affect the evaluation context but is not a claim subject",
                        )
                    if not transition_ids.intersection(modeled_assertion_ids):
                        report_defect(
                            claim_id,
                            "missing_dependency",
                            required,
                            f"{claim_location}.version_history",
                            f"snapshot-visible {older_type} successor {newer_id!r} lacks an explicitly modeled transition assertion",
                        )

        supporting_history_ids = {
            assertion_id
            for assertion_id in _list_or_empty(claim.get("assertion_ids"))
            if isinstance(assertion_id, str)
        } | {
            entity_id
            for entity_type, entity_id in subject_refs | eligible_scope_references
            if entity_type == "assertion"
        }
        contrary_history_ids = {
            assertion_id
            for assertion_id in _list_or_empty(claim.get("contrary_assertion_ids"))
            if isinstance(assertion_id, str)
        }
        basis_axes: list[Any] = []
        for reference in subject_refs:
            basis_axes.append(subject_time_axes(reference))
            if reference[0] == "provision_version":
                provision_entry = provision_versions.get(reference[1])
                parent_version_id = (
                    provision_entry[2] if provision_entry is not None else None
                )
                if isinstance(parent_version_id, str):
                    basis_axes.append(subject_time_axes(("version", parent_version_id)))
        basis_pending = list(supporting_history_ids)
        for time_axes in basis_axes:
            for basis_id in assertion_basis_ids(time_axes):
                if basis_id not in supporting_history_ids:
                    supporting_history_ids.add(basis_id)
                    basis_pending.append(basis_id)
        while basis_pending:
            basis_id = basis_pending.pop()
            basis_entry = assertions.get(basis_id)
            nested_ids = assertion_basis_ids(
                basis_entry[1].get("time_axes")
                if basis_entry is not None
                else None
            )
            for nested_id in nested_ids - supporting_history_ids:
                supporting_history_ids.add(nested_id)
                basis_pending.append(nested_id)

        conflict_sets = [
            {
                assertion_id
                for assertion_id in _list_or_empty(conflict.get("assertion_ids"))
                if isinstance(assertion_id, str)
            }
            for conflict in _list_or_empty(bundle.get("conflicts"))
            if isinstance(conflict, dict)
        ]
        history_queue = [
            *((assertion_id, "supporting") for assertion_id in supporting_history_ids),
            *((assertion_id, "contrary") for assertion_id in contrary_history_ids),
        ]
        seen_history_roles: set[tuple[str, str]] = set()
        while history_queue:
            older_id, older_role = history_queue.pop()
            if (older_id, older_role) in seen_history_roles:
                continue
            seen_history_roles.add((older_id, older_role))
            for newer_id, relation_field in incoming_history.get(older_id, []):
                if not incoming_history_is_visible(
                    newer_id, older_id, relation_field
                ):
                    continue
                newer_entry = assertions.get(newer_id)
                if newer_entry is None:
                    continue
                newer_role = (
                    older_role
                    if relation_field == "supersedes_assertion_ids"
                    else ("contrary" if older_role == "supporting" else "supporting")
                )
                history_queue.append((newer_id, newer_role))
                if not incoming_history_may_affect_context(
                    newer_entry[1], bibliographic_only=bibliographic_only
                ):
                    continue
                role_ids = (
                    supporting_history_ids
                    if newer_role == "supporting"
                    else contrary_history_ids
                )
                modeled = newer_id in role_ids
                if relation_field == "disputes_assertion_ids":
                    modeled = modeled and any(
                        {older_id, newer_id} <= conflict_ids
                        for conflict_ids in conflict_sets
                    )
                if not modeled:
                    relationship_name = (
                        "supersession"
                        if relation_field == "supersedes_assertion_ids"
                        else "dispute"
                    )
                    report_defect(
                        claim_id,
                        "missing_dependency",
                        {
                            claim_ref,
                            ("assertion", older_id),
                            ("assertion", newer_id),
                        },
                        f"{claim_location}.assertion_history",
                        f"reviewed incoming assertion {relationship_name} was visible by the selected snapshot but is not explicitly modeled in the claim",
                    )
        if not bibliographic_only and not time_bearing_references:
            report_defect(
                claim_id,
                "missing_dependency",
                {claim_ref},
                f"{claim_location}.subjects",
                "a material claim has no version-specific subject or assertion with intrinsic legal clocks",
            )
        missing_jurisdictions = (
            claim_jurisdictions - eligible_evidence_jurisdictions
        )
        if missing_jurisdictions:
            report_defect(
                claim_id,
                "missing_dependency",
                {
                    claim_ref,
                    *eligible_scope_references,
                    *(("jurisdiction", item) for item in missing_jurisdictions),
                },
                f"{claim_location}.jurisdiction_ids",
                "eligible claim evidence does not collectively cover the claim jurisdictions: "
                + ", ".join(sorted(missing_jurisdictions)),
            )
    return problems


def _affected_conflict_claims(
    claims: Any, conflict_assertion_ids: set[str]
) -> list[tuple[int, dict[str, Any]]]:
    affected: list[tuple[int, dict[str, Any]]] = []
    for claim_index, claim in enumerate(_list_or_empty(claims)):
        if not isinstance(claim, dict):
            continue
        supporting, contrary = _claim_conflict_assertion_sets(claim)
        if (
            supporting.isdisjoint(contrary)
            and bool(supporting & conflict_assertion_ids)
            and bool(contrary & conflict_assertion_ids)
            and conflict_assertion_ids <= supporting | contrary
        ):
            affected.append((claim_index, claim))
    return affected


def _typed_reference_ids(references: Any, entity_type: str) -> set[str]:
    return {
        reference["entity_id"]
        for reference in _list_or_empty(references)
        if isinstance(reference, dict)
        and reference.get("entity_type") == entity_type
        and isinstance(reference.get("entity_id"), str)
    }


def evidence_bundle_status_problems(
    path: Path, document: dict[str, Any]
) -> list[ValidationProblem]:
    """Keep coverage failures from being masked by a more optimistic status."""

    if not str(document.get("schema_id", "")).endswith("/evidence-bundle.schema.json"):
        return []
    generated_at = document.get("generated_at")
    generated = _parse_datetime(generated_at) if isinstance(generated_at, str) else None
    coverage = document.get("coverage")
    if not isinstance(coverage, list):
        return []

    problems: list[ValidationProblem] = []
    material_coverage_failure = False
    for index, result in enumerate(coverage):
        if not isinstance(result, dict):
            continue
        status = result.get("status")
        gap_ids = result.get("gap_ids")
        if status != "covered_for_declared_scope" or (
            isinstance(gap_ids, list) and bool(gap_ids)
        ):
            material_coverage_failure = True

        fresh_until = result.get("fresh_until")
        fresh = _parse_datetime(fresh_until) if isinstance(fresh_until, str) else None
        if generated is not None and fresh is not None and fresh < generated:
            material_coverage_failure = True
            if status == "covered_for_declared_scope":
                problems.append(
                    ValidationProblem(
                        path,
                        f"$.coverage[{index}].status",
                        "expired coverage must be marked stale before bundle publication",
                    )
                )

    if material_coverage_failure and document.get("status") != "INSUFFICIENT_COVERAGE":
        problems.append(
            ValidationProblem(
                path,
                "$.status",
                "material incomplete or stale coverage requires INSUFFICIENT_COVERAGE",
            )
        )

    status = document.get("status")
    unresolved_items = document.get("unresolved_items")
    unresolved = (
        [item for item in unresolved_items if isinstance(item, dict)]
        if isinstance(unresolved_items, list)
        else []
    )
    blocking = [item for item in unresolved if item.get("severity") == "blocking"]
    coverage_blocker_kinds = {
        "coverage_gap",
        "missing_dependency",
        "rights_limited_artifact",
        "stale_source",
        "unknown_effective_time",
        "unverified_assertion",
    }
    declared_coverage_blockers = sorted(
        {
            str(item.get("kind"))
            for item in blocking
            if item.get("kind") in coverage_blocker_kinds
        }
    )
    if declared_coverage_blockers and status != "INSUFFICIENT_COVERAGE":
        problems.append(
            ValidationProblem(
                path,
                "$.status",
                "MISSING_FACTS or CONFLICTED cannot mask blocking corpus-evidence conditions; INSUFFICIENT_COVERAGE is required: "
                + ", ".join(declared_coverage_blockers),
            )
        )
    if (
        status == "INSUFFICIENT_COVERAGE"
        and not material_coverage_failure
        and not declared_coverage_blockers
    ):
        problems.append(
            ValidationProblem(
                path,
                "$.status",
                "INSUFFICIENT_COVERAGE requires a material coverage result or blocking corpus-evidence item",
            )
        )
    has_blocking_conflict = any(
        item.get("kind") == "conflicting_assertions" for item in blocking
    )
    if (
        has_blocking_conflict
        and not declared_coverage_blockers
        and status != "CONFLICTED"
    ):
        problems.append(
            ValidationProblem(
                path,
                "$.status",
                "a blocking unresolved legal conflict requires CONFLICTED",
            )
        )

    if status == "MISSING_FACTS" and not any(
        item.get("kind") == "missing_fact" for item in blocking
    ):
        problems.append(
            ValidationProblem(
                path,
                "$.unresolved_items",
                "MISSING_FACTS requires an explicit blocking missing_fact item",
            )
        )

    if status == "CONFLICTED":
        claims = document.get("claims")
        citations = document.get("citations")
        conflicts = document.get("conflicts")
        if not isinstance(claims, list) or not claims:
            problems.append(
                ValidationProblem(path, "$.claims", "CONFLICTED requires at least one claim")
            )
        if not isinstance(citations, list) or not citations:
            problems.append(
                ValidationProblem(
                    path, "$.citations", "CONFLICTED requires at least one citation"
                )
            )
        if not isinstance(conflicts, list) or not any(
            isinstance(conflict, dict)
            and conflict.get("resolution_state") == "unresolved"
            for conflict in conflicts
        ):
            problems.append(
                ValidationProblem(
                    path,
                    "$.conflicts",
                    "CONFLICTED requires at least one unresolved conflict",
                )
            )
        if not any(item.get("kind") == "conflicting_assertions" for item in blocking):
            problems.append(
                ValidationProblem(
                    path,
                    "$.unresolved_items",
                    "CONFLICTED requires a blocking conflicting_assertions item",
                )
            )
        unrelated_blockers = sorted(
            {
                str(item.get("kind"))
                for item in blocking
                if item.get("kind") != "conflicting_assertions"
            }
        )
        if unrelated_blockers:
            problems.append(
                ValidationProblem(
                    path,
                    "$.status",
                    "CONFLICTED cannot mask other blocking conditions: "
                    + ", ".join(unrelated_blockers),
                )
            )

        claim_items = claims if isinstance(claims, list) else []
        for claim_index, claim in enumerate(claim_items):
            supporting, contrary = _claim_conflict_assertion_sets(claim)
            overlap = sorted(supporting & contrary)
            if overlap:
                problems.append(
                    ValidationProblem(
                        path,
                        f"$.claims[{claim_index}]",
                        "the same assertion cannot be both supporting and contrary: "
                        + ", ".join(overlap),
                    )
                )

        unresolved_conflict_signatures: set[
            tuple[frozenset[str], frozenset[str]]
        ] = set()
        seen_conflict_assertion_sets: set[frozenset[str]] = set()
        for conflict_index, conflict in enumerate(
            conflicts if isinstance(conflicts, list) else []
        ):
            if (
                not isinstance(conflict, dict)
                or conflict.get("resolution_state") != "unresolved"
            ):
                continue
            conflict_assertion_ids = {
                assertion_id
                for assertion_id in _list_or_empty(conflict.get("assertion_ids"))
                if isinstance(assertion_id, str)
            }
            assertion_signature = frozenset(conflict_assertion_ids)
            if assertion_signature in seen_conflict_assertion_sets:
                problems.append(
                    ValidationProblem(
                        path,
                        f"$.conflicts[{conflict_index}].assertion_ids",
                        "unresolved conflict assertion set duplicates another conflict group",
                    )
                )
            seen_conflict_assertion_sets.add(assertion_signature)
            affected_claims = _affected_conflict_claims(
                claim_items, conflict_assertion_ids
            )
            affected_claim_ids = {
                claim["claim_id"]
                for _, claim in affected_claims
                if isinstance(claim.get("claim_id"), str)
            }
            if not affected_claim_ids:
                problems.append(
                    ValidationProblem(
                        path,
                        f"$.conflicts[{conflict_index}].assertion_ids",
                        "unresolved conflict must be linked to an affected claim with explicit supporting and contrary assertions",
                    )
                )
            signature = (
                assertion_signature,
                frozenset(affected_claim_ids),
            )
            unresolved_conflict_signatures.add(signature)
            matching_blockers = [
                item
                for item in unresolved
                if item.get("kind") == "conflicting_assertions"
                and item.get("severity") == "blocking"
                and _typed_reference_ids(item.get("related_entities"), "assertion")
                == conflict_assertion_ids
                and _typed_reference_ids(item.get("related_entities"), "claim")
                == affected_claim_ids
            ]
            if len(matching_blockers) != 1:
                problems.append(
                    ValidationProblem(
                        path,
                        "$.unresolved_items",
                        "each unresolved conflict requires exactly one blocking item naming its exact assertion set and affected claims",
                    )
                )
            matching_tasks = [
                task
                for task in _list_or_empty(document.get("verification_tasks"))
                if isinstance(task, dict)
                and task.get("reason") == "conflicting"
                and _typed_reference_ids(task.get("targets"), "assertion")
                == conflict_assertion_ids
                and _typed_reference_ids(task.get("targets"), "claim")
                == affected_claim_ids
            ]
            if len(matching_tasks) != 1:
                problems.append(
                    ValidationProblem(
                        path,
                        "$.verification_tasks",
                        "each unresolved conflict requires exactly one conflicting verification task naming its exact assertion set and affected claims",
                    )
                )

        for unresolved_index, item in enumerate(unresolved):
            if (
                item.get("kind") != "conflicting_assertions"
                or item.get("severity") != "blocking"
            ):
                continue
            signature = (
                frozenset(
                    _typed_reference_ids(item.get("related_entities"), "assertion")
                ),
                frozenset(
                    _typed_reference_ids(item.get("related_entities"), "claim")
                ),
            )
            if signature not in unresolved_conflict_signatures:
                problems.append(
                    ValidationProblem(
                        path,
                        f"$.unresolved_items[{unresolved_index}].related_entities",
                        "blocking conflict item does not match one exact unresolved conflict and its affected claims",
                    )
                )

        for task_index, task in enumerate(
            _list_or_empty(document.get("verification_tasks"))
        ):
            if not isinstance(task, dict) or task.get("reason") != "conflicting":
                continue
            signature = (
                frozenset(_typed_reference_ids(task.get("targets"), "assertion")),
                frozenset(_typed_reference_ids(task.get("targets"), "claim")),
            )
            if signature not in unresolved_conflict_signatures:
                problems.append(
                    ValidationProblem(
                        path,
                        f"$.verification_tasks[{task_index}].targets",
                        "conflicting verification task does not match one exact unresolved conflict and its affected claims",
                    )
                )
    return problems


def evidence_bundle_privacy_problems(
    path: Path, document: dict[str, Any]
) -> list[ValidationProblem]:
    """Keep sensitive-looking claim details grounded in cited public text."""

    if not str(document.get("schema_id", "")).endswith("/evidence-bundle.schema.json"):
        return []
    claims = document.get("claims")
    citations = document.get("citations")
    if not isinstance(claims, list) or not isinstance(citations, list):
        return []

    def normalized(value: str) -> str:
        return re.sub(r"[\s,]", "", value).casefold()

    problems: list[ValidationProblem] = []
    for claim_index, claim in enumerate(claims):
        if not isinstance(claim, dict) or not isinstance(claim.get("claim_text"), str):
            continue
        citation_indexes = claim.get("citation_indexes")
        cited_text_parts: list[str] = []
        if isinstance(citation_indexes, list):
            for citation_index in citation_indexes:
                if not isinstance(citation_index, int) or not 0 <= citation_index < len(citations):
                    continue
                citation = citations[citation_index]
                if isinstance(citation, dict) and isinstance(citation.get("quoted_text"), str):
                    cited_text_parts.append(citation["quoted_text"])
        claim_text = claim["claim_text"]
        for pattern, label in (
            (CURRENCY_AMOUNT_PATTERN, "currency amount"),
            (EMAIL_ADDRESS_PATTERN, "email address"),
        ):
            for match in pattern.finditer(claim_text):
                if not any(
                    normalized(match.group(0)) in normalized(cited_text)
                    for cited_text in cited_text_parts
                ):
                    problems.append(
                        ValidationProblem(
                            path,
                            f"$.claims[{claim_index}].claim_text",
                            f"uncited {label} is forbidden in an agent evidence bundle",
                        )
                    )
    return problems


def evidence_bundle_handling_problems(
    path: Path, document: dict[str, Any]
) -> list[ValidationProblem]:
    """Bind retention and any public release to the exact reviewed bundle."""

    if not str(document.get("schema_id", "")).endswith(
        "/evidence-bundle.schema.json"
    ):
        return []
    handling = document.get("handling")
    if not isinstance(handling, dict):
        return []
    problems: list[ValidationProblem] = []
    generated_at = (
        _parse_datetime(document.get("generated_at"))
        if isinstance(document.get("generated_at"), str)
        else None
    )
    retention_until = (
        _parse_datetime(handling.get("retention_until"))
        if isinstance(handling.get("retention_until"), str)
        else None
    )
    if (
        handling.get("persistence") == "private_retained"
        and generated_at is not None
        and retention_until is not None
        and retention_until <= generated_at
    ):
        problems.append(
            ValidationProblem(
                path,
                "$.handling.retention_until",
                "private bundle retention must expire after bundle generation",
            )
        )

    if handling.get("persistence") != "public":
        return problems
    public_release = handling.get("public_release")
    if not isinstance(public_release, dict):
        return problems
    clearance = public_release.get("publication_clearance")
    if not _publication_clearance_is_valid(clearance):
        problems.append(
            ValidationProblem(
                path,
                "$.handling.public_release.publication_clearance",
                "public evidence bundle requires cleared, identified human publication review",
            )
        )
    elif isinstance(clearance, dict):
        reviewed_at = (
            _parse_datetime(clearance.get("reviewed_at"))
            if isinstance(clearance.get("reviewed_at"), str)
            else None
        )
        if (
            reviewed_at is not None
            and generated_at is not None
            and reviewed_at < generated_at
        ):
            problems.append(
                ValidationProblem(
                    path,
                    "$.handling.public_release.publication_clearance.reviewed_at",
                    "public bundle review cannot predate bundle generation",
                )
            )

    projection = dict(document)
    projected_handling = dict(handling)
    projected_public_release = dict(public_release)
    projected_public_release.pop("reviewed_payload_digest", None)
    projected_handling["public_release"] = projected_public_release
    projection["handling"] = projected_handling
    try:
        actual_digest = hashlib.sha256(_canonical_json_bytes(projection)).hexdigest()
    except (TypeError, UnicodeEncodeError, ValueError) as error:
        problems.append(
            ValidationProblem(
                path,
                "$.handling.public_release.reviewed_payload_digest",
                f"public bundle payload cannot be canonicalized: {error}",
            )
        )
    else:
        reviewed_digest = public_release.get("reviewed_payload_digest")
        declared_digest = (
            reviewed_digest.get("value")
            if isinstance(reviewed_digest, dict)
            else None
        )
        if declared_digest != actual_digest:
            problems.append(
                ValidationProblem(
                    path,
                    "$.handling.public_release.reviewed_payload_digest.value",
                    "public release digest does not match the exact bundle payload",
                )
            )
    return problems


CORRECTION_RECEIPT_FIELDS = {
    "draft_status",
    "public_review_status",
    "public_issue",
    "application",
    "duplicate_of_report_id",
}

# The base repository has no trusted GitHub organization, repository, bot
# identity, or authenticated receipt verifier yet.  A URL and a boolean inside
# an untrusted report are not proof that the project published or merged it.
# Keep public lifecycle receipts fail-closed until a separately reviewed policy
# can authenticate those external facts.
PROJECT_PUBLICATION_RECEIPTS_ENABLED = False


def _correction_prepublication_projection(
    document: dict[str, Any],
) -> dict[str, Any]:
    """Return the immutable public payload reviewed before an issue exists."""

    projection = dict(document)
    for field in CORRECTION_RECEIPT_FIELDS:
        projection.pop(field, None)
    privacy_review = document.get("privacy_review")
    if isinstance(privacy_review, dict):
        projected_privacy_review = dict(privacy_review)
        projected_privacy_review.pop("reviewed_payload_digest", None)
        projection["privacy_review"] = projected_privacy_review
    return projection


def correction_state_problems(
    path: Path, document: dict[str, Any]
) -> list[ValidationProblem]:
    """Enforce correction lifecycle gates that span multiple state fields."""

    if not str(document.get("schema_id", "")).endswith("/correction-report.schema.json"):
        return []
    problems: list[ValidationProblem] = []
    finding_status = document.get("finding_status")
    draft_status = document.get("draft_status")
    review_status = document.get("public_review_status")
    verification = document.get("verification")
    verification_status = verification.get("status") if isinstance(verification, dict) else None
    independent_fetch = (
        verification.get("independent_fetch") if isinstance(verification, dict) else None
    )
    verified_states = {"VERIFIED_GAP", "VERIFIED_ERROR", "OFFICIAL_CONFLICT"}
    evidence = document.get("public_evidence")
    evidence_items = evidence if isinstance(evidence, list) else []
    verification_time = (
        _parse_datetime(verification.get("checked_at"))
        if isinstance(verification, dict)
        and isinstance(verification.get("checked_at"), str)
        else None
    )

    if not PROJECT_PUBLICATION_RECEIPTS_ENABLED and (
        draft_status not in {"LOCAL_ONLY", "READY_TO_OPEN"}
        or review_status is not None
        or document.get("public_issue") is not None
        or document.get("application") is not None
    ):
        problems.append(
            ValidationProblem(
                path,
                "$.draft_status",
                "private-draft states and public correction receipts are disabled until trusted intake and receipt verification are configured",
            )
        )

    for index, item in enumerate(evidence_items):
        if not isinstance(item, dict):
            continue
        retrieved = (
            _parse_datetime(item.get("retrieved_at"))
            if isinstance(item.get("retrieved_at"), str)
            else None
        )
        clearance = item.get("publication_clearance")
        clearance_time = (
            _parse_datetime(clearance.get("reviewed_at"))
            if isinstance(clearance, dict)
            and isinstance(clearance.get("reviewed_at"), str)
            else None
        )
        if (
            clearance_time is not None
            and retrieved is not None
            and clearance_time < retrieved
        ):
            problems.append(
                ValidationProblem(
                    path,
                    f"$.public_evidence[{index}].publication_clearance.reviewed_at",
                    "publication clearance cannot predate correction evidence retrieval",
                )
            )
        if (
            item.get("role") in {"SUPPORTING", "CONTRARY"}
            and verification_time is not None
            and retrieved is not None
            and verification_time < retrieved
        ):
            problems.append(
                ValidationProblem(
                    path,
                    "$.verification.checked_at",
                    "correction verification cannot predate supporting or contrary evidence retrieval",
                )
            )

    if verification_status in verified_states and finding_status != verification_status:
        problems.append(
            ValidationProblem(
                path,
                "$.verification.status",
                "a verified verification status must exactly match finding_status",
            )
        )

    if (finding_status in verified_states or verification_status in verified_states) and (
        independent_fetch is not True
    ):
        problems.append(
            ValidationProblem(
                path,
                "$.verification.independent_fetch",
                "verified findings require an independent public-source fetch",
            )
        )

    if finding_status in verified_states:
        def verified_evidence(role: str) -> list[dict[str, Any]]:
            return [
                item
                for item in evidence_items
                if isinstance(item, dict)
                and item.get("role") == role
                and item.get("official_status") == "VERIFIED_OFFICIAL"
                and isinstance(item.get("content_digest"), dict)
                and isinstance(item.get("source_id"), str)
                and isinstance(item.get("capture_id"), str)
                and isinstance(item.get("artifact_id"), str)
            ]

        supporting = verified_evidence("SUPPORTING")
        if not supporting:
            problems.append(
                ValidationProblem(
                    path,
                    "$.public_evidence",
                    "verified findings require supporting evidence with a resolved source, capture, artifact, and content digest",
                )
            )

        observed_digest = (
            verification.get("observed_digest")
            if isinstance(verification, dict)
            else None
        )
        if not isinstance(observed_digest, dict) or not any(
            item.get("content_digest") == observed_digest for item in supporting
        ):
            problems.append(
                ValidationProblem(
                    path,
                    "$.verification.observed_digest",
                    "verified findings must bind the observed digest to supporting official evidence",
                )
            )

        if finding_status == "OFFICIAL_CONFLICT":
            contrary = verified_evidence("CONTRARY")
            if not contrary:
                problems.append(
                    ValidationProblem(
                        path,
                        "$.public_evidence",
                        "an official conflict requires contrary independently fetched official evidence with a content digest",
                    )
                )
            fingerprints = {
                (
                    item.get("official_url"),
                    json.dumps(item.get("content_digest"), sort_keys=True),
                    json.dumps(item.get("locator"), sort_keys=True),
                )
                for item in supporting + contrary
            }
            if contrary and len(fingerprints) < 2:
                problems.append(
                    ValidationProblem(
                        path,
                        "$.public_evidence",
                        "an official conflict requires two distinct official evidence observations",
                    )
                )

    if review_status is not None and draft_status != "OPENED":
        problems.append(
            ValidationProblem(
                path,
                "$.public_review_status",
                "a public review state is allowed only after the sanitized report is OPENED",
            )
        )
    if document.get("public_issue") is not None and draft_status != "OPENED":
        problems.append(
            ValidationProblem(
                path,
                "$.public_issue",
                "a public issue is allowed only after the sanitized report is OPENED",
            )
        )
    if draft_status in {"READY_TO_OPEN", "OPENED"}:
        attestation = document.get("privacy_attestation")
        submission_mode = (
            attestation.get("submission_mode") if isinstance(attestation, dict) else None
        )
        timing_protection = (
            attestation.get("timing_protection") if isinstance(attestation, dict) else None
        )
        if submission_mode not in {"broker_sanitized", "source_monitor"}:
            problems.append(
                ValidationProblem(
                    path,
                    "$.privacy_attestation.submission_mode",
                    "publishable reports must be rebuilt by the privacy broker or a source monitor",
                )
            )
        if submission_mode == "broker_sanitized" and timing_protection not in {
            "batched",
            "delayed",
        }:
            problems.append(
                ValidationProblem(
                    path,
                    "$.privacy_attestation.timing_protection",
                    "broker-published reports require batched or delayed timing protection",
                )
            )
        if submission_mode == "source_monitor" and timing_protection != "not_applicable":
            problems.append(
                ValidationProblem(
                    path,
                    "$.privacy_attestation.timing_protection",
                    "source-monitor reports must mark timing protection not_applicable",
                )
            )
        privacy_review = document.get("privacy_review")
        reviewer = (
            privacy_review.get("reviewer") if isinstance(privacy_review, dict) else None
        )
        if (
            not isinstance(privacy_review, dict)
            or privacy_review.get("status") != "CLEARED_FOR_PUBLICATION"
            or privacy_review.get("public_payload_origin")
            != "independently_reproduced_public_sources"
            or not isinstance(reviewer, dict)
            or reviewer.get("producer_type") != "human"
            or not isinstance(reviewer.get("producer_id"), str)
        ):
            problems.append(
                ValidationProblem(
                    path,
                    "$.privacy_review",
                    "public reports require an identified human review of a payload independently reproduced from public sources",
                )
            )
        if isinstance(privacy_review, dict):
            try:
                actual_digest = hashlib.sha256(
                    _canonical_json_bytes(
                        _correction_prepublication_projection(document)
                    )
                ).hexdigest()
            except (TypeError, UnicodeEncodeError, ValueError) as error:
                problems.append(
                    ValidationProblem(
                        path,
                        "$.privacy_review.reviewed_payload_digest",
                        f"public correction payload cannot be canonicalized: {error}",
                    )
                )
            else:
                reviewed_digest = privacy_review.get("reviewed_payload_digest")
                declared_digest = (
                    reviewed_digest.get("value")
                    if isinstance(reviewed_digest, dict)
                    else None
                )
                if declared_digest != actual_digest:
                    problems.append(
                        ValidationProblem(
                            path,
                            "$.privacy_review.reviewed_payload_digest.value",
                            "privacy review digest does not match the exact pre-publication correction payload",
                        )
                    )

        review_time = (
            _parse_datetime(privacy_review.get("reviewed_at"))
            if isinstance(privacy_review, dict)
            and isinstance(privacy_review.get("reviewed_at"), str)
            else None
        )
        if draft_status == "OPENED":
            public_issue = document.get("public_issue")
            published_at = (
                _parse_datetime(public_issue.get("published_at"))
                if isinstance(public_issue, dict)
                and isinstance(public_issue.get("published_at"), str)
                else None
            )
            published_digest = (
                public_issue.get("published_payload_digest")
                if isinstance(public_issue, dict)
                else None
            )
            reviewed_digest = (
                privacy_review.get("reviewed_payload_digest")
                if isinstance(privacy_review, dict)
                else None
            )
            if published_digest != reviewed_digest:
                problems.append(
                    ValidationProblem(
                        path,
                        "$.public_issue.published_payload_digest",
                        "public issue receipt does not match the privacy-reviewed pre-publication payload",
                    )
                )
            if (
                published_at is not None
                and review_time is not None
                and published_at < review_time
            ):
                problems.append(
                    ValidationProblem(
                        path,
                        "$.public_issue.published_at",
                        "public issue cannot predate the privacy review",
                    )
                )
        if evidence_items:
            for index, item in enumerate(evidence_items):
                if not isinstance(item, dict):
                    continue
                if not _publication_clearance_is_valid(
                    item.get("publication_clearance")
                ):
                    problems.append(
                        ValidationProblem(
                            path,
                            f"$.public_evidence[{index}].publication_clearance",
                            "public correction evidence requires independent publication clearance",
                        )
                    )
                retrieved = (
                    _parse_datetime(item.get("retrieved_at"))
                    if isinstance(item.get("retrieved_at"), str)
                    else None
                )
                clearance = item.get("publication_clearance")
                clearance_time = (
                    _parse_datetime(clearance.get("reviewed_at"))
                    if isinstance(clearance, dict)
                    and isinstance(clearance.get("reviewed_at"), str)
                    else None
                )
                if review_time is not None and retrieved is not None and review_time < retrieved:
                    problems.append(
                        ValidationProblem(
                            path,
                            "$.privacy_review.reviewed_at",
                            "privacy review cannot predate public evidence retrieval",
                        )
                    )
                if (
                    review_time is not None
                    and clearance_time is not None
                    and review_time < clearance_time
                ):
                    problems.append(
                        ValidationProblem(
                            path,
                            "$.privacy_review.reviewed_at",
                            "privacy review cannot predate public evidence publication clearance",
                        )
                    )
    if review_status in {"ACCEPTED", "APPLIED", "PROPAGATION_FAILED"} and (
        finding_status not in verified_states or independent_fetch is not True
    ):
        problems.append(
            ValidationProblem(
                path,
                "$.public_review_status",
                "accepted or applied corrections must be independently verified first",
            )
        )
    if review_status in {"APPLIED", "PROPAGATION_FAILED"} and not isinstance(
        document.get("application"), dict
    ):
        problems.append(
            ValidationProblem(
                path,
                "$.application",
                "applied or failed propagation states require merge, invalidation-event, and snapshot proof",
            )
        )
    return problems


def _producer_identity(value: Any) -> tuple[str, ...] | None:
    if not isinstance(value, dict):
        return None
    producer_id = value.get("producer_id")
    if isinstance(producer_id, str) and producer_id.strip():
        return ("stable-id", producer_id.strip().casefold())
    producer_type = value.get("producer_type")
    name = value.get("name")
    if not isinstance(producer_type, str) or not isinstance(name, str):
        return None
    return producer_type.casefold(), name.strip().casefold()


def _same_producer_identity(first: Any, second: Any) -> bool:
    first_id = first.get("producer_id") if isinstance(first, dict) else None
    second_id = second.get("producer_id") if isinstance(second, dict) else None
    if isinstance(first_id, str) and isinstance(second_id, str):
        return first_id.strip().casefold() == second_id.strip().casefold()
    first_identity = _producer_identity(
        {key: value for key, value in first.items() if key != "producer_id"}
        if isinstance(first, dict)
        else first
    )
    second_identity = _producer_identity(
        {key: value for key, value in second.items() if key != "producer_id"}
        if isinstance(second, dict)
        else second
    )
    return first_identity is not None and first_identity == second_identity


def _source_manifest_review_projection(document: dict[str, Any]) -> dict[str, Any]:
    """Return the source identity payload bound by an independent review."""

    projection = dict(document)
    identity_review = document.get("identity_review")
    if isinstance(identity_review, dict):
        projected_review = dict(identity_review)
        projected_review.pop("reviewed_manifest_digest", None)
        projection["identity_review"] = projected_review
    return projection


def source_manifest_identity_problems(
    path: Path, document: dict[str, Any]
) -> list[ValidationProblem]:
    """Keep a declared source a locator until an independent review binds it."""

    if not str(document.get("schema_id", "")).endswith(
        "/source-manifest.schema.json"
    ):
        return []
    problems: list[ValidationProblem] = []
    identity_state = document.get("identity_state")
    producer = document.get("producer")
    identity_review = document.get("identity_review")

    if identity_state != "reviewed":
        rights = document.get("rights")
        basis_evidence = (
            rights.get("basis_evidence") if isinstance(rights, dict) else None
        )
        for index, evidence in enumerate(_list_or_empty(basis_evidence)):
            if isinstance(evidence, dict) and evidence.get(
                "official_status"
            ) == "verified_official":
                problems.append(
                    ValidationProblem(
                        path,
                        f"$.rights.basis_evidence[{index}].official_status",
                        "a candidate source manifest cannot self-label rights evidence as verified official",
                    )
                )
        return problems

    if not isinstance(identity_review, dict):
        return problems
    reviewer = identity_review.get("reviewer")
    if _same_producer_identity(producer, reviewer):
        problems.append(
            ValidationProblem(
                path,
                "$.identity_review.reviewer",
                "the source-manifest producer may not approve its own source identity",
            )
        )

    created_at = (
        _parse_datetime(document.get("created_at"))
        if isinstance(document.get("created_at"), str)
        else None
    )
    updated_at = (
        _parse_datetime(document.get("updated_at"))
        if isinstance(document.get("updated_at"), str)
        else None
    )
    reviewed_at = (
        _parse_datetime(identity_review.get("reviewed_at"))
        if isinstance(identity_review.get("reviewed_at"), str)
        else None
    )
    if created_at is not None and updated_at is not None and updated_at < created_at:
        problems.append(
            ValidationProblem(
                path,
                "$.updated_at",
                "source-manifest updated_at cannot predate created_at",
            )
        )
    if reviewed_at is not None and created_at is not None and reviewed_at < created_at:
        problems.append(
            ValidationProblem(
                path,
                "$.identity_review.reviewed_at",
                "source identity review cannot predate the source manifest",
            )
        )
    if reviewed_at is not None and updated_at is not None and updated_at < reviewed_at:
        problems.append(
            ValidationProblem(
                path,
                "$.updated_at",
                "source-manifest updated_at must include the identity review",
            )
        )

    try:
        actual_digest = hashlib.sha256(
            _canonical_json_bytes(_source_manifest_review_projection(document))
        ).hexdigest()
    except (TypeError, UnicodeEncodeError, ValueError) as error:
        problems.append(
            ValidationProblem(
                path,
                "$.identity_review.reviewed_manifest_digest",
                f"source identity review payload cannot be canonicalized: {error}",
            )
        )
    else:
        reviewed_digest = identity_review.get("reviewed_manifest_digest")
        declared_digest = (
            reviewed_digest.get("value")
            if isinstance(reviewed_digest, dict)
            else None
        )
        if declared_digest != actual_digest:
            problems.append(
                ValidationProblem(
                    path,
                    "$.identity_review.reviewed_manifest_digest.value",
                    "source identity review digest does not match the exact source manifest",
                )
            )
    return problems


def relationship_review_problems(
    path: Path, document: dict[str, Any]
) -> list[ValidationProblem]:
    """Reviewed assertions must not be self-reviewed."""

    if not str(document.get("schema_id", "")).endswith(
        "/relationship-assertion.schema.json"
    ):
        return []
    if document.get("status") not in {"verified", "disputed", "superseded", "retracted"}:
        return []
    problems: list[ValidationProblem] = []
    producer = document.get("producer")
    reviewer = document.get("reviewer")
    if _same_producer_identity(producer, reviewer):
        problems.append(
            ValidationProblem(
                path,
                "$.reviewer",
                "an assertion producer may not review the same assertion",
            )
        )
    if document.get("interpretation_level") == "legal_interpretation" and (
        not isinstance(reviewer, dict) or reviewer.get("producer_type") != "human"
    ):
        problems.append(
            ValidationProblem(
                path,
                "$.reviewer",
                "reviewed legal interpretations require an independent human reviewer",
            )
        )
    created_at = (
        _parse_datetime(document.get("created_at"))
        if isinstance(document.get("created_at"), str)
        else None
    )
    reviewed_at = (
        _parse_datetime(document.get("reviewed_at"))
        if isinstance(document.get("reviewed_at"), str)
        else None
    )
    if created_at is not None and reviewed_at is not None and reviewed_at < created_at:
        problems.append(
            ValidationProblem(
                path,
                "$.reviewed_at",
                "assertion review cannot predate assertion creation",
            )
        )
    time_axes = document.get("time_axes")
    publication = (
        time_axes.get("publication") if isinstance(time_axes, dict) else None
    )
    if isinstance(publication, dict) and publication.get("status") in {
        "exact",
        "approximate",
    }:
        verbatim = publication.get("verbatim_value")
        normalized = publication.get("value")
        matching_binding = False
        for evidence_index, citation in enumerate(
            _list_or_empty(document.get("evidence"))
        ):
            if not isinstance(citation, dict):
                continue
            binding = citation.get("temporal_value_binding")
            if not isinstance(binding, dict):
                continue
            location = f"$.evidence[{evidence_index}].temporal_value_binding"
            source_value = binding.get("source_value")
            source_matches = isinstance(verbatim, str) and source_value == verbatim
            normalized_matches = binding.get("normalized_value") == normalized
            quoted_text = citation.get("quoted_text")
            quoted_digest = citation.get("quoted_text_digest")
            if isinstance(quoted_text, str) and isinstance(source_value, str):
                content_matches = " ".join(source_value.casefold().split()) in " ".join(
                    quoted_text.casefold().split()
                )
            elif isinstance(quoted_digest, dict) and isinstance(source_value, str):
                content_matches = quoted_digest.get("value") == hashlib.sha256(
                    source_value.encode("utf-8")
                ).hexdigest()
            else:
                content_matches = False
            if source_matches and normalized_matches and content_matches:
                matching_binding = True
            if not source_matches:
                problems.append(
                    ValidationProblem(
                        path,
                        f"{location}.source_value",
                        "reviewed assertion publication binding must match publication.verbatim_value",
                    )
                )
            if not normalized_matches:
                problems.append(
                    ValidationProblem(
                        path,
                        f"{location}.normalized_value",
                        "reviewed assertion publication binding must match publication.value",
                    )
                )
            if not content_matches:
                problems.append(
                    ValidationProblem(
                        path,
                        f"$.evidence[{evidence_index}]",
                        "reviewed assertion publication binding is not bound to its cited text or exact text digest",
                    )
                )
        if not isinstance(verbatim, str) or not verbatim:
            problems.append(
                ValidationProblem(
                    path,
                    "$.time_axes.publication.verbatim_value",
                    "reviewed assertion with a known publication time must preserve the source expression",
                )
            )
        if not matching_binding:
            problems.append(
                ValidationProblem(
                    path,
                    "$.evidence",
                    "reviewed assertion publication time lacks an exact source-to-normalized temporal binding",
                )
            )
    projection = dict(document)
    projection.pop("reviewed_assertion_digest", None)
    try:
        actual_digest = hashlib.sha256(_canonical_json_bytes(projection)).hexdigest()
    except (TypeError, UnicodeEncodeError, ValueError) as error:
        problems.append(
            ValidationProblem(
                path,
                "$.reviewed_assertion_digest",
                f"reviewed assertion cannot be canonicalized: {error}",
            )
        )
    else:
        reviewed_digest = document.get("reviewed_assertion_digest")
        declared_digest = (
            reviewed_digest.get("value")
            if isinstance(reviewed_digest, dict)
            else None
        )
        if declared_digest != actual_digest:
            problems.append(
                ValidationProblem(
                    path,
                    "$.reviewed_assertion_digest.value",
                    "assertion review digest does not match the exact assertion payload",
                )
            )
    return problems


def profile_review_problems(path: Path, document: dict[str, Any]) -> list[ValidationProblem]:
    """Bind authority and jurisdiction profile fields to their exact evidence."""

    schema_id = str(document.get("schema_id", ""))
    if not schema_id.endswith(("/authority.schema.json", "/jurisdiction.schema.json")):
        return []
    reviewed_states = {"verified", "disputed", "superseded", "retracted"}
    candidates: list[tuple[str, Any, Any, Any, Any]] = [
        (
            "$",
            document.get("profile_review_state"),
            document.get("producer"),
            document.get("reviewer"),
            document.get("reviewed_at"),
        )
    ]
    names = document.get("names")
    if isinstance(names, list):
        for index, name in enumerate(names):
            if isinstance(name, dict):
                candidates.append(
                    (
                        f"$.names[{index}]",
                        name.get("status"),
                        name.get("producer"),
                        name.get("reviewer"),
                        name.get("reviewed_at"),
                    )
                )
    problems: list[ValidationProblem] = []
    profile_created_at = (
        _parse_datetime(document.get("created_at"))
        if isinstance(document.get("created_at"), str)
        else None
    )
    profile_updated_at = (
        _parse_datetime(document.get("updated_at"))
        if isinstance(document.get("updated_at"), str)
        else None
    )
    for location, status, producer, reviewer, reviewed_at_value in candidates:
        if (
            status in reviewed_states
            and _same_producer_identity(producer, reviewer)
        ):
            problems.append(
                ValidationProblem(
                    path,
                    f"{location}.reviewer" if location != "$" else "$.reviewer",
                    "a profile claim producer may not review the same claim",
                )
            )
        reviewed_at = (
            _parse_datetime(reviewed_at_value)
            if isinstance(reviewed_at_value, str)
            else None
        )
        if (
            reviewed_at is not None
            and profile_updated_at is not None
            and profile_updated_at < reviewed_at
        ):
            problems.append(
                ValidationProblem(
                    path,
                    f"{location}.reviewed_at" if location != "$" else "$.reviewed_at",
                    "profile update time cannot predate a profile or name review",
                )
            )

    def check_bindings(
        bindings: Any,
        evidence: Any,
        expected_values: dict[tuple[str, int | None], Any],
        base_location: str,
        claim_created_at_value: Any,
    ) -> None:
        binding_items = bindings if isinstance(bindings, list) else []
        evidence_items = evidence if isinstance(evidence, list) else []
        claim_created_at = (
            _parse_datetime(claim_created_at_value)
            if isinstance(claim_created_at_value, str)
            else None
        )
        seen_keys: set[tuple[Any, Any]] = set()
        covered_keys: set[tuple[str, int | None]] = set()
        used_evidence_indexes: set[int] = set()

        for binding_index, binding in enumerate(binding_items):
            if not isinstance(binding, dict):
                continue
            binding_location = f"{base_location}[{binding_index}]"
            field = binding.get("field")
            branch_index = binding.get("branch_index")
            field_key = field if isinstance(field, str) else None
            normalized_branch_index = (
                branch_index
                if isinstance(branch_index, int) and not isinstance(branch_index, bool)
                else None
            )
            binding_key = (
                field_key,
                normalized_branch_index if field == "branch" else None,
            )
            if binding_key in seen_keys:
                problems.append(
                    ValidationProblem(
                        path,
                        binding_location,
                        "profile field has more than one evidence binding",
                    )
                )
            else:
                seen_keys.add(binding_key)

            if field == "branch" and (
                not isinstance(branch_index, int)
                or isinstance(branch_index, bool)
                or ("branch", branch_index) not in expected_values
            ):
                problems.append(
                    ValidationProblem(
                        path,
                        f"{binding_location}.branch_index",
                        "profile branch index is outside branches",
                    )
                )
            elif isinstance(field, str) and binding_key in expected_values:
                covered_keys.add(binding_key)

            selected_quotes: list[str] = []
            selected_digest_bound = False
            selected_digest_values: set[str] = set()
            for evidence_index_index, evidence_index in enumerate(
                _list_or_empty(binding.get("evidence_indexes"))
            ):
                if (
                    not isinstance(evidence_index, int)
                    or isinstance(evidence_index, bool)
                    or not 0 <= evidence_index < len(evidence_items)
                ):
                    problems.append(
                        ValidationProblem(
                            path,
                            f"{binding_location}.evidence_indexes[{evidence_index_index}]",
                            "profile evidence index is outside the binding's evidence array",
                        )
                    )
                    continue
                citation = evidence_items[evidence_index]
                used_evidence_indexes.add(evidence_index)
                quoted_text = (
                    citation.get("quoted_text") if isinstance(citation, dict) else None
                )
                if isinstance(quoted_text, str):
                    selected_quotes.append(quoted_text)
                elif isinstance(citation, dict) and isinstance(
                    citation.get("quoted_text_digest"), dict
                ):
                    digest_value = citation["quoted_text_digest"].get("value")
                    if isinstance(digest_value, str):
                        selected_digest_values.add(digest_value)

            source_value = binding.get("source_value")
            selected_digest_bound = (
                isinstance(source_value, str)
                and hashlib.sha256(source_value.encode("utf-8")).hexdigest()
                in selected_digest_values
            )
            if not isinstance(source_value, str) or not (
                selected_digest_bound
                or any(
                    _quote_has_exact_field_value(
                        quote,
                        source_value,
                        field="profile_binding",
                    )
                    for quote in selected_quotes
                )
            ):
                problems.append(
                    ValidationProblem(
                        path,
                        f"{binding_location}.source_value",
                        "profile source value is not present at an exact whole-field boundary in its selected evidence",
                    )
                )

            normalized_value = binding.get("normalized_value")
            expected_value = expected_values.get(binding_key)
            if binding_key in expected_values and normalized_value != expected_value:
                problems.append(
                    ValidationProblem(
                        path,
                        f"{binding_location}.normalized_value",
                        "profile field does not match its binding's normalized value",
                    )
                )
            if (
                binding.get("method") == "source_exact"
                and source_value != normalized_value
            ):
                problems.append(
                    ValidationProblem(
                        path,
                        f"{binding_location}.method",
                        "source_exact profile binding requires identical source and normalized values",
                    )
                )
            if field == "text" and binding.get("method") != "source_exact":
                problems.append(
                    ValidationProblem(
                        path,
                        f"{binding_location}.method",
                        "sourced-name text must be copied exactly from its selected evidence",
                    )
                )

            binding_created_at = (
                _parse_datetime(binding.get("created_at"))
                if isinstance(binding.get("created_at"), str)
                else None
            )
            if binding_created_at is not None and any(
                created_at is not None and binding_created_at < created_at
                for created_at in (profile_created_at, claim_created_at)
            ):
                problems.append(
                    ValidationProblem(
                        path,
                        f"{binding_location}.created_at",
                        "profile field binding cannot predate its profile or name",
                    )
                )
            if (
                binding_created_at is not None
                and profile_updated_at is not None
                and profile_updated_at < binding_created_at
            ):
                problems.append(
                    ValidationProblem(
                        path,
                        f"{binding_location}.created_at",
                        "profile field binding cannot postdate profile updated_at",
                    )
                )

            normalization_review = binding.get("normalization_review")
            if (
                binding.get("method") != "source_exact"
                and not isinstance(normalization_review, dict)
            ):
                problems.append(
                    ValidationProblem(
                        path,
                        f"{binding_location}.normalization_review",
                        "non-source-exact profile values require independent human normalization review",
                    )
                )
                continue
            if not isinstance(normalization_review, dict):
                continue
            reviewer = normalization_review.get("reviewer")
            if (
                not isinstance(reviewer, dict)
                or reviewer.get("producer_type") != "human"
                or not isinstance(reviewer.get("producer_id"), str)
            ):
                problems.append(
                    ValidationProblem(
                        path,
                        f"{binding_location}.normalization_review.reviewer",
                        "profile normalization requires an identified human reviewer",
                    )
                )
            elif _same_producer_identity(binding.get("producer"), reviewer):
                problems.append(
                    ValidationProblem(
                        path,
                        f"{binding_location}.normalization_review.reviewer",
                        "profile binding producer may not approve its own normalization",
                    )
                )
            reviewed_at = (
                _parse_datetime(normalization_review.get("reviewed_at"))
                if isinstance(normalization_review.get("reviewed_at"), str)
                else None
            )
            if reviewed_at is not None and any(
                created_at is not None and reviewed_at < created_at
                for created_at in (
                    profile_created_at,
                    claim_created_at,
                    binding_created_at,
                )
            ):
                problems.append(
                    ValidationProblem(
                        path,
                        f"{binding_location}.normalization_review.reviewed_at",
                        "profile normalization review cannot predate its binding, profile, or name",
                    )
                )
            if (
                reviewed_at is not None
                and profile_updated_at is not None
                and profile_updated_at < reviewed_at
            ):
                problems.append(
                    ValidationProblem(
                        path,
                        f"{binding_location}.normalization_review.reviewed_at",
                        "profile normalization review cannot postdate profile updated_at",
                    )
                )

            projected_binding = dict(binding)
            projected_review = dict(normalization_review)
            projected_review.pop("reviewed_binding_digest", None)
            projected_binding["normalization_review"] = projected_review
            try:
                actual_digest = hashlib.sha256(
                    _canonical_json_bytes(projected_binding)
                ).hexdigest()
            except (TypeError, UnicodeEncodeError, ValueError) as error:
                problems.append(
                    ValidationProblem(
                        path,
                        f"{binding_location}.normalization_review.reviewed_binding_digest",
                        f"profile binding cannot be canonicalized: {error}",
                    )
                )
            else:
                reviewed_digest = normalization_review.get(
                    "reviewed_binding_digest"
                )
                declared_digest = (
                    reviewed_digest.get("value")
                    if isinstance(reviewed_digest, dict)
                    else None
                )
                if declared_digest != actual_digest:
                    problems.append(
                        ValidationProblem(
                            path,
                            f"{binding_location}.normalization_review.reviewed_binding_digest.value",
                            "profile normalization review digest does not match the exact field binding",
                        )
                    )

        missing_keys = [key for key in expected_values if key not in covered_keys]
        if missing_keys:
            missing_labels = [
                f"branch[{index}]" if field == "branch" else field
                for field, index in missing_keys
            ]
            problems.append(
                ValidationProblem(
                    path,
                    base_location,
                    "profile fields lack evidence bindings for: "
                    + ", ".join(missing_labels),
                )
            )
        unused_evidence = sorted(
            set(range(len(evidence_items))) - used_evidence_indexes
        )
        if unused_evidence:
            evidence_location = base_location.rsplit(".", 1)[0] + ".evidence"
            if base_location == "$.profile_bindings":
                evidence_location = "$.profile_evidence"
            problems.append(
                ValidationProblem(
                    path,
                    evidence_location,
                    "profile contains evidence unused by every field binding at indexes: "
                    + ", ".join(map(str, unused_evidence)),
                )
            )

    if schema_id.endswith("/authority.schema.json"):
        expected_profile_values: dict[tuple[str, int | None], Any] = {
            ("authority_kind", None): document.get("authority_kind"),
            ("lifecycle_status", None): document.get("lifecycle_status"),
        }
        for branch_index, branch in enumerate(_list_or_empty(document.get("branches"))):
            expected_profile_values[("branch", branch_index)] = branch
    else:
        expected_profile_values = {
            ("jurisdiction_kind", None): document.get("jurisdiction_kind"),
            ("lifecycle_status", None): document.get("lifecycle_status"),
        }
    check_bindings(
        document.get("profile_bindings"),
        document.get("profile_evidence"),
        expected_profile_values,
        "$.profile_bindings",
        document.get("created_at"),
    )
    if isinstance(names, list):
        for name_index, name in enumerate(names):
            if not isinstance(name, dict):
                continue
            check_bindings(
                name.get("field_bindings"),
                name.get("evidence"),
                {
                    ("text", None): name.get("text"),
                    ("language", None): name.get("language"),
                    ("name_type", None): name.get("name_type"),
                    ("valid_during", None): name.get("valid_during"),
                },
                f"$.names[{name_index}].field_bindings",
                name.get("created_at"),
            )
    return problems


REBUILD_COMPONENTS = {
    "normalized_artifacts",
    "provision_versions",
    "relationship_graph",
    "summaries",
    "search_index",
    "embeddings",
    "coverage_ledgers",
    "evidence_bundles",
}

REBUILDS_BY_AFFECTED_ENTITY = {
    "source": REBUILD_COMPONENTS,
    "artifact": {
        "normalized_artifacts",
        "provision_versions",
        "relationship_graph",
        "summaries",
        "search_index",
        "embeddings",
        "evidence_bundles",
    },
    "capture": {
        "normalized_artifacts",
        "provision_versions",
        "relationship_graph",
        "summaries",
        "search_index",
        "embeddings",
        "evidence_bundles",
    },
    "derivation": {
        "normalized_artifacts",
        "provision_versions",
        "relationship_graph",
        "summaries",
        "search_index",
        "embeddings",
        "evidence_bundles",
    },
    "record": {
        "provision_versions",
        "relationship_graph",
        "summaries",
        "search_index",
        "embeddings",
        "evidence_bundles",
    },
    "version": {
        "provision_versions",
        "relationship_graph",
        "summaries",
        "search_index",
        "embeddings",
        "evidence_bundles",
    },
    "provision": {
        "provision_versions",
        "relationship_graph",
        "summaries",
        "search_index",
        "embeddings",
        "evidence_bundles",
    },
    "provision_version": {
        "provision_versions",
        "relationship_graph",
        "summaries",
        "search_index",
        "embeddings",
        "evidence_bundles",
    },
    "assertion": {
        "relationship_graph",
        "summaries",
        "search_index",
        "embeddings",
        "evidence_bundles",
    },
    "authority": {
        "relationship_graph",
        "summaries",
        "search_index",
        "embeddings",
        "evidence_bundles",
    },
    "jurisdiction": {
        "relationship_graph",
        "summaries",
        "search_index",
        "embeddings",
        "evidence_bundles",
    },
    "coverage": {"coverage_ledgers", "evidence_bundles"},
    "gap": {"coverage_ledgers", "evidence_bundles"},
    "claim": {"evidence_bundles"},
    "bundle": {"evidence_bundles"},
}

PRIMARY_ENTITY_TYPES_BY_EVENT = {
    "artifact_added": {"artifact"},
    "source_content_changed": {"source", "capture", "artifact"},
    "derived_artifact_rebuilt": {"derivation", "artifact"},
    "record_version_added": {"record", "version", "provision", "provision_version"},
    "assertion_state_changed": {"assertion"},
    "coverage_changed": {"coverage", "gap"},
    "rights_changed": {"source", "capture", "artifact", "derivation"},
    "artifact_quarantined": {"artifact"},
}


def invalidation_problems(path: Path, document: dict[str, Any]) -> list[ValidationProblem]:
    """Require a causal, complete propagation ledger between distinct snapshots."""

    if not str(document.get("schema_id", "")).endswith("/invalidation-event.schema.json"):
        return []
    problems: list[ValidationProblem] = []
    if document.get("snapshot_before") == document.get("snapshot_after"):
        problems.append(
            ValidationProblem(
                path,
                "$.snapshot_after",
                "invalidation must produce a snapshot distinct from snapshot_before",
            )
        )
    cause = document.get("cause")
    cause_is_material = isinstance(cause, dict) and any(
        (
            isinstance(value, list)
            and bool(value)
        )
        or (isinstance(value, str) and bool(value.strip()))
        for value in cause.values()
    )
    if not cause_is_material:
        problems.append(
            ValidationProblem(
                path,
                "$.cause",
                "invalidation requires at least one non-empty recorded cause",
            )
        )
    affected_entities = document.get("affected_entities")
    affected_types: set[str] = set()
    if isinstance(affected_entities, list):
        for change in affected_entities:
            entity = change.get("entity") if isinstance(change, dict) else None
            entity_type = entity.get("entity_type") if isinstance(entity, dict) else None
            if isinstance(entity_type, str):
                affected_types.add(entity_type)
    primary_types = PRIMARY_ENTITY_TYPES_BY_EVENT.get(document.get("event_type"), set())
    if primary_types and not affected_types.intersection(primary_types):
        problems.append(
            ValidationProblem(
                path,
                "$.affected_entities",
                "event type and affected entities do not name a matching direct change",
            )
        )
    rebuilds = document.get("rebuilds")
    if isinstance(rebuilds, list):
        present = {
            rebuild.get("component")
            for rebuild in rebuilds
            if isinstance(rebuild, dict) and isinstance(rebuild.get("component"), str)
        }
        missing = sorted(REBUILD_COMPONENTS - present)
        if missing:
            problems.append(
                ValidationProblem(
                    path,
                    "$.rebuilds",
                    "rebuild ledger must explicitly mark every component; missing: "
                    + ", ".join(missing),
                )
            )
        if document.get("propagation_status") == "succeeded":
            required: set[str] = set()
            for entity_type in affected_types:
                required.update(
                    REBUILDS_BY_AFFECTED_ENTITY.get(entity_type, REBUILD_COMPONENTS)
                )
            statuses = {
                rebuild.get("component"): rebuild.get("status")
                for rebuild in rebuilds
                if isinstance(rebuild, dict)
                and isinstance(rebuild.get("component"), str)
            }
            incomplete = sorted(
                component for component in required if statuses.get(component) != "succeeded"
            )
            if incomplete:
                problems.append(
                    ValidationProblem(
                        path,
                        "$.rebuilds",
                        "successful propagation requires affected downstream components to succeed: "
                        + ", ".join(incomplete),
                    )
                )
    return problems


def snapshot_problems(path: Path, document: dict[str, Any]) -> list[ValidationProblem]:
    """Validate deterministic ordering and the snapshot's RFC 8785 subset hash."""

    if not str(document.get("schema_id", "")).endswith("/snapshot.schema.json"):
        return []
    problems: list[ValidationProblem] = []
    for field, identity_field in (
        ("components", "component_id"),
        ("schema_catalog", "schema_id"),
    ):
        items = document.get(field)
        if not isinstance(items, list):
            continue
        identities = [
            item.get(identity_field)
            for item in items
            if isinstance(item, dict) and isinstance(item.get(identity_field), str)
        ]
        if len(identities) == len(items) and identities != sorted(identities):
            problems.append(
                ValidationProblem(
                    path,
                    f"$.{field}",
                    f"{field} must be sorted by {identity_field} before hashing",
                )
            )
        if len(identities) != len(set(identities)):
            problems.append(
                ValidationProblem(
                    path,
                    f"$.{field}",
                    f"{field} contains duplicate {identity_field} values",
                )
            )

    components = document.get("components")
    if isinstance(components, list):
        for index, component in enumerate(components):
            if not isinstance(component, dict):
                continue
            revision = component.get("revision")
            if not isinstance(revision, dict):
                continue
            revision_type = revision.get("revision_type")
            value = revision.get("value")
            expected_length = {
                "git_commit_sha1": 40,
                "git_commit_sha256": 64,
                "content_digest": 64,
            }.get(revision_type)
            if expected_length is not None and (
                not isinstance(value, str)
                or len(value) != expected_length
                or re.fullmatch(r"[a-f0-9]+", value) is None
            ):
                problems.append(
                    ValidationProblem(
                        path,
                        f"$.components[{index}].revision.value",
                        f"{revision_type} revision must be {expected_length} "
                        "lowercase hex characters",
                    )
                )

    snapshot_id = document.get("snapshot_id")
    if isinstance(snapshot_id, str):
        projection = dict(document)
        projection.pop("snapshot_id", None)
        try:
            # Snapshot schema property names are ASCII and the contract admits
            # no floating-point numbers. Under that closed subset, Python's
            # compact, UTF-8, sorted-key encoding is RFC 8785 canonical JSON.
            canonical = _canonical_json_bytes(projection)
        except (TypeError, UnicodeEncodeError, ValueError) as error:
            problems.append(
                ValidationProblem(path, "$", f"snapshot cannot be canonicalized: {error}")
            )
        else:
            digest = hashlib.sha256(canonical).hexdigest()
            if snapshot_id.rsplit(":", 1)[-1] != digest:
                problems.append(
                    ValidationProblem(
                        path,
                        "$.snapshot_id",
                        "snapshot ID digest does not match the canonical root projection",
                    )
                )
    return problems


def schema_catalog_problems(
    path: Path,
    document: dict[str, Any],
    schema_digests: dict[str, str],
) -> list[ValidationProblem]:
    if not str(document.get("schema_id", "")).endswith("/snapshot.schema.json"):
        return []
    catalog = document.get("schema_catalog")
    if not isinstance(catalog, list):
        return []
    problems: list[ValidationProblem] = []
    for index, contract in enumerate(catalog):
        if not isinstance(contract, dict):
            continue
        schema_id = contract.get("schema_id")
        digest = contract.get("content_digest")
        declared = digest.get("value") if isinstance(digest, dict) else None
        actual = schema_digests.get(schema_id) if isinstance(schema_id, str) else None
        if actual is None:
            problems.append(
                ValidationProblem(
                    path,
                    f"$.schema_catalog[{index}].schema_id",
                    "schema catalog entry is not present in the selected local registry",
                )
            )
        elif declared != actual:
            problems.append(
                ValidationProblem(
                    path,
                    f"$.schema_catalog[{index}].content_digest.value",
                    "schema catalog digest does not match the selected schema bytes",
                )
            )
    return problems


def _local_schema_reference_closure(
    root_schema_ids: Iterable[str],
    schemas: dict[str, dict[str, Any]],
) -> set[str]:
    """Return loaded root schemas and every loaded schema reached by ``$ref``."""

    pending = list(root_schema_ids)
    closure: set[str] = set()
    while pending:
        schema_id = pending.pop()
        if schema_id in closure or schema_id not in schemas:
            continue
        closure.add(schema_id)
        for location, value in _walk(schemas[schema_id]):
            if not location or location[-1] != "$ref" or not isinstance(value, str):
                continue
            target_id, _ = urldefrag(urljoin(schema_id, value))
            if target_id in schemas and target_id not in closure:
                pending.append(target_id)
    return closure


def snapshot_schema_catalog_completeness_problems(
    documents: list[tuple[Path, dict[str, Any]]],
    schemas: dict[str, dict[str, Any]],
) -> list[ValidationProblem]:
    """Require every selected snapshot to pin the selected schema closure exactly."""

    expected_schema_ids = _local_schema_reference_closure(
        (
            schema_id
            for _, document in documents
            if isinstance((schema_id := document.get("schema_id")), str)
        ),
        schemas,
    )
    problems: list[ValidationProblem] = []
    for path, document in documents:
        catalog = document.get("schema_catalog")
        if not isinstance(document.get("snapshot_id"), str) or not isinstance(
            catalog, list
        ):
            continue
        counts: dict[str, int] = {}
        for contract in catalog:
            if not isinstance(contract, dict):
                continue
            schema_id = contract.get("schema_id")
            if isinstance(schema_id, str):
                counts[schema_id] = counts.get(schema_id, 0) + 1

        missing = sorted(expected_schema_ids - counts.keys())
        if missing:
            problems.append(
                ValidationProblem(
                    path,
                    "$.schema_catalog",
                    "schema catalog is missing contracts used by the selected "
                    "document schema closure: " + ", ".join(missing),
                )
            )
        extraneous = sorted(counts.keys() - expected_schema_ids)
        if extraneous:
            problems.append(
                ValidationProblem(
                    path,
                    "$.schema_catalog",
                    "schema catalog contains contracts outside the selected "
                    "document schema closure: " + ", ".join(extraneous),
                )
            )
        duplicates = sorted(
            schema_id for schema_id, count in counts.items() if count > 1
        )
        if duplicates:
            problems.append(
                ValidationProblem(
                    path,
                    "$.schema_catalog",
                    "schema catalog must contain each contract exactly once; "
                    "duplicates: " + ", ".join(duplicates),
                )
            )
    return problems


def rights_assessment_problems(
    path: Path, document: dict[str, Any]
) -> list[ValidationProblem]:
    """Reject internally contradictory or unsupported rights declarations."""

    problems: list[ValidationProblem] = []
    for location, value in _walk(document):
        if not isinstance(value, dict):
            continue
        required_shape = {"publisher", "status", "basis_evidence", "permitted_uses", "review_state"}
        if not required_shape.issubset(value):
            continue
        status = value.get("status")
        permitted_uses = value.get("permitted_uses")
        review_state = value.get("review_state")
        if review_state in {"human_reviewed", "counsel_reviewed", "disputed"}:
            reviewer = value.get("reviewer")
            if (
                not isinstance(reviewer, dict)
                or reviewer.get("producer_type") != "human"
                or not isinstance(reviewer.get("producer_id"), str)
                or not isinstance(value.get("reviewed_at"), str)
            ):
                problems.append(
                    ValidationProblem(
                        path,
                        _json_location(location),
                        "reviewed rights require an identified human reviewer and review time",
                    )
                )
            projection = dict(value)
            projection.pop("reviewed_assessment_digest", None)
            try:
                actual_digest = hashlib.sha256(
                    _canonical_json_bytes(projection)
                ).hexdigest()
            except (TypeError, UnicodeEncodeError, ValueError) as error:
                problems.append(
                    ValidationProblem(
                        path,
                        _json_location((*location, "reviewed_assessment_digest")),
                        f"reviewed rights assessment cannot be canonicalized: {error}",
                    )
                )
            else:
                reviewed_digest = value.get("reviewed_assessment_digest")
                declared_digest = (
                    reviewed_digest.get("value")
                    if isinstance(reviewed_digest, dict)
                    else None
                )
                if declared_digest != actual_digest:
                    problems.append(
                        ValidationProblem(
                            path,
                            _json_location(
                                (*location, "reviewed_assessment_digest", "value")
                            ),
                            "rights review digest does not match the exact assessment",
                        )
                    )
            reviewed_at = (
                _parse_datetime(value.get("reviewed_at"))
                if isinstance(value.get("reviewed_at"), str)
                else None
            )
            evidence_times: list[datetime] = []
            evidence_retrieved_at = value.get("evidence_retrieved_at")
            if isinstance(evidence_retrieved_at, str):
                parsed = _parse_datetime(evidence_retrieved_at)
                if parsed is not None:
                    evidence_times.append(parsed)
            basis_evidence = value.get("basis_evidence")
            if isinstance(basis_evidence, list):
                for evidence in basis_evidence:
                    retrieved_at = (
                        evidence.get("retrieved_at")
                        if isinstance(evidence, dict)
                        else None
                    )
                    if isinstance(retrieved_at, str):
                        parsed = _parse_datetime(retrieved_at)
                        if parsed is not None:
                            evidence_times.append(parsed)
            if reviewed_at is not None and any(
                reviewed_at < evidence_time for evidence_time in evidence_times
            ):
                problems.append(
                    ValidationProblem(
                        path,
                        _json_location((*location, "reviewed_at")),
                        "rights review cannot predate its evidence retrieval",
                    )
                )
            next_review_at = (
                _parse_datetime(value.get("next_review_at"))
                if isinstance(value.get("next_review_at"), str)
                else None
            )
            if (
                reviewed_at is not None
                and next_review_at is not None
                and next_review_at <= reviewed_at
            ):
                problems.append(
                    ValidationProblem(
                        path,
                        _json_location((*location, "next_review_at")),
                        "rights validity deadline must follow the rights review",
                    )
                )
        if status == "open-license":
            required_text = ("license_name", "license_version", "license_jurisdiction", "attribution")
            for field in required_text:
                if not isinstance(value.get(field), str) or not value[field].strip():
                    problems.append(
                        ValidationProblem(
                            path,
                            _json_location(location),
                            f"open-license rights require non-empty {field}",
                        )
                    )
            if not isinstance(value.get("license_url") or value.get("terms_url"), str):
                problems.append(
                    ValidationProblem(
                        path,
                        _json_location(location),
                        "open-license rights require a public license_url or terms_url",
                    )
                )
        if isinstance(status, str) and status in {
            "public-domain",
            "statutory-exception",
        }:
            if not isinstance(value.get("legal_basis"), str) or not value[
                "legal_basis"
            ].strip():
                problems.append(
                    ValidationProblem(
                        path,
                        _json_location(location),
                        f"rights status {status!r} requires a jurisdiction-specific legal_basis",
                    )
                )
            if not isinstance(value.get("terms_url"), str):
                problems.append(
                    ValidationProblem(
                        path,
                        _json_location(location),
                        f"rights status {status!r} requires a public terms_url for the reviewed basis",
                    )
                )
        if status == "permission" and not isinstance(value.get("rights_holder"), str):
            problems.append(
                ValidationProblem(
                    path,
                    _json_location(location),
                    "permission-based rights require the named rights_holder",
                )
            )
        if status == "permission":
            if not isinstance(value.get("permission_reference"), str) or not value[
                "permission_reference"
            ].strip():
                problems.append(
                    ValidationProblem(
                        path,
                        _json_location(location),
                        "permission-based rights require a non-empty permission_reference",
                    )
                )
            if not isinstance(value.get("terms_url"), str):
                problems.append(
                    ValidationProblem(
                        path,
                        _json_location(location),
                        "permission-based rights require a public terms_url or permission evidence URL",
                    )
                )
        if (
            isinstance(status, str)
            and status in {"restricted", "unknown"}
            and isinstance(permitted_uses, dict)
        ):
            incorrectly_permitted = sorted(
                use for use, state in permitted_uses.items() if state == "permitted"
            )
            if incorrectly_permitted:
                problems.append(
                    ValidationProblem(
                        path,
                        _json_location((*location, "permitted_uses")),
                        f"rights status {status!r} cannot self-declare permitted uses: "
                        + ", ".join(incorrectly_permitted),
                    )
                )
    return problems


def publication_clearance_problems(
    path: Path, document: dict[str, Any]
) -> list[ValidationProblem]:
    """Bind each reviewed publication decision to its exact checks and status."""

    problems: list[ValidationProblem] = []
    for location, value in _walk(document):
        if not isinstance(value, dict) or not {
            "status",
            "checks",
            "review_state",
        }.issubset(value):
            continue
        if value.get("status") not in {"cleared", "restricted", "quarantined"}:
            continue
        projection = dict(value)
        projection.pop("reviewed_clearance_digest", None)
        try:
            actual_digest = hashlib.sha256(
                _canonical_json_bytes(projection)
            ).hexdigest()
        except (TypeError, UnicodeEncodeError, ValueError) as error:
            problems.append(
                ValidationProblem(
                    path,
                    _json_location((*location, "reviewed_clearance_digest")),
                    f"publication-clearance decision cannot be canonicalized: {error}",
                )
            )
            continue
        reviewed_digest = value.get("reviewed_clearance_digest")
        declared_digest = (
            reviewed_digest.get("value")
            if isinstance(reviewed_digest, dict)
            else None
        )
        if declared_digest != actual_digest:
            problems.append(
                ValidationProblem(
                    path,
                    _json_location((*location, "reviewed_clearance_digest", "value")),
                    "publication-clearance review digest does not match the exact decision",
                )
            )
    return problems


def _artifact_id_content_digest(artifact_id: Any) -> dict[str, str] | None:
    if not isinstance(artifact_id, str) or not artifact_id.startswith(
        "urn:trace-the-law:artifact:sha256:"
    ):
        return None
    value = artifact_id.rsplit(":", 1)[-1]
    if re.fullmatch(r"[a-f0-9]{64}", value) is None:
        return None
    return {"algorithm": "sha256", "value": value}


def review_target_problems(
    path: Path, document: dict[str, Any]
) -> list[ValidationProblem]:
    """Prevent a reviewed rights or clearance object moving to unrelated bytes."""

    schema_name = str(document.get("schema_id", "")).rsplit("/", 1)[-1]
    candidates: list[
        tuple[str, Any, dict[str, Any], dict[str, str] | None, str | None]
    ] = []

    def add_candidate(
        location: str,
        value: Any,
        entity: dict[str, Any],
        content_digest: dict[str, str] | None = None,
        source_url: str | None = None,
    ) -> None:
        if isinstance(value, dict) and value.get("review_state") in {
            "human_reviewed",
            "counsel_reviewed",
            "specialist_reviewed",
            "disputed",
        }:
            candidates.append(
                (location, value, entity, content_digest, source_url)
            )

    if schema_name == "source-manifest.schema.json":
        add_candidate(
            "$.rights",
            document.get("rights"),
            {"entity_type": "source", "entity_id": document.get("source_id")},
            source_url=document.get("official_homepage")
            if isinstance(document.get("official_homepage"), str)
            else None,
        )
    elif schema_name == "capture.schema.json":
        retrieval = document.get("retrieval")
        source_url = (
            retrieval.get("source_url") if isinstance(retrieval, dict) else None
        )
        entity = {
            "entity_type": "capture",
            "entity_id": document.get("capture_id"),
        }
        content_digest = _artifact_id_content_digest(document.get("artifact_id"))
        add_candidate(
            "$.rights", document.get("rights"), entity, content_digest, source_url
        )
        add_candidate(
            "$.publication_clearance",
            document.get("publication_clearance"),
            entity,
            content_digest,
            source_url,
        )
    elif schema_name == "derivation.schema.json":
        output_artifact_id = document.get("output_artifact_id")
        add_candidate(
            "$.publication_clearance",
            document.get("publication_clearance"),
            {"entity_type": "artifact", "entity_id": output_artifact_id},
            _artifact_id_content_digest(output_artifact_id),
        )
    elif schema_name == "evidence-bundle.schema.json":
        handling = document.get("handling")
        public_release = (
            handling.get("public_release") if isinstance(handling, dict) else None
        )
        add_candidate(
            "$.handling.public_release.publication_clearance",
            public_release.get("publication_clearance")
            if isinstance(public_release, dict)
            else None,
            {"entity_type": "bundle", "entity_id": document.get("bundle_id")},
        )
    elif schema_name == "correction-report.schema.json":
        for index, evidence in enumerate(
            _list_or_empty(document.get("public_evidence"))
        ):
            if not isinstance(evidence, dict):
                continue
            content_digest = (
                evidence.get("excerpt_digest")
                if isinstance(evidence.get("public_excerpt"), str)
                else evidence.get("content_digest")
            )
            add_candidate(
                f"$.public_evidence[{index}].publication_clearance",
                evidence.get("publication_clearance"),
                {"entity_type": "report", "entity_id": document.get("report_id")},
                content_digest if isinstance(content_digest, dict) else None,
                evidence.get("official_url")
                if isinstance(evidence.get("official_url"), str)
                else None,
            )

    problems: list[ValidationProblem] = []
    for location, value, entity, content_digest, source_url in candidates:
        target = value.get("reviewed_target")
        if not isinstance(target, dict):
            continue
        if target.get("entity") != entity:
            problems.append(
                ValidationProblem(
                    path,
                    f"{location}.reviewed_target.entity",
                    "reviewed decision target does not match its enclosing entity",
                )
            )
        if content_digest is not None and target.get("content_digest") != content_digest:
            problems.append(
                ValidationProblem(
                    path,
                    f"{location}.reviewed_target.content_digest",
                    "reviewed decision target does not match the enclosing bytes",
                )
            )
        if source_url is not None and target.get("source_url") != source_url:
            problems.append(
                ValidationProblem(
                    path,
                    f"{location}.reviewed_target.source_url",
                    "reviewed decision target does not match the enclosing source URL",
                )
            )
    return problems


def _publication_capture_problems(
    artifact_path: Path,
    artifact_id: str,
    capture_id: str,
    captures: dict[str, tuple[Path, dict[str, Any]]],
    required_uses: set[str],
    location: str,
    *,
    direct_capture: bool = False,
    evaluation_at: datetime | None = None,
) -> list[ValidationProblem]:
    capture_entry = captures.get(capture_id)
    if capture_entry is None:
        return [
            ValidationProblem(
                artifact_path,
                location,
                f"publication basis capture {capture_id!r} does not resolve",
            )
        ]
    _, capture = capture_entry
    problems: list[ValidationProblem] = []
    if not _capture_http_succeeded(capture):
        problems.append(
            ValidationProblem(
                artifact_path,
                location,
                f"publication basis capture {capture_id!r} is not a complete HTTP 200 retrieval",
            )
        )
    rights = capture.get("rights")
    if not isinstance(rights, dict):
        return [
            ValidationProblem(
                artifact_path,
                location,
                f"publication basis capture {capture_id!r} has no rights assessment",
            )
        ]
    problems.extend(rights_assessment_problems(artifact_path, {"rights": rights}))
    retrieval = capture.get("retrieval")
    expected_target = {
        "entity": {"entity_type": "capture", "entity_id": capture_id},
        "content_digest": _artifact_id_content_digest(capture.get("artifact_id")),
        "source_url": retrieval.get("source_url")
        if isinstance(retrieval, dict)
        else None,
    }
    if rights.get("reviewed_target") != expected_target:
        problems.append(
            ValidationProblem(
                artifact_path,
                location,
                f"publication basis capture {capture_id!r} rights review is not bound to these exact bytes and URL",
            )
        )
    allowed_statuses = {"open-license", "public-domain", "statutory-exception", "permission"}
    if rights.get("status") not in allowed_statuses:
        problems.append(
            ValidationProblem(
                artifact_path,
                location,
                f"publication basis capture {capture_id!r} does not establish publishable rights",
            )
        )
    if rights.get("review_state") not in {"human_reviewed", "counsel_reviewed"}:
        problems.append(
            ValidationProblem(
                artifact_path,
                location,
                f"publication basis capture {capture_id!r} requires human or counsel rights review",
            )
        )
    next_review_at = (
        _parse_datetime(rights.get("next_review_at"))
        if isinstance(rights.get("next_review_at"), str)
        else None
    )
    if (
        evaluation_at is not None
        and next_review_at is not None
        and next_review_at <= evaluation_at
    ):
        problems.append(
            ValidationProblem(
                artifact_path,
                location,
                f"publication basis capture {capture_id!r} has an expired rights review",
            )
        )
    rights_reviewer = rights.get("reviewer")
    if (
        not isinstance(rights_reviewer, dict)
        or rights_reviewer.get("producer_type") != "human"
        or not isinstance(rights_reviewer.get("producer_id"), str)
        or not isinstance(rights.get("reviewed_at"), str)
    ):
        problems.append(
            ValidationProblem(
                artifact_path,
                location,
                f"publication basis capture {capture_id!r} lacks an identified human rights reviewer",
            )
        )
    uses = rights.get("permitted_uses")
    missing_uses = sorted(
        use
        for use in required_uses
        if not isinstance(uses, dict) or uses.get(use) != "permitted"
    )
    if missing_uses:
        problems.append(
            ValidationProblem(
                artifact_path,
                location,
                f"publication basis capture {capture_id!r} does not permit: "
                + ", ".join(missing_uses),
            )
        )
    clearance = capture.get("publication_clearance")
    if not _publication_clearance_is_valid(clearance):
        problems.append(
            ValidationProblem(
                artifact_path,
                location,
                f"publication basis capture {capture_id!r} lacks independent privacy and publication clearance",
            )
        )
    else:
        if clearance.get("reviewed_target") != expected_target:
            problems.append(
                ValidationProblem(
                    artifact_path,
                    location,
                    f"publication basis capture {capture_id!r} clearance is not bound to these exact bytes and URL",
                )
            )
        clearance_time = _parse_datetime(clearance["reviewed_at"])
        retrieved_at = (
            _parse_datetime(retrieval.get("retrieved_at"))
            if isinstance(retrieval, dict)
            and isinstance(retrieval.get("retrieved_at"), str)
            else None
        )
        if (
            clearance_time is not None
            and retrieved_at is not None
            and clearance_time < retrieved_at
        ):
            problems.append(
                ValidationProblem(
                    artifact_path,
                    location,
                    f"publication basis capture {capture_id!r} uses a clearance older than the captured bytes",
                )
            )
    if direct_capture and capture.get("artifact_id") != artifact_id:
        problems.append(
            ValidationProblem(
                artifact_path,
                location,
                "direct capture publication basis must point to the published artifact bytes",
            )
        )
    return problems


def _publication_clearance_is_valid(value: Any) -> bool:
    if not isinstance(value, dict) or value.get("status") != "cleared":
        return False
    if value.get("review_state") not in {"human_reviewed", "specialist_reviewed"}:
        return False
    reviewer = value.get("reviewer")
    if (
        not isinstance(reviewer, dict)
        or reviewer.get("producer_type") != "human"
        or not isinstance(reviewer.get("producer_id"), str)
        or not isinstance(value.get("reviewed_at"), str)
        or _parse_datetime(value["reviewed_at"]) is None
    ):
        return False
    checks = value.get("checks")
    if not isinstance(checks, dict):
        return False
    projection = dict(value)
    projection.pop("reviewed_clearance_digest", None)
    reviewed_digest = value.get("reviewed_clearance_digest")
    if not isinstance(reviewed_digest, dict) or reviewed_digest.get("value") != (
        hashlib.sha256(_canonical_json_bytes(projection)).hexdigest()
    ):
        return False
    allowed_by_check = {
        "personal_data": {"not_present", "cleared", "not_applicable"},
        "sealing_or_reporting_restrictions": {
            "not_present",
            "cleared",
            "not_applicable",
        },
        "official_redactions_preserved": {"preserved", "not_applicable"},
        "sensitive_material": {"not_present", "cleared", "not_applicable"},
    }
    return set(checks) == set(allowed_by_check) and all(
        checks[field] in allowed for field, allowed in allowed_by_check.items()
    )


TRANSFORM_RIGHTS_USE = {
    "markdown_transcription": "transcription",
    "extracted_text": "transcription",
    "ocr_text": "transcription",
    "structured_extraction": "transcription",
    "translation": "translation",
    "summary": "summarisation",
    "thumbnail": "public_mirroring",
}
UNCLASSIFIED_TRANSFORM_USE = "__unclassified_transform__"


@dataclass(frozen=True)
class ArtifactRightsRoute:
    """One exact, source-covered route to an immutable artifact."""

    required_uses: frozenset[str]
    derivation_ids: frozenset[str]
    capture_ids: frozenset[str]


RightsRouteCache = dict[
    tuple[frozenset[str], frozenset[str] | None],
    dict[str, tuple[ArtifactRightsRoute, ...]],
]


def _nondominated_rights_routes(
    candidates: Iterable[ArtifactRightsRoute],
) -> tuple[ArtifactRightsRoute, ...]:
    kept: list[ArtifactRightsRoute] = []
    for candidate in candidates:
        if any(
            known.required_uses <= candidate.required_uses
            and known.derivation_ids <= candidate.derivation_ids
            and known.capture_ids <= candidate.capture_ids
            for known in kept
        ):
            continue
        kept = [
            known
            for known in kept
            if not (
                candidate.required_uses <= known.required_uses
                and candidate.derivation_ids <= known.derivation_ids
                and candidate.capture_ids <= known.capture_ids
            )
        ]
        kept.append(candidate)
    return tuple(
        sorted(
            kept,
            key=lambda item: (
                len(item.derivation_ids),
                len(item.required_uses),
                len(item.capture_ids),
                sorted(item.derivation_ids),
                sorted(item.required_uses),
                sorted(item.capture_ids),
            ),
        )
    )


def _artifact_rights_route_options(
    artifact_id: str,
    basis_capture_ids: set[str],
    captures: dict[str, tuple[Path, dict[str, Any]]],
    derivations: dict[str, tuple[Path, dict[str, Any]]],
    route_cache: RightsRouteCache | None = None,
    *,
    allowed_derivation_ids: set[str] | None = None,
) -> tuple[ArtifactRightsRoute, ...]:
    """Return exact transform routes, optionally limited to declared dependencies."""

    basis_key = frozenset(basis_capture_ids)
    allowed_key = (
        frozenset(allowed_derivation_ids)
        if allowed_derivation_ids is not None
        else None
    )
    cache_key = (basis_key, allowed_key)
    if route_cache is None:
        route_cache = {}
    routes_by_artifact = route_cache.get(cache_key)
    if routes_by_artifact is None:
        options: dict[str, set[ArtifactRightsRoute]] = {}
        pending: list[str] = []

        def add_option(candidate_id: str, option: ArtifactRightsRoute) -> bool:
            existing = options.setdefault(candidate_id, set())
            reduced = _nondominated_rights_routes((*existing, option))
            reduced_set = set(reduced)
            if reduced_set == existing:
                return False
            options[candidate_id] = reduced_set
            pending.append(candidate_id)
            return True

        for capture_id in basis_key:
            capture_entry = captures.get(capture_id)
            if capture_entry is not None and not _capture_http_succeeded(
                capture_entry[1]
            ):
                continue
            captured_artifact_id = (
                capture_entry[1].get("artifact_id")
                if capture_entry is not None
                else None
            )
            if isinstance(captured_artifact_id, str):
                add_option(
                    captured_artifact_id,
                    ArtifactRightsRoute(
                        frozenset(), frozenset(), frozenset({capture_id})
                    ),
                )

        routes: list[
            tuple[str, str, tuple[str, ...], str, frozenset[str]]
        ] = []
        dependent_routes: dict[str, set[int]] = {}
        for derivation_id, (_, route) in derivations.items():
            if allowed_key is not None and derivation_id not in allowed_key:
                continue
            output_id = route.get("output_artifact_id")
            inputs = route.get("input_artifacts")
            declared_capture_ids = frozenset(
                capture_id
                for capture_id in _list_or_empty(
                    route.get("rights_basis_capture_ids")
                )
                if isinstance(capture_id, str)
            )
            if (
                not isinstance(output_id, str)
                or not isinstance(inputs, list)
                or not inputs
                or not declared_capture_ids
                or not declared_capture_ids <= basis_key
            ):
                continue
            input_ids = tuple(
                item.get("artifact_id") if isinstance(item, dict) else None
                for item in inputs
            )
            if not all(isinstance(input_id, str) for input_id in input_ids):
                continue
            transform_use = TRANSFORM_RIGHTS_USE.get(
                route.get("representation"), UNCLASSIFIED_TRANSFORM_USE
            )
            route_index = len(routes)
            typed_input_ids = tuple(input_ids)
            routes.append(
                (
                    derivation_id,
                    output_id,
                    typed_input_ids,
                    transform_use,
                    declared_capture_ids,
                )
            )
            for input_id in typed_input_ids:
                dependent_routes.setdefault(input_id, set()).add(route_index)

        queued_routes: set[int] = set()
        while pending:
            changed_artifact_id = pending.pop()
            queued_routes.update(dependent_routes.get(changed_artifact_id, set()))
            while queued_routes:
                route_index = queued_routes.pop()
                (
                    derivation_id,
                    output_id,
                    input_ids,
                    transform_use,
                    declared_capture_ids,
                ) = routes[route_index]
                if any(not options.get(input_id) for input_id in input_ids):
                    continue
                combined: tuple[ArtifactRightsRoute, ...] = (
                    ArtifactRightsRoute(frozenset(), frozenset(), frozenset()),
                )
                for input_id in input_ids:
                    combined = _nondominated_rights_routes(
                        ArtifactRightsRoute(
                            left.required_uses | right.required_uses,
                            left.derivation_ids | right.derivation_ids,
                            left.capture_ids | right.capture_ids,
                        )
                        for left in combined
                        for right in options[input_id]
                    )
                for combined_route in combined:
                    if not combined_route.capture_ids <= declared_capture_ids:
                        continue
                    add_option(
                        output_id,
                        ArtifactRightsRoute(
                            combined_route.required_uses | {transform_use},
                            combined_route.derivation_ids | {derivation_id},
                            declared_capture_ids,
                        ),
                    )

        routes_by_artifact = {
            candidate_id: _nondominated_rights_routes(candidates)
            for candidate_id, candidates in options.items()
            if candidates
        }
        route_cache[cache_key] = routes_by_artifact
    return routes_by_artifact.get(artifact_id, ())


def _derivation_clearance_problems(
    path: Path,
    location: str,
    derivation_ids: set[str] | frozenset[str],
    derivations: dict[str, tuple[Path, dict[str, Any]]],
    *,
    deadline: datetime | None = None,
) -> list[ValidationProblem]:
    problems: list[ValidationProblem] = []
    for derivation_id in sorted(derivation_ids):
        derivation_entry = derivations.get(derivation_id)
        if derivation_entry is None:
            problems.append(
                ValidationProblem(
                    path,
                    location,
                    f"selected derivation {derivation_id!r} does not resolve",
                )
            )
            continue
        derivation = derivation_entry[1]
        clearance = derivation.get("publication_clearance")
        if not _publication_clearance_is_valid(clearance):
            problems.append(
                ValidationProblem(
                    path,
                    location,
                    f"selected derivation {derivation_id!r} lacks independent output privacy and publication clearance",
                )
            )
            continue
        expected_target = {
            "entity": {
                "entity_type": "artifact",
                "entity_id": derivation.get("output_artifact_id"),
            },
            "content_digest": _artifact_id_content_digest(
                derivation.get("output_artifact_id")
            ),
        }
        if clearance.get("reviewed_target") != expected_target:
            problems.append(
                ValidationProblem(
                    path,
                    location,
                    f"selected derivation {derivation_id!r} clearance is not bound to its exact output bytes",
                )
            )
        created_at = (
            _parse_datetime(derivation.get("created_at"))
            if isinstance(derivation.get("created_at"), str)
            else None
        )
        reviewed_at = _parse_datetime(clearance["reviewed_at"])
        if (
            created_at is not None
            and reviewed_at is not None
            and reviewed_at < created_at
        ):
            problems.append(
                ValidationProblem(
                    path,
                    location,
                    f"selected derivation {derivation_id!r} uses a clearance older than its output",
                )
            )
        if deadline is not None and (
            (created_at is not None and created_at > deadline)
            or (reviewed_at is not None and reviewed_at > deadline)
        ):
            problems.append(
                ValidationProblem(
                    path,
                    location,
                    f"selected derivation {derivation_id!r} was created or cleared after bundle generation",
                )
            )
    return problems


def _bundle_capture_deadline_problems(
    path: Path,
    location: str,
    capture_ids: Iterable[str],
    captures: dict[str, tuple[Path, dict[str, Any]]],
    generated_at: datetime | None,
) -> list[ValidationProblem]:
    if generated_at is None:
        return []
    problems: list[ValidationProblem] = []
    for capture_id in sorted(set(capture_ids)):
        capture_entry = captures.get(capture_id)
        if capture_entry is None:
            continue
        capture = capture_entry[1]
        retrieval = capture.get("retrieval")
        clearance = capture.get("publication_clearance")
        rights = capture.get("rights")
        times = [
            _parse_datetime(capture["created_at"])
            if isinstance(capture.get("created_at"), str)
            else None,
            _parse_datetime(retrieval["retrieved_at"])
            if isinstance(retrieval, dict)
            and isinstance(retrieval.get("retrieved_at"), str)
            else None,
            _parse_datetime(clearance["reviewed_at"])
            if isinstance(clearance, dict)
            and isinstance(clearance.get("reviewed_at"), str)
            else None,
            _parse_datetime(rights["reviewed_at"])
            if isinstance(rights, dict)
            and isinstance(rights.get("reviewed_at"), str)
            else None,
        ]
        if any(value is not None and value > generated_at for value in times):
            problems.append(
                ValidationProblem(
                    path,
                    location,
                    f"capture {capture_id!r} was retrieved, recorded, or cleared after bundle generation",
                )
            )
    return problems


def _bundle_delivery_basis_problems(
    path: Path,
    bundle: dict[str, Any],
    required_clearance_refs: set[tuple[str, str]],
    required_rights_refs: set[tuple[str, str]],
    captures: dict[str, tuple[Path, dict[str, Any]]],
    derivations: dict[str, tuple[Path, dict[str, Any]]],
    generated_at: datetime | None,
) -> list[ValidationProblem]:
    """Pin post-snapshot delivery decisions into a public bundle payload."""

    handling = bundle.get("handling")
    if not isinstance(handling, dict) or handling.get("persistence") != "public":
        return []
    public_release = handling.get("public_release")
    delivery_bases = (
        public_release.get("delivery_bases")
        if isinstance(public_release, dict)
        else None
    )
    basis_items = delivery_bases if isinstance(delivery_bases, list) else []
    problems: list[ValidationProblem] = []
    indexed_bases: dict[tuple[str, str], tuple[int, dict[str, Any]]] = {}
    for index, basis in enumerate(basis_items):
        if not isinstance(basis, dict):
            continue
        entity_type = basis.get("entity_type")
        entity_id = basis.get("entity_id")
        if not isinstance(entity_type, str) or not isinstance(entity_id, str):
            continue
        reference = (entity_type, entity_id)
        location = f"$.handling.public_release.delivery_bases[{index}]"
        if reference in indexed_bases:
            problems.append(
                ValidationProblem(
                    path,
                    location,
                    "delivery decisions must be pinned exactly once per capture or derivation",
                )
            )
            continue
        indexed_bases[reference] = (index, basis)
        entry = (
            captures.get(entity_id)
            if entity_type == "capture"
            else derivations.get(entity_id)
            if entity_type == "derivation"
            else None
        )
        if entry is None:
            problems.append(
                ValidationProblem(
                    path,
                    f"{location}.entity_id",
                    "delivery basis does not resolve to the selected capture or derivation",
                )
            )
            continue
        state = entry[1]
        clearance = state.get("publication_clearance")
        expected_clearance_digest = (
            clearance.get("reviewed_clearance_digest")
            if isinstance(clearance, dict)
            else None
        )
        if basis.get("publication_clearance_digest") != expected_clearance_digest:
            problems.append(
                ValidationProblem(
                    path,
                    f"{location}.publication_clearance_digest",
                    "delivery basis does not match the exact resolved publication-clearance review",
                )
            )
        clearance_reviewed_at = (
            _parse_datetime(clearance.get("reviewed_at"))
            if isinstance(clearance, dict)
            and isinstance(clearance.get("reviewed_at"), str)
            else None
        )
        if (
            generated_at is not None
            and clearance_reviewed_at is not None
            and clearance_reviewed_at > generated_at
        ):
            problems.append(
                ValidationProblem(
                    path,
                    f"{location}.publication_clearance_digest",
                    "delivery basis uses a publication-clearance review made after bundle generation",
                )
            )
        rights_digest = basis.get("reviewed_assessment_digest")
        if entity_type == "capture" and rights_digest is not None:
            rights = state.get("rights")
            expected_rights_digest = (
                rights.get("reviewed_assessment_digest")
                if isinstance(rights, dict)
                else None
            )
            if rights_digest != expected_rights_digest:
                problems.append(
                    ValidationProblem(
                        path,
                        f"{location}.reviewed_assessment_digest",
                        "delivery basis does not match the exact resolved reuse-rights review",
                    )
                )
            rights_reviewed_at = (
                _parse_datetime(rights.get("reviewed_at"))
                if isinstance(rights, dict)
                and isinstance(rights.get("reviewed_at"), str)
                else None
            )
            if (
                generated_at is not None
                and rights_reviewed_at is not None
                and rights_reviewed_at > generated_at
            ):
                problems.append(
                    ValidationProblem(
                        path,
                        f"{location}.reviewed_assessment_digest",
                        "delivery basis uses a reuse-rights review made after bundle generation",
                    )
                )

    for entity_type, entity_id in sorted(required_clearance_refs):
        entry = (
            captures.get(entity_id)
            if entity_type == "capture"
            else derivations.get(entity_id)
            if entity_type == "derivation"
            else None
        )
        if entry is not None and not _publication_clearance_is_valid(
            entry[1].get("publication_clearance")
        ):
            problems.append(
                ValidationProblem(
                    path,
                    "$.handling.public_release.delivery_bases",
                    f"public delivery requires valid independent publication clearance for {entity_type} {entity_id!r}",
                )
            )
        if (entity_type, entity_id) not in indexed_bases:
            problems.append(
                ValidationProblem(
                    path,
                    "$.handling.public_release.delivery_bases",
                    f"public delivery must pin the publication-clearance review for {entity_type} {entity_id!r}",
                )
            )
    required_capture_ids = {
        entity_id
        for entity_type, entity_id in required_clearance_refs
        if entity_type == "capture"
    }
    required_derivation_ids = {
        entity_id
        for entity_type, entity_id in required_clearance_refs
        if entity_type == "derivation"
    }
    problems.extend(
        _bundle_capture_deadline_problems(
            path,
            "$.handling.public_release.delivery_bases",
            required_capture_ids,
            captures,
            generated_at,
        )
    )
    problems.extend(
        _derivation_clearance_problems(
            path,
            "$.handling.public_release.delivery_bases",
            required_derivation_ids,
            derivations,
            deadline=generated_at,
        )
    )
    for entity_type, entity_id in sorted(required_rights_refs):
        indexed = indexed_bases.get((entity_type, entity_id))
        if indexed is None:
            continue
        index, basis = indexed
        if not isinstance(basis.get("reviewed_assessment_digest"), dict):
            problems.append(
                ValidationProblem(
                    path,
                    f"$.handling.public_release.delivery_bases[{index}].reviewed_assessment_digest",
                    f"public delivery must pin the reuse-rights review for {entity_type} {entity_id!r}",
                )
            )
    return problems


def _route_artifact_availability_problems(
    path: Path,
    location: str,
    capture_ids: Iterable[str],
    derivation_ids: Iterable[str],
    artifacts: dict[str, tuple[Path, dict[str, Any]]],
    captures: dict[str, tuple[Path, dict[str, Any]]],
    derivations: dict[str, tuple[Path, dict[str, Any]]],
) -> list[ValidationProblem]:
    """Reject a publication route that traverses removed or quarantined bytes."""

    route_artifact_ids: set[str] = set()
    for capture_id in set(capture_ids):
        capture_entry = captures.get(capture_id)
        captured_artifact_id = (
            capture_entry[1].get("artifact_id")
            if capture_entry is not None
            else None
        )
        if isinstance(captured_artifact_id, str):
            route_artifact_ids.add(captured_artifact_id)
    for derivation_id in set(derivation_ids):
        derivation_entry = derivations.get(derivation_id)
        if derivation_entry is None:
            continue
        derivation = derivation_entry[1]
        output_artifact_id = derivation.get("output_artifact_id")
        if isinstance(output_artifact_id, str):
            route_artifact_ids.add(output_artifact_id)
        settings_artifact_id = derivation.get("settings_artifact_id")
        if isinstance(settings_artifact_id, str):
            route_artifact_ids.add(settings_artifact_id)
        for item in _list_or_empty(derivation.get("input_artifacts")):
            input_artifact_id = (
                item.get("artifact_id") if isinstance(item, dict) else None
            )
            if isinstance(input_artifact_id, str):
                route_artifact_ids.add(input_artifact_id)

    problems: list[ValidationProblem] = []
    for artifact_id in sorted(route_artifact_ids):
        artifact_entry = artifacts.get(artifact_id)
        if artifact_entry is None:
            continue
        availability = artifact_entry[1].get("availability")
        if availability in {"quarantined", "removed_with_tombstone"}:
            problems.append(
                ValidationProblem(
                    path,
                    location,
                    f"publication route traverses {availability} artifact {artifact_id!r}",
                )
            )
    return problems


def _derived_bundle_rights_problems(
    path: Path,
    location: str,
    artifact_id: str,
    outer_derivation_ids: set[str],
    selected_derivation_ids: set[str],
    required_uses: set[str],
    artifacts: dict[str, tuple[Path, dict[str, Any]]],
    captures: dict[str, tuple[Path, dict[str, Any]]],
    sources: dict[str, tuple[Path, dict[str, Any]]],
    derivations: dict[str, tuple[Path, dict[str, Any]]],
    route_cache: RightsRouteCache,
    generated_at: datetime | None,
    rights_evaluation_at: datetime | None,
    *,
    require_reuse_rights: bool,
) -> list[ValidationProblem]:
    """Accept one fully cleared derivation route for public bundle content."""

    candidates: list[list[ValidationProblem]] = []
    for derivation_id in sorted(outer_derivation_ids):
        derivation_entry = derivations.get(derivation_id)
        if derivation_entry is None:
            continue
        derivation = derivation_entry[1]
        route_problems: list[ValidationProblem] = []
        if derivation.get("output_artifact_id") != artifact_id:
            route_problems.append(
                ValidationProblem(
                    path,
                    location,
                    "selected public-bundle derivation does not produce the cited artifact",
                )
            )
        representation_use = TRANSFORM_RIGHTS_USE.get(
            derivation.get("representation")
        )
        if representation_use is None:
            route_problems.append(
                ValidationProblem(
                    path,
                    location,
                    "an unclassified derivation cannot establish public-bundle rights",
                )
            )
        capture_ids = {
            capture_id
            for capture_id in _list_or_empty(
                derivation.get("rights_basis_capture_ids")
            )
            if isinstance(capture_id, str)
        }
        if not capture_ids:
            route_problems.append(
                ValidationProblem(
                    path,
                    location,
                    "selected public-bundle derivation has no rights-basis captures",
                )
            )
        accumulated_uses = {"capture", "redistribution", *required_uses}
        if representation_use is not None:
            accumulated_uses.add(representation_use)
        inputs = derivation.get("input_artifacts")
        if not isinstance(inputs, list) or not inputs:
            route_problems.append(
                ValidationProblem(
                    path,
                    location,
                    "selected public-bundle derivation has no input route",
                )
            )
        else:
            combined_routes: tuple[ArtifactRightsRoute, ...] = (
                ArtifactRightsRoute(frozenset(), frozenset(), frozenset()),
            )
            for item in inputs:
                input_id = item.get("artifact_id") if isinstance(item, dict) else None
                route_options = (
                    _artifact_rights_route_options(
                        input_id,
                        capture_ids,
                        captures,
                        derivations,
                        route_cache,
                        allowed_derivation_ids=selected_derivation_ids,
                    )
                    if isinstance(input_id, str)
                    else ()
                )
                if not route_options:
                    route_problems.append(
                        ValidationProblem(
                            path,
                            location,
                            "selected derivation rights bases do not cover every cited input",
                        )
                    )
                    continue
                combined_routes = _nondominated_rights_routes(
                    ArtifactRightsRoute(
                        left.required_uses | right.required_uses,
                        left.derivation_ids | right.derivation_ids,
                        left.capture_ids | right.capture_ids,
                    )
                    for left in combined_routes
                    for right in route_options
                )
            if combined_routes:
                for combined_route in combined_routes:
                    candidate_problems = list(route_problems)
                    if UNCLASSIFIED_TRANSFORM_USE in combined_route.required_uses:
                        candidate_problems.append(
                            ValidationProblem(
                                path,
                                location,
                                "a nested unclassified derivation cannot establish public-bundle rights",
                            )
                        )
                    route_derivation_ids = set(combined_route.derivation_ids) | {
                        derivation_id
                    }
                    route_capture_ids = set(combined_route.capture_ids) | capture_ids
                    candidate_problems.extend(
                        _route_artifact_availability_problems(
                            path,
                            location,
                            route_capture_ids,
                            route_derivation_ids,
                            artifacts,
                            captures,
                            derivations,
                        )
                    )
                    candidate_problems.extend(
                        _derivation_clearance_problems(
                            path,
                            location,
                            route_derivation_ids,
                            derivations,
                            deadline=generated_at,
                        )
                    )
                    candidate_uses = accumulated_uses | {
                        use
                        for use in combined_route.required_uses
                        if use != UNCLASSIFIED_TRANSFORM_USE
                    }
                    for capture_id in route_capture_ids:
                        capture_entry = captures.get(capture_id)
                        capture = capture_entry[1] if capture_entry is not None else None
                        source_id = (
                            capture.get("source_id")
                            if isinstance(capture, dict)
                            else None
                        )
                        source_entry = (
                            sources.get(source_id)
                            if isinstance(source_id, str)
                            else None
                        )
                        if (
                            not isinstance(capture, dict)
                            or capture.get("source_status") != "verified_official"
                            or source_entry is None
                            or source_entry[1].get("identity_state") != "reviewed"
                        ):
                            candidate_problems.append(
                                ValidationProblem(
                                    path,
                                    location,
                                    f"capture {capture_id!r} in a derived evidence route is not backed by a reviewed official source",
                                )
                            )
                        if require_reuse_rights:
                            candidate_problems.extend(
                                _publication_capture_problems(
                                    path,
                                    artifact_id,
                                    capture_id,
                                    captures,
                                    candidate_uses,
                                    location,
                                    direct_capture=False,
                                    evaluation_at=rights_evaluation_at,
                                )
                            )
                        else:
                            if capture_entry is None or not _publication_clearance_is_valid(
                                capture_entry[1].get("publication_clearance")
                            ):
                                candidate_problems.append(
                                    ValidationProblem(
                                        path,
                                        location,
                                        f"capture {capture_id!r} in a public citation route lacks publication clearance",
                                    )
                                )
                    candidate_problems.extend(
                        _bundle_capture_deadline_problems(
                            path,
                            location,
                            route_capture_ids,
                            captures,
                            generated_at,
                        )
                    )
                    if not candidate_problems:
                        return []
                    candidates.append(candidate_problems)
                continue
        if route_problems:
            candidates.append(route_problems)
    if candidates:
        return min(candidates, key=len)
    return [
        ValidationProblem(
            path,
            location,
            "public bundle has no selected derivation route that establishes reuse rights",
        )
    ]


def corpus_publication_problems(
    documents: list[tuple[Path, dict[str, Any]]]
) -> list[ValidationProblem]:
    """Resolve publication routes without collapsing source-scoped rights."""

    artifacts: dict[str, tuple[Path, dict[str, Any]]] = {}
    captures: dict[str, tuple[Path, dict[str, Any]]] = {}
    derivations: dict[str, tuple[Path, dict[str, Any]]] = {}
    sources: dict[str, tuple[Path, dict[str, Any]]] = {}
    for path, document in documents:
        schema_id = str(document.get("schema_id", ""))
        if schema_id.endswith("/artifact.schema.json") and isinstance(
            document.get("artifact_id"), str
        ):
            artifacts[document["artifact_id"]] = (path, document)
        elif schema_id.endswith("/capture.schema.json") and isinstance(
            document.get("capture_id"), str
        ):
            captures[document["capture_id"]] = (path, document)
        elif schema_id.endswith("/derivation.schema.json") and isinstance(
            document.get("derivation_id"), str
        ):
            derivations[document["derivation_id"]] = (path, document)
        elif schema_id.endswith("/source-manifest.schema.json") and isinstance(
            document.get("source_id"), str
        ):
            sources[document["source_id"]] = (path, document)

    problems: list[ValidationProblem] = []
    rights_route_cache: RightsRouteCache = {}
    snapshot_times = [
        parsed
        for _, document in documents
        if str(document.get("schema_id", "")).endswith("/snapshot.schema.json")
        and isinstance(document.get("generated_at"), str)
        and (parsed := _parse_datetime(document["generated_at"])) is not None
    ]
    corpus_evaluation_at = max(snapshot_times, default=None)

    for path, artifact in documents:
        if not str(artifact.get("schema_id", "")).endswith("/artifact.schema.json"):
            continue
        if artifact.get("availability") != "public_mirror":
            continue
        problems.append(
            ValidationProblem(
                path,
                "$.availability",
                "public mirrors are disabled in V1 until a release-as-of delivery manifest binds attribution, unofficial-copy notice, rights review, and publication clearance",
            )
        )
        artifact_id = artifact.get("artifact_id")
        artifact_created_at = (
            _parse_datetime(artifact.get("created_at"))
            if isinstance(artifact.get("created_at"), str)
            else None
        )
        evaluation_at = corpus_evaluation_at or artifact_created_at
        bases = artifact.get("publication_basis")
        if not isinstance(artifact_id, str) or not isinstance(bases, list):
            continue
        for index, basis in enumerate(bases):
            if not isinstance(basis, dict):
                continue
            location = f"$.publication_basis[{index}]"
            basis_id = basis.get("basis_id")
            if not isinstance(basis_id, str):
                continue
            if basis.get("basis_type") == "capture":
                capture_entry = captures.get(basis_id)
                capture = capture_entry[1] if capture_entry is not None else None
                source_id = capture.get("source_id") if isinstance(capture, dict) else None
                source_entry = sources.get(source_id) if isinstance(source_id, str) else None
                if (
                    not isinstance(capture, dict)
                    or capture.get("source_status") != "verified_official"
                    or source_entry is None
                    or source_entry[1].get("identity_state") != "reviewed"
                ):
                    problems.append(
                        ValidationProblem(
                            path,
                            location,
                            "publication basis capture is not backed by a reviewed official source",
                        )
                    )
                problems.extend(
                    _publication_capture_problems(
                        path,
                        artifact_id,
                        basis_id,
                        captures,
                        {"capture", "public_mirroring", "redistribution"},
                        location,
                        direct_capture=True,
                        evaluation_at=evaluation_at,
                    )
                )
                continue

            derivation_entry = derivations.get(basis_id)
            if derivation_entry is None:
                problems.append(
                    ValidationProblem(
                        path,
                        location,
                        f"publication basis derivation {basis_id!r} does not resolve",
                    )
                )
                continue
            _, derivation = derivation_entry
            basis_problems: list[ValidationProblem] = []
            if derivation.get("output_artifact_id") != artifact_id:
                basis_problems.append(
                    ValidationProblem(
                        path,
                        location,
                        "publication basis derivation must produce the published artifact",
                    )
                )
            required_uses = {"capture", "public_mirroring", "redistribution"}
            representation = derivation.get("representation")
            if representation in TRANSFORM_RIGHTS_USE:
                required_uses.add(TRANSFORM_RIGHTS_USE[representation])
            else:
                basis_problems.append(
                    ValidationProblem(
                        path,
                        location,
                        "an 'other' derivation cannot automatically establish publication rights",
                    )
                )
            capture_ids = derivation.get("rights_basis_capture_ids")
            if isinstance(capture_ids, list):
                basis_set = {
                    capture_id for capture_id in capture_ids if isinstance(capture_id, str)
                }
                inputs = derivation.get("input_artifacts")
                combined_routes: tuple[ArtifactRightsRoute, ...] = (
                    ArtifactRightsRoute(frozenset(), frozenset(), frozenset()),
                )
                if isinstance(inputs, list):
                    for input_index, item in enumerate(inputs):
                        input_id = item.get("artifact_id") if isinstance(item, dict) else None
                        route_options = (
                            _artifact_rights_route_options(
                                input_id,
                                basis_set,
                                captures,
                                derivations,
                                rights_route_cache,
                            )
                            if isinstance(input_id, str)
                            else ()
                        )
                        if not route_options:
                            basis_problems.append(
                                ValidationProblem(
                                    path,
                                    location,
                                    "derivation rights-basis captures do not cover "
                                    f"input_artifacts[{input_index}]",
                                )
                            )
                            continue
                        combined_routes = _nondominated_rights_routes(
                            ArtifactRightsRoute(
                                left.required_uses | right.required_uses,
                                left.derivation_ids | right.derivation_ids,
                                left.capture_ids | right.capture_ids,
                            )
                            for left in combined_routes
                            for right in route_options
                        )
                candidate_routes = combined_routes or (
                    ArtifactRightsRoute(frozenset(), frozenset(), frozenset()),
                )
                route_candidates: list[list[ValidationProblem]] = []
                for route in candidate_routes:
                    candidate_problems = list(basis_problems)
                    if UNCLASSIFIED_TRANSFORM_USE in route.required_uses:
                        candidate_problems.append(
                            ValidationProblem(
                                path,
                                location,
                                "a nested 'other' derivation cannot automatically establish publication rights",
                            )
                        )
                    candidate_problems.extend(
                        _route_artifact_availability_problems(
                            path,
                            location,
                            basis_set | set(route.capture_ids),
                            set(route.derivation_ids) | {basis_id},
                            artifacts,
                            captures,
                            derivations,
                        )
                    )
                    candidate_problems.extend(
                        _derivation_clearance_problems(
                            path,
                            location,
                            set(route.derivation_ids) | {basis_id},
                            derivations,
                        )
                    )
                    route_required_uses = required_uses | {
                        use
                        for use in route.required_uses
                        if use != UNCLASSIFIED_TRANSFORM_USE
                    }
                    for capture_id in basis_set:
                        capture_entry = captures.get(capture_id)
                        capture = capture_entry[1] if capture_entry is not None else None
                        source_id = (
                            capture.get("source_id") if isinstance(capture, dict) else None
                        )
                        source_entry = (
                            sources.get(source_id) if isinstance(source_id, str) else None
                        )
                        if (
                            not isinstance(capture, dict)
                            or capture.get("source_status") != "verified_official"
                            or source_entry is None
                            or source_entry[1].get("identity_state") != "reviewed"
                        ):
                            candidate_problems.append(
                                ValidationProblem(
                                    path,
                                    location,
                                    f"capture {capture_id!r} in a publication route is not backed by a reviewed official source",
                                )
                            )
                        candidate_problems.extend(
                            _publication_capture_problems(
                                path,
                                artifact_id,
                                capture_id,
                                captures,
                                route_required_uses,
                                location,
                                evaluation_at=evaluation_at,
                            )
                        )
                    if not candidate_problems:
                        route_candidates = []
                        break
                    route_candidates.append(candidate_problems)
                if route_candidates:
                    problems.extend(min(route_candidates, key=len))
            else:
                problems.extend(basis_problems)
    return problems


TOP_LEVEL_ID_FIELDS = {
    "artifact.schema.json": "artifact_id",
    "authority.schema.json": "authority_id",
    "capture.schema.json": "capture_id",
    "correction-report.schema.json": "report_id",
    "coverage-ledger.schema.json": "coverage_id",
    "derivation.schema.json": "derivation_id",
    "evidence-bundle.schema.json": "bundle_id",
    "invalidation-event.schema.json": "event_id",
    "jurisdiction.schema.json": "jurisdiction_id",
    "record.schema.json": "record_id",
    "relationship-assertion.schema.json": "assertion_id",
    "snapshot.schema.json": "snapshot_id",
    "source-manifest.schema.json": "source_id",
}


def _capture_acquisition_problems(
    captures: dict[str, tuple[Path, dict[str, Any]]],
    sources: dict[str, tuple[Path, dict[str, Any]]],
) -> list[ValidationProblem]:
    """Bind every capture URL to a declared entrypoint or cited link chain."""

    problems: list[ValidationProblem] = []
    discovered_parents: dict[str, str] = {}
    for capture_id, (path, capture) in captures.items():
        source_id = capture.get("source_id")
        source_entry = sources.get(source_id) if isinstance(source_id, str) else None
        if source_entry is None:
            continue
        source = source_entry[1]
        entrypoints = {
            entrypoint["entrypoint_id"]: entrypoint
            for entrypoint in _list_or_empty(source.get("entrypoints"))
            if isinstance(entrypoint, dict)
            and isinstance(entrypoint.get("entrypoint_id"), str)
        }
        acquisition = capture.get("acquisition")
        if not isinstance(acquisition, dict):
            continue
        entrypoint_id = acquisition.get("entrypoint_id")
        entrypoint = (
            entrypoints.get(entrypoint_id) if isinstance(entrypoint_id, str) else None
        )
        if entrypoint is None:
            problems.append(
                ValidationProblem(
                    path,
                    "$.acquisition.entrypoint_id",
                    "capture acquisition entrypoint does not resolve in its source manifest",
                )
            )
            continue
        retrieval = capture.get("retrieval")
        source_url = (
            retrieval.get("source_url") if isinstance(retrieval, dict) else None
        )
        route = acquisition.get("route")
        if route == "entrypoint_exact":
            if source_url != entrypoint.get("url"):
                problems.append(
                    ValidationProblem(
                        path,
                        "$.retrieval.source_url",
                        "direct capture URL must exactly match its declared source entrypoint",
                    )
                )
            continue
        if route != "discovered_link":
            continue

        evidence = acquisition.get("discovery_evidence")
        parent_capture_id = (
            evidence.get("capture_id") if isinstance(evidence, dict) else None
        )
        if not isinstance(parent_capture_id, str):
            continue
        discovered_parents[capture_id] = parent_capture_id
        if parent_capture_id == capture_id:
            problems.append(
                ValidationProblem(
                    path,
                    "$.acquisition.discovery_evidence.capture_id",
                    "a discovered capture may not cite itself as its acquisition route",
                )
            )
            continue
        parent_entry = captures.get(parent_capture_id)
        if parent_entry is None:
            continue
        parent = parent_entry[1]
        if parent.get("source_id") != source_id:
            problems.append(
                ValidationProblem(
                    path,
                    "$.acquisition.discovery_evidence.capture_id",
                    "discovery parent must belong to the same source manifest",
                )
            )
        parent_acquisition = parent.get("acquisition")
        if (
            not isinstance(parent_acquisition, dict)
            or parent_acquisition.get("entrypoint_id") != entrypoint_id
        ):
            problems.append(
                ValidationProblem(
                    path,
                    "$.acquisition.entrypoint_id",
                    "discovered capture and parent must trace to the same entrypoint",
                )
            )
        if not _capture_http_succeeded(parent):
            problems.append(
                ValidationProblem(
                    path,
                    "$.acquisition.discovery_evidence.capture_id",
                    "discovery parent must be a complete HTTP 200 capture",
                )
            )
        parent_retrieval = parent.get("retrieval")
        child_retrieval = capture.get("retrieval")
        parent_evidence_times = [
            _parse_datetime(parent["created_at"])
            if isinstance(parent.get("created_at"), str)
            else None,
            _parse_datetime(parent_retrieval["retrieved_at"])
            if isinstance(parent_retrieval, dict)
            and isinstance(parent_retrieval.get("retrieved_at"), str)
            else None,
        ]
        child_retrieved_at = (
            _parse_datetime(child_retrieval["retrieved_at"])
            if isinstance(child_retrieval, dict)
            and isinstance(child_retrieval.get("retrieved_at"), str)
            else None
        )
        if child_retrieved_at is not None and any(
            evidence_time is not None and child_retrieved_at < evidence_time
            for evidence_time in parent_evidence_times
        ):
            problems.append(
                ValidationProblem(
                    path,
                    "$.retrieval.retrieved_at",
                    "discovered capture retrieval cannot predate the parent capture evidence used to discover it",
                )
            )
        if isinstance(evidence, dict) and evidence.get("artifact_id") != parent.get(
            "artifact_id"
        ):
            problems.append(
                ValidationProblem(
                    path,
                    "$.acquisition.discovery_evidence.artifact_id",
                    "discovery evidence must cite the parent capture's exact artifact",
                )
            )
        discovered_value = acquisition.get("discovered_value")
        quoted_text = evidence.get("quoted_text") if isinstance(evidence, dict) else None
        if not (
            isinstance(discovered_value, str)
            and isinstance(quoted_text, str)
            and _quote_has_exact_field_value(
                quoted_text,
                discovered_value,
                field="discovered_value",
            )
        ):
            problems.append(
                ValidationProblem(
                    path,
                    "$.acquisition.discovered_value",
                    "discovered URL value must occur at an exact whole-field boundary in parent evidence",
                )
            )
        parent_url = (
            parent_retrieval.get("source_url")
            if isinstance(parent_retrieval, dict)
            else None
        )
        if (
            isinstance(parent_url, str)
            and isinstance(discovered_value, str)
            and isinstance(source_url, str)
        ):
            try:
                resolved_url = urljoin(parent_url, discovered_value)
                parent_parts = urlsplit(parent_url)
                child_parts = urlsplit(source_url)
                parent_port = parent_parts.port
                child_port = child_parts.port
            except ValueError:
                problems.append(
                    ValidationProblem(
                        path,
                        "$.retrieval.source_url",
                        "discovered capture origin is malformed or has an invalid network port",
                    )
                )
            else:
                if resolved_url != source_url:
                    problems.append(
                        ValidationProblem(
                            path,
                            "$.retrieval.source_url",
                            "capture URL does not resolve from its cited discovery value and parent URL",
                        )
                    )
                parent_origin = (
                    parent_parts.scheme.casefold(),
                    (parent_parts.hostname or "").casefold(),
                    (
                        parent_port
                        if parent_port is not None
                        else (443 if parent_parts.scheme.casefold() == "https" else 80)
                    ),
                )
                child_origin = (
                    child_parts.scheme.casefold(),
                    (child_parts.hostname or "").casefold(),
                    (
                        child_port
                        if child_port is not None
                        else (443 if child_parts.scheme.casefold() == "https" else 80)
                    ),
                )
                if child_origin != parent_origin:
                    problems.append(
                        ValidationProblem(
                            path,
                            "$.retrieval.source_url",
                            "discovered captures must remain on the reviewed source origin in V1; declare a separate reviewed source manifest for a cross-origin target",
                        )
                    )

    reported_cycles: set[frozenset[str]] = set()
    for start_capture_id in discovered_parents:
        chain: list[str] = []
        indexes: dict[str, int] = {}
        current = start_capture_id
        while current in discovered_parents:
            if current in indexes:
                cycle = frozenset(chain[indexes[current] :])
                if cycle and cycle not in reported_cycles:
                    reported_cycles.add(cycle)
                    cycle_path = captures[start_capture_id][0]
                    problems.append(
                        ValidationProblem(
                            cycle_path,
                            "$.acquisition.discovery_evidence.capture_id",
                            "capture acquisition lineage contains a discovery cycle",
                        )
                    )
                break
            indexes[current] = len(chain)
            chain.append(current)
            current = discovered_parents[current]
    return problems


def corpus_integrity_problems(
    documents: list[tuple[Path, dict[str, Any]]]
) -> list[ValidationProblem]:
    """Check byte/provenance references that require more than one document."""

    artifacts: dict[str, tuple[Path, dict[str, Any]]] = {}
    authorities: dict[str, tuple[Path, dict[str, Any]]] = {}
    assertions: dict[str, tuple[Path, dict[str, Any]]] = {}
    bundles: dict[str, tuple[Path, dict[str, Any]]] = {}
    captures: dict[str, tuple[Path, dict[str, Any]]] = {}
    corrections: dict[str, tuple[Path, dict[str, Any]]] = {}
    coverages: dict[str, tuple[Path, dict[str, Any]]] = {}
    derivations: dict[str, tuple[Path, dict[str, Any]]] = {}
    events: dict[str, tuple[Path, dict[str, Any]]] = {}
    gap_records: dict[str, tuple[Path, dict[str, Any]]] = {}
    jurisdictions: dict[str, tuple[Path, dict[str, Any]]] = {}
    claim_records: dict[str, tuple[Path, dict[str, Any]]] = {}
    component_records: dict[str, tuple[Path, dict[str, Any]]] = {}
    records: dict[str, tuple[Path, dict[str, Any]]] = {}
    record_versions: dict[str, tuple[Path, str, dict[str, Any]]] = {}
    provision_versions: dict[str, tuple[Path, str, str, dict[str, Any]]] = {}
    provision_records: dict[str, set[str]] = {}
    snapshots: dict[str, tuple[Path, dict[str, Any]]] = {}
    sources: dict[str, tuple[Path, dict[str, Any]]] = {}
    seen_ids: dict[str, Path] = {}
    problems: list[ValidationProblem] = []
    rights_route_cache: RightsRouteCache = {}

    for path, document in documents:
        schema_name = str(document.get("schema_id", "")).rsplit("/", 1)[-1]
        id_field = TOP_LEVEL_ID_FIELDS.get(schema_name)
        identity = document.get(id_field) if id_field is not None else None
        if isinstance(identity, str):
            earlier = seen_ids.get(identity)
            if earlier is not None:
                problems.append(
                    ValidationProblem(
                        path,
                        f"$.{id_field}",
                        f"top-level identity duplicates {earlier}",
                    )
                )
            else:
                seen_ids[identity] = path
        if schema_name == "artifact.schema.json" and isinstance(identity, str):
            artifacts[identity] = (path, document)
        elif schema_name == "authority.schema.json" and isinstance(identity, str):
            authorities[identity] = (path, document)
        elif schema_name == "relationship-assertion.schema.json" and isinstance(
            identity, str
        ):
            assertions[identity] = (path, document)
        elif schema_name == "capture.schema.json" and isinstance(identity, str):
            captures[identity] = (path, document)
        elif schema_name == "correction-report.schema.json" and isinstance(identity, str):
            corrections[identity] = (path, document)
        elif schema_name == "coverage-ledger.schema.json" and isinstance(identity, str):
            coverages[identity] = (path, document)
        elif schema_name == "derivation.schema.json" and isinstance(identity, str):
            derivations[identity] = (path, document)
        elif schema_name == "evidence-bundle.schema.json" and isinstance(identity, str):
            bundles[identity] = (path, document)
        elif schema_name == "invalidation-event.schema.json" and isinstance(identity, str):
            events[identity] = (path, document)
        elif schema_name == "jurisdiction.schema.json" and isinstance(identity, str):
            jurisdictions[identity] = (path, document)
        elif schema_name == "record.schema.json" and isinstance(identity, str):
            records[identity] = (path, document)
        elif schema_name == "snapshot.schema.json" and isinstance(identity, str):
            snapshots[identity] = (path, document)
        elif schema_name == "source-manifest.schema.json" and isinstance(identity, str):
            sources[identity] = (path, document)

    problems.extend(_capture_acquisition_problems(captures, sources))
    corpus_evaluation_at = max(
        (
            parsed
            for _, snapshot in snapshots.values()
            if isinstance(snapshot.get("generated_at"), str)
            and (parsed := _parse_datetime(snapshot["generated_at"])) is not None
        ),
        default=None,
    )
    derivation_ids_by_output: dict[str, set[str]] = {}
    for derivation_id, (_, derivation) in derivations.items():
        output_artifact_id = derivation.get("output_artifact_id")
        if isinstance(output_artifact_id, str):
            derivation_ids_by_output.setdefault(output_artifact_id, set()).add(
                derivation_id
            )

    official_capture_artifact_ids = {
        capture.get("artifact_id")
        for _, capture in captures.values()
        if isinstance(capture.get("artifact_id"), str)
        and _capture_http_succeeded(capture)
        and capture.get("source_status") == "verified_official"
        and isinstance(capture.get("source_id"), str)
        and capture["source_id"] in sources
        and sources[capture["source_id"]][1].get("identity_state") == "reviewed"
    }
    official_provenance_artifact_ids = set(official_capture_artifact_ids)
    official_provenance_changed = True
    while official_provenance_changed:
        official_provenance_changed = False
        for _, derivation in derivations.values():
            output_artifact_id = derivation.get("output_artifact_id")
            input_artifact_ids = {
                item.get("artifact_id")
                for item in _list_or_empty(derivation.get("input_artifacts"))
                if isinstance(item, dict) and isinstance(item.get("artifact_id"), str)
            }
            if (
                isinstance(output_artifact_id, str)
                and output_artifact_id not in official_provenance_artifact_ids
                and input_artifact_ids
                and input_artifact_ids <= official_provenance_artifact_ids
            ):
                official_provenance_artifact_ids.add(output_artifact_id)
                official_provenance_changed = True
    derived_official_artifact_ids = (
        official_provenance_artifact_ids - official_capture_artifact_ids
    )

    for source_id, (path, source) in sources.items():
        if source.get("identity_state") != "reviewed":
            continue
        identity_review = source.get("identity_review")
        review_time = (
            _parse_datetime(identity_review.get("reviewed_at"))
            if isinstance(identity_review, dict)
            and isinstance(identity_review.get("reviewed_at"), str)
            else None
        )
        for index, citation in enumerate(
            _list_or_empty(source.get("identity_evidence"))
        ):
            if not isinstance(citation, dict):
                continue
            location = f"$.identity_evidence[{index}]"
            artifact_id = citation.get("artifact_id")
            capture_id = citation.get("capture_id")
            capture_entry = (
                captures.get(capture_id) if isinstance(capture_id, str) else None
            )
            if capture_entry is None:
                problems.append(
                    ValidationProblem(
                        path,
                        f"{location}.capture_id",
                        "reviewed source identity evidence must resolve to an exact capture",
                    )
                )
                continue
            capture = capture_entry[1]
            if capture.get("source_id") != source_id:
                problems.append(
                    ValidationProblem(
                        path,
                        f"{location}.capture_id",
                        "source identity evidence capture must belong to this source manifest",
                    )
                )
            if capture.get("artifact_id") != artifact_id:
                problems.append(
                    ValidationProblem(
                        path,
                        f"{location}.artifact_id",
                        "source identity evidence must cite the capture's exact artifact",
                    )
                )
            if not isinstance(artifact_id, str) or artifact_id not in artifacts:
                problems.append(
                    ValidationProblem(
                        path,
                        f"{location}.artifact_id",
                        "source identity evidence artifact does not resolve",
                    )
                )
            if not _capture_http_succeeded(capture):
                problems.append(
                    ValidationProblem(
                        path,
                        f"{location}.capture_id",
                        "source identity review requires a complete HTTP 200 capture",
                    )
                )
            retrieval = capture.get("retrieval")
            retrieval_time = (
                _parse_datetime(retrieval.get("retrieved_at"))
                if isinstance(retrieval, dict)
                and isinstance(retrieval.get("retrieved_at"), str)
                else None
            )
            artifact_entry = (
                artifacts.get(artifact_id) if isinstance(artifact_id, str) else None
            )
            artifact_time = (
                _parse_datetime(artifact_entry[1].get("created_at"))
                if artifact_entry is not None
                and isinstance(artifact_entry[1].get("created_at"), str)
                else None
            )
            if review_time is not None and any(
                review_time < evidence_time
                for evidence_time in (retrieval_time, artifact_time)
                if evidence_time is not None
            ):
                problems.append(
                    ValidationProblem(
                        path,
                        "$.identity_review.reviewed_at",
                        "source identity review cannot predate its captured evidence",
                    )
                )

    for _capture_id, (path, capture) in captures.items():
        if capture.get("source_status") != "verified_official":
            continue
        source_id = capture.get("source_id")
        source_entry = sources.get(source_id) if isinstance(source_id, str) else None
        if source_entry is None or source_entry[1].get("identity_state") != "reviewed":
            problems.append(
                ValidationProblem(
                    path,
                    "$.source_status",
                    "verified-official capture requires an independently reviewed source manifest",
                )
            )

    evidence_bearing_schemas = {
        "authority.schema.json",
        "evidence-bundle.schema.json",
        "jurisdiction.schema.json",
        "record.schema.json",
        "relationship-assertion.schema.json",
    }
    for path, document in documents:
        schema_name = str(document.get("schema_id", "")).rsplit("/", 1)[-1]
        if schema_name not in evidence_bearing_schemas:
            continue
        for location, value in _walk(document):
            if not isinstance(value, dict):
                continue
            artifact_id = value.get("artifact_id")
            capture_id = value.get("capture_id")
            if not isinstance(artifact_id, str) or not isinstance(
                value.get("locator"), dict
            ):
                continue
            capture_entry = (
                captures.get(capture_id) if isinstance(capture_id, str) else None
            )
            has_official_route = False
            if capture_entry is not None:
                capture = capture_entry[1]
                source_id = capture.get("source_id")
                source_entry = (
                    sources.get(source_id) if isinstance(source_id, str) else None
                )
                if capture.get("source_status") != "verified_official" or (
                    source_entry is None
                    or source_entry[1].get("identity_state") != "reviewed"
                ):
                    problems.append(
                        ValidationProblem(
                            path,
                            _json_location((*location, "capture_id")),
                            "legal and profile evidence requires a verified-official capture from an independently reviewed source manifest",
                        )
                    )
                elif capture.get("artifact_id") == artifact_id and _capture_http_succeeded(
                    capture
                ):
                    has_official_route = True
            elif not isinstance(capture_id, str) and artifact_id in derived_official_artifact_ids:
                has_official_route = True
            if not has_official_route:
                problems.append(
                    ValidationProblem(
                        path,
                        _json_location(location),
                        "legal and profile evidence must resolve through an exact reviewed-official capture or a complete derivation from reviewed-official captures",
                    )
                )
            if schema_name != "evidence-bundle.schema.json" and not (
                isinstance(value.get("quoted_text"), str)
                or isinstance(value.get("quoted_text_digest"), dict)
            ):
                problems.append(
                    ValidationProblem(
                        path,
                        _json_location(location),
                        "legal and profile evidence must bind cited content with quoted_text or quoted_text_digest",
                    )
                )
            quoted_text = value.get("quoted_text")
            if isinstance(quoted_text, str) and not _is_minimal_public_temporal_fact_quote(
                value
            ):
                quote_location = _json_location((*location, "quoted_text"))
                if isinstance(capture_id, str):
                    quote_route_problems = _publication_capture_problems(
                        path,
                        artifact_id,
                        capture_id,
                        captures,
                        {"capture", "transcription", "redistribution"},
                        quote_location,
                        direct_capture=True,
                        evaluation_at=corpus_evaluation_at,
                    )
                else:
                    outer_derivation_ids = derivation_ids_by_output.get(
                        artifact_id, set()
                    )
                    quote_route_problems = (
                        _derived_bundle_rights_problems(
                            path,
                            quote_location,
                            artifact_id,
                            outer_derivation_ids,
                            set(derivations),
                            {"transcription"},
                            artifacts,
                            captures,
                            sources,
                            derivations,
                            rights_route_cache,
                            corpus_evaluation_at,
                            corpus_evaluation_at,
                            require_reuse_rights=True,
                        )
                        if outer_derivation_ids
                        else [
                            ValidationProblem(
                                path,
                                quote_location,
                                "quoted text artifact has no exact capture or derivation publication route",
                            )
                        ]
                    )
                if quote_route_problems:
                    problems.append(
                        ValidationProblem(
                            path,
                            quote_location,
                            "public copied source text requires an exact human-reviewed rights and publication-clearance route; retain a content digest or keep the bytes private",
                        )
                    )
                    problems.extend(quote_route_problems)

    for path, document in documents:
        if str(document.get("schema_id", "")).endswith("/record.schema.json"):
            problems.extend(
                _record_metadata_evidence_chronology_problems(
                    path,
                    document,
                    artifacts,
                    captures,
                )
            )
        if str(document.get("schema_id", "")).endswith(
            ("/authority.schema.json", "/jurisdiction.schema.json")
        ):
            problems.extend(
                _profile_binding_evidence_chronology_problems(
                    path,
                    document,
                    artifacts,
                    captures,
                )
            )

    entity_ids: dict[str, set[str]] = {
        "artifact": set(artifacts),
        "authority": set(authorities),
        "assertion": set(assertions),
        "bundle": set(bundles),
        "capture": set(captures),
        "coverage": set(coverages),
        "derivation": set(derivations),
        "event": set(events),
        "jurisdiction": set(jurisdictions),
        "record": set(records),
        "report": set(corrections),
        "snapshot": set(snapshots),
        "source": set(sources),
    }
    for record_id, (record_path, record) in records.items():
        versions = record.get("versions")
        if not isinstance(versions, list):
            continue
        for version in versions:
            if not isinstance(version, dict):
                continue
            version_id = version.get("version_id")
            if isinstance(version_id, str):
                earlier_version = record_versions.get(version_id)
                if earlier_version is not None:
                    problems.append(
                        ValidationProblem(
                            record_path,
                            "$.versions",
                            f"version identity duplicates {earlier_version[0]}",
                        )
                    )
                else:
                    record_versions[version_id] = (record_path, record_id, version)
                entity_ids.setdefault("version", set()).add(version_id)
            provisions = version.get("provisions")
            if not isinstance(provisions, list):
                continue
            for provision in provisions:
                if not isinstance(provision, dict):
                    continue
                provision_id = provision.get("provision_id")
                provision_version_id = provision.get("provision_version_id")
                if isinstance(provision_id, str):
                    existing_records = provision_records.get(provision_id, set())
                    if existing_records and record_id not in existing_records:
                        problems.append(
                            ValidationProblem(
                                record_path,
                                "$.versions[*].provisions",
                                "stable provision identity is reused by more than one record",
                            )
                        )
                    entity_ids.setdefault("provision", set()).add(provision_id)
                    provision_records.setdefault(provision_id, set()).add(record_id)
                if isinstance(provision_version_id, str):
                    earlier_provision_version = provision_versions.get(
                        provision_version_id
                    )
                    if earlier_provision_version is not None:
                        problems.append(
                            ValidationProblem(
                                record_path,
                                "$.versions[*].provisions",
                                "provision-version identity duplicates "
                                f"{earlier_provision_version[0]}",
                            )
                        )
                    else:
                        provision_versions[provision_version_id] = (
                            record_path,
                            record_id,
                            version_id if isinstance(version_id, str) else "",
                            provision,
                        )
                    entity_ids.setdefault("provision_version", set()).add(
                        provision_version_id
                    )
    for _, document in documents:
        schema_name = str(document.get("schema_id", "")).rsplit("/", 1)[-1]
        if schema_name == "coverage-ledger.schema.json":
            gaps = document.get("known_gaps")
            if isinstance(gaps, list):
                for gap in gaps:
                    gap_id = gap.get("gap_id") if isinstance(gap, dict) else None
                    if isinstance(gap_id, str):
                        entity_ids.setdefault("gap", set()).add(gap_id)
                        gap_records.setdefault(gap_id, (path, gap))
        elif schema_name == "evidence-bundle.schema.json":
            claims = document.get("claims")
            if isinstance(claims, list):
                for claim in claims:
                    claim_id = claim.get("claim_id") if isinstance(claim, dict) else None
                    if isinstance(claim_id, str):
                        entity_ids.setdefault("claim", set()).add(claim_id)
                        claim_records.setdefault(claim_id, (path, claim))
        elif schema_name == "snapshot.schema.json":
            components = document.get("components")
            if isinstance(components, list):
                for component in components:
                    component_id = (
                        component.get("component_id")
                        if isinstance(component, dict)
                        else None
                    )
                    if isinstance(component_id, str):
                        entity_ids.setdefault("component", set()).add(component_id)
                        component_records.setdefault(component_id, (path, component))

    for authority_id, (path, authority) in authorities.items():
        relationship_specs = (
            (
                "jurisdictions_served",
                "jurisdiction_id",
                "jurisdiction",
                {"serves_jurisdiction"},
            ),
            (
                "parent_relationships",
                "parent_authority_id",
                "authority",
                {"institutionally_part_of"},
            ),
        )
        for field, target_field, target_type, predicates in relationship_specs:
            references = authority.get(field)
            if not isinstance(references, list):
                continue
            for index, reference in enumerate(references):
                if not isinstance(reference, dict):
                    continue
                target_id = reference.get(target_field)
                assertion_id = reference.get("assertion_id")
                location = f"$.{field}[{index}]"
                if not isinstance(target_id, str) or target_id not in entity_ids.get(
                    target_type, set()
                ):
                    problems.append(
                        ValidationProblem(
                            path,
                            f"{location}.{target_field}",
                            f"authority relationship {target_type} does not resolve",
                        )
                    )

                assertion_entry = (
                    assertions.get(assertion_id) if isinstance(assertion_id, str) else None
                )
                if assertion_entry is None:
                    problems.append(
                        ValidationProblem(
                            path,
                            f"{location}.assertion_id",
                            "authority relationship assertion does not resolve",
                        )
                    )
                    continue
                assertion = assertion_entry[1]
                if assertion.get("subject") != {
                    "entity_type": "authority",
                    "entity_id": authority_id,
                }:
                    problems.append(
                        ValidationProblem(
                            path,
                            f"{location}.assertion_id",
                            "authority relationship assertion subject does not match this authority",
                        )
                    )
                if assertion.get("object") != {
                    "entity_type": target_type,
                    "entity_id": target_id,
                }:
                    problems.append(
                        ValidationProblem(
                            path,
                            f"{location}.assertion_id",
                            "authority relationship assertion object does not match the referenced target",
                        )
                    )
                if assertion.get("predicate") not in predicates:
                    problems.append(
                        ValidationProblem(
                            path,
                            f"{location}.assertion_id",
                            "authority relationship assertion predicate does not match the reference role",
                        )
                    )

    for jurisdiction_id, (path, jurisdiction) in jurisdictions.items():
        references = jurisdiction.get("territorial_relationships")
        if not isinstance(references, list):
            continue
        for index, reference in enumerate(references):
            if not isinstance(reference, dict):
                continue
            target_id = reference.get("related_jurisdiction_id")
            assertion_id = reference.get("assertion_id")
            location = f"$.territorial_relationships[{index}]"
            if not isinstance(target_id, str) or target_id not in jurisdictions:
                problems.append(
                    ValidationProblem(
                        path,
                        f"{location}.related_jurisdiction_id",
                        "related jurisdiction does not resolve",
                    )
                )
            assertion_entry = (
                assertions.get(assertion_id) if isinstance(assertion_id, str) else None
            )
            if assertion_entry is None:
                problems.append(
                    ValidationProblem(
                        path,
                        f"{location}.assertion_id",
                        "territorial relationship assertion does not resolve",
                    )
                )
                continue
            assertion = assertion_entry[1]
            if assertion.get("subject") != {
                "entity_type": "jurisdiction",
                "entity_id": jurisdiction_id,
            }:
                problems.append(
                    ValidationProblem(
                        path,
                        f"{location}.assertion_id",
                        "territorial assertion subject does not match this jurisdiction",
                    )
                )
            if assertion.get("object") != {
                "entity_type": "jurisdiction",
                "entity_id": target_id,
            }:
                problems.append(
                    ValidationProblem(
                        path,
                        f"{location}.assertion_id",
                        "territorial assertion object does not match related_jurisdiction_id",
                    )
                )
            if assertion.get("predicate") not in {
                "territorially_within",
                "territorially_overlaps",
            }:
                problems.append(
                    ValidationProblem(
                        path,
                        f"{location}.assertion_id",
                        "territorial assertion predicate does not match a territorial reference",
                    )
                )

    authority_predicates = {
        "adopting": "adopted_by",
        "enacting": "enacted_by",
        "making": "made_by",
        "assenting": "assented_by",
        "issuing": "issued_by",
        "deciding": "decided_by",
        "publishing": "published_by",
        "administering": "administered_by",
        "consolidating": "consolidated_by",
        "translating": "translated_by",
        "custodian": "held_by_custodian",
    }
    captured_artifact_ids = official_capture_artifact_ids
    provenance_artifact_ids = official_provenance_artifact_ids

    # Jurisdiction labels are legal scope, not free metadata. Seed them only
    # from complete official captures whose independently reviewed source
    # manifest names the jurisdiction, then propagate the union through a
    # derivation only when every input has that reviewed provenance.
    artifact_jurisdiction_ids: dict[str, set[str]] = {}
    for _, capture in captures.values():
        artifact_id = capture.get("artifact_id")
        source_id = capture.get("source_id")
        source_entry = sources.get(source_id) if isinstance(source_id, str) else None
        if (
            isinstance(artifact_id, str)
            and artifact_id in captured_artifact_ids
            and source_entry is not None
        ):
            artifact_jurisdiction_ids.setdefault(artifact_id, set()).update(
                jurisdiction_id
                for jurisdiction_id in _list_or_empty(
                    source_entry[1].get("jurisdiction_ids")
                )
                if isinstance(jurisdiction_id, str)
            )
    jurisdiction_provenance_changed = True
    while jurisdiction_provenance_changed:
        jurisdiction_provenance_changed = False
        for _, derivation in derivations.values():
            output_artifact_id = derivation.get("output_artifact_id")
            input_artifact_ids = {
                item.get("artifact_id")
                for item in _list_or_empty(derivation.get("input_artifacts"))
                if isinstance(item, dict) and isinstance(item.get("artifact_id"), str)
            }
            if (
                not isinstance(output_artifact_id, str)
                or not input_artifact_ids
                or not input_artifact_ids <= artifact_jurisdiction_ids.keys()
            ):
                continue
            propagated = set().union(
                *(artifact_jurisdiction_ids[item] for item in input_artifact_ids)
            )
            if not propagated <= artifact_jurisdiction_ids.get(
                output_artifact_id, set()
            ):
                artifact_jurisdiction_ids.setdefault(output_artifact_id, set()).update(
                    propagated
                )
                jurisdiction_provenance_changed = True

    derivations_by_output = {
        derivation.get("output_artifact_id"): derivation
        for _, derivation in derivations.values()
        if isinstance(derivation.get("output_artifact_id"), str)
    }

    def observation_evidence_problems(
        path: Path,
        location: str,
        entity: dict[str, Any],
    ) -> list[ValidationProblem]:
        time_axes = entity.get("time_axes")
        observation = (
            time_axes.get("observation") if isinstance(time_axes, dict) else None
        )
        observation_bounds = (
            _temporal_point_bounds(observation)
            if isinstance(observation, dict)
            else None
        )
        if observation_bounds is None:
            return []
        evidence_times: list[datetime] = []
        artifact_ids: set[str] = set()
        capture_ids: set[str] = set()
        for nested_location, value in _walk(entity):
            if nested_location and nested_location[0] == "time_axes":
                continue
            if isinstance(value, dict):
                artifact_id = value.get("artifact_id")
                capture_id = value.get("capture_id")
                if isinstance(artifact_id, str):
                    artifact_ids.add(artifact_id)
                if isinstance(capture_id, str):
                    capture_ids.add(capture_id)
                for field in ("created_at", "reviewed_at"):
                    timestamp = value.get(field)
                    parsed = _parse_datetime(timestamp) if isinstance(timestamp, str) else None
                    if parsed is not None:
                        evidence_times.append(parsed)
        for artifact_id in _list_or_empty(entity.get("artifact_ids")):
            if isinstance(artifact_id, str):
                artifact_ids.add(artifact_id)
        content_artifact_id = entity.get("content_artifact_id")
        if isinstance(content_artifact_id, str):
            artifact_ids.add(content_artifact_id)
        for artifact_id in artifact_ids:
            artifact_entry = artifacts.get(artifact_id)
            artifact_time = (
                _parse_datetime(artifact_entry[1].get("created_at"))
                if artifact_entry is not None
                and isinstance(artifact_entry[1].get("created_at"), str)
                else None
            )
            if artifact_time is not None:
                evidence_times.append(artifact_time)
            derivation = derivations_by_output.get(artifact_id)
            derivation_time = (
                _parse_datetime(derivation.get("created_at"))
                if isinstance(derivation, dict)
                and isinstance(derivation.get("created_at"), str)
                else None
            )
            if derivation_time is not None:
                evidence_times.append(derivation_time)
        for capture_id in capture_ids:
            capture_entry = captures.get(capture_id)
            retrieval = (
                capture_entry[1].get("retrieval")
                if capture_entry is not None
                else None
            )
            retrieval_time = (
                _parse_datetime(retrieval.get("retrieved_at"))
                if isinstance(retrieval, dict)
                and isinstance(retrieval.get("retrieved_at"), str)
                else None
            )
            if retrieval_time is not None:
                evidence_times.append(retrieval_time)
        if evidence_times and observation_bounds[0] < max(evidence_times):
            return [
                ValidationProblem(
                    path,
                    f"{location}.time_axes.observation",
                    "observation cannot predate the latest selected evidence, derivation, or normalization review",
                )
            ]
        return []

    for assertion_id, (assertion_path, assertion) in assertions.items():
        problems.extend(
            observation_evidence_problems(
                assertion_path,
                "$",
                assertion,
            )
        )

    transition_predicates = VERSION_TRANSITION_PREDICATES

    def validate_derivation_assertions(
        owner_path: Path,
        base_location: str,
        assertion_ids: Any,
        owner_type: str,
        owner_id: Any,
        owner_time_axes: Any,
        required_jurisdiction_ids: set[str],
        provision_id: str | None = None,
    ) -> None:
        """Require every declared history edge to be reviewed and owner-specific."""

        if not isinstance(assertion_ids, list) or not isinstance(owner_id, str):
            return
        owner_observation = (
            owner_time_axes.get("observation")
            if isinstance(owner_time_axes, dict)
            else None
        )
        owner_observation_bounds = (
            _temporal_point_bounds(owner_observation)
            if isinstance(owner_observation, dict)
            else None
        )
        owner_observation_instant = (
            owner_observation_bounds[0]
            if owner_observation_bounds is not None
            else None
        )
        for index, assertion_id in enumerate(assertion_ids):
            location = f"{base_location}[{index}]"
            assertion_entry = (
                assertions.get(assertion_id) if isinstance(assertion_id, str) else None
            )
            if assertion_entry is None:
                continue
            assertion = assertion_entry[1]
            if assertion.get("status") not in {"verified", "superseded"}:
                problems.append(
                    ValidationProblem(
                        owner_path,
                        location,
                        "a derivation assertion must be independently reviewed as verified or superseded",
                    )
                )
            endpoints = {
                key
                for endpoint in (assertion.get("subject"), assertion.get("object"))
                if (key := _entity_reference_key(endpoint)) is not None
            }
            if (owner_type, owner_id) not in endpoints:
                problems.append(
                    ValidationProblem(
                        owner_path,
                        location,
                        "a derivation assertion must concern the exact version state that declares it",
                    )
                )
            if assertion.get("predicate") not in transition_predicates:
                problems.append(
                    ValidationProblem(
                        owner_path,
                        location,
                        "a derivation assertion must use a legal version-transition predicate",
                    )
                )
            scope = assertion.get("scope")
            extent = scope.get("extent") if isinstance(scope, dict) else None
            targets = {
                item
                for item in _list_or_empty(
                    scope.get("target_provision_ids")
                    if isinstance(scope, dict)
                    else None
                )
                if isinstance(item, str)
            }
            extent_covers = extent == "whole_entity" or (
                provision_id is not None
                and extent == "selected_provisions"
                and provision_id in targets
            )
            scope_jurisdictions = {
                item
                for item in _list_or_empty(
                    scope.get("jurisdiction_ids") if isinstance(scope, dict) else None
                )
                if isinstance(item, str)
            }
            if not extent_covers or not required_jurisdiction_ids <= scope_jurisdictions:
                problems.append(
                    ValidationProblem(
                        owner_path,
                        location,
                        "a derivation assertion scope must cover the exact version extent and all record jurisdictions",
                    )
                )
            assertion_time_axes = assertion.get("time_axes")
            assertion_observation = (
                assertion_time_axes.get("observation")
                if isinstance(assertion_time_axes, dict)
                else None
            )
            assertion_publication = (
                assertion_time_axes.get("publication")
                if isinstance(assertion_time_axes, dict)
                else None
            )
            reviewed_at = (
                _parse_datetime(assertion.get("reviewed_at"))
                if isinstance(assertion.get("reviewed_at"), str)
                else None
            )
            if (
                not isinstance(assertion_publication, dict)
                or assertion_publication.get("status") not in {"exact", "approximate"}
                or not _temporal_point_not_after(
                    assertion_observation, owner_observation
                )
                or reviewed_at is None
                or owner_observation_instant is None
                or reviewed_at > owner_observation_instant
            ):
                problems.append(
                    ValidationProblem(
                        owner_path,
                        location,
                        "a derivation assertion must have a source-bound publication time and be observed and reviewed by the owning version observation",
                    )
                )
    legal_axis_predicates = {
        "effectiveness": {
            "amends",
            "commences",
            "corrects",
            "expires",
            "inserts",
            "invalidates",
            "limits",
            "renumbers",
            "repeals",
            "revives",
            "stays",
            "substitutes",
            "supersedes",
        },
        "applicability": {
            "applies",
            "distinguishes",
            "extends",
            "implements",
            "interprets",
            "invalidates",
            "limits",
            "overrules",
            "stays",
        },
    }

    def transition_is_asserted(
        current_type: str,
        current_id: str,
        predecessor_id: str,
        assertion_ids: Any,
        required_jurisdiction_ids: set[str],
        owner_time_axes: Any,
        provision_id: str | None = None,
    ) -> bool:
        if not isinstance(assertion_ids, list):
            return False

        owner_observation = (
            owner_time_axes.get("observation")
            if isinstance(owner_time_axes, dict)
            else None
        )
        owner_observation_bounds = (
            _temporal_point_bounds(owner_observation)
            if isinstance(owner_observation, dict)
            else None
        )
        owner_observation_instant = (
            owner_observation_bounds[0]
            if owner_observation_bounds is not None
            else None
        )
        for assertion_id in assertion_ids:
            assertion_entry = (
                assertions.get(assertion_id)
                if isinstance(assertion_id, str)
                else None
            )
            if assertion_entry is None:
                continue
            assertion = assertion_entry[1]
            if (
                assertion.get("subject")
                != {"entity_type": current_type, "entity_id": current_id}
                or assertion.get("object")
                != {"entity_type": current_type, "entity_id": predecessor_id}
                or assertion.get("predicate") not in transition_predicates
                or assertion.get("status") not in {"verified", "superseded"}
            ):
                continue
            scope = assertion.get("scope")
            if not isinstance(scope, dict):
                continue
            scope_jurisdictions = {
                jurisdiction_id
                for jurisdiction_id in _list_or_empty(scope.get("jurisdiction_ids"))
                if isinstance(jurisdiction_id, str)
            }
            if not required_jurisdiction_ids <= scope_jurisdictions:
                continue
            extent = scope.get("extent")
            if current_type == "version":
                if extent != "whole_entity":
                    continue
            elif current_type == "provision_version":
                targets = {
                    target
                    for target in _list_or_empty(scope.get("target_provision_ids"))
                    if isinstance(target, str)
                }
                if extent != "whole_entity" and not (
                    extent == "selected_provisions"
                    and isinstance(provision_id, str)
                    and provision_id in targets
                ):
                    continue
            assertion_time_axes = assertion.get("time_axes")
            assertion_observation = (
                assertion_time_axes.get("observation")
                if isinstance(assertion_time_axes, dict)
                else None
            )
            if not _temporal_point_not_after(
                assertion_observation, owner_observation
            ):
                continue
            reviewed_at = (
                _parse_datetime(assertion.get("reviewed_at"))
                if isinstance(assertion.get("reviewed_at"), str)
                else None
            )
            if (
                reviewed_at is None
                or owner_observation_instant is None
                or reviewed_at > owner_observation_instant
            ):
                continue
            clocks_compatible = True
            for axis_name in ("effectiveness", "applicability"):
                owner_interval = (
                    owner_time_axes.get(axis_name)
                    if isinstance(owner_time_axes, dict)
                    else None
                )
                if isinstance(owner_interval, dict) and owner_interval.get(
                    "status"
                ) in {"known", "open_ended"}:
                    assertion_interval = (
                        assertion_time_axes.get(axis_name)
                        if isinstance(assertion_time_axes, dict)
                        else None
                    )
                    if not _temporal_intervals_overlap(
                        owner_interval, assertion_interval
                    ):
                        clocks_compatible = False
                        break
            if clocks_compatible:
                return True
        return False

    def validate_legal_axis_basis(
        path: Path,
        location: str,
        axis_name: str,
        interval: Any,
        direct_owner_refs: set[tuple[str, str]],
        container_refs: set[tuple[str, str]],
        provision_id: str | None,
        required_jurisdiction_ids: set[str],
        owner_time_axes: Any,
    ) -> None:
        if (
            not isinstance(interval, dict)
            or interval.get("status") not in {"known", "open_ended"}
        ):
            return
        assertion_ids = interval.get("basis_assertion_ids")
        if not isinstance(assertion_ids, list) or not assertion_ids:
            problems.append(
                ValidationProblem(
                    path,
                    f"{location}.{axis_name}.basis_assertion_ids",
                    "a known legal interval requires at least one reviewed basis assertion",
                )
            )
            return
        claimed_interval = {
            key: value
            for key, value in interval.items()
            if key != "basis_assertion_ids"
        }
        covered_jurisdictions: set[str] = set()
        for assertion_index, assertion_id in enumerate(assertion_ids):
            assertion_location = (
                f"{location}.{axis_name}.basis_assertion_ids[{assertion_index}]"
            )
            assertion_entry = (
                assertions.get(assertion_id) if isinstance(assertion_id, str) else None
            )
            if assertion_entry is None:
                problems.append(
                    ValidationProblem(
                        path,
                        assertion_location,
                        "legal-status basis assertion does not resolve",
                    )
                )
                continue
            assertion = assertion_entry[1]
            basis_is_valid = True
            if assertion.get("status") not in {"verified", "superseded"}:
                basis_is_valid = False
                problems.append(
                    ValidationProblem(
                        path,
                        assertion_location,
                        "a known legal interval requires a reviewed verified or superseded basis assertion",
                    )
                )
            owner_observation = (
                owner_time_axes.get("observation")
                if isinstance(owner_time_axes, dict)
                else None
            )
            owner_observation_bounds = (
                _temporal_point_bounds(owner_observation)
                if isinstance(owner_observation, dict)
                else None
            )
            owner_observation_instant = (
                owner_observation_bounds[0]
                if owner_observation_bounds is not None
                else None
            )
            assertion_time_axes = assertion.get("time_axes")
            assertion_observation = (
                assertion_time_axes.get("observation")
                if isinstance(assertion_time_axes, dict)
                else None
            )
            reviewed_at = (
                _parse_datetime(assertion.get("reviewed_at"))
                if isinstance(assertion.get("reviewed_at"), str)
                else None
            )
            if (
                not _temporal_point_not_after(
                    assertion_observation, owner_observation
                )
                or reviewed_at is None
                or owner_observation_instant is None
                or reviewed_at > owner_observation_instant
            ):
                basis_is_valid = False
                problems.append(
                    ValidationProblem(
                        path,
                        assertion_location,
                        "legal-status basis assertion was not observed and independently reviewed by the owning record observation time",
                    )
                )
            if assertion.get("predicate") not in legal_axis_predicates[axis_name]:
                basis_is_valid = False
                problems.append(
                    ValidationProblem(
                        path,
                        assertion_location,
                        f"assertion predicate cannot establish {axis_name}",
                    )
                )
            assertion_interval = (
                assertion_time_axes.get(axis_name)
                if isinstance(assertion_time_axes, dict)
                else None
            )
            comparable_assertion_interval = (
                {
                    key: value
                    for key, value in assertion_interval.items()
                    if key != "basis_assertion_ids"
                }
                if isinstance(assertion_interval, dict)
                else None
            )
            if comparable_assertion_interval != claimed_interval:
                basis_is_valid = False
                problems.append(
                    ValidationProblem(
                        path,
                        assertion_location,
                        f"basis assertion {axis_name} interval does not match the record interval",
                    )
                )
            endpoints: set[tuple[str, str]] = set()
            for endpoint in (assertion.get("subject"), assertion.get("object")):
                if (
                    isinstance(endpoint, dict)
                    and isinstance(endpoint.get("entity_type"), str)
                    and isinstance(endpoint.get("entity_id"), str)
                ):
                    endpoints.add((endpoint["entity_type"], endpoint["entity_id"]))
            scope = assertion.get("scope")
            extent = scope.get("extent") if isinstance(scope, dict) else None
            targets = (
                scope.get("target_provision_ids") if isinstance(scope, dict) else None
            )
            selected_provision_applies = (
                provision_id is not None
                and extent == "selected_provisions"
                and isinstance(targets, list)
                and provision_id in targets
            )
            direct_applies = bool(endpoints & direct_owner_refs) and (
                extent == "whole_entity" or selected_provision_applies
            )
            container_applies = bool(endpoints & container_refs) and (
                extent == "whole_entity"
                or selected_provision_applies
            )
            if not direct_applies and not container_applies:
                basis_is_valid = False
                problems.append(
                    ValidationProblem(
                        path,
                        assertion_location,
                        "basis assertion scope does not cover the record or provision whose legal interval it supports",
                    )
                )
            scope_jurisdiction_ids = (
                scope.get("jurisdiction_ids") if isinstance(scope, dict) else None
            )
            if basis_is_valid and isinstance(scope_jurisdiction_ids, list):
                covered_jurisdictions.update(
                    jurisdiction_id
                    for jurisdiction_id in scope_jurisdiction_ids
                    if isinstance(jurisdiction_id, str)
                )
        missing_jurisdictions = sorted(
            required_jurisdiction_ids - covered_jurisdictions
        )
        if missing_jurisdictions:
            problems.append(
                ValidationProblem(
                    path,
                    f"{location}.{axis_name}.basis_assertion_ids",
                    "reviewed legal-status bases do not cover record jurisdictions: "
                    + ", ".join(missing_jurisdictions),
                )
            )

    def cyclic_nodes(
        edges: dict[str, set[str]],
    ) -> set[str]:
        """Return graph nodes participating in a directed cycle without recursion."""

        state: dict[str, int] = {}
        cycles: set[str] = set()
        for root in edges:
            if state.get(root, 0) != 0:
                continue
            path_nodes: list[str] = [root]
            active_index = {root: 0}
            state[root] = 1
            stack: list[tuple[str, Any]] = [(root, iter(edges.get(root, set())))]
            while stack:
                node, children = stack[-1]
                try:
                    child = next(children)
                except StopIteration:
                    stack.pop()
                    state[node] = 2
                    active_index.pop(node, None)
                    path_nodes.pop()
                    continue
                if child not in edges:
                    continue
                child_state = state.get(child, 0)
                if child_state == 0:
                    state[child] = 1
                    active_index[child] = len(path_nodes)
                    path_nodes.append(child)
                    stack.append((child, iter(edges.get(child, set()))))
                elif child_state == 1:
                    cycles.update(path_nodes[active_index[child] :])
        return cycles

    def reviewed_effective_window(
        assertion: dict[str, Any],
    ) -> tuple[datetime, datetime | None] | None:
        """Return a conservative half-open window for a reviewed relationship."""

        if assertion.get("status") not in {"verified", "superseded"}:
            return None
        time_axes = assertion.get("time_axes")
        interval = (
            time_axes.get("effectiveness") if isinstance(time_axes, dict) else None
        )
        if not isinstance(interval, dict) or interval.get("status") not in {
            "known",
            "open_ended",
        }:
            return None
        start = interval.get("start")
        start_bounds = (
            _temporal_point_bounds(start) if isinstance(start, dict) else None
        )
        if start_bounds is None:
            return None
        upper: datetime | None = None
        if interval.get("status") == "known":
            end = interval.get("end")
            end_bounds = (
                _temporal_point_bounds(end) if isinstance(end, dict) else None
            )
            if end_bounds is None:
                return None
            upper = (
                end_bounds[1]
                if interval.get("end_inclusive") is True
                else end_bounds[0]
            )
            if upper <= start_bounds[0]:
                return None
        return start_bounds[0], upper

    def time_aware_cyclic_nodes(
        nodes: Iterable[str],
        edges: list[tuple[str, str, datetime, datetime | None]],
    ) -> set[str]:
        """Detect cycles only where every reviewed edge is effective together."""

        cycles: set[str] = set()
        node_set = set(nodes)
        for instant in sorted({start for _, _, start, _ in edges}):
            active: dict[str, set[str]] = {node: set() for node in node_set}
            for source, target, start, end in edges:
                if start <= instant and (end is None or instant < end):
                    active.setdefault(source, set()).add(target)
            cycles.update(cyclic_nodes(active))
        return cycles

    authority_parent_edges: list[
        tuple[str, str, datetime, datetime | None]
    ] = []
    for authority_id, (_, authority) in authorities.items():
        for reference in _list_or_empty(authority.get("parent_relationships")):
            if not isinstance(reference, dict):
                continue
            target_id = reference.get("parent_authority_id")
            assertion_id = reference.get("assertion_id")
            assertion_entry = (
                assertions.get(assertion_id)
                if isinstance(assertion_id, str)
                else None
            )
            if (
                not isinstance(target_id, str)
                or assertion_entry is None
                or assertion_entry[1].get("predicate")
                != "institutionally_part_of"
            ):
                continue
            window = reviewed_effective_window(assertion_entry[1])
            if window is not None:
                authority_parent_edges.append(
                    (authority_id, target_id, window[0], window[1])
                )
    for authority_id in sorted(
        time_aware_cyclic_nodes(authorities, authority_parent_edges)
    ):
        problems.append(
            ValidationProblem(
                authorities[authority_id][0],
                "$.parent_relationships",
                f"authority parent hierarchy contains a cycle at {authority_id!r}",
            )
        )

    jurisdiction_within_edges: list[
        tuple[str, str, datetime, datetime | None]
    ] = []
    for jurisdiction_id, (_, jurisdiction) in jurisdictions.items():
        references = jurisdiction.get("territorial_relationships")
        for reference in references if isinstance(references, list) else []:
            if not isinstance(reference, dict):
                continue
            assertion_id = reference.get("assertion_id")
            assertion_entry = (
                assertions.get(assertion_id) if isinstance(assertion_id, str) else None
            )
            if (
                assertion_entry is not None
                and assertion_entry[1].get("predicate") == "territorially_within"
                and isinstance(reference.get("related_jurisdiction_id"), str)
            ):
                window = reviewed_effective_window(assertion_entry[1])
                if window is not None:
                    jurisdiction_within_edges.append(
                        (
                            jurisdiction_id,
                            reference["related_jurisdiction_id"],
                            window[0],
                            window[1],
                        )
                    )
    for jurisdiction_id in sorted(
        time_aware_cyclic_nodes(jurisdictions, jurisdiction_within_edges)
    ):
        problems.append(
            ValidationProblem(
                jurisdictions[jurisdiction_id][0],
                "$.territorial_relationships",
                f"territorial containment contains a cycle at {jurisdiction_id!r}",
            )
        )

    assertion_supersession_edges: dict[str, set[str]] = {}
    for assertion_id, (path, assertion) in assertions.items():
        supersedes = assertion.get("supersedes_assertion_ids")
        dispute_ids = assertion.get("disputes_assertion_ids")
        assertion_supersession_edges[assertion_id] = (
            {
                predecessor_id
                for predecessor_id in supersedes
                if isinstance(predecessor_id, str)
            }
            if isinstance(supersedes, list)
            else set()
        )
        for field, identities in (
            ("supersedes_assertion_ids", supersedes),
            ("disputes_assertion_ids", dispute_ids),
        ):
            for index, related_id in enumerate(
                identities if isinstance(identities, list) else []
            ):
                if related_id == assertion_id:
                    problems.append(
                        ValidationProblem(
                            path,
                            f"$.{field}[{index}]",
                            "an assertion may not supersede or dispute itself",
                        )
                    )
                elif isinstance(related_id, str) and related_id not in assertions:
                    problems.append(
                        ValidationProblem(
                            path,
                            f"$.{field}[{index}]",
                            "related assertion does not resolve",
                        )
                    )
                elif isinstance(related_id, str):
                    related_assertion = assertions[related_id][1]
                    if not _assertions_share_history_proposition(
                        assertion, related_assertion, field
                    ):
                        problems.append(
                            ValidationProblem(
                                path,
                                f"$.{field}[{index}]",
                                "assertion history edge must concern the same subject, object, predicate family, and overlapping scope",
                            )
                        )
                    assertion_time_axes = assertion.get("time_axes")
                    related_time_axes = related_assertion.get("time_axes")
                    assertion_observation = (
                        assertion_time_axes.get("observation")
                        if isinstance(assertion_time_axes, dict)
                        else None
                    )
                    related_observation = (
                        related_time_axes.get("observation")
                        if isinstance(related_time_axes, dict)
                        else None
                    )
                    if not _temporal_point_not_after(
                        related_observation, assertion_observation
                    ):
                        problems.append(
                            ValidationProblem(
                                path,
                                f"$.{field}[{index}]",
                                "an assertion cannot supersede or dispute an assertion first observed later",
                            )
                        )
    for assertion_id in sorted(cyclic_nodes(assertion_supersession_edges)):
        problems.append(
            ValidationProblem(
                assertions[assertion_id][0],
                "$.supersedes_assertion_ids",
                f"assertion supersession chain contains a cycle at {assertion_id!r}",
            )
        )

    for record_id, (path, record) in records.items():
        jurisdiction_ids = record.get("jurisdiction_ids")
        if isinstance(jurisdiction_ids, list):
            for index, jurisdiction_id in enumerate(jurisdiction_ids):
                if isinstance(jurisdiction_id, str) and jurisdiction_id not in jurisdictions:
                    problems.append(
                        ValidationProblem(
                            path,
                            f"$.jurisdiction_ids[{index}]",
                            "record jurisdiction does not resolve",
                        )
                    )

        relationships = record.get("authority_relationships")
        relationship_items = relationships if isinstance(relationships, list) else []
        for index, relationship in enumerate(relationship_items):
            if not isinstance(relationship, dict):
                continue
            authority_id = relationship.get("authority_id")
            assertion_id = relationship.get("assertion_id")
            role = relationship.get("role")
            location = f"$.authority_relationships[{index}]"
            if isinstance(authority_id, str) and authority_id not in authorities:
                problems.append(
                    ValidationProblem(
                        path,
                        f"{location}.authority_id",
                        "record authority does not resolve",
                    )
                )
            assertion_entry = assertions.get(assertion_id) if isinstance(assertion_id, str) else None
            if assertion_entry is None:
                if isinstance(assertion_id, str):
                    problems.append(
                        ValidationProblem(
                            path,
                            f"{location}.assertion_id",
                            "record authority assertion does not resolve",
                        )
                    )
                continue
            assertion = assertion_entry[1]
            expected_subject = {"entity_type": "record", "entity_id": record_id}
            expected_object = {"entity_type": "authority", "entity_id": authority_id}
            if assertion.get("subject") != expected_subject:
                problems.append(
                    ValidationProblem(
                        path,
                        f"{location}.assertion_id",
                        "authority assertion subject does not match this record",
                    )
                )
            if assertion.get("object") != expected_object:
                problems.append(
                    ValidationProblem(
                        path,
                        f"{location}.assertion_id",
                        "authority assertion object does not match authority_id",
                    )
                )
            if assertion.get("predicate") != authority_predicates.get(role):
                problems.append(
                    ValidationProblem(
                        path,
                        f"{location}.role",
                        "authority role does not match the referenced assertion predicate",
                    )
                )

        versions = record.get("versions")
        if not isinstance(versions, list):
            continue
        for version_index, version in enumerate(versions):
            if not isinstance(version, dict):
                continue
            version_id = version.get("version_id")
            version_observation_payload = dict(version)
            version_observation_payload.pop("provisions", None)
            problems.extend(
                observation_evidence_problems(
                    path,
                    f"$.versions[{version_index}]",
                    version_observation_payload,
                )
            )
            artifact_ids = version.get("artifact_ids")
            if isinstance(artifact_ids, list):
                for artifact_index, artifact_id in enumerate(artifact_ids):
                    if isinstance(artifact_id, str) and artifact_id not in artifacts:
                        problems.append(
                            ValidationProblem(
                                path,
                                f"$.versions[{version_index}].artifact_ids[{artifact_index}]",
                                "record version artifact does not resolve",
                            )
                        )
                    elif (
                        isinstance(artifact_id, str)
                        and artifact_id not in provenance_artifact_ids
                    ):
                        problems.append(
                            ValidationProblem(
                                path,
                                f"$.versions[{version_index}].artifact_ids[{artifact_index}]",
                                "record version artifact has no capture or derivation provenance",
                            )
                        )
                declared_record_jurisdictions = {
                    jurisdiction_id
                    for jurisdiction_id in _list_or_empty(jurisdiction_ids)
                    if isinstance(jurisdiction_id, str)
                }
                reviewed_artifact_jurisdictions: set[str] = set()
                record_evidence = _list_or_empty(record.get("metadata_evidence"))
                for binding in _list_or_empty(record.get("jurisdiction_bindings")):
                    if not isinstance(binding, dict):
                        continue
                    jurisdiction_id = binding.get("jurisdiction_id")
                    review = binding.get("normalization_review")
                    producer = binding.get("producer")
                    reviewer = review.get("reviewer") if isinstance(review, dict) else None
                    projection = dict(binding)
                    projected_review = dict(review) if isinstance(review, dict) else {}
                    projected_review.pop("reviewed_binding_digest", None)
                    projection["normalization_review"] = projected_review
                    try:
                        expected_binding_digest = hashlib.sha256(
                            _canonical_json_bytes(projection)
                        ).hexdigest()
                    except (TypeError, UnicodeEncodeError, ValueError):
                        expected_binding_digest = None
                    reviewed_digest = (
                        review.get("reviewed_binding_digest")
                        if isinstance(review, dict)
                        else None
                    )
                    independently_bound = (
                        isinstance(jurisdiction_id, str)
                        and isinstance(producer, dict)
                        and isinstance(producer.get("producer_id"), str)
                        and isinstance(reviewer, dict)
                        and reviewer.get("producer_type") == "human"
                        and isinstance(reviewer.get("producer_id"), str)
                        and not _same_producer_identity(producer, reviewer)
                        and isinstance(reviewed_digest, dict)
                        and reviewed_digest.get("value")
                        == expected_binding_digest
                    )
                    if not independently_bound:
                        continue
                    for evidence_index in _list_or_empty(
                        binding.get("evidence_indexes")
                    ):
                        if (
                            not isinstance(evidence_index, int)
                            or isinstance(evidence_index, bool)
                            or not 0 <= evidence_index < len(record_evidence)
                        ):
                            continue
                        citation = record_evidence[evidence_index]
                        evidence_artifact_id = (
                            citation.get("artifact_id")
                            if isinstance(citation, dict)
                            else None
                        )
                        if (
                            isinstance(evidence_artifact_id, str)
                            and evidence_artifact_id in artifact_ids
                            and jurisdiction_id
                            in artifact_jurisdiction_ids.get(
                                evidence_artifact_id, set()
                            )
                        ):
                            reviewed_artifact_jurisdictions.add(jurisdiction_id)
                unsupported_jurisdictions = sorted(
                    declared_record_jurisdictions
                    - reviewed_artifact_jurisdictions
                )
                if unsupported_jurisdictions:
                    problems.append(
                        ValidationProblem(
                            path,
                            f"$.versions[{version_index}].artifact_ids",
                            "record jurisdictions lack reviewed official-source provenance for this version: "
                            + ", ".join(unsupported_jurisdictions),
                        )
                    )
            version_relationships = version.get("authority_relationships")
            version_relationship_items = (
                version_relationships
                if isinstance(version_relationships, list)
                else []
            )
            has_verified_issuance = False
            for relationship_index, relationship in enumerate(
                version_relationship_items
            ):
                if not isinstance(relationship, dict):
                    continue
                location = (
                    f"$.versions[{version_index}].authority_relationships"
                    f"[{relationship_index}]"
                )
                authority_id = relationship.get("authority_id")
                assertion_id = relationship.get("assertion_id")
                role = relationship.get("role")
                authority_resolves = (
                    isinstance(authority_id, str) and authority_id in authorities
                )
                if isinstance(authority_id, str) and not authority_resolves:
                    problems.append(
                        ValidationProblem(
                            path,
                            f"{location}.authority_id",
                            "record-version authority does not resolve",
                        )
                    )
                assertion_entry = (
                    assertions.get(assertion_id)
                    if isinstance(assertion_id, str)
                    else None
                )
                if assertion_entry is None:
                    if isinstance(assertion_id, str):
                        problems.append(
                            ValidationProblem(
                                path,
                                f"{location}.assertion_id",
                                "record-version authority assertion does not resolve",
                            )
                        )
                    continue
                assertion = assertion_entry[1]
                subject_matches = assertion.get("subject") == {
                    "entity_type": "version",
                    "entity_id": version_id,
                }
                object_matches = assertion.get("object") == {
                    "entity_type": "authority",
                    "entity_id": authority_id,
                }
                predicate_matches = (
                    assertion.get("predicate") == authority_predicates.get(role)
                )
                if not subject_matches:
                    problems.append(
                        ValidationProblem(
                            path,
                            f"{location}.assertion_id",
                            "authority assertion subject does not match this record version",
                        )
                    )
                if not object_matches:
                    problems.append(
                        ValidationProblem(
                            path,
                            f"{location}.assertion_id",
                            "record-version authority assertion object does not match authority_id",
                        )
                    )
                if not predicate_matches:
                    problems.append(
                        ValidationProblem(
                            path,
                            f"{location}.role",
                            "record-version authority role does not match the referenced assertion predicate",
                        )
                    )
                producer = assertion.get("producer")
                reviewer = assertion.get("reviewer")
                independently_reviewed = (
                    assertion.get("status") == "verified"
                    and assertion.get("interpretation_level")
                    == "explicit_source_text"
                    and isinstance(assertion.get("reviewed_at"), str)
                    and _parse_datetime(assertion["reviewed_at"]) is not None
                    and isinstance(producer, dict)
                    and isinstance(producer.get("producer_id"), str)
                    and isinstance(reviewer, dict)
                    and isinstance(reviewer.get("producer_id"), str)
                    and not _same_producer_identity(producer, reviewer)
                )
                if (
                    role == "issuing"
                    and authority_resolves
                    and subject_matches
                    and object_matches
                    and predicate_matches
                    and independently_reviewed
                ):
                    has_verified_issuance = True
            if version.get("version_kind") == "official_translation":
                if not has_verified_issuance:
                    problems.append(
                        ValidationProblem(
                            path,
                            f"$.versions[{version_index}].authority_relationships",
                            "official_translation requires a verified, independently reviewed, version-specific issuing authority relationship",
                        )
                    )
                version_artifact_ids = {
                    artifact_id
                    for artifact_id in (
                        artifact_ids if isinstance(artifact_ids, list) else []
                    )
                    if isinstance(artifact_id, str)
                }
                if not version_artifact_ids.intersection(captured_artifact_ids):
                    problems.append(
                        ValidationProblem(
                            path,
                            f"$.versions[{version_index}].artifact_ids",
                            "official_translation requires at least one directly captured authority-issued artifact, not only project derivations",
                        )
                    )
            if version.get("version_kind") in {
                "unofficial_consolidation",
                "unofficial_translation",
            }:
                version_artifact_ids = {
                    artifact_id
                    for artifact_id in (
                        artifact_ids if isinstance(artifact_ids, list) else []
                    )
                    if isinstance(artifact_id, str)
                }
                if not version_artifact_ids.intersection(derivations_by_output):
                    problems.append(
                        ValidationProblem(
                            path,
                            f"$.versions[{version_index}].artifact_ids",
                            "an unofficial consolidation or translation requires an exact project derivation output",
                        )
                    )
            assertion_ids = version.get("derived_from_assertion_ids")
            if isinstance(assertion_ids, list):
                for assertion_index, assertion_id in enumerate(assertion_ids):
                    if isinstance(assertion_id, str) and assertion_id not in assertions:
                        problems.append(
                            ValidationProblem(
                                path,
                                f"$.versions[{version_index}].derived_from_assertion_ids[{assertion_index}]",
                                "record-version derivation assertion does not resolve",
                            )
                        )
            time_axes = version.get("time_axes")
            if isinstance(time_axes, dict):
                direct_owner_refs = (
                    {("version", version_id)}
                    if isinstance(version_id, str)
                    else set()
                )
                for axis_name in ("effectiveness", "applicability"):
                    validate_legal_axis_basis(
                        path,
                        f"$.versions[{version_index}].time_axes",
                        axis_name,
                        time_axes.get(axis_name),
                        direct_owner_refs,
                        {("record", record_id)},
                        None,
                        {
                            jurisdiction_id
                            for jurisdiction_id in _list_or_empty(jurisdiction_ids)
                            if isinstance(jurisdiction_id, str)
                        },
                        time_axes,
                    )
            validate_derivation_assertions(
                path,
                f"$.versions[{version_index}].derived_from_assertion_ids",
                assertion_ids,
                "version",
                version_id,
                time_axes,
                {
                    jurisdiction_id
                    for jurisdiction_id in _list_or_empty(jurisdiction_ids)
                    if isinstance(jurisdiction_id, str)
                },
            )
            predecessor_ids = version.get("supersedes_version_ids")
            if isinstance(predecessor_ids, list) and isinstance(version_id, str):
                for predecessor_index, predecessor_id in enumerate(predecessor_ids):
                    predecessor_entry = (
                        record_versions.get(predecessor_id)
                        if isinstance(predecessor_id, str)
                        else None
                    )
                    location = (
                        f"$.versions[{version_index}].supersedes_version_ids[{predecessor_index}]"
                    )
                    if predecessor_entry is None:
                        problems.append(
                            ValidationProblem(
                                path,
                                location,
                                "superseded record version does not resolve",
                            )
                        )
                    elif predecessor_entry[1] != record_id:
                        problems.append(
                            ValidationProblem(
                                path,
                                location,
                                "record version may supersede only a version of the same record",
                            )
                        )
                    else:
                        current_observation = (
                            time_axes.get("observation")
                            if isinstance(time_axes, dict)
                            else None
                        )
                        predecessor_time_axes = predecessor_entry[2].get("time_axes")
                        predecessor_observation = (
                            predecessor_time_axes.get("observation")
                            if isinstance(predecessor_time_axes, dict)
                            else None
                        )
                        if not _temporal_point_not_after(
                            predecessor_observation, current_observation
                        ):
                            problems.append(
                                ValidationProblem(
                                    path,
                                    location,
                                    "record version cannot supersede a predecessor first observed later",
                                )
                            )
                    if predecessor_id == version_id:
                        problems.append(
                            ValidationProblem(
                                path,
                                location,
                                "record version may not supersede itself",
                            )
                        )
                    elif isinstance(predecessor_id, str) and not transition_is_asserted(
                        "version",
                        version_id,
                        predecessor_id,
                        assertion_ids,
                        {
                            jurisdiction_id
                            for jurisdiction_id in _list_or_empty(jurisdiction_ids)
                            if isinstance(jurisdiction_id, str)
                        },
                        time_axes,
                    ):
                        problems.append(
                            ValidationProblem(
                                path,
                                location,
                                "record-version transition lacks a matching relationship assertion",
                            )
                        )

            provisions = version.get("provisions")
            if not isinstance(provisions, list):
                continue
            current_provision_ids = {
                item.get("provision_id")
                for item in provisions
                if isinstance(item, dict) and isinstance(item.get("provision_id"), str)
            }
            for provision_index, provision in enumerate(provisions):
                if not isinstance(provision, dict):
                    continue
                base_location = (
                    f"$.versions[{version_index}].provisions[{provision_index}]"
                )
                problems.extend(
                    observation_evidence_problems(
                        path,
                        base_location,
                        provision,
                    )
                )
                text_citations = provision.get("text_citations")
                for citation_index, citation in enumerate(
                    text_citations if isinstance(text_citations, list) else []
                ):
                    citation_artifact_id = (
                        citation.get("artifact_id") if isinstance(citation, dict) else None
                    )
                    if (
                        isinstance(citation_artifact_id, str)
                        and (
                            not isinstance(artifact_ids, list)
                            or citation_artifact_id not in artifact_ids
                        )
                    ):
                        problems.append(
                            ValidationProblem(
                                path,
                                f"{base_location}.text_citations[{citation_index}].artifact_id",
                                "provision text citation artifact must be listed on its record version",
                            )
                        )
                content_artifact_id = provision.get("content_artifact_id")
                if isinstance(content_artifact_id, str):
                    artifact_entry = artifacts.get(content_artifact_id)
                    if artifact_entry is None:
                        problems.append(
                            ValidationProblem(
                                path,
                                f"{base_location}.content_artifact_id",
                                "complete provision content artifact does not resolve",
                            )
                        )
                    elif artifact_entry[1].get("content_digest") != provision.get(
                        "content_digest"
                    ):
                        problems.append(
                            ValidationProblem(
                                path,
                                f"{base_location}.content_digest",
                                "complete provision digest does not match its content artifact",
                            )
                        )
                    if artifact_entry is not None:
                        provision_observation = provision.get("time_axes")
                        provision_observation = (
                            provision_observation.get("observation")
                            if isinstance(provision_observation, dict)
                            else None
                        )
                        observation_bounds = (
                            _temporal_point_bounds(provision_observation)
                            if isinstance(provision_observation, dict)
                            else None
                        )
                        observation_instant = (
                            observation_bounds[0]
                            if observation_bounds is not None
                            else None
                        )
                        has_exact_scope_attestation = False
                        for attestation in _list_or_empty(
                            artifact_entry[1].get("legal_scope_attestations")
                        ):
                            if not isinstance(attestation, dict):
                                continue
                            review = attestation.get("review")
                            producer = attestation.get("producer")
                            reviewer = (
                                review.get("reviewer")
                                if isinstance(review, dict)
                                else None
                            )
                            projection = dict(attestation)
                            projected_review = (
                                dict(review) if isinstance(review, dict) else {}
                            )
                            projected_review.pop(
                                "reviewed_attestation_digest", None
                            )
                            projection["review"] = projected_review
                            try:
                                expected_attestation_digest = hashlib.sha256(
                                    _canonical_json_bytes(projection)
                                ).hexdigest()
                            except (TypeError, UnicodeEncodeError, ValueError):
                                expected_attestation_digest = None
                            reviewed_digest = (
                                review.get("reviewed_attestation_digest")
                                if isinstance(review, dict)
                                else None
                            )
                            reviewed_at = (
                                _parse_datetime(review.get("reviewed_at"))
                                if isinstance(review, dict)
                                and isinstance(review.get("reviewed_at"), str)
                                else None
                            )
                            if (
                                attestation.get("record_id") == record_id
                                and attestation.get("version_id") == version_id
                                and attestation.get("provision_id")
                                == provision.get("provision_id")
                                and attestation.get("provision_version_id")
                                == provision.get("provision_version_id")
                                and attestation.get("scope")
                                == "complete_provision_text"
                                and attestation.get("content_digest")
                                == artifact_entry[1].get("content_digest")
                                and isinstance(producer, dict)
                                and isinstance(producer.get("producer_id"), str)
                                and isinstance(reviewer, dict)
                                and reviewer.get("producer_type") == "human"
                                and isinstance(reviewer.get("producer_id"), str)
                                and not _same_producer_identity(producer, reviewer)
                                and isinstance(reviewed_digest, dict)
                                and reviewed_digest.get("value")
                                == expected_attestation_digest
                                and reviewed_at is not None
                                and observation_instant is not None
                                and reviewed_at <= observation_instant
                            ):
                                has_exact_scope_attestation = True
                                break
                        if not has_exact_scope_attestation:
                            problems.append(
                                ValidationProblem(
                                    path,
                                    f"{base_location}.content_artifact_id",
                                    "complete provision text requires an exact independently reviewed artifact-scope attestation",
                                )
                            )
                    if content_artifact_id not in provenance_artifact_ids:
                        problems.append(
                            ValidationProblem(
                                path,
                                f"{base_location}.content_artifact_id",
                                "complete provision content artifact has no capture or derivation provenance",
                            )
                        )
                    if not isinstance(artifact_ids, list) or content_artifact_id not in artifact_ids:
                        problems.append(
                            ValidationProblem(
                                path,
                                f"{base_location}.content_artifact_id",
                                "complete provision content artifact must be listed on its record version",
                            )
                        )
                parent_id = provision.get("parent_provision_id")
                if isinstance(parent_id, str):
                    if parent_id not in entity_ids.get("provision", set()):
                        problems.append(
                            ValidationProblem(
                                path,
                                f"{base_location}.parent_provision_id",
                                "parent provision does not resolve",
                            )
                        )
                    elif parent_id not in current_provision_ids:
                        problems.append(
                            ValidationProblem(
                                path,
                                f"{base_location}.parent_provision_id",
                                "parent provision must exist in the same record version",
                            )
                        )
                    if parent_id == provision.get("provision_id"):
                        problems.append(
                            ValidationProblem(
                                path,
                                f"{base_location}.parent_provision_id",
                                "a provision may not be its own parent",
                            )
                        )
                provision_version_id = provision.get("provision_version_id")
                provision_assertion_ids = provision.get("derived_from_assertion_ids")
                if isinstance(provision_assertion_ids, list):
                    for assertion_index, assertion_id in enumerate(
                        provision_assertion_ids
                    ):
                        if isinstance(assertion_id, str) and assertion_id not in assertions:
                            problems.append(
                                ValidationProblem(
                                    path,
                                    f"{base_location}.derived_from_assertion_ids[{assertion_index}]",
                                    "provision-version derivation assertion does not resolve",
                                )
                            )
                predecessor_provision_ids = provision.get(
                    "predecessor_provision_version_ids"
                )
                if isinstance(predecessor_provision_ids, list) and isinstance(
                    provision_version_id, str
                ):
                    for predecessor_index, predecessor_id in enumerate(
                        predecessor_provision_ids
                    ):
                        predecessor_entry = (
                            provision_versions.get(predecessor_id)
                            if isinstance(predecessor_id, str)
                            else None
                        )
                        location = (
                            f"{base_location}.predecessor_provision_version_ids[{predecessor_index}]"
                        )
                        if predecessor_entry is None:
                            problems.append(
                                ValidationProblem(
                                    path,
                                    location,
                                    "predecessor provision version does not resolve",
                                )
                            )
                        elif predecessor_entry[1] != record_id:
                            problems.append(
                                ValidationProblem(
                                    path,
                                    location,
                                    "provision transition may reference only the same record",
                                )
                            )
                        elif predecessor_entry[3].get("provision_id") != provision.get(
                            "provision_id"
                        ):
                            problems.append(
                                ValidationProblem(
                                    path,
                                    location,
                                    "predecessor must be a version of the same stable provision",
                                )
                            )
                        else:
                            current_time_axes = provision.get("time_axes")
                            predecessor_time_axes = predecessor_entry[3].get(
                                "time_axes"
                            )
                            current_observation = (
                                current_time_axes.get("observation")
                                if isinstance(current_time_axes, dict)
                                else None
                            )
                            predecessor_observation = (
                                predecessor_time_axes.get("observation")
                                if isinstance(predecessor_time_axes, dict)
                                else None
                            )
                            if not _temporal_point_not_after(
                                predecessor_observation, current_observation
                            ):
                                problems.append(
                                    ValidationProblem(
                                        path,
                                        location,
                                        "provision version cannot name a predecessor first observed later",
                                    )
                                )
                        if predecessor_id == provision_version_id:
                            problems.append(
                                ValidationProblem(
                                    path,
                                    location,
                                    "provision version may not precede itself",
                                )
                            )
                        elif isinstance(
                            predecessor_id, str
                        ) and not transition_is_asserted(
                            "provision_version",
                            provision_version_id,
                            predecessor_id,
                            provision_assertion_ids,
                            {
                                jurisdiction_id
                                for jurisdiction_id in _list_or_empty(jurisdiction_ids)
                                if isinstance(jurisdiction_id, str)
                            },
                            provision.get("time_axes"),
                            provision.get("provision_id")
                            if isinstance(provision.get("provision_id"), str)
                            else None,
                        ):
                            problems.append(
                                ValidationProblem(
                                    path,
                                    location,
                                    "provision transition lacks a matching relationship assertion",
                                )
                            )

                provision_time_axes = provision.get("time_axes")
                if isinstance(provision_time_axes, dict):
                    provision_id = provision.get("provision_id")
                    direct_owner_refs = {
                        (entity_type, entity_id)
                        for entity_type, entity_id in (
                            ("provision", provision_id),
                            ("provision_version", provision_version_id),
                        )
                        if isinstance(entity_id, str)
                    }
                    container_refs = {("record", record_id)}
                    if isinstance(version_id, str):
                        container_refs.add(("version", version_id))
                    for axis_name in ("effectiveness", "applicability"):
                        validate_legal_axis_basis(
                            path,
                            f"{base_location}.time_axes",
                            axis_name,
                            provision_time_axes.get(axis_name),
                            direct_owner_refs,
                            container_refs,
                            provision_id if isinstance(provision_id, str) else None,
                            {
                                jurisdiction_id
                                for jurisdiction_id in _list_or_empty(jurisdiction_ids)
                                if isinstance(jurisdiction_id, str)
                            },
                            provision_time_axes,
                        )
                validate_derivation_assertions(
                    path,
                    f"{base_location}.derived_from_assertion_ids",
                    provision_assertion_ids,
                    "provision_version",
                    provision.get("provision_version_id"),
                    provision_time_axes,
                    {
                        jurisdiction_id
                        for jurisdiction_id in _list_or_empty(jurisdiction_ids)
                        if isinstance(jurisdiction_id, str)
                    },
                    provision.get("provision_id")
                    if isinstance(provision.get("provision_id"), str)
                    else None,
                )

            parent_edges = {
                item["provision_id"]: {item["parent_provision_id"]}
                if isinstance(item.get("parent_provision_id"), str)
                else set()
                for item in provisions
                if isinstance(item, dict) and isinstance(item.get("provision_id"), str)
            }
            for provision_id in sorted(cyclic_nodes(parent_edges)):
                problems.append(
                    ValidationProblem(
                        path,
                        f"$.versions[{version_index}].provisions",
                        f"provision parent hierarchy contains a cycle at {provision_id!r}",
                    )
                )

    version_edges = {
        version_id: {
            predecessor_id
            for predecessor_id in _list_or_empty(version.get("supersedes_version_ids"))
            if isinstance(predecessor_id, str)
        }
        for version_id, (_, _, version) in record_versions.items()
    }
    for version_id in sorted(cyclic_nodes(version_edges)):
        version_path = record_versions[version_id][0]
        problems.append(
            ValidationProblem(
                version_path,
                "$.versions",
                f"record-version supersession chain contains a cycle at {version_id!r}",
            )
        )

    provision_edges = {
        provision_version_id: {
            predecessor_id
            for predecessor_id in _list_or_empty(
                provision.get("predecessor_provision_version_ids")
            )
            if isinstance(predecessor_id, str)
        }
        for provision_version_id, (_, _, _, provision) in provision_versions.items()
    }
    for provision_version_id in sorted(cyclic_nodes(provision_edges)):
        provision_path = provision_versions[provision_version_id][0]
        problems.append(
            ValidationProblem(
                provision_path,
                "$.versions[*].provisions",
                "provision-version predecessor chain contains a cycle at "
                f"{provision_version_id!r}",
            )
        )

    for source_id, (path, source) in sources.items():
        for field, known, label in (
            ("authority_ids", authorities, "authority"),
            ("jurisdiction_ids", jurisdictions, "jurisdiction"),
        ):
            identities = source.get(field)
            if not isinstance(identities, list):
                continue
            for index, identity in enumerate(identities):
                if isinstance(identity, str) and identity not in known:
                    problems.append(
                        ValidationProblem(
                            path,
                            f"$.{field}[{index}]",
                            f"source manifest {label} does not resolve",
                        )
                    )

    for coverage_id, (path, coverage) in coverages.items():
        source_id = coverage.get("source_id")
        source_entry = sources.get(source_id) if isinstance(source_id, str) else None
        if source_entry is None:
            problems.append(
                ValidationProblem(
                    path,
                    "$.source_id",
                    f"coverage ledger {coverage_id!r} source manifest does not resolve",
                )
            )
            continue
        source = source_entry[1]
        entrypoints = source.get("entrypoints")
        source_entrypoints = {
            item["entrypoint_id"]: item
            for item in (entrypoints if isinstance(entrypoints, list) else [])
            if isinstance(item, dict)
            and isinstance(item.get("entrypoint_id"), str)
        }
        scope = coverage.get("declared_scope")
        scope_entrypoint_ids = (
            scope.get("entrypoint_ids") if isinstance(scope, dict) else None
        )
        declared_entrypoints = {
            item for item in scope_entrypoint_ids if isinstance(item, str)
        } if isinstance(scope_entrypoint_ids, list) else set()
        for index, entrypoint_id in enumerate(
            scope_entrypoint_ids if isinstance(scope_entrypoint_ids, list) else []
        ):
            if isinstance(entrypoint_id, str) and entrypoint_id not in source_entrypoints:
                problems.append(
                    ValidationProblem(
                        path,
                        f"$.declared_scope.entrypoint_ids[{index}]",
                        "coverage entrypoint does not resolve in its source manifest",
                    )
                )
        if coverage.get("status") == "covered_for_declared_scope":
            non_exhaustive = sorted(
                entrypoint_id
                for entrypoint_id in declared_entrypoints
                if source_entrypoints.get(entrypoint_id, {}).get("enumeration_scope")
                != "declared_exhaustive"
            )
            if non_exhaustive:
                problems.append(
                    ValidationProblem(
                        path,
                        "$.status",
                        "covered scope requires source entrypoints declared exhaustive: "
                        + ", ".join(non_exhaustive),
                    )
                )
        runs = coverage.get("enumeration_runs")
        if isinstance(runs, list):
            for index, run in enumerate(runs):
                if not isinstance(run, dict):
                    continue
                entrypoint_id = run.get("entrypoint_id")
                if isinstance(entrypoint_id, str) and entrypoint_id not in declared_entrypoints:
                    problems.append(
                        ValidationProblem(
                            path,
                            f"$.enumeration_runs[{index}].entrypoint_id",
                            "enumeration run is outside the declared coverage entrypoints",
                        )
                    )
                source_entrypoint = source_entrypoints.get(entrypoint_id)
                expected_group = (
                    source_entrypoint.get("independent_group")
                    if isinstance(source_entrypoint, dict)
                    else None
                )
                if isinstance(expected_group, str) and run.get("independent_group") != expected_group:
                    problems.append(
                        ValidationProblem(
                            path,
                            f"$.enumeration_runs[{index}].independent_group",
                            "enumeration run independent_group does not match its source entrypoint",
                        )
                    )
        if isinstance(scope, dict):
            for field in ("authority_ids", "jurisdiction_ids", "document_kinds", "languages"):
                declared = scope.get(field)
                source_values = source.get(field)
                if isinstance(declared, list) and isinstance(source_values, list):
                    outside = sorted(
                        str(value) for value in declared if value not in source_values
                    )
                    if outside:
                        problems.append(
                            ValidationProblem(
                                path,
                                f"$.declared_scope.{field}",
                                "coverage scope exceeds its source manifest for: "
                                + ", ".join(outside),
                            )
                        )
        supersedes_id = coverage.get("supersedes_coverage_id")
        if isinstance(supersedes_id, str):
            if supersedes_id == coverage_id:
                problems.append(
                    ValidationProblem(
                        path,
                        "$.supersedes_coverage_id",
                        "coverage ledger may not supersede itself",
                    )
                )

            elif supersedes_id not in coverages:
                problems.append(
                    ValidationProblem(
                        path,
                        "$.supersedes_coverage_id",
                        "superseded coverage ledger does not resolve",
                    )
                )
            else:
                predecessor = coverages[supersedes_id][1]
                generated_at = (
                    _parse_datetime(coverage.get("generated_at"))
                    if isinstance(coverage.get("generated_at"), str)
                    else None
                )
                predecessor_generated_at = (
                    _parse_datetime(predecessor.get("generated_at"))
                    if isinstance(predecessor.get("generated_at"), str)
                    else None
                )
                if (
                    generated_at is not None
                    and predecessor_generated_at is not None
                    and generated_at <= predecessor_generated_at
                ):
                    problems.append(
                        ValidationProblem(
                            path,
                            "$.generated_at",
                            "a coverage ledger must be generated after the ledger it supersedes",
                        )
                    )
                if coverage.get("source_id") != predecessor.get("source_id"):
                    problems.append(
                        ValidationProblem(
                            path,
                            "$.supersedes_coverage_id",
                            "coverage supersession must stay within one source manifest",
                        )
                    )
                if coverage.get("declared_scope") != predecessor.get("declared_scope"):
                    problems.append(
                        ValidationProblem(
                            path,
                            "$.supersedes_coverage_id",
                            "coverage supersession must preserve the exact declared scope",
                        )
                    )

    coverage_edges = {
        coverage_id: {supersedes_id}
        if isinstance((supersedes_id := coverage.get("supersedes_coverage_id")), str)
        else set()
        for coverage_id, (_, coverage) in coverages.items()
    }
    for coverage_id in sorted(cyclic_nodes(coverage_edges)):
        problems.append(
            ValidationProblem(
                coverages[coverage_id][0],
                "$.supersedes_coverage_id",
                f"coverage supersession chain contains a cycle at {coverage_id!r}",
            )
        )

    for capture_id, (path, capture) in captures.items():
        artifact_id = capture.get("artifact_id")
        artifact_entry = artifacts.get(artifact_id) if isinstance(artifact_id, str) else None
        if isinstance(artifact_id, str) and artifact_id not in artifacts:
            problems.append(
                ValidationProblem(
                    path,
                    "$.artifact_id",
                    f"capture {capture_id!r} references an unresolved artifact",
                )
            )
        retrieval = capture.get("retrieval")
        retrieved_at = (
            _parse_datetime(retrieval.get("retrieved_at"))
            if isinstance(retrieval, dict)
            and isinstance(retrieval.get("retrieved_at"), str)
            else None
        )
        capture_created_at = (
            _parse_datetime(capture.get("created_at"))
            if isinstance(capture.get("created_at"), str)
            else None
        )
        if (
            retrieved_at is not None
            and capture_created_at is not None
            and capture_created_at < retrieved_at
        ):
            problems.append(
                ValidationProblem(
                    path,
                    "$.created_at",
                    "capture creation cannot predate retrieval",
                )
            )
        artifact_created_at = (
            _parse_datetime(artifact_entry[1].get("created_at"))
            if artifact_entry is not None
            and isinstance(artifact_entry[1].get("created_at"), str)
            else None
        )
        if (
            artifact_created_at is not None
            and capture_created_at is not None
            and artifact_created_at > capture_created_at
        ):
            problems.append(
                ValidationProblem(
                    path,
                    "$.artifact_id",
                    "capture cannot reference an artifact created after the capture record",
                )
            )
        clearance = capture.get("publication_clearance")
        clearance_time = (
            _parse_datetime(clearance.get("reviewed_at"))
            if isinstance(clearance, dict)
            and isinstance(clearance.get("reviewed_at"), str)
            else None
        )
        if (
            clearance_time is not None
            and retrieved_at is not None
            and clearance_time < retrieved_at
        ):
            problems.append(
                ValidationProblem(
                    path,
                    "$.publication_clearance.reviewed_at",
                    "capture publication clearance cannot predate retrieval",
                )
            )
        source_id = capture.get("source_id")
        if isinstance(source_id, str) and source_id not in sources:
            problems.append(
                ValidationProblem(
                    path,
                    "$.source_id",
                    f"capture {capture_id!r} references an unresolved source manifest",
                )
            )

    artifact_inputs_by_output: dict[str, set[str]] = {}
    for _, derivation in derivations.values():
        output_id = derivation.get("output_artifact_id")
        inputs = derivation.get("input_artifacts")
        if not isinstance(output_id, str) or not isinstance(inputs, list):
            continue
        artifact_inputs_by_output.setdefault(output_id, set()).update(
            item["artifact_id"]
            for item in inputs
            if isinstance(item, dict) and isinstance(item.get("artifact_id"), str)
        )

    def artifact_depends_on(artifact_id: str, target_id: str) -> bool:
        pending = [artifact_id]
        visited: set[str] = set()
        while pending:
            candidate_id = pending.pop()
            if candidate_id == target_id:
                return True
            if candidate_id in visited:
                continue
            visited.add(candidate_id)
            pending.extend(artifact_inputs_by_output.get(candidate_id, set()))
        return False

    for derivation_id, (path, derivation) in derivations.items():
        output_id = derivation.get("output_artifact_id")
        derivation_created_at = (
            _parse_datetime(derivation.get("created_at"))
            if isinstance(derivation.get("created_at"), str)
            else None
        )
        if isinstance(output_id, str) and output_id not in artifacts:
            problems.append(
                ValidationProblem(
                    path,
                    "$.output_artifact_id",
                    f"derivation {derivation_id!r} output artifact does not resolve",
                )
            )
        output_entry = artifacts.get(output_id) if isinstance(output_id, str) else None
        output_created_at = (
            _parse_datetime(output_entry[1].get("created_at"))
            if output_entry is not None
            and isinstance(output_entry[1].get("created_at"), str)
            else None
        )
        if (
            output_created_at is not None
            and derivation_created_at is not None
            and output_created_at > derivation_created_at
        ):
            problems.append(
                ValidationProblem(
                    path,
                    "$.output_artifact_id",
                    "derivation output artifact cannot be created after the derivation record",
                )
            )
        inputs = derivation.get("input_artifacts")
        if isinstance(inputs, list):
            for index, item in enumerate(inputs):
                artifact_id = item.get("artifact_id") if isinstance(item, dict) else None
                if isinstance(artifact_id, str) and artifact_id not in artifacts:
                    problems.append(
                        ValidationProblem(
                            path,
                            f"$.input_artifacts[{index}].artifact_id",
                            "derivation input artifact does not resolve",
                        )
                    )
                input_entry = artifacts.get(artifact_id) if isinstance(artifact_id, str) else None
                input_created_at = (
                    _parse_datetime(input_entry[1].get("created_at"))
                    if input_entry is not None
                    and isinstance(input_entry[1].get("created_at"), str)
                    else None
                )
                if (
                    input_created_at is not None
                    and derivation_created_at is not None
                    and input_created_at > derivation_created_at
                ):
                    problems.append(
                        ValidationProblem(
                            path,
                            f"$.input_artifacts[{index}].artifact_id",
                            "derivation input artifact cannot be created after the derivation record",
                        )
                    )
                if (
                    isinstance(artifact_id, str)
                    and isinstance(output_id, str)
                    and artifact_depends_on(artifact_id, output_id)
                ):
                    problems.append(
                        ValidationProblem(
                            path,
                            f"$.input_artifacts[{index}].artifact_id",
                            "derivation provenance contains an artifact dependency cycle",
                        )
                    )
        settings_id = derivation.get("settings_artifact_id")
        settings_digest = derivation.get("settings_digest")
        if isinstance(settings_id, str):
            settings_entry = artifacts.get(settings_id)
            if settings_entry is None:
                problems.append(
                    ValidationProblem(
                        path,
                        "$.settings_artifact_id",
                        "derivation settings artifact does not resolve",
                    )
                )
            elif isinstance(settings_digest, dict):
                artifact_digest = settings_entry[1].get("content_digest")
                if artifact_digest != settings_digest:
                    problems.append(
                        ValidationProblem(
                            path,
                            "$.settings_digest",
                            "settings digest does not match the settings artifact",
                        )
                    )
            settings_created_at = (
                _parse_datetime(settings_entry[1].get("created_at"))
                if settings_entry is not None
                and isinstance(settings_entry[1].get("created_at"), str)
                else None
            )
            if (
                settings_created_at is not None
                and derivation_created_at is not None
                and settings_created_at > derivation_created_at
            ):
                problems.append(
                    ValidationProblem(
                        path,
                        "$.settings_artifact_id",
                        "derivation settings artifact cannot be created after the derivation record",
                    )
                )
            if settings_id == output_id:
                problems.append(
                    ValidationProblem(
                        path,
                        "$.settings_artifact_id",
                        "derivation settings artifact may not also be its output",
                    )
                )
        basis_capture_ids = derivation.get("rights_basis_capture_ids")
        if isinstance(basis_capture_ids, list):
            for index, capture_id in enumerate(basis_capture_ids):
                if isinstance(capture_id, str) and capture_id not in captures:
                    problems.append(
                        ValidationProblem(
                            path,
                            f"$.rights_basis_capture_ids[{index}]",
                            "derivation rights-basis capture does not resolve",
                        )
                    )
            basis_set = {
                capture_id
                for capture_id in basis_capture_ids
                if isinstance(capture_id, str)
            }
            if isinstance(inputs, list):
                for index, item in enumerate(inputs):
                    artifact_id = item.get("artifact_id") if isinstance(item, dict) else None
                    if isinstance(artifact_id, str) and not (
                        _artifact_rights_route_options(
                            artifact_id,
                            basis_set,
                            captures,
                            derivations,
                            rights_route_cache,
                        )
                    ):
                        problems.append(
                            ValidationProblem(
                                path,
                                f"$.input_artifacts[{index}].artifact_id",
                                "derivation rights-basis captures do not cover this input",
                            )
                        )

        clearance = derivation.get("publication_clearance")
        clearance_time = (
            _parse_datetime(clearance.get("reviewed_at"))
            if isinstance(clearance, dict)
            and isinstance(clearance.get("reviewed_at"), str)
            else None
        )
        if (
            clearance_time is not None
            and derivation_created_at is not None
            and clearance_time < derivation_created_at
        ):
            problems.append(
                ValidationProblem(
                    path,
                    "$.publication_clearance.reviewed_at",
                    "derivation publication clearance cannot predate its output",
                )
            )

    for snapshot_id, (path, snapshot) in snapshots.items():
        predecessor_id = snapshot.get("predecessor_snapshot_id")
        transition_event_id = snapshot.get("transition_event_id")
        if isinstance(predecessor_id, str) and predecessor_id not in snapshots:
            problems.append(
                ValidationProblem(
                    path,
                    "$.predecessor_snapshot_id",
                    f"snapshot {snapshot_id!r} predecessor does not resolve",
                )
            )
        elif isinstance(predecessor_id, str):
            predecessor = snapshots[predecessor_id][1]
            generated_at = (
                _parse_datetime(snapshot.get("generated_at"))
                if isinstance(snapshot.get("generated_at"), str)
                else None
            )
            predecessor_generated_at = (
                _parse_datetime(predecessor.get("generated_at"))
                if isinstance(predecessor.get("generated_at"), str)
                else None
            )
            if (
                generated_at is not None
                and predecessor_generated_at is not None
                and generated_at <= predecessor_generated_at
            ):
                problems.append(
                    ValidationProblem(
                        path,
                        "$.predecessor_snapshot_id",
                        "snapshot must be generated after its predecessor",
                    )
                )
        if predecessor_id == snapshot_id:
            problems.append(
                ValidationProblem(
                    path,
                    "$.predecessor_snapshot_id",
                    "snapshot may not name itself as predecessor",
                )
            )
        if isinstance(predecessor_id, str):
            transition_event_entry = (
                events.get(transition_event_id)
                if isinstance(transition_event_id, str)
                else None
            )
            if transition_event_entry is None:
                problems.append(
                    ValidationProblem(
                        path,
                        "$.transition_event_id",
                        "post-genesis snapshot transition event does not resolve",
                    )
                )
            else:
                transition_event = transition_event_entry[1]
                if (
                    transition_event.get("snapshot_before") != predecessor_id
                    or transition_event.get("snapshot_after") != snapshot_id
                ):
                    problems.append(
                        ValidationProblem(
                            path,
                            "$.transition_event_id",
                            "snapshot transition event does not bind its exact predecessor and resulting snapshot",
                )
            )

    genesis_snapshots = sorted(
        snapshot_id
        for snapshot_id, (_, snapshot) in snapshots.items()
        if not isinstance(snapshot.get("predecessor_snapshot_id"), str)
    )
    if snapshots and len(genesis_snapshots) != 1:
        problem_path = min((path for path, _ in snapshots.values()), key=str)
        problems.append(
            ValidationProblem(
                problem_path,
                "$",
                "a closed corpus must contain exactly one genesis snapshot; every other snapshot must remain on that event-bound lineage",
            )
        )

    for snapshot_id, (path, _) in snapshots.items():
        chain: set[str] = set()
        current_id: Any = snapshot_id
        while isinstance(current_id, str) and current_id in snapshots:
            if current_id in chain:
                problems.append(
                    ValidationProblem(
                        path,
                        "$.predecessor_snapshot_id",
                        "snapshot predecessor chain contains a cycle",
                    )
                )
                break
            chain.add(current_id)
            current_id = snapshots[current_id][1].get("predecessor_snapshot_id")

    for report_id, (path, report) in corrections.items():
        public_issue = report.get("public_issue")
        privacy_review = report.get("privacy_review")
        report_publication_at = max(
            (
                parsed
                for timestamp in (
                    public_issue.get("published_at")
                    if isinstance(public_issue, dict)
                    else None,
                    privacy_review.get("reviewed_at")
                    if isinstance(privacy_review, dict)
                    else None,
                )
                if isinstance(timestamp, str)
                and (parsed := _parse_datetime(timestamp)) is not None
            ),
            default=corpus_evaluation_at,
        )
        corpus_snapshot_id = report.get("corpus_snapshot_id")
        if isinstance(corpus_snapshot_id, str) and corpus_snapshot_id not in snapshots:
            problems.append(
                ValidationProblem(
                    path,
                    "$.corpus_snapshot_id",
                    "correction report corpus snapshot does not resolve",
                )
            )
        duplicate_id = report.get("duplicate_of_report_id")
        if isinstance(duplicate_id, str):
            if duplicate_id == report_id:
                problems.append(
                    ValidationProblem(
                        path,
                        "$.duplicate_of_report_id",
                        "a correction report may not duplicate itself",
                    )
                )
            elif duplicate_id not in corrections:
                problems.append(
                    ValidationProblem(
                        path,
                        "$.duplicate_of_report_id",
                        "duplicate correction report does not resolve",
                    )
                )
        for index, evidence in enumerate(
            _list_or_empty(report.get("public_evidence"))
        ):
            if not isinstance(evidence, dict):
                continue
            location = f"$.public_evidence[{index}]"
            source_id = evidence.get("source_id")
            capture_id = evidence.get("capture_id")
            artifact_id = evidence.get("artifact_id")
            public_excerpt = evidence.get("public_excerpt")
            if isinstance(public_excerpt, str):
                excerpt_digest = evidence.get("excerpt_digest")
                expected_excerpt_digest = hashlib.sha256(
                    public_excerpt.encode("utf-8")
                ).hexdigest()
                if (
                    not isinstance(excerpt_digest, dict)
                    or excerpt_digest.get("algorithm") != "sha256"
                    or excerpt_digest.get("value") != expected_excerpt_digest
                ):
                    problems.append(
                        ValidationProblem(
                            path,
                            f"{location}.excerpt_digest",
                            "public correction excerpt digest must equal the exact UTF-8 excerpt bytes",
                        )
                    )
                evidence_clearance = evidence.get("publication_clearance")
                expected_clearance_target = {
                    "entity": {"entity_type": "report", "entity_id": report_id},
                    "content_digest": excerpt_digest,
                    "source_url": evidence.get("official_url"),
                }
                if not _publication_clearance_is_valid(evidence_clearance) or (
                    isinstance(evidence_clearance, dict)
                    and evidence_clearance.get("reviewed_target")
                    != expected_clearance_target
                ):
                    problems.append(
                        ValidationProblem(
                            path,
                            f"{location}.publication_clearance",
                            "public correction excerpt requires privacy clearance bound to the exact excerpt, report, and source URL",
                        )
                    )
                if not isinstance(capture_id, str) or not isinstance(
                    artifact_id, str
                ):
                    problems.append(
                        ValidationProblem(
                            path,
                            f"{location}.public_excerpt",
                            "public correction excerpts require an exact verified capture route",
                        )
                    )
                else:
                    problems.extend(
                        _publication_capture_problems(
                            path,
                            artifact_id,
                            capture_id,
                            captures,
                            {"capture", "transcription", "redistribution"},
                            f"{location}.public_excerpt",
                            direct_capture=True,
                            evaluation_at=report_publication_at,
                        )
                    )
            if evidence.get("official_status") != "VERIFIED_OFFICIAL":
                continue
            source_entry = (
                sources.get(source_id) if isinstance(source_id, str) else None
            )
            capture_entry = (
                captures.get(capture_id) if isinstance(capture_id, str) else None
            )
            artifact_entry = (
                artifacts.get(artifact_id) if isinstance(artifact_id, str) else None
            )
            if source_entry is None or source_entry[1].get(
                "identity_state"
            ) != "reviewed":
                problems.append(
                    ValidationProblem(
                        path,
                        f"{location}.source_id",
                        "verified correction evidence requires a reviewed source manifest",
                    )
                )
            if capture_entry is None:
                problems.append(
                    ValidationProblem(
                        path,
                        f"{location}.capture_id",
                        "verified correction evidence capture does not resolve",
                    )
                )
            else:
                capture = capture_entry[1]
                retrieval = capture.get("retrieval")
                if capture.get("source_id") != source_id:
                    problems.append(
                        ValidationProblem(
                            path,
                            f"{location}.capture_id",
                            "verified correction evidence capture and source do not agree",
                        )
                    )
                if capture.get("source_status") != "verified_official":
                    problems.append(
                        ValidationProblem(
                            path,
                            f"{location}.capture_id",
                            "verified correction evidence requires a verified-official capture",
                        )
                    )
                if capture.get("artifact_id") != artifact_id:
                    problems.append(
                        ValidationProblem(
                            path,
                            f"{location}.artifact_id",
                            "verified correction evidence must cite the capture's exact artifact",
                        )
                    )
                if not _capture_http_succeeded(capture):
                    problems.append(
                        ValidationProblem(
                            path,
                            f"{location}.capture_id",
                            "verified correction evidence requires a complete HTTP 200 capture",
                        )
                    )
                if not isinstance(retrieval, dict) or evidence.get(
                    "official_url"
                ) != retrieval.get("source_url"):
                    problems.append(
                        ValidationProblem(
                            path,
                            f"{location}.official_url",
                            "verified correction evidence URL must equal the capture retrieval URL",
                        )
                    )
                if not isinstance(retrieval, dict) or evidence.get(
                    "retrieved_at"
                ) != retrieval.get("retrieved_at"):
                    problems.append(
                        ValidationProblem(
                            path,
                            f"{location}.retrieved_at",
                            "verified correction evidence time must equal the capture retrieval time",
                        )
                    )
            if artifact_entry is None:
                problems.append(
                    ValidationProblem(
                        path,
                        f"{location}.artifact_id",
                        "verified correction evidence artifact does not resolve",
                    )
                )
            elif evidence.get("content_digest") != artifact_entry[1].get(
                "content_digest"
            ):
                problems.append(
                    ValidationProblem(
                        path,
                        f"{location}.content_digest",
                        "verified correction evidence digest must equal the resolved artifact digest",
                    )
                )
        application = report.get("application")
        review_status = report.get("public_review_status")
        if isinstance(application, dict) and review_status not in {
            "APPLIED",
            "PROPAGATION_FAILED",
        }:
            problems.append(
                ValidationProblem(
                    path,
                    "$.application",
                    "application proof is allowed only for APPLIED or PROPAGATION_FAILED review states",
                )
            )
        if not isinstance(application, dict):
            continue
        event_id = application.get("invalidation_event_id")
        event_entry = events.get(event_id) if isinstance(event_id, str) else None
        if event_entry is None:
            problems.append(
                ValidationProblem(
                    path,
                    "$.application.invalidation_event_id",
                    "correction application invalidation event does not resolve",
                )
            )
            continue
        event = event_entry[1]
        event_time = (
            _parse_datetime(event.get("occurred_at"))
            if isinstance(event.get("occurred_at"), str)
            else None
        )

        report_verification = report.get("verification")
        report_verification_time = (
            _parse_datetime(report_verification.get("checked_at"))
            if isinstance(report_verification, dict)
            and isinstance(report_verification.get("checked_at"), str)
            else None
        )
        correction_prerequisites: list[tuple[str, datetime | None]] = [
            ("verification.checked_at", report_verification_time)
        ]
        for index, item in enumerate(_list_or_empty(report.get("public_evidence"))):
            if not isinstance(item, dict):
                continue
            retrieved_time = (
                _parse_datetime(item.get("retrieved_at"))
                if isinstance(item.get("retrieved_at"), str)
                else None
            )
            clearance = item.get("publication_clearance")
            clearance_time = (
                _parse_datetime(clearance.get("reviewed_at"))
                if isinstance(clearance, dict)
                and isinstance(clearance.get("reviewed_at"), str)
                else None
            )
            correction_prerequisites.extend(
                [
                    (f"public_evidence[{index}].retrieved_at", retrieved_time),
                    (
                        f"public_evidence[{index}].publication_clearance.reviewed_at",
                        clearance_time,
                    ),
                ]
            )
        privacy_review = report.get("privacy_review")
        privacy_review_time = (
            _parse_datetime(privacy_review.get("reviewed_at"))
            if isinstance(privacy_review, dict)
            and isinstance(privacy_review.get("reviewed_at"), str)
            else None
        )
        correction_prerequisites.append(
            ("privacy_review.reviewed_at", privacy_review_time)
        )
        if review_status in {"APPLIED", "PROPAGATION_FAILED"} and event_time is not None:
            for prerequisite_name, prerequisite_time in correction_prerequisites:
                if prerequisite_time is not None and event_time < prerequisite_time:
                    problems.append(
                        ValidationProblem(
                            path,
                            "$.application.invalidation_event_id",
                            "correction application invalidation event occurred_at "
                            f"cannot predate {prerequisite_name}",
                        )
                    )
        if event.get("snapshot_before") != corpus_snapshot_id:
            problems.append(
                ValidationProblem(
                    path,
                    "$.corpus_snapshot_id",
                    "an applied correction must be rebased and reverified against the invalidation event's before snapshot",
                )
            )
        cause = event.get("cause")
        report_ids = cause.get("correction_report_ids") if isinstance(cause, dict) else None
        if not isinstance(report_ids, list) or report_id not in report_ids:
            problems.append(
                ValidationProblem(
                    path,
                    "$.application.invalidation_event_id",
                    "application event cause does not name this correction report",
                )
            )
        merge_commit_url = application.get("merge_commit_url")
        if not isinstance(cause, dict) or cause.get("merge_commit_url") != merge_commit_url:
            problems.append(
                ValidationProblem(
                    path,
                    "$.application.merge_commit_url",
                    "application merge commit does not match the invalidation event cause",
                )
            )
        snapshot_after = application.get("snapshot_after")
        if snapshot_after not in snapshots:
            problems.append(
                ValidationProblem(
                    path,
                    "$.application.snapshot_after",
                    "correction application snapshot does not resolve",
                )
            )
        if event.get("snapshot_after") != snapshot_after:
            problems.append(
                ValidationProblem(
                    path,
                    "$.application.snapshot_after",
                    "application snapshot does not match the invalidation event",
                )
            )
        expected_propagation = {
            "APPLIED": "succeeded",
            "PROPAGATION_FAILED": "failed",
        }.get(review_status)
        if expected_propagation is not None and event.get("propagation_status") != expected_propagation:
            problems.append(
                ValidationProblem(
                    path,
                    "$.public_review_status",
                    f"{review_status} requires an invalidation event with propagation_status {expected_propagation!r}",
                )
            )

    correction_duplicate_edges = {
        report_id: {duplicate_id}
        if isinstance((duplicate_id := report.get("duplicate_of_report_id")), str)
        else set()
        for report_id, (_, report) in corrections.items()
    }
    for report_id in sorted(cyclic_nodes(correction_duplicate_edges)):
        problems.append(
            ValidationProblem(
                corrections[report_id][0],
                "$.duplicate_of_report_id",
                f"correction duplicate chain contains a cycle at {report_id!r}",
            )
        )

    incoming_assertion_history: dict[str, list[tuple[str, str]]] = {}
    for newer_id, (_, newer_assertion) in assertions.items():
        for relation_field in (
            "supersedes_assertion_ids",
            "disputes_assertion_ids",
        ):
            for older_id in _list_or_empty(newer_assertion.get(relation_field)):
                if isinstance(older_id, str):
                    incoming_assertion_history.setdefault(older_id, []).append(
                        (newer_id, relation_field)
                    )

    incoming_coverage_history: dict[str, list[str]] = {}
    for newer_id, (_, newer_coverage) in coverages.items():
        older_id = newer_coverage.get("supersedes_coverage_id")
        if isinstance(older_id, str):
            incoming_coverage_history.setdefault(older_id, []).append(newer_id)

    incoming_version_history: dict[str, list[str]] = {}
    for newer_id, (_, _, newer_version) in record_versions.items():
        for older_id in _list_or_empty(
            newer_version.get("supersedes_version_ids")
        ):
            if isinstance(older_id, str):
                incoming_version_history.setdefault(older_id, []).append(newer_id)

    incoming_provision_version_history: dict[str, list[str]] = {}
    for newer_id, (_, _, _, newer_provision) in provision_versions.items():
        for older_id in _list_or_empty(
            newer_provision.get("predecessor_provision_version_ids")
        ):
            if isinstance(older_id, str):
                incoming_provision_version_history.setdefault(
                    older_id, []
                ).append(newer_id)

    def bibliographic_values(
        entity_type: str, entity_id: str, field: str
    ) -> set[str]:
        """Return only whitelisted metadata values for one exact bundle subject."""

        if entity_id not in entity_ids.get(entity_type, set()):
            return set()
        if field == "entity_id":
            return {entity_id}
        if entity_type == "record" and entity_id in records:
            record = records[entity_id][1]
            if field in {"canonical_title", "record_kind"} and isinstance(
                record.get(field), str
            ):
                return {record[field]}
            if field == "identifier":
                return {
                    item["value"]
                    for item in _list_or_empty(record.get("identifiers"))
                    if isinstance(item, dict) and isinstance(item.get("value"), str)
                }
        if entity_type == "version" and entity_id in record_versions:
            version = record_versions[entity_id][2]
            if field == "language" and isinstance(version.get("language"), str):
                return {version["language"]}
        if entity_type == "provision_version" and entity_id in provision_versions:
            provision = provision_versions[entity_id][3]
            if field in {"designation", "heading"} and isinstance(
                provision.get(field), str
            ):
                return {provision[field]}
        if entity_type == "provision":
            # A stable provision has no version-independent designation or
            # heading. Those facts must name one exact provision_version.
            return set()
        if entity_type in {"authority", "jurisdiction"} and field == "name":
            entry = (
                authorities.get(entity_id)
                if entity_type == "authority"
                else jurisdictions.get(entity_id)
            )
            profile = entry[1] if entry is not None else {}
            return {
                name["text"]
                for name in _list_or_empty(profile.get("names"))
                if isinstance(name, dict) and isinstance(name.get("text"), str)
            }
        if entity_type == "assertion" and field == "predicate":
            assertion_entry = assertions.get(entity_id)
            predicate = (
                assertion_entry[1].get("predicate")
                if assertion_entry is not None
                else None
            )
            return {predicate} if isinstance(predicate, str) else set()
        return set()

    known_direct_quotes: dict[tuple[str, str, bytes], set[str]] = {}
    for _, document in documents:
        for _, value in _walk(document):
            key = _direct_citation_key(value)
            quoted_text = value.get("quoted_text") if isinstance(value, dict) else None
            if key is not None and isinstance(quoted_text, str):
                known_direct_quotes.setdefault(key, set()).add(quoted_text)

    for bundle_id, (path, bundle) in bundles.items():
        handling = bundle.get("handling")
        if not isinstance(handling, dict) or handling.get("persistence") != "public":
            problems.append(
                ValidationProblem(
                    path,
                    "$.handling.persistence",
                    "a closed public corpus may contain only independently cleared public evidence bundles",
                )
            )
        context = bundle.get("evaluation_context")
        corpus_snapshot = (
            context.get("corpus_snapshot") if isinstance(context, dict) else None
        )
        snapshot_id = (
            corpus_snapshot.get("snapshot_id")
            if isinstance(corpus_snapshot, dict)
            else None
        )
        snapshot_entry = snapshots.get(snapshot_id) if isinstance(snapshot_id, str) else None
        if snapshot_entry is None:
            problems.append(
                ValidationProblem(
                    path,
                    "$.evaluation_context.corpus_snapshot.snapshot_id",
                    f"evidence bundle {bundle_id!r} corpus snapshot does not resolve",
                )
            )
        elif corpus_snapshot.get("recorded_at") != snapshot_entry[1].get("generated_at"):
            problems.append(
                ValidationProblem(
                    path,
                    "$.evaluation_context.corpus_snapshot.recorded_at",
                    "bundle snapshot time does not match the resolved snapshot manifest",
                )
            )
        if isinstance(snapshot_id, str):
            lineage: list[str] = []
            seen_snapshot_ids: set[str] = set()
            cursor: str | None = snapshot_id
            while isinstance(cursor, str) and cursor not in seen_snapshot_ids:
                seen_snapshot_ids.add(cursor)
                lineage.append(cursor)
                snapshot_cursor_entry = snapshots.get(cursor)
                predecessor = (
                    snapshot_cursor_entry[1].get("predecessor_snapshot_id")
                    if snapshot_cursor_entry is not None
                    else None
                )
                cursor = predecessor if isinstance(predecessor, str) else None
            lineage_position = {
                lineage_snapshot_id: index
                for index, lineage_snapshot_id in enumerate(lineage)
            }
            successful_repairs = [
                repair
                for _, repair in events.values()
                if repair.get("propagation_status") == "succeeded"
                and isinstance(repair.get("snapshot_before"), str)
                and repair["snapshot_before"] in lineage_position
                and isinstance(repair.get("snapshot_after"), str)
                and repair["snapshot_after"] in lineage_position
            ]
            unresolved_snapshot_events: list[str] = []
            for event_id, (_, event) in events.items():
                if event.get("propagation_status") not in {"pending", "failed"}:
                    continue
                before_id = event.get("snapshot_before")
                if not isinstance(before_id, str) or before_id not in lineage_position:
                    continue
                event_time = (
                    _parse_datetime(event.get("occurred_at"))
                    if isinstance(event.get("occurred_at"), str)
                    else None
                )
                repaired = False
                for repair in successful_repairs:
                    repair_before = repair.get("snapshot_before")
                    repair_after = repair.get("snapshot_after")
                    repair_time = (
                        _parse_datetime(repair.get("occurred_at"))
                        if isinstance(repair.get("occurred_at"), str)
                        else None
                    )
                    if (
                        isinstance(repair_before, str)
                        and isinstance(repair_after, str)
                        and lineage_position[repair_before]
                        <= lineage_position[before_id]
                        and lineage_position[repair_after]
                        < lineage_position[repair_before]
                        and event_time is not None
                        and repair_time is not None
                        and repair_time > event_time
                    ):
                        repaired = True
                        break
                if not repaired:
                    unresolved_snapshot_events.append(event_id)
            unresolved_snapshot_events.sort()
            if unresolved_snapshot_events:
                problems.append(
                    ValidationProblem(
                        path,
                        "$.evaluation_context.corpus_snapshot.snapshot_id",
                        "bundle snapshot is blocked by pending or failed invalidation propagation: "
                        + ", ".join(unresolved_snapshot_events),
                    )
                )
        dependencies = bundle.get("dependencies")
        dependency_refs = {
            (item.get("entity_type"), item.get("entity_id"))
            for item in (dependencies if isinstance(dependencies, list) else [])
            if isinstance(item, dict)
            and isinstance(item.get("entity_type"), str)
            and isinstance(item.get("entity_id"), str)
        }
        expected_dependency_refs = set(dependency_refs)
        derivations_by_output: dict[str, set[str]] = {}
        for derivation_id, (_, derivation) in derivations.items():
            output_artifact_id = derivation.get("output_artifact_id")
            if isinstance(output_artifact_id, str):
                derivations_by_output.setdefault(output_artifact_id, set()).add(
                    derivation_id
                )
        captures_by_artifact: dict[str, set[str]] = {}
        for capture_id, (_, capture) in captures.items():
            captured_artifact_id = capture.get("artifact_id")
            if isinstance(captured_artifact_id, str):
                captures_by_artifact.setdefault(captured_artifact_id, set()).add(
                    capture_id
                )

        missing_dependency_reports: set[tuple[str, str, str]] = set()

        def require_dependency(entity_type: Any, entity_id: Any, location: str) -> None:
            if (
                not isinstance(entity_type, str)
                or not isinstance(entity_id, str)
            ):
                return
            reference = (entity_type, entity_id)
            expected_dependency_refs.add(reference)
            if reference in dependency_refs:
                return
            marker = (entity_type, entity_id, location)
            if marker in missing_dependency_reports:
                return
            missing_dependency_reports.add(marker)
            problems.append(
                ValidationProblem(
                    path,
                    location,
                    f"evidence bundle must explicitly depend on {entity_type} {entity_id!r}",
                )
            )

        def require_citation_dependencies(citations: Any) -> None:
            for citation in _list_or_empty(citations):
                if not isinstance(citation, dict):
                    continue
                artifact_id = citation.get("artifact_id")
                capture_id = citation.get("capture_id")
                require_dependency(
                    "artifact", artifact_id, "$.dependencies"
                )
                if isinstance(capture_id, str):
                    require_dependency("capture", capture_id, "$.dependencies")
                elif isinstance(artifact_id, str) and artifact_id in derivations_by_output:
                    candidate_ids = derivations_by_output[artifact_id]
                    selected_ids = {
                        derivation_id
                        for derivation_id in candidate_ids
                        if ("derivation", derivation_id) in dependency_refs
                    }
                    if len(selected_ids) == 1:
                        require_dependency(
                            "derivation", next(iter(selected_ids)), "$.dependencies"
                        )
                    elif not selected_ids and len(candidate_ids) == 1:
                        require_dependency(
                            "derivation", next(iter(candidate_ids)), "$.dependencies"
                        )
                    else:
                        problems.append(
                            ValidationProblem(
                                path,
                                "$.dependencies",
                                f"capture-less citation of derived artifact {artifact_id!r} must select exactly one producing derivation dependency",
                            )
                        )
                temporal_binding = citation.get("temporal_value_binding")
                if isinstance(temporal_binding, dict):
                    require_dependency(
                        "artifact",
                        temporal_binding.get("settings_artifact_id"),
                        "$.dependencies",
                    )

        def require_time_basis_dependencies(time_axes: Any) -> None:
            if not isinstance(time_axes, dict):
                return
            for _, value in _walk(time_axes):
                if not isinstance(value, dict):
                    continue
                for assertion_id in _list_or_empty(
                    value.get("basis_assertion_ids")
                ):
                    require_dependency(
                        "assertion", assertion_id, "$.dependencies"
                    )

        generated_at = (
            _parse_datetime(bundle.get("generated_at"))
            if isinstance(bundle.get("generated_at"), str)
            else None
        )
        public_release = (
            handling.get("public_release")
            if isinstance(handling, dict)
            else None
        )
        public_release_clearance = (
            public_release.get("publication_clearance")
            if isinstance(public_release, dict)
            else None
        )
        public_release_reviewed_at = (
            _parse_datetime(public_release_clearance.get("reviewed_at"))
            if isinstance(public_release_clearance, dict)
            and isinstance(public_release_clearance.get("reviewed_at"), str)
            else None
        )
        rights_evaluation_at = max(
            (
                value
                for value in (generated_at, public_release_reviewed_at)
                if value is not None
            ),
            default=None,
        )
        snapshot_generated_at = (
            _parse_datetime(snapshot_entry[1].get("generated_at"))
            if snapshot_entry is not None
            and isinstance(snapshot_entry[1].get("generated_at"), str)
            else None
        )

        def incoming_assertion_is_snapshot_visible(
            newer_id: str, older_id: str, relation_field: str
        ) -> bool:
            if snapshot_generated_at is None:
                return False
            newer_entry = assertions.get(newer_id)
            older_entry = assertions.get(older_id)
            if newer_entry is None or older_entry is None:
                return False
            newer = newer_entry[1]
            if newer.get("status") not in {
                "verified",
                "disputed",
                "superseded",
            } or not _assertions_share_history_proposition(
                newer, older_entry[1], relation_field
            ):
                return False
            created_at = (
                _parse_datetime(newer.get("created_at"))
                if isinstance(newer.get("created_at"), str)
                else None
            )
            reviewed_at = (
                _parse_datetime(newer.get("reviewed_at"))
                if isinstance(newer.get("reviewed_at"), str)
                else None
            )
            if (
                created_at is None
                or reviewed_at is None
                or created_at > snapshot_generated_at
                or reviewed_at > snapshot_generated_at
            ):
                return False
            time_axes = newer.get("time_axes")
            observation = (
                time_axes.get("observation")
                if isinstance(time_axes, dict)
                else None
            )
            snapshot_point = {
                "status": "exact",
                "value": snapshot_entry[1].get("generated_at"),
                "precision": "second",
                "calendar": "gregory",
            }
            return not _temporal_point_definitely_after(
                observation, snapshot_point
            )

        def legal_state_is_snapshot_visible(
            entity_type: str, entity_id: str
        ) -> bool:
            if snapshot_generated_at is None or snapshot_entry is None:
                return False
            if entity_type == "version":
                state_entry = record_versions.get(entity_id)
                record_id = state_entry[1] if state_entry is not None else None
                state = state_entry[2] if state_entry is not None else None
            elif entity_type == "provision_version":
                state_entry = provision_versions.get(entity_id)
                record_id = state_entry[1] if state_entry is not None else None
                state = state_entry[3] if state_entry is not None else None
            else:
                return False
            record_entry = records.get(record_id) if isinstance(record_id, str) else None
            record_updated_at = (
                _parse_datetime(record_entry[1].get("updated_at"))
                if record_entry is not None
                and isinstance(record_entry[1].get("updated_at"), str)
                else None
            )
            if record_updated_at is None or record_updated_at > snapshot_generated_at:
                return False
            time_axes = state.get("time_axes") if isinstance(state, dict) else None
            observation = (
                time_axes.get("observation") if isinstance(time_axes, dict) else None
            )
            snapshot_point = {
                "status": "exact",
                "value": snapshot_entry[1].get("generated_at"),
                "precision": "second",
                "calendar": "gregory",
            }
            return not _temporal_point_definitely_after(
                observation, snapshot_point
            )

        if (
            generated_at is not None
            and snapshot_generated_at is not None
            and generated_at < snapshot_generated_at
        ):
            problems.append(
                ValidationProblem(
                    path,
                    "$.generated_at",
                    "evidence bundle generation cannot predate its corpus snapshot",
                )
            )
        if snapshot_generated_at is not None:
            snapshot_availability_point = {
                "status": "exact",
                "value": snapshot_entry[1].get("generated_at"),
                "precision": "second",
                "calendar": "gregory",
            }

            def dependency_states(
                entity_type: Any, entity_id: Any
            ) -> list[dict[str, Any]]:
                if not isinstance(entity_type, str) or not isinstance(entity_id, str):
                    return []
                top_level_maps = {
                    "artifact": artifacts,
                    "assertion": assertions,
                    "authority": authorities,
                    "bundle": bundles,
                    "capture": captures,
                    "coverage": coverages,
                    "derivation": derivations,
                    "event": events,
                    "jurisdiction": jurisdictions,
                    "record": records,
                    "report": corrections,
                    "snapshot": snapshots,
                    "source": sources,
                }
                entry = top_level_maps.get(entity_type, {}).get(entity_id)
                if entry is not None:
                    return [entry[1]]
                if entity_type == "version":
                    version_entry = record_versions.get(entity_id)
                    return [version_entry[2]] if version_entry is not None else []
                if entity_type == "provision_version":
                    provision_entry = provision_versions.get(entity_id)
                    return [provision_entry[3]] if provision_entry is not None else []
                if entity_type == "provision":
                    return [
                        provision_entry[3]
                        for provision_entry in provision_versions.values()
                        if provision_entry[3].get("provision_id") == entity_id
                    ]
                nested_maps = {
                    "claim": claim_records,
                    "component": component_records,
                    "gap": gap_records,
                }
                nested_entry = nested_maps.get(entity_type, {}).get(entity_id)
                return [nested_entry[1]] if nested_entry is not None else []

            for dependency_index, dependency in enumerate(
                _list_or_empty(dependencies)
            ):
                if not isinstance(dependency, dict):
                    continue
                entity_type = dependency.get("entity_type")
                entity_id = dependency.get("entity_id")
                unavailable_locations = sorted(
                    {
                        location
                        for state in dependency_states(entity_type, entity_id)
                        for location in _dependency_availability_violations(
                            entity_type,
                            state,
                            snapshot_generated_at,
                            snapshot_availability_point,
                        )
                    }
                )
                if unavailable_locations:
                    problems.append(
                        ValidationProblem(
                            path,
                            f"$.dependencies[{dependency_index}]",
                            f"{entity_type} dependency {entity_id!r} contains state, evidence, observation, or review clocks unavailable at the selected corpus snapshot: "
                            + ", ".join(unavailable_locations),
                        )
                    )
        require_dependency(
            "snapshot",
            snapshot_id,
            "$.evaluation_context.corpus_snapshot.snapshot_id",
        )
        jurisdiction_ids = context.get("jurisdiction_ids") if isinstance(context, dict) else None
        for index, jurisdiction_id in enumerate(
            jurisdiction_ids if isinstance(jurisdiction_ids, list) else []
        ):
            require_dependency(
                "jurisdiction",
                jurisdiction_id,
                f"$.evaluation_context.jurisdiction_ids[{index}]",
            )

        citations = bundle.get("citations")
        citation_items = citations if isinstance(citations, list) else []
        for citation_index, citation in enumerate(citation_items):
            verification = (
                citation.get("content_verification")
                if isinstance(citation, dict)
                else None
            )
            verified_at = (
                _parse_datetime(verification.get("verified_at"))
                if isinstance(verification, dict)
                and isinstance(verification.get("verified_at"), str)
                else None
            )
            if (
                verified_at is not None
                and snapshot_generated_at is not None
                and verified_at > snapshot_generated_at
            ):
                problems.append(
                    ValidationProblem(
                        path,
                        f"$.citations[{citation_index}].content_verification.verified_at",
                        "bundle citation content verification was unavailable at the selected corpus snapshot",
                    )
                )
            if (
                verified_at is not None
                and generated_at is not None
                and verified_at > generated_at
            ):
                problems.append(
                    ValidationProblem(
                        path,
                        f"$.citations[{citation_index}].content_verification.verified_at",
                        "bundle citation content verification cannot postdate bundle generation",
                    )
                )
        bundle_handling = bundle.get("handling")
        is_public_bundle = (
            isinstance(bundle_handling, dict)
            and bundle_handling.get("persistence") == "public"
        )
        required_delivery_clearance_refs: set[tuple[str, str]] = set()
        required_delivery_rights_refs: set[tuple[str, str]] = set()
        public_derivation_routes: list[tuple[str, bool]] = []
        if is_public_bundle:
            for entity_type, entity_id in dependency_refs:
                if entity_type not in {"capture", "derivation"}:
                    continue
                required_delivery_clearance_refs.add((entity_type, entity_id))
                if entity_type == "derivation":
                    public_derivation_routes.append((entity_id, False))
        rights_uses_by_citation: dict[int, set[str]] = {}
        rights_uses_by_content = {
            "bibliographic_fact": set(),
            "source_excerpt": set(),
            "summary": {"summarisation"},
            "translation": {"translation"},
        }
        rights_claims = _list_or_empty(bundle.get("claims"))
        if is_public_bundle:
            for claim_index, claim in enumerate(rights_claims):
                if not isinstance(claim, dict):
                    continue
                content_use = claim.get("content_use")
                if content_use in {"summary", "translation"}:
                    claim_text = claim.get("claim_text")
                    for citation_index in _list_or_empty(
                        claim.get("citation_indexes")
                    ):
                        if not (
                            isinstance(citation_index, int)
                            and 0 <= citation_index < len(citation_items)
                            and isinstance(claim_text, str)
                        ):
                            continue
                        citation = citation_items[citation_index]
                        key = _direct_citation_key(citation)
                        if key is None:
                            continue
                        if any(
                            _has_material_verbatim_overlap(claim_text, quote)
                            for quote in known_direct_quotes.get(key, set())
                        ):
                            problems.append(
                                ValidationProblem(
                                    path,
                                    f"$.claims[{claim_index}].content_use",
                                    "a transformed claim reproduces known source text verbatim; classify copied text as source_excerpt",
                                )
                            )
                            break
                if content_use == "bibliographic_fact":
                    subjects = _list_or_empty(claim.get("subjects"))
                    facts = _list_or_empty(claim.get("bibliographic_facts"))
                    for fact_index, fact in enumerate(facts):
                        if not isinstance(fact, dict):
                            continue
                        subject_index = fact.get("subject_index")
                        field = fact.get("field")
                        value = fact.get("value")
                        if (
                            not isinstance(subject_index, int)
                            or not 0 <= subject_index < len(subjects)
                            or not isinstance(subjects[subject_index], dict)
                        ):
                            problems.append(
                                ValidationProblem(
                                    path,
                                    f"$.claims[{claim_index}].bibliographic_facts[{fact_index}].subject_index",
                                    "bibliographic fact does not select a claim subject",
                                )
                            )
                            continue
                        subject = subjects[subject_index]
                        allowed_values = (
                            bibliographic_values(
                                subject.get("entity_type"),
                                subject.get("entity_id"),
                                field,
                            )
                            if isinstance(subject.get("entity_type"), str)
                            and isinstance(subject.get("entity_id"), str)
                            and isinstance(field, str)
                            else set()
                        )
                        if not isinstance(value, str) or value not in allowed_values:
                            problems.append(
                                ValidationProblem(
                                    path,
                                    f"$.claims[{claim_index}].bibliographic_facts[{fact_index}].value",
                                    "bibliographic fact is not exact whitelisted metadata on its selected subject",
                                )
                            )
                if content_use == "other":
                    problems.append(
                        ValidationProblem(
                            path,
                            f"$.claims[{claim_index}].content_use",
                            "an unclassified content use cannot establish public-bundle rights",
                        )
                    )
                    continue
                required_uses = rights_uses_by_content.get(content_use)
                if required_uses is None:
                    continue
                cited_indexes = _list_or_empty(claim.get("citation_indexes"))
                for citation_index in cited_indexes:
                    if isinstance(citation_index, int) and 0 <= citation_index < len(
                        citation_items
                    ):
                        rights_uses_by_citation.setdefault(citation_index, set()).update(
                            required_uses
                        )
                if content_use == "source_excerpt" and not any(
                    isinstance(citation_index, int)
                    and 0 <= citation_index < len(citation_items)
                    and isinstance(citation_items[citation_index], dict)
                    and isinstance(citation_items[citation_index].get("quoted_text"), str)
                    for citation_index in cited_indexes
                ):
                    problems.append(
                        ValidationProblem(
                            path,
                            f"$.claims[{claim_index}].content_use",
                            "source_excerpt content use requires cited quoted_text",
                        )
                    )
        for citation_index, citation in enumerate(citation_items):
            if not isinstance(citation, dict):
                continue
            artifact_id = citation.get("artifact_id")
            capture_id = citation.get("capture_id")
            required_rights_uses = rights_uses_by_citation.get(citation_index, set())
            cited_content_uses = {
                claim.get("content_use")
                for claim in rights_claims
                if isinstance(claim, dict)
                and citation_index in _list_or_empty(claim.get("citation_indexes"))
                and isinstance(claim.get("content_use"), str)
            }
            requires_reuse_rights = any(
                content_use != "bibliographic_fact"
                for content_use in cited_content_uses
            )
            artifact_entry = (
                artifacts.get(artifact_id) if isinstance(artifact_id, str) else None
            )
            if is_public_bundle and artifact_entry is not None and artifact_entry[1].get(
                "availability"
            ) in {"quarantined", "removed_with_tombstone"}:
                problems.append(
                    ValidationProblem(
                        path,
                        f"$.citations[{citation_index}].artifact_id",
                        "a public bundle may not cite quarantined or removed artifact bytes",
                    )
                )
            if (
                is_public_bundle
                and isinstance(citation.get("quoted_text"), str)
                and not required_rights_uses
                and all(
                    not (
                        isinstance(claim, dict)
                        and citation_index in _list_or_empty(
                            claim.get("citation_indexes")
                        )
                        and claim.get("content_use") == "source_excerpt"
                    )
                    for claim in rights_claims
                )
            ):
                problems.append(
                    ValidationProblem(
                        path,
                        f"$.citations[{citation_index}].quoted_text",
                        "a public bibliographic-only citation cannot carry a source excerpt",
                    )
                )
            require_dependency(
                "artifact", artifact_id, f"$.citations[{citation_index}].artifact_id"
            )
            if isinstance(capture_id, str):
                require_dependency(
                    "capture", capture_id, f"$.citations[{citation_index}].capture_id"
                )
                if is_public_bundle:
                    required_delivery_clearance_refs.add(("capture", capture_id))
                    if requires_reuse_rights:
                        required_delivery_rights_refs.add(("capture", capture_id))
                capture_entry = captures.get(capture_id)
                if capture_entry is not None:
                    require_dependency(
                        "source",
                        capture_entry[1].get("source_id"),
                        f"$.citations[{citation_index}].capture_id",
                    )
                    if (
                        is_public_bundle
                        and not _publication_clearance_is_valid(
                            capture_entry[1].get("publication_clearance")
                        )
                    ):
                        problems.append(
                            ValidationProblem(
                                path,
                                f"$.citations[{citation_index}].capture_id",
                                "a public bundle may cite a source capture only after that capture is publication-cleared",
                            )
                        )
                    if is_public_bundle:
                        problems.extend(
                            _bundle_capture_deadline_problems(
                                path,
                                f"$.citations[{citation_index}]",
                                {capture_id},
                                captures,
                                generated_at,
                            )
                        )
                    if is_public_bundle and (
                        required_rights_uses
                        or any(
                            isinstance(claim, dict)
                            and citation_index
                            in _list_or_empty(claim.get("citation_indexes"))
                            and claim.get("content_use") == "source_excerpt"
                            for claim in rights_claims
                        )
                    ):
                        problems.extend(
                            _publication_capture_problems(
                                path,
                                artifact_id if isinstance(artifact_id, str) else "",
                                capture_id,
                                captures,
                                {
                                    "capture",
                                    "redistribution",
                                    *required_rights_uses,
                                },
                                f"$.citations[{citation_index}]",
                                direct_capture=True,
                                evaluation_at=rights_evaluation_at,
                            )
                        )
            elif isinstance(artifact_id, str) and artifact_id in derivations_by_output:
                declared_derivation_ids = {
                    entity_id
                    for entity_type, entity_id in dependency_refs
                    if entity_type == "derivation"
                }
                outer_derivation_ids = {
                    derivation_id
                    for derivation_id in derivations_by_output[artifact_id]
                    if derivation_id in declared_derivation_ids
                }
                if len(outer_derivation_ids) != 1:
                    problems.append(
                        ValidationProblem(
                            path,
                            f"$.citations[{citation_index}].artifact_id",
                            "a derived citation must explicitly depend on exactly one derivation that produced it",
                        )
                    )
                if is_public_bundle:
                    public_derivation_routes.extend(
                        (derivation_id, requires_reuse_rights)
                        for derivation_id in outer_derivation_ids
                    )
                if is_public_bundle:
                    problems.extend(
                        _derived_bundle_rights_problems(
                            path,
                            f"$.citations[{citation_index}]",
                            artifact_id,
                            outer_derivation_ids,
                            declared_derivation_ids,
                            required_rights_uses,
                            artifacts,
                            captures,
                            sources,
                            derivations,
                            rights_route_cache,
                            generated_at,
                            rights_evaluation_at,
                            require_reuse_rights=requires_reuse_rights,
                        )
                    )
            elif is_public_bundle and isinstance(artifact_id, str):
                problems.append(
                    ValidationProblem(
                        path,
                        f"$.citations[{citation_index}].artifact_id",
                        "a public citation artifact must resolve through an explicit capture or selected derivation route",
                    )
                )

        pending_public_derivations = list(public_derivation_routes)
        seen_public_derivations: set[tuple[str, bool]] = set()
        while pending_public_derivations:
            derivation_id, requires_reuse_rights = pending_public_derivations.pop()
            route_state = (derivation_id, requires_reuse_rights)
            if route_state in seen_public_derivations:
                continue
            seen_public_derivations.add(route_state)
            derivation_entry = derivations.get(derivation_id)
            if derivation_entry is None:
                continue
            required_delivery_clearance_refs.add(("derivation", derivation_id))
            derivation = derivation_entry[1]
            for rights_capture_id in _list_or_empty(
                derivation.get("rights_basis_capture_ids")
            ):
                if not isinstance(rights_capture_id, str):
                    continue
                required_delivery_clearance_refs.add(
                    ("capture", rights_capture_id)
                )
                if requires_reuse_rights:
                    required_delivery_rights_refs.add(
                        ("capture", rights_capture_id)
                    )
            for input_artifact in _list_or_empty(
                derivation.get("input_artifacts")
            ):
                input_artifact_id = (
                    input_artifact.get("artifact_id")
                    if isinstance(input_artifact, dict)
                    else None
                )
                if not isinstance(input_artifact_id, str):
                    continue
                candidate_routes = {
                    ("capture", capture_id)
                    for capture_id in captures_by_artifact.get(
                        input_artifact_id, set()
                    )
                } | {
                    ("derivation", nested_derivation_id)
                    for nested_derivation_id in derivations_by_output.get(
                        input_artifact_id, set()
                    )
                }
                for route_type, route_id in candidate_routes & dependency_refs:
                    if route_type == "capture":
                        required_delivery_clearance_refs.add(
                            ("capture", route_id)
                        )
                        if requires_reuse_rights:
                            required_delivery_rights_refs.add(
                                ("capture", route_id)
                            )
                    else:
                        pending_public_derivations.append(
                            (route_id, requires_reuse_rights)
                        )

        if is_public_bundle:
            problems.extend(
                _route_artifact_availability_problems(
                    path,
                    "$.handling.public_release.delivery_bases",
                    {
                        entity_id
                        for entity_type, entity_id in required_delivery_clearance_refs
                        if entity_type == "capture"
                    },
                    {
                        entity_id
                        for entity_type, entity_id in required_delivery_clearance_refs
                        if entity_type == "derivation"
                    },
                    artifacts,
                    captures,
                    derivations,
                )
            )
        problems.extend(
            _bundle_delivery_basis_problems(
                path,
                bundle,
                required_delivery_clearance_refs,
                required_delivery_rights_refs,
                captures,
                derivations,
                generated_at,
            )
        )

        claims = bundle.get("claims")
        claim_items = claims if isinstance(claims, list) else []
        unresolved_items = bundle.get("unresolved_items")
        unresolved = (
            [item for item in unresolved_items if isinstance(item, dict)]
            if isinstance(unresolved_items, list)
            else []
        )
        problems.extend(
            _bundle_context_problems(
                path,
                bundle,
                assertions,
                authorities,
                jurisdictions,
                records,
                record_versions,
                provision_versions,
                provision_records,
            )
        )

        def has_exact_assertion_blocker(assertion_id: str) -> bool:
            for item in unresolved:
                if (
                    item.get("kind") != "unverified_assertion"
                    or item.get("severity") != "blocking"
                ):
                    continue
                related = item.get("related_entities")
                references = {
                    (reference.get("entity_type"), reference.get("entity_id"))
                    for reference in related if isinstance(reference, dict)
                } if isinstance(related, list) else set()
                if ("assertion", assertion_id) in references:
                    return True
            return False

        conflicts = bundle.get("conflicts")
        conflict_items = conflicts if isinstance(conflicts, list) else []
        for claim_index, claim in enumerate(claim_items):
            if not isinstance(claim, dict):
                continue
            for subject_index, subject in enumerate(
                claim.get("subjects") if isinstance(claim.get("subjects"), list) else []
            ):
                if not isinstance(subject, dict):
                    continue
                require_dependency(
                    subject.get("entity_type"),
                    subject.get("entity_id"),
                    f"$.claims[{claim_index}].subjects[{subject_index}]",
                )
            for field in ("assertion_ids", "contrary_assertion_ids"):
                identities = claim.get(field)
                for assertion_index, assertion_id in enumerate(
                    identities if isinstance(identities, list) else []
                ):
                    location = f"$.claims[{claim_index}].{field}[{assertion_index}]"
                    require_dependency("assertion", assertion_id, location)
                    assertion_entry = (
                        assertions.get(assertion_id)
                        if isinstance(assertion_id, str)
                        else None
                    )
                    if field != "assertion_ids" or assertion_entry is None:
                        continue
                    assertion_status = assertion_entry[1].get("status")
                    if assertion_status in {"candidate", "retracted"}:
                        if (
                            bundle.get("status") != "INSUFFICIENT_COVERAGE"
                            or not has_exact_assertion_blocker(assertion_id)
                        ):
                            problems.append(
                                ValidationProblem(
                                    path,
                                    location,
                                    "a candidate or retracted supporting assertion requires INSUFFICIENT_COVERAGE and an exact blocking unverified_assertion",
                                )
                            )
                    elif assertion_status == "disputed" and not any(
                        assertion_id in _list_or_empty(conflict.get("assertion_ids"))
                        for conflict in conflict_items
                        if isinstance(conflict, dict)
                    ):
                        problems.append(
                            ValidationProblem(
                                path,
                                location,
                                "a disputed supporting assertion must appear in the bundle conflicts",
                            )
                        )

        for conflict_index, conflict in enumerate(conflict_items):
            if not isinstance(conflict, dict):
                continue
            conflict_assertion_ids = {
                assertion_id
                for assertion_id in _list_or_empty(conflict.get("assertion_ids"))
                if isinstance(assertion_id, str)
            }
            affected_conflict_claims = _affected_conflict_claims(
                claim_items, conflict_assertion_ids
            )
            for claim_index, claim in affected_conflict_claims:
                supporting, contrary = _claim_conflict_assertion_sets(claim)
                for supporting_id in sorted(supporting & conflict_assertion_ids):
                    supporting_entry = assertions.get(supporting_id)
                    if supporting_entry is None:
                        continue
                    for contrary_id in sorted(contrary & conflict_assertion_ids):
                        contrary_entry = assertions.get(contrary_id)
                        if contrary_entry is None:
                            continue
                        if not _assertions_form_a_conflict(
                            supporting_entry[1], contrary_entry[1]
                        ):
                            problems.append(
                                ValidationProblem(
                                    path,
                                    f"$.conflicts[{conflict_index}].assertion_ids",
                                    "conflict assertions "
                                    f"{supporting_id!r} and {contrary_id!r} for claim "
                                    f"{claim_index} lack a reviewed disputes_assertion_ids link "
                                    "or semantic incompatibility over the same proposition, "
                                    "predicate family, jurisdiction, scope, and time",
                                )
                            )
            if conflict.get("resolution_state") == "unresolved":
                for claim_index, claim in affected_conflict_claims:
                    claim_subjects = {
                        (subject["entity_type"], subject["entity_id"])
                        for subject in _list_or_empty(claim.get("subjects"))
                        if isinstance(subject, dict)
                        and isinstance(subject.get("entity_type"), str)
                        and isinstance(subject.get("entity_id"), str)
                        and subject.get("entity_type") != "assertion"
                    }
                    for assertion_id in sorted(conflict_assertion_ids):
                        assertion_entry = assertions.get(assertion_id)
                        if assertion_entry is None:
                            continue
                        assertion = assertion_entry[1]
                        endpoints = {
                            (endpoint["entity_type"], endpoint["entity_id"])
                            for endpoint in (
                                assertion.get("subject"),
                                assertion.get("object"),
                            )
                            if isinstance(endpoint, dict)
                            and isinstance(endpoint.get("entity_type"), str)
                            and isinstance(endpoint.get("entity_id"), str)
                        }
                        if not endpoints & claim_subjects:
                            problems.append(
                                ValidationProblem(
                                    path,
                                    f"$.conflicts[{conflict_index}].assertion_ids",
                                    f"conflict assertion {assertion_id!r} does not concern a non-assertion subject of affected claim {claim_index}",
                                )
                            )
            for field in ("assertion_ids", "resolution_assertion_ids"):
                identities = conflict.get(field)
                for assertion_index, assertion_id in enumerate(
                    identities if isinstance(identities, list) else []
                ):
                    location = f"$.conflicts[{conflict_index}].{field}[{assertion_index}]"
                    require_dependency("assertion", assertion_id, location)
                    if field == "resolution_assertion_ids":
                        assertion_entry = (
                            assertions.get(assertion_id)
                            if isinstance(assertion_id, str)
                            else None
                        )
                        if assertion_entry is not None and assertion_entry[1].get(
                            "status"
                        ) not in {"verified", "superseded"}:
                            problems.append(
                                ValidationProblem(
                                    path,
                                    location,
                                    "a conflict resolution must use a reviewed supporting assertion",
                                )
                            )

        for unresolved_index, item in enumerate(unresolved):
            related_entities = item.get("related_entities")
            for reference_index, reference in enumerate(
                related_entities if isinstance(related_entities, list) else []
            ):
                if isinstance(reference, dict):
                    require_dependency(
                        reference.get("entity_type"),
                        reference.get("entity_id"),
                        f"$.unresolved_items[{unresolved_index}].related_entities[{reference_index}]",
                    )
            report_ids = item.get("correction_report_ids")
            for report_index, report_id in enumerate(
                report_ids if isinstance(report_ids, list) else []
            ):
                require_dependency(
                    "report",
                    report_id,
                    f"$.unresolved_items[{unresolved_index}].correction_report_ids[{report_index}]",
                )

        verification_tasks = bundle.get("verification_tasks")
        for task_index, task in enumerate(
            verification_tasks if isinstance(verification_tasks, list) else []
        ):
            targets = task.get("targets") if isinstance(task, dict) else None
            for target_index, target in enumerate(
                targets if isinstance(targets, list) else []
            ):
                if isinstance(target, dict):
                    require_dependency(
                        target.get("entity_type"),
                        target.get("entity_id"),
                        f"$.verification_tasks[{task_index}].targets[{target_index}]",
                    )

        processed_dependency_refs: set[tuple[str, str]] = set()
        while expected_dependency_refs - processed_dependency_refs:
            entity_type, entity_id = min(
                expected_dependency_refs - processed_dependency_refs
            )
            processed_dependency_refs.add((entity_type, entity_id))
            if not isinstance(entity_type, str) or not isinstance(entity_id, str):
                continue
            if entity_type == "artifact" and entity_id in artifacts:
                candidate_routes = {
                    ("capture", capture_id)
                    for capture_id in captures_by_artifact.get(entity_id, set())
                } | {
                    ("derivation", derivation_id)
                    for derivation_id in derivations_by_output.get(entity_id, set())
                }
                selected_routes = candidate_routes & dependency_refs
                if not selected_routes and len(candidate_routes) == 1:
                    route_type, route_id = next(iter(candidate_routes))
                    require_dependency(route_type, route_id, "$.dependencies")
                elif candidate_routes and len(selected_routes) != 1:
                    problems.append(
                        ValidationProblem(
                            path,
                            "$.dependencies",
                            f"artifact {entity_id!r} must select exactly one capture or derivation provenance dependency",
                        )
                    )
            elif entity_type == "capture" and entity_id in captures:
                capture = captures[entity_id][1]
                require_dependency("artifact", capture.get("artifact_id"), "$.dependencies")
                require_dependency("source", capture.get("source_id"), "$.dependencies")
                acquisition = capture.get("acquisition")
                discovery_evidence = (
                    acquisition.get("discovery_evidence")
                    if isinstance(acquisition, dict)
                    else None
                )
                if isinstance(discovery_evidence, dict):
                    require_dependency(
                        "artifact",
                        discovery_evidence.get("artifact_id"),
                        "$.dependencies",
                    )
                    require_dependency(
                        "capture",
                        discovery_evidence.get("capture_id"),
                        "$.dependencies",
                    )
            elif entity_type == "derivation" and entity_id in derivations:
                derivation = derivations[entity_id][1]
                require_dependency(
                    "artifact", derivation.get("output_artifact_id"), "$.dependencies"
                )
                for item in _list_or_empty(derivation.get("input_artifacts")):
                    if isinstance(item, dict):
                        require_dependency("artifact", item.get("artifact_id"), "$.dependencies")
                require_dependency(
                    "artifact", derivation.get("settings_artifact_id"), "$.dependencies"
                )
                for capture_id in _list_or_empty(
                    derivation.get("rights_basis_capture_ids")
                ):
                    require_dependency("capture", capture_id, "$.dependencies")
            elif entity_type == "source" and entity_id in sources:
                source = sources[entity_id][1]
                require_citation_dependencies(source.get("identity_evidence"))
                for authority_id in _list_or_empty(source.get("authority_ids")):
                    require_dependency("authority", authority_id, "$.dependencies")
                for jurisdiction_id in _list_or_empty(source.get("jurisdiction_ids")):
                    require_dependency("jurisdiction", jurisdiction_id, "$.dependencies")
            elif entity_type == "authority" and entity_id in authorities:
                authority = authorities[entity_id][1]
                require_citation_dependencies(authority.get("profile_evidence"))
                for name in _list_or_empty(authority.get("names")):
                    if isinstance(name, dict):
                        require_citation_dependencies(name.get("evidence"))
                for relationship in (
                    _list_or_empty(authority.get("jurisdictions_served"))
                    + _list_or_empty(authority.get("parent_relationships"))
                ):
                    if not isinstance(relationship, dict):
                        continue
                    require_dependency(
                        "jurisdiction",
                        relationship.get("jurisdiction_id"),
                        "$.dependencies",
                    )
                    require_dependency(
                        "authority",
                        relationship.get("parent_authority_id"),
                        "$.dependencies",
                    )
                    require_dependency(
                        "assertion",
                        relationship.get("assertion_id"),
                        "$.dependencies",
                    )
            elif entity_type == "jurisdiction" and entity_id in jurisdictions:
                jurisdiction = jurisdictions[entity_id][1]
                require_citation_dependencies(jurisdiction.get("profile_evidence"))
                for name in _list_or_empty(jurisdiction.get("names")):
                    if isinstance(name, dict):
                        require_citation_dependencies(name.get("evidence"))
                for relationship in _list_or_empty(
                    jurisdiction.get("territorial_relationships")
                ):
                    if isinstance(relationship, dict):
                        require_dependency(
                            "jurisdiction",
                            relationship.get("related_jurisdiction_id"),
                            "$.dependencies",
                        )
                        require_dependency(
                            "assertion",
                            relationship.get("assertion_id"),
                            "$.dependencies",
                        )
            elif entity_type == "record" and entity_id in records:
                record = records[entity_id][1]
                require_citation_dependencies(record.get("metadata_evidence"))
                for jurisdiction_id in _list_or_empty(record.get("jurisdiction_ids")):
                    require_dependency("jurisdiction", jurisdiction_id, "$.dependencies")
                for relationship in _list_or_empty(
                    record.get("authority_relationships")
                ):
                    if isinstance(relationship, dict):
                        require_dependency(
                            "authority", relationship.get("authority_id"), "$.dependencies"
                        )
                        require_dependency(
                            "assertion", relationship.get("assertion_id"), "$.dependencies"
                        )
            elif entity_type == "version" and entity_id in record_versions:
                _, record_id, version = record_versions[entity_id]
                require_dependency("record", record_id, "$.dependencies")
                for artifact_id in _list_or_empty(version.get("artifact_ids")):
                    require_dependency("artifact", artifact_id, "$.dependencies")
                require_citation_dependencies(version.get("metadata_evidence"))
                for relationship in _list_or_empty(
                    version.get("authority_relationships")
                ):
                    if isinstance(relationship, dict):
                        require_dependency(
                            "authority",
                            relationship.get("authority_id"),
                            "$.dependencies",
                        )
                        require_dependency(
                            "assertion",
                            relationship.get("assertion_id"),
                            "$.dependencies",
                        )
                require_citation_dependencies(version.get("publication_evidence"))
                require_time_basis_dependencies(version.get("time_axes"))
                for assertion_id in _list_or_empty(
                    version.get("derived_from_assertion_ids")
                ):
                    require_dependency("assertion", assertion_id, "$.dependencies")
                for predecessor_id in _list_or_empty(
                    version.get("supersedes_version_ids")
                ):
                    require_dependency("version", predecessor_id, "$.dependencies")
                for successor_id in incoming_version_history.get(entity_id, []):
                    if legal_state_is_snapshot_visible("version", successor_id):
                        require_dependency(
                            "version", successor_id, "$.dependencies"
                        )
            elif entity_type == "provision" and entity_id in provision_records:
                for record_id in provision_records[entity_id]:
                    require_dependency("record", record_id, "$.dependencies")
            elif entity_type == "provision_version" and entity_id in provision_versions:
                _, record_id, version_id, provision = provision_versions[entity_id]
                require_dependency("record", record_id, "$.dependencies")
                require_dependency("version", version_id, "$.dependencies")
                require_dependency(
                    "provision", provision.get("provision_id"), "$.dependencies"
                )
                require_dependency(
                    "artifact", provision.get("content_artifact_id"), "$.dependencies"
                )
                for citation in _list_or_empty(provision.get("text_citations")):
                    if isinstance(citation, dict):
                        require_dependency(
                            "artifact", citation.get("artifact_id"), "$.dependencies"
                        )
                        require_dependency(
                            "capture", citation.get("capture_id"), "$.dependencies"
                        )
                require_citation_dependencies(provision.get("publication_evidence"))
                require_time_basis_dependencies(provision.get("time_axes"))
                for assertion_id in _list_or_empty(
                    provision.get("derived_from_assertion_ids")
                ):
                    require_dependency("assertion", assertion_id, "$.dependencies")
                for predecessor_id in _list_or_empty(
                    provision.get("predecessor_provision_version_ids")
                ):
                    require_dependency(
                        "provision_version", predecessor_id, "$.dependencies"
                    )
                for successor_id in incoming_provision_version_history.get(
                    entity_id, []
                ):
                    if legal_state_is_snapshot_visible(
                        "provision_version", successor_id
                    ):
                        require_dependency(
                            "provision_version", successor_id, "$.dependencies"
                        )
            elif entity_type == "assertion" and entity_id in assertions:
                assertion = assertions[entity_id][1]
                for endpoint in (assertion.get("subject"), assertion.get("object")):
                    if isinstance(endpoint, dict):
                        require_dependency(
                            endpoint.get("entity_type"),
                            endpoint.get("entity_id"),
                            "$.dependencies",
                        )
                require_citation_dependencies(assertion.get("evidence"))
                require_time_basis_dependencies(assertion.get("time_axes"))
                for linked_assertion_id in (
                    _list_or_empty(assertion.get("supersedes_assertion_ids"))
                    + _list_or_empty(assertion.get("disputes_assertion_ids"))
                ):
                    require_dependency(
                        "assertion", linked_assertion_id, "$.dependencies"
                    )
                for newer_id, relation_field in incoming_assertion_history.get(
                    entity_id, []
                ):
                    if incoming_assertion_is_snapshot_visible(
                        newer_id, entity_id, relation_field
                    ):
                        require_dependency(
                            "assertion", newer_id, "$.dependencies"
                        )
            elif entity_type == "report" and entity_id in corrections:
                report = corrections[entity_id][1]
                require_dependency(
                    "snapshot", report.get("corpus_snapshot_id"), "$.dependencies"
                )
                require_dependency(
                    "report", report.get("duplicate_of_report_id"), "$.dependencies"
                )
                for jurisdiction_id in _list_or_empty(
                    report.get("jurisdiction_ids")
                ):
                    require_dependency(
                        "jurisdiction", jurisdiction_id, "$.dependencies"
                    )
                for reference in (
                    _list_or_empty(report.get("targets"))
                    + _list_or_empty(
                        report.get("proposed_change", {}).get("entity_refs")
                        if isinstance(report.get("proposed_change"), dict)
                        else None
                    )
                ):
                    if isinstance(reference, dict):
                        require_dependency(
                            reference.get("entity_type"),
                            reference.get("entity_id"),
                            "$.dependencies",
                        )
                coverage_context = report.get("coverage_context")
                if isinstance(coverage_context, dict):
                    require_dependency(
                        "coverage",
                        coverage_context.get("coverage_id"),
                        "$.dependencies",
                    )
                    require_dependency(
                        "source",
                        coverage_context.get("source_id"),
                        "$.dependencies",
                    )
                for evidence in _list_or_empty(report.get("public_evidence")):
                    if not isinstance(evidence, dict):
                        continue
                    for evidence_type, field in (
                        ("authority", "authority_id"),
                        ("source", "source_id"),
                        ("capture", "capture_id"),
                        ("artifact", "artifact_id"),
                    ):
                        require_dependency(
                            evidence_type, evidence.get(field), "$.dependencies"
                        )
                application = report.get("application")
                if isinstance(application, dict):
                    require_dependency(
                        "event",
                        application.get("invalidation_event_id"),
                        "$.dependencies",
                    )
                    require_dependency(
                        "snapshot",
                        application.get("snapshot_after"),
                        "$.dependencies",
                    )
            elif entity_type == "snapshot" and entity_id in snapshots:
                snapshot = snapshots[entity_id][1]
                require_dependency(
                    "snapshot", snapshot.get("predecessor_snapshot_id"), "$.dependencies"
                )
                require_dependency(
                    "event", snapshot.get("transition_event_id"), "$.dependencies"
                )
            elif entity_type == "event" and entity_id in events:
                event = events[entity_id][1]
                require_dependency(
                    "snapshot", event.get("snapshot_before"), "$.dependencies"
                )
                require_dependency(
                    "snapshot", event.get("snapshot_after"), "$.dependencies"
                )
                cause = event.get("cause")
                for report_id in _list_or_empty(
                    cause.get("correction_report_ids")
                    if isinstance(cause, dict)
                    else None
                ):
                    require_dependency("report", report_id, "$.dependencies")
                for change in _list_or_empty(event.get("affected_entities")):
                    entity = change.get("entity") if isinstance(change, dict) else None
                    if isinstance(entity, dict):
                        require_dependency(
                            entity.get("entity_type"),
                            entity.get("entity_id"),
                            "$.dependencies",
                        )
            elif entity_type == "coverage" and entity_id in coverages:
                coverage = coverages[entity_id][1]
                require_dependency("source", coverage.get("source_id"), "$.dependencies")
                coverage_scope = coverage.get("declared_scope")
                if isinstance(coverage_scope, dict):
                    for authority_id in _list_or_empty(
                        coverage_scope.get("authority_ids")
                    ):
                        require_dependency("authority", authority_id, "$.dependencies")
                    for jurisdiction_id in _list_or_empty(
                        coverage_scope.get("jurisdiction_ids")
                    ):
                        require_dependency("jurisdiction", jurisdiction_id, "$.dependencies")
                for run in _list_or_empty(coverage.get("enumeration_runs")):
                    if isinstance(run, dict):
                        for artifact_id in _list_or_empty(
                            run.get("index_artifact_ids")
                        ):
                            require_dependency("artifact", artifact_id, "$.dependencies")
                for gap in _list_or_empty(coverage.get("known_gaps")):
                    if not isinstance(gap, dict):
                        continue
                    require_dependency("gap", gap.get("gap_id"), "$.dependencies")
                    for report_id in _list_or_empty(
                        gap.get("correction_report_ids")
                    ):
                        require_dependency("report", report_id, "$.dependencies")
        coverage_results = bundle.get("coverage")
        if isinstance(coverage_results, list):
            for index, result in enumerate(coverage_results):
                if not isinstance(result, dict):
                    continue
                coverage_id = result.get("coverage_id")
                coverage_entry = (
                    coverages.get(coverage_id) if isinstance(coverage_id, str) else None
                )
                location = f"$.coverage[{index}]"
                if coverage_entry is None:
                    problems.append(
                        ValidationProblem(
                            path,
                            f"{location}.coverage_id",
                            "evidence bundle coverage ledger does not resolve",
                        )
                    )
                    continue
                if ("coverage", coverage_id) not in dependency_refs:
                    problems.append(
                        ValidationProblem(
                            path,
                            f"{location}.coverage_id",
                            "evidence bundle coverage ledger must also be an explicit dependency",
                        )
                    )
                visible_successors = sorted(
                    successor_id
                    for successor_id in incoming_coverage_history.get(
                        coverage_id, []
                    )
                    if (
                        snapshot_generated_at is not None
                        and (successor_entry := coverages.get(successor_id))
                        is not None
                        and isinstance(successor_entry[1].get("generated_at"), str)
                        and (
                            successor_generated_at := _parse_datetime(
                                successor_entry[1]["generated_at"]
                            )
                        )
                        is not None
                        and successor_generated_at <= snapshot_generated_at
                    )
                )
                if visible_successors:
                    problems.append(
                        ValidationProblem(
                            path,
                            f"{location}.coverage_id",
                            "bundle selected a coverage ledger superseded by a ledger visible at its corpus snapshot: "
                            + ", ".join(visible_successors),
                        )
                    )
                ledger = coverage_entry[1]
                for field in (
                    "status",
                    "fresh_until",
                    "last_successful_enumeration_at",
                ):
                    if result.get(field) != ledger.get(field):
                        problems.append(
                            ValidationProblem(
                                path,
                                f"{location}.{field}",
                                f"bundle coverage {field} does not match the resolved ledger",
                            )
                        )
                known_gaps = ledger.get("known_gaps")
                expected_gap_ids = sorted(
                    gap["gap_id"]
                    for gap in (
                        known_gaps if isinstance(known_gaps, list) else []
                    )
                    if isinstance(gap, dict)
                    and isinstance(gap.get("gap_id"), str)
                    and gap.get("state")
                    in {"open", "investigating", "accepted_unresolved"}
                )
                actual_gap_ids = result.get("gap_ids")
                if (
                    not isinstance(actual_gap_ids, list)
                    or not all(isinstance(item, str) for item in actual_gap_ids)
                    or sorted(actual_gap_ids) != expected_gap_ids
                ):
                    problems.append(
                        ValidationProblem(
                            path,
                            f"{location}.gap_ids",
                            "bundle gap IDs do not match unresolved gaps in the coverage ledger",
                        )
                    )

    for event_id, (path, event) in events.items():
        before_id = event.get("snapshot_before")
        after_id = event.get("snapshot_after")
        before_entry = snapshots.get(before_id) if isinstance(before_id, str) else None
        after_entry = snapshots.get(after_id) if isinstance(after_id, str) else None
        if before_entry is None:
            problems.append(
                ValidationProblem(
                    path,
                    "$.snapshot_before",
                    f"invalidation event {event_id!r} before snapshot does not resolve",
                )
            )
        if after_entry is None:
            problems.append(
                ValidationProblem(
                    path,
                    "$.snapshot_after",
                    f"invalidation event {event_id!r} after snapshot does not resolve",
                )
            )
        elif after_entry[1].get("predecessor_snapshot_id") != before_id:
            problems.append(
                ValidationProblem(
                    path,
                    "$.snapshot_after",
                    "invalidation after snapshot does not name snapshot_before as its predecessor",
                )
            )
        elif after_entry[1].get("transition_event_id") != event_id:
            problems.append(
                ValidationProblem(
                    path,
                    "$.snapshot_after",
                    "invalidation after snapshot does not bind this exact transition event",
                )
            )
        if before_entry is not None and after_entry is not None:
            before_generated_at = (
                _parse_datetime(before_entry[1].get("generated_at"))
                if isinstance(before_entry[1].get("generated_at"), str)
                else None
            )
            event_occurred_at = (
                _parse_datetime(event.get("occurred_at"))
                if isinstance(event.get("occurred_at"), str)
                else None
            )
            after_generated_at = (
                _parse_datetime(after_entry[1].get("generated_at"))
                if isinstance(after_entry[1].get("generated_at"), str)
                else None
            )
            if (
                before_generated_at is not None
                and after_generated_at is not None
                and after_generated_at <= before_generated_at
            ):
                problems.append(
                    ValidationProblem(
                        path,
                        "$.snapshot_after",
                        "invalidation after snapshot must be generated after snapshot_before",
                    )
                )
            if (
                before_generated_at is not None
                and event_occurred_at is not None
                and event_occurred_at < before_generated_at
            ):
                problems.append(
                    ValidationProblem(
                        path,
                        "$.occurred_at",
                        "invalidation event cannot predate snapshot_before",
                    )
                )
            if (
                after_generated_at is not None
                and event_occurred_at is not None
                and event_occurred_at > after_generated_at
            ):
                problems.append(
                    ValidationProblem(
                        path,
                        "$.occurred_at",
                        "invalidation event cannot postdate snapshot_after",
                    )
                )
        cause = event.get("cause")
        report_ids = cause.get("correction_report_ids") if isinstance(cause, dict) else None
        if isinstance(report_ids, list):
            for index, report_id in enumerate(report_ids):
                report_entry = (
                    corrections.get(report_id) if isinstance(report_id, str) else None
                )
                if report_entry is None:
                    problems.append(
                        ValidationProblem(
                            path,
                            f"$.cause.correction_report_ids[{index}]",
                            "invalidation correction report does not resolve",
                        )
                    )
                    continue
                required_review_status = {
                    "succeeded": "APPLIED",
                    "failed": "PROPAGATION_FAILED",
                    "pending": "ACCEPTED",
                }.get(event.get("propagation_status"))
                report = report_entry[1]
                if report.get("public_review_status") != required_review_status:
                    problems.append(
                        ValidationProblem(
                            path,
                            f"$.cause.correction_report_ids[{index}]",
                            "an invalidation event may use a correction report only after the corresponding reviewed lifecycle state",
                        )
                    )

    scalar_reference_fields = {
        "artifact_id": "artifact",
        "assertion_id": "assertion",
        "authority_id": "authority",
        "capture_id": "capture",
        "content_artifact_id": "artifact",
        "coverage_id": "coverage",
        "derivation_id": "derivation",
        "duplicate_of_report_id": "report",
        "invalidation_event_id": "event",
        "output_artifact_id": "artifact",
        "parent_authority_id": "authority",
        "parent_provision_id": "provision",
        "provision_id": "provision",
        "provision_version_id": "provision_version",
        "record_id": "record",
        "related_jurisdiction_id": "jurisdiction",
        "settings_artifact_id": "artifact",
        "source_id": "source",
        "supersedes_coverage_id": "coverage",
        "transition_event_id": "event",
        "version_id": "version",
    }
    array_reference_fields = {
        "affected_claim_ids": "claim",
        "artifact_ids": "artifact",
        "assertion_ids": "assertion",
        "basis_assertion_ids": "assertion",
        "contrary_assertion_ids": "assertion",
        "correction_report_ids": "report",
        "derived_from_assertion_ids": "assertion",
        "disputes_assertion_ids": "assertion",
        "gap_ids": "gap",
        "index_artifact_ids": "artifact",
        "predecessor_provision_version_ids": "provision_version",
        "resolution_assertion_ids": "assertion",
        "rights_basis_capture_ids": "capture",
        "supersedes_assertion_ids": "assertion",
        "supersedes_version_ids": "version",
        "target_provision_ids": "provision",
        "version_ids": "version",
    }

    for path, document in documents:
        for location, value in _walk(document):
            if (
                isinstance(value, dict)
                and isinstance(value.get("entity_type"), str)
                and isinstance(value.get("entity_id"), str)
            ):
                entity_type = value["entity_type"]
                if value["entity_id"] not in entity_ids.get(entity_type, set()):
                    problems.append(
                        ValidationProblem(
                            path,
                            _json_location(location),
                            f"{entity_type} entity reference does not resolve in this corpus",
                        )
                    )
            if (
                location
                and location[-1] in {"jurisdiction_ids", "authority_ids"}
                and isinstance(value, list)
            ):
                entity_type = (
                    "jurisdiction" if location[-1] == "jurisdiction_ids" else "authority"
                )
                known = entity_ids.get(entity_type, set())
                for index, identity in enumerate(value):
                    if isinstance(identity, str) and identity not in known:
                        problems.append(
                            ValidationProblem(
                                path,
                                _json_location((*location, index)),
                                f"{entity_type} reference does not resolve in this corpus",
                            )
                        )
            if location and isinstance(location[-1], str):
                field = location[-1]
                scalar_type = scalar_reference_fields.get(field)
                if (
                    scalar_type is not None
                    and isinstance(value, str)
                    and value not in entity_ids.get(scalar_type, set())
                ):
                    problems.append(
                        ValidationProblem(
                            path,
                            _json_location(location),
                            f"{scalar_type} reference does not resolve in this corpus",
                        )
                    )
                array_type = array_reference_fields.get(field)
                if array_type is not None and isinstance(value, list):
                    known = entity_ids.get(array_type, set())
                    for index, identity in enumerate(value):
                        if isinstance(identity, str) and identity not in known:
                            problems.append(
                                ValidationProblem(
                                    path,
                                    _json_location((*location, index)),
                                    f"{array_type} reference does not resolve in this corpus",
                                )
                            )

    source_artifact_ids = {
        capture.get("artifact_id")
        for _, capture in captures.values()
        if isinstance(capture.get("artifact_id"), str)
    }
    for path, document in documents:
        for location, value in _walk(document):
            if not isinstance(value, dict) or not {"artifact_id", "locator"}.issubset(value):
                continue
            artifact_id = value.get("artifact_id")
            if isinstance(artifact_id, str) and artifact_id not in artifacts:
                problems.append(
                    ValidationProblem(
                        path,
                        _json_location((*location, "artifact_id")),
                        "citation artifact does not resolve",
                    )
                )
            capture_id = value.get("capture_id")
            if (
                isinstance(artifact_id, str)
                and artifact_id in source_artifact_ids
                and not isinstance(capture_id, str)
            ):
                problems.append(
                    ValidationProblem(
                        path,
                        _json_location(location),
                        "source-acquired citation must name its exact capture_id",
                    )
                )
            if isinstance(capture_id, str):
                capture_entry = captures.get(capture_id)
                if capture_entry is None:
                    problems.append(
                        ValidationProblem(
                            path,
                            _json_location((*location, "capture_id")),
                            "citation capture does not resolve",
                        )
                    )
                elif capture_entry[1].get("artifact_id") != artifact_id:
                    problems.append(
                        ValidationProblem(
                            path,
                            _json_location((*location, "capture_id")),
                            "citation capture does not resolve to the cited artifact",
                        )
                    )
                elif not _capture_http_succeeded(capture_entry[1]):
                    problems.append(
                        ValidationProblem(
                            path,
                            _json_location((*location, "capture_id")),
                            "only a complete HTTP 200 capture can serve as legal or profile evidence in v1",
                        )
                    )
            content_verification = value.get("content_verification")
            content_verified_at = (
                _parse_datetime(content_verification.get("verified_at"))
                if isinstance(content_verification, dict)
                and isinstance(content_verification.get("verified_at"), str)
                else None
            )
            content_evidence_times: list[datetime] = []
            artifact_entry = (
                artifacts.get(artifact_id) if isinstance(artifact_id, str) else None
            )
            if artifact_entry is not None and isinstance(
                artifact_entry[1].get("created_at"), str
            ):
                artifact_time = _parse_datetime(artifact_entry[1]["created_at"])
                if artifact_time is not None:
                    content_evidence_times.append(artifact_time)
            capture_entry = (
                captures.get(capture_id) if isinstance(capture_id, str) else None
            )
            retrieval = (
                capture_entry[1].get("retrieval")
                if capture_entry is not None
                else None
            )
            if isinstance(retrieval, dict) and isinstance(
                retrieval.get("retrieved_at"), str
            ):
                retrieval_time = _parse_datetime(retrieval["retrieved_at"])
                if retrieval_time is not None:
                    content_evidence_times.append(retrieval_time)
            if (
                content_verified_at is not None
                and any(
                    content_verified_at < evidence_time
                    for evidence_time in content_evidence_times
                )
            ):
                problems.append(
                    ValidationProblem(
                        path,
                        _json_location(
                            (*location, "content_verification", "verified_at")
                        ),
                        "source-content verification cannot predate its cited bytes or capture",
                    )
                )
            temporal_binding = value.get("temporal_value_binding")
            if isinstance(temporal_binding, dict):
                binding_created_at = (
                    _parse_datetime(temporal_binding.get("created_at"))
                    if isinstance(temporal_binding.get("created_at"), str)
                    else None
                )
                binding_reviewed_at = (
                    _parse_datetime(temporal_binding.get("reviewed_at"))
                    if isinstance(temporal_binding.get("reviewed_at"), str)
                    else None
                )
                evidence_times: list[datetime] = []
                artifact_entry = (
                    artifacts.get(artifact_id) if isinstance(artifact_id, str) else None
                )
                if artifact_entry is not None and isinstance(
                    artifact_entry[1].get("created_at"), str
                ):
                    artifact_time = _parse_datetime(artifact_entry[1]["created_at"])
                    if artifact_time is not None:
                        evidence_times.append(artifact_time)
                capture_entry = (
                    captures.get(capture_id) if isinstance(capture_id, str) else None
                )
                retrieval = (
                    capture_entry[1].get("retrieval")
                    if capture_entry is not None
                    else None
                )
                if isinstance(retrieval, dict) and isinstance(
                    retrieval.get("retrieved_at"), str
                ):
                    retrieval_time = _parse_datetime(retrieval["retrieved_at"])
                    if retrieval_time is not None:
                        evidence_times.append(retrieval_time)
                content_verification = value.get("content_verification")
                if isinstance(content_verification, dict) and isinstance(
                    content_verification.get("verified_at"), str
                ):
                    content_verified_at = _parse_datetime(
                        content_verification["verified_at"]
                    )
                    if content_verified_at is not None:
                        evidence_times.append(content_verified_at)
                settings_id = temporal_binding.get("settings_artifact_id")
                settings_entry = (
                    artifacts.get(settings_id) if isinstance(settings_id, str) else None
                )
                if settings_entry is not None and isinstance(
                    settings_entry[1].get("created_at"), str
                ):
                    settings_time = _parse_datetime(settings_entry[1]["created_at"])
                    if settings_time is not None:
                        evidence_times.append(settings_time)
                if (
                    binding_created_at is not None
                    and any(binding_created_at < evidence_time for evidence_time in evidence_times)
                ):
                    problems.append(
                        ValidationProblem(
                            path,
                            _json_location(
                                (*location, "temporal_value_binding", "created_at")
                            ),
                            "temporal normalization cannot predate its cited bytes or settings",
                        )
                    )
                if (
                    binding_reviewed_at is not None
                    and any(binding_reviewed_at < evidence_time for evidence_time in evidence_times)
                ):
                    problems.append(
                        ValidationProblem(
                            path,
                            _json_location(
                                (*location, "temporal_value_binding", "reviewed_at")
                            ),
                            "temporal normalization review cannot predate its cited bytes or settings",
                        )
                    )

    for path, document in documents:
        for location, value in _walk(document):
            if not isinstance(value, dict) or not isinstance(value.get("reviewed_at"), str):
                continue
            reviewed_at = _parse_datetime(value["reviewed_at"])
            if reviewed_at is None:
                continue
            evidence_items: list[Any] = []
            for evidence_field in ("evidence", "profile_evidence"):
                field_value = value.get(evidence_field)
                if isinstance(field_value, list):
                    evidence_items.extend(field_value)
            evidence_times: list[datetime] = []
            for evidence in evidence_items:
                if not isinstance(evidence, dict):
                    continue
                artifact_id = evidence.get("artifact_id")
                artifact_entry = artifacts.get(artifact_id) if isinstance(artifact_id, str) else None
                if artifact_entry is not None and isinstance(
                    artifact_entry[1].get("created_at"), str
                ):
                    artifact_time = _parse_datetime(artifact_entry[1]["created_at"])
                    if artifact_time is not None:
                        evidence_times.append(artifact_time)
                capture_id = evidence.get("capture_id")
                capture_entry = captures.get(capture_id) if isinstance(capture_id, str) else None
                retrieval = capture_entry[1].get("retrieval") if capture_entry is not None else None
                if isinstance(retrieval, dict) and isinstance(
                    retrieval.get("retrieved_at"), str
                ):
                    retrieval_time = _parse_datetime(retrieval["retrieved_at"])
                    if retrieval_time is not None:
                        evidence_times.append(retrieval_time)
                content_verification = evidence.get("content_verification")
                if isinstance(content_verification, dict) and isinstance(
                    content_verification.get("verified_at"), str
                ):
                    content_verified_at = _parse_datetime(
                        content_verification["verified_at"]
                    )
                    if content_verified_at is not None:
                        evidence_times.append(content_verified_at)
            if any(reviewed_at < evidence_time for evidence_time in evidence_times):
                problems.append(
                    ValidationProblem(
                        path,
                        _json_location((*location, "reviewed_at")),
                        "review cannot predate its cited evidence",
                    )
                )
    return problems


def validate_document(
    path: Path,
    document: Any,
    schemas: dict[str, dict[str, Any]],
    registry: Registry,
) -> list[ValidationProblem]:
    if not isinstance(document, dict):
        return [ValidationProblem(path, "$", "document root must be an object")]

    try:
        _reject_non_finite_numbers(document)
    except ValueError as error:
        return [ValidationProblem(path, "$", str(error))]

    schema_id = document.get("schema_id")
    if not isinstance(schema_id, str):
        return [ValidationProblem(path, "$.schema_id", "missing schema_id")]
    if schema_id not in schemas:
        return [ValidationProblem(path, "$.schema_id", f"unknown schema_id {schema_id!r}")]

    validator = Draft202012Validator(
        schemas[schema_id],
        registry=registry,
        format_checker=Draft202012Validator.FORMAT_CHECKER,
    )
    problems = [
        ValidationProblem(path, _json_location(error.absolute_path), error.message)
        for error in sorted(
            validator.iter_errors(document), key=lambda item: list(item.absolute_path)
        )
    ]
    schema_invalid = bool(problems)
    semantic_checks = (
        privacy_problems,
        public_url_problems,
        artifact_identity_problems,
        storage_location_problems,
        collection_identity_problems,
        record_semantic_problems,
        evidence_content_verification_problems,
        coverage_ledger_problems,
        evidence_bundle_reference_problems,
        evidence_bundle_status_problems,
        evidence_bundle_privacy_problems,
        evidence_bundle_handling_problems,
        correction_state_problems,
        source_manifest_identity_problems,
        relationship_review_problems,
        profile_review_problems,
        temporal_problems,
        invalidation_problems,
        snapshot_problems,
        rights_assessment_problems,
        publication_clearance_problems,
        review_target_problems,
    )
    for check in semantic_checks:
        if not schema_invalid:
            problems.extend(check(path, document))
            continue
        try:
            problems.extend(check(path, document))
        except Exception as error:
            # Preserve all shape errors and any other semantic diagnostics, but
            # never let one schema-invalid subtree turn validation into a CI DoS.
            problems.append(
                ValidationProblem(
                    path,
                    "$",
                    f"{check.__name__} could not evaluate schema-invalid input ({type(error).__name__})",
                )
            )
    return problems


def validate_paths(
    paths: Iterable[Path],
    schema_directory: Path = DEFAULT_SCHEMA_DIRECTORY,
    *,
    closed_corpus: bool = False,
) -> list[ValidationProblem]:
    schemas, registry = load_schema_registry(schema_directory)
    schema_digests: dict[str, str] = {}
    for schema_path in iter_structured_files((schema_directory,)):
        schema = load_document(schema_path)
        if isinstance(schema, dict) and isinstance(schema.get("$id"), str):
            schema_digests[schema["$id"]] = hashlib.sha256(schema_path.read_bytes()).hexdigest()
    problems: list[ValidationProblem] = []
    documents: list[tuple[Path, dict[str, Any]]] = []
    for path in iter_structured_files(paths):
        try:
            document = load_document(path)
        except (
            OSError,
            RecursionError,
            ValueError,
            json.JSONDecodeError,
            yaml.YAMLError,
        ) as error:
            problems.append(ValidationProblem(path, "$", f"cannot parse: {error}"))
            continue
        document_problems = validate_document(path, document, schemas, registry)
        problems.extend(document_problems)
        schema_id = document.get("schema_id") if isinstance(document, dict) else None
        schema_valid = (
            isinstance(schema_id, str)
            and schema_id in schemas
            and Draft202012Validator(
                schemas[schema_id],
                registry=registry,
                format_checker=Draft202012Validator.FORMAT_CHECKER,
            ).is_valid(document)
        )
        if isinstance(document, dict) and schema_valid:
            documents.append((path, document))
            problems.extend(schema_catalog_problems(path, document, schema_digests))
    if closed_corpus:
        problems.extend(
            snapshot_schema_catalog_completeness_problems(documents, schemas)
        )
        problems.extend(corpus_publication_problems(documents))
        problems.extend(corpus_integrity_problems(documents))
    return problems


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "paths",
        nargs="*",
        type=Path,
        default=list(DEFAULT_DATA_DIRECTORIES),
        help="files or directories to validate (defaults to examples/)",
    )
    parser.add_argument(
        "--schemas",
        type=Path,
        default=DEFAULT_SCHEMA_DIRECTORY,
        help="directory containing JSON Schema contracts",
    )
    parser.add_argument(
        "--closed-corpus",
        action="store_true",
        help=(
            "also require every cross-document reference and publication route "
            "to resolve within the selected paths"
        ),
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    arguments = build_parser().parse_args(argv)
    files = list(iter_structured_files(arguments.paths))
    if not files:
        print("validation setup failed: no structured documents found", file=sys.stderr)
        return 2
    try:
        problems = validate_paths(
            files,
            arguments.schemas,
            closed_corpus=arguments.closed_corpus,
        )
    except (OSError, ValueError) as error:
        print(f"validation setup failed: {error}", file=sys.stderr)
        return 2

    for problem in problems:
        print(problem.render(), file=sys.stderr)
    if problems:
        print(f"validation failed with {len(problems)} problem(s)", file=sys.stderr)
        return 1

    print(
        f"validated {len(files)} document(s) in "
        f"{'closed-corpus' if arguments.closed_corpus else 'fragment'} mode against "
        f"{len(load_schema_registry(arguments.schemas)[0])} schema(s)"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
