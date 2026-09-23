"""external-resources.json: declarations, tiers, and what each URL is used for."""

from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any, Iterable
from urllib.parse import urlsplit, urlunsplit
from .model import CODE_EXTENSIONS, DOC_URL_KEYS, Finding, add_finding
from .patterns import EXECUTABLE_FENCE_LANGUAGES, NETWORK_RE
from .text import canonical_url, enclosing_fence


def load_manifest(
    skill_dir: Path,
    findings: list[Finding],
) -> tuple[dict[str, Any] | None, dict[str, dict[str, Any]]]:
    path = skill_dir / "external-resources.json"

    if not path.exists():
        return None, {}

    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except Exception as error:
        add_finding(
            findings,
            "Blocker",
            "Invalid external-resource manifest",
            str(path),
            str(error),
            "The runtime cannot derive an enforceable resource policy.",
            "Replace it with valid JSON.",
            "§20",
        )
        return None, {}

    required = {
        "version",
        "hasExternalResources",
        "requiresRuntimeGate",
        "resources",
    }

    if not isinstance(data, dict) or not required.issubset(data):
        add_finding(
            findings,
            "Major",
            "Incomplete external-resource manifest",
            str(path),
            f"Required fields: {sorted(required)}",
            "Resource and Runtime Gate state cannot be established.",
            "Add all required fields.",
            "§20",
        )
        return data if isinstance(data, dict) else None, {}

    resources = data.get("resources")

    if not isinstance(resources, list):
        add_finding(
            findings,
            "Blocker",
            "Resource declaration is not an array",
            str(path),
            repr(resources),
            "The resource allowlist cannot be processed.",
            "Set resources to an array.",
            "§20",
        )
        return data, {}

    declared: dict[str, dict[str, Any]] = {}

    for index, resource in enumerate(resources):
        location = f"{path}:resources[{index}]"

        if not isinstance(resource, dict):
            add_finding(
                findings,
                "Blocker",
                "Invalid external-resource entry",
                location,
                repr(resource),
                "The entry cannot be enforced.",
                "Replace it with an object.",
                "§20",
            )
            continue

        url = resource.get("url")
        tier = resource.get("tier")
        purpose = resource.get("purpose")
        max_bytes = resource.get("maxBytes")

        if not isinstance(url, str):
            add_finding(
                findings,
                "Blocker",
                "External resource has no valid URL",
                location,
                repr(url),
                "The destination cannot be authorized.",
                "Declare an exact HTTPS URL.",
                "§21",
            )
            continue

        normalized = canonical_url(url)

        if not normalized.startswith("https://"):
            add_finding(
                findings,
                "Blocker",
                "Runtime URL is not HTTPS",
                location,
                normalized,
                "The resource lacks transport confidentiality and integrity.",
                "Use an exact HTTPS URL.",
                "§21",
            )

        if "@" in urlsplit(url).netloc:
            add_finding(
                findings,
                "Blocker",
                "URL contains embedded credentials",
                location,
                normalized,
                "Credentials may leak through configuration or logs.",
                "Remove URL credentials.",
                "§21",
            )

        if tier not in {0, 1, 2, 3}:
            add_finding(
                findings,
                "Blocker",
                "Unknown external-resource tier",
                location,
                repr(tier),
                "The Runtime Gate cannot select a safe policy.",
                "Use Tier 0, 1, 2, or 3.",
                "§20",
            )

        if not isinstance(purpose, str) or len(purpose.strip()) < 3:
            add_finding(
                findings,
                "Major",
                "External resource has no meaningful purpose",
                location,
                repr(purpose),
                "Reviewers cannot determine whether access is necessary.",
                "Document the bounded purpose.",
                "§20",
            )

        if (
            not isinstance(max_bytes, int)
            or max_bytes < 1
            or max_bytes > 10_485_760
        ):
            add_finding(
                findings,
                "Major",
                "Invalid external response limit",
                location,
                repr(max_bytes),
                "The runtime may accept unbounded remote content.",
                "Set maxBytes between 1 and 10485760.",
                "§29",
            )

        if tier == 1 and not re.fullmatch(
            r"sha256-[a-fA-F0-9]{64}",
            str(resource.get("hash", "")),
        ):
            add_finding(
                findings,
                "Blocker",
                "Tier 1 resource lacks a valid SHA-256 pin",
                location,
                repr(resource.get("hash")),
                "Post-audit remote mutation cannot be detected.",
                "Add a byte-level SHA-256 pin.",
                "§23",
            )

        if tier == 2:
            schema = resource.get("schema")
            if (
                not isinstance(schema, dict)
                or schema.get("type") != "object"
                or not isinstance(schema.get("allowedKeys"), list)
            ):
                add_finding(
                    findings,
                    "Blocker",
                    "Tier 2 resource lacks a strict schema",
                    location,
                    repr(schema),
                    "Dynamic content may reach the agent without bounded structure.",
                    "Declare an object schema with allowedKeys.",
                    "§24",
                )

        if tier == 3:
            missing = [
                key for key in (
                    "keyId",
                    "signatureHeader",
                    "enterpriseAuthorization",
                )
                if not resource.get(key)
            ]
            if missing:
                add_finding(
                    findings,
                    "Blocker",
                    "Tier 3 resource lacks managed trust controls",
                    location,
                    f"Missing: {missing}",
                    "Agent-controlling content cannot be authenticated.",
                    "Add managed authorization and trusted-key references.",
                    "§25",
                )

        if normalized in declared:
            add_finding(
                findings,
                "Major",
                "Duplicate external-resource declaration",
                location,
                normalized,
                "Multiple policies may compete for one destination.",
                "Keep one declaration per normalized URL.",
                "§20",
            )
        else:
            declared[normalized] = resource

    return data, declared


def url_usage(
    path: Path,
    text: str,
    offset: int,
    code_spans: list[tuple[int, int, str]],
) -> str:
    """Classify one URL occurrence as `runtime` or `documentation`.

    Only a runtime occurrence can produce an actual request, so only a runtime
    occurrence needs an entry in external-resources.json. A documentation
    occurrence is a Tier 0 candidate: human-readable, never fetched.
    """
    suffix = path.suffix.lower()

    line_start = text.rfind("\n", 0, offset) + 1
    line_end = text.find("\n", offset)
    line = text[line_start:line_end if line_end >= 0 else len(text)]

    # A specification identifier such as `$schema` names a document, it does
    # not request one. The key may sit on the line above the value.
    preceding = text[:line_start].rstrip().rsplit("\n", 1)[-1] if line_start else ""

    for candidate in (line, preceding):
        key = re.match(r"\s*[\"']?([\w.$-]+)[\"']?\s*[:=]", candidate)
        if key and key.group(1).lower() in DOC_URL_KEYS:
            return "documentation"

    if suffix in CODE_EXTENSIONS:
        return "runtime"

    if NETWORK_RE.search(line):
        return "runtime"

    if suffix == ".md":
        fenced, language = enclosing_fence(offset, code_spans)
        return (
            "runtime"
            if fenced and language in EXECUTABLE_FENCE_LANGUAGES
            else "documentation"
        )

    if suffix in {".json", ".jsonc", ".yaml", ".yml", ".toml", ".ini", ".cfg", ".conf"}:
        return "runtime"

    return "documentation"
