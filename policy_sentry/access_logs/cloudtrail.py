"""
Parse AWS CloudTrail access logs and normalize them into IAM-oriented events.

The parser is intentionally tolerant: it accepts the delivered
``{"Records": [...]}`` files (plain or ``.gz``), a bare list of events, a single
event, and JSON Lines / NDJSON files.  Resource ARNs are collected from the
structured ``resources`` block as well as from any ARN-shaped string embedded
anywhere in the event, which keeps resource extraction working across services
that surface ARNs through ``requestParameters`` or ``responseElements`` only.
"""

from __future__ import annotations

import gzip
import json
import logging
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import TYPE_CHECKING, Any

from policy_sentry.querying.all import get_all_actions

if TYPE_CHECKING:
    from collections.abc import Iterable

logger = logging.getLogger(__name__)

# Real ARNs look like: arn:aws:s3:::bucket/key or arn:aws-cn:iam::123:role/x
ARN_REGEX = re.compile(r"arn:(?:aws|aws-cn|aws-us-gov):[A-Za-z0-9_.\-]+:[A-Za-z0-9_.\-]*:\d{0,12}:[^\s\"'\\\]\)}>]+")

# CloudTrail eventSource prefixes that do not match their IAM service prefix.
EVENT_SOURCE_SERVICE_ALIASES: dict[str, str] = {
    "monitoring": "cloudwatch",
    "monitoring.amazonaws.com": "cloudwatch",
    "awscloudtrail": "cloudtrail",
}

# A small, well-known set of CloudTrail eventName -> IAM action corrections for
# API names that do not map 1:1 onto an IAM action. Keys are "service:event".
CLOUDTRAIL_ACTION_OVERRIDES: dict[str, str] = {
    "s3:listbuckets": "s3:ListAllMyBuckets",
    "s3:listobjects": "s3:ListBucket",
    "s3:listobjectsv2": "s3:ListBucket",
    "s3:headbucket": "s3:ListBucket",
    "s3:headobject": "s3:GetObject",
}

_ACTION_CANONICAL_CACHE: dict[str, str] = {}


def _canonical_action_map() -> dict[str, str]:
    """Return a ``lowercase action -> canonical action`` map (cached)."""
    if not _ACTION_CANONICAL_CACHE:
        _ACTION_CANONICAL_CACHE.update({action.lower(): action for action in get_all_actions()})
    return _ACTION_CANONICAL_CACHE


def canonicalize_action(action: str) -> str | None:
    """
    Return the canonical IAM action (e.g. ``s3:GetObject``) for ``action`` using
    the bundled IAM database, or ``None`` when the action is unknown.
    """
    if not action or ":" not in action:
        return None
    return _canonical_action_map().get(action.strip().lower())


@dataclass
class CloudTrailEvent:
    """A normalized CloudTrail record with its resolved IAM action and ARNs."""

    event_source: str
    event_name: str
    action: str | None
    resource_arns: list[str] = field(default_factory=list)
    aws_region: str | None = None
    account_id: str | None = None
    event_id: str | None = None
    raw: dict[str, Any] | None = None

    @property
    def is_mapped(self) -> bool:
        return self.action is not None


def event_source_to_service(event_source: str | None) -> str:
    """
    Convert a CloudTrail ``eventSource`` (``s3.amazonaws.com``) into the IAM
    service prefix (``s3``), honoring :data:`EVENT_SOURCE_SERVICE_ALIASES`.
    """
    if not event_source:
        return ""
    source = event_source.strip().lower()
    if source in EVENT_SOURCE_SERVICE_ALIASES:
        return EVENT_SOURCE_SERVICE_ALIASES[source]
    prefix = source.split(".", 1)[0]
    return EVENT_SOURCE_SERVICE_ALIASES.get(prefix, prefix)


def map_event_to_action(event_source: str | None, event_name: str | None) -> str | None:
    """
    Map a CloudTrail ``eventSource``/``eventName`` pair to a canonical IAM
    action known to the bundled IAM database.

    The lookup tries, in order: an explicit override, the direct
    ``service:eventName`` candidate, and the service alias table. Returns
    ``None`` when no known action can be resolved.
    """
    if not event_source or not event_name:
        return None
    service = event_source_to_service(event_source)
    event = event_name.strip()

    override = CLOUDTRAIL_ACTION_OVERRIDES.get(f"{service}:{event.lower()}")
    if override:
        canonical_override = canonicalize_action(override)
        if canonical_override:
            return canonical_override

    direct = canonicalize_action(f"{service}:{event}")
    if direct:
        return direct

    # Last resort: some event names differ only by a known verb prefix shape;
    # consult overrides keyed by the raw event source prefix as well.
    raw_prefix = event_source.strip().split(".", 1)[0].lower()
    if raw_prefix != service:
        fallback = canonicalize_action(f"{raw_prefix}:{event}")
        if fallback:
            return fallback
    return None


def _clean_arn(candidate: str) -> str:
    return candidate.rstrip(".,;:) ]}'\"")


def extract_arns(value: object) -> list[str]:
    """
    Extract and de-duplicate ARNs from an arbitrary parsed JSON value.

    Works on strings (including ARNs embedded in longer text), lists and dicts.
    Only strings that match the ARN shape are returned, in first-seen order.
    """
    seen: set[str] = set()
    ordered: list[str] = []

    def consider(text: str) -> None:
        for match in ARN_REGEX.findall(text):
            arn = _clean_arn(match)
            if arn and arn not in seen and re.match(r"^arn:[^:]*:[^:]*:[^:]*:[^:]*:.+", arn):
                seen.add(arn)
                ordered.append(arn)

    def walk(node: object) -> None:
        if isinstance(node, str):
            if "arn:" in node:
                consider(node)
        elif isinstance(node, dict):
            # Prefer the explicit resources block so ordering is stable and the
            # genuinely targeted resources come first.
            resources = node.get("resources")
            if isinstance(resources, list):
                for resource in resources:
                    if isinstance(resource, dict) and resource.get("ARN"):
                        consider(str(resource["ARN"]))
            for key, child in node.items():
                if key == "resources":
                    continue
                walk(child)
        elif isinstance(node, list):
            for item in node:
                walk(item)

    walk(value)
    return ordered


def normalize_event(record: dict[str, Any]) -> CloudTrailEvent | None:
    """Normalize a single raw CloudTrail record into a :class:`CloudTrailEvent`."""
    event_name = record.get("eventName")
    event_source = record.get("eventSource")
    if not event_name or not event_source:
        return None

    user_identity = record.get("userIdentity") or {}
    account_id = record.get("recipientAccountId")
    if not account_id and isinstance(user_identity, dict):
        account_id = user_identity.get("accountId")

    return CloudTrailEvent(
        event_source=str(event_source),
        event_name=str(event_name),
        action=map_event_to_action(str(event_source), str(event_name)),
        resource_arns=extract_arns(record),
        aws_region=record.get("awsRegion"),
        account_id=account_id,
        event_id=record.get("eventID"),
        raw=record,
    )


def _read_text(path: Path) -> str:
    if path.suffix == ".gz":
        with gzip.open(path, "rt", encoding="utf-8") as handle:
            return handle.read()
    return path.read_text(encoding="utf-8")


def _coerce_records(payload: object) -> list[dict[str, Any]]:
    if isinstance(payload, dict):
        records = payload.get("Records")
        if isinstance(records, list):
            return [r for r in records if isinstance(r, dict)]
        if payload.get("eventName") and payload.get("eventSource"):
            return [payload]
        return []
    if isinstance(payload, list):
        records: list[dict[str, Any]] = []
        for item in payload:
            records.extend(_coerce_records(item))
        return records
    return []


def parse_cloudtrail_text(text: str, file_name: str = "<stream>") -> list[dict[str, Any]]:
    """
    Parse CloudTrail content as JSON, JSON Lines, or newline-delimited JSON.

    Standard CloudTrail files are a single JSON object. If whole-document JSON
    parsing fails, the parser falls back to one JSON value per line.
    """
    try:
        return _coerce_records(json.loads(text))
    except json.JSONDecodeError:
        records: list[dict[str, Any]] = []
        for line_number, raw_line in enumerate(text.splitlines(), start=1):
            stripped_line = raw_line.strip()
            if not stripped_line:
                continue
            try:
                records.extend(_coerce_records(json.loads(stripped_line)))
            except json.JSONDecodeError as exc:
                logger.debug("Skipping invalid JSON line %s in %s: %s", line_number, file_name, exc)
        return records


def iter_log_files(paths: str | Path | Iterable[str | Path]) -> list[Path]:
    """
    Expand the given paths into a de-duplicated list of CloudTrail log files.

    Directories are scanned recursively for ``.json``, ``.jsonl``, ``.ndjson``
    and ``.json.gz`` files.
    """
    if isinstance(paths, (str, Path)):
        path_values: Iterable[str | Path] = [paths]
    else:
        path_values = paths

    files: list[Path] = []
    seen: set[Path] = set()
    suffixes = {".json", ".jsonl", ".ndjson", ".log"}
    for value in path_values:
        path = Path(value)
        if path.is_dir():
            candidates = [p for p in path.rglob("*") if p.is_file()]
        elif path.is_file():
            candidates = [path]
        else:
            logger.warning("Access log path does not exist: %s", path)
            continue
        for candidate in sorted(candidates):
            if candidate.suffix == ".gz" or candidate.suffix.lower() in suffixes:
                resolved = candidate.resolve()
                if resolved not in seen:
                    seen.add(resolved)
                    files.append(candidate)
    return files


def load_cloudtrail_events(paths: str | Path | Iterable[str | Path]) -> list[CloudTrailEvent]:
    """
    Load and normalize CloudTrail events from one or more files/directories.

    Duplicate records (same ``eventID``, or same source/name/ARNs when no id is
    present) are de-duplicated so repeated API calls do not inflate the policy.
    """
    events: list[CloudTrailEvent] = []
    seen_keys: set[str] = set()
    for log_file in iter_log_files(paths):
        try:
            text = _read_text(log_file)
        except (OSError, gzip.BadGzipFile) as exc:
            logger.warning("Could not read %s: %s", log_file, exc)
            continue
        for record in parse_cloudtrail_text(text, str(log_file)):
            event = normalize_event(record)
            if event is None:
                continue
            dedupe_key = event.event_id or "|".join(
                [event.event_source, event.event_name, ",".join(event.resource_arns)]
            )
            if dedupe_key in seen_keys:
                continue
            seen_keys.add(dedupe_key)
            events.append(event)
    return events
