"""
Turn normalized access-log events into least-privilege policies and comparisons.

This is the main library entry point for the access-log reverse-engineering
feature. It produces:

* an exact-action, ARN-converged IAM policy;
* a Policy Sentry actions-mode template (optionally carrying the backward
  compatible ``resource-arns`` extension) that round-trips through
  :func:`policy_sentry.command.write_policy.write_policy_with_template`;
* coverage / no-extra-action verification against the original events; and
* a before/after comparison describing how much the wildcard policy shrank.
"""

from __future__ import annotations

import fnmatch
from collections.abc import Iterable
from pathlib import Path
from typing import Any

from policy_sentry.access_logs.cloudtrail import CloudTrailEvent, load_cloudtrail_events
from policy_sentry.analysis.expand import determine_actions_to_expand
from policy_sentry.querying.actions import get_action_data
from policy_sentry.util.arns import arn_matches_format
from policy_sentry.writing.sid_group import SidGroup


def _coerce_events(source: object) -> list[CloudTrailEvent]:
    if isinstance(source, CloudTrailEvent):
        return [source]
    if isinstance(source, (str, Path)):
        return load_cloudtrail_events(source)
    if isinstance(source, Iterable):
        items = list(source)
        if all(isinstance(item, CloudTrailEvent) for item in items):
            return [item for item in items if isinstance(item, CloudTrailEvent)]
        paths = [item for item in items if isinstance(item, (str, Path))]
        return load_cloudtrail_events(paths)
    msg = f"Unsupported access-log source: {type(source)!r}"
    raise TypeError(msg)


def observed_actions(events: Iterable[CloudTrailEvent]) -> list[str]:
    """Return the sorted, de-duplicated canonical IAM actions present in events."""
    return sorted({event.action for event in events if event.action})


def build_action_resource_arn_map(events: Iterable[CloudTrailEvent]) -> dict[str, list[str]]:
    """
    Map every observed action to the concrete log ARNs that can constrain it.

    An ARN is only attached to an action when it matches one of that action's
    resource-specific ARN formats in the IAM database. Unrelated ARNs that
    merely appear in the same event (e.g. the caller's role ARN) are filtered
    out automatically.
    """
    mapping: dict[str, list[str]] = {}
    for event in events:
        if not event.action:
            continue
        action = event.action
        service_name, action_name = action.split(":", 1)
        rows = get_action_data(service_name, action_name).get(service_name, [])
        matched: list[str] = mapping.setdefault(action, [])
        for arn in event.resource_arns:
            if arn in matched:
                continue
            for row in rows:
                raw_arn_format = row["resource_arn_format"]
                if raw_arn_format == "*":
                    continue
                if arn_matches_format(arn, raw_arn_format):
                    matched.append(arn)
                    break
    return {action: arns for action, arns in sorted(mapping.items()) if arns}


def unmapped_events(events: Iterable[CloudTrailEvent]) -> list[dict[str, str]]:
    """Describe log calls that could not be mapped to a known IAM action."""
    return [{"eventSource": event.event_source, "eventName": event.event_name} for event in events if not event.action]


def policy_from_cloudtrail(
    source: str | Path | Iterable[str | Path] | Iterable[CloudTrailEvent],
    *,
    include_dependent_actions: bool = False,
) -> dict[str, Any]:
    """
    Generate the ARN-converged, exact-action least-privilege policy from logs.

    Arguments:
        source: A log file/directory path, an iterable of paths, or an iterable
            of pre-parsed :class:`CloudTrailEvent` objects.
        include_dependent_actions: Also grant the dependent actions AWS says the
            observed actions rely on. Defaults to ``False`` so the result only
            contains actions that were actually called.
    """
    events = _coerce_events(source)
    actions = observed_actions(events)
    arn_map = build_action_resource_arn_map(events)
    sid_group = SidGroup()
    return sid_group.add_by_actions_and_arns(
        actions,
        arn_map,
        include_dependent_actions=include_dependent_actions,
    )


def template_from_cloudtrail(
    source: str | Path | Iterable[str | Path] | Iterable[CloudTrailEvent],
    *,
    name: str = "PolicyFromAccessLogs",
    with_resource_arns: bool = True,
) -> dict[str, Any]:
    """
    Return a Policy Sentry actions-mode template derived from the logs.

    When ``with_resource_arns`` is true (default) the template includes the
    optional ``resource-arns`` mapping, which this version of Policy Sentry
    understands and uses to preserve concrete ARN constraints through
    ``write-policy``. Set it to ``False`` to emit a plain, universally
    compatible ``mode: actions`` template (ARN formats are rendered by the
    standard engine instead of concrete ARNs).
    """
    events = _coerce_events(source)
    actions = observed_actions(events)
    template: dict[str, Any] = {
        "mode": "actions",
        "name": name,
        "actions": actions,
    }
    if with_resource_arns:
        arn_map = build_action_resource_arn_map(events)
        if arn_map:
            template["resource-arns"] = dict(sorted(arn_map.items()))
    return template


_ACCESS_LEVEL_TO_CRUD_BUCKET = {
    "Read": "read",
    "Write": "write",
    "List": "list",
    "Tagging": "tagging",
    "Permissions management": "permissions-management",
}


def crud_template_from_cloudtrail(
    source: str | Path | Iterable[str | Path] | Iterable[CloudTrailEvent],
    *,
    name: str = "CrudPolicyFromAccessLogs",
) -> dict[str, Any]:
    """
    Build the classic Policy Sentry CRUD template from the logs.

    This is the schema-only compatibility path described in the project
    roadmap: each observed ARN is dropped into the CRUD bucket matching the
    inferred access level of the action that touched it. Running this through
    ``write-policy`` grants *all* actions of that level for the ARN, so it is
    broader than :func:`template_from_cloudtrail` with ``resource-arns``; prefer
    that exact form when the acceptance bar is "no unrelated actions".

    Actions AWS only supports on ``*`` land in ``wildcard-only.single-actions``;
    resource-supporting actions for which the logs exposed no ARN go to
    ``skip-resource-constraints`` so they are not silently dropped.
    """
    events = _coerce_events(source)
    actions = observed_actions(events)
    arn_map = build_action_resource_arn_map(events)

    buckets: dict[str, list[str]] = {key: [] for key in _ACCESS_LEVEL_TO_CRUD_BUCKET.values()}
    wildcard_only: list[str] = []
    skip_constraints: list[str] = []

    for action in actions:
        service_name, action_name = action.split(":", 1)
        rows = get_action_data(service_name, action_name).get(service_name, [])
        resource_rows = [row for row in rows if row["resource_arn_format"] != "*"]
        placed = False
        for row in resource_rows:
            bucket = _ACCESS_LEVEL_TO_CRUD_BUCKET.get(row["access_level"])
            if bucket is None:
                continue
            for arn in arn_map.get(action, []):
                if not arn_matches_format(arn, row["resource_arn_format"]):
                    continue
                placed = True
                if arn not in buckets[bucket]:
                    buckets[bucket].append(arn)
        if placed:
            continue
        if resource_rows:
            skip_constraints.append(action)
        else:
            wildcard_only.append(action)

    template: dict[str, Any] = {"mode": "crud", "name": name}
    for bucket_name in ("read", "write", "list", "tagging", "permissions-management"):
        template[bucket_name] = sorted(buckets[bucket_name])
    template["wildcard-only"] = {"single-actions": sorted(wildcard_only)}
    template["skip-resource-constraints"] = sorted(skip_constraints)
    return template


def wildcard_baseline_policy(services: Iterable[str] | None = None) -> dict[str, Any]:
    """
    Build the typical rejected "before" policy.

    With no arguments this is the full administrator wildcard
    (``Action: "*"`` / ``Resource: "*"``). When ``services`` are supplied it
    renders the equally common service-wide wildcard form
    (``s3:*`` ... on ``Resource: "*"``).
    """
    actions = sorted({f"{service}:*" for service in services}) if services else ["*"]
    return {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Sid": "WildcardBaseline",
                "Effect": "Allow",
                "Action": actions,
                "Resource": ["*"],
            }
        ],
    }


def _statement_actions(statement: dict[str, Any]) -> list[str]:
    action_clause = statement.get("Action")
    if isinstance(action_clause, str):
        return [action_clause]
    if isinstance(action_clause, list):
        return [str(item) for item in action_clause]
    return []


def expand_policy_actions(policy: dict[str, Any]) -> set[str]:
    """Return the lower-cased set of concrete Allow actions a policy grants."""
    patterns: list[str] = []
    for statement in policy.get("Statement", []):
        if isinstance(statement, dict) and statement.get("Effect", "Allow") != "Deny":
            patterns.extend(_statement_actions(statement))
    return {action.lower() for action in determine_actions_to_expand(patterns)}


def _statement_resources(statement: dict[str, Any]) -> list[str]:
    resource_clause = statement.get("Resource")
    if isinstance(resource_clause, str):
        return [resource_clause]
    if isinstance(resource_clause, list):
        return [str(item) for item in resource_clause]
    return []


def evaluate_policy_coverage(
    policy: dict[str, Any],
    source: str | Path | Iterable[str | Path] | Iterable[CloudTrailEvent],
) -> dict[str, Any]:
    """
    Verify that every observed call is allowed by ``policy``.

    A call is covered when some Allow statement (1) allows its mapped action and
    (2) either lists ``Resource: "*"`` or contains a resource pattern that
    matches at least one ARN from the event. Calls that could not be mapped to
    an IAM action are reported separately and counted as uncovered.
    """
    events = _coerce_events(source)
    allowed_actions = expand_policy_actions(policy)

    action_statements: dict[str, list[dict[str, Any]]] = {}
    for statement in policy.get("Statement", []):
        if not isinstance(statement, dict) or statement.get("Effect", "Allow") == "Deny":
            continue
        expanded = {action.lower() for action in determine_actions_to_expand(_statement_actions(statement))}
        for action in expanded:
            action_statements.setdefault(action, []).append(statement)

    covered: list[dict[str, str]] = []
    missing: list[dict[str, str]] = []
    observed_set = set(observed_actions(events))

    for event in events:
        label = f"{event.event_source}:{event.event_name}"
        if not event.action:
            missing.append({"call": label, "reason": "unmapped-event-to-iam-action"})
            continue
        action_lower = event.action.lower()
        if action_lower not in allowed_actions:
            missing.append({"call": label, "action": event.action, "reason": "action-not-allowed"})
            continue

        covering_statements = action_statements.get(action_lower, [])
        resource_ok = not event.resource_arns  # nothing concrete to check against
        for statement in covering_statements:
            resources = _statement_resources(statement)
            if "*" in resources:
                resource_ok = True
                break
            for pattern in resources:
                if any(fnmatch.fnmatchcase(arn, pattern) for arn in event.resource_arns):
                    resource_ok = True
                    break
            if resource_ok:
                break
        if not resource_ok:
            missing.append(
                {
                    "call": label,
                    "action": event.action,
                    "reason": "no-resource-match",
                    "arns": ",".join(event.resource_arns),
                }
            )
        else:
            covered.append({"call": label, "action": event.action})

    extra_actions = sorted(allowed_actions - {action.lower() for action in observed_set})
    return {
        "total_calls": len(events),
        "covered_calls": len(covered),
        "all_covered": not missing,
        "missing": missing,
        "extra_actions": extra_actions,
        "has_unrelated_actions": bool(extra_actions),
    }


def summarize_policy(policy: dict[str, Any]) -> dict[str, Any]:
    """Compute compact size/scope metrics for an IAM policy."""
    statements = [s for s in policy.get("Statement", []) if isinstance(s, dict)]
    expanded_actions = expand_policy_actions(policy)
    services = sorted({action.split(":", 1)[0] for action in expanded_actions if ":" in action})

    wildcard_resource_statements = 0
    concrete_resources: set[str] = set()
    wildcard_resource_actions: set[str] = set()
    for statement in statements:
        resources = _statement_resources(statement)
        if "*" in resources:
            wildcard_resource_statements += 1
            wildcard_resource_actions.update(
                action.lower() for action in determine_actions_to_expand(_statement_actions(statement))
            )
        for resource in resources:
            if resource != "*":
                concrete_resources.add(resource)

    raw_action_patterns: list[str] = []
    full_action_wildcard = False
    for statement in statements:
        actions = _statement_actions(statement)
        raw_action_patterns.extend(actions)
        if any(action.strip() == "*" for action in actions):
            full_action_wildcard = True

    return {
        "statement_count": len(statements),
        "action_pattern_count": len(raw_action_patterns),
        "expanded_action_count": len(expanded_actions),
        "service_count": len(services),
        "services": services,
        "wildcard_resource_statements": wildcard_resource_statements,
        "wildcard_resource_action_count": len(wildcard_resource_actions),
        "concrete_resource_count": len(concrete_resources),
        "concrete_resources": sorted(concrete_resources),
        "full_action_wildcard": full_action_wildcard,
    }


def build_comparison_report(
    before_policy: dict[str, Any],
    after_policy: dict[str, Any],
    source: str | Path | Iterable[str | Path] | Iterable[CloudTrailEvent] | None = None,
    *,
    group_name: str | None = None,
) -> dict[str, Any]:
    """
    Build the before/after convergence comparison, optionally with coverage.
    """
    before = summarize_policy(before_policy)
    after = summarize_policy(after_policy)

    before_actions = before["expanded_action_count"]
    after_actions = after["expanded_action_count"]
    actions_removed = max(before_actions - after_actions, 0)
    action_reduction_pct = round(100.0 * actions_removed / before_actions, 2) if before_actions else 0.0

    report: dict[str, Any] = {
        "group": group_name,
        "actions": {
            "before": before_actions,
            "after": after_actions,
            "removed": actions_removed,
            "reduction_percent": action_reduction_pct,
        },
        "statements": {"before": before["statement_count"], "after": after["statement_count"]},
        "services": {"before": before["service_count"], "after": after["service_count"]},
        "wildcard_resource_statements": {
            "before": before["wildcard_resource_statements"],
            "after": after["wildcard_resource_statements"],
        },
        "actions_on_wildcard_resource": {
            "before": before["wildcard_resource_action_count"],
            "after": after["wildcard_resource_action_count"],
        },
        "concrete_resources": {
            "before": before["concrete_resource_count"],
            "after": after["concrete_resource_count"],
        },
        "before_summary": before,
        "after_summary": after,
    }

    if source is not None:
        coverage = evaluate_policy_coverage(after_policy, source)
        report["coverage"] = coverage
        report["least_privilege_verified"] = bool(coverage["all_covered"] and not coverage["has_unrelated_actions"])
    return report


def format_comparison_markdown(report: dict[str, Any]) -> str:
    """Render a single-group comparison report as a Markdown table."""
    title = report.get("group") or "Access-log policy"
    actions = report["actions"]
    lines = [
        f"### {title}",
        "",
        "| Metric | Before (wildcard) | After (least privilege) |",
        "| --- | ---: | ---: |",
        f"| Granted actions (expanded) | {actions['before']} | {actions['after']} |",
        f"| Action reduction | — | {actions['removed']} ({actions['reduction_percent']}%) |",
        f"| Statements | {report['statements']['before']} | {report['statements']['after']} |",
        f"| Services | {report['services']['before']} | {report['services']['after']} |",
        (
            f'| `Resource: "*"` statements | {report["wildcard_resource_statements"]["before"]} | '
            f"{report['wildcard_resource_statements']['after']} |"
        ),
        (
            f'| Actions on `Resource: "*"` | {report["actions_on_wildcard_resource"]["before"]} | '
            f"{report['actions_on_wildcard_resource']['after']} |"
        ),
        (
            f"| Concrete resource ARNs | {report['concrete_resources']['before']} | "
            f"{report['concrete_resources']['after']} |"
        ),
    ]
    coverage = report.get("coverage")
    if coverage:
        lines.extend(
            [
                "",
                (
                    f"Coverage: {coverage['covered_calls']}/{coverage['total_calls']} observed calls covered; "
                    f"unrelated actions: {len(coverage['extra_actions'])}; "
                    f"least-privilege verified: {report.get('least_privilege_verified')}"
                ),
            ]
        )
        if coverage["missing"]:
            lines.extend(["", "Missing calls:"])
            lines.extend(f"- `{item['call']}` — {item['reason']}" for item in coverage["missing"])
        if coverage["extra_actions"]:
            lines.extend(["", "Extra actions:"])
            lines.extend(f"- `{action}`" for action in coverage["extra_actions"])
    return "\n".join(lines)
