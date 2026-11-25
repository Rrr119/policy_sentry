"""
Derive least-privilege IAM policies from access logs.

The initial implementation understands AWS CloudTrail events. It converts the
recorded API calls into exact IAM actions and binds those actions to the
resource ARNs that actually appear in the logs, then renders the result with
the standard :class:`policy_sentry.writing.sid_group.SidGroup` machinery so the
output stays compatible with Policy Sentry templates.
"""

from __future__ import annotations

from policy_sentry.access_logs.builder import (
    build_action_resource_arn_map,
    build_comparison_report,
    crud_template_from_cloudtrail,
    evaluate_policy_coverage,
    format_comparison_markdown,
    policy_from_cloudtrail,
    template_from_cloudtrail,
)
from policy_sentry.access_logs.cloudtrail import (
    CloudTrailEvent,
    extract_arns,
    load_cloudtrail_events,
    map_event_to_action,
)

__all__ = [
    "CloudTrailEvent",
    "build_action_resource_arn_map",
    "build_comparison_report",
    "crud_template_from_cloudtrail",
    "evaluate_policy_coverage",
    "extract_arns",
    "format_comparison_markdown",
    "load_cloudtrail_events",
    "map_event_to_action",
    "policy_from_cloudtrail",
    "template_from_cloudtrail",
]
