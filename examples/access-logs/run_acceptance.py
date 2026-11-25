#!/usr/bin/env python3
"""
Acceptance demo: turn the three sample CloudTrail groups into least-privilege
policies and produce before/after permission comparisons.

Run from the repository root:

    uv run python examples/access-logs/run_acceptance.py

Artifacts are written to ``examples/access-logs/output/<group>/`` and the
aggregate comparison to ``examples/access-logs/output/comparison.md``.
The process exits non-zero if any group fails the acceptance criteria
(every observed call covered and zero unrelated actions).
"""

from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import Any

REPO_ROOT = Path(__file__).resolve().parents[2]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

HERE = Path(__file__).resolve().parent
LOG_DIR = HERE / "cloudtrail"
OUT_DIR = HERE / "output"

GROUPS = [
    ("01-data-pipeline", "Data pipeline (S3/DynamoDB/KMS/Lambda/EC2)"),
    ("02-web-api", "Web API (DynamoDB/SQS/Lambda/Secrets Manager/STS)"),
    ("03-security-ops", "Security ops (IAM/S3/EC2/SNS)"),
]


def main() -> int:
    import yaml

    from policy_sentry.access_logs.builder import (
        build_comparison_report,
        crud_template_from_cloudtrail,
        format_comparison_markdown,
        observed_actions,
        policy_from_cloudtrail,
        template_from_cloudtrail,
        wildcard_baseline_policy,
    )
    from policy_sentry.access_logs.cloudtrail import load_cloudtrail_events
    from policy_sentry.command.write_policy import write_policy_with_template

    aggregate: list[dict[str, Any]] = []
    markdown: list[str] = [
        "# CloudTrail -> least-privilege acceptance report",
        "",
        (
            "Baseline ('before') is the common rejected policy shape: service-wide "
            'wildcards (`s3:*`, `dynamodb:*`, ...) on `Resource: "*"`, synthesized '
            "from the services observed in each log group. The generated ('after') "
            "policy grants only the exact IAM actions that were called, scoped to "
            "the concrete resource ARNs present in the logs. Actions that AWS only "
            'supports on `Resource: "*"` (e.g. `ec2:Describe*`) remain wildcard-'
            "resource by necessity."
        ),
        "",
    ]

    all_verified = True
    for slug, title in GROUPS:
        log_file = LOG_DIR / f"{slug}.json"
        group_dir = OUT_DIR / slug
        group_dir.mkdir(parents=True, exist_ok=True)

        events = load_cloudtrail_events(log_file)
        policy = policy_from_cloudtrail(events)
        template = template_from_cloudtrail(events, name=slug)
        crud_template = crud_template_from_cloudtrail(events, name=f"{slug}-crud")
        roundtripped = write_policy_with_template(template)

        services = sorted({action.split(":", 1)[0] for action in observed_actions(events)})
        before = wildcard_baseline_policy(services)
        report = build_comparison_report(before, policy, events, group_name=title)
        report["template_roundtrip_matches_policy"] = json.dumps(policy, sort_keys=True) == json.dumps(
            roundtripped, sort_keys=True
        )

        (group_dir / "policy.json").write_text(json.dumps(policy, indent=4) + "\n", encoding="utf-8")
        (group_dir / "template.yml").write_text(yaml.safe_dump(template, sort_keys=False), encoding="utf-8")
        (group_dir / "crud-template.yml").write_text(yaml.safe_dump(crud_template, sort_keys=False), encoding="utf-8")
        (group_dir / "before-policy.json").write_text(json.dumps(before, indent=4) + "\n", encoding="utf-8")
        (group_dir / "comparison.json").write_text(json.dumps(report, indent=2, default=str) + "\n", encoding="utf-8")

        verified = bool(report.get("least_privilege_verified")) and report["template_roundtrip_matches_policy"]
        all_verified = all_verified and verified
        aggregate.append({"slug": slug, "title": title, "report": report, "verified": verified})
        markdown.extend((format_comparison_markdown(report), ""))

    # Summary table across all three groups.
    markdown.extend(
        (
            "## Cross-group summary",
            "",
            (
                "| Group | Calls covered | Actions before -> after | Reduction | "
                "Actions on `Resource:*` before -> after | Concrete ARNs | Verified |"
            ),
            "| --- | ---: | ---: | ---: | ---: | ---: | :---: |",
        )
    )
    for item in aggregate:
        report: dict[str, Any] = item["report"]
        coverage = report["coverage"]
        markdown.append(
            f"| {item['slug']} | {coverage['covered_calls']}/{coverage['total_calls']} "
            f"| {report['actions']['before']} -> {report['actions']['after']} "
            f"| {report['actions']['reduction_percent']}% "
            f"| {report['actions_on_wildcard_resource']['before']} -> "
            f"{report['actions_on_wildcard_resource']['after']} "
            f"| {report['concrete_resources']['after']} "
            f"| {'PASS' if item['verified'] else 'FAIL'} |"
        )
    markdown.append("")

    OUT_DIR.mkdir(parents=True, exist_ok=True)
    (OUT_DIR / "comparison.md").write_text("\n".join(markdown), encoding="utf-8")
    (OUT_DIR / "comparison.json").write_text(json.dumps(aggregate, indent=2, default=str) + "\n", encoding="utf-8")

    print("\n".join(markdown))
    print(f"\nArtifacts written under {OUT_DIR}")
    if not all_verified:
        print("ACCEPTANCE FAILED", file=sys.stderr)
        return 1
    print("ACCEPTANCE PASSED: 3/3 groups cover every call with zero unrelated actions.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
