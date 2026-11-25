"""
Acceptance tests for deriving least-privilege policies from CloudTrail logs.

These encode the task acceptance criteria for the three sample log groups:

* the generated policy covers every observed call (action + resource);
* it contains no unrelated actions;
* resource-supporting actions are pinned to concrete ARNs; and
* the generated template stays compatible with ``write-policy``.
"""

from __future__ import annotations

import gzip
import json
import tempfile
import unittest
from pathlib import Path
from typing import ClassVar

from policy_sentry.access_logs.builder import (
    build_comparison_report,
    crud_template_from_cloudtrail,
    evaluate_policy_coverage,
    expand_policy_actions,
    observed_actions,
    policy_from_cloudtrail,
    template_from_cloudtrail,
    wildcard_baseline_policy,
)
from policy_sentry.access_logs.cloudtrail import load_cloudtrail_events, map_event_to_action
from policy_sentry.command.write_policy import write_policy_with_template

REPO_ROOT = Path(__file__).resolve().parents[2]
LOG_DIR = REPO_ROOT / "examples" / "access-logs" / "cloudtrail"


class CloudTrailThreeGroupAcceptance(unittest.TestCase):
    maxDiff = None

    EXPECTED_ACTIONS: ClassVar[dict[str, set[str]]] = {
        "01-data-pipeline": {
            "s3:ListBucket",
            "s3:GetObject",
            "s3:PutObject",
            "dynamodb:PutItem",
            "dynamodb:GetItem",
            "dynamodb:Query",
            "kms:Decrypt",
            "lambda:InvokeFunction",
            "ec2:DescribeInstances",
            "ec2:DescribeRegions",
        },
        "02-web-api": {
            "sts:GetCallerIdentity",
            "dynamodb:GetItem",
            "dynamodb:Query",
            "dynamodb:PutItem",
            "sqs:SendMessage",
            "sqs:ReceiveMessage",
            "sqs:DeleteMessage",
            "lambda:InvokeFunction",
            "secretsmanager:GetSecretValue",
        },
        "03-security-ops": {
            "iam:GetRole",
            "iam:ListRoles",
            "s3:GetBucketPolicy",
            "s3:PutBucketPolicy",
            "ec2:DescribeSecurityGroups",
            "ec2:DescribeVpcs",
            "sns:Publish",
        },
    }

    WILDCARD_RESOURCE_ACTIONS: ClassVar[dict[str, set[str]]] = {
        "01-data-pipeline": {"ec2:DescribeInstances", "ec2:DescribeRegions"},
        "02-web-api": {"sts:GetCallerIdentity"},
        "03-security-ops": {"iam:ListRoles", "ec2:DescribeSecurityGroups", "ec2:DescribeVpcs"},
    }

    EXPECTED_ARNS: ClassVar[dict[str, list[str]]] = {
        "01-data-pipeline": [
            "arn:aws:s3:::acme-data-lake",
            "arn:aws:s3:::acme-data-lake/raw/events/2026/11/25/a.json",
            "arn:aws:s3:::acme-data-lake/curated/2026-11-25.parquet",
            "arn:aws:dynamodb:us-east-1:123456789012:table/PipelineCheckpoints",
            "arn:aws:kms:us-east-1:123456789012:key/11111111-2222-3333-4444-555555555555",
            "arn:aws:lambda:us-east-1:123456789012:function:etl-curator",
        ],
        "02-web-api": [
            "arn:aws:dynamodb:us-east-1:123456789012:table/Products",
            "arn:aws:dynamodb:us-east-1:123456789012:table/Orders",
            "arn:aws:sqs:us-east-1:123456789012:order-events",
            "arn:aws:lambda:us-east-1:123456789012:function:order-processor",
            "arn:aws:secretsmanager:us-east-1:123456789012:secret:prod-db-password-AbC12",
        ],
        "03-security-ops": [
            "arn:aws:iam::123456789012:role/deploy-role",
            "arn:aws:s3:::acme-audit-logs",
            "arn:aws:sns:us-east-1:123456789012:security-alerts",
        ],
    }

    def _run_group(self, slug: str) -> None:
        log_file = LOG_DIR / f"{slug}.json"
        self.assertTrue(log_file.exists(), f"missing fixture {log_file}")
        events = load_cloudtrail_events(log_file)
        self.assertGreater(len(events), 0)

        # 1. Event -> IAM action mapping is complete and exact.
        self.assertEqual(
            {a.lower() for a in observed_actions(events)}, {a.lower() for a in self.EXPECTED_ACTIONS[slug]}
        )

        policy = policy_from_cloudtrail(events)

        # 2. Policy grants exactly the observed actions (no unrelated actions).
        granted = expand_policy_actions(policy)
        self.assertEqual(granted, {a.lower() for a in self.EXPECTED_ACTIONS[slug]})
        action_occurrences = [action.lower() for statement in policy["Statement"] for action in statement["Action"]]
        self.assertEqual(len(action_occurrences), len(set(action_occurrences)))

        # 3. Every observed call is covered, including resource matching.
        coverage = evaluate_policy_coverage(policy, events)
        self.assertTrue(coverage["all_covered"], coverage["missing"])
        self.assertEqual(coverage["covered_calls"], coverage["total_calls"])
        self.assertEqual(coverage["extra_actions"], [])
        self.assertFalse(coverage["has_unrelated_actions"])

        # 4. Resource convergence: concrete ARNs, no ARN format placeholders.
        all_resources = [resource for statement in policy["Statement"] for resource in statement["Resource"]]
        for resource in all_resources:
            if resource != "*":
                self.assertTrue(resource.startswith("arn:"), resource)
                self.assertNotIn("${", resource)
        for arn in self.EXPECTED_ARNS[slug]:
            self.assertIn(arn, all_resources, f"expected ARN {arn} in policy resources")

        # 5. The only Resource:'*' actions are the genuinely wildcard-only calls.
        wildcard_actions: set[str] = set()
        for statement in policy["Statement"]:
            if statement["Resource"] == ["*"]:
                wildcard_actions.update(a.lower() for a in statement["Action"])
        self.assertEqual(
            wildcard_actions,
            {a.lower() for a in self.WILDCARD_RESOURCE_ACTIONS[slug]},
        )

        # 6. Extended template round-trips to the exact same policy.
        template = template_from_cloudtrail(events, name=slug)
        self.assertEqual(template["mode"], "actions")
        self.assertIn("resource-arns", template)
        roundtripped = write_policy_with_template(template)
        self.assertEqual(
            json.dumps(policy, sort_keys=True),
            json.dumps(roundtripped, sort_keys=True),
        )

        # 7. Plain classic actions template still works with stock write-policy.
        plain_template = template_from_cloudtrail(events, with_resource_arns=False)
        self.assertNotIn("resource-arns", plain_template)
        plain_policy = write_policy_with_template(plain_template)
        self.assertTrue({a.lower() for a in self.EXPECTED_ACTIONS[slug]}.issubset(expand_policy_actions(plain_policy)))

        # 8. Comparison shows real convergence and a verified result.
        services = sorted({a.split(":", 1)[0] for a in self.EXPECTED_ACTIONS[slug]})
        before = wildcard_baseline_policy(services)
        report = build_comparison_report(before, policy, events, group_name=slug)
        self.assertTrue(report["least_privilege_verified"])
        self.assertGreater(report["actions"]["before"], report["actions"]["after"])
        self.assertGreater(report["actions"]["reduction_percent"], 90.0)
        self.assertGreater(report["concrete_resources"]["after"], 0)
        self.assertLess(
            report["actions_on_wildcard_resource"]["after"],
            report["actions_on_wildcard_resource"]["before"],
        )

    def test_group_01_data_pipeline(self) -> None:
        self._run_group("01-data-pipeline")

    def test_group_02_web_api(self) -> None:
        self._run_group("02-web-api")

    def test_group_03_security_ops(self) -> None:
        self._run_group("03-security-ops")

    def test_crud_template_is_classic_schema_and_covers(self) -> None:
        for slug in self.EXPECTED_ACTIONS:
            events = load_cloudtrail_events(LOG_DIR / f"{slug}.json")
            template = crud_template_from_cloudtrail(events, name=slug)
            # Pure classic CRUD schema: no extension keys required.
            self.assertEqual(template["mode"], "crud")
            self.assertNotIn("resource-arns", template)
            for key in ("read", "write", "list", "tagging", "permissions-management"):
                self.assertIn(key, template)
            # Stock write-policy renders it and it still covers every call.
            policy = write_policy_with_template(template)
            coverage = evaluate_policy_coverage(policy, events)
            self.assertTrue(coverage["all_covered"], coverage["missing"])


class CloudTrailParsingFormats(unittest.TestCase):
    def test_jsonl_and_directory_and_gzip(self) -> None:
        record = {
            "eventSource": "s3.amazonaws.com",
            "eventName": "GetObject",
            "eventID": "abc",
            "resources": [{"ARN": "arn:aws:s3:::demo-bucket/path/file.txt"}],
        }
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            (tmp_path / "one.jsonl").write_text(
                json.dumps(record) + "\n" + json.dumps({**record, "eventID": "def"}) + "\n",
                encoding="utf-8",
            )
            nested = tmp_path / "nested"
            nested.mkdir()
            with gzip.open(nested / "two.json.gz", "wt", encoding="utf-8") as handle:
                json.dump({"Records": [{**record, "eventID": "ghi"}]}, handle)

            events = load_cloudtrail_events(tmp_path)
            ids = {event.event_id for event in events}
            self.assertEqual(ids, {"abc", "def", "ghi"})
            self.assertTrue(all(event.action == "s3:GetObject" for event in events))
            self.assertEqual(
                events[0].resource_arns,
                ["arn:aws:s3:::demo-bucket/path/file.txt"],
            )

    def test_full_wildcard_admin_baseline_expands_to_all_actions(self) -> None:
        baseline = wildcard_baseline_policy()
        # The bundled IAM database tracks ~21k actions; just assert a large,
        # stable lower bound so the comparison clearly demonstrates reduction.
        self.assertGreater(len(expand_policy_actions(baseline)), 10_000)

    def test_known_cloudtrail_to_iam_name_corrections(self) -> None:
        # S3 listing API names do not match their IAM action names 1:1.
        self.assertEqual(map_event_to_action("s3.amazonaws.com", "ListBuckets"), "s3:ListAllMyBuckets")
        self.assertEqual(map_event_to_action("s3.amazonaws.com", "ListObjectsV2"), "s3:ListBucket")
        # monitoring.amazonaws.com is the CloudWatch event source.
        self.assertEqual(map_event_to_action("monitoring.amazonaws.com", "ListMetrics"), "cloudwatch:ListMetrics")
        # Direct mapping for ordinary events.
        self.assertEqual(map_event_to_action("sqs.amazonaws.com", "SendMessage"), "sqs:SendMessage")
        # Unknown events resolve to None rather than a fabricated action.
        self.assertIsNone(map_event_to_action("nonexistent-svc.amazonaws.com", "DoThing"))


if __name__ == "__main__":
    unittest.main()
