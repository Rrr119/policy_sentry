# Generate least-privilege policies from CloudTrail logs

This folder contains three representative CloudTrail log groups and the
acceptance harness for log-driven policy generation:

| File | Workload | Services |
| --- | --- | --- |
| `cloudtrail/01-data-pipeline.json` | Data pipeline | S3, DynamoDB, KMS, Lambda, EC2 |
| `cloudtrail/02-web-api.json` | Web API | DynamoDB, SQS, Lambda, Secrets Manager, STS |
| `cloudtrail/03-security-ops.json` | Security operations | IAM, S3, EC2, SNS |

The generator maps each CloudTrail `eventSource`/`eventName` to a canonical IAM
action, extracts the resource ARNs that actually appear in the records, and
renders an **exact-action** policy scoped to those concrete ARNs. Calls AWS only
supports on `Resource: "*"` (for example `ec2:Describe*` and
`sts:GetCallerIdentity`) remain wildcard-resource by necessity.

## Run the acceptance harness

```bash
# from the repository root
uv run python examples/access-logs/run_acceptance.py
```

It writes, for every group, a `policy.json`, a compatible `template.yml`, a
classic `crud-template.yml`, a `before-policy.json`, and a `comparison.json`
under `output/<group>/`, plus the aggregate `output/comparison.md`. It exits
non-zero unless all three groups cover every call with zero unrelated actions.

The same criteria are encoded as pytest acceptance tests in
`test/access_logs/test_cloudtrail_acceptance.py`.

## Use the CLI on your own logs

```bash
policy_sentry write-policy-from-logs \
  --input-file cloudtrail/01-data-pipeline.json \
  --compare \
  --template-out template.yml \
  --comparison-markdown comparison.md

# a whole CloudTrail prefix/directory (recurses), JSONL and .json.gz work too:
policy_sentry write-policy-from-logs -i ./cloudtrail-logs/ --strict

# emit the classic level-based CRUD template instead:
policy_sentry write-policy-from-logs -i logs.json --template --template-kind crud
```

`--strict` fails if any event cannot be mapped to an IAM action or the generated
policy does not cover every call.

## Library API

```python
from policy_sentry.access_logs import (
    load_cloudtrail_events,
    policy_from_cloudtrail,
    template_from_cloudtrail,
    evaluate_policy_coverage,
    build_comparison_report,
)
from policy_sentry.access_logs.builder import wildcard_baseline_policy

events = load_cloudtrail_events(["cloudtrail/01-data-pipeline.json"])
policy = policy_from_cloudtrail(events)
coverage = evaluate_policy_coverage(policy, events)
assert coverage["all_covered"] and not coverage["extra_actions"]
```

## Compatibility with existing templates

`template_from_cloudtrail()` returns a normal `mode: actions` template. By
default it adds an optional `resource-arns` mapping that binds each action to
the concrete log ARNs; this is a backward-compatible extension understood by
this version of Policy Sentry:

```yaml
mode: actions
name: 02-web-api
actions:
  - dynamodb:GetItem
  - sqs:SendMessage
resource-arns:
  dynamodb:GetItem:
    - arn:aws:dynamodb:us-east-1:123456789012:table/Products
  sqs:SendMessage:
    - arn:aws:sqs:us-east-1:123456789012:order-events
```

That template round-trips through the existing command unchanged:

```bash
policy_sentry write-policy --input-file output/02-web-api/template.yml
```

Pass `with_resource_arns=False` to get the plain, universally-supported
`mode: actions` template, or use `crud_template_from_cloudtrail()` for the
classic ARN-plus-CRUD-level template (which intentionally expands sibling
actions and is therefore broader than the exact-action form).

## Before/after comparison (sample run)

"Before" is the commonly rejected service-wildcard policy
(`s3:*`, `dynamodb:*`, ... on `Resource: "*"`).

| Group | Calls covered | Actions before -> after | Reduction | Actions on `Resource:*` before -> after | Concrete ARNs | Verified |
| --- | ---: | ---: | ---: | ---: | ---: | :---: |
| 01-data-pipeline | 11/11 | 1223 -> 10 | 99.18% | 1223 -> 2 | 7 | PASS |
| 02-web-api | 9/9 | 253 -> 9 | 96.44% | 253 -> 1 | 5 | PASS |
| 03-security-ops | 7/7 | 1201 -> 7 | 99.42% | 1201 -> 3 | 3 | PASS |

The full per-group reports are in `output/comparison.md` and
`output/*/comparison.json`.
