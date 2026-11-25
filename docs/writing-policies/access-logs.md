# Least privilege from CloudTrail access logs

Policy Sentry can reverse-engineer a least-privilege policy directly from AWS
CloudTrail events. It maps each recorded `eventSource`/`eventName` to a canonical
IAM action, collects the resource ARNs that appear in the records, and binds the
exact observed actions to those concrete ARNs. This is useful when the existing
policy is wildcard-heavy and repeatedly rejected by security review.

## CLI

```bash
policy_sentry write-policy-from-logs \
  --input-file trail.json \
  --compare \
  --template-out template.yml
```

`--input-file` accepts a CloudTrail `{"Records": [...]}` file, a JSON-Lines file,
a `.json.gz` delivered log, or a directory (scanned recursively) and may be
passed multiple times.

Useful flags:

* `--compare` prints a Markdown before/after comparison (on stderr).
* `--baseline-policy before.json` compares against the real rejected policy;
  otherwise a service-wildcard baseline is synthesized from the logs.
* `--comparison-json` / `--comparison-markdown` write the report to disk.
* `--template` prints a Policy Sentry actions-mode YAML template.
* `--template-kind crud` prints the classic ARN + CRUD-level template.
* `--plain-template` omits the `resource-arns` extension.
* `--strict` exits non-zero if events cannot be mapped or a call is uncovered.

The command is also registered under the alias
`generate-policy-from-cloudtrail`.

## Library

```python
from policy_sentry.access_logs import (
    load_cloudtrail_events,
    policy_from_cloudtrail,
    template_from_cloudtrail,
    evaluate_policy_coverage,
    build_comparison_report,
)
from policy_sentry.access_logs.builder import wildcard_baseline_policy

events = load_cloudtrail_events("./cloudtrail-logs/")
policy = policy_from_cloudtrail(events)

coverage = evaluate_policy_coverage(policy, events)
assert coverage["all_covered"]          # every logged call is allowed
assert coverage["extra_actions"] == []  # and nothing unrelated was added

services = sorted({e.action.split(":", 1)[0] for e in events if e.action})
report = build_comparison_report(wildcard_baseline_policy(services), policy, events)
print(report["actions"], report["concrete_resources"])
```

## Template compatibility

`template_from_cloudtrail()` returns a standard `mode: actions` template. It also
populates an optional, backward-compatible `resource-arns` map that this version
of Policy Sentry uses to preserve concrete ARN constraints through
`write-policy`. Omitting it (`with_resource_arns=False`) produces a classic
actions template, and `crud_template_from_cloudtrail()` produces the traditional
CRUD template where each ARN is placed in its inferred access-level bucket.

!!! note
    The CRUD form intentionally grants all actions of the inferred level for an
    ARN, following Policy Sentry's historical approach. The default log-derived
    policy instead keeps only the exact actions that were observed.

## Worked example and acceptance

Three sample CloudTrail groups live under
[`examples/access-logs/`](https://github.com/salesforce/policy_sentry/tree/master/examples/access-logs),
together with an acceptance harness and a before/after report:

```bash
uv run python examples/access-logs/run_acceptance.py
```

| Group | Calls covered | Actions before -> after | Reduction | Actions on `Resource:"*"` before -> after | Concrete ARNs |
| --- | ---: | ---: | ---: | ---: | ---: |
| 01-data-pipeline | 11/11 | 1223 -> 10 | 99.18% | 1223 -> 2 | 7 |
| 02-web-api | 9/9 | 253 -> 9 | 96.44% | 253 -> 1 | 5 |
| 03-security-ops | 7/7 | 1201 -> 7 | 99.42% | 1201 -> 3 | 3 |
