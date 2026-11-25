"""
Generate a least-privilege IAM policy from CloudTrail access logs.

This is the command-line front end for the access-log reverse-engineering
feature. It can emit the converged policy, a Policy Sentry compatible actions
template, and a before/after wildcard-vs-least-privilege comparison.
"""

from __future__ import annotations

import json
import logging
import sys
from pathlib import Path
from typing import Any

import click
import yaml

from policy_sentry import set_stream_logger
from policy_sentry.access_logs.builder import (
    build_comparison_report,
    crud_template_from_cloudtrail,
    format_comparison_markdown,
    observed_actions,
    policy_from_cloudtrail,
    template_from_cloudtrail,
    unmapped_events,
    wildcard_baseline_policy,
)
from policy_sentry.access_logs.cloudtrail import load_cloudtrail_events
from policy_sentry.util.file import read_yaml_file

logger = logging.getLogger(__name__)


def _dump_policy(policy: dict[str, Any], fmt: str) -> str:
    if fmt == "yaml":
        return yaml.safe_dump(policy, sort_keys=False)
    return json.dumps(policy, indent=4)


@click.command("write-policy-from-logs")
@click.option(
    "--input-file",
    "-i",
    "input_files",
    multiple=True,
    required=True,
    type=click.Path(exists=True),
    help="CloudTrail log file, directory, JSONL or .json.gz. Repeatable.",
)
@click.option("--name", default="PolicyFromAccessLogs", show_default=True, help="Template/policy name label.")
@click.option(
    "--fmt",
    type=click.Choice(["json", "yaml"]),
    default="json",
    show_default=True,
    help="Output format for the generated policy.",
)
@click.option(
    "--include-dependent-actions",
    is_flag=True,
    default=False,
    help="Also include AWS-documented dependent actions (off by default to avoid unobserved actions).",
)
@click.option(
    "--template",
    "emit_template",
    is_flag=True,
    default=False,
    help="Print a compatible Policy Sentry actions-mode YAML template instead of the JSON policy.",
)
@click.option(
    "--plain-template",
    is_flag=True,
    default=False,
    help="Omit the resource-arns extension so the template uses only the classic actions schema.",
)
@click.option(
    "--template-kind",
    type=click.Choice(["actions", "crud"]),
    default="actions",
    show_default=True,
    help="Template family to emit: exact 'actions' (with resource-arns) or classic level-based 'crud'.",
)
@click.option("--template-out", type=click.Path(dir_okay=False), help="Write the YAML template to this path.")
@click.option("--output-policy", "--out", type=click.Path(dir_okay=False), help="Write the policy to this file.")
@click.option(
    "--baseline-policy",
    type=click.Path(exists=True, dir_okay=False),
    help="The existing broad/wildcard policy to compare against. Defaults to service-level wildcards from the logs.",
)
@click.option("--compare", is_flag=True, default=False, help="Print a before/after Markdown comparison to stderr.")
@click.option("--comparison-json", type=click.Path(dir_okay=False), help="Write the comparison report as JSON.")
@click.option("--comparison-markdown", type=click.Path(dir_okay=False), help="Write the comparison report as Markdown.")
@click.option(
    "--strict",
    is_flag=True,
    default=False,
    help="Exit with a non-zero status if events cannot be mapped or coverage is incomplete.",
)
@click.option(
    "--verbose",
    "-v",
    type=click.Choice(["critical", "error", "warning", "info", "debug"], case_sensitive=False),
)
def write_policy_from_logs(
    input_files: tuple[str, ...],
    name: str,
    fmt: str,
    include_dependent_actions: bool,
    emit_template: bool,
    plain_template: bool,
    template_kind: str,
    template_out: str | None,
    output_policy: str | None,
    baseline_policy: str | None,
    compare: bool,
    comparison_json: str | None,
    comparison_markdown: str | None,
    strict: bool,
    verbose: str | None,
) -> None:
    """Derive a least-privilege, ARN-scoped IAM policy from CloudTrail access logs."""
    if verbose:
        set_stream_logger(level=getattr(logging, verbose.upper()))

    events = load_cloudtrail_events(list(input_files))
    if not events:
        raise click.ClickException(f"No CloudTrail events found in: {', '.join(input_files)}")

    policy = policy_from_cloudtrail(events, include_dependent_actions=include_dependent_actions)
    if template_kind == "crud":
        template = crud_template_from_cloudtrail(events, name=name)
    else:
        template = template_from_cloudtrail(events, name=name, with_resource_arns=not plain_template)

    baseline: dict[str, Any]
    if baseline_policy:
        baseline = read_yaml_file(baseline_policy)
    else:
        services = sorted({action.split(":", 1)[0] for action in observed_actions(events)})
        baseline = wildcard_baseline_policy(services)

    report = build_comparison_report(baseline, policy, events, group_name=name)
    unmapped = unmapped_events(events)
    if unmapped:
        report["unmapped_events"] = unmapped

    if template_out:
        Path(template_out).write_text(yaml.safe_dump(template, sort_keys=False), encoding="utf-8")
        click.echo(f"Wrote template to {template_out}", err=True)

    if output_policy:
        Path(output_policy).write_text(_dump_policy(policy, fmt), encoding="utf-8")
        click.echo(f"Wrote policy to {output_policy}", err=True)

    if comparison_json:
        Path(comparison_json).write_text(json.dumps(report, indent=2, default=str), encoding="utf-8")
    if comparison_markdown:
        Path(comparison_markdown).write_text(format_comparison_markdown(report) + "\n", encoding="utf-8")

    if compare:
        click.echo(format_comparison_markdown(report), err=True)

    if emit_template:
        click.echo(yaml.safe_dump(template, sort_keys=False))
    elif not output_policy:
        click.echo(_dump_policy(policy, fmt))

    if strict and (unmapped or not report.get("coverage", {}).get("all_covered")):
        missing = report.get("coverage", {}).get("missing", [])
        raise click.ClickException(f"Strict mode: {len(unmapped)} unmapped event(s), {len(missing)} uncovered call(s).")


def main() -> None:  # pragma: no cover - convenience entry point
    """Allow ``python -m policy_sentry.command.write_policy_from_logs`` style use."""
    sys.exit(write_policy_from_logs())


if __name__ == "__main__":  # pragma: no cover
    main()
