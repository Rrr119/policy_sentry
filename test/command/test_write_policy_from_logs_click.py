import json
import tempfile
import unittest
from pathlib import Path

from click.testing import CliRunner

from policy_sentry.command.write_policy_from_logs import write_policy_from_logs

REPO_ROOT = Path(__file__).resolve().parents[2]
LOG_DIR = REPO_ROOT / "examples" / "access-logs" / "cloudtrail"


class WritePolicyFromLogsClickTests(unittest.TestCase):
    def setUp(self) -> None:
        self.runner = CliRunner()

    def test_three_groups_strict_json(self) -> None:
        for log_file in sorted(LOG_DIR.glob("*.json")):
            result = self.runner.invoke(
                write_policy_from_logs,
                ["--input-file", str(log_file), "--strict", "--name", log_file.stem],
            )
            self.assertEqual(result.exit_code, 0, msg=result.output)
            policy = json.loads(result.output)
            self.assertEqual(policy["Version"], "2012-10-17")
            self.assertTrue(policy["Statement"])

    def test_directory_input_with_compare_and_outputs(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            out = Path(tmp)
            result = self.runner.invoke(
                write_policy_from_logs,
                [
                    "--input-file",
                    str(LOG_DIR),
                    "--strict",
                    "--compare",
                    "--template-out",
                    str(out / "t.yml"),
                    "--comparison-json",
                    str(out / "c.json"),
                    "--comparison-markdown",
                    str(out / "c.md"),
                    "--output-policy",
                    str(out / "p.json"),
                ],
            )
            self.assertEqual(result.exit_code, 0, msg=result.output)
            self.assertTrue((out / "t.yml").exists())
            report = json.loads((out / "c.json").read_text(encoding="utf-8"))
            # Directory loads all three groups together.
            self.assertTrue(report["coverage"]["all_covered"])
            self.assertEqual(report["coverage"]["extra_actions"], [])
            policy = json.loads((out / "p.json").read_text(encoding="utf-8"))
            self.assertTrue(policy["Statement"])
            markdown = (out / "c.md").read_text(encoding="utf-8")
            self.assertIn("least-privilege verified: True", markdown)

    def test_template_flag_emits_yaml(self) -> None:
        log_file = LOG_DIR / "02-web-api.json"
        result = self.runner.invoke(
            write_policy_from_logs,
            ["--input-file", str(log_file), "--template", "--plain-template"],
        )
        self.assertEqual(result.exit_code, 0, msg=result.output)
        self.assertIn("mode: actions", result.output)
        self.assertIn("dynamodb:PutItem", result.output)
        self.assertNotIn("resource-arns", result.output)

    def test_missing_input_exits_nonzero(self) -> None:
        result = self.runner.invoke(
            write_policy_from_logs,
            ["--input-file", str(LOG_DIR / "does-not-exist.json")],
        )
        self.assertNotEqual(result.exit_code, 0)


if __name__ == "__main__":
    unittest.main()
