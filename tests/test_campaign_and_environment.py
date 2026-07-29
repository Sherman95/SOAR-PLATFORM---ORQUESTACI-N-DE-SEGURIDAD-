"""Pruebas de aceptación para los Tickets 10 y 11."""

import csv
import json
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock


ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / "src"
sys.path[:0] = [str(ROOT), str(SRC)]

from campaign import CampaignStatistics
from config.version import VERSION_LABEL
from experiment import ExperimentRun


class CampaignStatisticsTests(unittest.TestCase):
    def make_run(self, root, scenario, index):
        expected_interface = (
            "Ethernet0/3" if index < 5 else "Ethernet0/2"
        ) if scenario == "attack" else None
        run = ExperimentRun(
            root,
            threshold_mac_per_second=50,
            configured_poll_interval=0.5,
            kali_connected_interface=expected_interface,
            scenario_label=scenario,
            observe_only=scenario == "normal",
            campaign_id="article_campaign",
        )
        if scenario == "normal" and index == 0:
            run.record_detection({"detection_cycle_ms": 600.0})
        if scenario == "attack" and index < 9:
            detected_interface = expected_interface if index < 8 else "Ethernet0/1"
            run.record_mitigation({
                "detected_interface": detected_interface,
                "detection_cycle_ms": 500.0 + index,
                "end_to_end_ms": 900.0 + index,
                "mitigation_success": index < 8,
            })
        run.finalize()
        return run

    def test_generates_article_ready_campaign_files_and_rates(self):
        with tempfile.TemporaryDirectory() as directory, mock.patch.object(
            ExperimentRun, "_git_commit", return_value="test-commit"
        ), mock.patch.object(
            ExperimentRun, "export_summary", return_value=Path(directory) / "summary.csv"
        ), mock.patch.object(
            ExperimentRun,
            "export_threshold_evaluation",
            return_value=Path(directory) / "threshold_evaluation.csv",
        ):
            for index in range(10):
                self.make_run(directory, "normal", index)
            for index in range(10):
                self.make_run(directory, "attack", index)

            results, summary_file, report, summary = CampaignStatistics(
                directory
            ).generate("article_campaign")

            self.assertTrue(results.exists())
            self.assertTrue(summary_file.exists())
            self.assertTrue(report.exists())
            with open(results, encoding="utf-8-sig") as file:
                self.assertEqual(len(list(csv.DictReader(file))), 20)
            persisted = json.loads(summary_file.read_text(encoding="utf-8"))
            self.assertTrue(persisted["campaign_complete"])
            self.assertEqual(persisted["counts"]["true_positives"], 9)
            self.assertEqual(persisted["counts"]["false_positives"], 1)
            self.assertEqual(persisted["counts"]["true_negatives"], 9)
            self.assertEqual(persisted["counts"]["false_negatives"], 1)
            self.assertEqual(persisted["rates_percent"]["detection_rate"], 90.0)
            self.assertEqual(persisted["rates_percent"]["mitigation_rate"], 80.0)
            self.assertEqual(
                persisted["rates_percent"]["port_identification_accuracy"],
                80.0,
            )
            end_to_end = persisted["metric_statistics_ms"]["end_to_end_ms"]
            self.assertEqual(end_to_end["count"], 9)
            for field in (
                "mean", "standard_deviation", "median", "minimum", "maximum"
            ):
                self.assertIsNotNone(end_to_end[field])
            self.assertEqual(summary, persisted)


class ReproducibleEnvironmentTests(unittest.TestCase):
    def test_required_dependencies_are_exactly_pinned(self):
        requirements = (ROOT / "requirements.txt").read_text(encoding="utf-8")
        for dependency in (
            "netmiko==4.7.0",
            "pysnmp==4.4.12",
            "pyasn1==0.4.8",
            "python-dotenv==1.2.2",
            "pytest==9.1.1",
        ):
            self.assertIn(dependency, requirements)
        self.assertNotIn(">=", requirements)

    def test_environment_template_is_safe_and_local_env_is_ignored(self):
        gitignore = (ROOT / ".gitignore").read_text(encoding="utf-8")
        template = (ROOT / ".env.example").read_text(encoding="utf-8")
        self.assertIn(".env", gitignore)
        self.assertIn("!.env.example", gitignore)
        self.assertIn("SWITCH_PASS=\n", template)
        self.assertNotIn("cisco123", template)

    def test_ssh_test_contains_no_password(self):
        source = (ROOT / "tests" / "test_ssh.py").read_text(encoding="utf-8")
        self.assertNotIn("cisco123", source)
        self.assertNotIn('"password"', source)
        self.assertIn("from config.settings import SWITCH", source)

    def test_python_and_agent_versions_have_one_source(self):
        self.assertEqual(
            (ROOT / ".python-version").read_text(encoding="utf-8").strip(),
            "3.14.4",
        )
        self.assertIn(VERSION_LABEL, (ROOT / "README.md").read_text(encoding="utf-8"))
        for relative in ("run.py", "src/agent.py", "src/dashboard.py", "src/reporter.py"):
            source = (ROOT / relative).read_text(encoding="utf-8")
            self.assertIn("VERSION_LABEL", source)
            self.assertNotIn('"v7.0"', source)


if __name__ == "__main__":
    unittest.main()
