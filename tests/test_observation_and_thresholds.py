"""Pruebas de aceptación para los Tickets 8 y 9."""

import csv
import json
import sys
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace


ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / "src"
sys.path[:0] = [str(ROOT), str(SRC)]

from agent import SOARAgent
from detector import InterfaceIdentity, calcular_tasa_mac
from experiment import ExperimentRun


class ObservationModeTests(unittest.TestCase):
    def test_mac_rate_is_new_mac_count_divided_by_elapsed_seconds(self):
        self.assertEqual(calcular_tasa_mac(50, 2.0), 25.0)
        self.assertEqual(calcular_tasa_mac(50, 0), 0.0)

    def test_observation_records_detection_without_switch_configuration(self):
        alerts = []
        detections = []

        def forbidden_config(*_args, **_kwargs):
            raise AssertionError("observe-only no puede configurar el switch")

        agent = SOARAgent.__new__(SOARAgent)
        agent.detector = SimpleNamespace(
            resolver_interfaz=lambda _: InterfaceIdentity(
                bridge_port=4, if_index=4, if_name="Ethernet0/3"
            )
        )
        agent.net = SimpleNamespace(config=forbidden_config)
        agent.reporter = SimpleNamespace(
            registrar_alerta=lambda alert, **details: alerts.append(
                (alert, details)
            )
        )
        agent.experiment = SimpleNamespace(
            record_detection=lambda result: detections.append(result)
        )
        agent.threshold_mac_per_second = 50
        agent.scenario_label = "normal"

        agent._registrar_observacion(
            bridge_port=4,
            new_mac_count=60,
            rate=120.0,
            poll_started_ns=1_000_000_000,
            cam_received_ns=1_200_000_000,
            anomaly_identified_ns=1_250_000_000,
            actual_poll_interval_ms=500.0,
        )

        self.assertEqual(alerts[0][0], "MAC_FLOOD_OBSERVED")
        self.assertFalse(alerts[0][1]["configuration_sent"])
        self.assertEqual(detections[0]["detection_cycle_ms"], 250.0)
        self.assertEqual(detections[0]["detected_interface"], "Ethernet0/3")


class ThresholdEvaluationTests(unittest.TestCase):
    def make_run(self, root, scenario, detected):
        run = ExperimentRun(
            root,
            threshold_mac_per_second=25,
            configured_poll_interval=0.5,
            scenario_label=scenario,
            observe_only=True,
        )
        if detected:
            run.record_detection({
                "detected_interface": "Ethernet0/3",
                "detection_cycle_ms": 800.0,
                "end_to_end_ms": None,
            })
        run.finalize()
        return run

    def test_classifies_five_normal_and_five_attack_trials(self):
        with tempfile.TemporaryDirectory() as directory:
            normal_runs = [
                self.make_run(directory, "normal", index < 2)
                for index in range(5)
            ]
            attack_runs = [
                self.make_run(directory, "attack", index < 4)
                for index in range(5)
            ]

            normal_metadata = [
                json.loads(run.metadata_file.read_text(encoding="utf-8"))
                for run in normal_runs
            ]
            attack_metadata = [
                json.loads(run.metadata_file.read_text(encoding="utf-8"))
                for run in attack_runs
            ]
            self.assertEqual(
                [item["classification"] for item in normal_metadata].count(
                    "false_positive"
                ),
                2,
            )
            self.assertEqual(
                [item["classification"] for item in attack_metadata].count(
                    "true_positive"
                ),
                4,
            )

            evaluation = ExperimentRun.export_threshold_evaluation(directory)
            with open(evaluation, encoding="utf-8-sig") as file:
                rows = list(csv.DictReader(file))
            self.assertEqual(len(rows), 1)
            self.assertEqual(rows[0]["normal_trials"], "5")
            self.assertEqual(rows[0]["attack_trials"], "5")
            self.assertEqual(rows[0]["false_positives"], "2")
            self.assertEqual(rows[0]["true_negatives"], "3")
            self.assertEqual(rows[0]["false_negatives"], "1")
            self.assertEqual(rows[0]["attacks_detected"], "4/5")
            self.assertEqual(rows[0]["mean_detection_cycle_ms"], "800.0")


if __name__ == "__main__":
    unittest.main()
