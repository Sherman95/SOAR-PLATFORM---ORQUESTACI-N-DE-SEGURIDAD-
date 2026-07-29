"""Pruebas de aceptacion para los Tickets 6 y 7."""

import csv
import json
import sys
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest import mock


ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / "src"
sys.path[:0] = [str(ROOT), str(SRC)]

from detector import CamReadResult
from experiment import ExperimentRun, SUMMARY_FIELDS
from mitigador import Mitigador
from network import InterfaceStatus
from reporter import Reporter


class TimingReporter:
    def __init__(self):
        self.event = None

    def registrar_evento(self, *args, **kwargs):
        self.event = {
            "origen": args[0], "puerto": args[1], "accion": args[2],
            "ms": args[3], **kwargs,
        }


class FullTimingTests(unittest.TestCase):
    def test_t0_to_t5_metrics_are_measured_from_monotonic_ns(self):
        states = iter([
            InterfaceStatus(True, "Ethernet0/3", "up_up", "up"),
            InterfaceStatus(True, "Ethernet0/3", "administratively_down", "down"),
        ])
        network = SimpleNamespace(
            esta_vivo=lambda: True,
            estado_interfaz=lambda _: next(states),
            config=lambda _: (True, "OK"),
        )
        reporter = TimingReporter()
        mitigator = Mitigador(network, reporter)

        # t3, t4 y t5. t0, t1 y t2 llegan desde el ciclo de deteccion.
        with mock.patch(
            "mitigador.time.monotonic_ns",
            side_effect=[3_000_000_000, 4_000_000_000, 5_000_000_000],
        ):
            success = mitigator.bloquear_mac_flood(
                4,
                "Ethernet0/3",
                if_index=4,
                new_mac_count=241,
                threshold_mac_per_second=50,
                poll_started_ns=1_000_000_000,
                cam_received_ns=1_500_000_000,
                anomaly_identified_ns=2_000_000_000,
                actual_poll_interval_ms=550.0,
            )

        self.assertTrue(success)
        event = reporter.event
        self.assertEqual(event["snmp_read_ms"], 500.0)
        self.assertEqual(event["analysis_ms"], 500.0)
        self.assertEqual(event["ssh_command_ms"], 1000.0)
        self.assertEqual(event["verification_ms"], 1000.0)
        self.assertEqual(event["detection_cycle_ms"], 1000.0)
        self.assertEqual(event["containment_ms"], 3000.0)
        self.assertEqual(event["end_to_end_ms"], 4000.0)
        self.assertEqual(event["actual_poll_interval_ms"], 550.0)
        self.assertEqual(event["ms"], 4000.0)

    def test_experimental_timing_has_no_manual_estimate_or_write_memory(self):
        sources = "\n".join(
            (SRC / name).read_text(encoding="utf-8").lower()
            for name in ("agent.py", "mitigador.py", "reporter.py", "dashboard.py")
        )
        self.assertNotIn("900_000", sources)
        self.assertNotIn("15 minutos", sources)
        self.assertNotIn("write memory", sources)
        self.assertNotIn("monotonic()", sources)
        self.assertIn("monotonic_ns()", sources)


class ExperimentStorageTests(unittest.TestCase):
    def make_run(self, root, kali_interface="Ethernet0/3"):
        return ExperimentRun(
            root,
            threshold_mac_per_second=50,
            configured_poll_interval=0.5,
            kali_connected_interface=kali_interface,
            macof_command="macof -i eth0",
        )

    def test_runs_are_separate_and_previous_results_are_not_deleted(self):
        with tempfile.TemporaryDirectory() as directory:
            first = self.make_run(directory)
            marker = first.run_dir / "marker.txt"
            marker.write_text("preserve", encoding="utf-8")
            second = self.make_run(directory, "Ethernet0/2")

            self.assertEqual(first.run_id, "run_001")
            self.assertEqual(second.run_id, "run_002")
            self.assertEqual(marker.read_text(encoding="utf-8"), "preserve")
            self.assertNotEqual(first.run_dir, second.run_dir)

    def test_new_run_immediately_owns_all_required_artifact_files(self):
        with tempfile.TemporaryDirectory() as directory:
            run = self.make_run(directory)
            required = (
                run.metadata_file,
                run.snapshots_file,
                run.events_file,
                run.metrics_file,
                run.switch_before_file,
                run.switch_after_file,
            )
            self.assertTrue(all(path.exists() for path in required))
            metrics = json.loads(run.metrics_file.read_text(encoding="utf-8"))
            self.assertEqual(metrics["run_id"], run.run_id)
            self.assertEqual(metrics["status"], "running")

    def test_run_contains_required_artifacts_metadata_and_run_ids(self):
        with tempfile.TemporaryDirectory() as directory:
            run = self.make_run(directory)
            run.mark_baseline(4)
            snapshot_result = CamReadResult(
                True, {4: {"00:00:00:00:00:01"}}, 12.5
            )
            run.record_snapshot(
                snapshot_result,
                poll_number=1,
                poll_started_ns=100,
                actual_poll_interval_ms=510.0,
                rate=241.0,
                total_macs=5,
            )
            mitigation = {
                "detected_interface": "Ethernet0/3",
                "snmp_read_ms": 12.5,
                "analysis_ms": 1.0,
                "ssh_command_ms": 100.0,
                "verification_ms": 20.0,
                "detection_cycle_ms": 13.5,
                "containment_ms": 120.0,
                "end_to_end_ms": 133.5,
                "mitigation_success": True,
            }
            run.record_mitigation(mitigation)

            fake_network = SimpleNamespace(
                comando_resultado=lambda command, timeout=20: (True, command)
            )
            run.capture_switch(fake_network, run.switch_before_file)
            run.capture_switch(fake_network, run.switch_after_file)

            reporter = Reporter(
                None,
                str(run.events_file),
                str(run.report_file),
                run_id=run.run_id,
            )
            reporter.registrar_evento(
                "MAC_FLOOD_SNMP", "Ethernet0/3", "SHUTDOWN",
                mitigation_success=True,
            )
            metrics = run.finalize()

            required = {
                "metadata.json", "cam_snapshots.jsonl", "events.jsonl",
                "metrics.json", "switch_before.txt", "switch_after.txt",
            }
            self.assertTrue(required.issubset({path.name for path in run.run_dir.iterdir()}))

            metadata = json.loads(run.metadata_file.read_text(encoding="utf-8"))
            for field in SUMMARY_FIELDS:
                self.assertIn(field, metadata)
            self.assertEqual(metadata["run_id"], run.run_id)
            self.assertEqual(metadata["detected_interface"], "Ethernet0/3")
            self.assertEqual(metadata["initial_mac_count"], 4)
            self.assertEqual(metadata["peak_mac_count"], 5)
            self.assertEqual(metadata["end_to_end_ms"], 133.5)

            snapshot = json.loads(run.snapshots_file.read_text(encoding="utf-8"))
            event = json.loads(run.events_file.read_text(encoding="utf-8"))
            self.assertEqual(snapshot["run_id"], run.run_id)
            self.assertEqual(event["run_id"], run.run_id)
            self.assertEqual(metrics["run_id"], run.run_id)

            with open(Path(directory) / "summary.csv", encoding="utf-8-sig") as file:
                rows = list(csv.DictReader(file))
            self.assertEqual(len(rows), 1)
            self.assertEqual(rows[0]["run_id"], run.run_id)

    def test_ten_runs_export_to_one_summary_without_overwrite(self):
        with tempfile.TemporaryDirectory() as directory:
            for _ in range(10):
                run = self.make_run(directory)
                run.finalize()
            with open(Path(directory) / "summary.csv", encoding="utf-8-sig") as file:
                rows = list(csv.DictReader(file))
            self.assertEqual(len(rows), 10)
            self.assertEqual(rows[0]["run_id"], "run_001")
            self.assertEqual(rows[-1]["run_id"], "run_010")


if __name__ == "__main__":
    unittest.main()
