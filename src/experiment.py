"""Persistencia inmutable y exportable de ejecuciones experimentales."""

import csv
import json
import os
import re
import subprocess
import time
from datetime import datetime
from pathlib import Path


SUMMARY_FIELDS = [
    "run_id",
    "campaign_id",
    "started_at",
    "git_commit",
    "kali_connected_interface",
    "detected_interface",
    "threshold_mac_per_second",
    "configured_poll_interval_ms",
    "actual_poll_interval_ms",
    "macof_command",
    "initial_mac_count",
    "peak_mac_count",
    "detection_cycle_ms",
    "end_to_end_ms",
    "mitigation_success",
    "scenario_label",
    "observe_only",
    "anomaly_detected",
    "classification",
    "run_duration_ms",
]

THRESHOLD_EVALUATION_FIELDS = [
    "threshold_mac_per_second",
    "normal_trials",
    "attack_trials",
    "true_positives",
    "false_positives",
    "true_negatives",
    "false_negatives",
    "attacks_detected",
    "mean_detection_cycle_ms",
    "mean_end_to_end_ms",
    "mean_run_duration_ms",
]


class ExperimentRun:
    """Representa un run_NNN que nunca sobrescribe ejecuciones anteriores."""

    def __init__(
        self,
        root,
        threshold_mac_per_second,
        configured_poll_interval,
        kali_connected_interface=None,
        macof_command="macof",
        scenario_label="attack",
        observe_only=False,
        campaign_id="default",
    ):
        if scenario_label not in {"normal", "attack"}:
            raise ValueError("scenario_label debe ser 'normal' o 'attack'")
        self.started_monotonic_ns = time.monotonic_ns()
        self.root = Path(root)
        self.root.mkdir(parents=True, exist_ok=True)
        self.run_id, self.run_dir = self._allocate_run_dir()
        self.metadata_file = self.run_dir / "metadata.json"
        self.snapshots_file = self.run_dir / "cam_snapshots.jsonl"
        self.events_file = self.run_dir / "events.jsonl"
        self.metrics_file = self.run_dir / "metrics.json"
        self.switch_before_file = self.run_dir / "switch_before.txt"
        self.switch_after_file = self.run_dir / "switch_after.txt"
        self.report_file = self.run_dir / "report.txt"

        # La corrida queda inequívocamente identificada incluso si el proceso se
        # interrumpe antes de producir su primera muestra o evento.
        self.snapshots_file.touch()
        self.events_file.touch()
        self.switch_before_file.touch()
        self.switch_after_file.touch()

        self.actual_poll_intervals = []
        self.initial_mac_count = 0
        self.peak_mac_count = 0
        self.detected_interface = None
        self.mitigation_result = None
        self.detection_result = None
        self.snapshot_count = 0
        self.failed_snapshot_count = 0
        self.metadata = {
            "experiment": "mac_flooding_validation",
            "run_id": self.run_id,
            "campaign_id": campaign_id,
            "started_at": datetime.now().astimezone().isoformat(),
            "finished_at": None,
            "status": "running",
            "git_commit": self._git_commit(),
            "kali_connected_interface": kali_connected_interface,
            "detected_interface": None,
            "threshold_mac_per_second": threshold_mac_per_second,
            "configured_poll_interval_ms": round(configured_poll_interval * 1000, 3),
            "actual_poll_interval_ms": None,
            "macof_command": macof_command,
            "initial_mac_count": None,
            "peak_mac_count": None,
            "detection_cycle_ms": None,
            "end_to_end_ms": None,
            "mitigation_success": None,
            "scenario_label": scenario_label,
            "observe_only": bool(observe_only),
            "anomaly_detected": False,
            "classification": None,
            "run_duration_ms": None,
        }
        self._write_json(self.metadata_file, self.metadata)
        self._write_json(
            self.metrics_file,
            {"run_id": self.run_id, "status": "running"},
        )

    def _allocate_run_dir(self):
        numbers = []
        for path in self.root.glob("run_*"):
            match = re.fullmatch(r"run_(\d+)", path.name)
            if match:
                numbers.append(int(match.group(1)))
        candidate = max(numbers, default=0) + 1
        while True:
            run_id = f"run_{candidate:03d}"
            run_dir = self.root / run_id
            try:
                run_dir.mkdir(exist_ok=False)
                return run_id, run_dir
            except FileExistsError:
                candidate += 1

    @staticmethod
    def _git_commit():
        try:
            return subprocess.check_output(
                ["git", "rev-parse", "HEAD"],
                text=True,
                stderr=subprocess.DEVNULL,
            ).strip()
        except Exception:
            return "unknown"

    @staticmethod
    def _write_json(path, value):
        with open(path, "w", encoding="utf-8") as file:
            json.dump(value, file, indent=2, ensure_ascii=False)

    def mark_baseline(self, mac_count):
        self.initial_mac_count = mac_count
        self.metadata["initial_mac_count"] = mac_count
        self._write_json(self.metadata_file, self.metadata)

    def record_snapshot(
        self,
        result,
        poll_number,
        poll_started_ns,
        actual_poll_interval_ms,
        rate=None,
        total_macs=None,
    ):
        if actual_poll_interval_ms is not None:
            self.actual_poll_intervals.append(actual_poll_interval_ms)
        total = (
            sum(len(macs) for macs in result.entries.values())
            if total_macs is None
            else total_macs
        )
        self.peak_mac_count = max(self.peak_mac_count, total)
        self.snapshot_count += 1
        if not result.success:
            self.failed_snapshot_count += 1
        snapshot = {
            "run_id": self.run_id,
            "ts": datetime.now().astimezone().isoformat(),
            "poll_number": poll_number,
            "poll_started_ns": poll_started_ns,
            "success": result.success,
            "snmp_read_ms": result.elapsed_ms,
            "snmp_walks": getattr(result, "snmp_walks", []),
            "actual_poll_interval_ms": actual_poll_interval_ms,
            "rate": rate,
            "total_macs": total,
            "error_type": result.error_type,
            "error_message": result.error_message,
            "entries": {
                str(port): sorted(macs) for port, macs in result.entries.items()
            },
        }
        with open(self.snapshots_file, "a", encoding="utf-8") as file:
            file.write(json.dumps(snapshot, ensure_ascii=False) + "\n")

    def record_mitigation(self, result):
        self.mitigation_result = dict(result)
        self.record_detection(result)

    def record_detection(self, result):
        """Conserva la primera anomalía para clasificar y medir la corrida."""
        if self.detection_result is None:
            self.detection_result = dict(result)
        if result.get("detected_interface"):
            self.detected_interface = result["detected_interface"]
        self.metadata["anomaly_detected"] = True
        self._write_json(self.metadata_file, self.metadata)

    def _classification(self, status):
        if status != "completed":
            return "not_evaluated"
        detected = self.detection_result is not None
        if self.metadata["scenario_label"] == "attack":
            return "true_positive" if detected else "false_negative"
        return "false_positive" if detected else "true_negative"

    def capture_switch(self, network, destination):
        sections = []
        for command in (
            "show interfaces status",
            "show mac address-table dynamic",
            "show running-config | section ^interface",
        ):
            ok, output = network.comando_resultado(command, timeout=20)
            sections.append(f"===== {command} | success={ok} =====\n{output}\n")
        with open(destination, "w", encoding="utf-8") as file:
            file.write("\n".join(sections))

    def finalize(self, status="completed"):
        timing = self.mitigation_result or self.detection_result or {}
        run_duration_ms = round(
            (time.monotonic_ns() - self.started_monotonic_ns) / 1_000_000,
            3,
        )
        classification = self._classification(status)
        actual_average = (
            round(sum(self.actual_poll_intervals) / len(self.actual_poll_intervals), 3)
            if self.actual_poll_intervals else None
        )
        metrics = {
            "run_id": self.run_id,
            "snapshot_count": self.snapshot_count,
            "failed_snapshot_count": self.failed_snapshot_count,
            "initial_mac_count": self.initial_mac_count,
            "peak_mac_count": self.peak_mac_count,
            "actual_poll_interval_ms": actual_average,
            "scenario_label": self.metadata["scenario_label"],
            "observe_only": self.metadata["observe_only"],
            "anomaly_detected": self.detection_result is not None,
            "classification": classification,
            "run_duration_ms": run_duration_ms,
            **{
                key: timing.get(key)
                for key in (
                    "snmp_read_ms",
                    "analysis_ms",
                    "ssh_command_ms",
                    "verification_ms",
                    "detection_cycle_ms",
                    "containment_ms",
                    "end_to_end_ms",
                    "mitigation_success",
                )
            },
        }
        self._write_json(self.metrics_file, metrics)
        self.metadata.update({
            "finished_at": datetime.now().astimezone().isoformat(),
            "status": status,
            "detected_interface": self.detected_interface,
            "actual_poll_interval_ms": actual_average,
            "initial_mac_count": self.initial_mac_count,
            "peak_mac_count": self.peak_mac_count,
            "detection_cycle_ms": timing.get("detection_cycle_ms"),
            "end_to_end_ms": timing.get("end_to_end_ms"),
            "mitigation_success": timing.get("mitigation_success"),
            "anomaly_detected": self.detection_result is not None,
            "classification": classification,
            "run_duration_ms": run_duration_ms,
        })
        self._write_json(self.metadata_file, self.metadata)
        self.export_summary(self.root)
        self.export_threshold_evaluation(self.root)
        return metrics

    @classmethod
    def export_summary(cls, root):
        root = Path(root)
        root.mkdir(parents=True, exist_ok=True)
        rows = []
        for metadata_file in sorted(root.glob("run_*/metadata.json")):
            try:
                with open(metadata_file, "r", encoding="utf-8") as file:
                    metadata = json.load(file)
                rows.append({field: metadata.get(field) for field in SUMMARY_FIELDS})
            except (OSError, json.JSONDecodeError):
                continue
        summary = root / "summary.csv"
        with open(summary, "w", newline="", encoding="utf-8-sig") as file:
            writer = csv.DictWriter(file, fieldnames=SUMMARY_FIELDS)
            writer.writeheader()
            writer.writerows(rows)
        return summary

    @classmethod
    def export_threshold_evaluation(cls, root):
        """Agrupa corridas completadas sin fabricar resultados ausentes."""
        root = Path(root)
        root.mkdir(parents=True, exist_ok=True)
        groups = {}
        for metadata_file in sorted(root.glob("run_*/metadata.json")):
            try:
                with open(metadata_file, "r", encoding="utf-8") as file:
                    metadata = json.load(file)
            except (OSError, json.JSONDecodeError):
                continue
            if metadata.get("status") != "completed":
                continue
            if metadata.get("scenario_label") not in {"normal", "attack"}:
                continue
            if metadata.get("classification") not in {
                "true_positive", "false_positive",
                "true_negative", "false_negative",
            }:
                continue
            threshold = metadata.get("threshold_mac_per_second")
            if threshold is not None:
                groups.setdefault(threshold, []).append(metadata)

        rows = []
        for threshold in sorted(groups, key=float):
            records = groups[threshold]
            classifications = [record.get("classification") for record in records]
            normal_trials = sum(
                record.get("scenario_label") == "normal" for record in records
            )
            attack_trials = sum(
                record.get("scenario_label") == "attack" for record in records
            )

            def mean(field):
                values = [
                    record[field] for record in records
                    if isinstance(record.get(field), (int, float))
                ]
                return round(sum(values) / len(values), 3) if values else ""

            true_positives = classifications.count("true_positive")
            rows.append({
                "threshold_mac_per_second": threshold,
                "normal_trials": normal_trials,
                "attack_trials": attack_trials,
                "true_positives": true_positives,
                "false_positives": classifications.count("false_positive"),
                "true_negatives": classifications.count("true_negative"),
                "false_negatives": classifications.count("false_negative"),
                "attacks_detected": f"{true_positives}/{attack_trials}",
                "mean_detection_cycle_ms": mean("detection_cycle_ms"),
                "mean_end_to_end_ms": mean("end_to_end_ms"),
                "mean_run_duration_ms": mean("run_duration_ms"),
            })

        destination = root / "threshold_evaluation.csv"
        with open(destination, "w", newline="", encoding="utf-8-sig") as file:
            writer = csv.DictWriter(
                file, fieldnames=THRESHOLD_EVALUATION_FIELDS
            )
            writer.writeheader()
            writer.writerows(rows)
        return destination
