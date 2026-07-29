"""Resumen estadístico reproducible de campañas MAC Flooding."""

import csv
import json
import statistics
from datetime import datetime
from pathlib import Path


TIMING_FIELDS = (
    "snmp_read_ms",
    "analysis_ms",
    "ssh_command_ms",
    "verification_ms",
    "detection_cycle_ms",
    "containment_ms",
    "end_to_end_ms",
    "actual_poll_interval_ms",
)

RESULT_FIELDS = (
    "run_id",
    "campaign_id",
    "started_at",
    "scenario_label",
    "observe_only",
    "classification",
    "threshold_mac_per_second",
    "kali_connected_interface",
    "detected_interface",
    "port_identification_correct",
    "mitigation_success",
    *TIMING_FIELDS,
)


def _normalizar_interfaz(value):
    val = str(value or "").replace(" ", "").lower()
    if val.startswith("et") and not val.startswith("ethernet"):
        val = val.replace("et", "ethernet", 1)
    return val


def _rate(numerator, denominator):
    return round(numerator * 100 / denominator, 3) if denominator else None


def _descriptive(values):
    """Estadísticos descriptivos; no inventa una desviación con n < 2."""
    if not values:
        return {
            "count": 0,
            "mean": None,
            "standard_deviation": None,
            "median": None,
            "minimum": None,
            "maximum": None,
        }
    return {
        "count": len(values),
        "mean": round(statistics.mean(values), 3),
        "standard_deviation": (
            round(statistics.stdev(values), 3) if len(values) >= 2 else None
        ),
        "median": round(statistics.median(values), 3),
        "minimum": round(min(values), 3),
        "maximum": round(max(values), 3),
    }


class CampaignStatistics:
    def __init__(self, experiment_root):
        self.root = Path(experiment_root)

    def _load_results(self, campaign_id=None):
        rows = []
        for metadata_file in sorted(self.root.glob("run_*/metadata.json")):
            try:
                metadata = json.loads(metadata_file.read_text(encoding="utf-8"))
            except (OSError, json.JSONDecodeError):
                continue
            if metadata.get("status") != "completed":
                continue
            if metadata.get("scenario_label") not in {"normal", "attack"}:
                continue
            if campaign_id is not None and metadata.get("campaign_id") != campaign_id:
                continue

            metrics = {}
            metrics_file = metadata_file.parent / "metrics.json"
            try:
                metrics = json.loads(metrics_file.read_text(encoding="utf-8"))
            except (OSError, json.JSONDecodeError):
                pass

            expected = metadata.get("kali_connected_interface")
            detected = metadata.get("detected_interface")
            port_correct = ""
            if metadata["scenario_label"] == "attack" and expected:
                port_correct = (
                    _normalizar_interfaz(expected)
                    == _normalizar_interfaz(detected)
                )

            row = {
                field: metrics.get(field, metadata.get(field))
                for field in RESULT_FIELDS
            }
            row["port_identification_correct"] = port_correct
            rows.append(row)
        return rows

    def generate(self, campaign_id=None):
        self.root.mkdir(parents=True, exist_ok=True)
        rows = self._load_results(campaign_id)

        results_file = self.root / "results.csv"
        with open(results_file, "w", newline="", encoding="utf-8-sig") as file:
            writer = csv.DictWriter(file, fieldnames=RESULT_FIELDS)
            writer.writeheader()
            writer.writerows(rows)

        classifications = [row["classification"] for row in rows]
        attacks = [row for row in rows if row["scenario_label"] == "attack"]
        normal = [row for row in rows if row["scenario_label"] == "normal"]
        true_positives = classifications.count("true_positive")
        false_positives = classifications.count("false_positive")
        true_negatives = classifications.count("true_negative")
        false_negatives = classifications.count("false_negative")
        mitigated = sum(row["mitigation_success"] is True for row in attacks)
        attacks_with_expected_port = [
            row for row in attacks if row["kali_connected_interface"]
        ]
        correct_ports = sum(
            row["port_identification_correct"] is True
            for row in attacks_with_expected_port
        )

        attack_port_counts = {}
        for row in attacks:
            interface = row["kali_connected_interface"]
            if interface:
                attack_port_counts[interface] = attack_port_counts.get(interface, 0) + 1

        metric_statistics = {
            field: _descriptive([
                row[field] for row in rows
                if isinstance(row.get(field), (int, float))
            ])
            for field in TIMING_FIELDS
        }
        campaign_complete = (
            len(attacks) >= 10
            and len(normal) >= 10
            and sum(
                _normalizar_interfaz(row["kali_connected_interface"])
                == "ethernet0/3"
                for row in attacks
            ) >= 5
            and sum(
                _normalizar_interfaz(row["kali_connected_interface"])
                == "ethernet0/2"
                for row in attacks
            ) >= 5
        )
        summary = {
            "generated_at": datetime.now().astimezone().isoformat(),
            "campaign_id": campaign_id,
            "campaign_complete": campaign_complete,
            "requirements": {
                "attack_trials_required": 10,
                "normal_trials_required": 10,
                "attacks_ethernet0_3_required": 5,
                "attacks_ethernet0_2_required": 5,
            },
            "counts": {
                "total_runs": len(rows),
                "attack_trials": len(attacks),
                "normal_trials": len(normal),
                "true_positives": true_positives,
                "false_positives": false_positives,
                "true_negatives": true_negatives,
                "false_negatives": false_negatives,
                "successful_mitigations": mitigated,
                "correct_port_identifications": correct_ports,
                "attack_ports": attack_port_counts,
            },
            "rates_percent": {
                "detection_rate": _rate(
                    true_positives, true_positives + false_negatives
                ),
                "mitigation_rate": _rate(mitigated, len(attacks)),
                "port_identification_accuracy": _rate(
                    correct_ports, len(attacks_with_expected_port)
                ),
            },
            "metric_statistics_ms": metric_statistics,
            "definitions": {
                "detection_rate": "TP / (TP + FN)",
                "mitigation_rate": "mitigaciones exitosas / pruebas de ataque",
                "port_identification_accuracy": (
                    "puertos detectados correctamente / ataques con puerto Kali registrado"
                ),
                "standard_deviation": "desviación estándar muestral",
            },
        }

        summary_file = self.root / "summary.json"
        summary_file.write_text(
            json.dumps(summary, indent=2, ensure_ascii=False), encoding="utf-8"
        )

        report_file = self.root / "statistical_report.txt"
        rates = summary["rates_percent"]
        lines = [
            "RESUMEN ESTADÍSTICO — MAC FLOODING",
            f"Campaña: {campaign_id or 'todas'}",
            f"Campaña completa: {'sí' if campaign_complete else 'no'}",
            f"Corridas: {len(rows)} (ataques={len(attacks)}, normales={len(normal)})",
            f"TP={true_positives} FP={false_positives} "
            f"TN={true_negatives} FN={false_negatives}",
            f"Tasa de detección: {rates['detection_rate']} %",
            f"Tasa de mitigación: {rates['mitigation_rate']} %",
            "Precisión de identificación del puerto: "
            f"{rates['port_identification_accuracy']} %",
            "",
            "ESTADÍSTICOS TEMPORALES (ms)",
        ]
        for field, values in metric_statistics.items():
            lines.append(
                f"{field}: n={values['count']}, media={values['mean']}, "
                f"desv={values['standard_deviation']}, mediana={values['median']}, "
                f"mín={values['minimum']}, máx={values['maximum']}"
            )
        report_file.write_text("\n".join(lines) + "\n", encoding="utf-8")
        return results_file, summary_file, report_file, summary
