"""Restauracion manual y verificable entre ejecuciones experimentales."""

import re
import time
from dataclasses import asdict, dataclass
from pathlib import Path

from config.settings import (
    EXPERIMENT_ROOT,
    KALI_IP,
    RESTORE_SETTLE_SECONDS,
    SNMP,
    SWITCH,
)
from detector import Detector
from network import NetworkManager
from reporter import Reporter


@dataclass
class RestoreResult:
    interface: str
    action: str
    command_sent: bool
    command_accepted: bool
    cam_clear_success: bool
    verification_status: str
    connectivity_status: str
    baseline_mac_count: int | None
    baseline_status: str
    restoration_success: bool
    ready_for_experiment: bool
    initial_status: str

    def to_dict(self):
        return asdict(self)


class ManualRestorer:
    """Ejecuta no shutdown sin cambiar VLAN y valida el escenario resultante."""

    def __init__(
        self,
        network=None,
        detector=None,
        reporter=None,
        settle_seconds=RESTORE_SETTLE_SECONDS,
    ):
        self.net = network or NetworkManager(SWITCH)
        self.detector = detector or Detector(self.net, SNMP)
        self.reporter = reporter or self._latest_run_reporter()
        self.settle_seconds = settle_seconds

    @staticmethod
    def _latest_run_reporter():
        root = Path(EXPERIMENT_ROOT)
        runs = sorted(path for path in root.glob("run_*") if path.is_dir())
        if runs:
            run_dir = runs[-1]
            return Reporter(
                None,
                str(run_dir / "events.jsonl"),
                str(run_dir / "report.txt"),
                reset_session=False,
                run_id=run_dir.name,
            )
        fallback = root / "manual_restore_unscoped"
        return Reporter(
            None,
            str(fallback / "events.jsonl"),
            str(fallback / "report.txt"),
            reset_session=False,
            run_id="manual_restore_unscoped",
        )

    def _connectivity_status(self, ip_address: str | None) -> str:
        if not ip_address:
            return "not_configured"
        ok, output = self.net.comando_resultado(
            f"ping {ip_address} repeat 3 timeout 1", timeout=10
        )
        if not ok:
            return "check_failed"
        match = re.search(r"Success rate is\s+(\d+)\s+percent", output, re.I)
        if not match:
            return "unparseable"
        return "reachable" if int(match.group(1)) > 0 else "unreachable"

    def restore(
        self, interface: str, verify_ip: str | None = None
    ) -> RestoreResult:
        verify_ip = verify_ip or KALI_IP
        if not self.net.esta_vivo():
            result = RestoreResult(
                interface, "no_shutdown", False, False, False,
                "ssh_unavailable", "not_checked", None,
                "not_checked", False, False, "unavailable",
            )
            self._record(result, verify_ip)
            return result

        initial = self.net.estado_interfaz(interface)
        if not initial.success:
            result = RestoreResult(
                interface, "no_shutdown", False, False, False,
                "initial_state_unavailable", "not_checked", None,
                "not_checked", False, False, initial.status,
            )
            self._record(result, verify_ip)
            return result

        accepted, _ = self.net.config([
            f"interface {interface}",
            " no shutdown",
            "exit",
        ])
        if not accepted:
            result = RestoreResult(
                interface, "no_shutdown", True, False, False,
                "command_rejected", "not_checked", None,
                "not_checked", False, False, initial.status,
            )
            self._record(result, verify_ip)
            return result

        cam_clear_ok, _ = self.net.comando_resultado(
            "clear mac address-table dynamic", timeout=10
        )
        if self.settle_seconds > 0:
            time.sleep(self.settle_seconds)

        final_state = self.net.estado_interfaz(interface)
        connectivity = self._connectivity_status(verify_ip)
        cam_result = self.detector.leer_cam()
        if cam_result.success:
            baseline_count = sum(len(macs) for macs in cam_result.entries.values())
            baseline_status = (
                "expected_3_to_5" if 3 <= baseline_count <= 5 else "unexpected_count"
            )
        else:
            baseline_count = None
            baseline_status = "telemetry_unavailable"

        restoration_success = (
            accepted
            and cam_clear_ok
            and final_state.success
            and final_state.status == "up_up"
        )
        connectivity_ready = connectivity == "reachable"
        ready = (
            restoration_success
            and connectivity_ready
            and baseline_status == "expected_3_to_5"
        )
        result = RestoreResult(
            interface=interface,
            action="no_shutdown",
            command_sent=True,
            command_accepted=accepted,
            cam_clear_success=cam_clear_ok,
            verification_status=final_state.status,
            connectivity_status=connectivity,
            baseline_mac_count=baseline_count,
            baseline_status=baseline_status,
            restoration_success=restoration_success,
            ready_for_experiment=ready,
            initial_status=initial.status,
        )
        self._record(result, verify_ip)
        return result

    def _record(self, result: RestoreResult, verify_ip: str | None):
        self.reporter.registrar_evento(
            "MANUAL_RESTORE",
            result.interface,
            "MANUAL_RESTORE",
            event_type="RESTORATION",
            verify_ip=verify_ip,
            **result.to_dict(),
        )

    def close(self):
        self.net.desconectar()
