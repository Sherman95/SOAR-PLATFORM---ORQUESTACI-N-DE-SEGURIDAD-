"""Pruebas de aceptacion para los Tickets 2 y 3."""

import sys
import subprocess
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest import mock


ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / "src"
sys.path[:0] = [str(ROOT), str(SRC)]

from agent import SOARAgent
from detector import (
    CamMonitorState,
    CamReadResult,
    Detector,
    OID_BASE_PORT_IFINDEX,
    OID_FDB_PORT,
    OID_IF_NAME,
    SNMPReadError,
)
from mitigador import Mitigador
from network import InterfaceStatus


class ScriptedDetector(Detector):
    def __init__(self, rows):
        super().__init__(network=None, snmp_config={})
        self.rows = rows

    def _snmp_walk(self, oid):
        value = self.rows.get(oid, [])
        if isinstance(value, Exception):
            raise value
        return value


def fdb_row(mac_octets, bridge_port):
    suffix = ".".join(str(value) for value in mac_octets)
    return f"{OID_FDB_PORT}.{suffix}", str(bridge_port)


class DynamicInterfaceTests(unittest.TestCase):
    def resolve_scenario(self, bridge_port, if_index, if_name):
        detector = ScriptedDetector({
            OID_FDB_PORT: [fdb_row((0, 1, 2, 3, 4, 5), bridge_port)],
            OID_BASE_PORT_IFINDEX: [
                (f"{OID_BASE_PORT_IFINDEX}.{bridge_port}", str(if_index))
            ],
            OID_IF_NAME: [(f"{OID_IF_NAME}.{if_index}", if_name)],
        })
        result = detector.leer_cam()
        return result, detector.resolver_interfaz(bridge_port)

    def test_same_code_resolves_kali_on_ethernet_0_3(self):
        result, identity = self.resolve_scenario(4, 4, "Ethernet0/3")
        self.assertTrue(result.success)
        self.assertEqual(identity.if_name, "Ethernet0/3")
        self.assertEqual(identity.bridge_port, 4)
        self.assertEqual(identity.if_index, 4)

    def test_same_code_resolves_kali_on_ethernet_0_2(self):
        result, identity = self.resolve_scenario(3, 3, "Ethernet0/2")
        self.assertTrue(result.success)
        self.assertEqual(identity.if_name, "Ethernet0/2")
        self.assertEqual(identity.bridge_port, 3)
        self.assertEqual(identity.if_index, 3)

    def test_unresolved_bridge_port_alerts_and_is_not_blockable(self):
        alerts = []
        agent = SOARAgent.__new__(SOARAgent)
        agent.detector = SimpleNamespace(resolver_interfaz=lambda _: None)
        agent.reporter = SimpleNamespace(
            registrar_alerta=lambda name, **data: alerts.append((name, data))
        )
        agent.mitigador = SimpleNamespace(bloqueados=set())

        self.assertIsNone(agent._resolver_objetivo(99, 241))
        self.assertEqual(alerts[0][0], "INTERFAZ_NO_RESUELTA")
        self.assertEqual(alerts[0][1]["bridge_port"], 99)

    def test_mitigation_event_contains_dynamic_identity(self):
        events = []
        states = iter([
            InterfaceStatus(True, "Ethernet0/2", "up_up", "up"),
            InterfaceStatus(
                True, "Ethernet0/2", "administratively_down", "admin down"
            ),
        ])
        network = SimpleNamespace(
            esta_vivo=lambda: True,
            estado_interfaz=lambda _: next(states),
            config=lambda commands: (True, "OK"),
        )
        reporter = SimpleNamespace(
            registrar_evento=lambda *args, **kwargs: events.append((args, kwargs))
        )
        mitigator = Mitigador(network, reporter)

        success = mitigator.bloquear_mac_flood(
            3,
            "Ethernet0/2",
            if_index=3,
            new_mac_count=241,
            threshold_mac_per_second=50,
        )

        self.assertTrue(success)
        details = events[0][1]
        self.assertEqual(details["detected_interface"], "Ethernet0/2")
        self.assertEqual(details["bridge_port"], 3)
        self.assertEqual(details["if_index"], 3)
        self.assertEqual(details["new_mac_count"], 241)
        self.assertEqual(details["threshold_mac_per_second"], 50)
        self.assertEqual(details["action"], "shutdown")
        self.assertTrue(details["command_sent"])
        self.assertEqual(details["verification_status"], "administratively_down")
        self.assertTrue(details["mitigation_success"])


class SnmpFailureTests(unittest.TestCase):
    def test_detector_imports_in_a_clean_python_process(self):
        completed = subprocess.run(
            [sys.executable, "-c", "import sys; sys.path.insert(0, 'src'); import detector"],
            cwd=ROOT,
            capture_output=True,
            text=True,
        )
        self.assertEqual(completed.returncode, 0, completed.stderr)

    def test_empty_cam_is_a_successful_read(self):
        result = ScriptedDetector({OID_FDB_PORT: []}).leer_cam()
        self.assertTrue(result.success)
        self.assertEqual(result.entries, {})
        self.assertIsNone(result.error_type)

    def test_snmp_walk_records_iteration_timings(self):
        detector = Detector(
            network=None,
            snmp_config={
                "community": "public",
                "host": "192.0.2.1",
                "port": 161,
                "timeout": 2,
                "retries": 1,
            },
        )
        responses = iter([
            (None, None, None, [(f"{OID_FDB_PORT}.0.1.2.3.4.5", "4")]),
            (None, None, None, [(f"{OID_FDB_PORT}.0.1.2.3.4.6", "4")]),
        ])
        clock = iter([
            0,
            10_000_000, 15_000_000,
            20_000_000, 30_000_000,
            40_000_000, 41_000_000,
            42_000_000,
        ])

        with mock.patch("detector.bulkCmd", return_value=responses), \
             mock.patch("detector.time.monotonic_ns", side_effect=clock):
            rows = detector._snmp_walk(OID_FDB_PORT)

        self.assertEqual(len(rows), 2)
        metric = detector.last_walk_metrics[0]
        self.assertEqual(metric["label"], "OID_FDB_PORT")
        self.assertEqual(metric["response_count"], 2)
        self.assertEqual(metric["varbind_count"], 2)
        self.assertEqual(metric["completion_wait_ms"], 1.0)
        self.assertEqual(metric["iterations"][0]["elapsed_ms"], 5.0)
        self.assertEqual(metric["iterations"][1]["elapsed_ms"], 10.0)
        self.assertEqual(metric["iterations"][0]["varbind_count"], 1)

    def test_snmp_error_is_not_an_empty_success(self):
        failure = SNMPReadError("error_indication", "timeout")
        result = ScriptedDetector({OID_FDB_PORT: failure}).leer_cam()
        self.assertFalse(result.success)
        self.assertEqual(result.entries, {})
        self.assertEqual(result.error_type, "error_indication")
        self.assertEqual(result.error_message, "timeout")

    def test_outage_keeps_last_valid_cam_and_enters_degraded_state(self):
        state = CamMonitorState(degraded_after=3)
        first = CamReadResult(True, {3: {"00:00:00:00:00:01"}}, 10.0)
        failure = CamReadResult(False, {}, 2000.0, "timeout", "no response")

        state.observe(first, observed_at_ns=1_000_000_000)
        self.assertIsNone(state.observe(failure, observed_at_ns=2_000_000_000))
        self.assertIsNone(state.observe(failure, observed_at_ns=3_000_000_000))
        self.assertIsNone(state.observe(failure, observed_at_ns=4_000_000_000))
        self.assertTrue(state.telemetry_degraded)
        self.assertEqual(state.last_valid_entries, first.entries)

        restored = CamReadResult(
            True,
            {3: {"00:00:00:00:00:01", "00:00:00:00:00:02"}},
            12.0,
        )
        comparison = state.observe(restored, observed_at_ns=5_000_000_000)
        self.assertEqual(comparison.previous_entries, first.entries)
        self.assertEqual(comparison.recovered_after_failures, 3)
        self.assertFalse(state.telemetry_degraded)


if __name__ == "__main__":
    unittest.main()
