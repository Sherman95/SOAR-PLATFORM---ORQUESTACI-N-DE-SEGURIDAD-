"""Pruebas de aceptacion para shutdown_only y restauracion manual."""

import inspect
import sys
import unittest
from pathlib import Path
from types import SimpleNamespace


ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / "src"
sys.path[:0] = [str(ROOT), str(SRC)]

from agent import SOARAgent
from detector import CamReadResult
from mitigador import Mitigador
from network import InterfaceStatus, NetworkManager
from restorer import ManualRestorer


class CapturingReporter:
    def __init__(self):
        self.events = []

    def registrar_evento(self, *args, **kwargs):
        self.events.append((args, kwargs))


class FakeNetwork:
    def __init__(self, states, config_result=(True, "OK"), ping_percent=100):
        self.states = iter(states)
        self.config_result = config_result
        self.ping_percent = ping_percent
        self.config_calls = []
        self.command_calls = []

    def esta_vivo(self):
        return True

    def estado_interfaz(self, interface):
        return next(self.states)

    def config(self, commands):
        self.config_calls.append(commands)
        return self.config_result

    def comando_resultado(self, command, timeout=15):
        self.command_calls.append(command)
        if command.startswith("ping "):
            return True, f"Success rate is {self.ping_percent} percent (3/3)"
        return True, ""

    def desconectar(self):
        pass


def status(value):
    return InterfaceStatus(True, "Ethernet0/3", value, value)


class ShutdownOnlyTests(unittest.TestCase):
    def run_mitigation(self, network):
        reporter = CapturingReporter()
        mitigator = Mitigador(network, reporter)
        success = mitigator.bloquear_mac_flood(
            4,
            "Ethernet0/3",
            if_index=4,
            new_mac_count=241,
            threshold_mac_per_second=50,
        )
        return success, mitigator, reporter

    def test_success_requires_administratively_down_verification(self):
        network = FakeNetwork([status("up_up"), status("administratively_down")])
        success, mitigator, reporter = self.run_mitigation(network)

        self.assertTrue(success)
        self.assertEqual(network.config_calls[0], [
            "interface Ethernet0/3", " shutdown", "exit"
        ])
        self.assertEqual(mitigator.blocked_interfaces, {"Ethernet0/3"})
        event = reporter.events[0][1]
        self.assertEqual(event["interface"], "Ethernet0/3")
        self.assertEqual(event["action"], "shutdown")
        self.assertTrue(event["command_sent"])
        self.assertEqual(event["verification_status"], "administratively_down")
        self.assertTrue(event["mitigation_success"])

    def test_ios_invalid_input_is_not_success(self):
        network = FakeNetwork(
            [status("up_up")],
            config_result=(False, "% Invalid input detected"),
        )
        success, mitigator, reporter = self.run_mitigation(network)

        self.assertFalse(success)
        self.assertEqual(mitigator.blocked_interfaces, set())
        self.assertFalse(reporter.events[0][1]["mitigation_success"])
        self.assertEqual(reporter.events[0][1]["verification_status"], "command_rejected")

    def test_ssh_exception_result_is_not_success(self):
        network = FakeNetwork(
            [status("up_up")],
            config_result=(False, "SSHException: channel closed"),
        )
        success, mitigator, reporter = self.run_mitigation(network)
        self.assertFalse(success)
        self.assertNotIn("Ethernet0/3", mitigator.blocked_interfaces)
        self.assertFalse(reporter.events[0][1]["mitigation_success"])

    def test_unverified_shutdown_is_not_added_to_blocked_interfaces(self):
        network = FakeNetwork([status("up_up"), status("up_up")])
        success, mitigator, reporter = self.run_mitigation(network)
        self.assertFalse(success)
        self.assertEqual(mitigator.blocked_interfaces, set())
        self.assertEqual(reporter.events[0][1]["verification_status"], "up_up")

    def test_main_mitigation_contains_no_acl_or_recovery_thread(self):
        source = (SRC / "mitigador.py").read_text(encoding="utf-8").lower()
        self.assertNotIn("access-list", source)
        self.assertNotIn("access-group", source)
        self.assertNotIn("thread", source)
        self.assertNotIn("restaur", source)


class NetworkVerificationTests(unittest.TestCase):
    def test_ios_administratively_down_output_is_parsed(self):
        manager = NetworkManager({})
        manager.conn = SimpleNamespace(send_command=lambda *args, **kwargs: (
            "Ethernet0/3 is administratively down, line protocol is down"
        ))
        result = manager.estado_interfaz("Ethernet0/3")
        self.assertTrue(result.success)
        self.assertEqual(result.status, "administratively_down")

    def test_ios_up_up_output_is_parsed(self):
        manager = NetworkManager({})
        manager.conn = SimpleNamespace(send_command=lambda *args, **kwargs: (
            "Ethernet0/3 is up, line protocol is up (connected)"
        ))
        result = manager.estado_interfaz("Ethernet0/3")
        self.assertTrue(result.success)
        self.assertEqual(result.status, "up_up")

    def test_network_manager_rejects_ios_invalid_input(self):
        manager = NetworkManager({})
        manager.conn = SimpleNamespace(send_config_set=lambda *args, **kwargs: (
            "% Invalid input detected at '^' marker."
        ))
        accepted, _ = manager.config(["interface Ethernet0/3", "shutdown"])
        self.assertFalse(accepted)


class ManualRestoreTests(unittest.TestCase):
    def make_detector(self, mac_count=4):
        entries = {1: {f"00:00:00:00:00:{index:02x}" for index in range(mac_count)}}
        return SimpleNamespace(
            leer_cam=lambda: CamReadResult(True, entries, 10.0)
        )

    def test_restore_is_verified_registered_and_does_not_change_vlan(self):
        network = FakeNetwork([
            status("administratively_down"),
            status("up_up"),
        ])
        reporter = CapturingReporter()
        restorer = ManualRestorer(
            network, self.make_detector(), reporter, settle_seconds=0
        )
        result = restorer.restore("Ethernet0/3", "192.168.1.50")

        self.assertTrue(result.restoration_success)
        self.assertTrue(result.ready_for_experiment)
        self.assertEqual(result.baseline_mac_count, 4)
        self.assertEqual(result.connectivity_status, "reachable")
        self.assertEqual(network.config_calls[0], [
            "interface Ethernet0/3", " no shutdown", "exit"
        ])
        commands = " ".join(network.config_calls[0]).lower()
        self.assertNotIn("vlan", commands)
        self.assertIn("clear mac address-table dynamic", network.command_calls)
        self.assertEqual(reporter.events[0][1]["event_type"], "RESTORATION")
        self.assertTrue(reporter.events[0][1]["ready_for_experiment"])

    def test_restore_can_run_twice_without_critical_error(self):
        network = FakeNetwork([
            status("administratively_down"), status("up_up"),
            status("up_up"), status("up_up"),
        ])
        reporter = CapturingReporter()
        restorer = ManualRestorer(
            network, self.make_detector(), reporter, settle_seconds=0
        )

        first = restorer.restore("Ethernet0/3", "192.168.1.50")
        second = restorer.restore("Ethernet0/3", "192.168.1.50")
        self.assertTrue(first.ready_for_experiment)
        self.assertTrue(second.ready_for_experiment)
        self.assertEqual(len(reporter.events), 2)
        self.assertEqual(len(network.config_calls), 2)

    def test_agent_shutdown_does_not_restore_automatically(self):
        finalizer = inspect.getsource(SOARAgent._finalizar).lower()
        self.assertNotIn("restaurar_todos", finalizer)
        self.assertNotIn("no shutdown", finalizer)


if __name__ == "__main__":
    unittest.main()
