"""Pruebas de aceptacion del alcance experimental MAC Flooding."""

import contextlib
import importlib
import inspect
import io
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock


ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / "src"
sys.path[:0] = [str(ROOT), str(SRC)]


class MacOnlyScopeTests(unittest.TestCase):
    def test_main_agent_imports_without_scapy(self):
        for module_name in ("agent", "detector", "mitigador"):
            sys.modules.pop(module_name, None)
        with mock.patch.dict(sys.modules, {"scapy": None, "scapy.all": None}):
            module = importlib.import_module("agent")
        self.assertTrue(hasattr(module, "SOARAgent"))

    def test_arp_cannot_enter_detection_or_mitigation(self):
        from agent import SOARAgent
        from detector import Detector
        from mitigador import Mitigador

        self.assertFalse(hasattr(Detector, "iniciar_sniffer"))
        self.assertFalse(hasattr(Detector, "_procesar_arp"))
        self.assertFalse(hasattr(Mitigador, "cuarentena_arp"))
        self.assertNotIn("arp", inspect.getsource(SOARAgent.run).lower())

    def test_configuration_has_no_arp_vlan_or_port_fallback(self):
        from config import settings

        self.assertIs(settings.ENABLE_ARP_DETECTION, False)
        self.assertFalse(hasattr(settings, "VLAN_CUARENTENA"))
        self.assertFalse(hasattr(settings, "PUERTO_ATACANTE_NUM"))
        self.assertFalse(hasattr(settings, "PUERTO_ATACANTE_IOS"))

    def test_new_report_mentions_only_mac_scope(self):
        from reporter import Reporter

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            reporter = Reporter(
                str(root / "metrics.jsonl"),
                str(root / "events.jsonl"),
                str(root / "history.txt"),
            )
            reporter.registrar_evento(
                "MAC_FLOOD_SNMP", "Ethernet0/3", "SHUTDOWN", 10.0,
                mitigation_success=True,
            )
            output = io.StringIO()
            with contextlib.redirect_stdout(output):
                reporter.generar_reporte({"incidentes": 1, "puertos": {}})
            report = output.getvalue().lower()
            self.assertIn("mac flooding", report)
            self.assertNotIn("arp", report)
            self.assertNotIn("scapy", report)

    def test_dashboard_rejects_non_mac_events(self):
        from dashboard import is_mac_event

        self.assertTrue(is_mac_event({
            "accion": "SHUTDOWN", "mitigation_success": True
        }))
        self.assertFalse(is_mac_event({"origen": "ARP_SPOOF"}))


if __name__ == "__main__":
    unittest.main()
