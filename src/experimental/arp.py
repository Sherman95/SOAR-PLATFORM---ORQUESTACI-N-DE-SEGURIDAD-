"""Prototipo no validado de deteccion y respuesta ante ARP Spoofing.

Este modulo se conserva solo como trabajo experimental. ``src/agent.py`` no
lo importa, no lo inicializa y no depende de Scapy para ejecutar el agente de
MAC Flooding. No habilitar en una evaluacion sin una validacion independiente.
"""

import re
import threading
import time
from datetime import datetime


def dot_to_colon(mac_dot: str) -> str:
    h = mac_dot.replace(".", "").lower()
    return ":".join(h[i:i + 2] for i in range(0, 12, 2)) if len(h) == 12 else mac_dot


class ExperimentalARPDetector:
    """Detector ARP anterior, aislado y no utilizado por el agente principal."""

    def __init__(self, network, gateway_ip: str, gateway_mac_fallback: str):
        self.net = network
        self.gateway_ip = gateway_ip
        self.gateway_mac = gateway_mac_fallback
        self._mac_colon = dot_to_colon(gateway_mac_fallback)
        self._arp_count = 0
        self._arp_spoof = None
        self._arp_lock = threading.Lock()
        self._sniffer = None

    def descubrir_gateway_mac(self) -> str:
        out = self.net.comando(f"show ip arp {self.gateway_ip}")
        match = re.search(
            r"([0-9a-fA-F]{4}\.[0-9a-fA-F]{4}\.[0-9a-fA-F]{4})", out
        )
        if match:
            self.gateway_mac = match.group(1).lower()
            self._mac_colon = dot_to_colon(self.gateway_mac)
        return self.gateway_mac

    def verificar_arp_ssh(self):
        if not self.net.esta_vivo():
            return None
        out = self.net.comando(f"show ip arp {self.gateway_ip}")
        match = re.search(
            r"([0-9a-fA-F]{4}\.[0-9a-fA-F]{4}\.[0-9a-fA-F]{4})", out
        )
        if match and match.group(1).lower() != self.gateway_mac:
            return self.gateway_ip, match.group(1).lower()
        return None

    def iniciar_sniffer(self, iface=None) -> bool:
        # Importacion diferida: Scapy solo es necesario al usar este prototipo.
        from scapy.all import AsyncSniffer

        kwargs = {"filter": "arp", "prn": self._procesar_arp, "store": False}
        if iface:
            kwargs["iface"] = iface
        self._sniffer = AsyncSniffer(**kwargs)
        self._sniffer.start()
        return True

    def detener_sniffer(self):
        if self._sniffer:
            self._sniffer.stop()
            self._sniffer = None

    def _procesar_arp(self, pkt):
        from scapy.all import ARP

        if not pkt.haslayer(ARP) or pkt[ARP].op != 2:
            return
        with self._arp_lock:
            self._arp_count += 1
            if (
                pkt[ARP].psrc == self.gateway_ip
                and pkt[ARP].hwsrc.lower() != self._mac_colon
            ):
                self._arp_spoof = (pkt[ARP].psrc, pkt[ARP].hwsrc)

    def leer_y_resetear_arp(self) -> int:
        with self._arp_lock:
            count, self._arp_count = self._arp_count, 0
        return count

    def consumir_spoof(self):
        with self._arp_lock:
            spoof, self._arp_spoof = self._arp_spoof, None
        return spoof


class ExperimentalARPMitigator:
    """Cuarentena VLAN y restauracion ARP, fuera del flujo principal."""

    def __init__(self, network, reporter):
        self.net = network
        self.reporter = reporter

    def cuarentena(
        self,
        puerto_ios: str,
        detector: ExperimentalARPDetector,
        vlan_cuarentena: int,
        vlan_produccion: int,
        intervalo: int,
        max_espera: int,
    ) -> bool:
        ok, _ = self.net.config([
            f"interface {puerto_ios}",
            f" switchport access vlan {vlan_cuarentena}",
            f" description *** ARP-EXPERIMENTAL {datetime.now().isoformat()} ***",
            "exit",
        ])
        if not ok:
            return False
        threading.Thread(
            target=self._recuperar,
            args=(puerto_ios, detector, vlan_produccion, intervalo, max_espera),
            daemon=True,
        ).start()
        return True

    def _recuperar(self, puerto_ios, detector, vlan_produccion, intervalo, max_espera):
        inicio = time.monotonic()
        while time.monotonic() - inicio < max_espera:
            time.sleep(intervalo)
            if detector.verificar_arp_ssh() is None:
                self.net.config([
                    f"interface {puerto_ios}",
                    f" switchport access vlan {vlan_produccion}",
                    " no shutdown",
                    " no description",
                    "exit",
                ])
                return
        self.net.config([f"interface {puerto_ios}", " shutdown", "exit"])
