#!/usr/bin/env python3
"""
SOAR Agent — Orquestador Modular
======================================
Responsabilidad única: coordinar los módulos y mantener el bucle principal.
Este archivo NO contiene lógica de red, detección ni mitigación — solo orquesta.

Arquitectura:
  NetworkManager → gestiona SSH
  Detector       → detecta MAC Flooding mediante SNMP
  Mitigador      → ejecuta y verifica shutdown_only
  Reporter       → registra métricas, eventos e historial
"""

import argparse
import time
import signal
import sys
import os

from colorama import Fore, Back, Style, init

# ─── Rutas ────────────────────────────────────────────────────────────────────
_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
sys.path.insert(0, _ROOT)
sys.path.insert(0, os.path.dirname(__file__))

# ─── Configuración ────────────────────────────────────────────────────────────
from config.settings import (
    SWITCH, SNMP, MAC_THRESHOLD_PER_SECOND, POLL_INTERVAL,
    SNMP_DEGRADED_AFTER,
    PUERTOS, PROTECTED_INTERFACES,
    EXPERIMENT_ROOT, KALI_CONNECTED_INTERFACE, MACOF_COMMAND,
)
from config.version import VERSION_LABEL

# ─── Módulos ──────────────────────────────────────────────────────────────────
from network   import NetworkManager
from detector  import CamMonitorState, Detector, calcular_tasa_mac
from mitigador import Mitigador
from reporter  import Reporter
from experiment import ExperimentRun

init(autoreset=True)


def clear_screen():
    os.system("cls" if os.name == "nt" else "clear")


def normalizar_interfaz(nombre: str) -> str:
    return nombre.replace(" ", "").lower()


class SOARAgent:
    """
    Orquestador principal.
    Crea y conecta los módulos, ejecuta el bucle de vigilancia
    y coordina las respuestas ante amenazas detectadas.
    """

    def __init__(
        self,
        observe_only=False,
        scenario_label="attack",
        threshold_mac_per_second=MAC_THRESHOLD_PER_SECOND,
        campaign_id="default",
    ):
        self.observe_only = bool(observe_only)
        self.scenario_label = scenario_label
        self.threshold_mac_per_second = threshold_mac_per_second
        self.experiment = ExperimentRun(
            EXPERIMENT_ROOT,
            self.threshold_mac_per_second,
            POLL_INTERVAL,
            KALI_CONNECTED_INTERFACE,
            MACOF_COMMAND,
            scenario_label=self.scenario_label,
            observe_only=self.observe_only,
            campaign_id=campaign_id,
        )
        self.net       = NetworkManager(SWITCH)
        self.reporter  = Reporter(
            None,
            str(self.experiment.events_file),
            str(self.experiment.report_file),
            run_id=self.experiment.run_id,
        )
        self.detector  = Detector(self.net, SNMP)
        self.mitigador = Mitigador(self.net, self.reporter)
        self.cam_state  = CamMonitorState(SNMP_DEGRADED_AFTER)

        self.incidentes = 0
        self.anomalias   = 0
        self.polls      = 0
        self.snmp_failures_total = 0
        self.t_start_ns = time.monotonic_ns()
        self._running   = True

        signal.signal(signal.SIGINT, self._stop)

    def _resolver_objetivo(self, bridge_port: int, new_mac_count: int):
        """Retorna una identidad bloqueable o alerta y retorna None."""
        threshold = getattr(
            self, "threshold_mac_per_second", MAC_THRESHOLD_PER_SECOND
        )
        identity = self.detector.resolver_interfaz(bridge_port)
        if identity is None:
            print(
                f"{Back.YELLOW}{Fore.BLACK} INTERFAZ_NO_RESUELTA "
                f"{Style.RESET_ALL} bridge_port={bridge_port}; no se bloquea."
            )
            self.reporter.registrar_alerta(
                "INTERFAZ_NO_RESUELTA",
                bridge_port=bridge_port,
                new_mac_count=new_mac_count,
                threshold_mac_per_second=threshold,
            )
            return None

        protected = {
            normalizar_interfaz(name) for name in PROTECTED_INTERFACES
        }
        if (
            normalizar_interfaz(identity.if_name) in protected
            or bridge_port in self.mitigador.bloqueados
        ):
            return None
        return identity

    def _registrar_observacion(
        self,
        bridge_port,
        new_mac_count,
        rate,
        poll_started_ns,
        cam_received_ns,
        anomaly_identified_ns,
        actual_poll_interval_ms,
        snmp_walks=None,
    ):
        """Registra la detección sin ejecutar ninguna configuración IOS."""
        identity = self.detector.resolver_interfaz(bridge_port)
        detected_interface = identity.if_name if identity else None
        result = {
            "event_type": "MAC_FLOOD_OBSERVED",
            "bridge_port": bridge_port,
            "if_index": identity.if_index if identity else None,
            "detected_interface": detected_interface,
            "new_mac_count": new_mac_count,
            "mac_rate_per_second": round(rate, 3),
            "threshold_mac_per_second": self.threshold_mac_per_second,
            "snmp_read_ms": round(
                (cam_received_ns - poll_started_ns) / 1_000_000, 3
            ),
            "analysis_ms": round(
                (anomaly_identified_ns - cam_received_ns) / 1_000_000, 3
            ),
            "detection_cycle_ms": round(
                (anomaly_identified_ns - poll_started_ns) / 1_000_000, 3
            ),
            "snmp_walks": snmp_walks or [],
            "actual_poll_interval_ms": actual_poll_interval_ms,
            "scenario_label": self.scenario_label,
            "observe_only": True,
            "configuration_sent": False,
        }
        self.reporter.registrar_alerta("MAC_FLOOD_OBSERVED", **result)
        self.experiment.record_detection(result)
        interface_text = detected_interface or f"bridge_port={bridge_port}"
        print(
            f"\n{Back.YELLOW}{Fore.BLACK} OBSERVACION MAC FLOOD "
            f"{Style.RESET_ALL} {new_mac_count} MACs, {rate:.1f}/s en "
            f"{interface_text}; sin shutdown."
        )

    # ── Inicialización ────────────────────────────────────────────────────────
    def inicializar(self):
        """
        Fase de arranque:
          1) Conectar SSH
          2) No modificar VLAN, Port Security ni estado de interfaces
          3) Calibrar la tabla CAM antes de iniciar la vigilancia
        """
        if not self.net.conectar():
            self.experiment.finalize(status="initialization_failed")
            sys.exit(1)


    # ── Bucle principal ───────────────────────────────────────────────────────
    def run(self):
        clear_screen()
        print(f"{Fore.CYAN} [*] Iniciando SOAR Agent {VERSION_LABEL} — Arquitectura Modular{Style.RESET_ALL}")
        print(
            f"{Fore.CYAN} [*] Run {self.experiment.run_id}: "
            f"escenario={self.scenario_label}, "
            f"campaña={self.experiment.metadata['campaign_id']}, "
            f"umbral={self.threshold_mac_per_second} MAC/s, "
            f"modo={'observe_only' if self.observe_only else 'shutdown_only'}."
            f"{Style.RESET_ALL}"
        )
        self.inicializar()
        self.experiment.capture_switch(self.net, self.experiment.switch_before_file)

        # Calibración del baseline
        print(f"{Fore.CYAN} [*] Calibrando baseline (3 muestras)...{Style.RESET_ALL}")
        previous_poll_start_ns = None
        for baseline_index in range(3):
            poll_started_ns = time.monotonic_ns()
            actual_interval_ms = (
                round((poll_started_ns - previous_poll_start_ns) / 1_000_000, 3)
                if previous_poll_start_ns is not None else None
            )
            previous_poll_start_ns = poll_started_ns
            result = self.detector.leer_cam()
            cam_received_ns = time.monotonic_ns()
            comparison = self.cam_state.observe(result, cam_received_ns)
            baseline_total = sum(len(macs) for macs in result.entries.values())
            self.experiment.record_snapshot(
                result,
                f"baseline_{baseline_index + 1}",
                poll_started_ns,
                actual_interval_ms,
                rate=0,
                total_macs=baseline_total,
            )
            if comparison is None:
                self.snmp_failures_total += 1
                print(
                    f"{Fore.YELLOW} [!] Muestra de baseline descartada: "
                    f"{result.error_type}.{Style.RESET_ALL}"
                )
                if self.cam_state.telemetry_degraded:
                    print(
                        f"{Back.YELLOW}{Fore.BLACK} TELEMETRIA_DEGRADADA "
                        f"{Style.RESET_ALL}"
                    )
                time.sleep(POLL_INTERVAL)
                continue
            for macs in result.entries.values():
                self.detector.baseline_macs.update(macs)
            time.sleep(POLL_INTERVAL)
        print(f"{Fore.GREEN} [+] Baseline: {len(self.detector.baseline_macs)} MACs legítimas.{Style.RESET_ALL}")
        self.experiment.mark_baseline(len(self.detector.baseline_macs))

        print(f"\n{Back.BLUE}{Fore.WHITE}{Style.BRIGHT}"
              f" [ SOAR {VERSION_LABEL} — VIGILANCIA EN VIVO ] "
              f"{Style.RESET_ALL}\n")

        while self._running:
            poll_started_ns = time.monotonic_ns()
            actual_poll_interval_ms = (
                round((poll_started_ns - previous_poll_start_ns) / 1_000_000, 3)
                if previous_poll_start_ns is not None else None
            )
            previous_poll_start_ns = poll_started_ns
            self.polls += 1

            result = self.detector.leer_cam()
            cam_received_ns = time.monotonic_ns()
            comparison = self.cam_state.observe(result, cam_received_ns)

            if comparison is None:
                self.snmp_failures_total += 1
                failures = self.cam_state.consecutive_failures
                print(
                    f"{Fore.YELLOW} [!] SNMP no disponible "
                    f"({failures} fallo(s)); ciclo sin mitigacion.{Style.RESET_ALL}"
                )
                if failures == SNMP_DEGRADED_AFTER:
                    print(
                        f"{Back.YELLOW}{Fore.BLACK} TELEMETRIA_DEGRADADA "
                        f"{Style.RESET_ALL}"
                    )
                    self.reporter.registrar_alerta(
                        "TELEMETRIA_DEGRADADA",
                        error_type=result.error_type,
                        error_message=result.error_message,
                        consecutive_failures=failures,
                    )
                self.experiment.record_snapshot(
                    result,
                    self.polls,
                    poll_started_ns,
                    actual_poll_interval_ms,
                )
                elapsed = (time.monotonic_ns() - poll_started_ns) / 1_000_000_000
                time.sleep(max(0, POLL_INTERVAL - elapsed))
                continue

            if comparison.recovered_after_failures:
                print(
                    f"{Fore.GREEN} [+] TELEMETRIA_RESTAURADA tras "
                    f"{comparison.recovered_after_failures} fallo(s).{Style.RESET_ALL}"
                )

            cam = comparison.current_entries
            prev_macs = comparison.previous_entries
            total = sum(len(macs) for macs in cam.values())
            sample_seconds = comparison.elapsed_since_valid

            # La primera lectura valida establece estado, nunca dispara mitigacion.
            if sample_seconds == 0:
                for macs in cam.values():
                    self.detector.baseline_macs.update(macs)
                self.reporter.registrar_metrica(0, total)
                self.experiment.record_snapshot(
                    result,
                    self.polls,
                    poll_started_ns,
                    actual_poll_interval_ms,
                    rate=0,
                    total_macs=total,
                )
                elapsed = (time.monotonic_ns() - poll_started_ns) / 1_000_000_000
                time.sleep(max(0, POLL_INTERVAL - elapsed))
                continue

            nuevas_por_puerto = {
                puerto: len(macs - prev_macs.get(puerto, set()))
                for puerto, macs in cam.items()
            }
            tasas_por_puerto = {
                puerto: calcular_tasa_mac(nuevas, sample_seconds)
                for puerto, nuevas in nuevas_por_puerto.items()
            }
            pico_tasa = max(tasas_por_puerto.values(), default=0.0)
            self.reporter.registrar_metrica(round(pico_tasa, 2), total)
            self.experiment.record_snapshot(
                result,
                self.polls,
                poll_started_ns,
                actual_poll_interval_ms,
                rate=round(pico_tasa, 2),
                total_macs=total,
            )

            # ── (A) MAC FLOODING — SNMP ───────────────────────────────────
            for puerto, macs in cam.items():
                nuevas = nuevas_por_puerto.get(puerto, 0)
                tasa = tasas_por_puerto.get(puerto, 0.0)
                if tasa >= self.threshold_mac_per_second:
                    anomaly_identified_ns = time.monotonic_ns()
                    self.anomalias += 1
                    if self.observe_only:
                        self._registrar_observacion(
                            puerto,
                            nuevas,
                            tasa,
                            poll_started_ns,
                            cam_received_ns,
                            anomaly_identified_ns,
                            actual_poll_interval_ms,
                            getattr(result, "snmp_walks", []),
                        )
                        continue
                    self.experiment.record_detection({
                        "event_type": "MAC_FLOOD_DETECTED",
                        "bridge_port": puerto,
                        "new_mac_count": nuevas,
                        "mac_rate_per_second": round(tasa, 3),
                        "threshold_mac_per_second": self.threshold_mac_per_second,
                        "snmp_read_ms": round(
                            (cam_received_ns - poll_started_ns) / 1_000_000, 3
                        ),
                        "analysis_ms": round(
                            (anomaly_identified_ns - cam_received_ns) / 1_000_000,
                            3,
                        ),
                        "detection_cycle_ms": round(
                            (anomaly_identified_ns - poll_started_ns) / 1_000_000,
                            3,
                        ),
                        "snmp_walks": getattr(result, "snmp_walks", []),
                        "scenario_label": self.scenario_label,
                        "observe_only": False,
                    })
                    identity = self._resolver_objetivo(puerto, nuevas)
                    if identity is None:
                        continue
                    ios = identity.if_name
                    print(f"\n{Back.RED}{Fore.WHITE}"
                          f" 💥 MAC FLOOD ({nuevas} MACs, {tasa:.1f}/s) en {ios} "
                          f"{Style.RESET_ALL}")
                    if self.mitigador.bloquear_mac_flood(
                        puerto, ios,
                        if_index=identity.if_index,
                        new_mac_count=nuevas,
                        threshold_mac_per_second=self.threshold_mac_per_second,
                        poll_started_ns=poll_started_ns,
                        cam_received_ns=cam_received_ns,
                        anomaly_identified_ns=anomaly_identified_ns,
                        actual_poll_interval_ms=actual_poll_interval_ms,
                        snmp_walks=getattr(result, "snmp_walks", []),
                    ):
                        self.incidentes += 1
                    if self.mitigador.last_result:
                        self.experiment.record_mitigation(
                            self.mitigador.last_result
                        )

            # Status cada 2 ciclos
            if self.polls % 2 == 0:
                bloq = self.mitigador.bloqueados
                print(f"{Fore.CYAN} ⚡ Polls: {self.polls:03d} | "
                      f"CAM: {total:03d} MACs | "
                      f"Bloqueados: {bloq if bloq else '∅'}"
                      f"{Style.RESET_ALL}")

            if not self._running:
                break
            elapsed = (time.monotonic_ns() - poll_started_ns) / 1_000_000_000
            time.sleep(max(0, POLL_INTERVAL - elapsed))

        self._finalizar()

    def _stop(self, *_):
        self._running = False
        print(f"\n{Fore.YELLOW}[!] Deteniendo agente...{Style.RESET_ALL}")

    # ── Finalización ──────────────────────────────────────────────────────────
    def _finalizar(self):
        self.experiment.capture_switch(self.net, self.experiment.switch_after_file)
        experiment_metrics = self.experiment.finalize()
        self.reporter.generar_reporte({
            "uptime":               round(
                (time.monotonic_ns() - self.t_start_ns) / 1_000_000_000, 1
            ),
            "polls":                self.polls,
            "poll_interval":        POLL_INTERVAL,
            "incidentes":           self.incidentes,
            "anomalias":            self.anomalias,
            "historico_bloqueados": self.mitigador.historico_bloqueados,
            "interfaces_detectadas": self.mitigador.historico_interfaces,
            "snmp_failures":         self.snmp_failures_total,
            "puertos":              PUERTOS,
            "scenario_label":       self.scenario_label,
            "observe_only":         self.observe_only,
            "threshold_mac_per_second": self.threshold_mac_per_second,
            "classification":       experiment_metrics["classification"],
        })

        if self.mitigador.blocked_interfaces:
            print(
                f"\n{Fore.YELLOW} [!] Restauracion manual requerida para: "
                f"{', '.join(sorted(self.mitigador.blocked_interfaces))}."
                f"{Style.RESET_ALL}"
            )
            print(
                f"{Fore.YELLOW}     Use: python run.py restore --interface "
                f"<INTERFAZ>{Style.RESET_ALL}"
            )
        self.net.desconectar()
        sys.exit(0)


def parse_args():
    parser = argparse.ArgumentParser(description="Agente experimental MAC Flooding")
    parser.add_argument("--observe-only", action="store_true")
    parser.add_argument(
        "--scenario", choices=("normal", "attack"), default="attack"
    )
    parser.add_argument(
        "--threshold", type=float, default=MAC_THRESHOLD_PER_SECOND
    )
    parser.add_argument("--campaign-id", default="default")
    args = parser.parse_args()
    if args.threshold <= 0:
        parser.error("--threshold debe ser mayor que cero")
    if args.scenario == "normal" and not args.observe_only:
        parser.error("un escenario normal requiere --observe-only")
    return args


if __name__ == "__main__":
    cli_args = parse_args()
    SOARAgent(
        observe_only=cli_args.observe_only,
        scenario_label=cli_args.scenario,
        threshold_mac_per_second=cli_args.threshold,
        campaign_id=cli_args.campaign_id,
    ).run()
