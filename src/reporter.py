"""
reporter.py — Módulo de Reportes
Responsabilidad única: registrar métricas, eventos y generar reportes.
No contiene lógica de red ni de mitigación.
"""

import json
import os
import re
from datetime import datetime

from colorama import Fore, Style
from config.version import VERSION_LABEL


class Reporter:
    """
    Gestiona el registro persistente de métricas y eventos.
    Genera el reporte final de la sesión.
    """

    def __init__(self, metrics_file: str, events_file: str, history_file: str,
                 reset_session: bool = True, run_id: str = None):
        self.metrics_file = metrics_file
        self.events_file  = events_file
        self.history_file = history_file
        self.run_id = run_id

        self._buffer  = []   # buffer de métricas para reducir I/O
        self._eventos = []   # registro en memoria de todos los eventos
        self._alertas = []

        # El agente inicia archivos de sesion; comandos externos solo anexan.
        for path in (metrics_file, events_file):
            if not path:
                continue
            os.makedirs(os.path.dirname(path), exist_ok=True)
            if reset_session:
                try:
                    open(path, "w", encoding="utf-8").close()
                except Exception as e:
                    print(f"{Fore.YELLOW} [!] No se pudo inicializar {path}: {e}{Style.RESET_ALL}")

    # ── Métricas ──────────────────────────────────────────────────────────
    def registrar_metrica(self, rate: int, total_macs: int):
        """Registra la tasa MAC/s y el total CAM; escribe cada 10 muestras."""
        self._buffer.append({
            "run_id":     self.run_id,
            "ts":         datetime.now().isoformat(),
            "rate":       rate,
            "total_macs": total_macs,
        })
        if len(self._buffer) >= 10:
            self.flush_metricas()

    def flush_metricas(self):
        """Escribe el buffer de métricas al disco."""
        if not self._buffer:
            return
        if not self.metrics_file:
            self._buffer.clear()
            return
        try:
            with open(self.metrics_file, "a", encoding="utf-8") as f:
                f.writelines(json.dumps(m) + "\n" for m in self._buffer)
            self._buffer.clear()
        except Exception as e:
            print(f"{Fore.YELLOW} [!] Error guardando métricas: {e}{Style.RESET_ALL}")

    # ── Eventos ───────────────────────────────────────────────────────────
    def registrar_evento(self, origen: str, puerto: str,
                         accion: str, ms: float = None, **details):
        """Registra un evento de mitigación o recuperación."""
        ev = {
            "run_id":     self.run_id,
            "event_type": "MITIGATION",
            "origen":     origen,
            "puerto":     puerto,
            "accion":     accion,
            "ts":         datetime.now().isoformat(),
        }
        if ms is not None:
            ev["ms"] = ms
        ev.update(details)

        self._eventos.append(ev)

        try:
            with open(self.events_file, "a", encoding="utf-8") as f:
                f.write(json.dumps(ev) + "\n")
        except Exception as e:
            print(f"{Fore.YELLOW} [!] Error guardando evento: {e}{Style.RESET_ALL}")

    def registrar_alerta(self, alerta: str, **details):
        """Registra condiciones que deliberadamente no ejecutan mitigacion."""
        event = {
            "run_id": self.run_id,
            "event_type": "ALERT",
            "alert": alerta,
            "ts": datetime.now().isoformat(),
            **details,
        }
        self._alertas.append(event)
        try:
            with open(self.events_file, "a", encoding="utf-8") as file:
                file.write(json.dumps(event) + "\n")
        except Exception as exc:
            print(f"{Fore.YELLOW} [!] Error guardando alerta: {exc}{Style.RESET_ALL}")

    # ── Reporte final ─────────────────────────────────────────────────────
    def generar_reporte(self, stats: dict):
        """
        Genera e imprime el reporte final de la sesión.
        stats: dict con uptime, polls, poll_interval, incidentes,
               historico_bloqueados y puertos.
        """
        self.flush_metricas()

        puertos  = stats.get("puertos", {})
        interfaces_detectadas = stats.get("interfaces_detectadas", {})
        hist_blq = stats.get("historico_bloqueados", set())
        blq_str  = ", ".join(
            interfaces_detectadas.get(p, puertos.get(p, str(p))) for p in hist_blq
        ) or "Ninguno"

        tiempos = [
            e["end_to_end_ms"] for e in self._eventos
            if e.get("end_to_end_ms", 0) > 0
            and e.get("mitigation_success") is True
        ]
        t_prom  = round(sum(tiempos) / len(tiempos), 1) if tiempos else 0
        t_min   = round(min(tiempos), 1) if tiempos else 0
        operation_mode = (
            "observe_only" if stats.get("observe_only") else "shutdown_only"
        )

        lineas = [
            f"\n{Fore.CYAN}{'=' * 57}",
            f"  REPORTE DEL EXPERIMENTO — SOAR {VERSION_LABEL} Modular",
            f"{'=' * 57}{Style.RESET_ALL}",
            f"  Fecha/Hora:        {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}",
            f"  Uptime Misión:     {stats.get('uptime', 0)} s",
            f"  Monitoreo Core:    {stats.get('polls', 0)} ciclos "
            f"(Muestreo: {stats.get('poll_interval', 0.5)}s)",
            f"  Incidentes:        {stats.get('incidentes', 0)}",
            f"  Anomalías:         {stats.get('anomalias', 0)}",
            f"  Fallos SNMP:       {stats.get('snmp_failures', 0)}",
            f"  Escenario real:    {stats.get('scenario_label', 'attack')}",
            f"  Modo:              "
            f"{operation_mode}",
            f"  Umbral:            "
            f"{stats.get('threshold_mac_per_second')} MAC/s",
            f"  Clasificación:     {stats.get('classification', 'not_evaluated')}",
            f"  Interfaces afect.: [{blq_str}]",
            f"  T. prom end-to-end:{t_prom} ms",
            f"  T. min end-to-end: {t_min} ms",
            f"  {'─' * 53}",
            f"  ALCANCE VALIDADO",
            f"  MAC Flooding (SNMP, {operation_mode}): ACTIVO",
            f"  {'─' * 53}",
            f"  EVENTOS DE MITIGACIÓN",
        ]

        for ev in self._eventos:
            ms_str = f" ({ev['ms']}ms)" if ev.get("ms") else ""
            lineas.append(
                f"    [{ev['ts'][:19]}] {ev['accion']:<25} "
                f"← {ev['origen']} en {ev['puerto']}{ms_str}"
            )
        if not self._eventos:
            lineas.append("    (ninguno)")

        lineas.append(f"  ALERTAS DE OBSERVACIÓN")
        for alert in self._alertas:
            lineas.append(
                f"    [{alert['ts'][:19]}] {alert['alert']} "
                f"en {alert.get('detected_interface') or alert.get('bridge_port', '?')}"
            )
        if not self._alertas:
            lineas.append("    (ninguna)")

        lineas.append(f"{Fore.CYAN}{'=' * 57}{Style.RESET_ALL}")

        for l in lineas:
            print(l)

        # Persistir en historial
        ansi = re.compile(r'\x1B(?:[@-Z\\-_]|\[[0-?]*[ -/]*[@-~])')
        try:
            os.makedirs(os.path.dirname(self.history_file), exist_ok=True)
            with open(self.history_file, "a", encoding="utf-8") as f:
                f.write(f"\n[{datetime.now().isoformat()}]\n")
                for l in lineas:
                    f.write(ansi.sub('', l) + "\n")
                f.write("-" * 57 + "\n")
        except Exception as e:
            print(f"{Fore.YELLOW} [!] Error guardando historial: {e}{Style.RESET_ALL}")
