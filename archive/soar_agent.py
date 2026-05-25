"""
╔══════════════════════════════════════════════════════════════════════════╗
║                                                                          ║
║        AGENTE SOAR — Orquestación de Seguridad Autónoma                  ║
║        Proyecto de Titulación · Redes y Ciberseguridad                   ║
║                                                                          ║
║  Detecta: MAC Flooding + ARP Spoofing en tiempo real                     ║
║  Responde: SSH automático → shutdown + ACL dinámica en <1 segundo        ║
║  Evidencia: Log JSONL + métricas de tiempo + reporte de KPIs             ║
║                                                                          ║
║  Ejecución:  python soar_agent.py                                        ║
║  Restaurar:  python soar_agent.py --restore <puerto_ios>                 ║
║  Solo KPIs:  python soar_agent.py --report                               ║
║                                                                          ║
╚══════════════════════════════════════════════════════════════════════════╝
"""

import sys
import time
import signal
import logging
import argparse
import json
from datetime import datetime

# Módulos del agente
from modules.snmp_monitor  import SNMPMonitor
from modules.analyzer      import ThreatAnalyzer, ThreatType
from modules.ssh_responder import SSHResponder
from modules.arp_capture   import ARPCapture
from modules.event_logger  import EventLogger, setup_logging
from config.config import POLL_INTERVAL_SEC, PUERTOS, PUERTOS_PROTEGIDOS

logger = logging.getLogger("SOAR.MAIN")


# ═══════════════════════════════════════════════════════════════
# Banner de inicio
# ═══════════════════════════════════════════════════════════════
BANNER = """
\033[32m
 ██████  ██████   █████  ██████
 ██      ██   ██ ██   ██ ██   ██
 ███████ ██   ██ ███████ ██████
      ██ ██   ██ ██   ██ ██   ██
 ██████  ██████  ██   ██ ██   ██
\033[0m
\033[36m Orquestación de Seguridad Autónoma · GNS3 Lab\033[0m
\033[90m ─────────────────────────────────────────────\033[0m
"""


# ═══════════════════════════════════════════════════════════════
# Orquestador principal
# ═══════════════════════════════════════════════════════════════
class SOARAgent:
    """
    Orquesta los 4 módulos del agente en el ciclo:
    Monitorear → Detectar → Analizar → Responder → Registrar
    """

    def __init__(self):
        setup_logging(verbose=True)

        self.snmp_monitor = SNMPMonitor()
        self.analyzer     = ThreatAnalyzer()
        self.responder    = SSHResponder()
        self.arp_capture  = ARPCapture(callback=self._on_arp_packet)
        self.event_logger = EventLogger()

        self._running         = True
        self._poll_count      = 0
        self._incidents_total = 0
        self._t_start         = time.time()

        # Registrar señal de interrupción (Ctrl+C)
        signal.signal(signal.SIGINT, self._shutdown_handler)
        signal.signal(signal.SIGTERM, self._shutdown_handler)

    # ───────────────────────────────────────────────────────────
    # Arranque del agente
    # ───────────────────────────────────────────────────────────
    def start(self):
        print(BANNER)
        logger.info("=" * 60)
        logger.info("  SOAR Agent iniciado")
        logger.info(f"  Target switch:  {__import__('config').SWITCH['host']}")
        logger.info(f"  Poll interval:  {POLL_INTERVAL_SEC}s")
        logger.info(f"  Puertos watch:  {list(PUERTOS.keys())}")
        logger.info(f"  Protegidos:     {list(PUERTOS_PROTEGIDOS)}")
        logger.info("=" * 60)

        # Iniciar captura ARP en hilo separado
        self.arp_capture.start()

        # Loop principal de monitoreo SNMP
        self._monitor_loop()

    # ───────────────────────────────────────────────────────────
    # Loop principal
    # ───────────────────────────────────────────────────────────
    def _monitor_loop(self):
        logger.info("Loop de monitoreo SNMP activo. Presiona Ctrl+C para detener.")
        consecutive_errors = 0

        while self._running:
            t_poll_start = time.monotonic()

            try:
                # ── 1. Leer telemetría SNMP ──────────────────
                poll = self.snmp_monitor.poll()
                self._poll_count += 1
                consecutive_errors = 0

                # Log de métricas cada 10 polls (~5 seg)
                if self._poll_count % 10 == 0:
                    self._log_status(poll)

                # ── 2. Analizar amenazas SNMP ─────────────────
                threats = self.analyzer.analyze_snmp(poll)

                # ── 3. Analizar paquetes ARP encolados ────────
                for pkt in self.arp_capture.get_packets():
                    arp_threat = self.analyzer.analyze_arp_packet(pkt)
                    if arp_threat:
                        threats.append(arp_threat)

                # ── 4. Responder a cada amenaza detectada ─────
                for threat in threats:
                    self._handle_threat(threat, poll)

                # ── 5. Registrar métricas de tasa por puerto ──
                for port, data in poll["deltas"].items():
                    if data["rate"] > 0:
                        self.event_logger.log_metric(
                            port, data["rate"], data["total"]
                        )

            except Exception as e:
                consecutive_errors += 1
                logger.error(f"Error en poll #{self._poll_count}: {e}")
                if consecutive_errors >= 10:
                    logger.critical("Demasiados errores consecutivos — verificar conectividad SNMP")
                    consecutive_errors = 0

            # ── Esperar hasta el próximo intervalo ────────────
            elapsed = time.monotonic() - t_poll_start
            sleep_time = max(0, POLL_INTERVAL_SEC - elapsed)
            time.sleep(sleep_time)

    # ───────────────────────────────────────────────────────────
    # Manejar una amenaza detectada
    # ───────────────────────────────────────────────────────────
    def _handle_threat(self, threat, poll: dict):
        self._incidents_total += 1

        logger.critical(
            f"\n{'='*60}\n"
            f"  ⚠  INCIDENTE #{self._incidents_total} DETECTADO\n"
            f"  Tipo:      {threat.threat_type.value}\n"
            f"  Puerto:    {threat.port_ios}\n"
            f"  Severidad: {threat.severity}\n"
            f"  Info:      {threat.description}\n"
            f"{'='*60}"
        )

        # Registrar la detección
        self.event_logger.log_attack_detected(threat)

        # Responder automáticamente (solo para puertos conocidos)
        if threat.port_snmp in PUERTOS and threat.port_snmp not in PUERTOS_PROTEGIDOS:
            logger.warning(f"Iniciando respuesta automática → {threat.port_ios}")
            t0 = time.time()

            response = self.responder.full_response(
                port_ios  = threat.port_ios,
                port_num  = threat.port_snmp,
                evidence  = threat.evidence,
            )

            elapsed_ms = round((time.time() - t0) * 1000, 1)

            if response.get("success"):
                logger.critical(
                    f"  ✓ REMEDIACIÓN EXITOSA en {elapsed_ms} ms\n"
                    f"  Puerto {threat.port_ios} bloqueado.\n"
                    f"  ACL: SOAR-BLOCK-PORT{threat.port_snmp} activa."
                )
            else:
                logger.error(
                    f"  ✗ Remediación fallida: {response.get('error', 'desconocido')}"
                )

            self.event_logger.log_response_executed(threat, response)

        elif threat.threat_type == ThreatType.ARP_SPOOFING:
            # ARP Spoofing sin puerto conocido → alertar pero no bloquear a ciegas
            logger.warning(
                f"ARP Spoofing detectado sin puerto confirmado. "
                f"Revisar manualmente: {threat.evidence}"
            )

    # ───────────────────────────────────────────────────────────
    # Callback para paquetes ARP (desde hilo de captura)
    # ───────────────────────────────────────────────────────────
    def _on_arp_packet(self, pkt_info: dict):
        # Solo loguear ARP replies gratuitous (muy sospechosos)
        if pkt_info.get("is_gratuitous"):
            logger.warning(
                f"ARP Gratuitous: {pkt_info['src_mac']} → {pkt_info['src_ip']}"
            )

    # ───────────────────────────────────────────────────────────
    # Log de estado periódico
    # ───────────────────────────────────────────────────────────
    def _log_status(self, poll: dict):
        uptime = round(time.time() - self._t_start)
        stats  = self.analyzer.get_stats()
        arp    = self.arp_capture.get_stats()
        logger.info(
            f"[Status] uptime={uptime}s | polls={self._poll_count} | "
            f"incidentes={self._incidents_total} | "
            f"total_macs={poll['total_macs']} | "
            f"arp_pkts={arp['total']} | "
            f"alertas_activas={stats['active_alerts']}"
        )

    # ───────────────────────────────────────────────────────────
    # Shutdown limpio
    # ───────────────────────────────────────────────────────────
    def _shutdown_handler(self, sig, frame):
        print("\n")
        logger.info("Señal de parada recibida — cerrando agente...")
        self._running = False
        self.arp_capture.stop()
        self._print_final_report()
        sys.exit(0)

    def _print_final_report(self):
        kpis = self.event_logger.compute_kpis()
        print("\n" + "="*60)
        print("  REPORTE FINAL DEL EXPERIMENTO")
        print("="*60)
        for k, v in kpis.items():
            print(f"  {k:<30} {v}")
        print("="*60)

        # Guardar reporte en JSON
        report_path = f"reports/kpis_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
        import pathlib
        pathlib.Path("reports").mkdir(exist_ok=True)
        with open(report_path, "w") as f:
            json.dump(kpis, f, indent=2)
        logger.info(f"Reporte guardado en {report_path}")


# ═══════════════════════════════════════════════════════════════
# CLI — Modos de ejecución
# ═══════════════════════════════════════════════════════════════
def main():
    parser = argparse.ArgumentParser(
        description="SOAR Agent — Orquestación de Seguridad Autónoma"
    )
    parser.add_argument(
        "--restore",
        metavar="PUERTO_IOS",
        help='Restaurar puerto bloqueado. Ej: --restore "ethernet 0/3"'
    )
    parser.add_argument(
        "--report",
        action="store_true",
        help="Mostrar KPIs del log existente y salir"
    )
    parser.add_argument(
        "--test-ssh",
        action="store_true",
        help="Verificar conexión SSH al switch y salir"
    )
    args = parser.parse_args()

    setup_logging()

    # ── Modo restaurar puerto ────────────────────────────────
    if args.restore:
        logger.info(f"Restaurando puerto: {args.restore}")
        responder = SSHResponder()
        port_num  = int(args.restore.split("/")[-1]) + 1  # estimación
        result    = responder.restore_port(args.restore, port_num)
        print(json.dumps(result, indent=2))
        return

    # ── Modo reporte KPIs ────────────────────────────────────
    if args.report:
        el   = EventLogger()
        kpis = el.compute_kpis()
        print(json.dumps(kpis, indent=2))
        return

    # ── Modo test SSH ────────────────────────────────────────
    if args.test_ssh:
        from netmiko import ConnectHandler
        from config.config import SWITCH
        logger.info(f"Probando SSH a {SWITCH['host']}...")
        try:
            conn = ConnectHandler(**SWITCH)
            conn.enable()
            out  = conn.send_command("show version | include IOS")
            conn.disconnect()
            logger.info(f"SSH OK: {out.strip()[:80]}")
        except Exception as e:
            logger.error(f"SSH FALLO: {e}")
        return

    # ── Modo principal: monitoreo continuo ───────────────────
    agent = SOARAgent()
    agent.start()


if __name__ == "__main__":
    main()
