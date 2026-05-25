#!/usr/bin/env python3
"""
SOAR Agent v2.1 — Deteccion dual: SNMP + ARP local
Si el SNMP falla (switch saturado), el ARP igual detecta el ataque
porque los paquetes llegan directamente a tu PC por el Cloud node.
"""

import time, signal, sys, json, logging, threading
from datetime import datetime
from collections import defaultdict
from netmiko import ConnectHandler
from pysnmp.hlapi import (nextCmd, SnmpEngine, CommunityData,
                          UdpTransportTarget, ContextData,
                          ObjectType, ObjectIdentity)
from colorama import Fore, Style, init
init(autoreset=True)

# ─── CONFIGURACION ────────────────────────────────────────────
SWITCH = {
    "device_type": "cisco_ios",
    "host":        "192.168.1.10",
    "username":    "admin",
    "password":    "cisco123",
    "secret":      "cisco123",
    "timeout":     30,
}
SNMP_HOST     = "192.168.1.10"
SNMP_COMM     = "public"
UMBRAL_SNMP   = 50    # MACs/seg via SNMP → alerta
UMBRAL_ARP    = 100   # paquetes ARP/seg via captura local → alerta
POLL_INTERVAL = 0.5
PUERTOS = {
    1: "ethernet 0/0",   # uplink — PROTEGIDO
    2: "ethernet 0/1",   # victima-1
    3: "ethernet 0/2",   # victima-2
    4: "ethernet 0/3",   # atacante
    5: "ethernet 1/0",   # cloud/agente — PROTEGIDO
}
PROTEGIDOS = {1, 5}
# Puerto IOS del atacante para bloqueo por ARP
# (cuando SNMP no puede decir el numero de puerto exacto)
PUERTO_ATACANTE_IOS = "ethernet 0/3"
PUERTO_ATACANTE_NUM = 4

# ─── HELPERS ─────────────────────────────────────────────────
logging.basicConfig(level=logging.WARNING)

def ts():
    return datetime.now().strftime("%H:%M:%S.%f")[:12]

def log_info(msg):   print(f"{Fore.CYAN}[{ts()}] INFO     {Style.RESET_ALL}{msg}")
def log_warn(msg):   print(f"{Fore.YELLOW}[{ts()}] WARN     {Style.RESET_ALL}{msg}")
def log_alert(msg):  print(f"{Fore.RED}{Style.BRIGHT}[{ts()}] ⚠ ALERTA  {Style.RESET_ALL}{msg}")
def log_ok(msg):     print(f"{Fore.GREEN}{Style.BRIGHT}[{ts()}] ✓ OK      {Style.RESET_ALL}{msg}")
def log_error(msg):  print(f"{Fore.RED}[{ts()}] ERROR    {Style.RESET_ALL}{msg}")

BANNER = f"""{Fore.GREEN}
 ██████  ██████   █████  ██████     v2.1
 ██      ██   ██ ██   ██ ██   ██    SNMP + ARP dual
 ███████ ██   ██ ███████ ██████     SSH Persistente
      ██ ██   ██ ██   ██ ██   ██    Respuesta <200ms
 ██████  ██████  ██   ██ ██   ██
{Style.RESET_ALL}"""


# ══════════════════════════════════════════════════════════════
class SOARAgent:

    def __init__(self):
        self.conn         = None
        self.prev_macs    = {}
        self.prev_time    = time.monotonic()
        self.bloqueados   = set()
        self.incidentes   = 0
        self.polls        = 0
        self.t_start      = time.time()
        self.eventos      = []
        self._running     = True

        # Contador ARP para deteccion alternativa
        self._arp_count   = 0        # paquetes ARP en la ventana
        self._arp_lock    = threading.Lock()
        self._arp_alertado = False   # para no alertar dos veces

        signal.signal(signal.SIGINT, self._stop)

    # ── SSH persistente ───────────────────────────────────────
    def conectar_ssh(self) -> bool:
        try:
            log_info(f"Conectando SSH a {SWITCH['host']}...")
            self.conn = ConnectHandler(**SWITCH)
            self.conn.enable()
            out = self.conn.send_command("show version | include IOS")
            log_ok(f"SSH OK: {out.strip()[:55]}")
            return True
        except Exception as e:
            log_error(f"SSH fallo: {e}")
            return False

    def _ssh_vivo(self) -> bool:
        try:
            self.conn.send_command("", expect_string=r"[>#]", max_loops=5)
            return True
        except:
            log_warn("SSH caido — reconectando...")
            return self.conectar_ssh()

    # ── SNMP: leer tabla CAM ──────────────────────────────────
    def leer_cam(self) -> dict:
        cam = defaultdict(set)
        try:
            for (err, _, _, vbs) in nextCmd(
                SnmpEngine(),
                CommunityData(SNMP_COMM, mpModel=1),
                UdpTransportTarget((SNMP_HOST, 161), timeout=1.5, retries=0),
                ContextData(),
                ObjectType(ObjectIdentity("BRIDGE-MIB", "dot1dTpFdbPort")),
                lexicographicMode=False, maxRows=8000,
            ):
                if err: break
                for vb in vbs:
                    try:
                        oid   = str(vb[0])
                        port  = int(str(vb[1]))
                        parts = oid.split(".")
                        mac   = ":".join(f"{int(x):02x}" for x in parts[-6:])
                        cam[port].add(mac)
                    except: pass
        except Exception as e:
            log_warn(f"SNMP error: {e}")
        return cam

    # ── Deteccion SNMP ────────────────────────────────────────
    def detectar_snmp(self, cam: dict) -> list:
        ahora   = time.monotonic()
        elapsed = max(ahora - self.prev_time, 0.01)
        alertas = []

        for puerto, macs in cam.items():
            if puerto in PROTEGIDOS or puerto in self.bloqueados:
                continue
            nuevas = macs - self.prev_macs.get(puerto, set())
            tasa   = len(nuevas) / elapsed
            if tasa >= UMBRAL_SNMP:
                alertas.append({
                    "origen":     "SNMP",
                    "puerto":     puerto,
                    "puerto_ios": PUERTOS.get(puerto, f"e0/{puerto-1}"),
                    "tasa":       round(tasa, 1),
                    "total_macs": len(macs),
                })

        self.prev_macs = {p: m.copy() for p, m in cam.items()}
        self.prev_time = ahora
        return alertas

    # ── Captura ARP en hilo separado ──────────────────────────
    def iniciar_arp_sniffer(self):
        """
        Intenta iniciar Scapy para capturar ARP.
        Si Scapy no esta disponible, lo omite silenciosamente.
        """
        try:
            from scapy.all import sniff, ARP
            def _callback(pkt):
                if pkt.haslayer(ARP):
                    with self._arp_lock:
                        self._arp_count += 1

            def _loop():
                sniff(filter="arp", prn=_callback,
                      store=False, stop_filter=lambda _: not self._running)

            t = threading.Thread(target=_loop, daemon=True, name="ARP-sniffer")
            t.start()
            log_info("Captura ARP activa (deteccion secundaria)")
        except Exception as e:
            log_warn(f"ARP sniffer no disponible: {e} — usando solo SNMP")

    def leer_tasa_arp(self) -> float:
        """Retorna paquetes ARP por segundo y resetea el contador."""
        with self._arp_lock:
            count = self._arp_count
            self._arp_count = 0
        return count / POLL_INTERVAL

    # ── Bloqueo via SSH ───────────────────────────────────────
    def bloquear(self, alerta: dict) -> bool:
        puerto_ios = alerta["puerto_ios"]
        puerto_num = alerta["puerto"]
        acl_name   = f"SOAR-BLOCK-P{puerto_num}"
        ts_b       = datetime.now().isoformat()[:19]
        t0         = time.monotonic()

        try:
            if not self._ssh_vivo():
                return False

            self.conn.send_config_set([
                f"interface {puerto_ios}",
                "shutdown",
                f"description *** BLOQUEADO-SOAR {ts_b} [{alerta['origen']}] ***",
                "exit",
                f"ip access-list extended {acl_name}",
                " deny   ip any any log",
                " permit ip any any",
                "exit",
                f"interface {puerto_ios}",
                f" ip access-group {acl_name} in",
                "exit",
            ])
            self.conn.send_command("write memory")

            elapsed_ms = round((time.monotonic() - t0) * 1000, 1)
            evento = {
                "tipo": "BLOQUEO", "origen": alerta["origen"],
                "puerto": puerto_ios, "tasa": alerta.get("tasa", "?"),
                "elapsed_ms": elapsed_ms, "ts": ts_b,
            }
            self.eventos.append(evento)
            with open("soar_eventos.jsonl", "a") as f:
                f.write(json.dumps(evento) + "\n")

            log_ok(
                f"[{alerta['origen']}] Puerto {puerto_ios} bloqueado | "
                f"ACL {acl_name} | {elapsed_ms} ms"
            )
            return True
        except Exception as e:
            log_error(f"Bloqueo fallido: {e}")
            self.conn = None
            return False

    # ── Loop principal ────────────────────────────────────────
    def run(self):
        print(BANNER)
        print(f"  Target:         {SWITCH['host']}")
        print(f"  Umbral SNMP:    {UMBRAL_SNMP} MACs/seg")
        print(f"  Umbral ARP:     {UMBRAL_ARP} pkts/seg")
        print(f"  Poll interval:  {POLL_INTERVAL}s")
        print()

        if not self.conectar_ssh():
            log_error("SSH fallo al inicio. Verificar red.")
            sys.exit(1)

        self.iniciar_arp_sniffer()
        log_info("Monitoreo activo (SNMP + ARP). Ctrl+C para detener.\n")

        errores_snmp = 0

        while self._running:
            t_ciclo = time.monotonic()
            self.polls += 1

            # ── DETECCION 1: SNMP ────────────────────────────
            cam     = self.leer_cam()
            alertas = []

            if cam:
                errores_snmp = 0
                alertas = self.detectar_snmp(cam)
            else:
                errores_snmp += 1
                if errores_snmp == 3:
                    log_warn("SNMP sin respuesta — switch saturado")

            # ── DETECCION 2: ARP local ───────────────────────
            tasa_arp = self.leer_tasa_arp()

            if (tasa_arp >= UMBRAL_ARP
                    and PUERTO_ATACANTE_NUM not in self.bloqueados
                    and not self._arp_alertado):

                log_alert(
                    f"FLOOD detectado via ARP | "
                    f"{tasa_arp:.0f} pkts/seg | "
                    f"SNMP no responde — actuando por ARP"
                )
                alertas.append({
                    "origen":     "ARP",
                    "puerto":     PUERTO_ATACANTE_NUM,
                    "puerto_ios": PUERTO_ATACANTE_IOS,
                    "tasa":       tasa_arp,
                    "total_macs": "?",
                })
                self._arp_alertado = True

            # ── RESPUESTA ────────────────────────────────────
            for alerta in alertas:
                self.incidentes += 1
                if not any(a["origen"] == "ARP" for a in alertas):
                    log_alert(
                        f"INCIDENTE #{self.incidentes} [{alerta['origen']}] | "
                        f"Puerto {alerta['puerto_ios']} | "
                        f"{alerta['tasa']} MACs/seg"
                    )
                if self.bloquear(alerta):
                    self.bloqueados.add(alerta["puerto"])
                    self._arp_alertado = False

            # ── STATUS cada 20 polls ─────────────────────────
            if self.polls % 20 == 0:
                total = sum(len(m) for m in cam.values()) if cam else 0
                log_info(
                    f"polls={self.polls} | MACs={total} | "
                    f"incidentes={self.incidentes} | "
                    f"ARP={tasa_arp:.0f}/s | "
                    f"bloqueados={[PUERTOS.get(p) for p in self.bloqueados]}"
                )

            time.sleep(max(0, POLL_INTERVAL - (time.monotonic() - t_ciclo)))

    # ── Reporte final ─────────────────────────────────────────
    def _stop(self, *_):
        self._running = False
        print(f"\n{Fore.CYAN}{'='*52}")
        print("  REPORTE FINAL DEL EXPERIMENTO")
        print(f"{'='*52}{Style.RESET_ALL}")
        print(f"  Uptime:         {round(time.time()-self.t_start, 1)}s")
        print(f"  Polls SNMP:     {self.polls}")
        print(f"  Incidentes:     {self.incidentes}")
        print(f"  Bloqueados:     {[PUERTOS.get(p) for p in self.bloqueados]}")
        if self.eventos:
            t = [e["elapsed_ms"] for e in self.eventos]
            print(f"  T. prom resp:   {round(sum(t)/len(t),1)} ms")
            print(f"  T. min resp:    {min(t)} ms")
            print(f"  Reduccion:      {round((1-sum(t)/len(t)/900000)*100,2)}% vs manual")
            snmp_bl = sum(1 for e in self.eventos if e["origen"]=="SNMP")
            arp_bl  = sum(1 for e in self.eventos if e["origen"]=="ARP")
            print(f"  Bloqueos SNMP:  {snmp_bl}")
            print(f"  Bloqueos ARP:   {arp_bl}")
        print(f"{Fore.CYAN}{'='*52}{Style.RESET_ALL}")
        if self.conn:
            try: self.conn.disconnect()
            except: pass
        sys.exit(0)


if __name__ == "__main__":
    SOARAgent().run()