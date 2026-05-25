#!/usr/bin/env python3
"""
SOAR Agent v3.1 — Deteccion Absoluta de Rafagas (Burst) + UI Avanzada
Especializado para mitigacion fulminante de MAC Flooding.
Incluye Calibracion Inicial y Restauracion Automatica.
"""

import time, signal, sys, json, os, threading
from datetime import datetime
from collections import defaultdict
from netmiko import ConnectHandler
from pysnmp.hlapi import (nextCmd, SnmpEngine, CommunityData,
                          UdpTransportTarget, ContextData,
                          ObjectType, ObjectIdentity)
from colorama import Fore, Back, Style, init

init(autoreset=True)

# ─── CONFIGURACION ESTRATEGICA ────────────────────────────────
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

# NUEVA LOGICA: Si entran X MACs o X ARPs de golpe en 0.5s -> BLOQUEO INMEDIATO
BURST_SNMP    = 25   # MACs nuevas en un solo poll
BURST_ARP     = 40   # Paquetes ARP en un solo poll
POLL_INTERVAL = 0.5

PUERTOS = {
    1: "ethernet 0/0",   # uplink — PROTEGIDO
    2: "ethernet 0/1",   # victima-1
    3: "ethernet 0/2",   # victima-2
    4: "ethernet 0/3",   # atacante
    5: "ethernet 1/0",   # cloud/agente — PROTEGIDO
}
PROTEGIDOS = {1, 5}
PUERTO_ATACANTE_IOS = "ethernet 0/3"
PUERTO_ATACANTE_NUM = 4

# ─── UI / VISUALES ───────────────────────────────────────────
def clear_screen():
    os.system('cls' if os.name == 'nt' else 'clear')

def ts():
    return datetime.now().strftime("%H:%M:%S.%f")[:12]

def log_status(polls, macs, arp, bloqueados):
    blq_str = ", ".join([PUERTOS.get(p, str(p)) for p in bloqueados]) if bloqueados else "Ninguno"
    print(f"{Fore.CYAN} ⚡ [STATUS] {Fore.WHITE}Polls: {polls:03d} | Tabla CAM: {macs:03d} MACs | ARP Burst: {arp:03d} pkts | Bloqueados: [{Fore.RED}{blq_str}{Fore.WHITE}]")

def log_warn(msg):
    print(f"{Fore.YELLOW} ⚠  [WARN]   {msg}")

def log_alert(msg):
    print(f"\n{Back.RED}{Fore.WHITE}{Style.BRIGHT} >>> ALERTA CRITICA DE SEGURIDAD <<< {Style.RESET_ALL}")
    print(f"{Fore.RED}{Style.BRIGHT} 💥 {msg}\n")

def log_action(msg):
    print(f"{Back.GREEN}{Fore.BLACK}{Style.BRIGHT} ✓ ACCION {Style.RESET_ALL} {Fore.GREEN}{msg}\n")

BANNER = f"""{Fore.MAGENTA}{Style.BRIGHT}
 ╔══════════════════════════════════════════════════════════════╗
 ║  ██████╗  ██████╗  █████╗ ██████╗       SOAR AGENT v3.1      ║
 ║ ██╔════╝ ██╔═══██╗██╔══██╗██╔══██╗      Defensa Activa       ║
 ║ ███████╗ ██║   ██║███████║██████╔╝      ================     ║
 ║ ╚════██║ ██║   ██║██╔══██║██╔══██╗      Zero-Trust           ║
 ║ ██████╔╝ ╚██████╔╝██║  ██║██║  ██║      Burst Detection      ║
 ║ ╚═════╝   ╚═════╝ ╚═╝  ╚═╝╚═╝  ╚═╝                           ║
 ╚══════════════════════════════════════════════════════════════╝
{Style.RESET_ALL}"""

class SOARAgent:
    def __init__(self):
        self.conn         = None
        self.prev_macs    = {}
        self.bloqueados   = set()
        self.incidentes   = 0
        self.polls        = 0
        self.t_start      = time.time()
        self.eventos      = []
        self._running     = True
        self._arp_count   = 0
        self._arp_lock    = threading.Lock()

        signal.signal(signal.SIGINT, self._stop)

    def conectar_ssh(self) -> bool:
        try:
            print(f"{Fore.CYAN} [*] Autenticando en {SWITCH['host']} vía SSH...{Style.RESET_ALL}")
            self.conn = ConnectHandler(**SWITCH)
            self.conn.enable()
            out = self.conn.send_command("show version | include IOS")
            print(f"{Fore.GREEN} [+] SSH Establecido: {out.strip()[:55]}{Style.RESET_ALL}")
            return True
        except Exception as e:
            print(f"{Fore.RED} [-] Fallo conexión SSH: {e}{Style.RESET_ALL}")
            return False

    def leer_cam(self) -> dict:
        cam = defaultdict(set)
        try:
            for (err, _, _, vbs) in nextCmd(
                SnmpEngine(), CommunityData(SNMP_COMM, mpModel=1),
                UdpTransportTarget((SNMP_HOST, 161), timeout=1.0, retries=0),
                ContextData(), ObjectType(ObjectIdentity("BRIDGE-MIB", "dot1dTpFdbPort")),
                lexicographicMode=False, maxRows=8000,
            ):
                if err: break
                for vb in vbs:
                    try:
                        oid   = str(vb[0])
                        port  = int(str(vb[1]))
                        mac   = ":".join(f"{int(x):02x}" for x in oid.split(".")[-6:])
                        cam[port].add(mac)
                    except: pass
        except: pass
        return cam

    def iniciar_arp_sniffer(self):
        try:
            from scapy.all import sniff, ARP
            def _callback(pkt):
                if pkt.haslayer(ARP):
                    with self._arp_lock:
                        self._arp_count += 1
            def _loop():
                sniff(filter="arp", prn=_callback, store=False, stop_filter=lambda _: not self._running)
            t = threading.Thread(target=_loop, daemon=True)
            t.start()
            print(f"{Fore.GREEN} [+] Sniffer ARP secundario ONLINE.{Style.RESET_ALL}")
        except:
            print(f"{Fore.YELLOW} [-] Scapy/Npcap no detectado. Operando en modo SNMP estricto.{Style.RESET_ALL}")

    def leer_y_resetear_arp(self) -> int:
        with self._arp_lock:
            count = self._arp_count
            self._arp_count = 0
        return count

    def bloquear(self, origen, puerto_num, puerto_ios) -> bool:
        acl_name = f"SOAR-BLOCK-P{puerto_num}"
        ts_b     = datetime.now().isoformat()[:19]
        t0       = time.monotonic()

        try:
            self.conn.send_config_set([
                f"interface {puerto_ios}",
                "shutdown",
                f"description *** LOCKDOWN BY SOAR [{origen}] ***",
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
            log_action(f"Mitigación Exitosa | Puerto: {puerto_ios} | Regla: {acl_name} | Tiempo: {elapsed_ms}ms")
            self.eventos.append({"origen": origen, "puerto": puerto_ios, "ms": elapsed_ms})
            return True
        except Exception as e:
            print(f"{Fore.RED} [-] Error al inyectar ACL: {e}{Style.RESET_ALL}")
            return False

    def restaurar_red(self):
        if not self.bloqueados:
            return
            
        print(f"\n{Back.YELLOW}{Fore.BLACK} [!] RESTAURANDO PUERTOS BLOQUEADOS... {Style.RESET_ALL}")
        comandos = []
        for puerto_num in self.bloqueados:
            p_ios = PUERTOS.get(puerto_num, f"e0/{puerto_num-1}")
            acl_name = f"SOAR-BLOCK-P{puerto_num}"
            comandos.extend([
                f"interface {p_ios}",
                "no shutdown",
                "no description",
                f"no ip access-group {acl_name} in",
                "exit",
                f"no ip access-list extended {acl_name}"
            ])
        comandos.append("clear mac address-table dynamic")
        
        try:
            # Si la conexión se cerró, intenta reconectar
            if not self.conn or not self.conn.is_alive():
                self.conectar_ssh()
            self.conn.send_config_set(comandos)
            self.conn.send_command("write memory")
            print(f"{Fore.GREEN} [+] Red restaurada a la normalidad.{Style.RESET_ALL}")
        except Exception as e:
            print(f"{Fore.RED} [-] Fallo al restaurar: {e}{Style.RESET_ALL}")

    def run(self):
        clear_screen()
        print(BANNER)
        print(f"{Fore.WHITE}{Style.BRIGHT} ⚙  CONFIGURACIÓN DEL MOTOR")
        print(f" ├── Target IPv4  : {SWITCH['host']}")
        print(f" ├── Umbral SNMP  : {BURST_SNMP} MACs nuevas/poll")
        print(f" ├── Umbral ARP   : {BURST_ARP} Paquetes/poll")
        print(f" └── Polling Core : {POLL_INTERVAL} segundos\n")

        if not self.conectar_ssh(): sys.exit(1)
        self.iniciar_arp_sniffer()
        
        # ---> CALIBRACIÓN INICIAL (Baseline) <---
        print(f"{Fore.CYAN} [*] Calibrando estado inicial de la red (Baseline)...{Style.RESET_ALL}")
        self.prev_macs = self.leer_cam()
        time.sleep(1)
        
        print(f"\n{Back.BLUE}{Fore.WHITE}{Style.BRIGHT} [ INICIANDO VIGILANCIA EN TIEMPO REAL ] {Style.RESET_ALL}\n")

        while self._running:
            t_ciclo = time.monotonic()
            self.polls += 1
            cam = self.leer_cam()
            arp_burst = self.leer_y_resetear_arp()

            # DETECCION SNMP BURST
            for puerto, macs in cam.items():
                if puerto in PROTEGIDOS or puerto in self.bloqueados: continue
                nuevas = len(macs - self.prev_macs.get(puerto, set()))
                
                if nuevas >= BURST_SNMP:
                    p_ios = PUERTOS.get(puerto, f"e0/{puerto-1}")
                    log_alert(f"MAC FLOOD DETECTADO (SNMP) | {nuevas} MACs inyectadas de golpe en {p_ios}")
                    if self.bloquear("SNMP", puerto, p_ios):
                        self.bloqueados.add(puerto)
                        self.incidentes += 1

            # DETECCION ARP BURST (Respaldo)
            if arp_burst >= BURST_ARP and PUERTO_ATACANTE_NUM not in self.bloqueados:
                log_alert(f"TORMENTA ARP DETECTADA | {arp_burst} paquetes en {POLL_INTERVAL}s")
                if self.bloquear("ARP", PUERTO_ATACANTE_NUM, PUERTO_ATACANTE_IOS):
                    self.bloqueados.add(PUERTO_ATACANTE_NUM)
                    self.incidentes += 1

            self.prev_macs = {p: m.copy() for p, m in cam.items()}
            
            # ---> LOGS CADA SEGUNDO <---
            if self.polls % 2 == 0:
                total_macs = sum(len(m) for m in cam.values()) if cam else 0
                log_status(self.polls, total_macs, arp_burst, self.bloqueados)

            time.sleep(max(0, POLL_INTERVAL - (time.monotonic() - t_ciclo)))

    def _stop(self, *_):
        self._running = False
        print(f"\n\n{Fore.CYAN}==================================================")
        print(f"{Style.BRIGHT}  REPORTE FINAL DEL EXPERIMENTO")
        print(f"=================================================={Style.RESET_ALL}")
        
        uptime = round(time.time() - self.t_start, 1)
        print(f"  Uptime:          {uptime} s")
        print(f"  Polls SNMP:      {self.polls}")
        print(f"  Incidentes:      {self.incidentes}")
        
        blq_str = [PUERTOS.get(p, f"e0/{p-1}") for p in self.bloqueados]
        print(f"  Bloqueados:      {blq_str}")
        
        if self.eventos:
            tiempos = [e["ms"] for e in self.eventos]
            t_prom = sum(tiempos) / len(tiempos)
            t_min = min(tiempos)
            
            # Cálculo de reducción asumiendo 15 mins (900,000 ms) de respuesta manual
            reduccion = round((1 - (t_prom / 900000)) * 100, 2)
            
            snmp_bl = sum(1 for e in self.eventos if e["origen"] == "SNMP")
            arp_bl  = sum(1 for e in self.eventos if e["origen"] == "ARP")
            
            print(f"  T. prom resp:    {round(t_prom, 1)} ms")
            print(f"  T. min resp:     {round(t_min, 1)} ms")
            print(f"  Reduccion:       {reduccion}% vs respuesta manual")
            print(f"  Bloqueos SNMP:   {snmp_bl}")
            print(f"  Bloqueos ARP:    {arp_bl}")
            
        print(f"{Fore.CYAN}=================================================={Style.RESET_ALL}")
        
        # Limpieza automática del switch
        self.restaurar_red()
        
        if self.conn:
            try: self.conn.disconnect()
            except: pass
        sys.exit(0)

if __name__ == "__main__":
    SOARAgent().run()