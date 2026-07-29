"""Configuracion central del experimento validado de MAC Flooding."""

import os

from dotenv import load_dotenv


load_dotenv()

SWITCH = {
    "device_type": "cisco_ios",
    "host": os.getenv("SWITCH_HOST", "192.168.1.10"),
    "username": os.getenv("SWITCH_USERNAME", "admin"),
    "password": os.getenv("SWITCH_PASS", ""),
    "secret": os.getenv("SWITCH_SECRET") or os.getenv("SWITCH_PASS", ""),
    "timeout": 5,
    "global_delay_factor": 2,
}

SNMP = {
    "host": os.getenv("SNMP_HOST", "192.168.1.10"),
    "community": os.getenv("SNMP_COMMUNITY", "public"),
    "port": 161,
    "timeout": 2,
    "retries": 1,
}

# Bloqueo explicito del prototipo no validado. El agente principal no consulta
# esta bandera ni importa src/experimental/arp.py.
ENABLE_ARP_DETECTION = False

MAC_THRESHOLD_PER_SECOND = 50
POLL_INTERVAL = 0.5
SNMP_DEGRADED_AFTER = 3

PUERTOS = {
    1: "ethernet 0/0",  # uplink al router
    2: "ethernet 0/1",  # Victima-1
    3: "ethernet 0/2",  # Victima-2
    4: "ethernet 0/3",  # Host del escenario de ataque
    5: "ethernet 1/0",  # Cloud / Agente
}
PROTECTED_INTERFACES = {"Ethernet0/0", "Ethernet1/0"}
# Alias conservado para no romper integraciones anteriores en español.
INTERFACES_PROTEGIDAS = PROTECTED_INTERFACES

RESTORE_SETTLE_SECONDS = 3
KALI_IP = os.getenv("KALI_IP")
KALI_CONNECTED_INTERFACE = os.getenv("KALI_CONNECTED_INTERFACE")
MACOF_COMMAND = os.getenv("MACOF_COMMAND", "macof")

_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
EXPERIMENT_ROOT = os.path.join(
    _ROOT, "data", "experiments", "mac_flooding_validation"
)
METRICS_FILE = os.path.join(_ROOT, "data", "soar_metrics.jsonl")
EVENTS_FILE = os.path.join(_ROOT, "data", "soar_events.jsonl")
HISTORY_FILE = os.path.join(_ROOT, "data", "history_reports.txt")
