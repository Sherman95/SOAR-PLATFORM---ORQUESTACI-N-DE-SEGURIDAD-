"""
╔══════════════════════════════════════════════════════════════╗
║           SOAR AGENT — Configuración Central                 ║
║  Proyecto: Orquestación de Seguridad Autónoma en GNS3        ║
╚══════════════════════════════════════════════════════════════╝
Editar este archivo para adaptar el agente a tu laboratorio.
"""

# ─── Dispositivo objetivo (Switch IOU en GNS3) ────────────────
SWITCH = {
    "device_type": "cisco_ios",
    "host":        "192.168.1.10",   # IP de gestión del Switch IOU
    "username":    "admin",
    "password":    "cisco123",
    "secret":      "cisco123",       # enable secret
    "timeout":     10,
    "session_log": "logs/ssh_session.log",
}

# ─── SNMP ─────────────────────────────────────────────────────
SNMP = {
    "host":      "192.168.1.10",
    "community": "public",
    "port":      161,
    "timeout":   2,
    "retries":   1,
}

# ─── Umbrales de detección ────────────────────────────────────
THRESHOLDS = {
    # MAC Flooding: MACs nuevas por segundo en un puerto → alarma
    "mac_flood_rate":     5,   # MACs/seg

    # ARP Spoofing: ratio ARP-request / ARP-reply anómalos
    "arp_ratio_max":      5.0,  # requests por cada reply

    # Cantidad de IPs distintas que una MAC puede reclamar
    "ips_per_mac_max":    3,

    # Segundos de gracia antes de considerar el puerto limpio
    "clear_grace_period": 30,
}

# ─── Puertos del switch monitoreados ──────────────────────────
# Formato: {numero_snmp: "nombre_ios"}
# El número SNMP viene del OID dot1dTpFdbPort
PUERTOS = {
    1: "ethernet 0/0",   # uplink al router
    2: "ethernet 0/1",   # Victima-1
    3: "ethernet 0/2",   # Victima-2
    4: "ethernet 0/3",   # Atacante (Kali)
    5: "ethernet 0/4",   # Reservado / Agente
}

# Puertos que NUNCA deben bloquearse (uplinks críticos)
PUERTOS_PROTEGIDOS = {1}

# ─── Intervalos de polling ────────────────────────────────────
POLL_INTERVAL_SEC   = 0.5    # Frecuencia de consulta SNMP
ARP_WINDOW_SEC      = 5.0    # Ventana de análisis ARP

# ─── Rutas de archivos ────────────────────────────────────────
LOG_FILE     = "logs/soar_events.jsonl"   # Un JSON por línea
METRICS_FILE = "logs/metrics.jsonl"
REPORT_DIR   = "reports/"
