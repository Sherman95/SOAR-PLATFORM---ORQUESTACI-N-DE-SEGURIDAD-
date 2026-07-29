Ticket 2 — Identificar dinámicamente el puerto de Kali

Prioridad: crítica

Objetivo

Demostrar que el agente detecta dónde se origina el MAC Flooding y no bloquea un puerto configurado previamente.

Aunque el entorno sea fijo, el artículo necesita demostrar que el puerto se identifica durante la ejecución.

Flujo requerido
MAC aprendida
→ dot1dTpFdbPort
→ dot1dBasePort
→ dot1dBasePortIfIndex
→ ifIndex
→ ifName
→ Ethernet0/2 o Ethernet0/3

En Cisco IOU se debe validar exactamente qué OID y qué nombre de interfaz devuelve el dispositivo.

Criterios de aceptación

Primera prueba:

Kali → Ethernet0/3
Resultado → agente bloquea Ethernet0/3

Segunda prueba:

Kali → Ethernet0/2
Resultado → agente bloquea Ethernet0/2

Sin cambiar código, constantes ni configuración entre ambas ejecuciones.

El evento debe registrar:

{
  "detected_interface": "Ethernet0/2",
  "bridge_port": 3,
  "if_index": 3,
  "new_mac_count": 241,
  "threshold_mac_per_second": 50
}

Si no puede resolver la interfaz, debe generar una alerta y no bloquear ningún puerto.