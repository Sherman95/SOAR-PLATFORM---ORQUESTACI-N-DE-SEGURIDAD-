Ticket 8 — Modo observación para validar falsos positivos

Prioridad: alta

Objetivo

Comprobar que el agente no apaga puertos durante tráfico normal de la topología.

Comando
python run.py monitor --observe-only

En este modo:

Detecta anomalías.
Registra alertas.
No ejecuta shutdown.
Escenarios legítimos
Red inactiva.
Ping entre Victima-1 y Victima-2.
Ping hacia el gateway.
Reinicio de una VPCS.
Limpieza manual de la tabla CAM y reaprendizaje.
Reconexión de una víctima.
Escenario de ataque
sudo macof -i eth0 -n 500
Criterios de aceptación
Cada ejecución se etiqueta como normal o attack.
Se registran verdaderos positivos, falsos positivos, verdaderos negativos y falsos negativos.
El modo observación nunca envía configuración al switch.