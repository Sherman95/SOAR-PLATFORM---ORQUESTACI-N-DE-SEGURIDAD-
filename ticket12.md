Ticket 12 — Pruebas unitarias básicas

Prioridad: media

No hace falta una suite industrial, pero sí pruebas sobre los riesgos principales:

Timeout SNMP no borra el baseline.
Recuperación de SNMP no genera ataque falso.
Mapeo de bridge port a interfaz.
Interfaz desconocida no se bloquea.
Puerto protegido no se bloquea.
Fallo SSH no se registra como éxito.
Cálculo correcto de MAC/s.
Cálculo correcto de media y desviación estándar.

Usar pytest y mocks. Estas pruebas no necesitan levantar GNS3.

Configuración experimental concreta

La topología debería quedar fija y documentada:

Nodo	Dirección	Interfaz del switch
R-IOU	192.168.1.1	Ethernet0/0
Victima-1	192.168.1.20	Ethernet0/1
Victima-2	192.168.1.30	Ethernet0/2 o Ethernet1/0
Kali	192.168.1.99	Ethernet0/2 o Ethernet0/3
SW-IOU	192.168.1.10	VLAN 1
Agente Python	Red host-only	Enlace de gestión

Para demostrar identificación dinámica, se debe reservar al menos dos interfaces donde Kali pueda conectarse alternativamente.

También conviene definir interfaces protegidas:

PROTECTED_INTERFACES = {
    "Ethernet0/0",  # router
    "Ethernet1/0"   # gestión
}

El agente nunca debe apagar esas interfaces, incluso si presentan muchas MAC.