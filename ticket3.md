Ticket 3 — Diferenciar fallo SNMP de tabla CAM vacía

Prioridad: crítica

Objetivo

Evitar que una pausa o timeout en GNS3 genere un falso ataque cuando la consulta SNMP vuelva a funcionar.

Trabajo

leer_cam() no debe devolver {} tanto para errores como para respuestas vacías.

Debe devolver un resultado explícito:

@dataclass
class CamReadResult:
    success: bool
    entries: dict
    elapsed_ms: float
    error_type: str | None
    error_message: str | None
Reglas
Si SNMP falla, no actualizar el baseline.
Si SNMP falla, no ejecutar mitigación.
Si SNMP falla varias veces, mostrar estado TELEMETRIA_DEGRADADA.
La siguiente lectura exitosa debe compararse contra el último baseline válido, no contra un diccionario vacío.
Prueba obligatoria
Iniciar monitoreo normal.
Interrumpir temporalmente SNMP o apagar el enlace de gestión.
Restaurar el enlace.
Confirmar que no se detecte un MAC Flooding falso.