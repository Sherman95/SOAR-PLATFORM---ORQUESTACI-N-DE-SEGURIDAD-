Ticket 6 — Medir el tiempo experimental completo

Prioridad: crítica para el artículo

Objetivo

Medir desde el inicio del ciclo de monitoreo hasta que el puerto queda realmente confirmado como apagado.

Hitos
t0 = inicio del poll SNMP
t1 = tabla CAM recibida
t2 = anomalía identificada
t3 = inicio de la acción SSH
t4 = fin del comando shutdown
t5 = confirmación administratively down
Métricas
snmp_read_ms             = t1 - t0
analysis_ms              = t2 - t1
ssh_command_ms           = t4 - t3
verification_ms          = t5 - t4
detection_cycle_ms       = t2 - t0
containment_ms           = t5 - t2
end_to_end_ms            = t5 - t0
actual_poll_interval_ms
Criterios de aceptación
Se usa time.monotonic_ns().
No se inventan porcentajes para dividir las fases.
El tiempo de respuesta principal es end_to_end_ms.
Se registra el intervalo real entre lecturas.
Se elimina el 99,9 % frente a “15 minutos humanos”.
write memory no forma parte del tiempo de contención.