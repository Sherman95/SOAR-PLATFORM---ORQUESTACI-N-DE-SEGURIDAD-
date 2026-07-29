Ticket 5 — Restauración manual y controlada entre ejecuciones

Prioridad: alta

Objetivo

Restablecer el escenario para la siguiente prueba sin depender de hilos automáticos ni analizar toda la red.

En GNS3 no necesitan un recuperador autónomo sofisticado. Necesitan que cada ejecución empiece desde el mismo estado.

Comando sugerido
python run.py restore --interface Ethernet0/3

O:

python run.py restore --run-id run_003
Restauración mínima
Ejecutar no shutdown.
Limpiar la tabla CAM dinámica.
Confirmar que la interfaz volvió a up/up.
Verificar conectividad de Kali.
No imponer VLAN 1 si ya estaba correctamente configurada.
No activar hilos automáticos de restauración durante las mediciones.
Criterios de aceptación
Cada prueba comienza con 3–5 MAC legítimas.
El puerto vuelve al estado esperado.
La restauración queda registrada.
Ejecutarla dos veces no produce errores críticos.