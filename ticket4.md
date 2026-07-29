Ticket 4 — Simplificar la mitigación a shutdown_only

Prioridad: crítica

Objetivo

Aplicar una acción clara, compatible con el switch IOU y fácil de verificar.

Para el experimento no recomiendo combinar shutdown y ACL. Si el puerto queda apagado, la ACL no añade una contención medible y puede introducir errores en puertos de capa 2.

Flujo
Guardar el estado inicial de la interfaz.
Ejecutar shutdown.
Consultar nuevamente la interfaz.
Registrar éxito únicamente si aparece administratively down.
Resultado esperado
{
  "interface": "Ethernet0/3",
  "action": "shutdown",
  "command_sent": true,
  "verification_status": "administratively_down",
  "mitigation_success": true
}
Criterios de aceptación
Una excepción SSH no se registra como mitigación exitosa.
Una respuesta IOS con % Invalid input no se registra como éxito.
El puerto se añade a blocked_interfaces únicamente después de comprobar su estado.
La ACL queda fuera del experimento principal.

Esto también implica que el título del artículo ya no debería destacar la “generación dinámica de ACL”.