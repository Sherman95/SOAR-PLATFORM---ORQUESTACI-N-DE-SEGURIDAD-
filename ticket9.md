Ticket 9 — Validar el umbral dentro de GNS3

Prioridad: alta

Objetivo

Justificar experimentalmente el umbral que activa la detección.

No necesitan crear un algoritmo industrial de calibración. Basta con una evaluación controlada y documentada.

Valores sugeridos
10 MAC/s
25 MAC/s
50 MAC/s
100 MAC/s
Procedimiento

Para cada umbral:

Cinco pruebas normales.
Cinco pruebas de MAC Flooding.
Registrar falsos positivos.
Registrar ataques detectados.
Registrar tiempo de detección.
Registrar tiempo total.
Cálculo correcto
mac_rate = new_mac_count / elapsed_seconds

No debe confundirse:

MAC por ciclo

con:

MAC por segundo
Resultado esperado

Una tabla como:

Umbral	Ataques detectados	Falsos positivos	Tiempo medio
10 MAC/s	5/5	2/5	650 ms
25 MAC/s	5/5	0/5	810 ms
50 MAC/s	5/5	0/5	1.020 ms
100 MAC/s	4/5	0/5	1.430 ms

Los números deben provenir de las pruebas reales.