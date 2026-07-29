Ticket 7 — Guardar cada ejecución por separado

Prioridad: crítica para el artículo

Objetivo

Permitir diez o más repeticiones sin borrar resultados anteriores.

Estructura sencilla
data/
└── experiments/
    └── mac_flooding_validation/
        ├── run_001/
        │   ├── metadata.json
        │   ├── cam_snapshots.jsonl
        │   ├── events.jsonl
        │   ├── metrics.json
        │   ├── switch_before.txt
        │   └── switch_after.txt
        ├── run_002/
        └── summary.csv
Metadatos mínimos
Identificador de ejecución.
Fecha y hora.
Commit Git.
Puerto donde se conectó Kali.
Puerto identificado por el agente.
Umbral.
Intervalo configurado.
Intervalo real.
Comando macof.
MAC iniciales.
Pico de MAC.
Tiempo de detección.
Tiempo total.
Resultado de mitigación.
Criterios de aceptación
Al iniciar el agente no se eliminan ejecuciones anteriores.
Cada registro incluye run_id.
Se puede exportar todo a CSV.
Las capturas pueden asociarse inequívocamente con una ejecución.