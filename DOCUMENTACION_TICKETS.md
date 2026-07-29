# Documento de implementación de los tickets 1–12

## 1. Propósito

Este documento consolida el trabajo realizado para convertir el proyecto en un agente experimental enfocado exclusivamente en la detección y mitigación de **MAC Flooding** sobre Cisco IOS/IOU en GNS3.

Describe:

- El objetivo de cada ticket.
- Las decisiones de diseño adoptadas.
- Los componentes modificados.
- Los criterios de aceptación cubiertos.
- Los comandos de operación y validación.
- Las actividades que todavía requieren pruebas físicas en GNS3.

No se presentan como resultados científicos cifras generadas por pruebas unitarias. Los tiempos, tasas y porcentajes finales del artículo deben proceder únicamente de las corridas reales guardadas en `data/experiments/mac_flooding_validation/`.

## 2. Estado general

| Ticket | Tema | Implementación de software | Validación pendiente en GNS3 |
|---|---|---:|---:|
| 1 | Limitar el alcance a MAC Flooding | Completada | No |
| 2 | Identificación dinámica del puerto | Completada | Dos pruebas físicas E0/3 y E0/2 |
| 3 | Diferenciar fallo SNMP y CAM vacía | Completada | Interrupción real del enlace de gestión |
| 4 | Mitigación `shutdown_only` | Completada | Confirmación sobre IOS/IOU real |
| 5 | Restauración manual | Completada | Verificación entre corridas reales |
| 6 | Temporización completa `t0–t5` | Completada | Obtener tiempos reales |
| 7 | Evidencia separada por corrida | Completada | Poblar con repeticiones reales |
| 8 | Modo de observación | Completada | Ejecutar escenarios legítimos y ataque |
| 9 | Evaluación del umbral | Completada como infraestructura | Campaña de 40 corridas |
| 10 | Resumen estadístico | Completada como infraestructura | Campaña principal de 20 corridas |
| 11 | Dependencias y laboratorio | Completada | Reinstalación opcional en otro equipo |
| 12 | Pruebas unitarias y topología | Completada | No; las pruebas no requieren GNS3 |

## 3. Alcance experimental resultante

El flujo principal valida únicamente MAC Flooding:

```text
Poll SNMP de CAM
        ↓
Comparación contra la última lectura válida
        ↓
Cálculo de MAC nuevas / segundos transcurridos
        ↓
Resolución dinámica bridge port → ifIndex → ifName
        ↓
Alerta pasiva o shutdown_only
        ↓
Verificación administratively down
        ↓
Persistencia de evidencia y estadísticas
```

ARP Spoofing está fuera del alcance validado. Su prototipo permanece aislado en `src/experimental/arp.py` y no es importado por el agente principal.

## 4. Ticket 1 — Limitar el agente experimental a MAC Flooding

### Objetivo

Eliminar del flujo evaluado cualquier comportamiento ARP que el artículo no puede demostrar experimentalmente.

### Implementación

- Se declaró `ENABLE_ARP_DETECTION = False` en `config/settings.py`.
- Se retiró Scapy de las dependencias del agente principal.
- El detector y los restauradores ARP no se inicializan.
- Se eliminaron del flujo principal la cuarentena en VLAN 999 y las restauraciones ARP.
- Se retiró el puerto 4 como valor alternativo o fallback. Un bridge port con valor numérico 4 todavía puede aparecer como resultado dinámico de SNMP, pero nunca se utiliza como destino preconfigurado.
- Los reportes y dashboards nuevos solo analizan eventos MAC Flooding.
- El prototipo ARP se conserva en `src/experimental/arp.py` como código no validado.

### Resultado

El agente principal puede importarse y ejecutarse sin Scapy. Un paquete ARP no puede provocar bloqueo, cambio de VLAN ni una entrada de “ARP Spoofing mitigado” en reportes nuevos.

## 5. Ticket 2 — Identificación dinámica del puerto de Kali

### Objetivo

Demostrar que el agente identifica durante cada ejecución el puerto que origina el MAC Flooding.

### Implementación

El detector resuelve la interfaz mediante BRIDGE-MIB e IF-MIB:

```text
MAC aprendida
  → dot1dTpFdbPort
  → dot1dBasePortIfIndex
  → ifIndex
  → ifName
  → Ethernet0/2 o Ethernet0/3
```

Los OID utilizados se encuentran en `src/detector.py`. El resultado se representa mediante `InterfaceIdentity`, que conserva:

- `bridge_port`
- `if_index`
- `if_name`

Cada evento de mitigación registra además:

- `detected_interface`
- `new_mac_count`
- `threshold_mac_per_second`

Si la resolución falla, el agente registra `INTERFAZ_NO_RESUELTA` y no llama al mitigador.

### Validación pendiente

Ejecutar sin cambios de código:

1. Kali conectado a `Ethernet0/3`.
2. Kali conectado a `Ethernet0/2`.

En cada caso, `detected_interface` debe coincidir con la conexión física real.

## 6. Ticket 3 — Diferenciar fallo SNMP de CAM vacía

### Objetivo

Impedir que un timeout SNMP se interprete como una tabla CAM vacía y provoque un falso incremento cuando vuelva la telemetría.

### Implementación

`Detector.leer_cam()` devuelve un `CamReadResult` explícito:

```python
@dataclass
class CamReadResult:
    success: bool
    entries: dict
    elapsed_ms: float
    error_type: str | None
    error_message: str | None
```

`CamMonitorState` aplica estas reglas:

- Una lectura vacía exitosa tiene `success=True` y `entries={}`.
- Un timeout tiene `success=False` y conserva su causa.
- Un fallo no modifica la última CAM válida.
- Un fallo no habilita mitigaciones.
- Después de tres fallos consecutivos se declara `TELEMETRIA_DEGRADADA`.
- La recuperación se compara contra la última lectura válida, no contra `{}`.

### Resultado

Las pruebas unitarias demuestran que un timeout no borra el baseline y que una recuperación con la misma CAM produce una tasa de cero MAC/s.

## 7. Ticket 4 — Mitigación `shutdown_only`

### Objetivo

Aplicar una respuesta única, compatible con IOS y verificable experimentalmente.

### Flujo implementado

```text
Consultar estado inicial
        ↓
Enviar interface <ifName> + shutdown
        ↓
Consultar nuevamente la interfaz
        ↓
Éxito solo si aparece administratively down
```

### Reglas

- No se generan ACL dinámicas.
- Una excepción SSH se registra como fallo.
- `% Invalid input` se registra como comando rechazado.
- Una verificación `up/up` no se considera contención.
- La interfaz se añade a `blocked_interfaces` únicamente después de confirmar `administratively_down`.
- `write memory` no forma parte de la mitigación ni de su tiempo medido.

### Evento esperado

```json
{
  "interface": "Ethernet0/3",
  "action": "shutdown",
  "command_sent": true,
  "verification_status": "administratively_down",
  "mitigation_success": true
}
```

## 8. Ticket 5 — Restauración manual entre ejecuciones

### Objetivo

Restablecer el escenario de forma controlada sin hilos automáticos que alteren la medición.

### Comando

```bash
python run.py restore --interface Ethernet0/3 --verify-ip 192.168.1.99
```

`KALI_IP` también puede declararse en `.env`.

### Flujo implementado

1. Consultar el estado inicial.
2. Ejecutar `no shutdown`.
3. Limpiar la CAM mediante `clear mac address-table dynamic`.
4. Verificar estado `up/up`.
5. Verificar conectividad hacia Kali.
6. Leer un baseline y comprobar si contiene entre 3 y 5 MAC legítimas.
7. Registrar el resultado de restauración.

No se impone VLAN 1 y no existen restauradores automáticos durante la corrida. El comando es idempotente: ejecutarlo dos veces no produce un error crítico.

## 9. Ticket 6 — Temporización experimental completa

### Objetivo

Medir desde el inicio del poll SNMP hasta la confirmación real del puerto apagado.

### Hitos

| Hito | Definición |
|---|---|
| `t0` | Inicio del poll SNMP |
| `t1` | Tabla CAM recibida |
| `t2` | Anomalía identificada |
| `t3` | Inicio de la acción SSH |
| `t4` | Fin del comando `shutdown` |
| `t5` | Confirmación `administratively down` |

Todos los hitos se capturan con `time.monotonic_ns()`.

### Métricas

| Métrica | Cálculo |
|---|---|
| `snmp_read_ms` | `t1 - t0` |
| `analysis_ms` | `t2 - t1` |
| `ssh_command_ms` | `t4 - t3` |
| `verification_ms` | `t5 - t4` |
| `detection_cycle_ms` | `t2 - t0` |
| `containment_ms` | `t5 - t2` |
| `end_to_end_ms` | `t5 - t0` |
| `actual_poll_interval_ms` | Diferencia real entre inicios de polls |

La métrica principal es `end_to_end_ms`. Se eliminaron porcentajes inventados, divisiones artificiales de fases y comparaciones con “15 minutos humanos”.

## 10. Ticket 7 — Persistencia separada por ejecución

### Objetivo

Permitir diez o más repeticiones sin sobrescribir evidencia anterior.

### Estructura

```text
data/experiments/mac_flooding_validation/
├── run_001/
│   ├── metadata.json
│   ├── cam_snapshots.jsonl
│   ├── events.jsonl
│   ├── metrics.json
│   ├── switch_before.txt
│   ├── switch_after.txt
│   └── report.txt
├── run_002/
├── summary.csv
├── threshold_evaluation.csv
├── results.csv
├── summary.json
└── statistical_report.txt
```

`ExperimentRun` asigna el siguiente `run_NNN` libre mediante creación exclusiva de directorio. No elimina ni reutiliza una corrida existente.

### Metadatos principales

- `run_id` y `campaign_id`
- fecha de inicio y fin
- commit Git
- etiqueta `normal` o `attack`
- modo `observe_only` o activo
- puerto esperado de Kali y puerto detectado
- umbral e intervalo configurado/real
- comando `macof`
- MAC iniciales y pico de MAC
- tiempos de detección y end-to-end
- resultado de mitigación
- clasificación TP, FP, TN o FN

Cada captura y evento incluye `run_id`. Los archivos `switch_before.txt` y `switch_after.txt` quedan inequívocamente asociados por su directorio.

### Exportación

```bash
python run.py export
```

Este comando reconstruye `summary.csv` y `threshold_evaluation.csv` a partir de las corridas conservadas.

## 11. Ticket 8 — Modo de observación

### Objetivo

Validar falsos positivos sin permitir que el agente apague interfaces durante tráfico normal.

### Comandos

```bash
# Escenario normal por defecto
python run.py monitor --observe-only

# Ataque observado sin mitigación
python run.py monitor --observe-only --scenario attack
```

### Garantías

- Detecta anomalías y registra `MAC_FLOOD_OBSERVED`.
- Guarda tiempos de lectura y detección.
- Registra `configuration_sent: false`.
- No invoca `NetworkManager.config()`.
- No ejecuta `shutdown`.

### Clasificación

| Escenario real | Anomalía detectada | Clasificación |
|---|---:|---|
| `attack` | Sí | `true_positive` |
| `attack` | No | `false_negative` |
| `normal` | Sí | `false_positive` |
| `normal` | No | `true_negative` |

### Escenarios normales previstos

- Red inactiva.
- Ping entre Victima-1 y Victima-2.
- Ping hacia el gateway.
- Reinicio de una VPCS.
- Limpieza manual y reaprendizaje de la CAM.
- Reconexión de una víctima.

Cada escenario debe ocupar una corrida independiente.

## 12. Ticket 9 — Validación del umbral

### Objetivo

Justificar experimentalmente el umbral expresado en MAC nuevas por segundo.

### Cálculo

```python
mac_rate = new_mac_count / elapsed_seconds
```

El agente usa `calcular_tasa_mac()` y no confunde MAC por ciclo con MAC/s.

### Procedimiento

Evaluar `10`, `25`, `50` y `100` MAC/s. Para cada valor se requieren cinco pruebas normales y cinco ataques:

```bash
python run.py monitor --observe-only --scenario normal --threshold 25
python run.py monitor --observe-only --scenario attack --threshold 25
```

Repetir ambos comandos cinco veces antes de pasar al siguiente umbral.

### Salida

`threshold_evaluation.csv` agrupa:

- pruebas normales y ataques
- verdaderos y falsos positivos
- verdaderos y falsos negativos
- ataques detectados
- media del ciclo de detección
- media end-to-end, cuando exista mitigación
- duración media de corrida

### Estado

La infraestructura está implementada. Faltan las 40 corridas reales en GNS3. Los valores ilustrativos del ticket no fueron copiados como resultados.

## 13. Ticket 10 — Resumen estadístico de campaña

### Objetivo

Convertir las corridas reales en información directamente utilizable en el artículo.

### Campaña definida

- 10 ataques MAC Flooding.
- 10 escenarios legítimos.
- 5 ataques con Kali en `Ethernet0/3`.
- 5 ataques con Kali en `Ethernet0/2`.

Debe utilizarse un identificador exclusivo:

```bash
# Corridas legítimas
python run.py monitor --observe-only --scenario normal --campaign-id article_campaign

# Corridas de ataque con mitigación
python run.py experiment --campaign-id article_campaign
```

Antes de cada grupo de ataques, `KALI_CONNECTED_INTERFACE` debe reflejar la conexión real.

### Generación

```bash
python run.py statistics --campaign-id article_campaign
```

Se producen:

- `results.csv`: una fila por corrida.
- `summary.json`: resultado estructurado y definiciones.
- `statistical_report.txt`: resumen legible para el artículo.

### Estadísticos

Para cada métrica temporal disponible se calcula:

- cantidad de observaciones
- media
- desviación estándar muestral
- mediana
- mínimo
- máximo

Las tasas usan denominadores explícitos:

```text
tasa de detección = TP / (TP + FN)
tasa de mitigación = mitigaciones exitosas / pruebas de ataque
precisión del puerto = identificaciones correctas / ataques con puerto Kali registrado
```

`campaign_complete` solo es verdadero al alcanzar como mínimo 10 ataques, 10 normales y la distribución 5/5. Si faltan observaciones, las estadísticas quedan en `null`; no se fabrican valores.

### Estado

El generador está validado con datos sintéticos únicamente para comprobar las fórmulas. Los resultados publicables requieren completar la campaña física de 20 corridas.

## 14. Ticket 11 — Dependencias y configuración reproducible

### Python y dependencias

La versión seleccionada es Python `3.14.4`, declarada en `.python-version`.

Las dependencias directas están fijadas en `requirements.txt`:

```text
netmiko==4.7.0
pysnmp==4.4.12
pyasn1==0.4.8
pyasyncore==1.0.5
paramiko==4.0.0
matplotlib==3.10.9
colorama==0.4.6
python-dotenv==1.2.2
pytest==9.1.1
```

`pip check` no reporta dependencias rotas en el entorno utilizado.

### Variables de entorno

`.env` está excluido mediante `.gitignore`. `.env.example` proporciona las claves necesarias sin contraseñas:

```dotenv
SWITCH_HOST=192.168.1.10
SWITCH_USERNAME=admin
SWITCH_PASS=
SWITCH_SECRET=
SNMP_HOST=192.168.1.10
SNMP_COMMUNITY=public
KALI_IP=
KALI_CONNECTED_INTERFACE=Ethernet0/3
MACOF_COMMAND=sudo macof -i eth0 -n 500
```

`tests/test_ssh.py` consume `config.settings.SWITCH` y ya no contiene una contraseña literal.

### Versión del agente

`config/version.py` es la única fuente de la versión `v7.0`. La consola, el agente, los reportes y el dashboard importan `VERSION_LABEL`. El README presenta la misma versión.

## 15. Ticket 12 — Pruebas unitarias y topología fija

### Suite pytest

El proyecto usa `pytest` y mocks. La suite específica `tests/test_ticket12.py` cubre:

1. Timeout SNMP no borra el baseline.
2. Recuperación SNMP no genera un ataque falso.
3. Mapeo de bridge port a interfaz.
4. Interfaz desconocida no se bloquea.
5. Puerto protegido no se bloquea.
6. Fallo SSH no se registra como éxito.
7. Cálculo correcto de MAC/s.
8. Cálculo correcto de media y desviación estándar muestral.

Ejecución:

```bash
python -m pytest
```

Resultado de la última validación local:

```text
46 passed
2 warnings de deprecación internas de PySNMP/PySMI
```

Las advertencias no representan fallos del agente. La prueba manual SSH está protegida por `if __name__ == "__main__"`, por lo que pytest no intenta conectarse a GNS3.

### Topología experimental

| Nodo | Dirección | Interfaz | Observación |
|---|---|---|---|
| R-IOU | `192.168.1.1` | `Ethernet0/0` | Gateway |
| Victima-1 | `192.168.1.20` | `Ethernet0/1` | Tráfico legítimo |
| Victima-2 | `192.168.1.30` | `Ethernet0/2` | Perfil base |
| Kali | `192.168.1.99` | `Ethernet0/3` | Perfil base |
| SW-IOU | `192.168.1.10` | `VLAN 1` | Gestión SSH/SNMP |
| Agente | Red host-only | `Ethernet1/0` | Gestión protegida |

Para la segunda prueba de identificación se detiene la ejecución, se desconecta temporalmente Victima-2 y Kali se mueve a `Ethernet0/2`. No se cambia código ni se añade un fallback.

Las interfaces protegidas son:

```python
PROTECTED_INTERFACES = {
    "Ethernet0/0",  # router
    "Ethernet1/0",  # gestión
}
```

El agente comprueba esta lista antes de invocar la mitigación.

## 16. Comandos operativos

### Instalación

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -r requirements.txt
Copy-Item .env.example .env
```

### Pruebas

```bash
python -m pytest
python tests/test_ssh.py
```

El segundo comando es un health check manual y requiere el switch activo.

### Observación y ataque

```bash
python run.py monitor --observe-only --scenario normal --threshold 50
python run.py monitor --observe-only --scenario attack --threshold 50
python run.py experiment --threshold 50 --campaign-id article_campaign
```

### Restauración

```bash
python run.py restore --interface Ethernet0/3 --verify-ip 192.168.1.99
```

### Exportación y análisis

```bash
python run.py export
python run.py statistics --campaign-id article_campaign
python src/dashboard.py --run-id run_003 --no-show
```

## 17. Archivos principales

| Archivo | Responsabilidad |
|---|---|
| `config/settings.py` | Direcciones, credenciales por entorno, umbral e interfaces protegidas |
| `config/version.py` | Versión única del agente |
| `src/agent.py` | Orquestación, polling y selección de respuesta |
| `src/detector.py` | Lectura CAM, estado SNMP, tasa MAC/s y resolución de interfaz |
| `src/mitigador.py` | `shutdown_only` y verificación |
| `src/restorer.py` | Restauración manual |
| `src/experiment.py` | Directorios por corrida, metadatos y exportación |
| `src/campaign.py` | Resumen estadístico de campaña |
| `src/reporter.py` | Eventos, alertas y reporte de sesión |
| `src/dashboard.py` | Visualización por corrida |
| `run.py` | CLI interactiva y subcomandos |
| `tests/test_ticket12.py` | Riesgos principales con pytest y mocks |

## 18. Trabajo experimental pendiente

La implementación no sustituye las pruebas físicas. Para cerrar la validación científica deben ejecutarse:

1. Dos pruebas de identificación dinámica con Kali en `Ethernet0/3` y `Ethernet0/2`.
2. Una interrupción y recuperación real de SNMP.
3. Verificación de `shutdown` y restauración sobre IOS/IOU.
4. Cuarenta corridas para los umbrales 10, 25, 50 y 100 MAC/s.
5. Veinte corridas para la campaña principal del artículo.
6. Exportación final de los CSV, JSON, reporte estadístico y dashboards.

Hasta completar esas ejecuciones, el proyecto puede afirmar que la infraestructura experimental y sus controles están implementados y probados unitariamente, pero no debe publicar tasas o tiempos como resultados reales.

## 19. Conclusión

Los doce tickets transformaron el proyecto en una plataforma experimental acotada, auditable y reproducible para MAC Flooding. El agente identifica dinámicamente la interfaz, falla de forma segura ante pérdida SNMP, aplica una mitigación verificable, conserva cada corrida, mide tiempos reales, permite observación pasiva y genera estadísticas sin inventar datos.

La suite automatizada valida la lógica sin GNS3. La siguiente fase es ejecutar las campañas físicas documentadas y utilizar exclusivamente sus artefactos como evidencia del artículo.
