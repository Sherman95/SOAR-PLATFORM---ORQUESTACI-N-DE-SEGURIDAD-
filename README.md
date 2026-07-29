# 🛡️ SOAR Agent: Orquestación de Seguridad y Autonomía

![Python](https://img.shields.io/badge/Python-3.14.4-blue.svg)
![Agent](https://img.shields.io/badge/Agent-v7.0-cyan.svg)
![Netmiko](https://img.shields.io/badge/Netmiko-SSH_Automation-green.svg)
![PySNMP](https://img.shields.io/badge/PySNMP-Telemetry-yellow.svg)
![GNS3](https://img.shields.io/badge/GNS3-Network_Simulation-orange.svg)
![Status](https://img.shields.io/badge/Status-Experimental_MAC-orange.svg)

**Detección y mitigación experimental de MAC Flooding mediante Python y telemetría en entornos simulados.**

Este proyecto implementa una arquitectura **SOAR (Security Orchestration, Automation, and Response)** construida en Python. La versión experimental validada detecta y mitiga **exclusivamente MAC Flooding** sobre switches Cisco IOS simulados en GNS3.

> **Alcance de validación:** ARP Spoofing está fuera del alcance actual. Su prototipo se conserva aislado en `src/experimental/arp.py`, pero el agente principal no lo importa, no inicia Scapy y no ejecuta cuarentenas o restauraciones ARP.

## 🚀 Características Principales

* **Detección MAC:** Monitoreo de la tabla CAM mediante SNMP con umbral de 50 MAC nuevas por segundo.
* **Identificación dinámica:** Resuelve `dot1dTpFdbPort → dot1dBasePortIfIndex → ifName`; ningún puerto atacante está fijado como fallback.
* **Telemetría fail-closed:** Un timeout SNMP produce `TELEMETRIA_DEGRADADA`, conserva la última CAM válida y nunca ejecuta una mitigación con datos incompletos.
* **Mitigación verificable:** Ejecuta exclusivamente `shutdown` y declara éxito solo si IOS responde `administratively down`.
* **Restauración manual:** No existen hilos de recuperación durante la medición; cada escenario se restablece mediante un comando explícito y auditable.
* **Evidencia reproducible:** Cada ejecución se conserva en un directorio `run_NNN` con metadatos, capturas CAM, eventos, métricas temporales y estado del switch antes y después.
* **Temporización experimental:** Mide con `time.monotonic_ns()` desde el inicio del poll SNMP hasta la confirmación real de `administratively down`.
* **Arquitectura Modular (Clean Architecture):** Separación estricta de responsabilidades (Configuración, Datos, Lógica y Reportes).

---

## 📂 Arquitectura del Proyecto

El repositorio sigue estándares de ingeniería de software para despliegues escalables:

```text
SOAR_AGENT/
├── config/                 # ⚙️ Configuraciones centrales (IPs, umbrales, credenciales)
│   └── settings.py
├── data/experiments/mac_flooding_validation/
│   ├── run_001/            # Evidencia inmutable de una ejecución
│   │   ├── metadata.json
│   │   ├── cam_snapshots.jsonl
│   │   ├── events.jsonl
│   │   ├── metrics.json
│   │   ├── switch_before.txt
│   │   └── switch_after.txt
│   ├── summary.csv         # Resumen exportable de todas las ejecuciones
│   └── threshold_evaluation.csv # TP/FP/TN/FN agrupados por umbral
├── src/                    # 🧠 Core del sistema
│   ├── agent.py            # Orquestador del experimento MAC Flooding
│   ├── detector.py         # Detección CAM mediante SNMP
│   ├── mitigador.py        # Mitigación shutdown_only verificada
│   ├── experiment.py       # Persistencia y exportación por ejecución
│   ├── restorer.py         # Restauración manual entre ejecuciones
│   ├── dashboard.py        # Analítica exclusiva del alcance MAC
│   └── experimental/arp.py # Prototipo ARP no importado ni validado
├── tests/                  # 🧪 Pruebas de conectividad
│   └── test_ssh.py
├── run.py                  # 🚀 CLI Orquestador (Menú principal)
├── requirements.txt        # Dependencias del proyecto
└── README.md
```

---

## 🛠️ Requisitos e Instalación

### Entorno Simulado

* **GNS3** con imagen de Cisco IOS (L2 Switch).
* **Kali Linux** (como nodo atacante utilizando `macof`).
* Topología de red configurada (Management IP accesible vía SSH/SNMP).

### Topología experimental fijada

| Nodo | Dirección | Interfaz del switch | Función |
|---|---|---|---|
| R-IOU | `192.168.1.1` | `Ethernet0/0` | Gateway protegido |
| Victima-1 | `192.168.1.20` | `Ethernet0/1` | Tráfico legítimo |
| Victima-2 | `192.168.1.30` | `Ethernet0/2` | Tráfico legítimo en el perfil base |
| Kali | `192.168.1.99` | `Ethernet0/3` | Ataque en el perfil base |
| SW-IOU | `192.168.1.10` | `VLAN 1` | Gestión SSH/SNMP |
| Agente Python | Red host-only | `Ethernet1/0` | Enlace de gestión protegido |

Para demostrar identificación dinámica se reservan `Ethernet0/2` y `Ethernet0/3` como posiciones alternativas de Kali. El perfil A utiliza Kali en `Ethernet0/3` y Victima-2 en `Ethernet0/2`. En el perfil B se detiene la prueba, se desconecta temporalmente Victima-2 y se mueve Kali a `Ethernet0/2`; no se modifica código, umbral ni fallback de puertos. La interfaz real de cada perfil debe declararse como `KALI_CONNECTED_INTERFACE` antes de iniciar la corrida.

Las interfaces protegidas son exactamente:

```python
PROTECTED_INTERFACES = {
    "Ethernet0/0",  # router
    "Ethernet1/0",  # gestión
}
```

El agente descarta estas interfaces antes de invocar la mitigación, incluso si su tasa supera el umbral.

### Entorno Python (Windows/Linux)

1. Clonar el repositorio:

```bash
git clone https://github.com/tu-usuario/soar-agent-mac.git
cd soar-agent-mac
```

2. Crear y activar el entorno virtual:

```powershell
# En Windows
python -m venv .venv
.\.venv\Scripts\Activate.ps1
```

3. Instalar las dependencias fijadas. La versión oficial elegida para reproducir el laboratorio es Python `3.14.4`, declarada también en `.python-version`:

```bash
pip install -r requirements.txt
```

4. Crear la configuración local y completar sus credenciales:

```powershell
Copy-Item .env.example .env
```

`.env` está excluido de Git. `requirements.txt` fija las versiones realmente utilizadas de PySNMP, PyASN1, python-dotenv, Netmiko y el resto de dependencias directas.

5. Ejecutar las pruebas unitarias sin GNS3:

```bash
python -m pytest
```

El health check SSH permanece disponible mediante `python tests/test_ssh.py`, pero está aislado de la colección de pytest y es la única comprobación que requiere el laboratorio activo.

---

## 💻 Uso de la Plataforma

El sistema cuenta con un **CLI Interactivo** que centraliza todas las operaciones. Para iniciar la plataforma, simplemente ejecuta:

```bash
python run.py
```

### Validación de identificación de interfaz

El experimento debe ejecutarse dos veces sin modificar código ni configuración:

1. Conectar Kali a `Ethernet0/3` y comprobar que el evento registra `detected_interface: Ethernet0/3`.
2. Conectar Kali a `Ethernet0/2` y comprobar que el evento registra `detected_interface: Ethernet0/2`.

Cada mitigación registra `detected_interface`, `bridge_port`, `if_index`, `new_mac_count` y `threshold_mac_per_second`. Si BRIDGE-MIB no puede resolver la interfaz, se genera `INTERFAZ_NO_RESUELTA` y no se envía ningún comando de bloqueo.

### Restauración manual entre pruebas

```bash
python run.py restore --interface Ethernet0/3 --verify-ip <IP_DE_KALI>
```

La IP también puede definirse como `KALI_IP` en `.env`. El comando ejecuta `no shutdown`, limpia la tabla CAM dinámica y verifica `up/up`, conectividad con Kali y un baseline de 3 a 5 MAC legítimas. No cambia la VLAN de la interfaz y puede ejecutarse repetidamente.

### Identificación del experimento

Antes de ejecutar, pueden declararse en `.env` los datos que deben quedar asociados a la corrida:

```dotenv
KALI_CONNECTED_INTERFACE=Ethernet0/3
MACOF_COMMAND=macof -i eth0
```

El agente asigna automáticamente el siguiente identificador libre (`run_001`, `run_002`, etc.) y nunca elimina ni sobrescribe ejecuciones anteriores.

### Modo de observación

Para comprobar falsos positivos sin permitir cambios en el switch:

```bash
python run.py monitor --observe-only
```

La ejecución se etiqueta como `normal` de forma predeterminada. En este modo el agente detecta y registra `MAC_FLOOD_OBSERVED`, pero la ruta de configuración IOS y el comando `shutdown` no se ejecutan. Para una prueba positiva controlada:

```bash
python run.py monitor --observe-only --scenario attack
sudo macof -i eth0 -n 500
```

Al finalizar con `Ctrl+C`, la combinación entre la etiqueta real y la presencia de una anomalía produce una clasificación `true_positive`, `false_positive`, `true_negative` o `false_negative` en `metadata.json`, `metrics.json` y los CSV consolidados.

Los escenarios normales que deben ejecutarse por separado son: red inactiva, ping entre víctimas, ping al gateway, reinicio de una VPCS, limpieza y reaprendizaje de CAM, y reconexión de una víctima. Cada escenario debe ocupar una corrida distinta.

### Validación controlada del umbral

La tasa se calcula como `new_mac_count / elapsed_seconds`; el conteo de MAC nuevas de un ciclo no se presenta directamente como MAC/s. Para cada valor sugerido (`10`, `25`, `50` y `100` MAC/s), deben completarse cinco corridas normales y cinco de ataque:

```bash
python run.py monitor --observe-only --scenario normal --threshold 25
python run.py monitor --observe-only --scenario attack --threshold 25
```

Los comandos se repiten cinco veces por etiqueta y por umbral. `threshold_evaluation.csv` muestra cantidad de pruebas, ataques detectados, TP/FP/TN/FN y medias de detección, end-to-end y duración de corrida. Las celdas sin medición permanecen vacías; el agente no sustituye resultados ausentes ni incorpora las cifras ilustrativas del ticket.

### Campaña estadística para el artículo

Use un identificador exclusivo para evitar mezclar esta campaña con las pruebas de umbral. Las diez corridas legítimas se ejecutan pasivamente:

```bash
python run.py monitor --observe-only --scenario normal --campaign-id article_campaign
```

Los diez ataques se ejecutan con mitigación activa. Antes de cada grupo de cinco, establezca en `.env` el puerto real de Kali como `Ethernet0/3` o `Ethernet0/2`:

```bash
python run.py experiment --campaign-id article_campaign
```

Después de completar las 20 corridas:

```bash
python run.py statistics --campaign-id article_campaign
```

El comando produce `results.csv`, `summary.json` y `statistical_report.txt`. Calcula media, desviación estándar muestral, mediana, mínimo y máximo de cada métrica temporal. También calcula detección como `TP/(TP+FN)`, mitigación como mitigaciones exitosas/pruebas de ataque y precisión del puerto como identificaciones correctas/ataques con puerto Kali registrado. `summary.json` indica si se alcanzó la distribución mínima 10/10 y 5/5; nunca completa resultados ausentes.

### Exportar y consultar resultados

```bash
python run.py export
python src/dashboard.py --run-id run_003 --no-show
```

El primer comando reconstruye `summary.csv` y `threshold_evaluation.csv` con todas las corridas disponibles. El dashboard usa la ejecución indicada o, si se omite `--run-id`, la más reciente; su imagen queda dentro del mismo directorio de la corrida.

### Opciones del Menú (SOAR-CLI):

1. **🛡️ Iniciar SOAR Agent:** Levanta el monitoreo MAC Flooding en vivo. Detén el monitoreo con `Ctrl+C` para generar el log.
2. **📊 Generar Dashboard de Métricas:** Analiza la evidencia de la última ejecución y guarda `dashboard.png` junto a sus artefactos.
3. **🔌 Ejecutar Pruebas de Conectividad:** Valida la conexión SSH antes de iniciar la vigilancia.
4. **📜 Ver Historial de Reportes:** Imprime el reporte de la última ejecución; el consolidado completo se obtiene mediante `python run.py export`.

---

## 📈 Métricas experimentales

La temporización se registra sin porcentajes estimados ni comparaciones con tiempos humanos. Los hitos son `t0` (inicio del poll SNMP), `t1` (CAM recibida), `t2` (anomalía identificada), `t3` (inicio de acción SSH), `t4` (fin de `shutdown`) y `t5` (confirmación `administratively down`).

Cada mitigación registra `snmp_read_ms`, `analysis_ms`, `ssh_command_ms`, `verification_ms`, `detection_cycle_ms`, `containment_ms`, `end_to_end_ms` y `actual_poll_interval_ms`. La métrica principal de respuesta es `end_to_end_ms = t5 - t0`; `write memory` no forma parte del flujo ni del tiempo de contención.

---

## 👨‍💻 Autores

* Castillo Ortega Brandon Estefano
* Peña Paladines Martin Alexander
* Azuero Maldonado Ronald Alejandro
