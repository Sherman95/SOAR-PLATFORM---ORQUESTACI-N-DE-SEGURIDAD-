# 🛡️ SOAR Agent: Orquestación de Seguridad y Autonomía

![Python](https://img.shields.io/badge/Python-3.12+-blue.svg)
![Netmiko](https://img.shields.io/badge/Netmiko-SSH_Automation-green.svg)
![PySNMP](https://img.shields.io/badge/PySNMP-Telemetry-yellow.svg)
![GNS3](https://img.shields.io/badge/GNS3-Network_Simulation-orange.svg)
![Status](https://img.shields.io/badge/Status-Production_Ready-brightgreen.svg)

**Generación Dinámica de ACLs y Mitigación de Ataques LAN mediante Python y Telemetría en Entornos Simulados.**

Este proyecto implementa una arquitectura **SOAR (Security Orchestration, Automation, and Response)** construida 100% en Python. Está diseñado para detectar y mitigar ataques de denegación de servicio en Capa 2 (específicamente **MAC Flooding**) en milisegundos, operando sobre switches Cisco IOS simulados en GNS3.

## 🚀 Características Principales

* **Detección Dual (Zero-Trust):** Monitoreo de la tabla CAM vía SNMP (Polling de alta velocidad) con un motor de respaldo basado en análisis de tramas ARP (`scapy`), garantizando detección incluso si el plano de control del switch se satura.
* **Mitigación Sub-segundo:** Respuestas automatizadas mediante SSH (`netmiko`) que inyectan ACLs dinámicas y deshabilitan interfaces comprometidas sin intervención humana.
* **Data Pipeline & Dashboards:** Registro persistente de eventos (`.jsonl`) y generación automática de gráficas analíticas y KPIs en alta resolución (reducción del 99.8% en tiempos de respuesta).
* **Arquitectura Modular (Clean Architecture):** Separación estricta de responsabilidades (Configuración, Datos, Lógica y Reportes).

---

## 📂 Arquitectura del Proyecto

El repositorio sigue estándares de ingeniería de software para despliegues escalables:

```text
SOAR_AGENT/
├── config/                 # ⚙️ Configuraciones centrales (IPs, umbrales, credenciales)
│   └── settings.py
├── data/                   # 💾 Base de datos local (Métricas en crudo)
│   ├── soar_metrics.jsonl
│   ├── soar_events.jsonl
│   └── history_reports.txt # Historial persistente de KPIs
├── reports/                # 📊 Evidencias forenses
│   └── dashboards/         # Gráficas generadas automáticamente (.png)
├── src/                    # 🧠 Core del sistema
│   ├── agent.py            # Motor principal SOAR (Vigilancia y Mitigación)
│   └── dashboard.py        # Módulo de analítica de datos (Matplotlib)
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

### Entorno Python (Windows/Linux)

1. Clonar el repositorio:

```bash
git clone [https://github.com/tu-usuario/soar-agent-acls.git](https://github.com/tu-usuario/soar-agent-acls.git)
cd soar-agent-acls
```

2. Crear y activar el entorno virtual:

```powershell
# En Windows
python -m venv .venv
.\.venv\Scripts\Activate.ps1
```

3. Instalar las dependencias exactas (se requiere manejo de versiones para retrocompatibilidad del motor SNMP en Python 3.12+):

```bash
pip install netmiko colorama matplotlib scapy
pip install pysnmp==4.4.12 pyasn1==0.4.8 pyasyncore
```

---

## 💻 Uso de la Plataforma

El sistema cuenta con un **CLI Interactivo** que centraliza todas las operaciones. Para iniciar la plataforma, simplemente ejecuta:

```bash
python run.py
```

### Opciones del Menú (SOAR-CLI):

1. **🛡️ Iniciar SOAR Agent:** Levanta el monitoreo en vivo. (Ataca desde Kali para ver la mitigación en tiempo real). Detén el monitoreo con `Ctrl+C` para generar el log.
2. **📊 Generar Dashboard de Métricas:** Analiza los archivos `.jsonl` del último ataque y renderiza una gráfica HD en la carpeta `reports/dashboards/`.
3. **🔌 Ejecutar Pruebas de Conectividad:** Valida credenciales SSH y acceso SNMP antes de iniciar la vigilancia.
4. **📜 Ver Historial de Reportes:** Imprime en consola la base de datos de KPIs (tiempos de respuesta, reducción vs humano) de todos los experimentos pasados.

---

## 📈 Resultados del Experimento (KPIs)

En las pruebas de estrés bajo ataques volumétricos simulados, la arquitectura SOAR logró:

* **Tiempo Promedio de Respuesta:** ~1000 milisegundos (1 segundo).
* **Eficiencia:** Reducción del **99.89%** del tiempo en comparación con un administrador de red humano (estimado en 15 minutos).
* **Integridad:** El plano de control del Switch se mantuvo estable gracias a la intervención oportuna.

---

## 👨‍💻 Autores

* Castillo Ortega Brandon Estefano
* Peña Paladines Martin Alexander
* Azuero Maldonado Ronald Alejandro
