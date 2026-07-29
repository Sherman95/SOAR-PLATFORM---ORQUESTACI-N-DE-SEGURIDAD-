#!/usr/bin/env python3
"""
SOAR Platform — Entry Point
Interfaz de línea de comandos para el sistema de orquestación de seguridad.
"""

import argparse
import json
import os
import sys
import time
import subprocess
from colorama import Fore, Back, Style, init
from config.version import VERSION_LABEL

init(autoreset=True)

# ─── Constantes de presentación ───────────────────────────────────────────────
VERSION     = VERSION_LABEL
INSTITUTION = "Universidad Técnica de Machala"
SUBJECT     = "Seguridad de Redes  |  8vo Semestre  |  Paralelo A"
DIRECTOR    = "Ing. Oscar Efren Cardenas Villavicencio"
AUTHORS     = [
    "Castillo Ortega Brandon Estefano",
    "Peña Paladines Martin Alexander",
    "Azuero Maldonado Ronald Alejandro",
]
PERIOD      = "Abril - Agosto 2026"

W = 62   # ancho del marco


def run_command_line() -> bool:
    parser = argparse.ArgumentParser(description="SOAR experimental MAC Flooding")
    subcommands = parser.add_subparsers(dest="command", required=True)
    monitor = subcommands.add_parser(
        "monitor", help="Monitoreo pasivo para validar falsos positivos"
    )
    monitor.add_argument(
        "--observe-only", action="store_true", required=True,
        help="Detectar y registrar sin enviar configuración al switch",
    )
    monitor.add_argument(
        "--scenario", choices=("normal", "attack"), default="normal",
        help="Etiqueta real de la ejecución",
    )
    monitor.add_argument(
        "--threshold", type=float, default=None,
        help="Umbral experimental en MAC por segundo",
    )
    monitor.add_argument("--campaign-id", default="default")
    experiment = subcommands.add_parser(
        "experiment", help="Ejecutar ataque con mitigación shutdown_only"
    )
    experiment.add_argument("--threshold", type=float, default=None)
    experiment.add_argument("--campaign-id", default="default")
    restore = subcommands.add_parser(
        "restore", help="Restauracion manual entre ejecuciones"
    )
    restore.add_argument("--interface", required=True, help="Interfaz IOS")
    restore.add_argument(
        "--verify-ip",
        help="IP de Kali; tambien puede configurarse mediante KALI_IP",
    )
    subcommands.add_parser("export", help="Regenerar summary.csv de todos los runs")
    statistics_parser = subcommands.add_parser(
        "statistics", help="Generar resultados estadísticos de la campaña"
    )
    statistics_parser.add_argument("--campaign-id")
    args = parser.parse_args()

    if args.command == "restore":
        root = os.path.abspath(os.path.dirname(__file__))
        src = os.path.join(root, "src")
        sys.path[:0] = [root, src]
        from restorer import ManualRestorer

        restorer = ManualRestorer()
        try:
            result = restorer.restore(args.interface, args.verify_ip)
            print(json.dumps(result.to_dict(), indent=2, ensure_ascii=False))
            return result.ready_for_experiment
        finally:
            restorer.close()
    if args.command == "monitor":
        if args.threshold is not None and args.threshold <= 0:
            parser.error("--threshold debe ser mayor que cero")
        command = [
            sys.executable,
            os.path.join(os.path.dirname(__file__), "src", "agent.py"),
            "--observe-only",
            "--scenario",
            args.scenario,
            "--campaign-id",
            args.campaign_id,
        ]
        if args.threshold is not None:
            command.extend(["--threshold", str(args.threshold)])
        return subprocess.run(command).returncode == 0
    if args.command == "experiment":
        if args.threshold is not None and args.threshold <= 0:
            parser.error("--threshold debe ser mayor que cero")
        command = [
            sys.executable,
            os.path.join(os.path.dirname(__file__), "src", "agent.py"),
            "--scenario", "attack",
            "--campaign-id", args.campaign_id,
        ]
        if args.threshold is not None:
            command.extend(["--threshold", str(args.threshold)])
        return subprocess.run(command).returncode == 0
    if args.command == "export":
        root = os.path.abspath(os.path.dirname(__file__))
        src = os.path.join(root, "src")
        sys.path[:0] = [root, src]
        from config.settings import EXPERIMENT_ROOT
        from experiment import ExperimentRun

        summary = ExperimentRun.export_summary(EXPERIMENT_ROOT)
        threshold_evaluation = ExperimentRun.export_threshold_evaluation(
            EXPERIMENT_ROOT
        )
        print(summary)
        print(threshold_evaluation)
        return True
    if args.command == "statistics":
        root = os.path.abspath(os.path.dirname(__file__))
        src = os.path.join(root, "src")
        sys.path[:0] = [root, src]
        from campaign import CampaignStatistics
        from config.settings import EXPERIMENT_ROOT

        files = CampaignStatistics(EXPERIMENT_ROOT).generate(args.campaign_id)
        for path in files[:3]:
            print(path)
        return True
    return False


def clear_screen():
    os.system("cls" if os.name == "nt" else "clear")


def line(char="─", color=Fore.CYAN) -> str:
    return f"{color}{char * W}{Style.RESET_ALL}"


def box_line(content: str, color=Fore.CYAN, text_color=Fore.WHITE) -> str:
    pad   = W - 2 - len(content)
    left  = pad // 2
    right = pad - left
    return (f"{color}║{Style.RESET_ALL}"
            f"{' ' * left}{text_color}{content}{Style.RESET_ALL}"
            f"{' ' * right}{color}║{Style.RESET_ALL}")


def print_banner():
    C = Fore.CYAN
    W = Fore.WHITE
    G = Fore.GREEN
    R = Style.RESET_ALL
    B = Style.BRIGHT

    print(f"""
{C}{B}╔══════════════════════════════════════════════════════════════╗
║                                                              ║
║    ███████╗ ██████╗  █████╗ ██████╗                          ║
║    ██╔════╝██╔═══██╗██╔══██╗██╔══██╗                         ║
║    ███████╗██║   ██║███████║██████╔╝                         ║
║    ╚════██║██║   ██║██╔══██║██╔══██╗                         ║
║    ███████║╚██████╔╝██║  ██║██║  ██║                         ║
║    ╚══════╝ ╚═════╝ ╚═╝  ╚═╝╚═╝  ╚═╝                         ║
║                                                              ║
║        SECURITY ORCHESTRATION, AUTOMATION & RESPONSE        ║
║               Plataforma de Seguridad Autónoma               ║
╚══════════════════════════════════════════════════════════════╝{R}""")

    # Bloque de información académica
    print(f"{C}  {'─' * 60}{R}")
    print(f"{C}  {'Detección y Contención de MAC Flooding':^60}{R}")
    print(f"{C}  {'─' * 60}{R}")
    print(f"  {Fore.YELLOW}{'Entidad':10}{R}  {INSTITUTION}")
    print(f"  {Fore.YELLOW}{'Módulo':10}{R}  {SUBJECT}")
    print(f"  {Fore.YELLOW}{'Director':10}{R}  {DIRECTOR}")
    print(f"  {Fore.YELLOW}{'Autores':10}{R}  {AUTHORS[0]}")
    for a in AUTHORS[1:]:
        print(f"  {' ':10}   {a}")
    print(f"  {Fore.YELLOW}{'Periodo':10}{R}  {PERIOD}")
    print(f"{C}  {'─' * 60}{R}\n")


def print_menu():
    print(f"{Fore.WHITE}{Style.BRIGHT}  SELECCIONE UN MODULO DE OPERACION:{Style.RESET_ALL}\n")

    opciones = [
        ("1", "Iniciar SOAR Agent",            "Vigilancia y mitigacion en tiempo real"),
        ("2", "Dashboard de Metricas",          "Graficas forenses del ultimo experimento"),
        ("3", "Health Check",                   "Pruebas de conectividad SSH / SNMP"),
        ("4", "Historial de Reportes",          "Última corrida y resumen experimental"),
        ("0", "Salir",                          "Apagar el sistema de orquestacion"),
    ]

    for key, titulo, desc in opciones:
        color = Fore.RED if key == "0" else Fore.GREEN
        print(f"  {color}[ {key} ]{Style.RESET_ALL}  {Fore.WHITE}{Style.BRIGHT}{titulo}{Style.RESET_ALL}")
        print(f"         {Fore.WHITE}{desc}{Style.RESET_ALL}")
        if key != "0":
            print()

    print()


def separador():
    print(f"{Fore.CYAN}  {'─' * 60}{Style.RESET_ALL}")


def main_menu():
    while True:
        clear_screen()
        print_banner()
        print_menu()

        choice = input(f"{Fore.CYAN}  SOAR-CLI  {Fore.WHITE}> {Style.RESET_ALL}").strip()

        # ── [1] Agente SOAR ───────────────────────────────────────────────
        if choice == "1":
            clear_screen()
            separador()
            print(f"\n  {Fore.CYAN}MODULO{Style.RESET_ALL}  SOAR Agent — Vigilancia en Tiempo Real")
            print(f"  {Fore.YELLOW}INFO{Style.RESET_ALL}    Presione Ctrl+C para detener y generar el reporte final.")
            separador()
            print()
            try:
                subprocess.run([sys.executable, "src/agent.py"])
            except KeyboardInterrupt:
                pass
            separador()
            input(f"\n  Presione ENTER para regresar al menu...")

        # ── [2] Dashboard ─────────────────────────────────────────────────
        elif choice == "2":
            clear_screen()
            separador()
            print(f"\n  {Fore.CYAN}MODULO{Style.RESET_ALL}  Dashboard de Metricas — Reporte Forense")
            separador()
            print()
            subprocess.run([sys.executable, "src/dashboard.py"])
            separador()
            input(f"\n  Presione ENTER para regresar al menu...")

        # ── [3] Health Check ──────────────────────────────────────────────
        elif choice == "3":
            clear_screen()
            separador()
            print(f"\n  {Fore.CYAN}MODULO{Style.RESET_ALL}  Health Check — Conectividad SSH / SNMP")
            separador()
            print()
            if os.path.exists("tests/test_ssh.py"):
                subprocess.run([sys.executable, "tests/test_ssh.py"])
            else:
                print(f"  {Fore.RED}ERROR{Style.RESET_ALL}   tests/test_ssh.py no encontrado.")
            separador()
            input(f"\n  Presione ENTER para regresar al menu...")

        # ── [4] Historial ─────────────────────────────────────────────────
        elif choice == "4":
            clear_screen()
            separador()
            print(f"\n  {Fore.CYAN}MODULO{Style.RESET_ALL}  Historial de Reportes\n")
            separador()
            experiment_root = os.path.join(
                "data", "experiments", "mac_flooding_validation"
            )
            runs = sorted(
                entry.path for entry in os.scandir(experiment_root)
                if entry.is_dir() and entry.name.startswith("run_")
            ) if os.path.isdir(experiment_root) else []
            historial_path = os.path.join(runs[-1], "report.txt") if runs else None
            if historial_path and os.path.exists(historial_path):
                with open(historial_path, "r", encoding="utf-8") as f:
                    content = f.read().strip()
                print(f"\n{content}\n")
                print(
                    f"  {Fore.CYAN}RUN{Style.RESET_ALL}     "
                    f"{os.path.basename(runs[-1])}"
                )
                print(
                    f"  {Fore.CYAN}CSV{Style.RESET_ALL}     "
                    f"{os.path.join(experiment_root, 'summary.csv')}\n"
                )
            else:
                print(f"\n  {Fore.YELLOW}INFO{Style.RESET_ALL}    No existen reportes anteriores.")
                print(f"           Ejecute el agente (opcion 1) para generar el primero.\n")
            separador()
            input(f"\n  Presione ENTER para regresar al menu...")

        # ── [0] Salir ─────────────────────────────────────────────────────
        elif choice == "0":
            clear_screen()
            separador()
            print(f"\n  {Fore.GREEN}Sistema de orquestacion detenido correctamente.{Style.RESET_ALL}")
            print(f"  {Fore.WHITE}SOAR Platform {VERSION}  |  UTMACH 2026{Style.RESET_ALL}\n")
            separador()
            print()
            sys.exit(0)

        else:
            print(f"\n  {Fore.RED}ERROR{Style.RESET_ALL}   Opcion no valida. Intente de nuevo.")
            time.sleep(1)


if __name__ == "__main__":
    try:
        if len(sys.argv) > 1:
            sys.exit(0 if run_command_line() else 1)
        main_menu()
    except KeyboardInterrupt:
        print(f"\n\n  {Fore.RED}Apagado forzado del sistema.{Style.RESET_ALL}\n")
        sys.exit(0)
