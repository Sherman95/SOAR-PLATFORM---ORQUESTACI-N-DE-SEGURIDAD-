#!/usr/bin/env python3
"""
SOAR Agent - Entry Point
Orquestador principal con interfaz de línea de comandos (CLI).
"""

import os
import sys
import time
import subprocess
from colorama import Fore, Back, Style, init

init(autoreset=True)

def clear_screen():
    os.system('cls' if os.name == 'nt' else 'clear')

def print_banner():
    # Banner principal del sistema (Corregido a SOAR)
    banner = f"""{Fore.CYAN}{Style.BRIGHT}
 ╔══════════════════════════════════════════════════════════════╗
 ║   ██████╗  ██████╗  █████╗ ██████╗                           ║
 ║  ██╔════╝ ██╔═══██╗██╔══██╗██╔══██╗                          ║
 ║  ╚█████╗  ██║   ██║███████║██████╔╝                          ║
 ║   ╚═══██╗ ██║   ██║██╔══██║██╔══██╗                          ║
 ║  ██████╔╝ ╚██████╔╝██║  ██║██║  ██║                          ║
 ║  ╚═════╝   ╚═════╝ ╚═╝  ╚═╝╚═╝  ╚═╝                          ║
 ║                                                              ║
 ║          SOAR PLATFORM - ORQUESTACIÓN DE SEGURIDAD           ║
 ║                   Arquitectura Modular v4.0                  ║
 ╚══════════════════════════════════════════════════════════════╝{Style.RESET_ALL}"""
    
    # Información Académica con el equipo completo
    contexto_academico = f"""{Fore.CYAN} ├─ {Style.BRIGHT}Contexto:{Style.RESET_ALL}{Fore.CYAN} Orquestación Dinámica de ACLs y Mitigación LAN
 ├─ {Style.BRIGHT}Entidad: {Style.RESET_ALL}{Fore.CYAN} Universidad Técnica de Machala (UTMACH)
 ├─ {Style.BRIGHT}Facultad:{Style.RESET_ALL}{Fore.CYAN} Ingeniería Civil | Carrera de Tecnologías de la Información
 ├─ {Style.BRIGHT}Módulo:  {Style.RESET_ALL}{Fore.CYAN} Seguridad de Redes (Octavo Semestre - Paralelo A)
 ├─ {Style.BRIGHT}Director:{Style.RESET_ALL}{Fore.CYAN} Ing. Oscar Efren Cardenas Villavicencio
 ├─ {Style.BRIGHT}Autores: {Style.RESET_ALL}{Fore.CYAN} Castillo Ortega Brandon Estefano
 │            {Fore.CYAN} Peña Paladines Martin Alexander
 │            {Fore.CYAN} Azuero Maldonado Ronald Alejandro
 └─ {Style.BRIGHT}Periodo: {Style.RESET_ALL}{Fore.CYAN} 2026
{Style.RESET_ALL}"""
    
    print(banner)
    print(contexto_academico)
    

def main_menu():
    while True:
        clear_screen()
        print_banner()
        print(f"{Fore.WHITE}{Style.BRIGHT} SELECCIONE UN MÓDULO DE OPERACIÓN:{Style.RESET_ALL}\n")
        print(f"  {Fore.GREEN}[1]{Style.RESET_ALL} 🛡️  Iniciar SOAR Agent (Prevención en Tiempo Real)")
        print(f"  {Fore.GREEN}[2]{Style.RESET_ALL} 📊 Generar Dashboard de Métricas (Reporte Forense)")
        print(f"  {Fore.GREEN}[3]{Style.RESET_ALL} 🔌 Ejecutar Pruebas de Conectividad (Health Check)")
        print(f"  {Fore.GREEN}[4]{Style.RESET_ALL} 📜 Ver Historial de Reportes (Logs Anteriores)")
        print(f"  {Fore.RED}[0]{Style.RESET_ALL} ❌ Salir\n")
        
        choice = input(f"{Fore.CYAN} SOAR-CLI > {Style.RESET_ALL}")
        
        if choice == '1':
            print(f"\n{Fore.YELLOW}[*] Lanzando Agente SOAR... Presione Ctrl+C para detener y consolidar el experimento.{Style.RESET_ALL}\n")
            try:
                subprocess.run([sys.executable, "src/agent.py"])
            except KeyboardInterrupt:
                pass
            input(f"\n{Fore.CYAN}[*] Presione ENTER para continuar...{Style.RESET_ALL}")
            
        elif choice == '2':
            print(f"\n{Fore.YELLOW}[*] Procesando datos del último experimento y generando Dashboard...{Style.RESET_ALL}")
            subprocess.run([sys.executable, "src/dashboard.py"])
            input(f"\n{Fore.CYAN}[*] Presione ENTER para continuar...{Style.RESET_ALL}")
            
        elif choice == '3':
            print(f"\n{Fore.YELLOW}[*] Ejecutando pruebas de conexión SSH/SNMP...{Style.RESET_ALL}")
            if os.path.exists("tests/test_ssh.py"):
                subprocess.run([sys.executable, "tests/test_ssh.py"])
            else:
                print(f"{Fore.RED}[-] Archivo de diagnóstico no encontrado en tests/test_ssh.py{Style.RESET_ALL}")
            input(f"\n{Fore.CYAN}[*] Presione ENTER para continuar...{Style.RESET_ALL}")
            
        elif choice == '4':
            clear_screen()
            print_banner()
            print(f"{Fore.WHITE}{Style.BRIGHT} 📜 HISTORIAL DE EXPERIMENTOS EJECUTADOS:{Style.RESET_ALL}\n")
            historial_path = "data/history_reports.txt"
            
            if os.path.exists(historial_path):
                with open(historial_path, "r", encoding="utf-8") as f:
                    print(f.read())
            else:
                print(f"{Fore.RED} [-] No existen reportes previos registrados en la base de datos.{Style.RESET_ALL}")
                
            print(f"{Fore.CYAN}=================================================={Style.RESET_ALL}")
            input(f"\n{Fore.CYAN}[*] Presione ENTER para regresar al menú principal...{Style.RESET_ALL}")
            
        elif choice == '0':
            print(f"\n{Fore.GREEN}Apagando sistema de orquestación. ¡Misión cumplida!{Style.RESET_ALL}")
            sys.exit(0)
            
        else:
            print(f"\n{Fore.RED}[!] Opción no válida.{Style.RESET_ALL}")
            time.sleep(1)

if __name__ == "__main__":
    try:
        main_menu()
    except KeyboardInterrupt:
        print(f"\n\n{Fore.RED}Apagado forzado del sistema.{Style.RESET_ALL}")
        sys.exit(0)