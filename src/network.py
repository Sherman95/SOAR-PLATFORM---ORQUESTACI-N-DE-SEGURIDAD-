"""
network.py — Módulo de Gestión de Red
Responsabilidad única: mantener la conexión SSH y ejecutar comandos en el switch.
No contiene lógica de detección ni de mitigación.
"""

import re
from dataclasses import dataclass

from netmiko import ConnectHandler
from colorama import Fore, Style


IOS_ERRORES = ("% Invalid input", "Unrecognized command",
               "% Ambiguous command", "not supported")


@dataclass(frozen=True)
class InterfaceStatus:
    success: bool
    interface: str
    status: str
    raw_output: str
    error_message: str | None = None


class NetworkManager:
    """
    Gestiona la sesión SSH con el switch.
    Provee métodos de bajo nivel: conectar, ejecutar comandos, guardar config.
    """

    def __init__(self, switch_config: dict):
        self._cfg  = switch_config
        self.conn  = None

    # ── Conexión ──────────────────────────────────────────────────────────
    def conectar(self) -> bool:
        try:
            print(f"{Fore.CYAN} [*] Autenticando en {self._cfg['host']} vía SSH...{Style.RESET_ALL}")
            self.conn = ConnectHandler(**self._cfg)
            self.conn.enable()
            print(f"{Fore.GREEN} [+] SSH establecido.{Style.RESET_ALL}")
            return True
        except Exception as e:
            print(f"{Fore.RED} [-] Error SSH ({type(e).__name__}): {e}{Style.RESET_ALL}")
            self.conn = None
            return False

    def esta_vivo(self) -> bool:
        """Verifica si la sesión SSH responde. Reconecta si es necesario."""
        try:
            if not self.conn:
                return self.conectar()
            self.conn.send_command("\n", expect_string=r"[>#]", max_loops=3)
            return True
        except Exception:
            print(f"{Fore.YELLOW} [!] SSH caído. Reconectando...{Style.RESET_ALL}")
            self.conn = None
            return self.conectar()

    def desconectar(self):
        try:
            if self.conn:
                self.conn.disconnect()
        except Exception:
            pass
        finally:
            self.conn = None

    # ── Comandos ──────────────────────────────────────────────────────────
    def config(self, cmds: list) -> tuple[bool, str]:
        """
        Envía un bloque de comandos de configuración.
        Retorna (ok, salida). ok=False si el IOS rechazó algún comando.
        """
        try:
            out = self.conn.send_config_set(cmds, read_timeout=10)
            ok  = not any(m in out for m in IOS_ERRORES)
            return ok, out
        except Exception as e:
            return False, str(e)

    def comando(self, cmd: str, timeout: int = 15) -> str:
        """Ejecuta un comando show y retorna la salida como string."""
        try:
            return self.conn.send_command(cmd, read_timeout=timeout)
        except Exception as e:
            print(f"{Fore.RED} [!] Error ejecutando '{cmd}': {e}{Style.RESET_ALL}")
            return ""

    def comando_resultado(self, cmd: str, timeout: int = 15) -> tuple[bool, str]:
        """Ejecuta un comando y distingue excepciones o rechazos de IOS."""
        try:
            output = self.conn.send_command(cmd, read_timeout=timeout)
            accepted = not any(marker in output for marker in IOS_ERRORES)
            return accepted, output
        except Exception as exc:
            return False, str(exc)

    def estado_interfaz(self, interface: str) -> InterfaceStatus:
        """Consulta y normaliza el estado operacional de una interfaz IOS."""
        ok, output = self.comando_resultado(
            f"show interfaces {interface} | include line protocol", timeout=10
        )
        if not ok:
            return InterfaceStatus(False, interface, "query_failed", output, output)

        match = re.search(
            r"^\s*\S+\s+is\s+([^,]+),\s+line protocol is\s+(\S+)",
            output,
            flags=re.IGNORECASE | re.MULTILINE,
        )
        if not match:
            return InterfaceStatus(
                False, interface, "unparseable", output, "Estado no reconocido"
            )

        physical = match.group(1).strip().lower()
        protocol = match.group(2).strip().lower()
        if physical == "administratively down":
            status = "administratively_down"
        elif physical == "up" and protocol == "up":
            status = "up_up"
        elif physical == "up":
            status = "up_down"
        else:
            status = "down_down" if protocol == "down" else f"{physical}_{protocol}"
        return InterfaceStatus(True, interface, status, output)

    def guardar(self):
        """Persiste la configuración en NVRAM (write memory)."""
        try:
            out = self.conn.send_command("write memory", read_timeout=15)
            if "OK" in out or "%" not in out:
                return True
        except Exception as e:
            print(f"{Fore.YELLOW} [!] write memory falló: {e}{Style.RESET_ALL}")
        return False
