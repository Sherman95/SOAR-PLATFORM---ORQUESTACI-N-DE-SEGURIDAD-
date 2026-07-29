"""Deteccion de MAC Flooding y resolucion dinamica de interfaces por SNMP."""

import importlib.util  # PySNMP 4.x lo presupone cargado en Python 3.14
import time
from collections import defaultdict
from dataclasses import dataclass, field
from concurrent.futures import ThreadPoolExecutor

from colorama import Fore, Style
from pysnmp.hlapi import (
    CommunityData,
    ContextData,
    ObjectIdentity,
    ObjectType,
    SnmpEngine,
    UdpTransportTarget,
    bulkCmd,
)


OID_FDB_PORT = "1.3.6.1.2.1.17.4.3.1.2"
OID_BASE_PORT_IFINDEX = "1.3.6.1.2.1.17.1.4.1.2"
OID_IF_NAME = "1.3.6.1.2.1.31.1.1.1.1"


def calcular_tasa_mac(new_mac_count: int, elapsed_seconds: float) -> float:
    """Calcula MAC/s; nunca interpreta el conteo del ciclo como una tasa."""
    if elapsed_seconds <= 0:
        return 0.0
    return new_mac_count / elapsed_seconds


@dataclass
class CamReadResult:
    """Resultado explicito de una lectura completa de telemetria CAM."""

    success: bool
    entries: dict
    elapsed_ms: float
    error_type: str | None = None
    error_message: str | None = None
    snmp_walks: list[dict] = field(default_factory=list)


@dataclass
class SnmpWalkMetric:
    oid: str
    label: str
    elapsed_ms: float
    response_count: int
    varbind_count: int
    timeout_seconds: float
    retries: int
    iterations: list[dict] = field(default_factory=list)
    completion_wait_ms: float = 0.0
    error_type: str | None = None
    error_message: str | None = None

    def as_dict(self) -> dict:
        return {
            "oid": self.oid,
            "label": self.label,
            "elapsed_ms": self.elapsed_ms,
            "response_count": self.response_count,
            "varbind_count": self.varbind_count,
            "timeout_seconds": self.timeout_seconds,
            "retries": self.retries,
            "iterations": self.iterations,
            "completion_wait_ms": self.completion_wait_ms,
            "error_type": self.error_type,
            "error_message": self.error_message,
        }


@dataclass(frozen=True)
class InterfaceIdentity:
    bridge_port: int
    if_index: int
    if_name: str


@dataclass(frozen=True)
class CamComparison:
    """Transicion entre las dos ultimas lecturas CAM validas."""

    previous_entries: dict
    current_entries: dict
    elapsed_since_valid: float
    recovered_after_failures: int


@dataclass
class CamMonitorState:
    """Conserva la ultima CAM valida y contabiliza fallos consecutivos."""

    degraded_after: int = 3
    last_valid_entries: dict = field(default_factory=dict)
    last_valid_at_ns: int | None = None
    consecutive_failures: int = 0

    @property
    def telemetry_degraded(self) -> bool:
        return self.consecutive_failures >= self.degraded_after

    def observe(
        self, result: CamReadResult, observed_at_ns: int | None = None
    ) -> CamComparison | None:
        """Actualiza estado solo con lecturas validas; un fallo retorna None."""
        now_ns = time.monotonic_ns() if observed_at_ns is None else observed_at_ns
        if not result.success:
            self.consecutive_failures += 1
            return None

        previous = {
            port: set(macs) for port, macs in self.last_valid_entries.items()
        }
        elapsed = (
            max((now_ns - self.last_valid_at_ns) / 1_000_000_000, 1e-9)
            if self.last_valid_at_ns is not None
            else 0.0
        )
        recovered = self.consecutive_failures
        self.last_valid_entries = {
            port: set(macs) for port, macs in result.entries.items()
        }
        self.last_valid_at_ns = now_ns
        self.consecutive_failures = 0
        return CamComparison(previous, result.entries, elapsed, recovered)


class SNMPReadError(RuntimeError):
    def __init__(self, error_type: str, message: str):
        super().__init__(message)
        self.error_type = error_type


class Detector:
    """Lee la CAM y resuelve cada bridge port a la interfaz IOS real."""

    def __init__(self, network, snmp_config: dict):
        self.net = network
        self.snmp = snmp_config
        self.baseline_macs: set = set()
        self._interface_map: dict[int, InterfaceIdentity] = {}
        self.last_walk_metrics: list[dict] = []

    def _walk_label(self, oid: str) -> str:
        labels = {
            OID_FDB_PORT: "OID_FDB_PORT",
            OID_BASE_PORT_IFINDEX: "OID_BASE_PORT_IFINDEX",
            OID_IF_NAME: "OID_IF_NAME",
        }
        return labels.get(oid, oid)

    def _record_walk_metric(
        self,
        oid: str,
        started_ns: int,
        response_count: int,
        varbind_count: int,
        iterations: list[dict],
        completion_wait_ms: float = 0.0,
        error_type: str | None = None,
        error_message: str | None = None,
    ):
        metric = SnmpWalkMetric(
            oid=oid,
            label=self._walk_label(oid),
            elapsed_ms=round((time.monotonic_ns() - started_ns) / 1_000_000, 3),
            response_count=response_count,
            varbind_count=varbind_count,
            timeout_seconds=self.snmp["timeout"],
            retries=self.snmp["retries"],
            iterations=iterations,
            completion_wait_ms=completion_wait_ms,
            error_type=error_type,
            error_message=error_message,
        )
        self.last_walk_metrics.append(metric.as_dict())

    def _snmp_walk(self, oid: str) -> list[tuple[str, str]]:
        started_ns = time.monotonic_ns()
        rows = []
        response_count = 0
        varbind_count = 0
        iterations = []
        iterator = bulkCmd(
            SnmpEngine(),
            CommunityData(self.snmp["community"], mpModel=1),
            UdpTransportTarget(
                (self.snmp["host"], self.snmp["port"]),
                timeout=self.snmp["timeout"],
                retries=self.snmp["retries"],
            ),
            ContextData(),
            0, 25,
            ObjectType(ObjectIdentity(oid)),
            lexicographicMode=False,
            maxRows=4000,
        )
        while True:
            iteration_started_ns = time.monotonic_ns()
            try:
                error_indication, error_status, error_index, var_binds = next(
                    iterator
                )
            except StopIteration:
                completion_wait_ms = round(
                    (time.monotonic_ns() - iteration_started_ns) / 1_000_000,
                    3,
                )
                break
            iteration_elapsed_ms = round(
                (time.monotonic_ns() - iteration_started_ns) / 1_000_000,
                3,
            )
            response_count += 1
            if error_indication:
                message = str(error_indication)
                iterations.append({
                    "index": response_count,
                    "elapsed_ms": iteration_elapsed_ms,
                    "varbind_count": 0,
                    "error_type": "error_indication",
                    "error_message": message,
                })
                self._record_walk_metric(
                    oid, started_ns, response_count, varbind_count, iterations,
                    error_type="error_indication",
                    error_message=message,
                )
                raise SNMPReadError("error_indication", str(error_indication))
            if error_status:
                position = int(error_index or 0)
                message = (
                    error_status.prettyPrint()
                    if hasattr(error_status, "prettyPrint")
                    else str(error_status)
                )
                iterations.append({
                    "index": response_count,
                    "elapsed_ms": iteration_elapsed_ms,
                    "varbind_count": 0,
                    "error_type": "error_status",
                    "error_message": f"{message} (varbind {position})",
                })
                self._record_walk_metric(
                    oid, started_ns, response_count, varbind_count, iterations,
                    error_type="error_status",
                    error_message=f"{message} (varbind {position})",
                )
                raise SNMPReadError(
                    "error_status", f"{message} (varbind {position})"
                )
            iteration_varbind_count = 0
            first_oid = None
            last_oid = None
            for oid_value, value in var_binds:
                varbind_count += 1
                iteration_varbind_count += 1
                rendered_oid = str(oid_value)
                if first_oid is None:
                    first_oid = rendered_oid
                last_oid = rendered_oid
                rendered = value.prettyPrint() if hasattr(value, "prettyPrint") else str(value)
                rows.append((rendered_oid, rendered))
            iterations.append({
                "index": response_count,
                "elapsed_ms": iteration_elapsed_ms,
                "varbind_count": iteration_varbind_count,
                "first_oid": first_oid,
                "last_oid": last_oid,
                "error_type": None,
                "error_message": None,
            })
        self._record_walk_metric(
            oid, started_ns, response_count, varbind_count, iterations,
            completion_wait_ms,
        )
        return rows

    @staticmethod
    def _oid_index(oid: str) -> int:
        return int(oid.rsplit(".", 1)[-1])

    def leer_cam(self) -> CamReadResult:
        """Lee FDB, bridge-port mapping e ifName concurrentemente."""
        started_ns = time.monotonic_ns()
        self.last_walk_metrics = []
        try:
            with ThreadPoolExecutor(max_workers=3) as executor:
                future_fdb = executor.submit(self._snmp_walk, OID_FDB_PORT)
                future_base = executor.submit(self._snmp_walk, OID_BASE_PORT_IFINDEX)
                future_name = executor.submit(self._snmp_walk, OID_IF_NAME)

                fdb_rows = future_fdb.result()
                base_rows = future_base.result()
                name_rows = future_name.result()

            cam = defaultdict(set)
            for oid, value in fdb_rows:
                bridge_port = int(value)
                mac_octets = oid.split(".")[-6:]
                if len(mac_octets) != 6:
                    raise SNMPReadError("parse_error", f"OID MAC invalido: {oid}")
                mac = ":".join(f"{int(octet):02x}" for octet in mac_octets)
                cam[bridge_port].add(mac)

            entries = dict(cam)
            interface_map = {}
            if entries:
                base_to_ifindex = {self._oid_index(oid): int(value) for oid, value in base_rows}
                if_names = {self._oid_index(oid): value.strip() for oid, value in name_rows}
                
                for bridge_port in entries:
                    if_index = base_to_ifindex.get(bridge_port)
                    if_name = if_names.get(if_index) if if_index is not None else None
                    if if_index is not None and if_name:
                        interface_map[bridge_port] = InterfaceIdentity(
                            bridge_port=bridge_port,
                            if_index=if_index,
                            if_name=if_name,
                        )

            self._interface_map = interface_map
            return CamReadResult(
                success=True,
                entries=entries,
                elapsed_ms=round((time.monotonic_ns() - started_ns) / 1_000_000, 3),
                snmp_walks=list(self.last_walk_metrics),
            )
        except SNMPReadError as exc:
            error_type = exc.error_type
            message = str(exc)
        except Exception as exc:
            error_type = type(exc).__name__
            message = str(exc)

        elapsed = round((time.monotonic_ns() - started_ns) / 1_000_000, 3)
        print(
            f"{Fore.RED} [!] SNMP {error_type}: {message}{Style.RESET_ALL}"
        )
        return CamReadResult(
            False, {}, elapsed, error_type, message,
            list(self.last_walk_metrics),
        )

    def resolver_interfaz(self, bridge_port: int) -> InterfaceIdentity | None:
        return self._interface_map.get(bridge_port)

    def hay_macs_extranas(self, result: CamReadResult) -> bool | None:
        """Retorna None si no hay telemetria valida para decidir recuperacion."""
        if not result.success:
            return None
        actuales = {
            mac for macs in result.entries.values() for mac in macs
        }
        return bool(actuales - self.baseline_macs)

    def verificar_psecure(self, puertos: dict, protegidos: set) -> list:
        violaciones = []
        try:
            out = self.net.conn.send_command(
                "show logging | include PSECURE_VIOLATION",
                expect_string=r"#",
                read_timeout=15,
            )
            if "PSECURE_VIOLATION" in out:
                for num, ios in puertos.items():
                    if num not in protegidos and ios.replace("ethernet ", "Ethernet") in out:
                        violaciones.append((num, ios))
                if violaciones:
                    try:
                        self.net.conn.send_command(
                            "clear logging", expect_string=r"confirm", read_timeout=5
                        )
                        self.net.conn.send_command(
                            "\n", expect_string=r"#", read_timeout=5
                        )
                    except Exception:
                        pass
        except Exception as exc:
            print(f"{Fore.YELLOW} [!] verificar_psecure: {exc}{Style.RESET_ALL}")
        return violaciones
