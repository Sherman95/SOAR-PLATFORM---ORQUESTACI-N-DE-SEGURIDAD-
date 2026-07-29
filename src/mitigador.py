"""Mitigacion experimental shutdown_only para MAC Flooding."""

import time

from colorama import Back, Fore, Style


class Mitigador:
    """Apaga una interfaz y solo declara exito tras verificar su estado."""

    def __init__(self, network, reporter):
        self.net = network
        self.reporter = reporter
        self.bloqueados = set()
        self.blocked_interfaces = set()
        self.historico_bloqueados = set()
        self.historico_interfaces = {}
        self.initial_interface_states = {}
        self.last_result = None

    @staticmethod
    def _ms(start_ns: int, end_ns: int) -> float:
        return round((end_ns - start_ns) / 1_000_000, 3)

    def _timing_metrics(
        self, t0_ns, t1_ns, t2_ns, t3_ns, t4_ns, t5_ns,
        actual_poll_interval_ms,
    ):
        return {
            "snmp_read_ms": self._ms(t0_ns, t1_ns),
            "analysis_ms": self._ms(t1_ns, t2_ns),
            "ssh_command_ms": self._ms(t3_ns, t4_ns),
            "verification_ms": self._ms(t4_ns, t5_ns),
            "detection_cycle_ms": self._ms(t0_ns, t2_ns),
            "containment_ms": self._ms(t2_ns, t5_ns),
            "end_to_end_ms": self._ms(t0_ns, t5_ns),
            "actual_poll_interval_ms": actual_poll_interval_ms,
        }

    def _registrar_resultado(
        self,
        puerto_num,
        puerto_ios,
        timing_metrics,
        initial_status,
        command_sent,
        verification_status,
        mitigation_success,
        if_index,
        new_mac_count,
        threshold_mac_per_second,
        snmp_walks=None,
        command_output="",
    ):
        event = dict(
            event_type="MITIGATION_RESULT",
            interface=puerto_ios,
            detected_interface=puerto_ios,
            bridge_port=puerto_num,
            if_index=if_index,
            new_mac_count=new_mac_count,
            threshold_mac_per_second=threshold_mac_per_second,
            action="shutdown",
            initial_status=initial_status,
            command_sent=command_sent,
            command_output=command_output,
            verification_status=verification_status,
            mitigation_success=mitigation_success,
            snmp_walks=snmp_walks or [],
            **timing_metrics,
        )
        self.last_result = event.copy()
        self.reporter.registrar_evento(
            "MAC_FLOOD_SNMP",
            puerto_ios,
            "SHUTDOWN",
            timing_metrics["end_to_end_ms"],
            **event,
        )

    def bloquear_mac_flood(
        self,
        puerto_num: int,
        puerto_ios: str,
        *,
        if_index: int,
        new_mac_count: int,
        threshold_mac_per_second: int,
        poll_started_ns: int | None = None,
        cam_received_ns: int | None = None,
        anomaly_identified_ns: int | None = None,
        actual_poll_interval_ms: float | None = None,
        snmp_walks: list[dict] | None = None,
    ) -> bool:
        t3_ns = time.monotonic_ns()
        t2_ns = t3_ns if anomaly_identified_ns is None else anomaly_identified_ns
        t1_ns = t2_ns if cam_received_ns is None else cam_received_ns
        t0_ns = t1_ns if poll_started_ns is None else poll_started_ns
        if not self.net.esta_vivo():
            t4_ns = t5_ns = time.monotonic_ns()
            self._registrar_resultado(
                puerto_num,
                puerto_ios,
                self._timing_metrics(
                    t0_ns, t1_ns, t2_ns, t3_ns, t4_ns, t5_ns,
                    actual_poll_interval_ms,
                ),
                "unavailable",
                False,
                "ssh_unavailable",
                False,
                if_index,
                new_mac_count,
                threshold_mac_per_second,
                snmp_walks,
            )
            return False

        initial = self.net.estado_interfaz(puerto_ios)
        if not initial.success:
            t4_ns = t5_ns = time.monotonic_ns()
            self._registrar_resultado(
                puerto_num,
                puerto_ios,
                self._timing_metrics(
                    t0_ns, t1_ns, t2_ns, t3_ns, t4_ns, t5_ns,
                    actual_poll_interval_ms,
                ),
                initial.status,
                False,
                "initial_state_unavailable",
                False,
                if_index,
                new_mac_count,
                threshold_mac_per_second,
                snmp_walks,
                initial.raw_output,
            )
            return False

        self.initial_interface_states[puerto_ios] = initial.status
        print(
            f"\n{Back.RED}{Fore.WHITE} MITIGACION MAC FLOOD {Style.RESET_ALL} "
            f"{Fore.RED}shutdown_only en {puerto_ios}{Style.RESET_ALL}"
        )

        command_sent = True
        accepted, command_output = self.net.config([
            f"interface {puerto_ios}",
            " shutdown",
            "exit",
        ])
        t4_ns = time.monotonic_ns()
        if not accepted:
            t5_ns = t4_ns
            self._registrar_resultado(
                puerto_num,
                puerto_ios,
                self._timing_metrics(
                    t0_ns, t1_ns, t2_ns, t3_ns, t4_ns, t5_ns,
                    actual_poll_interval_ms,
                ),
                initial.status,
                command_sent,
                "command_rejected",
                False,
                if_index,
                new_mac_count,
                threshold_mac_per_second,
                snmp_walks,
                command_output,
            )
            return False

        verification = self.net.estado_interfaz(puerto_ios)
        t5_ns = time.monotonic_ns()
        success = (
            verification.success
            and verification.status == "administratively_down"
        )
        self._registrar_resultado(
            puerto_num,
            puerto_ios,
            self._timing_metrics(
                t0_ns, t1_ns, t2_ns, t3_ns, t4_ns, t5_ns,
                actual_poll_interval_ms,
            ),
            initial.status,
            command_sent,
            verification.status,
            success,
            if_index,
            new_mac_count,
            threshold_mac_per_second,
            snmp_walks,
            command_output,
        )

        if not success:
            print(
                f"{Fore.RED} [-] Shutdown no verificado en {puerto_ios}: "
                f"{verification.status}.{Style.RESET_ALL}"
            )
            return False

        self.bloqueados.add(puerto_num)
        self.blocked_interfaces.add(puerto_ios)
        self.historico_bloqueados.add(puerto_num)
        self.historico_interfaces[puerto_num] = puerto_ios
        print(
            f"{Fore.GREEN} [+] {puerto_ios} verificada administratively down."
            f"{Style.RESET_ALL}"
        )
        return True
