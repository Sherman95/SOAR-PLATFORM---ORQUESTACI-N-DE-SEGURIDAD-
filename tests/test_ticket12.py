"""Riesgos principales del agente cubiertos con pytest y mocks."""

import sys
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import Mock


ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / "src"
sys.path[:0] = [str(ROOT), str(SRC)]

from agent import SOARAgent
from campaign import _descriptive
from config.settings import PROTECTED_INTERFACES
from detector import (
    CamMonitorState,
    CamReadResult,
    Detector,
    InterfaceIdentity,
    OID_BASE_PORT_IFINDEX,
    OID_FDB_PORT,
    OID_IF_NAME,
    calcular_tasa_mac,
)
from mitigador import Mitigador


def test_timeout_snmp_no_borra_baseline():
    state = CamMonitorState()
    baseline = {3: {"00:00:00:00:00:01"}}
    state.observe(CamReadResult(True, baseline, 1.0), 1_000_000_000)

    result = state.observe(
        CamReadResult(False, {}, 2000.0, "timeout", "sin respuesta"),
        2_000_000_000,
    )

    assert result is None
    assert state.last_valid_entries == baseline


def test_recuperacion_snmp_no_genera_ataque_falso():
    state = CamMonitorState()
    baseline = {3: {"00:00:00:00:00:01"}}
    state.observe(CamReadResult(True, baseline, 1.0), 1_000_000_000)
    state.observe(
        CamReadResult(False, {}, 2000.0, "timeout", "sin respuesta"),
        2_000_000_000,
    )

    comparison = state.observe(
        CamReadResult(True, baseline, 1.0), 3_000_000_000
    )
    new_mac_count = len(
        comparison.current_entries[3] - comparison.previous_entries[3]
    )

    assert comparison.recovered_after_failures == 1
    assert calcular_tasa_mac(new_mac_count, comparison.elapsed_since_valid) == 0


def test_mapeo_bridge_port_a_interfaz_con_mock():
    detector = Detector(None, {})

    def walk(oid):
        return {
            OID_FDB_PORT: [(f"{OID_FDB_PORT}.0.1.2.3.4.5", "4")],
            OID_BASE_PORT_IFINDEX: [(f"{OID_BASE_PORT_IFINDEX}.4", "44")],
            OID_IF_NAME: [(f"{OID_IF_NAME}.44", "Ethernet0/3")],
        }[oid]

    detector._snmp_walk = Mock(side_effect=walk)
    result = detector.leer_cam()

    assert result.success
    assert detector.resolver_interfaz(4) == InterfaceIdentity(
        bridge_port=4, if_index=44, if_name="Ethernet0/3"
    )


def _agent_for_resolution(identity):
    agent = SOARAgent.__new__(SOARAgent)
    agent.detector = SimpleNamespace(resolver_interfaz=Mock(return_value=identity))
    agent.reporter = SimpleNamespace(registrar_alerta=Mock())
    agent.mitigador = SimpleNamespace(bloqueados=set())
    agent.threshold_mac_per_second = 50
    return agent


def test_interfaz_desconocida_no_se_bloquea():
    agent = _agent_for_resolution(None)

    assert agent._resolver_objetivo(99, 200) is None
    agent.reporter.registrar_alerta.assert_called_once()


def test_puerto_protegido_no_se_bloquea():
    assert PROTECTED_INTERFACES == {"Ethernet0/0", "Ethernet1/0"}
    identity = InterfaceIdentity(bridge_port=1, if_index=1, if_name="Ethernet0/0")
    agent = _agent_for_resolution(identity)

    assert agent._resolver_objetivo(1, 200) is None


def test_fallo_ssh_no_se_registra_como_exito():
    network = SimpleNamespace(
        esta_vivo=Mock(return_value=False),
        config=Mock(side_effect=AssertionError("no debe configurar sin SSH")),
    )
    reporter = SimpleNamespace(registrar_evento=Mock())
    mitigador = Mitigador(network, reporter)

    success = mitigador.bloquear_mac_flood(
        4,
        "Ethernet0/3",
        if_index=4,
        new_mac_count=200,
        threshold_mac_per_second=50,
    )

    assert success is False
    event = reporter.registrar_evento.call_args.kwargs
    assert event["mitigation_success"] is False
    assert event["verification_status"] == "ssh_unavailable"
    network.config.assert_not_called()


def test_calculo_correcto_mac_por_segundo():
    assert calcular_tasa_mac(50, 2.0) == 25.0
    assert calcular_tasa_mac(50, 0.5) == 100.0


def test_media_y_desviacion_estandar_muestral():
    values = _descriptive([1.0, 2.0, 3.0])
    assert values["mean"] == 2.0
    assert values["standard_deviation"] == 1.0
    assert values["median"] == 2.0
    assert values["minimum"] == 1.0
    assert values["maximum"] == 3.0
