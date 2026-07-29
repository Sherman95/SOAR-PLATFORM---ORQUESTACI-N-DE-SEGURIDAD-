"""Dashboard de la evidencia asociada a una ejecución MAC Flooding."""

import argparse
import sys, json, os
from datetime import datetime
from collections import Counter

try:
    import matplotlib.pyplot as plt
    import matplotlib.gridspec as gridspec
except ImportError:
    print("pip install matplotlib")
    sys.exit(1)

# ─── Rutas correctas ──────────────────────────────────────────
BASE_DIR     = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
sys.path.insert(0, BASE_DIR)
from config.version import VERSION_LABEL
EXPERIMENT_ROOT = os.path.join(
    BASE_DIR, "data", "experiments", "mac_flooding_validation"
)

PALETTE = {
    "green": "#1D9E75", "red": "#D85A30", "amber": "#BA7517",
    "blue":  "#378ADD", "gray": "#5F5E5A", "purple": "#7B5EA7",
    "bg":    "#F9F9F8", "text": "#2C2C2A", "grid": "#E8E8E5",
}

ACCION_COLOR = {
    "SHUTDOWN": PALETTE["red"],
}

MAC_ACTIONS = {"SHUTDOWN"}


def is_mac_event(event):
    """Excluye eventos historicos ajenos al alcance MAC validado."""
    return (
        event.get("accion") in MAC_ACTIONS
        and event.get("mitigation_success") is True
    )


# ─── Carga de datos ───────────────────────────────────────────
def resolve_run_dir(run_id=None):
    if not os.path.isdir(EXPERIMENT_ROOT):
        print("[!] No existen ejecuciones experimentales.")
        sys.exit(1)
    if run_id:
        run_dir = os.path.join(EXPERIMENT_ROOT, run_id)
        if not os.path.isdir(run_dir):
            print(f"[!] Ejecucion no encontrada: {run_id}")
            sys.exit(1)
        return run_dir
    runs = sorted(
        entry.path for entry in os.scandir(EXPERIMENT_ROOT)
        if entry.is_dir() and entry.name.startswith("run_")
    )
    if not runs:
        print("[!] No existen ejecuciones experimentales.")
        sys.exit(1)
    return runs[-1]


def load_metrics(run_dir):
    metrics = []
    snapshots_file = os.path.join(run_dir, "cam_snapshots.jsonl")
    if not os.path.exists(snapshots_file):
        print(f"[!] No encontrado: {snapshots_file}")
        print("    Corre el agente primero (opción [1] del menú).")
        sys.exit(1)
    with open(snapshots_file, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if line:
                try:
                    snapshot = json.loads(line)
                    if snapshot.get("success") and snapshot.get("rate") is not None:
                        metrics.append(snapshot)
                except Exception:
                    pass
    if not metrics:
        print(f"[!] Sin capturas CAM válidas en: {snapshots_file}")
        sys.exit(1)
    return metrics


def load_events(run_dir):
    events = []
    events_file = os.path.join(run_dir, "events.jsonl")
    if not os.path.exists(events_file):
        return events
    with open(events_file, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if line:
                try:
                    event = json.loads(line)
                    if is_mac_event(event):
                        events.append(event)
                except Exception:
                    pass
    return events


def to_seconds(metrics):
    """Convierte timestamps ISO a segundos relativos al primer punto."""
    t0 = datetime.fromisoformat(metrics[0]["ts"])
    return [(datetime.fromisoformat(m["ts"]) - t0).total_seconds() for m in metrics]


def ts_to_seconds(ts_iso, t0):
    return (datetime.fromisoformat(ts_iso) - t0).total_seconds()


# ─── Gráficas ─────────────────────────────────────────────────
def apply_style(ax, title, xlabel, ylabel):
    ax.set_facecolor(PALETTE["bg"])
    ax.set_title(title, fontsize=11, fontweight="bold",
                 color=PALETTE["text"], pad=10)
    ax.set_xlabel(xlabel, fontsize=9, color=PALETTE["gray"])
    ax.set_ylabel(ylabel, fontsize=9, color=PALETTE["gray"])
    ax.grid(True, color=PALETTE["grid"], linestyle="--", alpha=0.7)
    ax.spines[["top", "right"]].set_visible(False)
    ax.tick_params(colors=PALETTE["gray"])


def plot_mac_rate(metrics, events, ax):
    """Mayor tasa de MACs nuevas por segundo observada en un puerto."""
    secs  = to_seconds(metrics)
    rates = [m["rate"] for m in metrics]
    t0    = datetime.fromisoformat(metrics[0]["ts"])

    ax.fill_between(secs, rates, alpha=0.2, color=PALETTE["blue"])
    ax.plot(secs, rates, color=PALETTE["blue"], linewidth=1.5, label="MACs/segundo")
    ax.axhline(50, color=PALETTE["amber"], linestyle="--",
               linewidth=1, label="Umbral detección (50 MAC/s)")

    # Marcar eventos de MAC flood
    for ev in events:
        t = ts_to_seconds(ev["ts"], t0)
        ax.axvline(t, color=PALETTE["green"], linewidth=2)
        ax.annotate("🛡 Bloqueo", xy=(t, max(rates) * 0.85),
                    fontsize=9, fontweight="bold",
                    color=PALETTE["green"], ha="left")

    ax.legend(fontsize=8)
    apply_style(ax, "Pico de Inyección MAC por Puerto",
                "Tiempo (s)", "MACs nuevas / segundo")


def plot_cam_size(metrics, events, ax):
    """Total de MACs en la tabla CAM del switch."""
    secs   = to_seconds(metrics)
    totals = [m["total_macs"] for m in metrics]
    t0     = datetime.fromisoformat(metrics[0]["ts"])
    pico   = max(totals) if totals else 0

    ax.fill_between(secs, totals, alpha=0.15, color=PALETTE["red"])
    ax.plot(secs, totals, color=PALETTE["red"], linewidth=1.5)

    if pico > 0:
        idx = totals.index(pico)
        ax.annotate(f"Pico: {pico} MACs",
                    xy=(secs[idx], pico),
                    xytext=(secs[idx] + 1, pico * 0.95),
                    fontsize=9, fontweight="bold", color=PALETTE["red"],
                    arrowprops=dict(arrowstyle="->", color=PALETTE["red"]))

    for ev in events:
        t = ts_to_seconds(ev["ts"], t0)
        ax.axvline(t, color=PALETTE["green"], linewidth=2)

    apply_style(ax, "Saturación Tabla CAM del Switch",
                "Tiempo (s)", "Total MACs en memoria")


def plot_timing_breakdown(events, ax):
    """Muestra fases medidas, sin estimaciones ni porcentajes inventados."""
    if not events:
        ax.text(0.5, 0.5, "Sin mitigación verificada",
                transform=ax.transAxes, ha="center", fontsize=11,
                color=PALETTE["gray"])
        apply_style(ax, "Tiempo Experimental", "Fase", "Tiempo (ms)")
        return

    event = events[-1]
    keys = ["snmp_read_ms", "analysis_ms", "ssh_command_ms", "verification_ms"]
    labels = ["Lectura\nSNMP", "Análisis", "Comando\nSSH", "Verificación"]
    values = [event.get(key, 0) for key in keys]
    bars = ax.bar(labels, values, color=[
        PALETTE["blue"], PALETTE["amber"], PALETTE["red"], PALETTE["green"]
    ])
    for bar, value in zip(bars, values):
        ax.text(bar.get_x() + bar.get_width() / 2, bar.get_height(),
                f"{value:.3f}", ha="center", va="bottom", fontsize=8)
    ax.text(
        0.98, 0.95,
        f"End-to-end: {event.get('end_to_end_ms', 0):.3f} ms",
        transform=ax.transAxes, ha="right", va="top", fontweight="bold",
        color=PALETTE["green"],
    )
    apply_style(ax, "Desglose del Tiempo Experimental", "Fase", "Tiempo (ms)")


def plot_event_distribution(events, ax):
    """Distribución de tipos de mitigación aplicados."""
    if not events:
        ax.text(0.5, 0.5, "Sin eventos de mitigación\nen esta sesión",
                transform=ax.transAxes, ha="center", va="center",
                fontsize=12, color=PALETTE["gray"])
        ax.set_title("Distribución de Mitigaciones", fontweight="bold",
                     color=PALETTE["text"])
        ax.axis("off")
        return

    conteo = Counter(e.get("accion", "OTRO") for e in events)
    labels = list(conteo.keys())
    sizes  = list(conteo.values())
    colors = [ACCION_COLOR.get(l, PALETTE["blue"]) for l in labels]

    # Etiquetas legibles
    label_map = {
        "SHUTDOWN": "Shutdown verificado\n(MAC Flood)",
    }
    labels_display = [label_map.get(l, l) for l in labels]

    wedges, texts, autotexts = ax.pie(
        sizes, labels=labels_display, autopct="%1.0f%%",
        colors=colors, startangle=140,
        wedgeprops=dict(width=0.55, edgecolor="white"),
        textprops=dict(fontsize=8))

    for at in autotexts:
        at.set_fontweight("bold")
        at.set_fontsize(9)

    # Total en el centro
    total = sum(sizes)
    ax.text(0, 0, f"{total}\neventos", ha="center", va="center",
            fontsize=11, fontweight="bold", color=PALETTE["text"])

    ax.set_title("Distribución de Mitigaciones", fontweight="bold",
                 color=PALETTE["text"])


# ─── Generación del dashboard ─────────────────────────────────
def generate_dashboard(show=False, run_id=None):
    run_dir = resolve_run_dir(run_id)
    run_id = os.path.basename(run_dir)
    metrics = load_metrics(run_dir)
    events  = load_events(run_dir)

    os.makedirs(run_dir, exist_ok=True)

    fig = plt.figure(figsize=(16, 9), facecolor="white")
    fig.suptitle(
        f"SOAR Agent {VERSION_LABEL} — Dashboard MAC Flooding | {run_id}\n"
        f"Generado: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')} | "
        f"Muestras: {len(metrics)} | Eventos: {len(events)}",
        fontsize=11, color=PALETTE["text"], y=0.98)

    gs = gridspec.GridSpec(2, 2, figure=fig, hspace=0.38, wspace=0.28,
                           left=0.07, right=0.97, top=0.92, bottom=0.07)

    plot_mac_rate(metrics, events, fig.add_subplot(gs[0, 0]))
    plot_cam_size(metrics, events, fig.add_subplot(gs[0, 1]))
    plot_timing_breakdown(events, fig.add_subplot(gs[1, 0]))
    plot_event_distribution(events, fig.add_subplot(gs[1, 1]))

    nombre = "dashboard.png"
    ruta   = os.path.join(run_dir, nombre)
    fig.savefig(ruta, dpi=150, bbox_inches="tight", facecolor="white")
    print(f"\n[+] Dashboard guardado en: {ruta}")

    if show:
        plt.show()
    plt.close()


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--run-id")
    parser.add_argument("--no-show", action="store_true")
    args = parser.parse_args()
    generate_dashboard(show=not args.no_show, run_id=args.run_id)
