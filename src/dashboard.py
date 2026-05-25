"""
MÓDULO 6: Dashboard de Métricas DINÁMICO
Lee automáticamente los archivos JSONL generados por el agente SOAR.
"""

import argparse, sys, json
from datetime import datetime
try:
    import matplotlib.pyplot as plt
    import matplotlib.gridspec as gridspec
except ImportError:
    print("pip install matplotlib")
    sys.exit(1)

# Lee los archivos en vivo
def load_metrics():
    metrics = []
    try:
        with open("soar_metrics.jsonl", "r") as f:
            for line in f: metrics.append(json.loads(line.strip()))
    except FileNotFoundError:
        print("Falta soar_metrics.jsonl. ¡Corre el agente v4 primero!")
        sys.exit(1)
    return metrics

def load_events():
    events = []
    try:
        with open("soar_events.jsonl", "r") as f:
            for line in f: events.append(json.loads(line.strip()))
    except: pass
    return events

PALETTE = {"green": "#1D9E75", "red": "#D85A30", "amber": "#BA7517", "blue": "#378ADD", "gray": "#5F5E5A", "bg": "#F9F9F8", "text": "#2C2C2A", "grid": "#E8E8E5"}

def apply_style(ax, title, xlabel, ylabel):
    ax.set_facecolor(PALETTE["bg"])
    ax.set_title(title, fontsize=12, fontweight="bold", color=PALETTE["text"], pad=10)
    ax.set_xlabel(xlabel, fontsize=10, color=PALETTE["gray"])
    ax.set_ylabel(ylabel, fontsize=10, color=PALETTE["gray"])
    ax.grid(True, color=PALETTE["grid"], linestyle="--")
    ax.spines[["top", "right"]].set_visible(False)

def plot_mac_rate_timeline(metrics, events, ax):
    times = [m["ts"] for m in metrics]
    rates = [m["rate"] for m in metrics]
    ax.fill_between(times, rates, alpha=0.2, color=PALETTE["blue"])
    ax.plot(times, rates, color=PALETTE["blue"], linewidth=1.5)
    ax.axhline(25, color=PALETTE["amber"], linestyle="--", label="Umbral 25 MACs/s")

    if events:
        t_resp = events[0]["ts"]
        ax.axvline(t_resp, color=PALETTE["green"], linewidth=2)
        ax.annotate("Bloqueo Automático", xy=(t_resp, max(rates)*0.8), fontsize=10, fontweight="bold", color=PALETTE["green"])
    
    apply_style(ax, "Tasa de Inyección — Puerto Atacante", "Segundos", "MACs de golpe")

def plot_cam_table_size(metrics, events, ax):
    times = [m["ts"] for m in metrics]
    totals = [m["total_macs"] for m in metrics]
    ax.fill_between(times, totals, alpha=0.15, color=PALETTE["red"])
    ax.plot(times, totals, color=PALETTE["red"], linewidth=1.5)

    if events:
        t_resp = events[0]["ts"]
        ax.axvline(t_resp, color=PALETTE["green"], linewidth=2)
        ax.annotate(f"Pico: {max(totals)} MACs", xy=(t_resp, max(totals)), color=PALETTE["red"], fontweight="bold")

    apply_style(ax, "Saturación de Memoria CAM", "Segundos", "MACs totales")

def plot_response_comparison(events, ax):
    soar_ms = events[0]["total_ms"] if events else 0
    manual_ms = 900_000 
    bars = ax.bar(["Intervención Humana", "Agente SOAR v4"], [manual_ms, soar_ms], color=[PALETTE["red"], PALETTE["green"]], width=0.5)
    
    if soar_ms > 0:
        red = round((1 - soar_ms / manual_ms) * 100, 2)
        ax.annotate(f"KPI: {red}% Reducción", xy=(0.5, 10000), fontsize=12, fontweight="bold", color=PALETTE["green"], ha="center", bbox=dict(fc="white", ec=PALETTE["green"]))
        ax.text(bars[1].get_x() + bars[1].get_width()/2, bars[1].get_height()*1.1, f"{soar_ms} ms", ha="center", fontweight="bold", color=PALETTE["green"])

    apply_style(ax, "Eficiencia: Humano vs SOAR", "Método", "ms (log)")
    ax.set_yscale("log")
    ax.set_ylim(bottom=100)

def plot_response_breakdown(events, ax):
    if not events: return
    ev = events[0]
    total = ev["total_ms"]
    phases = {"SSH/SNMP": total - ev["shutdown_ms"] - ev["acl_ms"], "Shutdown": ev["shutdown_ms"], "ACL": ev["acl_ms"]}
    
    ax.pie(phases.values(), labels=phases.keys(), autopct="%1.0f%%", colors=[PALETTE["blue"], PALETTE["amber"], PALETTE["green"]], startangle=140, wedgeprops=dict(width=0.5, edgecolor="white"))
    ax.set_title("Desglose de Mitigación", fontweight="bold", color=PALETTE["text"])
    ax.text(0, -1.3, f"Total: {total} ms", ha="center", fontweight="bold", color=PALETTE["green"])

def generate_dashboard(show=False):
    metrics, events = load_metrics(), load_events()
    if not metrics: return

    fig = plt.figure(figsize=(16, 9), facecolor="white")
    gs = gridspec.GridSpec(2, 2, figure=fig, hspace=0.35, wspace=0.25)

    plot_mac_rate_timeline(metrics, events, fig.add_subplot(gs[0, 0]))
    plot_cam_table_size(metrics, events, fig.add_subplot(gs[0, 1]))
    plot_response_comparison(events, fig.add_subplot(gs[1, 0]))
    plot_response_breakdown(events, fig.add_subplot(gs[1, 1]))

    out_path = f"Dashboard_Dinamico_{datetime.now().strftime('%H%M%S')}.png"
    fig.savefig(out_path, dpi=300, bbox_inches="tight")
    print(f"\n¡Dashboard generado con datos reales! -> {out_path}")
    if show: plt.show()
    plt.close()

if __name__ == "__main__":
    generate_dashboard(show=True)