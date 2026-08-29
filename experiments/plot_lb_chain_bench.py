#!/usr/bin/env python3
"""plot_lb_chain_bench.py — graficos do benchmark Q1 do LB encadeado
(A-R1-{R2,R3}-R4-B): throughput agregado e indice de justica de Jain,
XDP-chain vs baseline ECMP-chain, em funcao do numero de fluxos
paralelos.

Le os arquivos gerados por run_lb_chain_bench.sh em dois diretorios de
resultados (um por modo): tcp_P{p}_r{rep}.json (iperf3) e
links_P{p}_r{rep}_after_r1.{txt,json} (contadores por link WAN em R1 —
a distribuicao de R4 no caminho de volta fica fora do escopo deste
grafico, ja que os dados TCP medidos fluem majoritariamente A->B).

Paleta segue a skill `dataviz`: XDP e ECMP sao duas categorias (mecanismos
distintos, nao uma escala ordinal), entao usam os slots categoricos 1
(azul) e 2 (laranja) da ordem fixa validada em references/palette.md, em
vez de dois tons do mesmo azul. Tokens de tinta/grade/superficie seguem
plot_fw_capacity.py (ja validado nesta base) para consistencia visual.

Uso:
    python3 plot_lb_chain_bench.py <xdp_results_dir> <baseline_results_dir> \\
        [--reps N] [--out-dir DIR]
"""
import argparse
import json
import sys
from pathlib import Path

import matplotlib

matplotlib.use("Agg")
import matplotlib.pyplot as plt
import numpy as np

STREAMS = [2, 4, 8, 16]

INK_PRIMARY = "#0b0b0b"
INK_SECONDARY = "#52514e"
INK_MUTED = "#898781"
GRIDLINE = "#e1e0d9"
AXIS_BASELINE = "#c3c2b7"
SURFACE = "#fcfcfb"

# Slots categoricos 1 (azul) e 2 (laranja) da ordem fixa validada da
# skill dataviz — identidade de mecanismo (XDP vs kernel), nao magnitude.
XDP_COLOR = "#2a78d6"
BASELINE_COLOR = "#eb6834"

WAN_IFACES = ("vethR12", "vethR13")  # links WAN de R1 na topologia encadeada


def throughput_gbps(results_dir: Path, p: int, rep: int):
    path = results_dir / f"tcp_P{p}_r{rep}.json"
    if not path.exists():
        return None
    with open(path) as f:
        data = json.load(f)
    return data["end"]["sum_received"]["bits_per_second"] / 1e9


def jain_index(byte_counts):
    """J = (sum b_i)^2 / (n * sum b_i^2); 1.0 = perfeitamente justo."""
    arr = np.asarray(byte_counts, dtype=float)
    if arr.sum() == 0:
        return float("nan")
    n = len(arr)
    return (arr.sum() ** 2) / (n * np.sum(arr ** 2))


def xdp_link_bytes(results_dir: Path, p: int, rep: int):
    path = results_dir / f"links_P{p}_r{rep}_after_r1.txt"
    if not path.exists():
        return None
    counts = []
    for line in path.read_text().splitlines():
        tokens = line.split()
        if len(tokens) < 3 or not tokens[0].isdigit():
            continue
        counts.append(int(tokens[-2]))  # coluna BYTES (penultima)
    return counts or None


def _iface_tx_bytes(snapshot, iface):
    for entry in snapshot:
        if entry.get("ifname") == iface:
            return entry.get("stats64", {}).get("tx", {}).get("bytes", 0)
    return None


def baseline_link_bytes(results_dir: Path, p: int, rep: int):
    before_path = results_dir / f"links_P{p}_r{rep}_before_r1.json"
    after_path = results_dir / f"links_P{p}_r{rep}_after_r1.json"
    if not before_path.exists() or not after_path.exists():
        return None
    before = json.loads(before_path.read_text())
    after = json.loads(after_path.read_text())
    counts = []
    for iface in WAN_IFACES:
        b = _iface_tx_bytes(before, iface)
        a = _iface_tx_bytes(after, iface)
        if b is None or a is None:
            return None
        counts.append(a - b)
    return counts


def collect(results_dir: Path, reps: int, link_bytes_fn):
    throughput_by_p, fairness_by_p = {}, {}
    for p in STREAMS:
        tputs, fairness = [], []
        for rep in range(1, reps + 1):
            t = throughput_gbps(results_dir, p, rep)
            if t is not None:
                tputs.append(t)
            counts = link_bytes_fn(results_dir, p, rep)
            if counts:
                fairness.append(jain_index(counts))
        if not tputs:
            print(f"Aviso: nenhum dado de throughput para P={p} em "
                  f"{results_dir}.", file=sys.stderr)
            continue
        throughput_by_p[p] = tputs
        fairness_by_p[p] = fairness
    return throughput_by_p, fairness_by_p


def _bar_with_error(ax, values_by_p, color, label, width, offset):
    present = [p for p in STREAMS if p in values_by_p]
    xs = np.array([STREAMS.index(p) for p in present]) + offset
    means = [np.mean(values_by_p[p]) for p in present]
    stds = [np.std(values_by_p[p], ddof=1) if len(values_by_p[p]) > 1 else 0.0
            for p in present]
    ax.bar(
        xs, means, width=width, color=color, label=label,
        yerr=stds, capsize=4,
        error_kw={"ecolor": INK_SECONDARY, "elinewidth": 1.2, "capthick": 1.2},
        zorder=2,
    )


def _style_axes(ax, ylabel, title):
    ax.set_ylabel(ylabel, color=INK_SECONDARY)
    ax.set_title(title, color=INK_PRIMARY, fontsize=13, fontweight="bold", pad=14)
    ax.yaxis.grid(True, color=GRIDLINE, linewidth=1, zorder=0)
    ax.set_axisbelow(True)
    for spine in ("top", "right", "left"):
        ax.spines[spine].set_visible(False)
    ax.spines["bottom"].set_color(AXIS_BASELINE)
    ax.tick_params(axis="both", colors=INK_MUTED, length=0)


def plot_throughput(xdp_tput, baseline_tput, out_dir: Path):
    fig, ax = plt.subplots(figsize=(7, 5), dpi=150)
    fig.patch.set_facecolor(SURFACE)
    ax.set_facecolor(SURFACE)

    _bar_with_error(ax, xdp_tput, XDP_COLOR, "XDP (encadeado)", 0.35, -0.19)
    _bar_with_error(ax, baseline_tput, BASELINE_COLOR, "ECMP (kernel)", 0.35, 0.19)

    ax.set_xticks(np.arange(len(STREAMS)))
    ax.set_xticklabels([f"P={p}" for p in STREAMS], color=INK_SECONDARY)
    _style_axes(ax, "Throughput agregado (Gbit/s)",
                "LB encadeado — throughput vs fluxos paralelos")

    # Headroom no topo do eixo para a legenda nao sobrepor a barra mais
    # alta, qualquer que seja a relacao entre os grupos populados.
    all_values = [v for series in (xdp_tput, baseline_tput) for vs in series.values() for v in vs]
    if all_values:
        ax.set_ylim(0, max(all_values) * 1.25)
    ax.legend(loc="upper left", frameon=False, labelcolor=INK_SECONDARY, fontsize=9)

    fig.tight_layout()
    out_path = out_dir / "lb_chain_throughput.png"
    fig.savefig(out_path, facecolor=fig.get_facecolor())
    plt.close(fig)
    print(f"Gerado: {out_path}")


def plot_fairness(xdp_fair, baseline_fair, out_dir: Path):
    fig, ax = plt.subplots(figsize=(7, 5), dpi=150)
    fig.patch.set_facecolor(SURFACE)
    ax.set_facecolor(SURFACE)

    _bar_with_error(ax, xdp_fair, XDP_COLOR, "XDP (encadeado)", 0.35, -0.19)
    _bar_with_error(ax, baseline_fair, BASELINE_COLOR, "ECMP (kernel)", 0.35, 0.19)

    ax.set_xticks(np.arange(len(STREAMS)))
    ax.set_xticklabels([f"P={p}" for p in STREAMS], color=INK_SECONDARY)
    ax.set_ylim(0, 1.15)
    ax.axhline(1.0, color=INK_MUTED, linewidth=1, linestyle="--", zorder=1)
    _style_axes(ax, "Índice de justiça de Jain (bytes por link em R1)",
                "LB encadeado — justiça da distribuição vs fluxos paralelos")
    ax.legend(loc="lower right", frameon=False, labelcolor=INK_SECONDARY, fontsize=9)

    fig.tight_layout()
    out_path = out_dir / "lb_chain_fairness.png"
    fig.savefig(out_path, facecolor=fig.get_facecolor())
    plt.close(fig)
    print(f"Gerado: {out_path}")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("xdp_results_dir", type=Path)
    parser.add_argument("baseline_results_dir", type=Path)
    parser.add_argument("--reps", type=int, default=10)
    parser.add_argument("--out-dir", type=Path, default=None)
    args = parser.parse_args()

    for d in (args.xdp_results_dir, args.baseline_results_dir):
        if not d.is_dir():
            print(f"Erro: '{d}' nao e um diretorio.", file=sys.stderr)
            sys.exit(1)

    out_dir = args.out_dir or args.xdp_results_dir
    out_dir.mkdir(parents=True, exist_ok=True)

    xdp_tput, xdp_fair = collect(args.xdp_results_dir, args.reps, xdp_link_bytes)
    baseline_tput, baseline_fair = collect(
        args.baseline_results_dir, args.reps, baseline_link_bytes)

    plot_throughput(xdp_tput, baseline_tput, out_dir)
    plot_fairness(xdp_fair, baseline_fair, out_dir)


if __name__ == "__main__":
    main()
