#!/usr/bin/env python3
"""plot_lb_bench.py — graficos do benchmark Q3 do LB de links WAN (2 links,
topologia simples ns1/ns2 -> nssw -> nsp1/nsp2 -> nsext): throughput agregado
e indice de justica de Jain, comparando ate 3 series (ECMP do kernel e ate
duas versoes do LB XDP — ex.: antes/depois de uma refatoracao do hash de
fluxo) em funcao do numero de fluxos TCP paralelos.

Le os arquivos gerados por run_lb_bench.sh em ate 3 diretorios de
resultados: tcp_P{p}_r{rep}.json (iperf3) e links_P{p}_r{rep}_after.txt
(modo xdp, saida de `xdpunk-cli lb status`) ou
links_P{p}_r{rep}_{before,after}.txt (modo baseline, `ip -s -j link show`
antes/depois — contadores cumulativos, a distribuicao e a diferenca).

Paleta segue a skill `dataviz` (references/palette.md): categorias sao
identidade de mecanismo (nao ordinal), entao usam slots fixos da ordem
categorica validada — slot 1 azul para "XDP depois", slot 2 laranja para
"ECMP (kernel)" (mesmo mapeamento de plot_lb_chain_bench.py, ja validado
nesta base) e slot 3 aqua para "XDP antes", quando presente.

Uso:
    python3 plot_lb_bench.py --after DIR [--before DIR] [--baseline DIR] \\
        [--reps N] [--out-dir DIR]

Pelo menos um de --after/--before deve ser passado junto com --baseline
para uma comparacao com 2 series, ou os tres para 3 series.
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

# Slots categoricos 1 (azul), 2 (laranja) e 3 (aqua) da ordem fixa validada
# da skill dataviz. Mesmo mapeamento XDP=azul / ECMP=laranja usado em
# plot_lb_chain_bench.py, para que a leitura de cor seja consistente entre
# os dois conjuntos de graficos deste projeto.
COLOR_AFTER = "#2a78d6"    # slot 1 — XDP depois da refatoracao (ou unica versao XDP)
COLOR_BASELINE = "#eb6834"  # slot 2 — ECMP do kernel
COLOR_BEFORE = "#1baf7a"    # slot 3 — XDP antes da refatoracao

WAN_IFACES = ("vethw1s", "vethw2s")


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
    path = results_dir / f"links_P{p}_r{rep}_after.txt"
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
    before_path = results_dir / f"links_P{p}_r{rep}_before.txt"
    after_path = results_dir / f"links_P{p}_r{rep}_after.txt"
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
    if not present:
        return
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


def _series_layout(series):
    """Larguras/offsets centrados para 2 ou 3 series lado a lado."""
    n = len(series)
    width = 0.72 / n
    start = -0.5 * width * (n - 1)
    return width, [start + i * width for i in range(n)]


def plot_metric(series, out_path: Path, ylabel, title, ylim=None, hline=None,
                 legend_loc="upper left"):
    fig, ax = plt.subplots(figsize=(7, 5), dpi=150)
    fig.patch.set_facecolor(SURFACE)
    ax.set_facecolor(SURFACE)

    width, offsets = _series_layout(series)
    for (label, color, values_by_p), offset in zip(series, offsets):
        _bar_with_error(ax, values_by_p, color, label, width, offset)

    ax.set_xticks(np.arange(len(STREAMS)))
    ax.set_xticklabels([f"P={p}" for p in STREAMS], color=INK_SECONDARY)

    if hline is not None:
        ax.axhline(hline, color=INK_MUTED, linewidth=1, linestyle="--", zorder=1)

    _style_axes(ax, ylabel, title)

    if ylim is not None:
        ax.set_ylim(*ylim)
    else:
        all_values = [v for _, _, vs in series for lst in vs.values() for v in lst]
        if all_values:
            ax.set_ylim(0, max(all_values) * 1.25)

    ax.legend(loc=legend_loc, ncol=len(series) if legend_loc == "upper center" else 1,
              frameon=False, labelcolor=INK_SECONDARY, fontsize=9)

    fig.tight_layout()
    fig.savefig(out_path, facecolor=fig.get_facecolor())
    plt.close(fig)
    print(f"Gerado: {out_path}")


def main():
    parser = argparse.ArgumentParser(description=__doc__,
                                      formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--after", type=Path, required=True,
                         help="Diretorio de resultados XDP (versao atual / depois)")
    parser.add_argument("--before", type=Path, default=None,
                         help="Diretorio de resultados XDP anterior, para comparacao de 3 series")
    parser.add_argument("--baseline", type=Path, required=True,
                         help="Diretorio de resultados do ECMP nativo (kernel)")
    parser.add_argument("--reps", type=int, default=10)
    parser.add_argument("--out-dir", type=Path, default=None)
    args = parser.parse_args()

    dirs = [args.after, args.baseline] + ([args.before] if args.before else [])
    for d in dirs:
        if not d.is_dir():
            print(f"Erro: '{d}' nao e um diretorio.", file=sys.stderr)
            sys.exit(1)

    out_dir = args.out_dir or args.after
    out_dir.mkdir(parents=True, exist_ok=True)

    after_tput, after_fair = collect(args.after, args.reps, xdp_link_bytes)
    baseline_tput, baseline_fair = collect(args.baseline, args.reps, baseline_link_bytes)

    tput_series = [
        ("ECMP (kernel)", COLOR_BASELINE, baseline_tput),
    ]
    fair_series = [
        ("ECMP (kernel)", COLOR_BASELINE, baseline_fair),
    ]

    if args.before:
        before_tput, before_fair = collect(args.before, args.reps, xdp_link_bytes)
        tput_series.append(("XDP antes", COLOR_BEFORE, before_tput))
        fair_series.append(("XDP antes", COLOR_BEFORE, before_fair))

    tput_series.append(("XDP depois" if args.before else "XDP", COLOR_AFTER, after_tput))
    fair_series.append(("XDP depois" if args.before else "XDP", COLOR_AFTER, after_fair))

    plot_metric(
        tput_series, out_dir / "lb_throughput.png",
        "Throughput agregado (Gbit/s)",
        "LB de links WAN — throughput vs fluxos paralelos",
        legend_loc="upper left",
    )
    plot_metric(
        fair_series, out_dir / "lb_fairness.png",
        "Índice de justiça de Jain (bytes por link WAN)",
        "LB de links WAN — justiça da distribuição vs fluxos paralelos",
        ylim=(0, 1.22), hline=1.0, legend_loc="upper center",
    )


if __name__ == "__main__":
    main()
