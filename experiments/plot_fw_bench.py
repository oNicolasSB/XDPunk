#!/usr/bin/env python3
"""plot_fw_bench.py — graficos do benchmark Q1/Q2 do firewall (5-tupla,
first-match): firewall stateless em XDP vs FORWARD/iptables do kernel,
comparando throughput TCP, taxa de pacotes UDP 64B e latencia (RTT) em
funcao do numero de regras carregadas N ∈ {0, 8, 16, 32, 64}.

Le os arquivos gerados por run_fw_bench.sh em dois diretorios de
resultados (um por modo): tcp_N{n}_r{rep}.json e udp64_N{n}_r{rep}.json
(iperf3, REPS repeticoes por N) e ping_N{n}.txt (uma unica execucao de
200 pacotes por N; media/mdev extraidos da linha de estatisticas do
`ping -q`).

Paleta e disposicao seguem o mesmo padrao de plot_lb_bench.py
(references/palette.md da skill dataviz): slot 1 azul para XDP, slot 2
laranja para o mecanismo nativo do kernel — aqui iptables/FORWARD no
lugar do ECMP, mesma leitura de cor mantida entre os dois conjuntos de
graficos deste projeto.

Uso:
    python3 plot_fw_bench.py --xdp DIR --baseline DIR \\
        [--reps N] [--out-dir DIR]
"""
import argparse
import json
import re
import sys
from pathlib import Path

import matplotlib

matplotlib.use("Agg")
import matplotlib.pyplot as plt
import numpy as np

RULE_COUNTS = [0, 8, 16, 32, 64]

INK_PRIMARY = "#0b0b0b"
INK_SECONDARY = "#52514e"
INK_MUTED = "#898781"
GRIDLINE = "#e1e0d9"
AXIS_BASELINE = "#c3c2b7"
SURFACE = "#fcfcfb"

# Mesmo mapeamento de cor de plot_lb_bench.py / plot_lb_chain_bench.py:
# slot 1 azul = XDP, slot 2 laranja = mecanismo nativo do kernel.
COLOR_XDP = "#2a78d6"
COLOR_BASELINE = "#eb6834"

_RTT_RE = re.compile(
    r"rtt min/avg/max/mdev = [\d.]+/([\d.]+)/[\d.]+/([\d.]+) ms"
)


def tcp_gbps(results_dir: Path, n: int, rep: int):
    path = results_dir / f"tcp_N{n}_r{rep}.json"
    if not path.exists():
        return None
    with open(path) as f:
        data = json.load(f)
    return data["end"]["sum_received"]["bits_per_second"] / 1e9


def udp_pps(results_dir: Path, n: int, rep: int, duration_s: float):
    path = results_dir / f"udp64_N{n}_r{rep}.json"
    if not path.exists():
        return None
    with open(path) as f:
        data = json.load(f)
    return data["end"]["sum"]["packets"] / duration_s


def ping_rtt_avg_mdev(results_dir: Path, n: int):
    path = results_dir / f"ping_N{n}.txt"
    if not path.exists():
        return None
    m = _RTT_RE.search(path.read_text())
    if not m:
        return None
    return float(m.group(1)), float(m.group(2))


def collect_reps(results_dir: Path, reps: int, value_fn):
    by_n = {}
    for n in RULE_COUNTS:
        values = [v for rep in range(1, reps + 1)
                  if (v := value_fn(results_dir, n, rep)) is not None]
        if not values:
            print(f"Aviso: nenhum dado para N={n} em {results_dir}.",
                  file=sys.stderr)
            continue
        by_n[n] = values
    return by_n


def collect_ping(results_dir: Path):
    by_n = {}
    for n in RULE_COUNTS:
        r = ping_rtt_avg_mdev(results_dir, n)
        if r is None:
            print(f"Aviso: sem estatisticas de ping para N={n} em "
                  f"{results_dir}.", file=sys.stderr)
            continue
        by_n[n] = r
    return by_n


def _bar_with_error(ax, values_by_n, color, label, width, offset):
    """values_by_n: dict N -> lista de amostras (media/desvio calculados)."""
    present = [n for n in RULE_COUNTS if n in values_by_n]
    if not present:
        return
    xs = np.array([RULE_COUNTS.index(n) for n in present]) + offset
    means = [np.mean(values_by_n[n]) for n in present]
    stds = [np.std(values_by_n[n], ddof=1) if len(values_by_n[n]) > 1 else 0.0
            for n in present]
    ax.bar(
        xs, means, width=width, color=color, label=label,
        yerr=stds, capsize=4,
        error_kw={"ecolor": INK_SECONDARY, "elinewidth": 1.2, "capthick": 1.2},
        zorder=2,
    )
    return means, stds


def _bar_with_explicit_error(ax, mean_err_by_n, color, label, width, offset):
    """mean_err_by_n: dict N -> (media, erro) ja calculados (ex.: mdev)."""
    present = [n for n in RULE_COUNTS if n in mean_err_by_n]
    if not present:
        return
    xs = np.array([RULE_COUNTS.index(n) for n in present]) + offset
    means = [mean_err_by_n[n][0] for n in present]
    errs = [mean_err_by_n[n][1] for n in present]
    ax.bar(
        xs, means, width=width, color=color, label=label,
        yerr=errs, capsize=4,
        error_kw={"ecolor": INK_SECONDARY, "elinewidth": 1.2, "capthick": 1.2},
        zorder=2,
    )
    return means, errs


def _style_axes(ax, ylabel, title):
    ax.set_ylabel(ylabel, color=INK_SECONDARY)
    ax.set_title(title, color=INK_PRIMARY, fontsize=13, fontweight="bold", pad=14)
    ax.yaxis.grid(True, color=GRIDLINE, linewidth=1, zorder=0)
    ax.set_axisbelow(True)
    for spine in ("top", "right", "left"):
        ax.spines[spine].set_visible(False)
    ax.spines["bottom"].set_color(AXIS_BASELINE)
    ax.tick_params(axis="both", colors=INK_MUTED, length=0)


def plot_reps_metric(xdp_by_n, baseline_by_n, out_path: Path, ylabel, title):
    fig, ax = plt.subplots(figsize=(7, 5), dpi=150)
    fig.patch.set_facecolor(SURFACE)
    ax.set_facecolor(SURFACE)

    width = 0.32
    tops = []
    r = _bar_with_error(ax, baseline_by_n, COLOR_BASELINE, "iptables (kernel)",
                         width, -0.5 * width)
    if r:
        tops.extend(m + s for m, s in zip(*r))
    r = _bar_with_error(ax, xdp_by_n, COLOR_XDP, "XDP", width, 0.5 * width)
    if r:
        tops.extend(m + s for m, s in zip(*r))

    ax.set_xticks(np.arange(len(RULE_COUNTS)))
    ax.set_xticklabels([f"N={n}" for n in RULE_COUNTS], color=INK_SECONDARY)
    _style_axes(ax, ylabel, title)
    ax.set_ylim(0, max(tops) * 1.25 if tops else 1)
    ax.legend(loc="upper right", frameon=False, labelcolor=INK_SECONDARY,
               fontsize=9)

    fig.tight_layout()
    fig.savefig(out_path, facecolor=fig.get_facecolor())
    plt.close(fig)
    print(f"Gerado: {out_path}")


def plot_ping_metric(xdp_by_n, baseline_by_n, out_path: Path, ylabel, title):
    fig, ax = plt.subplots(figsize=(7, 5), dpi=150)
    fig.patch.set_facecolor(SURFACE)
    ax.set_facecolor(SURFACE)

    width = 0.32
    tops = []
    r = _bar_with_explicit_error(ax, baseline_by_n, COLOR_BASELINE,
                                  "iptables (kernel)", width, -0.5 * width)
    if r:
        tops.extend(m + e for m, e in zip(*r))
    r = _bar_with_explicit_error(ax, xdp_by_n, COLOR_XDP, "XDP", width,
                                  0.5 * width)
    if r:
        tops.extend(m + e for m, e in zip(*r))

    ax.set_xticks(np.arange(len(RULE_COUNTS)))
    ax.set_xticklabels([f"N={n}" for n in RULE_COUNTS], color=INK_SECONDARY)
    _style_axes(ax, ylabel, title)
    ax.set_ylim(0, max(tops) * 1.35 if tops else 1)
    ax.legend(loc="upper left", frameon=False, labelcolor=INK_SECONDARY,
               fontsize=9)

    fig.tight_layout()
    fig.savefig(out_path, facecolor=fig.get_facecolor())
    plt.close(fig)
    print(f"Gerado: {out_path}")


def main():
    parser = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--xdp", type=Path, required=True,
                        help="Diretorio de resultados do firewall XDP "
                             "(run_fw_bench.sh xdp)")
    parser.add_argument("--baseline", type=Path, required=True,
                        help="Diretorio de resultados do iptables "
                             "(run_fw_bench.sh baseline)")
    parser.add_argument("--reps", type=int, default=10)
    parser.add_argument("--duration", type=float, default=30.0,
                        help="Duracao (s) de cada execucao do iperf3 UDP, "
                             "para converter pacotes em pps (default: 30)")
    parser.add_argument("--out-dir", type=Path, default=None)
    args = parser.parse_args()

    for d in (args.xdp, args.baseline):
        if not d.is_dir():
            print(f"Erro: '{d}' nao e um diretorio.", file=sys.stderr)
            sys.exit(1)

    out_dir = args.out_dir or args.xdp
    out_dir.mkdir(parents=True, exist_ok=True)

    xdp_tput = collect_reps(args.xdp, args.reps, tcp_gbps)
    baseline_tput = collect_reps(args.baseline, args.reps, tcp_gbps)

    xdp_pps = collect_reps(
        args.xdp, args.reps,
        lambda d, n, r: udp_pps(d, n, r, args.duration))
    baseline_pps = collect_reps(
        args.baseline, args.reps,
        lambda d, n, r: udp_pps(d, n, r, args.duration))

    xdp_ping = collect_ping(args.xdp)
    baseline_ping = collect_ping(args.baseline)

    plot_reps_metric(
        xdp_tput, baseline_tput, out_dir / "fw_bench_throughput.png",
        "Throughput TCP (Gbit/s)",
        "Firewall — throughput TCP vs regras carregadas (LAN→LAN)",
    )
    plot_reps_metric(
        xdp_pps, baseline_pps, out_dir / "fw_bench_pps.png",
        "Taxa de pacotes UDP 64B (pps)",
        "Firewall — pps UDP 64B vs regras carregadas (LAN→LAN)",
    )
    plot_ping_metric(
        xdp_ping, baseline_ping, out_dir / "fw_bench_latency.png",
        "RTT médio ± mdev (ms)",
        "Firewall — latência (ping) vs regras carregadas (LAN→LAN)",
    )


if __name__ == "__main__":
    main()
