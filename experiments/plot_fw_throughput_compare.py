#!/usr/bin/env python3
"""plot_fw_throughput_compare.py — throughput TCP vs N, XDP vs iptables.

Mesmo estilo visual de plot_fw_throughput_sweep.py (pontos individuais +
media por N conectada + ajuste de regressao linear com R² anotado), mas
sobrepondo duas series — firewall XDP e FORWARD/iptables do kernel — para
comparar a forma da degradacao de throughput em funcao do numero de
regras carregadas.

Le os arquivos gerados por run_fw_bench.sh em dois diretorios de
resultados (um por modo): tcp_N{n}_r{rep}.json (iperf3, REPS repeticoes
por N). N e descoberto a partir dos nomes de arquivo presentes em cada
diretorio (nao precisa ser a mesma grade nos dois modos).

Paleta segue o mesmo mapeamento de plot_lb_bench.py / plot_fw_bench.py
(references/palette.md da skill dataviz): slot 1 azul = XDP, slot 2
laranja = mecanismo nativo do kernel.

Uso:
    python3 plot_fw_throughput_compare.py --xdp DIR --baseline DIR \\
        [--reps N] [--out DIR_OU_ARQUIVO.png]
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

INK_PRIMARY = "#0b0b0b"
INK_SECONDARY = "#52514e"
INK_MUTED = "#898781"
GRIDLINE = "#e1e0d9"
AXIS_BASELINE = "#c3c2b7"
SURFACE = "#fcfcfb"

# Mesmo mapeamento de cor de plot_lb_bench.py / plot_fw_bench.py:
# slot 1 azul = XDP, slot 2 laranja = mecanismo nativo do kernel.
COLOR_XDP = "#2a78d6"
COLOR_BASELINE = "#eb6834"

_N_RE = re.compile(r"tcp_N(\d+)_r\d+\.json$")


def discover_n_values(results_dir: Path):
    ns = set()
    for p in results_dir.glob("tcp_N*_r*.json"):
        m = _N_RE.search(p.name)
        if m:
            ns.add(int(m.group(1)))
    return sorted(ns)


def _tcp_gbps(end):
    return end["sum_received"]["bits_per_second"] / 1e9


def _udp_kpps(end):
    """Pacotes entregues por segundo no receptor, em milhares."""
    rcv = end["sum_received"]
    return (rcv["packets"] - rcv["lost_packets"]) / rcv["seconds"] / 1e3


# metrica -> (prefixo do arquivo, extrator, rotulo do eixo y, unidade, titulo)
METRICS = {
    "tcp": ("tcp", _tcp_gbps, "Throughput TCP (Gbit/s)", "Gbit/s",
            "Throughput TCP vs N — XDP vs iptables"),
    "pps": ("udp64", _udp_kpps, "Pacotes UDP 64 B entregues (kpps)", "kpps",
            "Taxa de pacotes UDP 64 B vs N — XDP vs iptables"),
}


def read_values(results_dir: Path, n: int, reps: int, metric: str):
    prefix, extract = METRICS[metric][:2]
    values = []
    for rep in range(1, reps + 1):
        path = results_dir / f"{prefix}_N{n}_r{rep}.json"
        if not path.exists():
            continue
        with open(path) as f:
            data = json.load(f)
        values.append(extract(data["end"]))
    return values


def collect(results_dir: Path, reps: int, metric: str = "tcp"):
    per_n = {}
    for n in discover_n_values(results_dir):
        values = read_values(results_dir, n, reps, metric)
        if values:
            per_n[n] = values
        else:
            print(f"Aviso: nenhum valor valido para N={n} em {results_dir}.",
                  file=sys.stderr)
    return per_n


def linear_fit(per_n):
    n_values = sorted(per_n.keys())
    all_x = np.array([n for n in n_values for _ in per_n[n]], dtype=float)
    all_y = np.array([v for n in n_values for v in per_n[n]])
    slope, intercept = np.polyfit(all_x, all_y, 1)
    pred = slope * all_x + intercept
    ss_res = np.sum((all_y - pred) ** 2)
    ss_tot = np.sum((all_y - all_y.mean()) ** 2)
    r_squared = 1 - ss_res / ss_tot if ss_tot > 0 else float("nan")
    return slope, intercept, r_squared


def plot_series(ax, per_n, color, label, jitter_span, rng, unit="Gbit/s"):
    n_values = sorted(per_n.keys())
    means = np.array([np.mean(per_n[n]) for n in n_values])

    for n in n_values:
        values = per_n[n]
        jitter = rng.uniform(-jitter_span, jitter_span, size=len(values))
        ax.scatter(
            np.full(len(values), n) + jitter, values,
            s=22, facecolor=color, edgecolor=SURFACE, linewidth=0.8,
            alpha=0.45, zorder=2,
        )

    ax.plot(
        n_values, means, color=color, linewidth=2, marker="o",
        markersize=6, markerfacecolor=color, markeredgecolor=SURFACE,
        markeredgewidth=1.2, zorder=3, label=f"{label} — média por N",
    )

    slope, intercept, r_squared = linear_fit(per_n)
    x_fit = np.array([min(n_values), max(n_values)])
    ax.plot(
        x_fit, slope * x_fit + intercept, color=color, linewidth=1.5,
        linestyle="--", alpha=0.6, zorder=1,
        label=f"{label} — ajuste linear (R²={r_squared:.3f})",
    )
    print(f"{label}: valor(N) ≈ {slope:.6f} × N + {intercept:.4f} "
          f"({unit})  |  R² = {r_squared:.4f}")
    return n_values


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
    parser.add_argument("--out", type=Path, default=None,
                        help="Caminho do PNG de saida (default: "
                             "<xdp>/fw_throughput_compare.png, ou "
                             "fw_pps_compare.png com --metric pps)")
    parser.add_argument("--metric", choices=sorted(METRICS), default="tcp",
                        help="tcp = throughput TCP (default); pps = taxa de "
                             "pacotes UDP 64 B entregues")
    parser.add_argument("--title-suffix", default="LAN→LAN",
                        help="Texto entre parenteses no fim do titulo")
    args = parser.parse_args()
    ylabel, unit, title = METRICS[args.metric][2:]

    for d in (args.xdp, args.baseline):
        if not d.is_dir():
            print(f"Erro: '{d}' nao e um diretorio.", file=sys.stderr)
            sys.exit(1)

    xdp_per_n = collect(args.xdp, args.reps, args.metric)
    baseline_per_n = collect(args.baseline, args.reps, args.metric)
    if not xdp_per_n or not baseline_per_n:
        print("Erro: sem dados suficientes para plotar.", file=sys.stderr)
        sys.exit(1)

    all_n = sorted(set(xdp_per_n) | set(baseline_per_n))
    jitter_span = max(all_n) * 0.01 if len(all_n) > 1 else 1

    fig, ax = plt.subplots(figsize=(8, 5.5), dpi=150)
    fig.patch.set_facecolor(SURFACE)
    ax.set_facecolor(SURFACE)

    rng = np.random.default_rng(0)
    plot_series(ax, baseline_per_n, COLOR_BASELINE, "iptables (kernel)",
                jitter_span, rng, unit)
    plot_series(ax, xdp_per_n, COLOR_XDP, "XDP", jitter_span, rng, unit)

    ax.set_xlabel("N (regras de firewall carregadas)", color=INK_SECONDARY)
    ax.set_ylabel(ylabel, color=INK_SECONDARY)
    ax.set_title(f"{title} ({args.title_suffix})",
                 color=INK_PRIMARY, fontsize=13, fontweight="bold", pad=14)
    ax.set_xlim(min(all_n) - jitter_span * 3, max(all_n) + jitter_span * 3)
    ax.set_ylim(bottom=0)

    ax.yaxis.grid(True, color=GRIDLINE, linewidth=1, zorder=0)
    ax.set_axisbelow(True)
    for spine in ("top", "right", "left"):
        ax.spines[spine].set_visible(False)
    ax.spines["bottom"].set_color(AXIS_BASELINE)
    ax.tick_params(axis="both", colors=INK_MUTED, length=0)

    handles, labels = ax.get_legend_handles_labels()
    ax.legend(
        handles, labels, loc="upper center", bbox_to_anchor=(0.5, -0.14),
        ncol=2, frameon=False, labelcolor=INK_SECONDARY, fontsize=9,
    )

    default_name = ("fw_throughput_compare.png" if args.metric == "tcp"
                    else f"fw_{args.metric}_compare.png")
    out_path = args.out or (args.xdp / default_name)
    fig.savefig(out_path, facecolor=fig.get_facecolor(), bbox_inches="tight")
    plt.close(fig)
    print(f"Gerado: {out_path}")


if __name__ == "__main__":
    main()
