#!/usr/bin/env python3
"""plot_lb_perf_compare.py — graficos XDPunk vs ECMP das metricas de
encaminhamento (latencia, throughput, jitter, pps) medidas por
run_lb_perf_bench_real.sh na topologia encadeada de 6 VMs.

Mesmo formato dos graficos de plot_fw_capacity.py (barra = media ± desvio
padrao, execucoes individuais sobrepostas, outliers pela regra 1.5×IQR em
destaque), com dois cenarios lado a lado.

Paleta segue a skill `dataviz`: XDP e ECMP sao categorias (mecanismos
distintos), entao usam os slots categoricos 1 (azul) e 2 (laranja) da ordem
fixa validada — os mesmos de plot_lb_chain_bench.py; o rotulo no eixo x
identifica cada barra (identidade nunca so pela cor).

Uso:
    python3 plot_lb_perf_compare.py --xdp DIR --baseline DIR \\
        [--out-dir DIR] [--title-suffix TEXTO]
"""
import argparse
import sys
from pathlib import Path

import matplotlib

matplotlib.use("Agg")
import matplotlib.pyplot as plt
import numpy as np

sys.path.insert(0, str(Path(__file__).resolve().parent))
from plot_fw_capacity import (  # noqa: E402
    AXIS_BASELINE, GRIDLINE, INK_MUTED, INK_PRIMARY, INK_SECONDARY,
    OUTLIER_COLOR, POINT_COLOR, SURFACE, iqr_outliers, read_csv_values,
)

XDP_COLOR = "#2a78d6"
BASELINE_COLOR = "#eb6834"

METRICS = [
    # (arquivo, titulo, rotulo_eixo_y, conversor)
    ("throughput", "Throughput TCP (1 fluxo)", "Throughput (Mbit/s)",
     lambda bps: bps / 1e6),
    ("latency", "Latência (RTT)", "RTT médio (ms)", lambda ms: ms),
    ("jitter", "Jitter (UDP, 200 Mbit/s)", "Jitter (ms)", lambda ms: ms),
    ("pps", "Taxa de encaminhamento (UDP 64 B, saturante)",
     "Pacotes entregues (kpps)", lambda pps: pps / 1e3),
]


def load(results_dir: Path, prefix, convert):
    path = results_dir / f"{prefix}.csv"
    if not path.exists():
        print(f"Aviso: {path} nao encontrado.", file=sys.stderr)
        return None
    values, total = read_csv_values(path, convert)
    if total - len(values):
        print(f"Aviso: {path}: {total - len(values)} execucao(oes) sem valor "
              f"valido ignorada(s).", file=sys.stderr)
    return values or None


def plot_metric(prefix, title, ylabel, convert, scenarios, out_dir: Path, suffix):
    data = []
    for label, color, d in scenarios:
        values = load(d, prefix, convert)
        if values is None:
            print(f"Aviso: metrica '{prefix}' pulada.", file=sys.stderr)
            return
        data.append((label, color, np.asarray(values)))

    fig, ax = plt.subplots(figsize=(6, 5), dpi=150)
    fig.patch.set_facecolor(SURFACE)
    ax.set_facecolor(SURFACE)

    xs = np.arange(len(data))
    means = [v.mean() for _, _, v in data]
    stds = [v.std(ddof=1) if len(v) > 1 else 0.0 for _, _, v in data]
    ax.bar(xs, means, width=0.5, color=[c for _, c, _ in data],
           yerr=stds, capsize=6,
           error_kw={"ecolor": INK_SECONDARY, "elinewidth": 1.5, "capthick": 1.5},
           zorder=2)

    rng = np.random.default_rng(0)
    for xi, (_, _, values), mean, std in zip(xs, data, means, stds):
        normal_idx, outlier_idx = iqr_outliers(values)
        jitter = rng.uniform(-0.12, 0.12, size=len(values))
        if len(normal_idx):
            ax.scatter(xi + jitter[normal_idx], values[normal_idx],
                       s=26, facecolor=POINT_COLOR, edgecolor=SURFACE,
                       linewidth=1.0, alpha=0.85, zorder=3,
                       label="Execução individual" if xi == 0 else None)
        if len(outlier_idx):
            ax.scatter(xi + jitter[outlier_idx], values[outlier_idx],
                       s=48, marker="D", facecolor=OUTLIER_COLOR,
                       edgecolor=SURFACE, linewidth=1.0, zorder=4,
                       label="Outlier (1,5×IQR)")
        ax.text(xi + 0.16, mean + std, f"{mean:.4g}", ha="left", va="center",
                fontsize=9, color=INK_SECONDARY, zorder=5)

    ax.set_xticks(xs)
    ax.set_xticklabels([label for label, _, _ in data], color=INK_SECONDARY)
    ax.set_ylabel(ylabel, color=INK_SECONDARY)
    ax.set_title(title, color=INK_PRIMARY, fontsize=12, fontweight="bold",
                 pad=24 if suffix else 14)
    if suffix:
        ax.text(0.5, 1.02, suffix, transform=ax.transAxes, ha="center",
                va="bottom", fontsize=9, color=INK_MUTED)

    top = max(max(v.max() for _, _, v in data),
              max(m + s for m, s in zip(means, stds)))
    ax.set_ylim(0, top * 1.3)
    ax.yaxis.grid(True, color=GRIDLINE, linewidth=1, zorder=0)
    ax.set_axisbelow(True)
    for spine in ("top", "right", "left"):
        ax.spines[spine].set_visible(False)
    ax.spines["bottom"].set_color(AXIS_BASELINE)
    ax.tick_params(axis="both", colors=INK_MUTED, length=0)

    # Uma entrada por tipo de marcador (outliers podem aparecer nas 2 barras).
    handles, labels = ax.get_legend_handles_labels()
    uniq = dict(zip(labels, handles))
    if uniq:
        ax.legend(uniq.values(), uniq.keys(), loc="upper center", ncol=2,
                  frameon=False, labelcolor=INK_SECONDARY, fontsize=9)

    fig.tight_layout()
    out_path = out_dir / f"lb_perf_{prefix}.png"
    fig.savefig(out_path, facecolor=fig.get_facecolor())
    plt.close(fig)
    print(f"Gerado: {out_path}  "
          + "  ".join(f"{l}: {m:.4g} ± {s:.2g}" for (l, _, _), m, s in zip(data, means, stds)))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--xdp", type=Path, required=True,
                        help="Resultados de run_lb_perf_bench_real.sh xdp")
    parser.add_argument("--baseline", type=Path, required=True,
                        help="Resultados de run_lb_perf_bench_real.sh baseline")
    parser.add_argument("--out-dir", type=Path, default=None,
                        help="Diretorio dos PNGs (default: o diretorio --xdp)")
    parser.add_argument("--title-suffix", default="LB encadeado, 6 VMs")
    args = parser.parse_args()

    for d in (args.xdp, args.baseline):
        if not d.is_dir():
            print(f"Erro: '{d}' nao e um diretorio.", file=sys.stderr)
            sys.exit(1)
    out_dir = args.out_dir or args.xdp
    out_dir.mkdir(parents=True, exist_ok=True)

    scenarios = [("ECMP (kernel)", BASELINE_COLOR, args.baseline),
                 ("XDPunk (XDP)", XDP_COLOR, args.xdp)]
    for prefix, title, ylabel, convert in METRICS:
        plot_metric(prefix, title, ylabel, convert, scenarios, out_dir,
                    args.title_suffix)


if __name__ == "__main__":
    main()
