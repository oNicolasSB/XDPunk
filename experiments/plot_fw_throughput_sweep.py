#!/usr/bin/env python3
"""plot_fw_throughput_sweep.py — throughput TCP vs N (linearidade).

Le os CSVs gerados por run_fw_throughput_sweep.sh (throughput_N<N>.csv,
uma medida bps por linha) para uma grade fina de N (ex.: 0, 200, ...,
2000) e produz um grafico de dispersao: pontos individuais + media por N
+ ajuste de regressao linear (minimos quadrados sobre TODAS as medidas
brutas, nao so as medias) com R² anotado, para avaliar visual e
numericamente se a queda de throughput e linear em N.

Paleta e specs de marca seguem a skill `dataviz` do projeto.

Uso:
    python3 plot_fw_throughput_sweep.py <results_dir> [--out DIR]
"""

import argparse
import csv
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
DATA_COLOR = "#2a78d6"       # ramp azul, degrau 450 (references/palette.md)
FIT_COLOR = INK_MUTED        # linha de referencia (ajuste), nao e serie de dados

_N_RE = re.compile(r"throughput_N(\d+)\.csv$")


def discover_n_values(results_dir: Path):
    ns = []
    for p in results_dir.glob("throughput_N*.csv"):
        m = _N_RE.search(p.name)
        if m:
            ns.append(int(m.group(1)))
    return sorted(ns)


def read_gbps(path: Path):
    values = []
    with open(path) as f:
        for row in csv.reader(f):
            if not row:
                continue
            try:
                values.append(float(row[0]) / 1e9)
            except ValueError:
                continue
    return values


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("results_dir", type=Path)
    parser.add_argument("--out", type=Path, default=None,
                        help="Caminho do PNG de saida (default: <results_dir>/fw_throughput_sweep.png)")
    args = parser.parse_args()

    if not args.results_dir.is_dir():
        print(f"Erro: '{args.results_dir}' nao e um diretorio.", file=sys.stderr)
        sys.exit(1)

    n_values = discover_n_values(args.results_dir)
    if not n_values:
        print(f"Erro: nenhum throughput_N*.csv encontrado em {args.results_dir}.",
              file=sys.stderr)
        sys.exit(1)

    per_n = {}
    for n in n_values:
        values = read_gbps(args.results_dir / f"throughput_N{n}.csv")
        if not values:
            print(f"Aviso: nenhum valor valido para N={n}, pulando.", file=sys.stderr)
            continue
        per_n[n] = values

    n_values = sorted(per_n.keys())
    means = np.array([np.mean(per_n[n]) for n in n_values])

    # Regressao linear sobre TODAS as medidas brutas (nao so as medias),
    # para nao inflar o ajuste tratando cada N como um unico ponto.
    all_x = np.array([n for n in n_values for _ in per_n[n]], dtype=float)
    all_y = np.array([v for n in n_values for v in per_n[n]])
    slope, intercept = np.polyfit(all_x, all_y, 1)
    pred = slope * all_x + intercept
    ss_res = np.sum((all_y - pred) ** 2)
    ss_tot = np.sum((all_y - all_y.mean()) ** 2)
    r_squared = 1 - ss_res / ss_tot if ss_tot > 0 else float("nan")

    print(f"Ajuste linear: throughput(N) ≈ {slope:.6f} × N + {intercept:.4f} "
          f"(Gbit/s)  |  R² = {r_squared:.4f}")

    fig, ax = plt.subplots(figsize=(8, 5.5), dpi=150)
    fig.patch.set_facecolor(SURFACE)
    ax.set_facecolor(SURFACE)

    # Pontos individuais (jitter horizontal leve para nao empilhar exatamente).
    rng = np.random.default_rng(0)
    jitter_span = max(n_values) * 0.01 if len(n_values) > 1 else 1
    for n in n_values:
        values = per_n[n]
        jitter = rng.uniform(-jitter_span, jitter_span, size=len(values))
        ax.scatter(
            np.full(len(values), n) + jitter, values,
            s=22, facecolor=DATA_COLOR, edgecolor=SURFACE, linewidth=0.8,
            alpha=0.55, zorder=2,
            label="Execução individual" if n == n_values[0] else None,
        )

    # Media por N, conectada.
    ax.plot(
        n_values, means, color=DATA_COLOR, linewidth=2, marker="o",
        markersize=6, markerfacecolor=DATA_COLOR, markeredgecolor=SURFACE,
        markeredgewidth=1.2, zorder=3, label="Média por N",
    )

    # Ajuste linear (referencia, nao serie de dados).
    x_fit = np.array([min(n_values), max(n_values)])
    ax.plot(
        x_fit, slope * x_fit + intercept, color=FIT_COLOR, linewidth=1.5,
        linestyle="--", zorder=1,
        label=f"Ajuste linear (R²={r_squared:.3f})",
    )

    ax.set_xlabel("N (regras de firewall carregadas)", color=INK_SECONDARY)
    ax.set_ylabel("Throughput TCP (Gbit/s)", color=INK_SECONDARY)
    ax.set_title("Throughput TCP vs N — LAN→LAN", color=INK_PRIMARY,
                 fontsize=13, fontweight="bold", pad=14)
    ax.set_xlim(min(n_values) - jitter_span * 3, max(n_values) + jitter_span * 3)
    ax.set_ylim(bottom=0)

    ax.yaxis.grid(True, color=GRIDLINE, linewidth=1, zorder=0)
    ax.set_axisbelow(True)
    for spine in ("top", "right", "left"):
        ax.spines[spine].set_visible(False)
    ax.spines["bottom"].set_color(AXIS_BASELINE)
    ax.tick_params(axis="both", colors=INK_MUTED, length=0)

    handles, labels = ax.get_legend_handles_labels()
    ax.legend(
        handles, labels, loc="upper center", bbox_to_anchor=(0.5, -0.12),
        ncol=3, frameon=False, labelcolor=INK_SECONDARY, fontsize=9,
    )

    out_path = args.out or (args.results_dir / "fw_throughput_sweep.png")
    fig.savefig(out_path, facecolor=fig.get_facecolor(), bbox_inches="tight")
    plt.close(fig)
    print(f"Gerado: {out_path}")


if __name__ == "__main__":
    main()
