#!/usr/bin/env python3
"""plot_fw_capacity.py — graficos do benchmark de capacidade do firewall XDP.

Le os dados brutos gerados por run_fw_capacity_bench.sh (CSVs de 20
execucoes por cenario N ∈ {0, 1000, 2000} regras) e produz graficos de
barra (throughput, latencia, jitter e, quando presente, pps): media ± desvio-padrao, com os pontos
individuais das execucoes sobrepostos (scatter) para evidenciar outliers.
Outliers (regra 1.5×IQR) sao destacados com marcador e cor distintos.

Paleta e specs de marca seguem a skill `dataviz` do projeto (ramp azul
sequencial/ordinal para os 3 cenarios ordenados por N; tokens de tinta
para eixos/texto; grade horizontal hairline).

Uso:
    python3 plot_fw_capacity.py <results_dir> [--out-dir DIR]
"""

import argparse
import csv
import sys
from pathlib import Path

import matplotlib

matplotlib.use("Agg")
import matplotlib.pyplot as plt
import numpy as np

RULE_COUNTS = [0, 1000, 2000]

# Ramp azul ordinal (references/palette.md da skill dataviz): degraus 250,
# 450, 650 — claro ao escuro acompanhando N crescente (ordem = magnitude).
BAR_COLORS = ["#86b6ef", "#2a78d6", "#104281"]

INK_PRIMARY = "#0b0b0b"
INK_SECONDARY = "#52514e"
INK_MUTED = "#898781"
GRIDLINE = "#e1e0d9"
AXIS_BASELINE = "#c3c2b7"
SURFACE = "#fcfcfb"
POINT_COLOR = "#52514e"
OUTLIER_COLOR = "#d03b3b"

METRICS = [
    # (arquivo_prefixo, titulo, rotulo_eixo_y, conversor)
    ("throughput", "Throughput TCP — LAN→LAN", "Throughput (Gbit/s)",
     lambda bps: bps / 1e9),
    ("latency", "Latência (RTT)", "RTT médio (ms)", lambda ms: ms),
    ("jitter", "Jitter (UDP, 200 Mbit/s)", "Jitter (ms)", lambda ms: ms),
    # So existe nos resultados de run_fw_capacity_bench_real.sh (3 VMs);
    # ausente nos do lab em netns — a metrica e pulada com aviso.
    ("pps", "Taxa de encaminhamento (UDP 64 B, saturante)",
     "Pacotes entregues (kpps)", lambda pps: pps / 1e3),
]


def read_csv_values(path: Path, convert):
    """Retorna (valores_validos, total_de_linhas_nao_vazias)."""
    values = []
    total = 0
    with open(path) as f:
        for row in csv.reader(f):
            if not row:
                continue
            total += 1
            raw = row[0].strip()
            try:
                v = float(raw)
            except ValueError:
                continue  # "NaN" (100% de perda de pacotes)
            if np.isnan(v):
                continue
            values.append(convert(v))
    return values, total


def iqr_outliers(values):
    """Retorna (indices_normais, indices_outliers) pela regra 1.5×IQR."""
    arr = np.asarray(values)
    q1, q3 = np.percentile(arr, [25, 75])
    iqr = q3 - q1
    low, high = q1 - 1.5 * iqr, q3 + 1.5 * iqr
    is_outlier = (arr < low) | (arr > high)
    return np.where(~is_outlier)[0], np.where(is_outlier)[0]


def plot_metric(prefix, title, ylabel, convert, results_dir: Path, out_dir: Path):
    per_n = {}
    for n in RULE_COUNTS:
        csv_path = results_dir / f"{prefix}_N{n}.csv"
        if not csv_path.exists():
            print(f"Aviso: {csv_path} nao encontrado, pulando metrica "
                  f"'{prefix}'.", file=sys.stderr)
            return
        values, total = read_csv_values(csv_path, convert)
        dropped = total - len(values)
        if dropped > 0:
            print(f"Aviso: {prefix} N={n}: {dropped} execucao(oes) sem "
                  f"valor valido (ex.: 100% de perda de pacotes) ignorada(s).",
                  file=sys.stderr)
        if not values:
            print(f"Erro: nenhum valor valido para '{prefix}' em N={n}.",
                  file=sys.stderr)
            return
        per_n[n] = values

    fig, ax = plt.subplots(figsize=(7, 5), dpi=150)
    fig.patch.set_facecolor(SURFACE)
    ax.set_facecolor(SURFACE)

    x_positions = np.arange(len(RULE_COUNTS))
    means = [np.mean(per_n[n]) for n in RULE_COUNTS]
    stds = [np.std(per_n[n], ddof=1) if len(per_n[n]) > 1 else 0.0
            for n in RULE_COUNTS]

    ax.bar(
        x_positions, means, width=0.5, color=BAR_COLORS,
        yerr=stds, capsize=6,
        error_kw={"ecolor": INK_SECONDARY, "elinewidth": 1.5, "capthick": 1.5},
        zorder=2,
    )

    # Pontos individuais (jitter horizontal leve) — normais vs outliers.
    rng = np.random.default_rng(0)
    for xi, n, mean, std in zip(x_positions, RULE_COUNTS, means, stds):
        values = np.asarray(per_n[n])
        normal_idx, outlier_idx = iqr_outliers(values)
        jitter = rng.uniform(-0.12, 0.12, size=len(values))

        if len(normal_idx):
            ax.scatter(
                xi + jitter[normal_idx], values[normal_idx],
                s=26, facecolor=POINT_COLOR, edgecolor=SURFACE,
                linewidth=1.0, alpha=0.85, zorder=3,
                label="Execução individual" if xi == 0 else None,
            )
        if len(outlier_idx):
            ax.scatter(
                xi + jitter[outlier_idx], values[outlier_idx],
                s=48, marker="D", facecolor=OUTLIER_COLOR, edgecolor=SURFACE,
                linewidth=1.0, zorder=4,
                label="Outlier (1,5×IQR)" if xi == 0 else None,
            )

        # Deslocado para a direita, fora da faixa de jitter dos pontos
        # (±0.12), para nao colidir com eles.
        ax.text(
            xi + 0.16, mean + std, f"{mean:.3g}",
            ha="left", va="center", fontsize=9, color=INK_SECONDARY,
            zorder=5,
        )

    ax.set_xticks(x_positions)
    ax.set_xticklabels([f"N={n}" for n in RULE_COUNTS], color=INK_SECONDARY)
    ax.set_ylabel(ylabel, color=INK_SECONDARY)
    ax.set_title(title, color=INK_PRIMARY, fontsize=13, fontweight="bold",
                 pad=14)

    # Headroom reservado no topo do eixo para a legenda nao sobrepor
    # barras/pontos/rotulos, qualquer que seja a altura relativa dos 3
    # cenarios.
    top_value = max(
        max(np.max(per_n[n]) for n in RULE_COUNTS),
        max(m + s for m, s in zip(means, stds)),
    )
    ax.set_ylim(0, top_value * 1.3)

    ax.yaxis.grid(True, color=GRIDLINE, linewidth=1, zorder=0)
    ax.set_axisbelow(True)
    for spine in ("top", "right", "left"):
        ax.spines[spine].set_visible(False)
    ax.spines["bottom"].set_color(AXIS_BASELINE)
    ax.tick_params(axis="both", colors=INK_MUTED, length=0)

    handles, labels = ax.get_legend_handles_labels()
    if handles:
        # Dentro do headroom reservado no topo do eixo (nunca sobre
        # barras/pontos/rotulos).
        ax.legend(
            handles, labels, loc="upper center", ncol=2, frameon=False,
            labelcolor=INK_SECONDARY, fontsize=9,
        )

    fig.tight_layout()
    out_path = out_dir / f"fw_capacity_{prefix}.png"
    fig.savefig(out_path, facecolor=fig.get_facecolor())
    plt.close(fig)
    print(f"Gerado: {out_path}")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("results_dir", type=Path,
                        help="Diretorio com os CSVs de run_fw_capacity_bench[_real].sh")
    parser.add_argument("--out-dir", type=Path, default=None,
                        help="Diretorio de saida dos PNGs (default: results_dir)")
    args = parser.parse_args()

    if not args.results_dir.is_dir():
        print(f"Erro: '{args.results_dir}' nao e um diretorio.", file=sys.stderr)
        sys.exit(1)
    out_dir = args.out_dir or args.results_dir
    out_dir.mkdir(parents=True, exist_ok=True)

    for prefix, title, ylabel, convert in METRICS:
        plot_metric(prefix, title, ylabel, convert, args.results_dir, out_dir)


if __name__ == "__main__":
    main()
