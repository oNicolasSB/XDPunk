#!/usr/bin/env bash
#
# run_lb_real_all.sh — executa a bateria completa do LB encadeado nas 6 VMs
# reais, nos dois modos (xdp e baseline/ECMP), sem intervencao:
#   1. setup do modo (scripts/setup_lb_chain_real.sh)
#   2. metricas de encaminhamento  (run_lb_perf_bench_real.sh)
#   3. Q1/Q2 throughput + justica  (run_lb_chain_bench_real.sh)
#   4. Q3 simetria ida/volta       (capture_lb_chain_symmetry_real.sh)
# Ao final a topologia fica no ultimo modo executado.
#
# Roda no host1. Duracao com os padroes: ~45 min por modo.
#
# Uso: bash run_lb_real_all.sh [MODOS]      (padrao: "xdp baseline")
# Variaveis: PERF_REPS (20), PERF_TCP_DUR (30), PERF_UDP_DUR (10),
#            LB_REPS (10), LB_DUR (30), SYM_FLOWS (40), SYM_DUR (5).
#
set -euo pipefail

read -r -a MODES <<< "${1:-xdp baseline}"
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_DIR="$(dirname "$SCRIPT_DIR")"

for m in "${MODES[@]}"; do
  [[ "$m" == "xdp" || "$m" == "baseline" ]] || { echo "ERRO: modo invalido '$m'"; exit 1; }
done

echo "######## Bateria LB encadeado real — modos: ${MODES[*]} — inicio $(date -Is)"
for MODE in "${MODES[@]}"; do
  echo
  echo "######## [$MODE] setup — $(date -Is)"
  bash "$REPO_DIR/scripts/setup_lb_chain_real.sh" "$MODE"

  echo "######## [$MODE] metricas de encaminhamento — $(date -Is)"
  bash "$SCRIPT_DIR/run_lb_perf_bench_real.sh" "$MODE" \
    "${PERF_REPS:-20}" "${PERF_TCP_DUR:-30}" "${PERF_UDP_DUR:-10}"

  echo "######## [$MODE] Q1/Q2 throughput e justica — $(date -Is)"
  bash "$SCRIPT_DIR/run_lb_chain_bench_real.sh" "$MODE" "${LB_REPS:-10}" "${LB_DUR:-30}"

  echo "######## [$MODE] Q3 simetria — $(date -Is)"
  bash "$SCRIPT_DIR/capture_lb_chain_symmetry_real.sh" "$MODE" "${SYM_FLOWS:-40}" "${SYM_DUR:-5}"
done
echo
echo "######## Bateria concluida — $(date -Is)"
ls -dt "$SCRIPT_DIR"/results/lb_*_real_* | head -$((3 * ${#MODES[@]}))
