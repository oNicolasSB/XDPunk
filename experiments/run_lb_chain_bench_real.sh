#!/usr/bin/env bash
#
# run_lb_chain_bench_real.sh — Q1/Q2: LB WAN encadeado (2 saltos) XDP vs
# ECMP na topologia de 6 VMs reais (ver docs/setup_xdp_lb_chain_real.md).
#
# Versao real de run_lb_chain_bench.sh (lab em netns), com o mesmo
# protocolo e os mesmos arquivos de saida (lidos por plot_lb_chain_bench.py
# com --wan-ifaces ens20,ens21):
#   ping.txt                          ping -c 200 -i 0.01 (latencia)
#   tcp_P{p}_r{rep}.json              iperf3 TCP, P fluxos paralelos
#   links_P{p}_r{rep}_{before,after}_r{1,4}.{txt,json}
#       xdp      -> `xdpunk-cli lb status` (contadores wan_stats, zerados
#                   antes de cada repeticao)
#       baseline -> `ip -s -j link show` (contadores tx das interfaces)
#
# Roda no host1 (A). host2 (servidor iperf3) e R1/R4 sao acionados por SSH
# pela rede de gerencia, somente entre repeticoes.
#
# Pre-requisito: bash scripts/setup_lb_chain_real.sh <xdp|baseline>
#
# Uso: bash run_lb_chain_bench_real.sh <xdp|baseline> [REPS] [DURACAO_S]
# Variaveis: STREAMS ("2 4 8 16"), as de scripts/lb_chain_real.env.
#
set -euo pipefail

MODE="${1:?Uso: $0 <xdp|baseline> [REPS] [DURACAO_S]}"
REPS="${2:-10}"
DUR="${3:-30}"
read -r -a STREAMS <<< "${STREAMS:-2 4 8 16}"

[[ "$MODE" == "xdp" || "$MODE" == "baseline" ]] || {
  echo "ERRO: modo deve ser 'xdp' ou 'baseline'."; exit 1;
}

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
# shellcheck source=../scripts/lb_chain_real.env
source "$SCRIPT_DIR/../scripts/lb_chain_real.env"
# shellcheck source=lb_real_common.sh
source "$SCRIPT_DIR/lb_real_common.sh"

OUT="$SCRIPT_DIR/results/lb_chain_real_${MODE}_$(date +%Y%m%d_%H%M%S)"
mkdir -p "$OUT"

lbr_require_tools
lbr_check_mode "$MODE"
trap lbr_stop_server EXIT
lbr_write_env "$OUT/env.txt" "$MODE" "reps=$REPS dur=$DUR streams=${STREAMS[*]}"

reset_counters() {
  if [[ "$MODE" == "xdp" ]]; then
    lbr_cli "$R1_MGMT" "stats --reset" >/dev/null
    lbr_cli "$R4_MGMT" "stats --reset" >/dev/null
  fi
}

snapshot_links() {  # snapshot_links <basepath_sem_extensao>
  if [[ "$MODE" == "xdp" ]]; then
    lbr_cli "$R1_MGMT" "lb status" > "$1_r1.txt" 2>&1
    lbr_cli "$R4_MGMT" "lb status" > "$1_r4.txt" 2>&1
  else
    lbr_ssh "$R1_MGMT" "ip -s -j link show" > "$1_r1.json" 2>&1
    lbr_ssh "$R4_MGMT" "ip -s -j link show" > "$1_r4.json" 2>&1
  fi
}

echo "== Benchmark LB encadeado real (host1-R1-{R2,R3}-R4-host2) — modo=$MODE reps=$REPS duracao=${DUR}s =="
echo "Resultados em: $OUT"
lbr_restart_server

echo "-- latencia (ping) --"
ping -c 200 -i 0.01 -q "$B_IP" > "$OUT/ping.txt" 2>&1 || true
echo "  RTT avg: $(lbr_ping_avg "$OUT/ping.txt") ms"

for P in "${STREAMS[@]}"; do
  echo "-- P=$P fluxos paralelos --"
  for ((rep = 1; rep <= REPS; rep++)); do
    reset_counters
    snapshot_links "$OUT/links_P${P}_r${rep}_before"

    lbr_iperf3 "$OUT/tcp_P${P}_r${rep}.json" -c "$B_IP" -P "$P" -t "$DUR"
    tput_bps=$(jq '.end.sum_received.bits_per_second' "$OUT/tcp_P${P}_r${rep}.json")
    echo "  P=$P rep=$rep: $(awk "BEGIN{printf \"%.3f\", $tput_bps/1e9}") Gbit/s agregado"

    snapshot_links "$OUT/links_P${P}_r${rep}_after"
  done
done

echo
echo "Concluido. Dados brutos (JSON/txt) em: $OUT"
echo "Graficos: python3 experiments/plot_lb_chain_bench.py <xdp_dir> <baseline_dir> --wan-ifaces $R1_W0,$R1_W1"
