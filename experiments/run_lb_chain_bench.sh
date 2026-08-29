#!/usr/bin/env bash
#
# run_lb_chain_bench.sh — Q1/Q2: LB WAN encadeado (2 saltos) XDP vs ECMP.
#
# Mede, no caminho nsA -> nsB (10.10.1.1 -> 10.10.2.1), com
# P in {2,4,8,16} fluxos TCP paralelos: throughput agregado (iperf3),
# latencia (ping) e contadores por link em R1/R4 (para o indice de
# justica de Jain, calculado depois por plot_lb_chain_bench.py).
#
# Pre-requisito: laboratorio correspondente ja carregado:
#   modo xdp      -> sudo bash scripts/setup_xdp_lb_chain.sh
#   modo baseline -> sudo bash scripts/setup_baseline_router_chain.sh
#
# Uso: sudo bash run_lb_chain_bench.sh <xdp|baseline> [REPS] [DURACAO_S]
#
set -euo pipefail

MODE="${1:?Uso: $0 <xdp|baseline> [REPS] [DURACAO_S]}"
REPS="${2:-10}"
DUR="${3:-30}"
STREAMS=(2 4 8 16)
B_IP="10.10.2.1"

[[ "$MODE" == "xdp" || "$MODE" == "baseline" ]] || {
  echo "ERRO: modo deve ser 'xdp' ou 'baseline'."; exit 1;
}

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
OUT="$SCRIPT_DIR/results/lb_chain_${MODE}_$(date +%Y%m%d_%H%M%S)"
mkdir -p "$OUT"

SERVER_PID=""
cleanup() {
  [[ -n "$SERVER_PID" ]] && kill "$SERVER_PID" 2>/dev/null || true
}
trap cleanup EXIT

command -v iperf3 >/dev/null || { echo "ERRO: iperf3 nao instalado."; exit 1; }
command -v jq >/dev/null || { echo "ERRO: jq nao instalado."; exit 1; }

reset_counters() {
  if [[ "$MODE" == "xdp" ]]; then
    xdpunk-cli --netns nsr1 --map-pin /sys/fs/bpf/xdpunk_r1 stats --reset >/dev/null
    xdpunk-cli --netns nsr4 --map-pin /sys/fs/bpf/xdpunk_r4 stats --reset >/dev/null
  fi
}

snapshot_links() {  # snapshot_links <basepath_sem_extensao>
  if [[ "$MODE" == "xdp" ]]; then
    xdpunk-cli --netns nsr1 --map-pin /sys/fs/bpf/xdpunk_r1 lb status > "$1_r1.txt" 2>&1
    xdpunk-cli --netns nsr4 --map-pin /sys/fs/bpf/xdpunk_r4 lb status > "$1_r4.txt" 2>&1
  else
    ip -n nsr1 -s -j link show > "$1_r1.json" 2>&1
    ip -n nsr4 -s -j link show > "$1_r4.json" 2>&1
  fi
}

echo "== Benchmark LB encadeado (A-R1-{R2,R3}-R4-B) — modo=$MODE reps=$REPS duracao=${DUR}s =="
echo "Resultados em: $OUT"

echo "Iniciando servidor iperf3 em nsB ($B_IP)..."
ip netns exec nsB iperf3 -s -B "$B_IP" >/dev/null 2>&1 &
SERVER_PID=$!
sleep 1

echo "-- latencia (ping) --"
ip netns exec nsA ping -c 200 -i 0.01 "$B_IP" > "$OUT/ping.txt" 2>&1
rtt_avg=$(grep -oP 'rtt min/avg/max/mdev = [0-9.]+/\K[0-9.]+' "$OUT/ping.txt" || echo "NA")
echo "  RTT avg: ${rtt_avg} ms"

for P in "${STREAMS[@]}"; do
  echo "-- P=$P fluxos paralelos --"
  for ((rep = 1; rep <= REPS; rep++)); do
    reset_counters
    snapshot_links "$OUT/links_P${P}_r${rep}_before"

    ip netns exec nsA iperf3 -c "$B_IP" -P "$P" -t "$DUR" --json \
      > "$OUT/tcp_P${P}_r${rep}.json"
    tput_bps=$(jq '.end.sum_received.bits_per_second' \
      "$OUT/tcp_P${P}_r${rep}.json")
    echo "  P=$P rep=$rep: $(awk "BEGIN{printf \"%.2f\", $tput_bps/1e9}") Gbit/s agregado"

    snapshot_links "$OUT/links_P${P}_r${rep}_after"
  done
done

echo
echo "Concluido. Dados brutos (JSON/txt) em: $OUT"
echo "Gerar graficos: python3 experiments/plot_lb_chain_bench.py <xdp_dir> <baseline_dir>"
