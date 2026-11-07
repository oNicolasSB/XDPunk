#!/usr/bin/env bash
#
# run_lb_perf_bench_real.sh — metricas do teste de firewall (latencia,
# throughput, jitter, pps) aplicadas ao caminho host1 -> host2 da topologia
# encadeada real, para comparar XDPunk (LB XDP em R1/R4) com ECMP do kernel
# (ver docs/setup_xdp_lb_chain_real.md). Sem regras de firewall.
#
# Mesma metodologia de run_fw_capacity_bench_real.sh; por repeticao:
#   - latencia  : RTT medio de `ping -c 200 -i 0.01`
#   - throughput: iperf3 TCP (1 fluxo), TCP_DUR s (bits/s no receptor)
#   - jitter    : iperf3 UDP a 200 Mbit/s, UDP_DUR s (jitter_ms do receptor)
#   - pps       : iperf3 UDP 64 B a 2 Gbit/s (saturante), UDP_DUR s —
#                 pacotes entregues/s no receptor
# Com 1 fluxo o LB (hash) e o ECMP mantem cada medicao num unico caminho:
# a comparacao isola o custo de encaminhamento + decisao de balanceamento.
#
# Saida: results/lb_perf_real_<modo>_<ts>/{throughput,latency,jitter,pps}.csv
#        (um valor por linha) + JSON/txt brutos.
#
# Pre-requisito: bash scripts/setup_lb_chain_real.sh <xdp|baseline>
#
# Uso: bash run_lb_perf_bench_real.sh <xdp|baseline> [REPS] [TCP_DUR_S] [UDP_DUR_S]
#
set -euo pipefail

MODE="${1:?Uso: $0 <xdp|baseline> [REPS] [TCP_DUR_S] [UDP_DUR_S]}"
REPS="${2:-20}"
TCP_DUR="${3:-30}"
UDP_DUR="${4:-10}"
UDP_BW="200M"
PPS_BW="2G"
PPS_LEN=64

[[ "$MODE" == "xdp" || "$MODE" == "baseline" ]] || {
  echo "ERRO: modo deve ser 'xdp' ou 'baseline'."; exit 1;
}

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
# shellcheck source=../scripts/lb_chain_real.env
source "$SCRIPT_DIR/../scripts/lb_chain_real.env"
# shellcheck source=lb_real_common.sh
source "$SCRIPT_DIR/lb_real_common.sh"

OUT="$SCRIPT_DIR/results/lb_perf_real_${MODE}_$(date +%Y%m%d_%H%M%S)"
mkdir -p "$OUT"

lbr_require_tools
lbr_check_mode "$MODE"
trap lbr_stop_server EXIT
lbr_write_env "$OUT/env.txt" "$MODE" \
  "reps=$REPS tcp_dur=$TCP_DUR udp_dur=$UDP_DUR udp_bw=$UDP_BW pps_bw=$PPS_BW pps_len=$PPS_LEN"

echo "== Metricas de encaminhamento (LB encadeado real) — modo=$MODE reps=$REPS =="
echo "Resultados em: $OUT"
[[ "$MODE" == "xdp" ]] && { lbr_cli "$R1_MGMT" "stats --reset" >/dev/null; lbr_cli "$R4_MGMT" "stats --reset" >/dev/null; }
lbr_restart_server

for m in throughput latency jitter pps; do : > "$OUT/${m}.csv"; done

for ((rep = 1; rep <= REPS; rep++)); do
  ping_file="$OUT/ping_r${rep}.txt"
  ping -c 200 -i 0.01 -q "$B_IP" > "$ping_file" 2>&1 || true
  rtt_avg="$(lbr_ping_avg "$ping_file")"
  echo "$rtt_avg" >> "$OUT/latency.csv"

  tcp_file="$OUT/tcp_r${rep}.json"
  lbr_iperf3 "$tcp_file" -c "$B_IP" -t "$TCP_DUR"
  bps="$(jq '.end.sum_received.bits_per_second' "$tcp_file")"
  echo "$bps" >> "$OUT/throughput.csv"

  udp_file="$OUT/udp_r${rep}.json"
  lbr_iperf3 "$udp_file" -u -b "$UDP_BW" -t "$UDP_DUR" -c "$B_IP"
  jitter="$(jq '.end.sum_received.jitter_ms // .end.sum.jitter_ms' "$udp_file")"
  echo "$jitter" >> "$OUT/jitter.csv"

  pps_file="$OUT/pps_r${rep}.json"
  lbr_iperf3 "$pps_file" -u -b "$PPS_BW" -l "$PPS_LEN" -t "$UDP_DUR" -c "$B_IP"
  pps="$(jq '(.end.sum_received // .end.sum) | (.packets - .lost_packets) / .seconds' "$pps_file")"
  echo "$pps" >> "$OUT/pps.csv"

  printf '  rep=%-3d RTT=%-7s ms  tput=%6.1f Mbit/s  jitter=%.4f ms  pps=%.0f\n' \
    "$rep" "$rtt_avg" "$(awk "BEGIN{print $bps/1e6}")" "$jitter" "$pps"
done

if [[ "$MODE" == "xdp" ]]; then
  { echo "--- R1"; lbr_cli "$R1_MGMT" stats; lbr_cli "$R1_MGMT" "lb status"
    echo "--- R4"; lbr_cli "$R4_MGMT" stats; lbr_cli "$R4_MGMT" "lb status"; } > "$OUT/state.txt" 2>&1
else
  { echo "--- R1"; lbr_ssh "$R1_MGMT" "ip -s link show $R1_W0; ip -s link show $R1_W1" </dev/null
    echo "--- R4"; lbr_ssh "$R4_MGMT" "ip -s link show $R4_W0; ip -s link show $R4_W1" </dev/null; } > "$OUT/state.txt" 2>&1
fi

echo
echo "Concluido. Dados brutos em: $OUT"
echo "Graficos: python3 experiments/plot_lb_perf_compare.py --xdp <dir_xdp> --baseline <dir_baseline>"
