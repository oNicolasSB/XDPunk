#!/usr/bin/env bash
#
# run_fw_capacity_bench_real.sh — Capacidade do firewall XDP (0/1000/2000
# regras) na topologia de 3 VMs reais (ver scripts/setup_xdp_fw_real.sh).
#
# Roda no CLIENTE (h1, 10.0.0.1). O servidor iperf3 (h2, 10.0.0.2) e o
# plano de controle do switch sao acionados via SSH pela rede de gerencia,
# e so entre rodadas — durante a medicao o switch so executa o XDP.
#
# Mesma metodologia de run_fw_capacity_bench.sh (lab em netns): regras
# NAO-casantes (`fw loadgen N`), todo pacote percorre o scan completo e cai
# na politica default ALLOW. Metricas por repeticao:
#   - latencia : RTT medio de `ping -c 200 -i 0.01`
#   - throughput: iperf3 TCP, TCP_DUR s (bits/s no receptor)
#   - jitter    : iperf3 UDP a 200 Mbit/s, UDP_DUR s (jitter_ms do receptor)
#   - pps       : iperf3 UDP 64 B a 2 Gbit/s (saturante), UDP_DUR s —
#                 pacotes entregues/s no receptor. Em enlace de 1 GbE o TCP
#                 com MTU 1500 (~81 kpps) nao satura o scan; pacotes pequenos
#                 sim, entao esta e a metrica que expoe o custo do firewall.
#
# Pre-requisitos: switch configurado (setup_xdp_fw_real.sh), IPs 10.0.0.x
# nas ens19 dos hosts, vizinhos estaticos apontando para os MACs do switch,
# iperf3 + jq em h1/h2 e SSH sem senha h1 -> sw/h2.
#
# Uso: bash run_fw_capacity_bench_real.sh [REPS] [TCP_DUR_S] [UDP_DUR_S]
# Variaveis: SW_SSH, SRV_SSH, SRV_IP, RULE_COUNTS ("0 1000 2000").
#
set -euo pipefail

REPS="${1:-20}"
TCP_DUR="${2:-30}"
UDP_DUR="${3:-10}"
UDP_BW="200M"
PPS_BW="2G"
PPS_LEN=64
read -r -a RULE_COUNTS <<< "${RULE_COUNTS:-0 1000 2000}"

SW_SSH="${SW_SSH:-nicolas@10.20.241.136}"
SRV_SSH="${SRV_SSH:-nicolas@10.20.241.134}"
SRV_IP="${SRV_IP:-10.0.0.2}"

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
OUT="$SCRIPT_DIR/results/fw_capacity_real_$(date +%Y%m%d_%H%M%S)"
mkdir -p "$OUT"

for c in iperf3 jq ping ssh; do
  command -v "$c" >/dev/null || { echo "ERRO: '$c' nao instalado."; exit 1; }
done

sw_cli() {  # sw_cli <args da xdpunk-cli...>
  ssh -o BatchMode=yes "$SW_SSH" \
    sudo env PATH=/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin \
    xdpunk-cli --netns xdpunk_root "$@"
}

restart_iperf_server() {
  ssh -o BatchMode=yes "$SRV_SSH" \
    'pkill -x iperf3; sleep 0.5; iperf3 -s -4 -D >/dev/null 2>&1' || true
  sleep 1
}
trap 'ssh -o BatchMode=yes "$SRV_SSH" "pkill -x iperf3" 2>/dev/null || true' EXIT

# "-4 -i 0": evita o bug de select() do iperf3 com relatorio de intervalo
# (ver run_fw_capacity_bench.sh); retries como rede de seguranca.
run_iperf3() {  # run_iperf3 <arquivo_json_saida> <args do iperf3...>
  local out="$1"; shift
  local attempt ec err
  for ((attempt = 1; attempt <= 15; attempt++)); do
    ec=0
    iperf3 -4 -i 0 --json "$@" > "$out" 2>"${out}.stderr" || ec=$?
    err="$(jq -r '.error // empty' "$out" 2>/dev/null)" || err="invalid_json"
    if [[ "$ec" -eq 0 && -z "$err" ]]; then
      rm -f "${out}.stderr"
      return 0
    fi
    echo "  [aviso] iperf3 falhou (tentativa $attempt, exit=$ec, error='$err')" >&2
    restart_iperf_server
  done
  echo "  [ERRO] iperf3 falhou apos 15 tentativas: $out" >&2
  return 1
}

extract_ping_avg() {  # RTT medio (ms) ou NaN em 100% de perda
  local line
  line="$(grep 'rtt min/avg/max/mdev' "$1" || true)"
  [[ -z "$line" ]] && { echo "NaN"; return; }
  echo "$line" | awk -F'= ' '{print $2}' | cut -d'/' -f2
}

# Contexto do experimento (para a monografia / reprodutibilidade)
{
  echo "date: $(date -Is)"
  echo "client: $(hostname) $(uname -r)"
  echo "reps=$REPS tcp_dur=$TCP_DUR udp_dur=$UDP_DUR udp_bw=$UDP_BW pps_bw=$PPS_BW pps_len=$PPS_LEN"
  echo "rule_counts: ${RULE_COUNTS[*]}"
  echo "--- switch"
  ssh -o BatchMode=yes "$SW_SSH" 'hostname; uname -r; nproc; ip -d link show ens19 | grep -o "prog/xdp[a-z]* id [0-9]*"; ip -d link show ens20 | grep -o "prog/xdp[a-z]* id [0-9]*"'
  sw_cli map dump
} > "$OUT/env.txt" 2>&1

echo "== Benchmark de capacidade do firewall XDP (3 VMs) =="
echo "N ∈ {${RULE_COUNTS[*]}}, $REPS repeticao(oes) — resultados em $OUT"
restart_iperf_server

for N in "${RULE_COUNTS[@]}"; do
  echo "-- N=$N regra(s) --"
  sw_cli fw flush >/dev/null
  [[ "$N" -gt 0 ]] && sw_cli fw loadgen "$N" >/dev/null
  sw_cli stats --reset >/dev/null
  restart_iperf_server

  for m in throughput latency jitter pps; do : > "$OUT/${m}_N${N}.csv"; done

  for ((rep = 1; rep <= REPS; rep++)); do
    ping_file="$OUT/ping_N${N}_r${rep}.txt"
    ping -c 200 -i 0.01 -q "$SRV_IP" > "$ping_file" 2>&1 || true
    rtt_avg="$(extract_ping_avg "$ping_file")"
    echo "$rtt_avg" >> "$OUT/latency_N${N}.csv"

    tcp_file="$OUT/tcp_N${N}_r${rep}.json"
    run_iperf3 "$tcp_file" -c "$SRV_IP" -t "$TCP_DUR"
    bps="$(jq '.end.sum_received.bits_per_second' "$tcp_file")"
    echo "$bps" >> "$OUT/throughput_N${N}.csv"

    udp_file="$OUT/udp_N${N}_r${rep}.json"
    run_iperf3 "$udp_file" -u -b "$UDP_BW" -t "$UDP_DUR" -c "$SRV_IP"
    jitter="$(jq '.end.sum_received.jitter_ms // .end.sum.jitter_ms' "$udp_file")"
    echo "$jitter" >> "$OUT/jitter_N${N}.csv"

    pps_file="$OUT/pps_N${N}_r${rep}.json"
    run_iperf3 "$pps_file" -u -b "$PPS_BW" -l "$PPS_LEN" -t "$UDP_DUR" -c "$SRV_IP"
    pps="$(jq '(.end.sum_received // .end.sum) | (.packets - .lost_packets) / .seconds' "$pps_file")"
    echo "$pps" >> "$OUT/pps_N${N}.csv"

    printf '  rep=%-3d RTT=%-7s ms  tput=%6.1f Mbit/s  jitter=%.4f ms  pps=%.0f\n' \
      "$rep" "$rtt_avg" "$(awk "BEGIN{print $bps/1e6}")" "$jitter" "$pps"
  done

  { sw_cli fw list | tail -3; echo; sw_cli stats; } > "$OUT/state_N${N}.txt" 2>&1
done

sw_cli fw flush >/dev/null
echo
echo "Concluido. Dados brutos em: $OUT"
echo "Graficos: python3 $SCRIPT_DIR/plot_fw_capacity.py $OUT"
