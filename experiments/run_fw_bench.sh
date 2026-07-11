#!/usr/bin/env bash
#
# run_fw_bench.sh — Experimentos Q1/Q2: firewall XDP vs iptables.
#
# Mede throughput TCP (Gbit/s), taxa de pacotes UDP 64B (pps) e latencia
# (ping) no caminho LAN->LAN (ns1 -> ns2), variando a carga de regras
# N ∈ {0, 8, 16, 32, 64}. As N regras sao NAO-casantes (src na faixa de
# benchmarking 198.18.0.0/15) — todo pacote percorre o scan inteiro
# (pior caso) e e aceito pela politica default.
#
# Pre-requisito: laboratorio correspondente ja carregado:
#   modo xdp      -> sudo bash scripts/setup_xdp_fw_lb.sh
#   modo baseline -> sudo bash scripts/setup_baseline_router.sh --fw-rules 1
#                    (o parametro inicial e irrelevante; as regras sao
#                     reconfiguradas por este script a cada N)
#
# Uso: sudo bash run_fw_bench.sh <xdp|baseline> [REPS] [DURACAO_S]
#
set -euo pipefail

MODE="${1:?Uso: $0 <xdp|baseline> [REPS] [DURACAO_S]}"
REPS="${2:-10}"
DUR="${3:-30}"
RULE_COUNTS=(0 8 16 32 64)

[[ "$MODE" == "xdp" || "$MODE" == "baseline" ]] || {
  echo "ERRO: modo deve ser 'xdp' ou 'baseline'."; exit 1;
}

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
OUT="$SCRIPT_DIR/results/fw_${MODE}_$(date +%Y%m%d_%H%M%S)"
mkdir -p "$OUT"

SERVER_PID=""
cleanup() {
  [[ -n "$SERVER_PID" ]] && kill "$SERVER_PID" 2>/dev/null || true
}
trap cleanup EXIT

command -v iperf3 >/dev/null || { echo "ERRO: iperf3 nao instalado."; exit 1; }
command -v jq >/dev/null || { echo "ERRO: jq nao instalado."; exit 1; }

configure_rules() {  # configure_rules <N>
  local n="$1" i
  if [[ "$MODE" == "xdp" ]]; then
    xdpunk-cli fw flush >/dev/null
    for ((i = 0; i < n; i++)); do
      xdpunk-cli fw add --prio "$i" \
        --src "198.18.0.$((i % 254 + 1))/32" \
        --proto tcp --dport 9 --action drop >/dev/null
    done
  else
    ip netns exec nssw iptables -F FORWARD
    for ((i = 0; i < n; i++)); do
      ip netns exec nssw iptables -A FORWARD \
        -p tcp -s "198.18.0.$((i % 254 + 1))" --dport 9 -j DROP
    done
  fi
}

echo "== Benchmark de firewall — modo=$MODE reps=$REPS duracao=${DUR}s =="
echo "Resultados em: $OUT"

echo "Iniciando servidor iperf3 em ns2..."
ip netns exec ns2 iperf3 -s >/dev/null 2>&1 &
SERVER_PID=$!
sleep 1

for N in "${RULE_COUNTS[@]}"; do
  echo "-- N=$N regra(s) --"
  configure_rules "$N"

  # Latencia (Q2): 200 pacotes, intervalo 10 ms
  ip netns exec ns1 ping -c 200 -i 0.01 -q 10.0.0.2 \
    > "$OUT/ping_N${N}.txt" 2>&1 || true

  for ((rep = 1; rep <= REPS; rep++)); do
    [[ "$MODE" == "xdp" ]] && xdpunk-cli stats --reset >/dev/null

    # Q1a: throughput TCP
    ip netns exec ns1 iperf3 -c 10.0.0.2 -t "$DUR" --json \
      > "$OUT/tcp_N${N}_r${rep}.json"
    tput_bps=$(jq '.end.sum_received.bits_per_second' \
      "$OUT/tcp_N${N}_r${rep}.json")
    echo "  TCP  N=$N rep=$rep: $(awk "BEGIN{printf \"%.2f\", $tput_bps/1e9}") Gbit/s"

    # Q1b: pps com UDP 64 bytes (estressa o custo por pacote)
    ip netns exec ns1 iperf3 -u -b 0 -l 64 -c 10.0.0.2 -t "$DUR" --json \
      > "$OUT/udp64_N${N}_r${rep}.json"
    pkts=$(jq '.end.sum.packets' "$OUT/udp64_N${N}_r${rep}.json")
    echo "  UDP64 N=$N rep=$rep: $(awk "BEGIN{printf \"%.0f\", $pkts/$DUR}") pps"
  done

  # Snapshot do estado do firewall apos a rodada
  if [[ "$MODE" == "xdp" ]]; then
    { xdpunk-cli fw list; echo; xdpunk-cli stats; } \
      > "$OUT/state_N${N}.txt" 2>&1
  else
    ip netns exec nssw iptables -L FORWARD -v -n -x \
      > "$OUT/state_N${N}.txt" 2>&1
  fi
done

echo
echo "Concluido. Dados brutos (JSON/txt) em: $OUT"
