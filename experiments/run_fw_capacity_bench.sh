#!/usr/bin/env bash
#
# run_fw_capacity_bench.sh — Capacidade do firewall XDP: 0 / 1000 / 2000
# regras carregadas, medindo throughput, latencia e jitter no caminho
# LAN->LAN (ns1 10.0.0.1 -> ns2 10.0.0.2), sem passar pelo LB de WAN.
#
# Diferente de run_fw_bench.sh (compara XDP vs iptables em N pequenos,
# {0,8,16,32,64}, com throughput/pps por N): aqui o objetivo e caracterizar
# o CUSTO DE ESCALA do scan linear do firewall XDP em si, em N grandes
# (0, 1000, 2000), com 20 repeticoes independentes por metrica/cenario
# para permitir analise estatistica (media, desvio-padrao, outliers).
#
# As N regras sao carregadas via `xdpunk-cli fw loadgen N`: NAO-casantes
# de proposito (src sequencial em 198.18.0.0/15, TCP, dport 9, DROP) —
# todo pacote de teste percorre o scan completo e cai na politica default
# ALLOW. Isola o custo puro do scan em funcao de N.
#
# Pre-requisito: laboratorio Fase 2 ja carregado:
#   sudo bash scripts/setup_xdp_fw_lb.sh
#
# Uso: sudo bash run_fw_capacity_bench.sh [REPS] [TCP_DUR_S] [UDP_DUR_S]
#
set -euo pipefail

REPS="${1:-20}"
TCP_DUR="${2:-30}"
UDP_DUR="${3:-10}"
UDP_BW="200M"
RULE_COUNTS=(0 1000 2000)

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
OUT="$SCRIPT_DIR/results/fw_capacity_$(date +%Y%m%d_%H%M%S)"
mkdir -p "$OUT"

command -v iperf3 >/dev/null || { echo "ERRO: iperf3 nao instalado."; exit 1; }
command -v jq >/dev/null || { echo "ERRO: jq nao instalado."; exit 1; }
command -v xdpunk-cli >/dev/null || {
  echo "ERRO: xdpunk-cli nao encontrado. Instale com:"
  echo "  sudo pip3 install $SCRIPT_DIR/../userspace/"
  exit 1
}
ip netns list | grep -q '^ns1' || {
  echo "ERRO: namespace ns1 nao existe. Rode antes:"
  echo "  sudo bash $SCRIPT_DIR/../scripts/setup_xdp_fw_lb.sh"
  exit 1
}

SERVER_PID=""
cleanup() {
  [[ -n "$SERVER_PID" ]] && kill "$SERVER_PID" 2>/dev/null || true
}
trap cleanup EXIT

# Causa raiz confirmada (ver historico): o iperf3 tem um bug conhecido
# (select failed: Bad file descriptor -> "the server has terminated") que
# o relatorio periodico de intervalo (-i, default 1s) em socket dual-stack
# expoe quando o teste roda mais devagar/mais tempo que o pedido — exatamente
# o que acontece em N alto (scan linear do firewall degrada o throughput por
# fluxo). "-4 -i 0" (IPv4 puro, sem relatorio de intervalo) elimina o bug
# (validado: 10/10 sucesso em N=2000, duracao exata, sem esse fix a taxa de
# falha passava de 90%). restart_iperf_server/run_iperf3 seguem como rede de
# seguranca para qualquer outra falha transitoria, mas nao devem mais ser
# necessarios na pratica.
restart_iperf_server() {
  [[ -n "$SERVER_PID" ]] && kill "$SERVER_PID" 2>/dev/null
  wait "$SERVER_PID" 2>/dev/null || true
  ip netns exec ns2 iperf3 -s -4 >/dev/null 2>&1 &
  SERVER_PID=$!
  sleep 1
}

run_iperf3() {  # run_iperf3 <arquivo_json_saida> <args do iperf3...>
  local out="$1"; shift
  local attempt ec err
  local -r max_attempts=15
  for ((attempt = 1; attempt <= max_attempts; attempt++)); do
    ec=0
    ip netns exec ns1 iperf3 -4 -i 0 --json "$@" > "$out" 2>"${out}.stderr" || ec=$?
    err="$(jq -r '.error // empty' "$out" 2>/dev/null)" || err="invalid_json"
    if [[ "$ec" -eq 0 && -z "$err" ]]; then
      rm -f "${out}.stderr"
      return 0
    fi
    echo "  [aviso] iperf3 falhou (tentativa $attempt/$max_attempts, exit=$ec, error='$err') — reiniciando servidor e tentando de novo" >&2
    restart_iperf_server
  done
  echo "  [ERRO] iperf3 continuou falhando apos $max_attempts tentativas: $out" >&2
  return 1
}

echo "== Benchmark de capacidade do firewall XDP =="
echo "N ∈ {${RULE_COUNTS[*]}} regra(s), $REPS repeticao(oes) por cenario"
echo "Resultados em: $OUT"

echo "Iniciando servidor iperf3 em ns2..."
restart_iperf_server

extract_ping_avg() {  # extract_ping_avg <arquivo> -> RTT medio (ms)
  local line
  line="$(grep 'rtt min/avg/max/mdev' "$1" || true)"
  if [[ -z "$line" ]]; then
    echo "NaN"  # 100% de perda: sem linha de resumo rtt
    return
  fi
  echo "$line" | awk -F'= ' '{print $2}' | cut -d'/' -f2
}

for N in "${RULE_COUNTS[@]}"; do
  echo "-- N=$N regra(s) --"
  xdpunk-cli fw flush >/dev/null
  xdpunk-cli fw loadgen "$N" >/dev/null
  xdpunk-cli stats --reset >/dev/null
  restart_iperf_server

  : > "$OUT/throughput_N${N}.csv"
  : > "$OUT/latency_N${N}.csv"
  : > "$OUT/jitter_N${N}.csv"

  for ((rep = 1; rep <= REPS; rep++)); do
    # Latencia: RTT medio de 200 pacotes (intervalo 10 ms)
    ping_file="$OUT/ping_N${N}_r${rep}.txt"
    ip netns exec ns1 ping -c 200 -i 0.01 -q 10.0.0.2 > "$ping_file" 2>&1 || true
    rtt_avg="$(extract_ping_avg "$ping_file")"
    echo "$rtt_avg" >> "$OUT/latency_N${N}.csv"

    # Throughput: TCP, DUR segundos
    tcp_file="$OUT/tcp_N${N}_r${rep}.json"
    run_iperf3 "$tcp_file" -c 10.0.0.2 -t "$TCP_DUR"
    bps="$(jq '.end.sum_received.bits_per_second' "$tcp_file")"
    echo "$bps" >> "$OUT/throughput_N${N}.csv"

    # Jitter: UDP, bitrate fixo (nao satura o link, isola o jitter de
    # enfileiramento/scan e nao o de congestionamento)
    udp_file="$OUT/udp_N${N}_r${rep}.json"
    run_iperf3 "$udp_file" -u -b "$UDP_BW" -t "$UDP_DUR" -c 10.0.0.2
    jitter="$(jq '.end.sum.jitter_ms' "$udp_file")"
    echo "$jitter" >> "$OUT/jitter_N${N}.csv"

    printf '  rep=%-3d RTT=%-8s ms  throughput=%-6.2f Gbit/s  jitter=%s ms\n' \
      "$rep" "$rtt_avg" "$(awk "BEGIN{printf \"%.2f\", $bps/1e9}")" "$jitter"
  done

  # Snapshot do estado do firewall/contadores apos a rodada
  { xdpunk-cli fw list; echo; xdpunk-cli stats; } > "$OUT/state_N${N}.txt" 2>&1
done

echo
echo "Concluido. Dados brutos (JSON/txt/csv) em: $OUT"
echo "Gerar graficos com:"
echo "  python3 $SCRIPT_DIR/plot_fw_capacity.py $OUT"
