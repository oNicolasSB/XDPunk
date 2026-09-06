#!/usr/bin/env bash
#
# run_fw_throughput_sweep.sh — Varredura fina de N para checar linearidade
# da queda de throughput TCP em funcao do numero de regras de firewall.
#
# Diferente de run_fw_capacity_bench.sh (3 pontos N∈{0,1000,2000}, 3
# metricas — throughput/latencia/jitter, 20 reps cada): aqui o objetivo e
# so o THROUGHPUT, mas numa grade fina de N (passo configuravel, default
# 200) para visualizar a forma da curva throughput x N e decidir se a
# relacao e linear (ajuste de regressao feito por plot_fw_throughput_sweep.py).
#
# Mesmo padrao de regras nao-casantes de sempre (fw loadgen): src
# sequencial em 198.18.0.0/15, TCP, dport 9, DROP.
#
# Pre-requisito: laboratorio Fase 2 ja carregado:
#   sudo bash scripts/setup_xdp_fw_lb.sh
#
# Uso: sudo bash run_fw_throughput_sweep.sh [START=0] [END=2000] [STEP=200] \
#                                            [REPS=10] [TCP_DUR_S=15]
#
set -euo pipefail

START="${1:-0}"
END="${2:-2000}"
STEP="${3:-200}"
REPS="${4:-10}"
TCP_DUR="${5:-15}"

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
OUT="$SCRIPT_DIR/results/fw_throughput_sweep_$(date +%Y%m%d_%H%M%S)"
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

N_VALUES=()
for ((n = START; n <= END; n += STEP)); do
  N_VALUES+=("$n")
done

echo "== Varredura de throughput vs N (linearidade) =="
echo "N ∈ {${N_VALUES[*]}} regra(s), $REPS repeticao(oes) por ponto, ${TCP_DUR}s/repeticao"
echo "Resultados em: $OUT"

echo "Iniciando servidor iperf3 em ns2..."
restart_iperf_server

for N in "${N_VALUES[@]}"; do
  echo "-- N=$N regra(s) --"
  xdpunk-cli fw flush >/dev/null
  xdpunk-cli fw loadgen "$N" >/dev/null
  xdpunk-cli stats --reset >/dev/null
  restart_iperf_server

  : > "$OUT/throughput_N${N}.csv"

  for ((rep = 1; rep <= REPS; rep++)); do
    tcp_file="$OUT/tcp_N${N}_r${rep}.json"
    run_iperf3 "$tcp_file" -c 10.0.0.2 -t "$TCP_DUR"
    bps="$(jq '.end.sum_received.bits_per_second' "$tcp_file")"
    echo "$bps" >> "$OUT/throughput_N${N}.csv"
  done

  mean_gbps="$(awk '{s+=$1; c++} END{printf "%.2f", (s/c)/1e9}' \
    "$OUT/throughput_N${N}.csv")"
  echo "  media: $mean_gbps Gbit/s"
done

echo
echo "Concluido. Dados brutos (JSON/csv) em: $OUT"
echo "Gerar grafico com:"
echo "  python3 $SCRIPT_DIR/plot_fw_throughput_sweep.py $OUT"
