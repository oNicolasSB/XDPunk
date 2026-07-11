#!/usr/bin/env bash
#
# run_lb_bench.sh — Experimento Q3: LB de links WAN XDP vs ECMP do kernel.
#
# Mede, no caminho LAN -> "internet" (ns1 -> nsext 192.0.2.10), com
# P ∈ {2, 4, 8, 16} fluxos TCP paralelos:
#   - throughput agregado (iperf3 --json);
#   - distribuicao de trafego por link WAN (contadores BPF no modo xdp;
#     contadores de interface no modo baseline) — insumo para o indice
#     de justica de Jain.
#
# Pre-requisito: laboratorio correspondente ja carregado:
#   modo xdp      -> sudo bash scripts/setup_xdp_fw_lb.sh
#   modo baseline -> sudo bash scripts/setup_baseline_router.sh --ecmp
#
# Uso: sudo bash run_lb_bench.sh <xdp|baseline> [REPS] [DURACAO_S]
#
set -euo pipefail

MODE="${1:?Uso: $0 <xdp|baseline> [REPS] [DURACAO_S]}"
REPS="${2:-10}"
DUR="${3:-30}"
STREAMS=(2 4 8 16)
EXT_IP="192.0.2.10"

[[ "$MODE" == "xdp" || "$MODE" == "baseline" ]] || {
  echo "ERRO: modo deve ser 'xdp' ou 'baseline'."; exit 1;
}

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
OUT="$SCRIPT_DIR/results/lb_${MODE}_$(date +%Y%m%d_%H%M%S)"
mkdir -p "$OUT"

SERVER_PID=""
cleanup() {
  [[ -n "$SERVER_PID" ]] && kill "$SERVER_PID" 2>/dev/null || true
}
trap cleanup EXIT

command -v iperf3 >/dev/null || { echo "ERRO: iperf3 nao instalado."; exit 1; }
command -v jq >/dev/null || { echo "ERRO: jq nao instalado."; exit 1; }

snapshot_links() {  # snapshot_links <arquivo>
  if [[ "$MODE" == "xdp" ]]; then
    xdpunk-cli lb status > "$1" 2>&1
  else
    ip -n nssw -s -j link show > "$1" 2>&1
  fi
}

echo "== Benchmark de LB WAN — modo=$MODE reps=$REPS duracao=${DUR}s =="
echo "Resultados em: $OUT"

echo "Iniciando servidor iperf3 em nsext ($EXT_IP)..."
ip netns exec nsext iperf3 -s -B "$EXT_IP" >/dev/null 2>&1 &
SERVER_PID=$!
sleep 1

for P in "${STREAMS[@]}"; do
  echo "-- P=$P fluxos paralelos --"
  for ((rep = 1; rep <= REPS; rep++)); do
    if [[ "$MODE" == "xdp" ]]; then
      xdpunk-cli stats --reset >/dev/null
    else
      # Contadores de interface sao cumulativos: snapshot antes e depois,
      # a distribuicao por link e a diferenca entre os dois.
      snapshot_links "$OUT/links_P${P}_r${rep}_before.txt"
    fi

    ip netns exec ns1 iperf3 -c "$EXT_IP" -P "$P" -t "$DUR" --json \
      > "$OUT/tcp_P${P}_r${rep}.json"
    tput_bps=$(jq '.end.sum_received.bits_per_second' \
      "$OUT/tcp_P${P}_r${rep}.json")
    echo "  P=$P rep=$rep: $(awk "BEGIN{printf \"%.2f\", $tput_bps/1e9}") Gbit/s agregado"

    snapshot_links "$OUT/links_P${P}_r${rep}_after.txt"
  done
done

echo
echo "Concluido. Dados brutos (JSON/txt) em: $OUT"
echo "Indice de justica de Jain: J = (sum b_i)^2 / (n * sum b_i^2),"
echo "com b_i = bytes por link WAN extraidos dos snapshots."
