#!/usr/bin/env bash
#
# capture_lb_chain_symmetry.sh — F3/Q3: mede a simetria observada do
# caminho ida/volta na topologia encadeada. Gera N_FLUXOS conexoes TCP
# curtas e distintas (portas de origem fixas via --cport do iperf3) de
# nsA para nsB, capturando simultaneamente em nsr2 (vethR21) e nsr3
# (vethR31) — qualquer pacote que atravesse R2/R3, em qualquer sentido,
# passa pela interface voltada para R1, entao uma captura por roteador
# basta.
#
# So SYN/SYN-ACK sao capturados (bastam para identificar a direcao de
# cada fluxo pelo IP de origem) — capturar tambem os dados inflaria os
# arquivos de captura sem necessidade, ja que o iperf3 satura o link.
# Cada invocacao do iperf3 abre 2 conexoes TCP para a porta $PORT: a de
# controle (porta de origem efemera) e a de dados (porta de origem fixada
# por --cport) — por isso o numero de "fluxos" observados no relatorio
# final costuma ser maior que N_FLUXOS, incluindo tambem as conexoes de
# controle (o que e correto: cada conexao TCP e um fluxo independente
# sujeito a sua propria decisao de hash no LB).
#
# Pre-requisito: sudo bash scripts/setup_xdp_lb_chain.sh
#
# Uso: sudo bash capture_lb_chain_symmetry.sh [NUM_FLUXOS] [DURACAO_S]
#
set -euo pipefail

N_FLOWS="${1:-40}"
DUR="${2:-5}"
A_IP="10.10.1.1"
B_IP="10.10.2.1"
PORT=5201

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
OUT="$SCRIPT_DIR/results/lb_chain_symmetry_$(date +%Y%m%d_%H%M%S)"
mkdir -p "$OUT"

command -v tcpdump >/dev/null || { echo "ERRO: tcpdump nao instalado."; exit 1; }

SERVER_PID=""; R2_PID=""; R3_PID=""
cleanup() {
  [[ -n "$SERVER_PID" ]] && kill "$SERVER_PID" 2>/dev/null || true
  [[ -n "$R2_PID" ]] && ip netns exec nsr2 kill "$R2_PID" 2>/dev/null || true
  [[ -n "$R3_PID" ]] && ip netns exec nsr3 kill "$R3_PID" 2>/dev/null || true
}
trap cleanup EXIT

echo "Iniciando servidor iperf3 em nsB ($B_IP:$PORT)..."
ip netns exec nsB iperf3 -s -B "$B_IP" -p "$PORT" >/dev/null 2>&1 &
SERVER_PID=$!
sleep 1

SYN_FILTER="tcp port $PORT and (tcp[tcpflags] & tcp-syn) != 0"
echo "Iniciando capturas em R2 (vethR21) e R3 (vethR31)..."
ip netns exec nsr2 tcpdump -ni vethR21 -n -tt "$SYN_FILTER" \
  > "$OUT/r2.txt" 2>/dev/null &
R2_PID=$!
ip netns exec nsr3 tcpdump -ni vethR31 -n -tt "$SYN_FILTER" \
  > "$OUT/r3.txt" 2>/dev/null &
R3_PID=$!
sleep 1

echo "Gerando $N_FLOWS fluxos TCP distintos (nsA -> nsB:$PORT)..."
CLIENT_PIDS=()
for ((i = 0; i < N_FLOWS; i++)); do
  ip netns exec nsA iperf3 -c "$B_IP" -p "$PORT" -t "$DUR" \
    -B "$A_IP" --cport "$((10000 + i))" >/dev/null 2>&1 &
  CLIENT_PIDS+=("$!")
done
# wait so' pelos clientes: o bare `wait` tambem esperaria o servidor
# iperf3 (SERVER_PID), que roda indefinidamente e travaria o script.
# `|| true`: um fluxo individual falhar nao deve abortar a medicao (set -e).
wait "${CLIENT_PIDS[@]}" || true

sleep 1
kill "$R2_PID" "$R3_PID" 2>/dev/null || true
wait "$R2_PID" "$R3_PID" 2>/dev/null || true
R2_PID=""; R3_PID=""

echo
python3 "$SCRIPT_DIR/parse_lb_chain_symmetry.py" \
  "$OUT/r2.txt" "$OUT/r3.txt" "$A_IP" "$B_IP" | tee "$OUT/symmetry_report.txt"
echo
echo "Dados brutos em: $OUT"
