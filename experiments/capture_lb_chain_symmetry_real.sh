#!/usr/bin/env bash
#
# capture_lb_chain_symmetry_real.sh — F3/Q3: simetria observada do caminho
# ida/volta na topologia encadeada real (XDP ou ECMP). Versao real de
# capture_lb_chain_symmetry.sh, com o mesmo procedimento e o mesmo parser:
# N_FLUXOS conexoes TCP curtas de host1 para host2 (portas de origem fixas
# via --cport) com captura simultanea de SYN/SYN-ACK em R2 e R3 nas
# interfaces voltadas para R1 — todo pacote que atravessa R2/R3, nos dois
# sentidos, passa por elas.
#
# Como no original, os clientes iperf3 sao disparados em paralelo contra um
# unico servidor: as conexoes de controle (porta efemera) e as de dados
# (porta fixa) sao fluxos TCP independentes, cada um sujeito a sua propria
# decisao de hash em R1 (ida) e em R4 (volta).
#
# Pre-requisito: bash scripts/setup_lb_chain_real.sh <xdp|baseline>
#
# Uso: bash capture_lb_chain_symmetry_real.sh <xdp|baseline> [NUM_FLUXOS] [DURACAO_S]
#
set -euo pipefail

MODE="${1:?Uso: $0 <xdp|baseline> [NUM_FLUXOS] [DURACAO_S]}"
N_FLOWS="${2:-40}"
DUR="${3:-5}"
PORT=5201

[[ "$MODE" == "xdp" || "$MODE" == "baseline" ]] || {
  echo "ERRO: modo deve ser 'xdp' ou 'baseline'."; exit 1;
}

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
# shellcheck source=../scripts/lb_chain_real.env
source "$SCRIPT_DIR/../scripts/lb_chain_real.env"
# shellcheck source=lb_real_common.sh
source "$SCRIPT_DIR/lb_real_common.sh"

OUT="$SCRIPT_DIR/results/lb_chain_symmetry_real_${MODE}_$(date +%Y%m%d_%H%M%S)"
mkdir -p "$OUT"

lbr_require_tools
lbr_check_mode "$MODE"

R2_SSH_PID=""; R3_SSH_PID=""
stop_captures() {
  lbr_ssh "$R2_MGMT" "pkill -INT -x tcpdump" </dev/null 2>/dev/null || true
  lbr_ssh "$R3_MGMT" "pkill -INT -x tcpdump" </dev/null 2>/dev/null || true
  [[ -n "$R2_SSH_PID" ]] && wait "$R2_SSH_PID" 2>/dev/null || true
  [[ -n "$R3_SSH_PID" ]] && wait "$R3_SSH_PID" 2>/dev/null || true
  R2_SSH_PID=""; R3_SSH_PID=""
}
trap 'stop_captures; lbr_stop_server' EXIT

echo "Iniciando servidor iperf3 em host2 ($B_IP:$PORT)..."
lbr_restart_server

SYN_FILTER="tcp port $PORT and (tcp[tcpflags] & tcp-syn) != 0"
echo "Iniciando capturas em R2 ($R2_A) e R3 ($R3_A)..."
lbr_ssh "$R2_MGMT" "tcpdump -l -ni $R2_A -n -tt '$SYN_FILTER' 2>/dev/null" > "$OUT/r2.txt" </dev/null &
R2_SSH_PID=$!
lbr_ssh "$R3_MGMT" "tcpdump -l -ni $R3_A -n -tt '$SYN_FILTER' 2>/dev/null" > "$OUT/r3.txt" </dev/null &
R3_SSH_PID=$!
sleep 3

echo "Gerando $N_FLOWS fluxos TCP distintos (host1 -> host2:$PORT)..."
CLIENT_PIDS=()
for ((i = 0; i < N_FLOWS; i++)); do
  iperf3 -4 -c "$B_IP" -p "$PORT" -t "$DUR" \
    -B "$A_IP" --cport "$((10000 + i))" >/dev/null 2>&1 </dev/null &
  CLIENT_PIDS+=("$!")
done
wait "${CLIENT_PIDS[@]}" || true

sleep 1
stop_captures

echo
python3 "$SCRIPT_DIR/parse_lb_chain_symmetry.py" \
  "$OUT/r2.txt" "$OUT/r3.txt" "$A_IP" "$B_IP" | tee "$OUT/symmetry_report.txt"
echo
echo "Dados brutos em: $OUT"
