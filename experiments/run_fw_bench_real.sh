#!/usr/bin/env bash
#
# run_fw_bench_real.sh — firewall XDP vs iptables na topologia de 3 VMs.
#
# Versao para maquinas reais de run_fw_bench.sh (mesmos arquivos de saida,
# lidos por plot_fw_bench.py e plot_fw_throughput_compare.py):
#   tcp_N{n}_r{rep}.json   iperf3 TCP           (throughput)
#   udp64_N{n}_r{rep}.json iperf3 UDP 64 B -b 0 (taxa de pacotes)
#   ping_N{n}.txt          ping -c 200 -i 0.01  (latencia)
#
# Roda no CLIENTE (h1). As N regras sao NAO-casantes (TCP, src em
# 198.18.0.0/15, dport 9, DROP) — todo pacote percorre a lista inteira e e
# aceito pela politica default. O switch precisa estar no modo correspondente:
#   xdp      -> scripts/setup_xdp_fw_real.sh
#   baseline -> scripts/setup_baseline_router_real.sh
#
# Uso: bash run_fw_bench_real.sh <xdp|baseline> [REPS] [DURACAO_S]
# Variaveis: RULE_COUNTS, SW_SSH, SRV_SSH, SRV_IP.
#
set -euo pipefail

MODE="${1:?Uso: $0 <xdp|baseline> [REPS] [DURACAO_S]}"
REPS="${2:-10}"
DUR="${3:-15}"
read -r -a RULE_COUNTS <<< "${RULE_COUNTS:-0 8 16 32 64 250 500 1000 1500 2000}"

SW_SSH="${SW_SSH:-nicolas@10.20.241.136}"
SRV_SSH="${SRV_SSH:-nicolas@10.20.241.134}"
SRV_IP="${SRV_IP:-10.0.0.2}"

[[ "$MODE" == "xdp" || "$MODE" == "baseline" ]] || {
  echo "ERRO: modo deve ser 'xdp' ou 'baseline'."; exit 1;
}

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
OUT="$SCRIPT_DIR/results/fw_real_${MODE}_$(date +%Y%m%d_%H%M%S)"
mkdir -p "$OUT"

for c in iperf3 jq ping ssh; do
  command -v "$c" >/dev/null || { echo "ERRO: '$c' nao instalado."; exit 1; }
done

sw() {  # sw <comando remoto (string)> — executa como root no switch
  ssh -o BatchMode=yes "$SW_SSH" \
    "sudo env PATH=/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin bash -c $(printf '%q' "$1")"
}

# Confere que o switch esta no modo pedido (evita medir o modo errado).
if [[ "$MODE" == "xdp" ]]; then
  sw 'ip link show ens19 | grep -q "prog/xdp"' || {
    echo "ERRO: XDP nao esta anexado no switch (rode setup_xdp_fw_real.sh)."; exit 1; }
else
  sw '! ip link show ens19 | grep -q "prog/xdp" && [ "$(sysctl -n net.ipv4.ip_forward)" = 1 ]' || {
    echo "ERRO: switch nao esta no modo baseline (rode setup_baseline_router_real.sh)."; exit 1; }
fi

configure_rules() {  # configure_rules <N>
  local n="$1"
  if [[ "$MODE" == "xdp" ]]; then
    sw "xdpunk-cli --netns xdpunk_root fw flush >/dev/null"
    [[ "$n" -gt 0 ]] && sw "xdpunk-cli --netns xdpunk_root fw loadgen $n >/dev/null"
  else
    # iptables-restore --noflush: carga em lote (2000 x `iptables -A` levaria
    # minutos). Mesmo formato de regra de run_fw_bench.sh.
    sw "iptables -F FORWARD"
    [[ "$n" -gt 0 ]] && sw "awk -v n=$n 'BEGIN { print \"*filter\";
        for (i = 1; i <= n; i++)
          printf \"-A FORWARD -p tcp -s 198.18.%d.%d/32 --dport 9 -j DROP\\n\", int(i / 254), i % 254 + 1;
        print \"COMMIT\" }' | iptables-restore --noflush"
  fi
  return 0
}

rule_count() {
  if [[ "$MODE" == "xdp" ]]; then
    sw "xdpunk-cli --netns xdpunk_root fw list" | grep -c 'DROP' || true
  else
    sw "iptables -S FORWARD" | grep -c '^-A FORWARD' || true
  fi
}

restart_iperf_server() {
  ssh -o BatchMode=yes "$SRV_SSH" \
    'pkill -x iperf3; sleep 0.5; iperf3 -s -4 -D >/dev/null 2>&1' || true
  sleep 1
}
trap 'ssh -o BatchMode=yes "$SRV_SSH" "pkill -x iperf3" 2>/dev/null || true' EXIT

# "-4 -i 0": evita o bug de select() do iperf3 (ver run_fw_capacity_bench.sh).
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

{
  echo "date: $(date -Is)"
  echo "mode: $MODE reps=$REPS dur=$DUR"
  echo "rule_counts: ${RULE_COUNTS[*]}"
  echo "client: $(hostname) $(uname -r)"
  echo "--- switch"
  sw 'hostname; uname -r; nproc; iptables -V; sysctl -n net.ipv4.ip_forward;
      ip -br link show ens19; ip -br link show ens20;
      ip link show ens19 | grep -o "prog/xdp[a-z]* id [0-9]*" || echo "sem XDP"'
} > "$OUT/env.txt" 2>&1

echo "== Firewall XDP vs iptables (3 VMs) — modo=$MODE reps=$REPS dur=${DUR}s =="
echo "N ∈ {${RULE_COUNTS[*]}} — resultados em $OUT"
restart_iperf_server

for N in "${RULE_COUNTS[@]}"; do
  configure_rules "$N"
  loaded="$(rule_count)"
  echo "-- N=$N regra(s) (carregadas: $loaded) --"
  [[ "$loaded" -eq "$N" ]] || { echo "ERRO: esperado $N regras, switch tem $loaded."; exit 1; }
  [[ "$MODE" == "xdp" ]] && sw "xdpunk-cli --netns xdpunk_root stats --reset >/dev/null"
  restart_iperf_server

  ping -c 200 -i 0.01 -q "$SRV_IP" > "$OUT/ping_N${N}.txt" 2>&1 || true

  for ((rep = 1; rep <= REPS; rep++)); do
    tcp_file="$OUT/tcp_N${N}_r${rep}.json"
    run_iperf3 "$tcp_file" -c "$SRV_IP" -t "$DUR"
    tput="$(jq '.end.sum_received.bits_per_second' "$tcp_file")"

    udp_file="$OUT/udp64_N${N}_r${rep}.json"
    run_iperf3 "$udp_file" -u -b 0 -l 64 -c "$SRV_IP" -t "$DUR"
    pps="$(jq '(.end.sum_received // .end.sum) | (.packets - .lost_packets) / .seconds' "$udp_file")"

    printf '  rep=%-3d tput=%7.1f Mbit/s  pps(recebido)=%.0f\n' \
      "$rep" "$(awk "BEGIN{print $tput/1e6}")" "$pps"
  done

  if [[ "$MODE" == "xdp" ]]; then
    sw "xdpunk-cli --netns xdpunk_root stats" > "$OUT/state_N${N}.txt" 2>&1
  else
    sw "iptables -L FORWARD -v -n -x | head -5; echo ...; iptables -L FORWARD -n | wc -l" \
      > "$OUT/state_N${N}.txt" 2>&1
  fi
done

configure_rules 0
echo
echo "Concluido. Dados brutos em: $OUT"
