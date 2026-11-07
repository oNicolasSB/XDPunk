# lb_real_common.sh — funcoes compartilhadas pelos benchmarks do LB
# encadeado em VMs reais (run_lb_chain_bench_real.sh,
# run_lb_perf_bench_real.sh, capture_lb_chain_symmetry_real.sh).
# Requer scripts/lb_chain_real.env carregado antes (lbr_ssh, enderecos).

lbr_require_tools() {
  local c
  for c in iperf3 jq ping ssh; do
    command -v "$c" >/dev/null || { echo "ERRO: '$c' nao instalado."; exit 1; }
  done
}

lbr_cli() {  # lbr_cli <ip_gerencia> <args da xdpunk-cli (string)>
  lbr_ssh "$1" "xdpunk-cli --netns xdpunk_root $2" </dev/null
}

# Confere que R1/R4 estao no modo pedido (evita medir o modo errado).
lbr_check_mode() {  # lbr_check_mode <xdp|baseline>
  local r dev
  for r in "$R1_MGMT:$R1_LAN" "$R4_MGMT:$R4_LAN"; do
    dev="${r#*:}"; r="${r%%:*}"
    if [[ "$1" == "xdp" ]]; then
      lbr_ssh "$r" "ip link show $dev | grep -q prog/xdp" </dev/null || {
        echo "ERRO: XDP nao anexado em $r ($dev). Rode: bash scripts/setup_lb_chain_real.sh xdp"; exit 1; }
    else
      lbr_ssh "$r" "! ip link show $dev | grep -q prog/xdp && [ \"\$(sysctl -n net.ipv4.ip_forward)\" = 1 ]" </dev/null || {
        echo "ERRO: $r nao esta no modo baseline. Rode: bash scripts/setup_lb_chain_real.sh baseline"; exit 1; }
    fi
  done
}

lbr_restart_server() {
  ssh -o BatchMode=yes "$SSH_USER@$H2_MGMT" \
    "pkill -x iperf3; sleep 0.5; iperf3 -s -4 -D -B $B_IP >/dev/null 2>&1" </dev/null || true
  sleep 1
}

lbr_stop_server() {
  ssh -o BatchMode=yes "$SSH_USER@$H2_MGMT" "pkill -x iperf3" </dev/null 2>/dev/null || true
}

# "-4 -i 0": evita o bug de select() do iperf3 com relatorio de intervalo
# (ver run_fw_capacity_bench.sh); retries como rede de seguranca.
lbr_iperf3() {  # lbr_iperf3 <arquivo_json_saida> <args do iperf3...>
  local out="$1"; shift
  local attempt ec err
  for ((attempt = 1; attempt <= 15; attempt++)); do
    ec=0
    iperf3 -4 -i 0 --json "$@" > "$out" 2>"${out}.stderr" </dev/null || ec=$?
    err="$(jq -r '.error // empty' "$out" 2>/dev/null)" || err="invalid_json"
    if [[ "$ec" -eq 0 && -z "$err" ]]; then
      rm -f "${out}.stderr"
      return 0
    fi
    echo "  [aviso] iperf3 falhou (tentativa $attempt, exit=$ec, error='$err')" >&2
    lbr_restart_server
  done
  echo "  [ERRO] iperf3 falhou apos 15 tentativas: $out" >&2
  return 1
}

lbr_ping_avg() {  # RTT medio (ms) ou NaN em 100% de perda
  local line
  line="$(grep 'rtt min/avg/max/mdev' "$1" || true)"
  [[ -z "$line" ]] && { echo "NaN"; return; }
  echo "$line" | awk -F'= ' '{print $2}' | cut -d'/' -f2
}

# Contexto do experimento (monografia / reprodutibilidade)
lbr_write_env() {  # lbr_write_env <arquivo> <modo> <parametros>
  local r
  {
    echo "date: $(date -Is)"
    echo "mode: $2"
    echo "params: $3"
    echo "client: $(hostname) $(uname -r)"
    for r in "$R1_MGMT" "$R2_MGMT" "$R3_MGMT" "$R4_MGMT" "$H2_MGMT"; do
      echo "--- $r"
      lbr_ssh "$r" 'echo "$(hostname) $(uname -r) nproc=$(nproc) ip_forward=$(sysctl -n net.ipv4.ip_forward)";
        for d in $(ls /sys/class/net); do
          case $d in lo|ens18|eth0) continue;; esac
          echo "  $d $(cat /sys/class/net/$d/operstate) $(ip link show $d | grep -o "prog/xdp[a-z]* id [0-9]*" || echo "sem-xdp")"
        done' </dev/null
    done
    if [[ "$2" == "xdp" ]]; then
      echo "--- R1 lb status"; lbr_cli "$R1_MGMT" "lb status"
      echo "--- R4 lb status"; lbr_cli "$R4_MGMT" "lb status"
    else
      echo "--- R1 rota ECMP"; lbr_ssh "$R1_MGMT" "ip route show $NET_B; sysctl net.ipv4.fib_multipath_hash_policy" </dev/null
      echo "--- R4 rota ECMP"; lbr_ssh "$R4_MGMT" "ip route show $NET_A; sysctl net.ipv4.fib_multipath_hash_policy" </dev/null
    fi
  } > "$1" 2>&1
}
