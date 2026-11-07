#!/usr/bin/env bash
#
# setup_lb_chain_real_edge.sh — configura um roteador de borda (R1 ou R4)
# da topologia encadeada real A-R1-{R2,R3}-R4-B (ver
# docs/setup_xdp_lb_chain_real.md). Normalmente chamado pelo orquestrador
# scripts/setup_lb_chain_real.sh, que descobre os MACs e passa as variaveis.
#
# Modos:
#   xdp      — xdp_fw_lb.c (sem alteracao) anexado em modo nativo nas 3
#              portas de dados; ip_forward=0. route_table: host local ->
#              LAN_IF; miss -> LB WAN (hash) entre W0 (via R2) e W1 (via R3).
#   baseline — roteador do kernel (ip_forward=1) com rota ECMP de 2 nexthops
#              (fib_multipath_hash_policy=1, hash L4) para a rede remota.
#   reset    — remove XDP/enderecos/rotas e desliga as portas de dados.
#
# Nos dois modos: mesmos offloads (GRO/LRO off, exigido pelo XDP nativo do
# virtio_net), IPv6 desligado nas portas de dados e vizinhos estaticos —
# a unica variavel entre os modos e XDP vs pilha IP do kernel.
#
# Variaveis obrigatorias (modos xdp/baseline):
#   LAN_IF LAN_HOST_IP LAN_HOST_MAC GW_IP REMOTE_NET
#   W0_IF W0_IP W0_PEER_IP W0_PEER_MAC   W1_IF W1_IP W1_PEER_IP W1_PEER_MAC
# Opcionais: XDP_MODE (native|generic, padrao native), LB_MODE (hash|rr).
#
# Uso: sudo env VAR=... bash setup_lb_chain_real_edge.sh <xdp|baseline|reset>
#
set -euo pipefail
export PATH="/usr/local/bin:/usr/local/sbin:/usr/sbin:/usr/bin:/sbin:/bin:$PATH"

MODE="${1:?uso: $0 <xdp|baseline|reset>}"
XDP_MODE="${XDP_MODE:-native}"
LB_MODE="${LB_MODE:-hash}"
CLI_NETNS="xdpunk_root"
BPF_PIN="/sys/fs/bpf/xdpunk_prog"
BPF_MAP_DIR="/sys/fs/bpf/xdpunk"
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
XDP_SRC="$SCRIPT_DIR/../xdp/xdp_fw_lb.c"
XDP_OBJ="/tmp/xdp_fw_lb.o"

case "$MODE" in xdp|baseline|reset) ;; *) echo "ERRO: modo invalido '$MODE'"; exit 1 ;; esac
case "$XDP_MODE" in
  native)  XDP_FLAG="xdpdrv" ;;
  generic) XDP_FLAG="xdpgeneric" ;;
  *) echo "ERRO: XDP_MODE deve ser native ou generic"; exit 1 ;;
esac

: "${LAN_IF:?}" "${W0_IF:?}" "${W1_IF:?}"
DEVS=("$LAN_IF" "$W0_IF" "$W1_IF")

echo "[$(hostname)] modo=$MODE  LAN=$LAN_IF W0=$W0_IF W1=$W1_IF"

# ---------------------------------------------------------------- limpeza
for dev in "${DEVS[@]}"; do
  ip link set dev "$dev" xdpdrv off 2>/dev/null || true
  ip link set dev "$dev" xdpgeneric off 2>/dev/null || true
  ip addr flush dev "$dev"
  ip route flush dev "$dev" 2>/dev/null || true
  ip neigh flush dev "$dev" nud permanent 2>/dev/null || true
done
[[ -n "${REMOTE_NET:-}" ]] && ip route del "$REMOTE_NET" 2>/dev/null || true
rm -f "$BPF_PIN"
rm -rf "$BPF_MAP_DIR"
ip netns del "$CLI_NETNS" 2>/dev/null || true
sysctl -qw net.ipv4.ip_forward=0

if [[ "$MODE" == "reset" ]]; then
  for dev in "${DEVS[@]}"; do ip link set dev "$dev" down; done
  echo "[$(hostname)] reset concluido."
  exit 0
fi

for v in LAN_HOST_IP LAN_HOST_MAC GW_IP REMOTE_NET W0_IP W0_PEER_IP W0_PEER_MAC \
         W1_IP W1_PEER_IP W1_PEER_MAC; do
  [[ -n "${!v:-}" ]] || { echo "ERRO: variavel $v nao definida."; exit 1; }
done
for c in ip ethtool; do
  command -v "$c" >/dev/null || { echo "ERRO: comando '$c' nao encontrado."; exit 1; }
done

# ------------------------------------------------------- base comum
sysctl -qw net.ipv4.conf.all.rp_filter=0
sysctl -qw net.ipv4.conf.default.rp_filter=0
sysctl -qw net.ipv4.conf.all.send_redirects=0
for dev in "${DEVS[@]}"; do
  sysctl -qw "net.ipv6.conf.$dev.disable_ipv6=1"
  sysctl -qw "net.ipv4.conf.$dev.rp_filter=0"
  # virtio_net recusa XDP nativo com GRO de hardware (guest offloads)
  # ativo; desligado tambem no baseline para manter a mesma base.
  ethtool -K "$dev" rx-gro-hw off gro off lro off >/dev/null 2>&1 || true
  ip link set dev "$dev" up
done

# Enlaces /30 com os roteadores de transito: IP + vizinho estatico (sem ARP
# durante a medicao, igual nos dois modos).
ip addr add "$W0_IP/30" dev "$W0_IF"
ip addr add "$W1_IP/30" dev "$W1_IF"
ip neigh replace "$W0_PEER_IP" lladdr "$W0_PEER_MAC" dev "$W0_IF" nud permanent
ip neigh replace "$W1_PEER_IP" lladdr "$W1_PEER_MAC" dev "$W1_IF" nud permanent

if [[ "$MODE" == "baseline" ]]; then
  # Gateway real do host local + vizinho estatico do host.
  ip addr add "$GW_IP/24" dev "$LAN_IF"
  ip neigh replace "$LAN_HOST_IP" lladdr "$LAN_HOST_MAC" dev "$LAN_IF" nud permanent
  sysctl -qw net.ipv4.fib_multipath_hash_policy=1
  ip route replace "$REMOTE_NET" \
    nexthop via "$W0_PEER_IP" dev "$W0_IF" weight 1 \
    nexthop via "$W1_PEER_IP" dev "$W1_IF" weight 1
  sysctl -qw net.ipv4.ip_forward=1

  echo
  ip route show "$REMOTE_NET"
  ip neigh show nud permanent
  echo "[$(hostname)] baseline pronto (kernel + ECMP hash L4)."
  exit 0
fi

# ------------------------------------------------------- modo xdp
for c in clang bpftool xdpunk-cli; do
  command -v "$c" >/dev/null || { echo "ERRO: comando '$c' nao encontrado."; exit 1; }
done
[[ -f "$XDP_SRC" ]] || { echo "ERRO: fonte '$XDP_SRC' nao encontrado."; exit 1; }

clang -O2 -g -target bpf -mcpu=v3 -I"/usr/include/$(uname -m)-linux-gnu" \
  -c "$XDP_SRC" -o "$XDP_OBJ"
mountpoint -q /sys/fs/bpf || mount -t bpf bpf /sys/fs/bpf/
bpftool prog load "$XDP_OBJ" "$BPF_PIN" pinmaps "$BPF_MAP_DIR"
for dev in "${DEVS[@]}"; do
  ip link set dev "$dev" "$XDP_FLAG" pinned "$BPF_PIN"
done

# A xdpunk-cli resolve interfaces dentro de um netns nomeado; o roteador
# opera no netns raiz, exposto como /var/run/netns/$CLI_NETNS.
ip netns attach "$CLI_NETNS" 1
cli() { xdpunk-cli --netns "$CLI_NETNS" --map-pin "$BPF_MAP_DIR" "$@"; }
cli map update "$LAN_HOST_IP" "$LAN_IF" --dmac "$LAN_HOST_MAC" >/dev/null
cli fw flush >/dev/null
cli lb link add 0 "$W0_IF" --dmac "$W0_PEER_MAC" >/dev/null
cli lb link add 1 "$W1_IF" --dmac "$W1_PEER_MAC" >/dev/null
cli lb mode "$LB_MODE" >/dev/null
cli stats --reset >/dev/null

echo
for dev in "${DEVS[@]}"; do
  printf '%-6s %s\n' "$dev" "$(ip link show "$dev" | grep -o 'prog/xdp[a-z]* id [0-9]*' || echo 'SEM XDP')"
done
cli map dump
cli lb status
echo "[$(hostname)] XDP pronto (modo $XDP_MODE, LB $LB_MODE). CLI: xdpunk-cli --netns $CLI_NETNS ..."
