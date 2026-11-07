#!/usr/bin/env bash
#
# setup_lb_chain_real_transit.sh — configura um roteador de transito (R2 ou
# R3) da topologia encadeada real: roteador comum do kernel, sem BPF,
# identico nos modos xdp e baseline (ver docs/setup_xdp_lb_chain_real.md).
#
# Variaveis: A_IF A_IP A_PEER_IP A_PEER_MAC  (lado R1)
#            B_IF B_IP B_PEER_IP B_PEER_MAC  (lado R4)
#            NET_A NET_B                     (redes dos hosts)
#
# Uso: sudo env VAR=... bash setup_lb_chain_real_transit.sh <setup|reset>
#
set -euo pipefail
export PATH="/usr/local/sbin:/usr/sbin:/usr/bin:/sbin:/bin:$PATH"

MODE="${1:?uso: $0 <setup|reset>}"
: "${A_IF:?}" "${B_IF:?}"
DEVS=("$A_IF" "$B_IF")

echo "[$(hostname)] transito modo=$MODE  A=$A_IF B=$B_IF"

for dev in "${DEVS[@]}"; do
  ip addr flush dev "$dev"
  ip route flush dev "$dev" 2>/dev/null || true
  ip neigh flush dev "$dev" nud permanent 2>/dev/null || true
done

if [[ "$MODE" == "reset" ]]; then
  sysctl -qw net.ipv4.ip_forward=0
  for dev in "${DEVS[@]}"; do ip link set dev "$dev" down; done
  echo "[$(hostname)] reset concluido."
  exit 0
fi
[[ "$MODE" == "setup" ]] || { echo "ERRO: modo invalido '$MODE'"; exit 1; }

for v in A_IP A_PEER_IP A_PEER_MAC B_IP B_PEER_IP B_PEER_MAC NET_A NET_B; do
  [[ -n "${!v:-}" ]] || { echo "ERRO: variavel $v nao definida."; exit 1; }
done

sysctl -qw net.ipv4.conf.all.rp_filter=0
sysctl -qw net.ipv4.conf.default.rp_filter=0
sysctl -qw net.ipv4.conf.all.send_redirects=0
for dev in "${DEVS[@]}"; do
  sysctl -qw "net.ipv6.conf.$dev.disable_ipv6=1"
  sysctl -qw "net.ipv4.conf.$dev.rp_filter=0"
  # Mesmos offloads dos roteadores de borda (encaminhamento por pacote).
  ethtool -K "$dev" rx-gro-hw off gro off lro off >/dev/null 2>&1 || true
  ip link set dev "$dev" up
done

ip addr add "$A_IP/30" dev "$A_IF"
ip addr add "$B_IP/30" dev "$B_IF"
ip neigh replace "$A_PEER_IP" lladdr "$A_PEER_MAC" dev "$A_IF" nud permanent
ip neigh replace "$B_PEER_IP" lladdr "$B_PEER_MAC" dev "$B_IF" nud permanent
ip route replace "$NET_A" via "$A_PEER_IP" dev "$A_IF"
ip route replace "$NET_B" via "$B_PEER_IP" dev "$B_IF"
sysctl -qw net.ipv4.ip_forward=1

ip route show | grep -E "^(${NET_A%/*}|${NET_B%/*})" || true
echo "[$(hostname)] transito pronto."
