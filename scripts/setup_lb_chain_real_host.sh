#!/usr/bin/env bash
#
# setup_lb_chain_real_host.sh — prepara um host final (host1 = A ou
# host2 = B) da topologia encadeada real (ver docs/setup_xdp_lb_chain_real.md).
#
# A rota para a rede remota usa o gateway do roteador de borda com vizinho
# PERMANENT no MAC da porta LAN dele: no modo xdp a porta nao tem IP (nao
# ha quem responda ARP) e no baseline isso mantem a mesma configuracao.
# A rota default (gerencia, eth0) nao e alterada. arp_ignore=1 impede que
# a eth0 responda ARP por IP configurado na porta de dados.
#
# Uso: sudo bash setup_lb_chain_real_host.sh <IFACE> <IP/24> <GW_IP> <REDE_REMOTA> <MAC_GW>
#      sudo bash setup_lb_chain_real_host.sh <IFACE> reset
#
set -euo pipefail
export PATH="/usr/local/sbin:/usr/sbin:/usr/bin:/sbin:/bin:$PATH"

IFACE="${1:?uso: $0 <IFACE> <IP/24> <GW_IP> <REDE_REMOTA> <MAC_GW> | <IFACE> reset}"

if [[ "${2:-}" == "reset" ]]; then
  ip addr flush dev "$IFACE"
  ip route flush dev "$IFACE" 2>/dev/null || true
  ip neigh flush dev "$IFACE" nud permanent 2>/dev/null || true
  ip link set dev "$IFACE" down
  echo "[$(hostname)] $IFACE resetada."
  exit 0
fi

ADDR="${2:?}"
GW_IP="${3:?}"
REMOTE_NET="${4:?}"
GW_MAC="${5:?}"

sysctl -qw net.ipv4.conf.all.arp_ignore=1
sysctl -qw "net.ipv6.conf.$IFACE.disable_ipv6=1"
ip addr flush dev "$IFACE"
ip route flush dev "$IFACE" 2>/dev/null || true
ip neigh flush dev "$IFACE" nud permanent 2>/dev/null || true
ip addr add "$ADDR" dev "$IFACE"
ip link set dev "$IFACE" up
ip neigh replace "$GW_IP" lladdr "$GW_MAC" dev "$IFACE" nud permanent
ip route replace "$REMOTE_NET" via "$GW_IP" dev "$IFACE"

ip -br addr show dev "$IFACE"
ip route show dev "$IFACE"
ip neigh show dev "$IFACE"
