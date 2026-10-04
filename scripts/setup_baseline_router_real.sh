#!/usr/bin/env bash
#
# setup_baseline_router_real.sh — baseline nativo do Linux (sem XDP) na
# topologia de 3 VMs: o switch encaminha h1<->h2 pela pilha IP do kernel
# (ip_forward=1) e o firewall e o iptables na chain FORWARD.
#
# Mesma semantica de encaminhamento do programa XDP (lookup por IP destino
# + reescrita de MACs), mesma configuracao dos hosts (setup_real_host.sh:
# vizinho estatico = MAC da porta do switch) e mesmos offloads das NICs que
# setup_xdp_fw_real.sh — a unica variavel entre os modos e XDP vs kernel.
#
# Diferente de setup_baseline_router.sh (lab em netns, bridge +
# br_netfilter): aqui nao se usa bridge porque o enlace h1<->sw compartilha
# o dominio L2 da rede de gerencia (ver docs/setup_xdp_fw_real.md) e uma
# bridge no switch uniria a rede de gerencia ao segmento isolado de h2.
#
# Uso (no switch): sudo bash setup_baseline_router_real.sh <MAC_h1_ens19> <MAC_h2_ens19>
# Variaveis: LAN1_IF (ens19), LAN2_IF (ens20).
#
set -euo pipefail
export PATH="/usr/local/bin:/usr/local/sbin:/usr/sbin:/sbin:$PATH"

H1_MAC="${1:?uso: $0 <MAC_h1> <MAC_h2>}"
H2_MAC="${2:?uso: $0 <MAC_h1> <MAC_h2>}"
LAN1_IF="${LAN1_IF:-ens19}"
LAN2_IF="${LAN2_IF:-ens20}"
H1_IP="10.0.0.1"
H2_IP="10.0.0.2"

for c in ip iptables ethtool; do
  command -v "$c" >/dev/null || { echo "ERRO: comando '$c' nao encontrado."; exit 1; }
done

echo "[1/3] Removendo XDP e estado anterior..."
for dev in "$LAN1_IF" "$LAN2_IF"; do
  ip link set dev "$dev" xdpdrv off 2>/dev/null || true
  ip link set dev "$dev" xdpgeneric off 2>/dev/null || true
  ip addr flush dev "$dev"
  ip route flush dev "$dev" 2>/dev/null || true
  ip neigh flush dev "$dev" nud permanent 2>/dev/null || true
done

echo "[2/3] Configurando encaminhamento IP do kernel..."
for dev in "$LAN1_IF" "$LAN2_IF"; do
  sysctl -qw "net.ipv6.conf.$dev.disable_ipv6=1"
  ethtool -K "$dev" rx-gro-hw off gro off lro off >/dev/null 2>&1 || true
  ip link set dev "$dev" up
done
ip route replace "$H1_IP/32" dev "$LAN1_IF"
ip route replace "$H2_IP/32" dev "$LAN2_IF"
ip neigh replace "$H1_IP" lladdr "$H1_MAC" dev "$LAN1_IF" nud permanent
ip neigh replace "$H2_IP" lladdr "$H2_MAC" dev "$LAN2_IF" nud permanent
# Sem redirects ICMP e sem filtro de rota reversa interferindo na medicao.
sysctl -qw net.ipv4.conf.all.send_redirects=0
sysctl -qw net.ipv4.conf.all.rp_filter=0
sysctl -qw net.ipv4.ip_forward=1

echo "[3/3] Firewall: iptables FORWARD vazio, politica ACCEPT..."
iptables -P FORWARD ACCEPT
iptables -F FORWARD

echo
ip route show dev "$LAN1_IF"; ip route show dev "$LAN2_IF"
ip neigh show nud permanent
iptables -V
echo "Baseline pronto (kernel router + iptables FORWARD)."
