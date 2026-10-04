#!/usr/bin/env bash
#
# setup_xdp_fw_real.sh — XDPunk Fase 2 em maquinas reais (3 VMs, sem netns).
#
# Topologia fisica (cada seta = enlace L2 dedicado):
#
#   h1 (cliente)            sw (DUT, este host)              h2 (servidor)
#   ens19 10.0.0.1/24  <->  LAN1_IF        LAN2_IF  <->  ens19 10.0.0.2/24
#
# O switch nao tem IP nas interfaces de dados e roda com ip_forward=0:
# todo encaminhamento h1<->h2 e feito pelo programa XDP (xdp_fw_lb.c).
#   - ARP: lookup do target IP na route_table -> redirect (sem rewrite);
#   - IPv4: firewall (scan linear) -> route_table hit -> rewrite MAC -> redirect.
# O LB de WAN fica desligado (lb_config.enabled = 0): miss -> XDP_PASS.
#
# A xdpunk-cli resolve interfaces dentro de um netns nomeado; aqui o switch
# opera no netns raiz, entao ele e exposto como /var/run/netns/$CLI_NETNS
# (`ip netns attach`). Use `xdpunk-cli --netns $CLI_NETNS ...`.
#
# Uso (no switch): sudo bash setup_xdp_fw_real.sh <MAC_h1_ens19> <MAC_h2_ens19>
# Variaveis: LAN1_IF (ens19), LAN2_IF (ens20), XDP_MODE (native|generic).
#
set -euo pipefail
export PATH="/usr/local/bin:/usr/local/sbin:/usr/sbin:/sbin:$PATH"

H1_MAC="${1:?uso: $0 <MAC_h1> <MAC_h2>}"
H2_MAC="${2:?uso: $0 <MAC_h1> <MAC_h2>}"
LAN1_IF="${LAN1_IF:-ens19}"
LAN2_IF="${LAN2_IF:-ens20}"
XDP_MODE="${XDP_MODE:-native}"
H1_IP="10.0.0.1"
H2_IP="10.0.0.2"
CLI_NETNS="xdpunk_root"

BPF_PIN="/sys/fs/bpf/xdpunk_prog"
BPF_MAP_DIR="/sys/fs/bpf/xdpunk"
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
XDP_SRC="$SCRIPT_DIR/../xdp/xdp_fw_lb.c"
XDP_OBJ="/tmp/xdp_fw_lb.o"

case "$XDP_MODE" in
  native)  XDP_FLAG="xdpdrv" ;;
  generic) XDP_FLAG="xdpgeneric" ;;
  *) echo "ERRO: XDP_MODE deve ser native ou generic"; exit 1 ;;
esac

for c in ip clang bpftool ethtool xdpunk-cli; do
  command -v "$c" >/dev/null || { echo "ERRO: comando '$c' nao encontrado."; exit 1; }
done

echo "[1/5] Limpando estado anterior..."
for dev in "$LAN1_IF" "$LAN2_IF"; do
  ip link set dev "$dev" xdpdrv off 2>/dev/null || true
  ip link set dev "$dev" xdpgeneric off 2>/dev/null || true
  ip addr flush dev "$dev"
  # Restos do baseline (setup_baseline_router_real.sh)
  ip route flush dev "$dev" 2>/dev/null || true
  ip neigh flush dev "$dev" nud permanent 2>/dev/null || true
done
iptables -F FORWARD 2>/dev/null || true
rm -f "$BPF_PIN"
rm -rf "$BPF_MAP_DIR"
ip netns del "$CLI_NETNS" 2>/dev/null || true

echo "[2/5] Configurando interfaces de dados ($LAN1_IF, $LAN2_IF)..."
sysctl -qw net.ipv4.ip_forward=0
for dev in "$LAN1_IF" "$LAN2_IF"; do
  # Sem IPv6 nas portas do switch: evita trafego de controle (ND/MLD)
  # gerado pelo proprio DUT nos enlaces de teste.
  sysctl -qw "net.ipv6.conf.$dev.disable_ipv6=1"
  # virtio_net recusa XDP nativo com GRO de hardware (guest offloads)
  # ativo; desligado tambem no modo generic para manter a mesma base.
  ethtool -K "$dev" rx-gro-hw off gro off lro off >/dev/null 2>&1 || true
  ip link set dev "$dev" up
done

echo "[3/5] Compilando programa eBPF..."
clang -O2 -g -target bpf -mcpu=v3 -I"/usr/include/$(uname -m)-linux-gnu" \
  -c "$XDP_SRC" -o "$XDP_OBJ"

echo "[4/5] Carregando e anexando XDP (modo $XDP_MODE)..."
mountpoint -q /sys/fs/bpf || mount -t bpf bpf /sys/fs/bpf/
bpftool prog load "$XDP_OBJ" "$BPF_PIN" pinmaps "$BPF_MAP_DIR"
for dev in "$LAN1_IF" "$LAN2_IF"; do
  ip link set dev "$dev" "$XDP_FLAG" pinned "$BPF_PIN"
done

echo "[5/5] Populando route_table..."
ip netns attach "$CLI_NETNS" 1
xdpunk-cli --netns "$CLI_NETNS" map update "$H1_IP" "$LAN1_IF" --dmac "$H1_MAC" >/dev/null
xdpunk-cli --netns "$CLI_NETNS" map update "$H2_IP" "$LAN2_IF" --dmac "$H2_MAC" >/dev/null
xdpunk-cli --netns "$CLI_NETNS" fw flush >/dev/null
xdpunk-cli --netns "$CLI_NETNS" stats --reset >/dev/null

echo
ip -br link show "$LAN1_IF"; ip -br link show "$LAN2_IF"
ip link show "$LAN1_IF" | grep -o 'prog/xdp[a-z]* id [0-9]*' || true
xdpunk-cli --netns "$CLI_NETNS" map dump
echo
echo "Switch XDP pronto. Plano de controle: xdpunk-cli --netns $CLI_NETNS <cmd>"
