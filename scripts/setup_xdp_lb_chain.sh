#!/usr/bin/env bash
#
# setup_xdp_lb_chain.sh — XDPunk: topologia encadeada A-R1-{R2,R3}-R4-B
# para analise de desempenho do load balancer em XDP com 2 saltos de
# decisao (ver docs/superpowers/specs/2026-08-29-lb-chain-topology-design.md).
#
# Topologia:
#
#  nsA 10.10.1.1/24 ─vethA/vethAr1─┐                              ┌─vethR4B/vethB─ nsB 10.10.2.1/24
#                                  │ nsr1 (XDP LB)      nsr4 (XDP LB)│
#                     ┌─vethR12/vethR21─ nsr2 (kernel)  ┐            │
#                     │                                  vethR24/vethR42
#                     └─vethR13/vethR31─ nsr3 (kernel)  ┐           │
#                                                        vethR34/vethR43
#
#  - nsA/nsB usam gateway "fake" (neigh estatico, sem ARP na LAN);
#  - nsr1/nsr4 NAO fazem IP forwarding (ip_forward=0): encaminhamento e XDP;
#  - nsr2/nsr3 sao roteadores comuns do kernel (transito puro, sem BPF);
#  - xdp_fw_lb.c e compilado 1x e carregado 2x (pins _r1/_r4 independentes).
#
set -euo pipefail

NSA="nsA"; NSR1="nsr1"; NSR2="nsr2"; NSR3="nsr3"; NSR4="nsr4"; NSB="nsB"

GW_A_IP="10.10.1.254"; GW_B_IP="10.10.2.254"
GW_MAC="02:00:00:00:00:fe"
A_IP="10.10.1.1"; B_IP="10.10.2.1"

BPF_PIN_R1="/sys/fs/bpf/xdpunk_r1_prog"; BPF_MAP_DIR_R1="/sys/fs/bpf/xdpunk_r1"
BPF_PIN_R4="/sys/fs/bpf/xdpunk_r4_prog"; BPF_MAP_DIR_R4="/sys/fs/bpf/xdpunk_r4"

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
XDP_SRC="$SCRIPT_DIR/../xdp/xdp_fw_lb.c"
XDP_OBJ="/tmp/xdp_lb_chain.o"

SW_DEVS_R1=(vethAr1 vethR12 vethR13)
SW_DEVS_R4=(vethR42 vethR43 vethR4B)

cleanup() {
  set +e
  for dev in "${SW_DEVS_R1[@]}"; do
    ip -n "$NSR1" link set dev "$dev" xdpgeneric off 2>/dev/null || true
  done
  for dev in "${SW_DEVS_R4[@]}"; do
    ip -n "$NSR4" link set dev "$dev" xdpgeneric off 2>/dev/null || true
  done
  rm -f "$BPF_PIN_R1" "$BPF_PIN_R4"
  rm -rf "$BPF_MAP_DIR_R1" "$BPF_MAP_DIR_R4"
  for ns in "$NSA" "$NSR1" "$NSR2" "$NSR3" "$NSR4" "$NSB"; do
    ip netns del "$ns" 2>/dev/null
  done
  rm -f "$XDP_OBJ"
}
trap cleanup EXIT

need_cmd() {
  command -v "$1" >/dev/null 2>&1 || {
    echo "ERRO: comando '$1' nao encontrado."
    [[ "$1" == "xdpunk-cli" ]] && \
      echo "Instale com: sudo pip3 install $SCRIPT_DIR/../userspace/"
    exit 1
  }
}

mac_of() { ip -n "$1" -br link show "$2" | awk '{print $3}'; }

need_cmd ip; need_cmd clang; need_cmd bpftool; need_cmd nsenter; need_cmd xdpunk-cli

if [[ ! -f "$XDP_SRC" ]]; then
  echo "ERRO: arquivo fonte '$XDP_SRC' nao encontrado."
  exit 1
fi

echo "[1/9] Criando namespaces..."
for ns in "$NSA" "$NSR1" "$NSR2" "$NSR3" "$NSR4" "$NSB"; do
  ip netns add "$ns"
  ip -n "$ns" link set lo up
done

echo "[2/9] Criando veth pairs..."
ip link add vethA   type veth peer name vethAr1
ip link add vethR12 type veth peer name vethR21
ip link add vethR13 type veth peer name vethR31
ip link add vethR24 type veth peer name vethR42
ip link add vethR34 type veth peer name vethR43
ip link add vethR4B type veth peer name vethB

ip link set vethA   netns "$NSA"
ip link set vethAr1 netns "$NSR1"
ip link set vethR12 netns "$NSR1"
ip link set vethR21 netns "$NSR2"
ip link set vethR13 netns "$NSR1"
ip link set vethR31 netns "$NSR3"
ip link set vethR24 netns "$NSR2"
ip link set vethR42 netns "$NSR4"
ip link set vethR34 netns "$NSR3"
ip link set vethR43 netns "$NSR4"
ip link set vethR4B netns "$NSR4"
ip link set vethB   netns "$NSB"

echo "[3/9] Configurando enderecos e subindo interfaces..."
ip -n "$NSA" addr add "$A_IP/24" dev vethA
ip -n "$NSB" addr add "$B_IP/24" dev vethB

# vethAr1/vethR4B (lado LAN de R1/R4): sem IP — gateway fake, XDP decide.
ip -n "$NSR1" addr add 172.20.1.1/30 dev vethR12
ip -n "$NSR1" addr add 172.20.2.1/30 dev vethR13
ip -n "$NSR2" addr add 172.20.1.2/30 dev vethR21
ip -n "$NSR2" addr add 172.20.3.1/30 dev vethR24
ip -n "$NSR3" addr add 172.20.2.2/30 dev vethR31
ip -n "$NSR3" addr add 172.20.4.1/30 dev vethR34
ip -n "$NSR4" addr add 172.20.3.2/30 dev vethR42
ip -n "$NSR4" addr add 172.20.4.2/30 dev vethR43

ip -n "$NSA"  link set vethA   up
ip -n "$NSB"  link set vethB   up
ip -n "$NSR1" link set vethAr1 up
ip -n "$NSR1" link set vethR12 up
ip -n "$NSR1" link set vethR13 up
ip -n "$NSR2" link set vethR21 up
ip -n "$NSR2" link set vethR24 up
ip -n "$NSR3" link set vethR31 up
ip -n "$NSR3" link set vethR34 up
ip -n "$NSR4" link set vethR42 up
ip -n "$NSR4" link set vethR43 up
ip -n "$NSR4" link set vethR4B up

echo "[4/9] Configurando sysctls (forwarding / rp_filter)..."
# nsr1/nsr4: forwarding do kernel DESLIGADO — encaminhamento e 100% XDP.
ip netns exec "$NSR1" sysctl -qw net.ipv4.ip_forward=0
ip netns exec "$NSR4" sysctl -qw net.ipv4.ip_forward=0

for ns in "$NSR2" "$NSR3"; do
  ip netns exec "$ns" sysctl -qw net.ipv4.ip_forward=1
  ip netns exec "$ns" sysctl -qw net.ipv4.conf.all.rp_filter=0
  ip netns exec "$ns" sysctl -qw net.ipv4.conf.default.rp_filter=0
done

if command -v ethtool >/dev/null 2>&1; then
  ip netns exec "$NSA"  ethtool -K vethA   gso off tso off gro off >/dev/null 2>&1 || true
  ip netns exec "$NSB"  ethtool -K vethB   gso off tso off gro off >/dev/null 2>&1 || true
  ip netns exec "$NSR2" ethtool -K vethR21 gso off tso off gro off >/dev/null 2>&1 || true
  ip netns exec "$NSR2" ethtool -K vethR24 gso off tso off gro off >/dev/null 2>&1 || true
  ip netns exec "$NSR3" ethtool -K vethR31 gso off tso off gro off >/dev/null 2>&1 || true
  ip netns exec "$NSR3" ethtool -K vethR34 gso off tso off gro off >/dev/null 2>&1 || true
else
  echo "  AVISO: ethtool nao encontrado — offloads (GSO/TSO) permanecem ativos."
fi

echo "[5/9] Configurando rotas..."
ip -n "$NSA" neigh add "$GW_A_IP" lladdr "$GW_MAC" dev vethA nud permanent
ip -n "$NSA" route add default via "$GW_A_IP" dev vethA
ip -n "$NSB" neigh add "$GW_B_IP" lladdr "$GW_MAC" dev vethB nud permanent
ip -n "$NSB" route add default via "$GW_B_IP" dev vethB

ip -n "$NSR2" route add 10.10.1.0/24 via 172.20.1.1
ip -n "$NSR2" route add 10.10.2.0/24 via 172.20.3.2
ip -n "$NSR3" route add 10.10.1.0/24 via 172.20.2.1
ip -n "$NSR3" route add 10.10.2.0/24 via 172.20.4.2

echo "[6/9] Compilando programa eBPF (XDP) uma unica vez..."
clang -O2 -g -target bpf -mcpu=v3 -c "$XDP_SRC" -o "$XDP_OBJ"

echo "[7/9] Carregando o mesmo objeto 2x (R1 e R4, pins independentes)..."
if ! mountpoint -q /sys/fs/bpf 2>/dev/null; then
  mount -t bpf bpf /sys/fs/bpf/ || {
    echo "ERRO: nao foi possivel montar bpffs em /sys/fs/bpf/."
    exit 1
  }
fi
bpftool prog load "$XDP_OBJ" "$BPF_PIN_R1" pinmaps "$BPF_MAP_DIR_R1"
bpftool prog load "$XDP_OBJ" "$BPF_PIN_R4" pinmaps "$BPF_MAP_DIR_R4"

for dev in "${SW_DEVS_R1[@]}"; do
  nsenter --net=/var/run/netns/"$NSR1" ip link set dev "$dev" xdpgeneric pinned "$BPF_PIN_R1"
done
for dev in "${SW_DEVS_R4[@]}"; do
  nsenter --net=/var/run/netns/"$NSR4" ip link set dev "$dev" xdpgeneric pinned "$BPF_PIN_R4"
done

echo "[8/9] Populando mapas via xdpunk-cli..."
MAC_A="$(mac_of "$NSA" vethA)"
MAC_B="$(mac_of "$NSB" vethB)"
MAC_R21="$(mac_of "$NSR2" vethR21)"
MAC_R31="$(mac_of "$NSR3" vethR31)"
MAC_R24="$(mac_of "$NSR2" vethR24)"
MAC_R34="$(mac_of "$NSR3" vethR34)"

xdpunk-cli --netns "$NSR1" --map-pin "$BPF_MAP_DIR_R1" \
  map update "$A_IP" vethAr1 --dmac "$MAC_A"
xdpunk-cli --netns "$NSR1" --map-pin "$BPF_MAP_DIR_R1" \
  lb link add 0 vethR12 --dmac "$MAC_R21"
xdpunk-cli --netns "$NSR1" --map-pin "$BPF_MAP_DIR_R1" \
  lb link add 1 vethR13 --dmac "$MAC_R31"
xdpunk-cli --netns "$NSR1" --map-pin "$BPF_MAP_DIR_R1" lb mode hash

xdpunk-cli --netns "$NSR4" --map-pin "$BPF_MAP_DIR_R4" \
  map update "$B_IP" vethR4B --dmac "$MAC_B"
xdpunk-cli --netns "$NSR4" --map-pin "$BPF_MAP_DIR_R4" \
  lb link add 0 vethR42 --dmac "$MAC_R24"
xdpunk-cli --netns "$NSR4" --map-pin "$BPF_MAP_DIR_R4" \
  lb link add 1 vethR43 --dmac "$MAC_R34"
xdpunk-cli --netns "$NSR4" --map-pin "$BPF_MAP_DIR_R4" lb mode hash

echo "[9/9] Resumo..."
echo
echo "=================================================================="
echo "Laboratorio XDPunk (LB encadeado A-R1-{R2,R3}-R4-B) carregado!"
echo
echo "R1: route_table 10.10.1.1 -> vethAr1 | wan_links: 0=vethR12(R2) 1=vethR13(R3)"
echo "R4: route_table 10.10.2.1 -> vethR4B | wan_links: 0=vethR42(R2) 1=vethR43(R3)"
echo
echo "------------------------------------------------------------------"
echo "Testar conectividade fim a fim (F1):"
echo "  ip netns exec nsA ping -c 3 $B_IP"
echo "  sudo xdpunk-cli --netns nsr1 --map-pin $BPF_MAP_DIR_R1 stats"
echo "  sudo xdpunk-cli --netns nsr4 --map-pin $BPF_MAP_DIR_R4 stats"
echo
echo "Observar o caminho nos roteadores do meio:"
echo "  ip netns exec nsr2 tcpdump -ni vethR21"
echo "  ip netns exec nsr3 tcpdump -ni vethR31"
echo
echo "Distribuicao por link / failover (F2, F4, F4b, F5):"
echo "  sudo xdpunk-cli --netns nsr1 --map-pin $BPF_MAP_DIR_R1 lb status"
echo "  sudo xdpunk-cli --netns nsr1 --map-pin $BPF_MAP_DIR_R1 lb link disable 0"
echo "  sudo xdpunk-cli --netns nsr1 --map-pin $BPF_MAP_DIR_R1 lb mode rr"
echo
echo "Benchmark (iperf3):"
echo "  ip netns exec nsB iperf3 -s -B $B_IP"
echo "  ip netns exec nsA iperf3 -c $B_IP -P 8"
echo "=================================================================="

trap - EXIT
