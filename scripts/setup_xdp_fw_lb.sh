#!/usr/bin/env bash
#
# setup_xdp_fw_lb.sh — XDPunk Fase 2: laboratorio de firewall + LB de links WAN.
#
# Topologia (enderecos de documentacao RFC 5737 na "internet"):
#
#              LAN 10.0.0.0/24                "WAN"                 "Internet"
#  ns1 ─veth1h/veth1s─┐            ┌─vethw1s/vethw1p─ nsp1 ─vethe1p/vethe1x─┐
#  10.0.0.1           │   nssw     │ 172.16.1.1/.2     fwd  198.51.100.1/.2 │ nsext
#                     │  XDP FW+LB │                                        │ lo:
#  ns2 ─veth2h/veth2s─┘  (4 veths) └─vethw2s/vethw2p─ nsp2 ─vethe2p/vethe2x─┘ 192.0.2.10/32
#  10.0.0.2                          172.16.2.1/.2     fwd  203.0.113.1/.2
#
#  - ns1/ns2 usam gateway "fake" 10.0.0.254 (neigh estatico, sem ARP na LAN);
#  - nssw NAO faz IP forwarding (ip_forward=0): todo encaminhamento e XDP;
#  - nsp1/nsp2 sao roteadores comuns do kernel (provedores WAN);
#  - trafego sem rota na route_table sai pela WAN via load balancer.
#
set -euo pipefail

NS1="ns1"; NS2="ns2"; NSSW="nssw"
NSP1="nsp1"; NSP2="nsp2"; NSEXT="nsext"

GW_IP="10.0.0.254"
GW_MAC="02:00:00:00:00:fe"   # MAC do gateway fake (nao existe em nenhuma NIC)
EXT_IP="192.0.2.10"

BPF_PIN="/sys/fs/bpf/xdpunk_prog"
BPF_MAP_DIR="/sys/fs/bpf/xdpunk"

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
XDP_SRC="$SCRIPT_DIR/../xdp/xdp_fw_lb.c"
XDP_OBJ="/tmp/xdp_fw_lb.o"

SW_DEVS=(veth1s veth2s vethw1s vethw2s)

cleanup() {
  set +e
  for dev in "${SW_DEVS[@]}"; do
    ip -n "$NSSW" link set dev "$dev" xdpgeneric off 2>/dev/null || true
  done
  rm -f "$BPF_PIN"
  rm -rf "$BPF_MAP_DIR"
  for ns in "$NS1" "$NS2" "$NSSW" "$NSP1" "$NSP2" "$NSEXT"; do
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

mac_of() {  # mac_of <netns> <iface>
  ip -n "$1" -br link show "$2" | awk '{print $3}'
}

need_cmd ip
need_cmd clang
need_cmd bpftool
need_cmd nsenter
need_cmd xdpunk-cli

if [[ ! -f "$XDP_SRC" ]]; then
  echo "ERRO: arquivo fonte '$XDP_SRC' nao encontrado."
  exit 1
fi

echo "[1/9] Criando namespaces..."
for ns in "$NS1" "$NS2" "$NSSW" "$NSP1" "$NSP2" "$NSEXT"; do
  ip netns add "$ns"
  ip -n "$ns" link set lo up
done

echo "[2/9] Criando veth pairs..."
ip link add veth1h type veth peer name veth1s
ip link add veth2h type veth peer name veth2s
ip link add vethw1s type veth peer name vethw1p
ip link add vethw2s type veth peer name vethw2p
ip link add vethe1p type veth peer name vethe1x
ip link add vethe2p type veth peer name vethe2x

ip link set veth1h  netns "$NS1"
ip link set veth2h  netns "$NS2"
ip link set veth1s  netns "$NSSW"
ip link set veth2s  netns "$NSSW"
ip link set vethw1s netns "$NSSW"
ip link set vethw2s netns "$NSSW"
ip link set vethw1p netns "$NSP1"
ip link set vethe1p netns "$NSP1"
ip link set vethw2p netns "$NSP2"
ip link set vethe2p netns "$NSP2"
ip link set vethe1x netns "$NSEXT"
ip link set vethe2x netns "$NSEXT"

echo "[3/9] Configurando enderecos e subindo interfaces..."
ip -n "$NS1" addr add 10.0.0.1/24 dev veth1h
ip -n "$NS2" addr add 10.0.0.2/24 dev veth2h

# IPs nas veths WAN do switch: apenas para o kernel do nssw responder os
# ARPs dos provedores (o encaminhamento continua 100% XDP).
ip -n "$NSSW" addr add 172.16.1.1/30 dev vethw1s
ip -n "$NSSW" addr add 172.16.2.1/30 dev vethw2s

ip -n "$NSP1" addr add 172.16.1.2/30    dev vethw1p
ip -n "$NSP1" addr add 198.51.100.1/30  dev vethe1p
ip -n "$NSP2" addr add 172.16.2.2/30    dev vethw2p
ip -n "$NSP2" addr add 203.0.113.1/30   dev vethe2p

ip -n "$NSEXT" addr add 198.51.100.2/30 dev vethe1x
ip -n "$NSEXT" addr add 203.0.113.2/30  dev vethe2x
ip -n "$NSEXT" addr add "$EXT_IP/32"    dev lo

ip -n "$NS1"   link set veth1h  up
ip -n "$NS2"   link set veth2h  up
ip -n "$NSSW"  link set veth1s  up
ip -n "$NSSW"  link set veth2s  up
ip -n "$NSSW"  link set vethw1s up
ip -n "$NSSW"  link set vethw2s up
ip -n "$NSP1"  link set vethw1p up
ip -n "$NSP1"  link set vethe1p up
ip -n "$NSP2"  link set vethw2p up
ip -n "$NSP2"  link set vethe2p up
ip -n "$NSEXT" link set vethe1x up
ip -n "$NSEXT" link set vethe2x up

echo "[4/9] Configurando sysctls (forwarding / rp_filter)..."
# nssw: forwarding do kernel DESLIGADO — prova que o encaminhamento e XDP.
ip netns exec "$NSSW" sysctl -qw net.ipv4.ip_forward=0

for ns in "$NSP1" "$NSP2"; do
  ip netns exec "$ns" sysctl -qw net.ipv4.ip_forward=1
  ip netns exec "$ns" sysctl -qw net.ipv4.conf.all.rp_filter=0
  ip netns exec "$ns" sysctl -qw net.ipv4.conf.default.rp_filter=0
done
# nsext: retorno pode chegar por caminho diferente da ida (assimetria).
ip netns exec "$NSEXT" sysctl -qw net.ipv4.conf.all.rp_filter=0
ip netns exec "$NSEXT" sysctl -qw net.ipv4.conf.default.rp_filter=0

# Offloads desligados nas pontas host/provedor: garante que o XDP generico
# veja pacotes de tamanho de fio (medicoes de pps mais fieis).
if command -v ethtool >/dev/null 2>&1; then
  ip netns exec "$NS1"   ethtool -K veth1h  gso off tso off gro off >/dev/null 2>&1 || true
  ip netns exec "$NS2"   ethtool -K veth2h  gso off tso off gro off >/dev/null 2>&1 || true
  ip netns exec "$NSP1"  ethtool -K vethw1p gso off tso off gro off >/dev/null 2>&1 || true
  ip netns exec "$NSP1"  ethtool -K vethe1p gso off tso off gro off >/dev/null 2>&1 || true
  ip netns exec "$NSP2"  ethtool -K vethw2p gso off tso off gro off >/dev/null 2>&1 || true
  ip netns exec "$NSP2"  ethtool -K vethe2p gso off tso off gro off >/dev/null 2>&1 || true
  ip netns exec "$NSEXT" ethtool -K vethe1x gso off tso off gro off >/dev/null 2>&1 || true
  ip netns exec "$NSEXT" ethtool -K vethe2x gso off tso off gro off >/dev/null 2>&1 || true
else
  echo "  AVISO: ethtool nao encontrado — offloads (GSO/TSO) permanecem ativos."
fi

echo "[5/9] Configurando rotas..."
# LAN: gateway fake — rota default + entrada neigh permanente (sem ARP).
for spec in "$NS1:veth1h" "$NS2:veth2h"; do
  ns="${spec%%:*}"; dev="${spec##*:}"
  ip -n "$ns" neigh add "$GW_IP" lladdr "$GW_MAC" dev "$dev" nud permanent
  ip -n "$ns" route add default via "$GW_IP" dev "$dev"
done

# Provedores: retorno para a LAN e ida para a "internet".
ip -n "$NSP1" route add 10.0.0.0/24 via 172.16.1.1
ip -n "$NSP1" route add "$EXT_IP/32" via 198.51.100.2
ip -n "$NSP2" route add 10.0.0.0/24 via 172.16.2.1
ip -n "$NSP2" route add "$EXT_IP/32" via 203.0.113.2

# nsext: retorno deterministico via nsp1 (medicoes). Para o teste de
# retorno assimetrico (F6), troque pela variante ECMP comentada abaixo.
ip -n "$NSEXT" route add 10.0.0.0/24 via 198.51.100.1
# ip -n "$NSEXT" route del 10.0.0.0/24
# ip -n "$NSEXT" route add 10.0.0.0/24 \
#   nexthop via 198.51.100.1 weight 1 \
#   nexthop via 203.0.113.1  weight 1

echo "[6/9] Compilando programa eBPF (XDP)..."
# -mcpu=v3: o round-robin usa __sync_fetch_and_add com valor de retorno
# (BPF_ATOMIC | BPF_FETCH), disponivel a partir do ISA v3 (kernel >= 5.12).
clang -O2 -g -target bpf -mcpu=v3 -c "$XDP_SRC" -o "$XDP_OBJ"

echo "[7/9] Carregando e anexando programa XDP..."
if ! mountpoint -q /sys/fs/bpf 2>/dev/null; then
  mount -t bpf bpf /sys/fs/bpf/ || {
    echo "ERRO: nao foi possivel montar bpffs em /sys/fs/bpf/."
    exit 1
  }
fi
# Carrega o programa e pina TODOS os mapas do objeto em $BPF_MAP_DIR
bpftool prog load "$XDP_OBJ" "$BPF_PIN" pinmaps "$BPF_MAP_DIR"

if [[ ! -e "$BPF_PIN" ]]; then
  echo "ERRO: programa XDP nao foi pinado. Verifique bpffs e o programa BPF."
  exit 1
fi

# nsenter --net troca apenas o network namespace, mantendo o mount
# namespace do caller — o pin em /sys/fs/bpf/ fica visivel.
for dev in "${SW_DEVS[@]}"; do
  nsenter --net=/var/run/netns/"$NSSW" \
    ip link set dev "$dev" xdpgeneric pinned "$BPF_PIN"
done

echo "[8/9] Populando mapas via xdpunk-cli..."
# Fallback manual (fragil, apenas referencia — value structs em hex LE):
#   bpftool map update pinned $BPF_MAP_DIR/route_table \
#     key hex 0a 00 00 01 value hex <ifindex LE32> <dmac 6B> <smac 6B>
MAC1H="$(mac_of "$NS1" veth1h)"
MAC2H="$(mac_of "$NS2" veth2h)"
MACW1P="$(mac_of "$NSP1" vethw1p)"
MACW2P="$(mac_of "$NSP2" vethw2p)"

xdpunk-cli map update 10.0.0.1 veth1s --dmac "$MAC1H"
xdpunk-cli map update 10.0.0.2 veth2s --dmac "$MAC2H"

xdpunk-cli lb link add 0 vethw1s --dmac "$MACW1P"
xdpunk-cli lb link add 1 vethw2s --dmac "$MACW2P"
xdpunk-cli lb mode hash

echo "[9/9] Resumo..."
echo
echo "=================================================================="
echo "Laboratorio XDPunk Fase 2 (firewall + LB WAN) carregado!"
echo
echo "Rotas LAN:    10.0.0.1 -> veth1s (ns1) | 10.0.0.2 -> veth2s (ns2)"
echo "Links WAN:    0 -> vethw1s (nsp1)      | 1 -> vethw2s (nsp2)"
echo "Modo do LB:   hash (afinidade de fluxo)"
echo "Firewall:     sem regras (politica default: ALLOW)"
echo
echo "------------------------------------------------------------------"
echo "Testar conectividade (LAN -> internet, atravessando FW + LB):"
echo "  ip netns exec ns1 ping $EXT_IP"
echo
echo "Observar o caminho nos provedores:"
echo "  ip netns exec nsp1 tcpdump -ni vethw1p"
echo "  ip netns exec nsp2 tcpdump -ni vethw2p"
echo
echo "Firewall (efeito imediato, sem recarregar o XDP):"
echo "  xdpunk-cli fw add --prio 0 --src 10.0.0.1/32 --dst $EXT_IP/32 \\"
echo "      --proto tcp --dport 5201 --action drop"
echo "  xdpunk-cli fw list"
echo
echo "Load balancer:"
echo "  xdpunk-cli lb status"
echo "  xdpunk-cli lb link disable 0     # failover manual"
echo "  xdpunk-cli lb mode rr            # round-robin por pacote"
echo
echo "Contadores do pipeline:"
echo "  xdpunk-cli stats"
echo
echo "Benchmark (iperf3):"
echo "  ip netns exec nsext iperf3 -s -B $EXT_IP"
echo "  ip netns exec ns1 iperf3 -c $EXT_IP -P 8"
echo "=================================================================="

trap - EXIT
