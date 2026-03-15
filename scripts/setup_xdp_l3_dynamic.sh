#!/usr/bin/env bash
set -euo pipefail

NS1="ns1"
NS2="ns2"
NS3="ns3"
NSSW="nssw"

VETH1H="veth1h"
VETH1S="veth1s"

VETH2H="veth2h"
VETH2S="veth2s"

VETH3H="veth3h"
VETH3S="veth3s"

IP1="10.0.0.1/24"
IP2="10.0.0.2/24"
IP3="10.0.0.3/24"

BPF_PIN="/sys/fs/bpf/xdp_fwd"
BPF_MAP_DIR="/sys/fs/bpf/xdp_fwd_maps"

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
XDP_SRC="$SCRIPT_DIR/../xdp/xdp_forward_dynamic.c"
XDP_OBJ="/tmp/xdp_forward_dynamic.o"

cleanup() {
  set +e
  for dev in "$VETH1S" "$VETH2S" "$VETH3S"; do
    ip -n "$NSSW" link set dev "$dev" xdpgeneric off 2>/dev/null || true
  done
  rm -f "$BPF_PIN"
  rm -rf "$BPF_MAP_DIR"
  ip netns del "$NS1" 2>/dev/null
  ip netns del "$NS2" 2>/dev/null
  ip netns del "$NS3" 2>/dev/null
  ip netns del "$NSSW" 2>/dev/null
  rm -f "$XDP_OBJ"
}
trap cleanup EXIT

need_cmd() {
  command -v "$1" >/dev/null 2>&1 || {
    echo "ERRO: comando '$1' nao encontrado."
    exit 1
  }
}

le32() {
  printf '%02x %02x %02x %02x' \
    $(($1 & 0xff)) \
    $((($1 >> 8) & 0xff)) \
    $((($1 >> 16) & 0xff)) \
    $((($1 >> 24) & 0xff))
}

need_cmd ip
need_cmd clang
need_cmd bpftool
need_cmd nsenter

if [[ ! -f "$XDP_SRC" ]]; then
  echo "ERRO: arquivo fonte '$XDP_SRC' nao encontrado."
  exit 1
fi

echo "[1/7] Criando namespaces..."
ip netns add "$NS1"
ip netns add "$NS2"
ip netns add "$NS3"
ip netns add "$NSSW"

echo "[2/7] Criando veth pairs..."
ip link add "$VETH1H" type veth peer name "$VETH1S"
ip link add "$VETH2H" type veth peer name "$VETH2S"
ip link add "$VETH3H" type veth peer name "$VETH3S"

ip link set "$VETH1H" netns "$NS1"
ip link set "$VETH2H" netns "$NS2"
ip link set "$VETH3H" netns "$NS3"

ip link set "$VETH1S" netns "$NSSW"
ip link set "$VETH2S" netns "$NSSW"
ip link set "$VETH3S" netns "$NSSW"

echo "[3/7] Subindo interfaces..."
for ns in "$NS1" "$NS2" "$NS3" "$NSSW"; do
  ip -n "$ns" link set lo up
done

ip -n "$NS1" addr add "$IP1" dev "$VETH1H"
ip -n "$NS2" addr add "$IP2" dev "$VETH2H"
ip -n "$NS3" addr add "$IP3" dev "$VETH3H"

ip -n "$NS1" link set "$VETH1H" up
ip -n "$NS2" link set "$VETH2H" up
ip -n "$NS3" link set "$VETH3H" up

ip -n "$NSSW" link set "$VETH1S" up
ip -n "$NSSW" link set "$VETH2S" up
ip -n "$NSSW" link set "$VETH3S" up

echo "[4/7] Compilando programa eBPF (XDP)..."

clang -O2 -g -target bpf \
  -c "$XDP_SRC" -o "$XDP_OBJ"

echo "[5/7] Descobrindo ifindex..."

IF1=$(ip netns exec "$NSSW" cat /sys/class/net/"$VETH1S"/ifindex)
IF2=$(ip netns exec "$NSSW" cat /sys/class/net/"$VETH2S"/ifindex)
IF3=$(ip netns exec "$NSSW" cat /sys/class/net/"$VETH3S"/ifindex)

echo "  $VETH1S=$IF1  $VETH2S=$IF2  $VETH3S=$IF3"

echo "[6/7] Carregando e anexando programa XDP..."

# Garante que o bpffs esta montado
if ! mountpoint -q /sys/fs/bpf 2>/dev/null; then
  mount -t bpf bpf /sys/fs/bpf/ || {
    echo "ERRO: nao foi possivel montar bpffs em /sys/fs/bpf/."
    exit 1
  }
fi
# Carrega o programa e pina automaticamente o mapa em $BPF_MAP_DIR
bpftool prog load "$XDP_OBJ" "$BPF_PIN" pinmaps "$BPF_MAP_DIR"

if [[ ! -e "$BPF_PIN" ]]; then
  echo "ERRO: programa XDP nao foi pinado. Verifique bpffs e o programa BPF."
  exit 1
fi

# Anexa o mesmo programa pinado em cada interface do switch.
# nsenter --net faz apenas setns() para o network namespace, mantendo
# o mount namespace do caller — o pin em /sys/fs/bpf/ fica visivel.
for dev in "$VETH1S" "$VETH2S" "$VETH3S"; do
  nsenter --net=/var/run/netns/"$NSSW" \
    ip link set dev "$dev" xdpgeneric pinned "$BPF_PIN"
done

echo "[7/7] Populando tabela de rotas..."

bpftool map update pinned "$BPF_MAP_DIR/route_table" \
  key hex 0a 00 00 01 value hex $(le32 "$IF1")

bpftool map update pinned "$BPF_MAP_DIR/route_table" \
  key hex 0a 00 00 02 value hex $(le32 "$IF2")

bpftool map update pinned "$BPF_MAP_DIR/route_table" \
  key hex 0a 00 00 03 value hex $(le32 "$IF3")

echo
echo "=============================================="
echo "Tabela de roteamento dinamica carregada!"
echo
echo "Rotas iniciais:"
echo "  10.0.0.1 -> $VETH1S (ns1)  ifindex=$IF1"
echo "  10.0.0.2 -> $VETH2S (ns2)  ifindex=$IF2"
echo "  10.0.0.3 -> $VETH3S (ns3)  ifindex=$IF3"
echo
echo "----------------------------------------------"
echo "Gerenciar rotas em tempo real (como root):"
echo
echo "  Ver todas as rotas:"
echo "    bpftool map dump pinned $BPF_MAP_DIR/route_table"
echo
echo "  Redirecionar 10.0.0.2 para ns3:"
echo "    bpftool map update pinned $BPF_MAP_DIR/route_table \\"
echo "      key hex 0a 00 00 02 value hex $(le32 "$IF3")"
echo
echo "  Restaurar 10.0.0.2 para ns2:"
echo "    bpftool map update pinned $BPF_MAP_DIR/route_table \\"
echo "      key hex 0a 00 00 02 value hex $(le32 "$IF2")"
echo
echo "  Remover rota para 10.0.0.3:"
echo "    bpftool map delete pinned $BPF_MAP_DIR/route_table \\"
echo "      key hex 0a 00 00 03"
echo
echo "----------------------------------------------"
echo "Testar:"
echo "  ip netns exec ns1 ping 10.0.0.2"
echo "  ip netns exec ns3 tcpdump -i veth3h"
echo "=============================================="

trap - EXIT