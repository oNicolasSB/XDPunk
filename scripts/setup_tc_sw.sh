#!/usr/bin/env bash
set -euo pipefail

NS1="ns1"
NS2="ns2"
NSSW="nssw"

# veth pairs:
# ns1 <-> nssw
VETH1H="veth1h"   # host side in ns1
VETH1S="veth1s"   # switch side in nssw

# ns2 <-> nssw
VETH2H="veth2h"   # host side in ns2
VETH2S="veth2s"   # switch side in nssw

# IPs for hosts (same subnet)
IP1="10.0.0.1/24"
IP2="10.0.0.2/24"

cleanup() {
  set +e
  tc_in_sw_del "$VETH1S"
  tc_in_sw_del "$VETH2S"
  ip netns del "$NS1" 2>/dev/null
  ip netns del "$NS2" 2>/dev/null
  ip netns del "$NSSW" 2>/dev/null
  rm -f /tmp/tc_redirect.c /tmp/tc_redirect_*.o
}
trap cleanup EXIT

tc_in_sw_del() {
  local dev="$1"
  ip netns exec "$NSSW" tc qdisc del dev "$dev" clsact 2>/dev/null || true
}

need_cmd() {
  command -v "$1" >/dev/null 2>&1 || {
    echo "ERRO: comando '$1' não encontrado."
    exit 1
  }
}

need_cmd ip
need_cmd tc
need_cmd clang

echo "[1/6] Criando namespaces..."
ip netns add "$NS1"
ip netns add "$NS2"
ip netns add "$NSSW"

echo "[2/6] Criando veth pairs e movendo para namespaces..."
ip link add "$VETH1H" type veth peer name "$VETH1S"
ip link add "$VETH2H" type veth peer name "$VETH2S"

ip link set "$VETH1H" netns "$NS1"
ip link set "$VETH2H" netns "$NS2"
ip link set "$VETH1S" netns "$NSSW"
ip link set "$VETH2S" netns "$NSSW"

echo "[3/6] Subindo interfaces e configurando IPs..."
ip -n "$NS1" link set lo up
ip -n "$NS2" link set lo up
ip -n "$NSSW" link set lo up

ip -n "$NS1" addr add "$IP1" dev "$VETH1H"
ip -n "$NS2" addr add "$IP2" dev "$VETH2H"

ip -n "$NS1" link set "$VETH1H" up
ip -n "$NS2" link set "$VETH2H" up
ip -n "$NSSW" link set "$VETH1S" up
ip -n "$NSSW" link set "$VETH2S" up

# (Opcional) desativa offloads que às vezes atrapalham testes/visibilidade
ip netns exec "$NSSW" ethtool -K "$VETH1S" gro off gso off tso off 2>/dev/null || true
ip netns exec "$NSSW" ethtool -K "$VETH2S" gro off gso off tso off 2>/dev/null || true

echo "[4/6] Gerando programa TC/eBPF (redirect simples por ifindex)..."
cat > /tmp/tc_redirect.c <<'EOF'
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

#ifndef OUT_IFINDEX
#define OUT_IFINDEX 0
#endif

SEC("tc")
int tc_redirect(struct __sk_buff *skb)
{
    if (OUT_IFINDEX == 0)
        return BPF_OK; // sem redirect (segurança)
    return bpf_redirect(OUT_IFINDEX, 0);
}

char _license[] SEC("license") = "GPL";
EOF

# Descobre ifindex das portas NO namespace do switch
IF1S=$(ip netns exec "$NSSW" cat /sys/class/net/"$VETH1S"/ifindex)
IF2S=$(ip netns exec "$NSSW" cat /sys/class/net/"$VETH2S"/ifindex)

echo "  - ifindex $VETH1S = $IF1S"
echo "  - ifindex $VETH2S = $IF2S"

echo "[5/6] Compilando dois objetos (um por direção)..."
clang -O2 -g -target bpf -DOUT_IFINDEX="$IF2S" -c /tmp/tc_redirect.c -o /tmp/tc_redirect_1to2.o
clang -O2 -g -target bpf -DOUT_IFINDEX="$IF1S" -c /tmp/tc_redirect.c -o /tmp/tc_redirect_2to1.o

echo "[6/6] Instalando TC (clsact) e anexando filtros ingress..."
# Para tráfego que entra no switch pela porta do ns1, manda para a porta do ns2
ip netns exec "$NSSW" tc qdisc add dev "$VETH1S" clsact
ip netns exec "$NSSW" tc filter add dev "$VETH1S" ingress bpf da obj /tmp/tc_redirect_1to2.o sec tc

# Para tráfego que entra no switch pela porta do ns2, manda para a porta do ns1 (bidirecional)
ip netns exec "$NSSW" tc qdisc add dev "$VETH2S" clsact
ip netns exec "$NSSW" tc filter add dev "$VETH2S" ingress bpf da obj /tmp/tc_redirect_2to1.o sec tc

echo
echo "Pronto!"
echo "Teste: ip netns exec $NS1 ping -c 3 10.0.0.2"
echo "Ver TC: ip netns exec $NSSW tc -s filter show dev $VETH1S ingress"
echo "        ip netns exec $NSSW tc -s filter show dev $VETH2S ingress"
echo
echo "Para limpar: Ctrl+C (o script está com trap) ou rode manualmente: ip netns del ns1; ip netns del ns2; ip netns del nssw"
echo
echo "OBS: Este script mantém rodando? Não. Ele configura e sai. O trap aqui serve se você interromper durante a execução."
trap - EXIT
