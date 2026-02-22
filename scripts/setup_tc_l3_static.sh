#!/usr/bin/env bash
set -euo pipefail

NS1="ns1"
NS2="ns2"
NSSW="nssw"

VETH1H="veth1h"
VETH1S="veth1s"

VETH2H="veth2h"
VETH2S="veth2s"

IP1="10.0.0.1/24"
IP2="10.0.0.2/24"

cleanup() {
  set +e
  ip netns exec "$NSSW" tc qdisc del dev "$VETH1S" clsact 2>/dev/null || true
  ip netns exec "$NSSW" tc qdisc del dev "$VETH2S" clsact 2>/dev/null || true
  ip netns del "$NS1" 2>/dev/null
  ip netns del "$NS2" 2>/dev/null
  ip netns del "$NSSW" 2>/dev/null
  rm -f /tmp/tc_forward.c /tmp/tc_forward.o
}
trap cleanup EXIT

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

echo "[2/6] Criando veth pairs..."
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

ip netns exec "$NSSW" ethtool -K "$VETH1S" gro off gso off tso off 2>/dev/null || true
ip netns exec "$NSSW" ethtool -K "$VETH2S" gro off gso off tso off 2>/dev/null || true

echo "[4/6] Gerando programa eBPF L3 (tabela estática)..."

cat > /tmp/tc_forward.c <<'EOF'
#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/if_arp.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

#ifndef IFINDEX_1
#define IFINDEX_1 0
#endif

#ifndef IFINDEX_2
#define IFINDEX_2 0
#endif

SEC("tc")
int tc_forward_ip(struct __sk_buff *skb)
{
    void *data = (void *)(long)skb->data;
    void *data_end = (void *)(long)skb->data_end;

    struct ethhdr *eth = data;
    if ((void*)(eth + 1) > data_end)
        return BPF_OK;

    // Encaminhar ARP como bridge simples
    if (eth->h_proto == bpf_htons(ETH_P_ARP)) {
        if (skb->ifindex == IFINDEX_1)
            return bpf_redirect(IFINDEX_2, 0);
        else
            return bpf_redirect(IFINDEX_1, 0);
    }

    if (eth->h_proto != bpf_htons(ETH_P_IP))
        return BPF_OK;

    struct iphdr *iph = (void*)(eth + 1);
    if ((void*)(iph + 1) > data_end)
        return BPF_OK;

    __u32 dst_ip = iph->daddr;

    if (dst_ip == bpf_htonl(0x0A000001))
        return bpf_redirect(IFINDEX_1, 0);

    if (dst_ip == bpf_htonl(0x0A000002))
        return bpf_redirect(IFINDEX_2, 0);

    return BPF_OK;
}

char _license[] SEC("license") = "GPL";
EOF

echo "[5/6] Descobrindo ifindex no namespace do switch..."

IF1S=$(ip netns exec "$NSSW" cat /sys/class/net/"$VETH1S"/ifindex)
IF2S=$(ip netns exec "$NSSW" cat /sys/class/net/"$VETH2S"/ifindex)

echo "  - $VETH1S ifindex = $IF1S"
echo "  - $VETH2S ifindex = $IF2S"

echo "[6/6] Compilando e anexando programa TC..."

clang -O2 -g -target bpf \
  -DIFINDEX_1="$IF1S" \
  -DIFINDEX_2="$IF2S" \
  -c /tmp/tc_forward.c -o /tmp/tc_forward.o

ip netns exec "$NSSW" tc qdisc add dev "$VETH1S" clsact
ip netns exec "$NSSW" tc filter add dev "$VETH1S" ingress bpf da obj /tmp/tc_forward.o sec tc

ip netns exec "$NSSW" tc qdisc add dev "$VETH2S" clsact
ip netns exec "$NSSW" tc filter add dev "$VETH2S" ingress bpf da obj /tmp/tc_forward.o sec tc

echo
echo "=============================================="
echo "Fase 2 concluída: Encaminhamento L3 estático"
echo "=============================================="
echo
echo "Teste:"
echo "  ip netns exec $NS1 ping -c 3 10.0.0.2"
echo
echo "Ver estatísticas:"
echo "  ip netns exec $NSSW tc -s filter show dev $VETH1S ingress"
echo "  ip netns exec $NSSW tc -s filter show dev $VETH2S ingress"
echo
echo "Pressione Ctrl+C para limpar ambiente."

trap - EXIT