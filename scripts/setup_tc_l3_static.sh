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

cleanup() {
  set +e
  for dev in "$VETH1S" "$VETH2S" "$VETH3S"; do
    ip netns exec "$NSSW" tc qdisc del dev "$dev" clsact 2>/dev/null || true
  done
  ip netns del "$NS1" 2>/dev/null
  ip netns del "$NS2" 2>/dev/null
  ip netns del "$NS3" 2>/dev/null
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

echo "[4/7] Gerando programa eBPF..."

cat > /tmp/tc_forward.c <<'EOF'
#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/if_arp.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

#ifndef IF1
#define IF1 0
#endif

#ifndef IF2
#define IF2 0
#endif

#ifndef IF3
#define IF3 0
#endif

SEC("tc")
int tc_forward(struct __sk_buff *skb)
{
    void *data = (void *)(long)skb->data;
    void *data_end = (void *)(long)skb->data_end;

    struct ethhdr *eth = data;
    if ((void*)(eth + 1) > data_end)
        return BPF_OK;

    // ARP flooding simples
    if (eth->h_proto == bpf_htons(ETH_P_ARP)) {
        if (skb->ifindex == IF1) return bpf_redirect(IF2, 0);
        if (skb->ifindex == IF2) return bpf_redirect(IF1, 0);
        if (skb->ifindex == IF3) return bpf_redirect(IF1, 0);
    }

    if (eth->h_proto != bpf_htons(ETH_P_IP))
        return BPF_OK;

    struct iphdr *iph = (void*)(eth + 1);
    if ((void*)(iph + 1) > data_end)
        return BPF_OK;

    __u32 dst = iph->daddr;

    // 10.0.0.1 -> ns1
    if (dst == bpf_htonl(0x0A000001))
        return bpf_redirect(IF1, 0);

    // 10.0.0.2 -> REDIRECIONA PARA ns3
    if (dst == bpf_htonl(0x0A000002))
        return bpf_redirect(IF3, 0);

    // 10.0.0.3 -> ns3
    if (dst == bpf_htonl(0x0A000003))
        return bpf_redirect(IF3, 0);

    return BPF_OK;
}

char _license[] SEC("license") = "GPL";
EOF

echo "[5/7] Descobrindo ifindex..."

IF1=$(ip netns exec "$NSSW" cat /sys/class/net/"$VETH1S"/ifindex)
IF2=$(ip netns exec "$NSSW" cat /sys/class/net/"$VETH2S"/ifindex)
IF3=$(ip netns exec "$NSSW" cat /sys/class/net/"$VETH3S"/ifindex)

echo "IF1=$IF1 IF2=$IF2 IF3=$IF3"

echo "[6/7] Compilando..."

clang -O2 -g -target bpf \
  -DIF1="$IF1" \
  -DIF2="$IF2" \
  -DIF3="$IF3" \
  -c /tmp/tc_forward.c -o /tmp/tc_forward.o

echo "[7/7] Instalando filtros..."

for dev in "$VETH1S" "$VETH2S" "$VETH3S"; do
  ip netns exec "$NSSW" tc qdisc add dev "$dev" clsact
  ip netns exec "$NSSW" tc filter add dev "$dev" ingress bpf da obj /tmp/tc_forward.o sec tc
done

echo
echo "=============================================="
echo "Agora teste:"
echo
echo "1) No ns3 rode:"
echo "   ip netns exec ns3 tcpdump -i veth3h"
echo
echo "2) No ns1 rode:"
echo "   ip netns exec ns1 ping 10.0.0.2"
echo
echo "Você verá o ping chegando no ns3."
echo "=============================================="

trap - EXIT