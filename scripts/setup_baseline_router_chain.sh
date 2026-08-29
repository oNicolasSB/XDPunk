#!/usr/bin/env bash
#
# setup_baseline_router_chain.sh — baseline sem XDP da topologia encadeada
# A-R1-{R2,R3}-R4-B: R1 e R4 viram roteadores kernel comuns com ECMP
# (hash L4), R2/R3 identicos ao lab XDP (roteadores de transito).
#
# Uso: sudo bash setup_baseline_router_chain.sh
#
set -euo pipefail

NSA="nsA"; NSR1="nsr1"; NSR2="nsr2"; NSR3="nsr3"; NSR4="nsr4"; NSB="nsB"
GW_A_IP="10.10.1.254"; GW_B_IP="10.10.2.254"
A_IP="10.10.1.1"; B_IP="10.10.2.1"

cleanup() {
  set +e
  for ns in "$NSA" "$NSR1" "$NSR2" "$NSR3" "$NSR4" "$NSB"; do
    ip netns del "$ns" 2>/dev/null
  done
}
trap cleanup EXIT

need_cmd() {
  command -v "$1" >/dev/null 2>&1 || { echo "ERRO: comando '$1' nao encontrado."; exit 1; }
}
need_cmd ip

echo "[1/6] Criando namespaces..."
for ns in "$NSA" "$NSR1" "$NSR2" "$NSR3" "$NSR4" "$NSB"; do
  ip netns add "$ns"
  ip -n "$ns" link set lo up
done

echo "[2/6] Criando veth pairs..."
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

echo "[3/6] Configurando enderecos (gateway REAL — kernel responde ARP)..."
ip -n "$NSA" addr add "$A_IP/24" dev vethA
ip -n "$NSB" addr add "$B_IP/24" dev vethB
ip -n "$NSR1" addr add "$GW_A_IP/24" dev vethAr1
ip -n "$NSR4" addr add "$GW_B_IP/24" dev vethR4B
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

echo "[4/6] Configurando sysctls (ip_forward, rp_filter, ECMP hash L4)..."
for ns in "$NSR1" "$NSR2" "$NSR3" "$NSR4"; do
  ip netns exec "$ns" sysctl -qw net.ipv4.ip_forward=1
  ip netns exec "$ns" sysctl -qw net.ipv4.conf.all.rp_filter=0
  ip netns exec "$ns" sysctl -qw net.ipv4.conf.default.rp_filter=0
done
ip netns exec "$NSR1" sysctl -qw net.ipv4.fib_multipath_hash_policy=1
ip netns exec "$NSR4" sysctl -qw net.ipv4.fib_multipath_hash_policy=1

if command -v ethtool >/dev/null 2>&1; then
  ip netns exec "$NSA"  ethtool -K vethA   gso off tso off gro off >/dev/null 2>&1 || true
  ip netns exec "$NSB"  ethtool -K vethB   gso off tso off gro off >/dev/null 2>&1 || true
  ip netns exec "$NSR2" ethtool -K vethR21 gso off tso off gro off >/dev/null 2>&1 || true
  ip netns exec "$NSR2" ethtool -K vethR24 gso off tso off gro off >/dev/null 2>&1 || true
  ip netns exec "$NSR3" ethtool -K vethR31 gso off tso off gro off >/dev/null 2>&1 || true
  ip netns exec "$NSR3" ethtool -K vethR34 gso off tso off gro off >/dev/null 2>&1 || true
fi

echo "[5/6] Configurando rotas (ECMP em R1 e R4)..."
ip -n "$NSA" route add default via "$GW_A_IP" dev vethA
ip -n "$NSB" route add default via "$GW_B_IP" dev vethB

ip -n "$NSR1" route add 10.10.2.0/24 \
  nexthop via 172.20.1.2 dev vethR12 weight 1 \
  nexthop via 172.20.2.2 dev vethR13 weight 1
ip -n "$NSR4" route add 10.10.1.0/24 \
  nexthop via 172.20.3.1 dev vethR42 weight 1 \
  nexthop via 172.20.4.1 dev vethR43 weight 1

ip -n "$NSR2" route add 10.10.1.0/24 via 172.20.1.1
ip -n "$NSR2" route add 10.10.2.0/24 via 172.20.3.2
ip -n "$NSR3" route add 10.10.1.0/24 via 172.20.2.1
ip -n "$NSR3" route add 10.10.2.0/24 via 172.20.4.2

echo "[6/6] Resumo..."
echo
echo "=================================================================="
echo "Baseline encadeado (roteadores kernel + ECMP, SEM XDP) carregado!"
echo
echo "Testar:"
echo "  ip netns exec nsA ping -c 3 $B_IP"
echo "  ip -n nsr1 route get $B_IP"
echo "  ip -n nsr1 -s link show vethR12   # distribuicao ECMP por link"
echo "=================================================================="

trap - EXIT
