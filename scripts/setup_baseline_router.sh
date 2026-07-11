#!/usr/bin/env bash
#
# setup_baseline_router.sh — baseline para os experimentos da Fase 2.
#
# Mesma topologia do setup_xdp_fw_lb.sh, porem SEM XDP: o nssw opera como
# roteador comum do kernel Linux.
#
#   - LAN: bridge br0 (veth1s + veth2s) com o IP de gateway 10.0.0.254/24;
#   - firewall baseline: iptables na chain FORWARD (--fw-rules N adiciona
#     N regras nao-casantes — pior caso do scan linear, espelhando o
#     experimento Q1 do firewall XDP). O trafego LAN->LAN em bridge so
#     atravessa o iptables com br_netfilter (bridge-nf-call-iptables=1);
#   - LB baseline: rota ECMP com hash L4 (--ecmp), comparavel ao modo
#     hash do LB XDP (experimento Q3).
#
# Uso: sudo bash setup_baseline_router.sh [--fw-rules N] [--ecmp]
#
set -euo pipefail

NS1="ns1"; NS2="ns2"; NSSW="nssw"
NSP1="nsp1"; NSP2="nsp2"; NSEXT="nsext"

GW_IP="10.0.0.254"
EXT_IP="192.0.2.10"

FW_RULES=0
ECMP=0
while [[ $# -gt 0 ]]; do
  case "$1" in
    --fw-rules) FW_RULES="$2"; shift 2 ;;
    --ecmp)     ECMP=1; shift ;;
    *) echo "Uso: $0 [--fw-rules N] [--ecmp]"; exit 1 ;;
  esac
done

cleanup() {
  set +e
  for ns in "$NS1" "$NS2" "$NSSW" "$NSP1" "$NSP2" "$NSEXT"; do
    ip netns del "$ns" 2>/dev/null
  done
}
trap cleanup EXIT

need_cmd() {
  command -v "$1" >/dev/null 2>&1 || {
    echo "ERRO: comando '$1' nao encontrado."
    exit 1
  }
}

need_cmd ip
[[ "$FW_RULES" -gt 0 ]] && need_cmd iptables

echo "[1/7] Criando namespaces..."
for ns in "$NS1" "$NS2" "$NSSW" "$NSP1" "$NSP2" "$NSEXT"; do
  ip netns add "$ns"
  ip -n "$ns" link set lo up
done

echo "[2/7] Criando veth pairs..."
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

echo "[3/7] Configurando bridge LAN e enderecos..."
# Bridge br0 une as portas LAN; o IP do gateway fica na propria bridge.
ip -n "$NSSW" link add br0 type bridge
ip -n "$NSSW" link set veth1s master br0
ip -n "$NSSW" link set veth2s master br0
ip -n "$NSSW" addr add "$GW_IP/24" dev br0

ip -n "$NS1" addr add 10.0.0.1/24 dev veth1h
ip -n "$NS2" addr add 10.0.0.2/24 dev veth2h

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
ip -n "$NSSW"  link set br0     up
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

echo "[4/7] Configurando sysctls..."
ip netns exec "$NSSW" sysctl -qw net.ipv4.ip_forward=1
for ns in "$NSP1" "$NSP2"; do
  ip netns exec "$ns" sysctl -qw net.ipv4.ip_forward=1
  ip netns exec "$ns" sysctl -qw net.ipv4.conf.all.rp_filter=0
  ip netns exec "$ns" sysctl -qw net.ipv4.conf.default.rp_filter=0
done
ip netns exec "$NSEXT" sysctl -qw net.ipv4.conf.all.rp_filter=0
ip netns exec "$NSEXT" sysctl -qw net.ipv4.conf.default.rp_filter=0

# Hash L4 no ECMP (equivalente ao hash de 5-tupla do LB XDP)
if [[ "$ECMP" -eq 1 ]]; then
  ip netns exec "$NSSW" sysctl -qw net.ipv4.fib_multipath_hash_policy=1
fi

# br_netfilter: faz o trafego em bridge (LAN->LAN) atravessar o iptables
# FORWARD — necessario para o baseline de firewall do experimento Q1.
if [[ "$FW_RULES" -gt 0 ]]; then
  modprobe br_netfilter 2>/dev/null || true
  if ! ip netns exec "$NSSW" sysctl -qw net.bridge.bridge-nf-call-iptables=1; then
    echo "  AVISO: br_netfilter indisponivel — iptables nao vera trafego LAN->LAN."
  fi
fi

# Offloads desligados (mesma condicao do lab XDP, comparacao justa)
if command -v ethtool >/dev/null 2>&1; then
  ip netns exec "$NS1"   ethtool -K veth1h  gso off tso off gro off >/dev/null 2>&1 || true
  ip netns exec "$NS2"   ethtool -K veth2h  gso off tso off gro off >/dev/null 2>&1 || true
  ip netns exec "$NSP1"  ethtool -K vethw1p gso off tso off gro off >/dev/null 2>&1 || true
  ip netns exec "$NSP1"  ethtool -K vethe1p gso off tso off gro off >/dev/null 2>&1 || true
  ip netns exec "$NSP2"  ethtool -K vethw2p gso off tso off gro off >/dev/null 2>&1 || true
  ip netns exec "$NSP2"  ethtool -K vethe2p gso off tso off gro off >/dev/null 2>&1 || true
  ip netns exec "$NSEXT" ethtool -K vethe1x gso off tso off gro off >/dev/null 2>&1 || true
  ip netns exec "$NSEXT" ethtool -K vethe2x gso off tso off gro off >/dev/null 2>&1 || true
fi

echo "[5/7] Configurando rotas..."
# LAN: gateway real — o kernel do nssw responde ARP por 10.0.0.254 (br0).
ip -n "$NS1" route add default via "$GW_IP" dev veth1h
ip -n "$NS2" route add default via "$GW_IP" dev veth2h

if [[ "$ECMP" -eq 1 ]]; then
  ip -n "$NSSW" route add "$EXT_IP/32" \
    nexthop via 172.16.1.2 dev vethw1s weight 1 \
    nexthop via 172.16.2.2 dev vethw2s weight 1
else
  ip -n "$NSSW" route add "$EXT_IP/32" via 172.16.1.2
fi

ip -n "$NSP1" route add 10.0.0.0/24 via 172.16.1.1
ip -n "$NSP1" route add "$EXT_IP/32" via 198.51.100.2
ip -n "$NSP2" route add 10.0.0.0/24 via 172.16.2.1
ip -n "$NSP2" route add "$EXT_IP/32" via 203.0.113.2

ip -n "$NSEXT" route add 10.0.0.0/24 via 198.51.100.1

echo "[6/7] Configurando iptables ($FW_RULES regra(s) nao-casante(s))..."
if [[ "$FW_RULES" -gt 0 ]]; then
  # Regras que nunca casam com o trafego do lab (src 198.18.0.0/15 =
  # faixa de benchmarking, RFC 2544): todo pacote percorre as N regras
  # e cai na policy ACCEPT — pior caso, espelhando o scan do XDP.
  for ((i = 1; i <= FW_RULES; i++)); do
    ip netns exec "$NSSW" iptables -A FORWARD \
      -p tcp -s "198.18.0.$((i % 254 + 1))" --dport 9 -j DROP
  done
fi

echo "[7/7] Resumo..."
echo
echo "=================================================================="
echo "Baseline (roteador kernel, SEM XDP) carregado!"
echo
echo "LAN:       br0 (veth1s+veth2s), gateway $GW_IP"
echo "Rota WAN:  $([[ "$ECMP" -eq 1 ]] && echo 'ECMP via nsp1+nsp2 (hash L4)' || echo 'unica via nsp1')"
echo "iptables:  $FW_RULES regra(s) na chain FORWARD"
echo
echo "Testar:"
echo "  ip netns exec ns1 ping 10.0.0.2"
echo "  ip netns exec ns1 ping $EXT_IP"
echo "  ip netns exec nssw iptables -L FORWARD -v -n"
echo "  ip -n nssw -s link show vethw1s   # distribuicao ECMP por link"
echo "=================================================================="

trap - EXIT
