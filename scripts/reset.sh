#!/usr/bin/env bash
set -euo pipefail

NS1="ns1"
NS2="ns2"
NS3="ns3"
NSSW="nssw"

VETHS=("veth1h" "veth1s" "veth2h" "veth2s" "veth3h" "veth3s")

echo "======================================"
echo "RESETANDO AMBIENTE DE REDE VIRTUAL"
echo "======================================"

echo "[1/7] Removendo programas eBPF do namespace do switch..."
if ip netns list | grep -q "$NSSW"; then
    for dev in veth1s veth2s veth3s; do
        # Remover XDP (nativo e genérico)
        ip netns exec "$NSSW" ip link set dev "$dev" xdp off 2>/dev/null || true
        ip netns exec "$NSSW" ip link set dev "$dev" xdpgeneric off 2>/dev/null || true
        # Remover filtros TC (clsact)
        ip netns exec "$NSSW" tc qdisc del dev "$dev" clsact 2>/dev/null || true
    done

    # Desabilitar ip_forward
    ip netns exec "$NSSW" sysctl -w net.ipv4.ip_forward=0 >/dev/null 2>&1 || true
fi

echo "[2/7] Removendo namespaces..."
ip netns del "$NS1" 2>/dev/null || true
ip netns del "$NS2" 2>/dev/null || true
ip netns del "$NS3" 2>/dev/null || true
ip netns del "$NSSW" 2>/dev/null || true

echo "[3/7] Removendo veths soltos (root namespace)..."
for v in "${VETHS[@]}"; do
    ip link del "$v" 2>/dev/null || true
done

echo "[4/7] Removendo XDP de qualquer interface no root namespace..."
for dev in $(ip -o link show | awk -F': ' '{print $2}' | cut -d'@' -f1); do
    ip link set dev "$dev" xdp off 2>/dev/null || true
done

echo "[5/7] Limpando arquivos temporários..."
rm -f /tmp/xdp_switch.c \
      /tmp/xdp_switch.o \
      /tmp/xdp_forward.c \
      /tmp/xdp_forward.o \
      /tmp/tc_forward.c \
      /tmp/tc_forward.o \
      /tmp/tc_redirect.c \
      /tmp/tc_redirect_*.o

echo "[6/7] Verificando programas BPF carregados (informativo)..."
bpftool prog show 2>/dev/null || true

echo "[7/7] Verificando mapas BPF restantes (informativo)..."
bpftool map show 2>/dev/null || true

echo
echo "✅ Ambiente completamente limpo com sucesso!"