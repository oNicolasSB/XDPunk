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

echo "[1/7] Removendo filtros TC e qdisc clsact no namespace do switch..."
if ip netns list | grep -q "$NSSW"; then
    for dev in veth1s veth2s veth3s; do
        ip netns exec "$NSSW" tc qdisc del dev "$dev" clsact 2>/dev/null || true
    done
fi

echo "[2/7] Removendo namespaces..."
ip netns del "$NS1" 2>/dev/null || true
ip netns del "$NS2" 2>/dev/null || true
ip netns del "$NS3" 2>/dev/null || true
ip netns del "$NSSW" 2>/dev/null || true

echo "[3/7] Removendo veths soltos (caso tenham sobrado no root namespace)..."
for v in "${VETHS[@]}"; do
    ip link del "$v" 2>/dev/null || true
done

echo "[4/7] Removendo clsact de qualquer interface restante no root namespace..."
for dev in $(ip -o link show | awk -F': ' '{print $2}' | cut -d'@' -f1); do
    tc qdisc del dev "$dev" clsact 2>/dev/null || true
done

echo "[5/7] Removendo programas XDP eventualmente anexados..."
for dev in $(ip -o link show | awk -F': ' '{print $2}' | cut -d'@' -f1); do
    ip link set dev "$dev" xdp off 2>/dev/null || true
done

echo "[6/7] Limpando arquivos temporários..."
rm -f /tmp/tc_redirect.c \
      /tmp/tc_redirect_*.o \
      /tmp/tc_forward.c \
      /tmp/tc_forward.o

echo "[7/7] Exibindo possíveis programas BPF ainda carregados (apenas informativo)..."
bpftool prog show 2>/dev/null || true

echo
echo "✅ Ambiente completamente limpo com sucesso!"