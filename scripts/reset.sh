#!/usr/bin/env bash
set -euo pipefail

NS1="ns1"
NS2="ns2"
NSSW="nssw"

VETHS=("veth1h" "veth1s" "veth2h" "veth2s")

echo "======================================"
echo "RESETANDO AMBIENTE DE REDE VIRTUAL"
echo "======================================"

echo "[1/6] Removendo filtros TC e qdisc clsact (se existirem)..."
if ip netns list | grep -q "$NSSW"; then
    for dev in veth1s veth2s; do
        ip netns exec "$NSSW" tc qdisc del dev "$dev" clsact 2>/dev/null || true
    done
fi

echo "[2/6] Removendo namespaces..."
ip netns del "$NS1" 2>/dev/null || true
ip netns del "$NS2" 2>/dev/null || true
ip netns del "$NSSW" 2>/dev/null || true

echo "[3/6] Removendo veths soltos (caso tenham sobrado no root namespace)..."
for v in "${VETHS[@]}"; do
    ip link del "$v" 2>/dev/null || true
done

echo "[4/6] Removendo programas BPF carregados via tc..."
tc filter show 2>/dev/null | grep bpf >/dev/null 2>&1 && \
    echo "⚠️  Existem filtros BPF no root namespace. Removendo clsact de todas interfaces..."

for dev in $(ip -o link show | awk -F': ' '{print $2}'); do
    tc qdisc del dev "$dev" clsact 2>/dev/null || true
done

echo "[5/6] Limpando arquivos temporários..."
rm -f /tmp/tc_redirect.c /tmp/tc_redirect_*.o

echo "[6/6] Limpando possíveis mapas BPF órfãos..."
bpftool net detach xdp dev 2>/dev/null || true
bpftool prog show 2>/dev/null || true

echo
echo "✅ Ambiente limpo com sucesso!"