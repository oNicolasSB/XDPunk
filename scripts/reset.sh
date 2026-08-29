#!/bin/bash
set -euo pipefail

NS1="ns1"
NS2="ns2"
NS3="ns3"
NSSW="nssw"
NSP1="nsp1"
NSP2="nsp2"
NSEXT="nsext"
NSA="nsA"
NSR1="nsr1"
NSR2="nsr2"
NSR3="nsr3"
NSR4="nsr4"
NSB="nsB"

VETHS=("veth1h" "veth1s" "veth2h" "veth2s" "veth3h" "veth3s"
       "vethw1s" "vethw1p" "vethw2s" "vethw2p"
       "vethe1p" "vethe1x" "vethe2p" "vethe2x"
       "vethA" "vethAr1" "vethR12" "vethR21" "vethR13" "vethR31"
       "vethR24" "vethR42" "vethR34" "vethR43" "vethR4B" "vethB")

echo "======================================"
echo "RESETANDO AMBIENTE DE REDE VIRTUAL"
echo "======================================"

echo "[1/7] Removendo programas eBPF do namespace do switch..."
if ip netns list | grep -q "$NSSW"; then
    for dev in veth1s veth2s veth3s vethw1s vethw2s; do
        # Remover XDP (nativo e generico)
        ip netns exec "$NSSW" ip link set dev "$dev" xdp off 2>/dev/null || true
        ip netns exec "$NSSW" ip link set dev "$dev" xdpgeneric off 2>/dev/null || true
        # Remover filtros TC (clsact)
        ip netns exec "$NSSW" tc qdisc del dev "$dev" clsact 2>/dev/null || true
    done

    # Limpar iptables do baseline e desabilitar ip_forward
    ip netns exec "$NSSW" iptables -F FORWARD 2>/dev/null || true
    ip netns exec "$NSSW" sysctl -w net.ipv4.ip_forward=0 >/dev/null 2>&1 || true
fi

if ip netns list | grep -q "$NSR1"; then
    for dev in vethAr1 vethR12 vethR13; do
        ip netns exec "$NSR1" ip link set dev "$dev" xdp off 2>/dev/null || true
        ip netns exec "$NSR1" ip link set dev "$dev" xdpgeneric off 2>/dev/null || true
    done
fi
if ip netns list | grep -q "$NSR4"; then
    for dev in vethR42 vethR43 vethR4B; do
        ip netns exec "$NSR4" ip link set dev "$dev" xdp off 2>/dev/null || true
        ip netns exec "$NSR4" ip link set dev "$dev" xdpgeneric off 2>/dev/null || true
    done
fi

echo "[2/7] Removendo namespaces..."
for ns in "$NS1" "$NS2" "$NS3" "$NSSW" "$NSP1" "$NSP2" "$NSEXT" \
          "$NSA" "$NSR1" "$NSR2" "$NSR3" "$NSR4" "$NSB"; do
    ip netns del "$ns" 2>/dev/null || true
done

echo "[3/7] Removendo veths soltos (root namespace)..."
for v in "${VETHS[@]}"; do
    ip link del "$v" 2>/dev/null || true
done

echo "[4/7] Removendo XDP de qualquer interface no root namespace..."
for dev in $(ip -o link show | awk -F': ' '{print $2}' | cut -d'@' -f1); do
    ip link set dev "$dev" xdp off 2>/dev/null || true
done

echo "[5/7] Limpando arquivos temporarios e pins BPF..."
rm -rf /sys/fs/bpf/xdp_fwd_maps \
       /sys/fs/bpf/xdpunk \
       /sys/fs/bpf/xdpunk_r1 \
       /sys/fs/bpf/xdpunk_r4
rm -f  /sys/fs/bpf/xdp_fwd \
       /sys/fs/bpf/xdpunk_prog \
       /sys/fs/bpf/xdpunk_r1_prog \
       /sys/fs/bpf/xdpunk_r4_prog
rm -f /tmp/xdp_switch.c \
      /tmp/xdp_switch.o \
      /tmp/xdp_forward.c \
      /tmp/xdp_forward.o \
      /tmp/xdp_forward_dynamic.o \
      /tmp/xdp_fw_lb.o \
      /tmp/xdp_lb_chain.o \
      /tmp/tc_forward.c \
      /tmp/tc_forward.o \
      /tmp/tc_redirect.c \
      /tmp/tc_redirect_*.o

echo "[6/7] Verificando programas BPF carregados (informativo)..."
bpftool prog show 2>/dev/null || true

echo "[7/7] Verificando mapas BPF restantes (informativo)..."
bpftool map show 2>/dev/null || true

echo
echo "Ambiente completamente limpo com sucesso!"
