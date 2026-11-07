#!/usr/bin/env bash
#
# setup_lb_chain_real.sh — orquestrador da topologia encadeada
# A-R1-{R2,R3}-R4-B em 6 VMs reais (ver docs/setup_xdp_lb_chain_real.md).
#
# Roda no host1 (A), a partir do repositorio. Copia scripts/ e xdp/ para as
# outras VMs (~/$REMOTE_DIR), descobre os MACs das portas de dados via SSH e
# configura as 6 maquinas no modo pedido:
#   xdp      — R1/R4 com xdp_fw_lb.c nativo (LB hash), R2/R3 kernel;
#   baseline — R1/R4 roteadores kernel com ECMP, R2/R3 kernel;
#   reset    — limpa tudo (portas de dados DOWN, sem IP).
# Os hosts e R2/R3 ficam identicos nos dois modos.
#
# Pre-requisito: SSH sem senha do host1 para R1..R4 e host2, sudo sem senha.
#
# Uso: bash scripts/setup_lb_chain_real.sh <xdp|baseline|reset>
# Variaveis: as de scripts/lb_chain_real.env; LB_MODE (hash|rr), XDP_MODE.
#
set -euo pipefail

MODE="${1:?uso: $0 <xdp|baseline|reset>}"
case "$MODE" in xdp|baseline|reset) ;; *) echo "ERRO: modo invalido '$MODE'"; exit 1 ;; esac

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_DIR="$(dirname "$SCRIPT_DIR")"
# shellcheck source=lb_chain_real.env
source "$SCRIPT_DIR/lb_chain_real.env"
RDIR="/home/$SSH_USER/$REMOTE_DIR"
LB_MODE="${LB_MODE:-hash}"
XDP_MODE="${XDP_MODE:-native}"

ROUTERS=("$R1_MGMT" "$R2_MGMT" "$R3_MGMT" "$R4_MGMT")

echo "== Topologia LB encadeada real — modo=$MODE =="

echo "[1/5] Copiando scripts/ e xdp/ para R1..R4 e host2 (~/$REMOTE_DIR)..."
for ip in "${ROUTERS[@]}" "$H2_MGMT"; do
  tar -C "$REPO_DIR" -cf - scripts xdp | \
    ssh -o BatchMode=yes "$SSH_USER@$ip" "mkdir -p ~/$REMOTE_DIR && tar -xf - -C ~/$REMOTE_DIR"
done

if [[ "$MODE" == "reset" ]]; then
  echo "[2/5] Resetando roteadores de borda..."
  lbr_ssh "$R1_MGMT" "LAN_IF=$R1_LAN W0_IF=$R1_W0 W1_IF=$R1_W1 REMOTE_NET=$NET_B bash $RDIR/scripts/setup_lb_chain_real_edge.sh reset"
  lbr_ssh "$R4_MGMT" "LAN_IF=$R4_LAN W0_IF=$R4_W0 W1_IF=$R4_W1 REMOTE_NET=$NET_A bash $RDIR/scripts/setup_lb_chain_real_edge.sh reset"
  echo "[3/5] Resetando transito..."
  lbr_ssh "$R2_MGMT" "A_IF=$R2_A B_IF=$R2_B bash $RDIR/scripts/setup_lb_chain_real_transit.sh reset"
  lbr_ssh "$R3_MGMT" "A_IF=$R3_A B_IF=$R3_B bash $RDIR/scripts/setup_lb_chain_real_transit.sh reset"
  echo "[4/5] Resetando hosts..."
  sudo bash "$SCRIPT_DIR/setup_lb_chain_real_host.sh" "$H1_IF" reset
  lbr_ssh "$H2_MGMT" "bash $RDIR/scripts/setup_lb_chain_real_host.sh $H2_IF reset"
  echo "[5/5] Reset concluido."
  exit 0
fi

echo "[2/5] Descobrindo MACs das portas de dados..."
MAC_H1="$(cat "/sys/class/net/$H1_IF/address")"
MAC_H2="$(lbr_mac "$H2_MGMT" "$H2_IF")"
MAC_R1_LAN="$(lbr_mac "$R1_MGMT" "$R1_LAN")"
MAC_R1_W0="$(lbr_mac "$R1_MGMT" "$R1_W0")"
MAC_R1_W1="$(lbr_mac "$R1_MGMT" "$R1_W1")"
MAC_R2_A="$(lbr_mac "$R2_MGMT" "$R2_A")"
MAC_R2_B="$(lbr_mac "$R2_MGMT" "$R2_B")"
MAC_R3_A="$(lbr_mac "$R3_MGMT" "$R3_A")"
MAC_R3_B="$(lbr_mac "$R3_MGMT" "$R3_B")"
MAC_R4_LAN="$(lbr_mac "$R4_MGMT" "$R4_LAN")"
MAC_R4_W0="$(lbr_mac "$R4_MGMT" "$R4_W0")"
MAC_R4_W1="$(lbr_mac "$R4_MGMT" "$R4_W1")"
printf '  host1 %s=%s | host2 %s=%s\n' "$H1_IF" "$MAC_H1" "$H2_IF" "$MAC_H2"
printf '  R1 %s=%s %s=%s %s=%s\n' "$R1_LAN" "$MAC_R1_LAN" "$R1_W0" "$MAC_R1_W0" "$R1_W1" "$MAC_R1_W1"
printf '  R2 %s=%s %s=%s | R3 %s=%s %s=%s\n' "$R2_A" "$MAC_R2_A" "$R2_B" "$MAC_R2_B" "$R3_A" "$MAC_R3_A" "$R3_B" "$MAC_R3_B"
printf '  R4 %s=%s %s=%s %s=%s\n' "$R4_LAN" "$MAC_R4_LAN" "$R4_W0" "$MAC_R4_W0" "$R4_W1" "$MAC_R4_W1"

echo "[3/5] Hosts (rota para a rede remota via gateway com vizinho estatico)..."
sudo bash "$SCRIPT_DIR/setup_lb_chain_real_host.sh" "$H1_IF" "$A_IP/24" "$GW_A_IP" "$NET_B" "$MAC_R1_LAN"
lbr_ssh "$H2_MGMT" "bash $RDIR/scripts/setup_lb_chain_real_host.sh $H2_IF $B_IP/24 $GW_B_IP $NET_A $MAC_R4_LAN"

echo "[4/5] Roteadores de transito R2/R3..."
lbr_ssh "$R2_MGMT" "A_IF=$R2_A A_IP=$R2_A_IP A_PEER_IP=$R1_W0_IP A_PEER_MAC=$MAC_R1_W0 \
  B_IF=$R2_B B_IP=$R2_B_IP B_PEER_IP=$R4_W0_IP B_PEER_MAC=$MAC_R4_W0 \
  NET_A=$NET_A NET_B=$NET_B bash $RDIR/scripts/setup_lb_chain_real_transit.sh setup"
lbr_ssh "$R3_MGMT" "A_IF=$R3_A A_IP=$R3_A_IP A_PEER_IP=$R1_W1_IP A_PEER_MAC=$MAC_R1_W1 \
  B_IF=$R3_B B_IP=$R3_B_IP B_PEER_IP=$R4_W1_IP B_PEER_MAC=$MAC_R4_W1 \
  NET_A=$NET_A NET_B=$NET_B bash $RDIR/scripts/setup_lb_chain_real_transit.sh setup"

echo "[5/5] Roteadores de borda R1/R4 (modo $MODE)..."
lbr_ssh "$R1_MGMT" "XDP_MODE=$XDP_MODE LB_MODE=$LB_MODE \
  LAN_IF=$R1_LAN LAN_HOST_IP=$A_IP LAN_HOST_MAC=$MAC_H1 GW_IP=$GW_A_IP REMOTE_NET=$NET_B \
  W0_IF=$R1_W0 W0_IP=$R1_W0_IP W0_PEER_IP=$R2_A_IP W0_PEER_MAC=$MAC_R2_A \
  W1_IF=$R1_W1 W1_IP=$R1_W1_IP W1_PEER_IP=$R3_A_IP W1_PEER_MAC=$MAC_R3_A \
  bash $RDIR/scripts/setup_lb_chain_real_edge.sh $MODE"
lbr_ssh "$R4_MGMT" "XDP_MODE=$XDP_MODE LB_MODE=$LB_MODE \
  LAN_IF=$R4_LAN LAN_HOST_IP=$B_IP LAN_HOST_MAC=$MAC_H2 GW_IP=$GW_B_IP REMOTE_NET=$NET_A \
  W0_IF=$R4_W0 W0_IP=$R4_W0_IP W0_PEER_IP=$R2_B_IP W0_PEER_MAC=$MAC_R2_B \
  W1_IF=$R4_W1 W1_IP=$R4_W1_IP W1_PEER_IP=$R3_B_IP W1_PEER_MAC=$MAC_R3_B \
  bash $RDIR/scripts/setup_lb_chain_real_edge.sh $MODE"

echo
echo "Teste de conectividade fim a fim (host1 $A_IP -> host2 $B_IP):"
if ping -c 5 -i 0.2 -W 1 "$B_IP"; then
  echo "OK — topologia pronta no modo $MODE."
else
  echo "FALHA — sem conectividade fim a fim no modo $MODE." >&2
  exit 1
fi
