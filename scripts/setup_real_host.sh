#!/usr/bin/env bash
#
# setup_real_host.sh — prepara um host final (h1 ou h2) da topologia de
# 3 VMs (ver setup_xdp_fw_real.sh).
#
# O vizinho do peer e fixado (PERMANENT) no MAC da porta do switch XDP
# voltada para este host. Motivo: no ambiente Proxmox atual o enlace
# h1<->sw compartilha o dominio L2 da rede de gerencia; com ARP dinamico a
# eth0 do outro host responde ao ARP e o trafego contorna o switch. Com o
# vizinho fixo, os quadros sao unicast para o switch (sem flooding na rede
# de gerencia) e o XDP reescreve os MACs. arp_ignore=1 impede que uma
# interface responda ARP por IP configurado em outra.
#
# Uso: sudo bash setup_real_host.sh <IFACE> <IP/24> <PEER_IP> <MAC_porta_switch>
#   h1: sudo bash setup_real_host.sh ens19 10.0.0.1/24 10.0.0.2 <MAC sw ens19>
#   h2: sudo bash setup_real_host.sh ens19 10.0.0.2/24 10.0.0.1 <MAC sw ens20>
#
set -euo pipefail

IFACE="${1:?uso: $0 <IFACE> <IP/24> <PEER_IP> <MAC_switch>}"
ADDR="${2:?}"
PEER="${3:?}"
SW_MAC="${4:?}"

sysctl -qw net.ipv4.conf.all.arp_ignore=1
sysctl -qw "net.ipv6.conf.$IFACE.disable_ipv6=1"
ip addr flush dev "$IFACE"
ip addr add "$ADDR" dev "$IFACE"
ip link set dev "$IFACE" up
ip neigh replace "$PEER" lladdr "$SW_MAC" dev "$IFACE" nud permanent

ip -br addr show dev "$IFACE"
ip neigh show dev "$IFACE"
