# setup_xdp_fw_lb.sh — Documentação Técnica

## Visão Geral

`scripts/setup_xdp_fw_lb.sh` provisiona o laboratório da **Fase 2** (firewall + balanceador de links WAN): 6 network namespaces, 6 pares veth, o programa XDP `xdp_fw_lb.c` anexado às 4 interfaces do switch e os mapas BPF populados via `xdpunk-cli`.

## Topologia

```
             LAN 10.0.0.0/24                "WAN"                 "Internet"
 ns1 ─veth1h/veth1s─┐            ┌─vethw1s/vethw1p─ nsp1 ─vethe1p/vethe1x─┐
 10.0.0.1           │   nssw     │ 172.16.1.1/.2     fwd  198.51.100.1/.2 │ nsext
                    │  XDP FW+LB │                                        │ lo:
 ns2 ─veth2h/veth2s─┘  (4 veths) └─vethw2s/vethw2p─ nsp2 ─vethe2p/vethe2x─┘ 192.0.2.10/32
 10.0.0.2                          172.16.2.1/.2     fwd  203.0.113.1/.2
```

| Namespace | Papel | Configuração-chave |
|---|---|---|
| `ns1`, `ns2` | hosts LAN | `default via 10.0.0.254` + **neigh estático** para o gateway fake |
| `nssw` | switch XDP | `ip_forward=0` (encaminhamento é 100% XDP); IPs 172.16.x.1/30 nas veths WAN apenas para responder ARP dos provedores |
| `nsp1`, `nsp2` | provedores WAN | `ip_forward=1`, `rp_filter=0`; rotas estáticas de ida (192.0.2.10) e retorno (10.0.0.0/24) |
| `nsext` | "internet" | `192.0.2.10/32` no loopback; retorno via nsp1 (variante ECMP comentada para o teste de assimetria) |

Endereços da "internet" usam as faixas de documentação da RFC 5737 (192.0.2.0/24, 198.51.100.0/24, 203.0.113.0/24).

## Pontos de Projeto

- **Gateway fake (10.0.0.254 / 02:00:00:00:00:fe).** O IP de gateway dos hosts LAN não existe em nenhuma interface: uma entrada `neigh ... nud permanent` evita ARP na LAN e entrega os frames diretamente ao switch, onde o XDP decide o destino. Nenhum ARP precisa ser respondido no lado LAN.
- **`ip_forward=0` no nssw.** Argumento central da avaliação: se a conectividade funciona com o forwarding do kernel desligado, todo o encaminhamento é comprovadamente XDP.
- **Offloads (GSO/TSO/GRO) desligados** nas pontas host/provedor via `ethtool`, para que o XDP genérico processe pacotes de tamanho de fio — essencial para medições de pps fieis.
- **População dos mapas via `xdpunk-cli`** (não `bpftool map update ... hex`): os values agora são structs de 16/20 bytes e montar o layout em hexadecimal é frágil. O script coleta os MACs com `ip -br link` e delega a serialização à CLI.

## Pins BPF

| Objeto | Caminho |
|---|---|
| Programa XDP | `/sys/fs/bpf/xdpunk_prog` |
| Mapas (todos) | `/sys/fs/bpf/xdpunk/<nome>` |

Separados dos pins da Fase 1 (`/sys/fs/bpf/xdp_fwd*`) — os dois laboratórios não colidem, mas não devem rodar simultaneamente (os nomes de namespaces/veths LAN se sobrepõem). `scripts/reset.sh` limpa ambos.

## Scripts Relacionados

- `scripts/setup_baseline_router.sh [--fw-rules N] [--ecmp]` — mesma topologia sem XDP (bridge + iptables + ECMP do kernel), baseline dos experimentos Q1–Q3;
- `experiments/run_fw_bench.sh <xdp|baseline>` — throughput/latência do firewall vs iptables (N ∈ {0..64} regras);
- `experiments/run_lb_bench.sh <xdp|baseline>` — throughput agregado e distribuição por link vs ECMP;
- `scripts/reset.sh` — limpeza completa (namespaces, veths, pins, iptables).

## Validação Rápida

```bash
sudo bash scripts/setup_xdp_fw_lb.sh
ip netns exec ns1 ping -c 3 192.0.2.10        # LAN -> internet via FW+LB
sudo xdpunk-cli stats                          # WAN_REDIRECT deve crescer
sudo xdpunk-cli lb status                      # distribuição por link
ip netns exec nsp1 tcpdump -ni vethw1p         # observar o caminho
```
