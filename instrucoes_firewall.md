# XDPunk Fase 2 — Instruções de Teste: Firewall + Load Balancer WAN

Este guia explica **como o sistema funciona** e **como testá-lo**, passo a passo, no ambiente Linux (Ubuntu 24.04+, kernel com suporte a eBPF/XDP, execução como root).

---

## 1. Como o sistema funciona

### 1.1 Visão geral

O XDPunk Fase 2 é um switch programável que roda **dentro do kernel Linux** via eBPF/XDP. O programa `xdp/xdp_fw_lb.c` é executado para **cada pacote** que chega às interfaces do switch, antes da pilha de rede do kernel, e decide em três estágios:

```
pacote chega em uma veth do switch (nssw)
  │
  ├─ 1. FIREWALL ── regras 5-tupla (IP orig/dest, portas, protocolo)
  │       casou regra DROP?  → XDP_DROP (pacote descartado no kernel)
  │       casou regra ALLOW? → segue
  │       nenhuma regra?     → segue (política default: ALLOW)
  │
  ├─ 2. ROTA LOCAL ── IP destino está na route_table?
  │       sim → reescreve MACs → bpf_redirect() para a veth do host  [LAN]
  │
  └─ 3. LOAD BALANCER ── IP destino desconhecido (= rota default)
          escolhe um link WAN por hash de fluxo (ou round-robin)
          → reescreve MACs → bpf_redirect() para a veth do provedor  [WAN]
```

Toda a política (regras, rotas, links, modo do LB) vive em **mapas BPF** pinados em `/sys/fs/bpf/xdpunk/`. O plano de controle (`xdpunk-cli`, Python) altera esses mapas em runtime — **as mudanças valem no pacote seguinte, sem recompilar nem recarregar o programa XDP**. Esse é o argumento central do trabalho (separação plano de dados / plano de controle).

### 1.2 O firewall

- Regras armazenadas no array `fw_rules` (até 64); o **índice é a prioridade** (menor vence, first-match).
- Cada regra casa por: IP/CIDR de origem, IP/CIDR de destino, porta de origem, porta de destino e protocolo (tcp/udp/icmp) — qualquer campo pode ser `any` (wildcard).
- Ação: `allow` (interrompe o scan e segue o pipeline) ou `drop` (descarta com `XDP_DROP`).
- **Stateless**: cada pacote é avaliado isoladamente; não há rastreamento de conexões. Tráfego de retorno também passa pelo firewall.
- Contadores por regra (`fw_stats`) e globais (`global_stats`) permitem verificar o efeito de cada regra.

### 1.3 O load balancer WAN

- Pacotes sem rota na `route_table` saem pela WAN. O slot do link é escolhido por:
  - **hash** (default): hash da 5-tupla → o mesmo fluxo usa sempre o mesmo link (afinidade de fluxo, sem reordenação TCP);
  - **rr**: round-robin por pacote → distribuição uniforme, mas pode reordenar pacotes do mesmo fluxo.
- `lb link disable N` retira um link imediatamente (failover manual): o tráfego migra para os links restantes no pacote seguinte.
- Como `bpf_redirect()` não altera o cabeçalho Ethernet e os provedores roteiam em L3, o XDP **reescreve os MACs** de origem/destino usando valores pré-configurados nos mapas — por isso `map update` e `lb link add` pedem `--dmac`.

### 1.4 A topologia de laboratório

```
             LAN 10.0.0.0/24                "WAN"                 "Internet"
 ns1 ─veth1h/veth1s─┐            ┌─vethw1s/vethw1p─ nsp1 ─vethe1p/vethe1x─┐
 10.0.0.1           │   nssw     │ 172.16.1.1/.2     fwd  198.51.100.1/.2 │ nsext
                    │  XDP FW+LB │                                        │ lo:
 ns2 ─veth2h/veth2s─┘  (4 veths) └─vethw2s/vethw2p─ nsp2 ─vethe2p/vethe2x─┘ 192.0.2.10/32
 10.0.0.2                          172.16.2.1/.2     fwd  203.0.113.1/.2
```

- `ns1`/`ns2`: hosts LAN, com gateway "fake" `10.0.0.254` (entrada ARP estática — o IP não existe em lugar nenhum; os frames vão direto para o switch decidir);
- `nssw`: o switch XDP — com `ip_forward=0`, provando que todo encaminhamento é do XDP;
- `nsp1`/`nsp2`: provedores WAN (roteadores comuns do kernel);
- `nsext`: a "internet" — o servidor de testes `192.0.2.10`.

---

## 2. Preparação do ambiente

```bash
# 1. Dependências + CLI (uma vez). O install.sh já instala o xdpunk-cli
#    (inclusive a versão da Fase 2, por cima da Fase 1, se existir).
sudo bash scripts/install.sh

# 2. Sempre antes de um novo setup: limpar estado anterior
sudo bash scripts/reset.sh

# 3. Subir o laboratório da Fase 2
sudo bash scripts/setup_xdp_fw_lb.sh
```

> **Nota sobre a instalação do CLI (PEP 668).** Em distros com Python 3.11+
> (Ubuntu 24.04+), `pip3 install ./userspace` é bloqueado com o erro
> `externally-managed-environment`. Por isso o `install.sh` instala o
> `xdpunk-cli` via **`pipx --system-site-packages`** (o `--system-site-packages`
> é necessário para enxergar o `bcc`/`python3-bpfcc`, que vem do apt e não
> existe no PyPI). Se precisar (re)instalar só o CLI manualmente:
>
> ```bash
> sudo PIPX_HOME=/opt/pipx PIPX_BIN_DIR=/usr/local/bin \
>     pipx install --force --system-site-packages ./userspace
> ```
>
> Alternativa rápida (menos limpa): `sudo pip3 install --break-system-packages ./userspace`.

Se o passo 3 terminar com o resumo "Laboratorio XDPunk Fase 2 ... carregado!", o ambiente está pronto. Confira:

```bash
sudo xdpunk-cli map dump      # 2 rotas LAN (10.0.0.1 e 10.0.0.2, com MACs)
sudo xdpunk-cli lb status     # 2 links WAN ativos, modo hash
sudo xdpunk-cli fw list       # nenhuma regra (politica default: ALLOW)
```

---

## 3. Testes funcionais

### T1 — Conectividade fim a fim (LAN → internet, atravessando FW + LB)

```bash
ip netns exec ns1 ping -c 5 192.0.2.10
sudo xdpunk-cli stats
```

**Esperado:** 0% de perda; em `stats`, os contadores `TOTAL`, `LAN_REDIRECT` (retorno) e `WAN_REDIRECT` (ida) crescem. Para ver por qual provedor o tráfego saiu:

```bash
ip netns exec nsp1 tcpdump -ni vethw1p icmp   # e/ou nsp2 / vethw2p
```

### T2 — Firewall: bloquear um fluxo específico (o teste central)

Em um terminal, suba o servidor e comprove que o tráfego passa:

```bash
ip netns exec nsext iperf3 -s -B 192.0.2.10
# noutro terminal:
ip netns exec ns1 iperf3 -c 192.0.2.10 -t 5      # deve funcionar
```

Agora adicione uma regra DROP **cirúrgica** (só TCP/5201 vindo de ns1):

```bash
sudo xdpunk-cli fw add --prio 0 --src 10.0.0.1/32 --dst 192.0.2.10/32 \
    --proto tcp --dport 5201 --action drop
```

**Esperado:**

```bash
ip netns exec ns1 iperf3 -c 192.0.2.10 -t 5      # FALHA (conexão não estabelece)
ip netns exec ns2 iperf3 -c 192.0.2.10 -t 5      # funciona (outro host)
ip netns exec ns1 ping -c 3 192.0.2.10           # funciona (outro protocolo)
sudo xdpunk-cli fw list                          # contador PKTS da regra 0 > 0
```

Remova a regra e confirme a restauração **imediata, sem recarregar nada**:

```bash
sudo xdpunk-cli fw del --prio 0
ip netns exec ns1 iperf3 -c 192.0.2.10 -t 5      # volta a funcionar
```

Variações úteis:

```bash
sudo xdpunk-cli fw add --prio 1 --proto icmp --action drop      # bloqueia todo ping
sudo xdpunk-cli fw add --prio 0 --src 10.0.0.0/24 --action allow # allow tem prioridade
sudo xdpunk-cli fw flush                                         # limpa tudo
```

### T3 — Afinidade de fluxo do LB (modo hash)

```bash
sudo xdpunk-cli stats --reset
ip netns exec ns1 iperf3 -c 192.0.2.10 -P 8 -t 10
sudo xdpunk-cli lb status
```

**Esperado:** os 8 fluxos se repartem entre os slots 0 e 1 (coluna `%`), e cada fluxo individual usa **um único** link (verifique com `tcpdump` nos provedores: cada porta de origem TCP aparece só de um lado).

### T4 — Failover manual de link

Com um iperf3 longo rodando (`-t 60`), desabilite o link em uso:

```bash
sudo xdpunk-cli lb link disable 0
```

**Esperado:** o tráfego migra para o link 1 no pacote seguinte (observe o gap nos intervalos de 1 s do iperf3 e o `tcpdump` em nsp2). `lb link enable 0` restaura.

### T5 — Modo round-robin

```bash
sudo xdpunk-cli lb mode rr
sudo xdpunk-cli stats --reset
ip netns exec ns1 iperf3 -c 192.0.2.10 -t 10
sudo xdpunk-cli lb status        # ~50/50 mesmo com UM fluxo
sudo xdpunk-cli lb mode hash     # volte ao default depois
```

**Esperado:** distribuição ~50/50 por link com um único fluxo; no JSON/saída do iperf3, retransmissões TCP maiores que no modo hash (efeito da reordenação — resultado relevante para a monografia).

### T6 — Retorno assimétrico

Ative o retorno ECMP na "internet" (ida pode ir por um provedor e a volta por outro):

```bash
ip -n nsext route del 10.0.0.0/24
ip -n nsext route add 10.0.0.0/24 \
    nexthop via 198.51.100.1 weight 1 \
    nexthop via 203.0.113.1  weight 1
ip netns exec ns1 iperf3 -c 192.0.2.10 -t 5     # deve continuar funcionando
```

**Esperado:** conectividade preservada — o retorno chegando por **qualquer** link WAN é resolvido pela `route_table` (com reescrita de MACs) de volta ao host LAN.

---

## 4. Benchmarks (comparação com o kernel)

Os experimentos comparam o XDP com os mecanismos nativos do kernel **na mesma topologia**:

```bash
# Firewall XDP vs iptables (throughput TCP, pps UDP-64B e latência, N = 0..64 regras)
sudo bash scripts/reset.sh && sudo bash scripts/setup_xdp_fw_lb.sh
sudo bash experiments/run_fw_bench.sh xdp 10 30

sudo bash scripts/reset.sh && sudo bash scripts/setup_baseline_router.sh --fw-rules 1
sudo bash experiments/run_fw_bench.sh baseline 10 30

# LB XDP vs ECMP do kernel (throughput agregado + distribuição por link)
sudo bash scripts/reset.sh && sudo bash scripts/setup_xdp_fw_lb.sh
sudo bash experiments/run_lb_bench.sh xdp 10 30

sudo bash scripts/reset.sh && sudo bash scripts/setup_baseline_router.sh --ecmp
sudo bash experiments/run_lb_bench.sh baseline 10 30
```

Os dados brutos (JSON do iperf3 + snapshots de contadores) ficam em `experiments/results/<experimento>_<timestamp>/`. Use `xdpunk-cli stats --reset` entre medições manuais.

> **Nota:** em veth o XDP roda em modo `xdpgeneric`, com números absolutos modestos — o que vale é a **comparação relativa** entre XDP e kernel no mesmo modo/ambiente.

---

## 5. Diagnóstico de problemas

| Sintoma | Verificação |
|---|---|
| Ping T1 falha | `tcpdump -e` salto a salto (`veth1s` → `vethw1p` → `vethe1x`): confira os **MACs de destino** de cada frame — reescrita errada é a causa mais provável. `sudo xdpunk-cli map dump` e `lb status` mostram os MACs configurados. |
| Setup falha no load do XDP | Erro do verificador eBPF: confira kernel ≥ 5.12 e clang com `-mcpu=v3` (já no script). `sudo bpftool prog load /tmp/xdp_fw_lb.o /sys/fs/bpf/teste` mostra o log detalhado. |
| CLI reclama de mapa inexistente | O lab não está de pé ou os pins foram removidos: rode `setup_xdp_fw_lb.sh` de novo. |
| Valores estranhos nos mapas | Valide o layout dos structs: `sudo bpftool map dump -j pinned /sys/fs/bpf/xdpunk/fw_rules` deve bater com `xdpunk-cli fw list`. |
| Tudo quebrado / estado sujo | `sudo bash scripts/reset.sh` e recomece. Nunca rode os dois labs (Fase 1 e Fase 2) ao mesmo tempo. |

Contadores úteis: `FW_DROP` (pacotes descartados pelo firewall), `LB_NO_LINK` (nenhum link WAN ativo — tudo desabilitado?), `PASS` (pacotes entregues à pilha do kernel, ex.: ARP dos provedores).

---

## 6. Limitações conhecidas (por projeto)

- **Stateless**: sem rastreamento de conexões; regras se aplicam a cada sentido separadamente.
- **Sem NAT**: o retorno WAN→LAN depende de rotas estáticas nos provedores (simplificação de laboratório).
- **IPv4 apenas**; fragmentos não-iniciais não casam regras com porta (portas = 0).
- Máx. 64 regras de firewall e 4 links WAN (constantes `MAX_FW_RULES`/`MAX_WAN_LINKS` em `xdp/xdp_fw_lb.c`).

Documentação detalhada: `docs/xdp_fw_lb.md` (programa XDP), `docs/setup_xdp_fw_lb.md` (laboratório) e `plano_firewall_loadbalancer.md` (plano completo da fase).
