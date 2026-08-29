# Topologia encadeada A–R1–{R2,R3}–R4–B para análise de desempenho do load balancer XDP

> Spec de design (fase de brainstorming). Implementação detalhada fica para o
> plano gerado pela skill `writing-plans` a partir deste documento.

## Contexto

O XDPunk Fase 2 já implementa um load balancer de links WAN em XDP
(`xdp/xdp_fw_lb.c`), validado no lab de 1 salto (`scripts/setup_xdp_fw_lb.sh`):
um único nó (`nssw`) recebe tráfego da LAN e distribui entre 2 links WAN por
hash de fluxo ou round-robin, com failover manual e comparação com ECMP do
kernel (`docs/xdp_fw_lb.md`, `plano_firewall_loadbalancer.md`).

Este documento cobre uma **nova topologia de avaliação**, pedida para medir o
comportamento do mesmo LB quando o tráfego atravessa **dois saltos de
balanceamento em cadeia** entre dois hosts finais:

```
A -> R1 -> (R2 ou R3, decisão do LB) -> R4 -> B
```

R1 e R4 são os dois pontos de decisão (cada um com 2 saídas possíveis: R2 e
R3); R2 e R3 são roteadores de trânsito puro, ligados a R1 e a R4 mas não
entre si.

## Decisões estruturais (aprovadas em brainstorming)

1. **R4 também roda o LB em XDP**, não é um roteador simples. No caminho de
   volta (B→A), R4 decide entre R2 e R3 exatamente como R1 decide no caminho
   de ida — dois saltos de decisão independentes, não um só.
2. **R2 e R3 são roteadores comuns do kernel Linux** (`ip_forward=1`,
   `rp_filter=0`), sem BPF — mesmo papel que `nsp1`/`nsp2` já têm no lab de 1
   salto: trânsito puro, sem participar de nenhuma decisão de encaminhamento.
3. **Baseline ECMP equivalente é desejado**: além do lab 100% XDP, um lab
   irmão com R1/R4 como roteadores kernel + ECMP (`fib_multipath_hash_policy`)
   para comparação XDP vs kernel também no caminho de 2 saltos (não só no de
   1 salto, que já existe).
4. **Zero mudança de código**: `xdp/xdp_fw_lb.c` e toda a CLI
   (`userspace/xdpunk_cli/`) são reaproveitados sem nenhuma alteração. R1 e
   R4 são duas *instâncias* independentes do mesmo programa/mesmo conjunto de
   mapas, diferenciadas só por pin path e namespace de anexação.
5. Sem regras de firewall carregadas nesta topologia — o objeto de estudo é
   só o LB (`fw` continua disponível/funcional, mas fora de escopo dos
   testes aqui).

## 1. Topologia e endereçamento

```
nsA 10.10.1.1/24 ─vethA/vethAr1─┐                                          ┌─vethR4B/vethB─ nsB 10.10.2.1/24
                                 │ nsr1 (XDP LB)                nsr4 (XDP LB)│
                    ┌─vethR12/vethR21─ nsr2 (kernel router,     ┐            │
                    │                  ip_forward=1)            │           │
                    │                                    vethR24/vethR42    │
                    └─vethR13/vethR31─ nsr3 (kernel router,     ┐           │
                                       ip_forward=1)             vethR34/vethR43
```

- **Namespaces**: `nsA`, `nsr1`, `nsr2`, `nsr3`, `nsr4`, `nsB`. Nomes novos,
  sem colisão com os labs já existentes (`ns1/ns2/ns3/nssw/nsp1/nsp2/nsext`).
  Os labs continuam **não podendo rodar simultaneamente** entre si nem com
  este (mesma regra geral já documentada em `CLAUDE.md`), mas como os nomes
  não se sobrepõem, o risco é só de rodar dois labs ao mesmo tempo por
  engano — mitigado pelo próprio `reset.sh` cobrindo todos.
- **Veths e endereçamento ponto-a-ponto** (`/30`, faixa `172.20.0.0/16`
  documental, sem significado externo):

  | Link | Interface local | Interface remota | Sub-rede |
  |---|---|---|---|
  | A ↔ R1 | `vethA` (nsA) | `vethAr1` (nsr1, sem IP) | `10.10.1.0/24` (só em nsA) |
  | R1 ↔ R2 | `vethR12` (nsr1) | `vethR21` (nsr2) | `172.20.1.0/30` |
  | R1 ↔ R3 | `vethR13` (nsr1) | `vethR31` (nsr3) | `172.20.2.0/30` |
  | R2 ↔ R4 | `vethR24` (nsr2) | `vethR42` (nsr4) | `172.20.3.0/30` |
  | R3 ↔ R4 | `vethR34` (nsr3) | `vethR43` (nsr4) | `172.20.4.0/30` |
  | R4 ↔ B | `vethR4B` (nsr4, sem IP) | `vethB` (nsB) | `10.10.2.0/24` (só em nsB) |

- **Gateway fake em nsA e nsB**: idêntico ao padrão de `setup_xdp_fw_lb.sh`
  — rota default (`10.10.1.254` / `10.10.2.254`) + `ip neigh ... nud
  permanent` com MAC que não existe em NIC nenhuma (`02:00:00:00:00:fe`).
  Nenhum ARP do lado LAN de R1/R4; os lados `vethAr1`/`vethR4B` não recebem
  IP algum (só participam do plano de dados XDP).
- **R2/R3**: `ip_forward=1`, `rp_filter=0` nas duas interfaces. Rotas
  estáticas: `10.10.1.0/24 via` (IP de R1 no link direto) e `10.10.2.0/24
  via` (IP de R4 no link direto) — cada um dos dois é o único próximo salto
  possível para a sub-rede oposta, já que R2/R3 não têm rota alternativa
  entre si.
- **Offloads** (`gso/tso/gro off` via `ethtool`) desligados nas pontas e nos
  roteadores kernel, mesma justificativa já documentada no lab de 1 salto
  (medições de pps fiéis com `xdpgeneric`).

## 2. Plano de dados: duas instâncias de `xdp_fw_lb.c`

`xdp/xdp_fw_lb.c` é compilado **uma única vez** (`/tmp/xdp_lb_chain.o`) e
carregado **duas vezes** com `bpftool prog load ... pinmaps`, em pins
distintos — cada carga recebe seu próprio conjunto de mapas, zerado:

| | R1 | R4 |
|---|---|---|
| Pin do programa | `/sys/fs/bpf/xdpunk_r1_prog` | `/sys/fs/bpf/xdpunk_r4_prog` |
| Diretório de mapas | `/sys/fs/bpf/xdpunk_r1/` | `/sys/fs/bpf/xdpunk_r4/` |
| `xdpgeneric` anexado em | `vethAr1`, `vethR12`, `vethR13` (nsr1) | `vethR42`, `vethR43`, `vethR4B` (nsr4) |
| `route_table` | `10.10.1.1 → vethAr1` (dmac=MAC de `vethA`, smac=MAC de `vethAr1`) | `10.10.2.1 → vethR4B` (dmac=MAC de `vethB`, smac=MAC de `vethR4B`) |
| `wan_links[0]` | `vethR12` (dmac=MAC de `vethR21`) | `vethR42` (dmac=MAC de `vethR24`) |
| `wan_links[1]` | `vethR13` (dmac=MAC de `vethR31`) | `vethR43` (dmac=MAC de `vethR34`) |
| `lb_config.mode` | `hash` (default; `rr` em F5) | `hash` (default; `rr` em F5) |
| `fw_config.num_rules` | `0` (default ALLOW) | `0` (default ALLOW) |

A CLI já suporta duas instâncias sem nenhuma mudança: todo comando recebe
`--netns nsr1|nsr4` e `--map-pin /sys/fs/bpf/xdpunk_r1|_r4` (os dois já são
flags genéricas existentes em `cli.py`). Sequência completa de população em
`scripts/setup_xdp_lb_chain.sh`:

```bash
# R1
xdpunk-cli --netns nsr1 --map-pin /sys/fs/bpf/xdpunk_r1 \
  map update 10.10.1.1 vethAr1 --dmac "$(mac_of nsA vethA)"
xdpunk-cli --netns nsr1 --map-pin /sys/fs/bpf/xdpunk_r1 \
  lb link add 0 vethR12 --dmac "$(mac_of nsr2 vethR21)"
xdpunk-cli --netns nsr1 --map-pin /sys/fs/bpf/xdpunk_r1 \
  lb link add 1 vethR13 --dmac "$(mac_of nsr3 vethR31)"
xdpunk-cli --netns nsr1 --map-pin /sys/fs/bpf/xdpunk_r1 lb mode hash

# R4
xdpunk-cli --netns nsr4 --map-pin /sys/fs/bpf/xdpunk_r4 \
  map update 10.10.2.1 vethR4B --dmac "$(mac_of nsB vethB)"
xdpunk-cli --netns nsr4 --map-pin /sys/fs/bpf/xdpunk_r4 \
  lb link add 0 vethR42 --dmac "$(mac_of nsr2 vethR24)"
xdpunk-cli --netns nsr4 --map-pin /sys/fs/bpf/xdpunk_r4 \
  lb link add 1 vethR43 --dmac "$(mac_of nsr3 vethR34)"
xdpunk-cli --netns nsr4 --map-pin /sys/fs/bpf/xdpunk_r4 lb mode hash
```

### Assimetria de caminho (propriedade a medir, não bug)

O hash de fluxo em `xdp_fw_lb.c` é:

```c
h = saddr ^ daddr ^ ((sport << 16) | dport) ^ proto;
h *= 0x9E3779B1U;
idx = (h >> 16) % num_links;
```

`saddr ^ daddr` é comutativo sob troca de origem/destino, mas
`(sport << 16) | dport` **não é** — trocar `sport`↔`dport` (como acontece no
sentido inverso do mesmo fluxo TCP/UDP) produz, em geral, um valor diferente
antes do XOR. Logo R1 (hash sobre a 5-tupla de ida) e R4 (hash sobre a
5-tupla de volta, com portas invertidas) podem escolher **links diferentes**
para o mesmo fluxo — o pacote pode ir por R2 e voltar por R3. Isso é
consistente com a limitação já aceita na Fase 2 original (retorno
assimétrico suportado, F6 do plano anterior), mas aqui deixa de ser um
cenário de exceção (ECMP assimétrico no provedor) e passa a acontecer,
potencialmente, em **toda** conexão — por isso vira um teste quantitativo
próprio (Q3 abaixo), não só uma nota de rodapé.

## 3. Scripts

| Arquivo | Papel |
|---|---|
| `scripts/setup_xdp_lb_chain.sh` (novo) | Cria os 6 namespaces e 6 veths, endereça (seção 1), compila `xdp_fw_lb.c` uma vez, carrega 2x (seção 2), anexa `xdpgeneric`, configura R2/R3 como roteadores kernel, popula os mapas via `xdpunk-cli`, imprime resumo de uso. Clona a estrutura de `scripts/setup_xdp_fw_lb.sh`. |
| `scripts/setup_baseline_router_chain.sh` (novo) | Mesma topologia, sem XDP: R1 e R4 viram roteadores kernel comuns com rota ECMP (`nexthop via <R2> weight 1 / via <R3> weight 1`) para a sub-rede oposta + `net.ipv4.fib_multipath_hash_policy=1`; R2/R3 idênticos ao lab XDP (kernel router puro). Clona `scripts/setup_baseline_router.sh --ecmp`. |
| `scripts/reset.sh` (estender) | Adicionar `nsA/nsr1/nsr2/nsr3/nsr4/nsB` e as 6 veths às listas de limpeza; remover pins `/sys/fs/bpf/xdpunk_r1*` e `/sys/fs/bpf/xdpunk_r4*`; remover `/tmp/xdp_lb_chain.o`. |
| `experiments/run_lb_chain_bench.sh <xdp\|baseline> [REPS] [DUR_S]` (novo) | Orquestra Q1/Q2: inicia `iperf3 -s` em `nsB`, roda `iperf3 -c` de `nsA` com P ∈ {2,4,8,16} fluxos paralelos, e `ping` para latência. Modo `xdp` lê/zera contadores nas **duas** instâncias (`--map-pin _r1` e `_r4`); modo `baseline` usa `ip -s link` nos 4 roteadores. Clona a estrutura de `experiments/run_lb_bench.sh`. |
| `experiments/simulate_lb_hash_symmetry.py` (novo) | Script analítico e independente do lab: reimplementa a fórmula de hash de `xdp_fw_lb.c` em Python; para N 5-tuplas sintéticas (aleatórias, portas/IPs variados), calcula se o índice de link escolhido pela 5-tupla de ida bate com o escolhido pela 5-tupla de volta (portas invertidas); reporta a taxa de simetria esperada (ex.: ~50% com `num_links=2`) — ver Q3. |
| `experiments/plot_lb_chain_*.py` (novo) | Gráficos de throughput, índice de justiça de Jain e taxa de simetria observada vs prevista. Carregar a skill `dataviz` antes de escrever. |

## 4. Plano de testes

Servidor: `ip netns exec nsB iperf3 -s -B 10.10.2.1` (2 instâncias/portas se
necessário fluxos concorrentes com portas fixas). Medições quantitativas:
≥10 repetições, média ± desvio (mesmo padrão metodológico da Fase 2).

### Funcionais (F)

- **F1 — conectividade fim a fim**: `ping`/`iperf3` de `nsA` para
  `10.10.2.1` atravessando os 2 saltos de LB; `tcpdump` em `nsr2`/`nsr3`
  confirma o caminho real; `xdpunk-cli stats` em R1 e R4 incrementam
  `WAN_REDIRECT`.
- **F2 — afinidade de fluxo**: `iperf3 -P 8`; cada fluxo mantém o mesmo link
  de saída em R1 durante toda a conexão (sem alternância) — verificado via
  `lb status` (distribuição em `wan_stats`) e tcpdump.
- **F3 — simetria de caminho** (específico desta topologia): para uma
  amostra de fluxos, captura em R2/R3 mostra se ida e volta do mesmo fluxo
  passam pelo mesmo roteador do meio ou não; compara a taxa observada com a
  prevista por `simulate_lb_hash_symmetry.py`.
- **F4 — failover em R1**: `lb link disable 0` em R1 durante iperf3
  contínuo → tráfego migra 100% para R3; medir gap nos intervalos de 1s do
  iperf3; reabilitar.
- **F4b — failover em R4**: mesmo teste do lado de R4 (afeta só o caminho de
  volta B→A).
- **F5 — modo round-robin**: `lb mode rr` em R1 (e/ou R4); `wan_stats`
  ~50/50 mesmo com fluxo único; observar retransmissões TCP por reordenação.
- **F6 (opcional) — falha dupla**: desabilitar o link 0 em R1 **e** em R4
  simultaneamente → todo o tráfego (ida e volta) converge para R3 nos dois
  saltos.

### Quantitativos (Q)

- **Q1 — throughput agregado e justiça (Jain)**: `iperf3 -P {2,4,8,16}`
  nsA→nsB, XDP-chain vs baseline ECMP-chain; mesma métrica do Q3 da Fase 2
  original, agora em caminho de 2 saltos de balanceamento.
- **Q2 — latência e custo do salto extra**: `ping -c 200 -i 0.01` nsA→nsB,
  XDP-chain vs baseline-chain, comparado também com os números já existentes
  do lab de 1 salto (`setup_xdp_fw_lb.sh`) para estimar o custo incremental
  de um segundo hop de LB em XDP.
- **Q3 — taxa de simetria ida/volta**: resultado do
  `simulate_lb_hash_symmetry.py` (previsão analítica) contrastado com a
  amostra observada em F3. Explica *por que* o caminho assimétrico ocorre
  (propriedade determinística do hash, não efeito de rede) — resultado
  quantitativo novo, sem equivalente na Fase 2 original (lá não havia um
  segundo hop com hash próprio).

## Riscos e mitigações

1. **Duas instâncias BPF simultâneas no mesmo host**: risco de confundir
   pin paths/netns nos comandos da CLI durante os scripts e os testes
   manuais. Mitigação: nomear os pins de forma explícita (`_r1`/`_r4`) e
   documentar cada comando com seu par `--netns`/`--map-pin` completo (sem
   depender de defaults).
2. **Medir simetria de caminho ao vivo (F3) é caro/impreciso** com só
   contadores agregados (`wan_stats` não distingue por fluxo). Mitigação:
   tratar F3 como amostragem qualitativa via tcpdump em poucos fluxos
   controlados, e apoiar a conclusão quantitativa principal no script
   analítico determinístico (Q3), que não depende de captura ao vivo.
3. **`bpftool prog load` do mesmo objeto duas vezes**: sem risco conhecido
   (mapas de um `pinmaps` são sempre próprios da carga), mas vale validar
   cedo (como já foi feito para o `bpf_loop()` na Fase 2) antes de escrever
   o resto do script.
4. **Baseline ECMP em 2 saltos**: o hash L4 do kernel em R1 e em R4 também
   pode ser assimétrico entre ida/volta — comparável ao ponto 4 acima, mas
   não há visibilidade de contadores por fluxo tão granular quanto no XDP;
   documentar como limitação da comparação, não tentar resolver.

## Arquivos críticos

- `scripts/setup_xdp_lb_chain.sh` (novo)
- `scripts/setup_baseline_router_chain.sh` (novo)
- `scripts/reset.sh` (estender)
- `experiments/run_lb_chain_bench.sh` (novo)
- `experiments/simulate_lb_hash_symmetry.py` (novo)
- `experiments/plot_lb_chain_*.py` (novo)
- `xdp/xdp_fw_lb.c` (reaproveitado sem alteração)
- `userspace/xdpunk_cli/` (reaproveitado sem alteração)
