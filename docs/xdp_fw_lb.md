# xdp_fw_lb.c — Documentação Técnica

## Visão Geral

`xdp/xdp_fw_lb.c` é o programa do plano de dados da **Fase 2** do XDPunk. Ele incorpora toda a lógica do switch L3 da Fase 1 (`xdp_forward_dynamic.c`, que permanece intacto como baseline) e adiciona duas funções de rede executadas por pacote, em kernel:

1. **Firewall stateless** — regras 5-tupla (IP origem/destino, portas, protocolo) com ação ALLOW/DROP;
2. **Load balancer de links WAN** — pacotes sem rota conhecida (miss na `route_table` = rota default) são distribuídos entre múltiplos provedores WAN por hash de fluxo ou round-robin.

Toda a política continua nos mapas BPF: regras, links e modo do balanceador mudam em runtime via `xdpunk-cli`, sem recompilar ou recarregar o programa.

---

## Pipeline por Pacote

```
ingress (qualquer veth do switch)
  │
  ├─ parse ethhdr (bounds check)
  │
  ├─ ETH_P_ARP → lê target IP (offset 24) → lookup route_table
  │      hit  → bpf_redirect (sem reescrita de MAC)
  │      miss → XDP_PASS (kernel do switch responde ARP dos IPs WAN)
  │
  ├─ ETH_P_IP → parse iphdr + portas TCP/UDP (ICMP/outros: portas = 0)
  │   ├─ FIREWALL: scan linear fw_rules[0..num_rules), first-match
  │   │     DROP  → XDP_DROP     ALLOW → segue     sem match → ALLOW
  │   ├─ lookup route_table(daddr)
  │   │     hit  → reescreve MACs (dmac/smac) → bpf_redirect   [LAN]
  │   └─ miss → LB WAN:
  │         hash 5-tupla % num_links   (ou round-robin atômico)
  │         pula links desabilitados (failover manual)
  │         reescreve MACs → bpf_redirect(wan_links[idx].ifindex)
  │
  └─ outro EtherType → XDP_PASS
```

## Mapas BPF

| Mapa | Tipo | Chave → Valor | Entradas | Função |
|---|---|---|---|---|
| `route_table` | HASH | IPv4 (NBO) → `route_entry` {ifindex, dmac, smac} | 256 | rede local conhecida |
| `fw_rules` | ARRAY | índice (= prioridade) → `fw_rule` (24 B) | 64 | regras do firewall |
| `fw_config` | ARRAY | 0 → {num_rules} | 1 | limite do scan |
| `fw_stats` | PERCPU_ARRAY | índice da regra → {packets, bytes} | 64 | hits por regra |
| `wan_links` | ARRAY | slot → `wan_link` {ifindex, smac, dmac, enabled} | 4 | links WAN |
| `lb_config` | ARRAY | 0 → {mode, num_links, enabled} | 1 | config do LB |
| `rr_state` | ARRAY | 0 → u64 | 1 | contador round-robin |
| `wan_stats` | PERCPU_ARRAY | slot → {packets, bytes} | 4 | tráfego por link |
| `global_stats` | PERCPU_ARRAY | evento → {packets, bytes} | 8 | pipeline (TOTAL, ARP, FW_DROP, LAN_REDIRECT, WAN_REDIRECT, PASS, LB_NO_LINK) |

Os contadores são per-CPU (sem instruções atômicas no caminho crítico); a CLI soma os valores de todos os CPUs na leitura. Todos os mapas são pinados em `/sys/fs/bpf/xdpunk/` pelo `bpftool prog load ... pinmaps`.

## Decisões de Projeto

- **Miss na route_table = rota default = WAN.** A `route_table` descreve a rede local; todo o resto sai pelo balanceador. Não há lógica de prefixo.
- **Reescrita de MAC obrigatória nos redirects IPv4.** `bpf_redirect()` não altera o cabeçalho Ethernet e os provedores WAN roteiam em L3 — um frame com `h_dest` errado é descartado pelo `ip_rcv` (PACKET_OTHERHOST). Os MACs corretos ficam pré-configurados nos mapas (`route_entry.dmac/smac`, `wan_link.dmac/smac`). No caso LAN→LAN a reescrita é idempotente.
- **Firewall: scan linear com first-match.** O índice do array é a prioridade; máscara 0, porta 0 e proto 0 são wildcards; `src_ip`/`dst_ip` são armazenados pré-mascarados. `fw_config.num_rules` limita o scan ao maior índice habilitado + 1, fazendo o custo escalar com N regras (mensurável no experimento Q1). Kernel ≥ 5.3 aceita o bounded loop nativamente.
- **Hash de fluxo** multiplicativo de Fibonacci/Knuth (`h *= 0x9E3779B1`) sobre a 5-tupla — afinidade de fluxo análoga ao ECMP L4 do kernel. **Round-robin** usa `__sync_fetch_and_add` num contador compartilhado; distribui uniformemente, mas pode reordenar pacotes do mesmo fluxo (efeito discutido nos resultados).
- **Sem NAT e sem decremento de TTL.** Não há reescrita de IP (logo, sem recomputação de checksum). O retorno WAN→LAN funciona porque os provedores têm rota estática para a LAN — simplificação de laboratório documentada nas limitações.
- **Fragmentos não-iniciais** não carregam cabeçalho L4: portas ficam 0 e regras com porta não os casam (limitação conhecida de filtros stateless).

## Interação com o Plano de Controle

Os structs C são espelhados em `userspace/xdpunk_cli/maps.py` (layouts sem padding implícito). Validação cruzada recomendada após qualquer mudança:

```bash
sudo bpftool map dump -j pinned /sys/fs/bpf/xdpunk/fw_rules
sudo xdpunk-cli fw list
```
