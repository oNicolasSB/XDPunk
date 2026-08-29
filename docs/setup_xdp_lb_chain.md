# setup_xdp_lb_chain.sh — Documentação Técnica

## Visão Geral

`scripts/setup_xdp_lb_chain.sh` provisiona uma topologia encadeada de 2
saltos de balanceamento (`A -> R1 -> {R2, R3} -> R4 -> B`) para medir o
comportamento do load balancer WAN em XDP (`xdp/xdp_fw_lb.c`) quando o
tráfego atravessa duas decisões de encaminhamento independentes, não
apenas uma (caso do lab `setup_xdp_fw_lb.sh`). Ver
`docs/superpowers/specs/2026-08-29-lb-chain-topology-design.md` para o
design completo.

## Topologia

```
nsA 10.10.1.1/24 ─vethA/vethAr1─┐                              ┌─vethR4B/vethB─ nsB 10.10.2.1/24
                                 │ nsr1 (XDP LB)      nsr4 (XDP LB)│
                    ┌─vethR12/vethR21─ nsr2 (kernel)  ┐            │
                    │                                  vethR24/vethR42
                    └─vethR13/vethR31─ nsr3 (kernel)  ┐           │
                                                        vethR34/vethR43
```

| Namespace | Papel | Configuração-chave |
|---|---|---|
| `nsA`, `nsB` | hosts finais | `default via 10.10.1.254`/`10.10.2.254` + **neigh estático** (gateway fake) |
| `nsr1`, `nsr4` | pontos de decisão do LB | `ip_forward=0`; duas instâncias independentes de `xdp_fw_lb.c` (pins `_r1`/`_r4`) |
| `nsr2`, `nsr3` | trânsito puro | `ip_forward=1`, `rp_filter=0`; roteadores kernel comuns, sem BPF |

## Pins BPF

| Instância | Programa | Mapas |
|---|---|---|
| R1 | `/sys/fs/bpf/xdpunk_r1_prog` | `/sys/fs/bpf/xdpunk_r1/<nome>` |
| R4 | `/sys/fs/bpf/xdpunk_r4_prog` | `/sys/fs/bpf/xdpunk_r4/<nome>` |

Mesmo objeto (`xdp/xdp_fw_lb.c`, sem alteração) compilado uma vez e
carregado duas vezes — cada carga tem mapas próprios. Todo comando de
`xdpunk-cli` precisa dos dois flags explícitos: `--netns nsr1|nsr4
--map-pin /sys/fs/bpf/xdpunk_r1|_r4`.

## Assimetria de caminho (esperada, não é bug)

O hash de fluxo (`saddr^daddr^((sport<<16)|dport)^proto`, depois
multiplicado por `0x9E3779B1` e deslocado) não é simétrico sob troca de
origem/destino — R1 (ida) e R4 (volta) podem escolher roteadores
diferentes para o mesmo fluxo. `experiments/simulate_lb_hash_symmetry.py`
estima analiticamente a taxa esperada (~50% com 2 links, validado
empiricamente); `experiments/capture_lb_chain_symmetry.sh` mede a taxa
observada ao vivo (em teste real, 47.6% observado em 21 fluxos — dentro
da faixa esperada dado o tamanho pequeno da amostra).

## Scripts Relacionados

- `scripts/setup_baseline_router_chain.sh` — mesma topologia sem XDP
  (R1/R4 como roteadores kernel + ECMP), baseline do experimento Q1;
- `experiments/run_lb_chain_bench.sh <xdp|baseline> [REPS] [DUR]` —
  throughput/latência/distribuição por link (Q1, Q2);
- `experiments/capture_lb_chain_symmetry.sh [N_FLUXOS] [DUR]` — taxa de
  simetria observada do caminho ida/volta (F3, Q3);
- `experiments/simulate_lb_hash_symmetry.py [N] [num_links] [seed]` —
  taxa de simetria prevista analiticamente (Q3);
- `experiments/plot_lb_chain_bench.py <xdp_dir> <baseline_dir>` —
  gráficos de throughput e justiça de Jain (Q1);
- `scripts/reset.sh` — limpeza completa (inclui esta topologia).

## Testes Funcionais

```bash
sudo bash scripts/setup_xdp_lb_chain.sh

# F1 — conectividade fim a fim
ip netns exec nsA ping -c 3 10.10.2.1
sudo xdpunk-cli --netns nsr1 --map-pin /sys/fs/bpf/xdpunk_r1 stats
sudo xdpunk-cli --netns nsr4 --map-pin /sys/fs/bpf/xdpunk_r4 stats

# F2 — afinidade de fluxo / distribuição por link
ip netns exec nsA iperf3 -c 10.10.2.1 -P 8
sudo xdpunk-cli --netns nsr1 --map-pin /sys/fs/bpf/xdpunk_r1 lb status

# F4 — failover manual em R1
sudo xdpunk-cli --netns nsr1 --map-pin /sys/fs/bpf/xdpunk_r1 lb link disable 0
sudo xdpunk-cli --netns nsr1 --map-pin /sys/fs/bpf/xdpunk_r1 lb link enable 0

# F4b — failover manual em R4 (afeta o caminho de volta)
sudo xdpunk-cli --netns nsr4 --map-pin /sys/fs/bpf/xdpunk_r4 lb link disable 0
sudo xdpunk-cli --netns nsr4 --map-pin /sys/fs/bpf/xdpunk_r4 lb link enable 0

# F5 — round-robin
sudo xdpunk-cli --netns nsr1 --map-pin /sys/fs/bpf/xdpunk_r1 lb mode rr

# F3/Q3 — simetria de caminho
sudo bash experiments/capture_lb_chain_symmetry.sh 40 5
python3 experiments/simulate_lb_hash_symmetry.py 100000 2
```

## Validação Rápida

```bash
sudo bash scripts/setup_xdp_lb_chain.sh
ip netns exec nsA ping -c 3 10.10.2.1
sudo xdpunk-cli --netns nsr1 --map-pin /sys/fs/bpf/xdpunk_r1 lb status
sudo xdpunk-cli --netns nsr4 --map-pin /sys/fs/bpf/xdpunk_r4 lb status
```
