#!/usr/bin/env python3
"""simulate_lb_hash_symmetry.py — modelo analitico da (a)simetria de
caminho ida/volta no LB encadeado (ver spec, secao 2 "Assimetria de
caminho").

Reimplementa em Python a formula de hash de fluxo de xdp/xdp_fw_lb.c
(modo LB_MODE_HASH) e mede, para N 5-tuplas aleatorias, a fracao de
fluxos em que o indice de link escolhido pela 5-tupla de ida bate com o
escolhido pela 5-tupla de volta (endereco/porta trocados). Portas e
enderecos sao tratados como inteiros opacos de 32/16 bits — a pergunta
de simetria depende so de como a formula reage a troca de
origem/destino, nao do byte-order real dos campos na rede.
"""
import random
import sys

MASK32 = 0xFFFFFFFF


def flow_link_index(saddr, daddr, sport, dport, proto, num_links):
    """Replica do hash de fluxo em xdp/xdp_fw_lb.c (LB_MODE_HASH)."""
    h = (saddr ^ daddr ^ (((sport << 16) | dport) & MASK32) ^ proto) & MASK32
    h = (h * 0x9E3779B1) & MASK32
    return (h >> 16) % num_links


def random_flow(rng):
    saddr = rng.getrandbits(32)
    daddr = rng.getrandbits(32)
    sport = rng.getrandbits(16)
    dport = rng.getrandbits(16)
    proto = rng.choice([6, 17])  # TCP, UDP
    return saddr, daddr, sport, dport, proto


def is_symmetric(flow, num_links):
    saddr, daddr, sport, dport, proto = flow
    fwd = flow_link_index(saddr, daddr, sport, dport, proto, num_links)
    rev = flow_link_index(daddr, saddr, dport, sport, proto, num_links)
    return fwd == rev


def main(n=100000, num_links=2, seed=None):
    rng = random.Random(seed)
    symmetric = sum(is_symmetric(random_flow(rng), num_links) for _ in range(n))
    rate = symmetric / n
    print(f"N={n} num_links={num_links}: taxa de simetria ida/volta = "
          f"{rate:.4f} ({symmetric}/{n})")
    return rate


def _selftest():
    # num_links=1: todo fluxo cai no indice 0 -> simetrico por definicao.
    assert flow_link_index(1, 2, 3, 4, 6, 1) == 0
    assert is_symmetric((1, 2, 3, 4, 6), num_links=1)

    # sport == dport: o termo de portas nao muda ao trocar sport/dport, e
    # saddr^daddr e comutativo -> ida e volta sempre no mesmo link,
    # qualquer que seja num_links.
    flow = (10, 20, 5555, 5555, 6)
    assert is_symmetric(flow, num_links=2)
    assert is_symmetric(flow, num_links=4)

    # Caso calculado a mao, replicando a formula do .c passo a passo.
    saddr, daddr, sport, dport, proto = 0x0A000001, 0x0A000002, 0x1F90, 0x0050, 6
    h = (saddr ^ daddr ^ ((sport << 16) | dport) ^ proto) & MASK32
    h = (h * 0x9E3779B1) & MASK32
    expected_idx = (h >> 16) % 2
    assert flow_link_index(saddr, daddr, sport, dport, proto, 2) == expected_idx

    print("selftest OK")


if __name__ == "__main__":
    if len(sys.argv) > 1 and sys.argv[1] == "--selftest":
        _selftest()
        sys.exit(0)
    n = int(sys.argv[1]) if len(sys.argv) > 1 else 100000
    num_links = int(sys.argv[2]) if len(sys.argv) > 2 else 2
    seed = int(sys.argv[3]) if len(sys.argv) > 3 else None
    main(n=n, num_links=num_links, seed=seed)
