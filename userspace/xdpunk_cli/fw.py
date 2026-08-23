"""Grupo `fw` — firewall stateless (fw_rules / fw_config / fw_stats).

Regras 5-tupla com wildcards (mascara 0 / porta 0 / proto 0), acao
ALLOW ou DROP. O indice do array e a prioridade (menor vence,
first-match). Nenhuma regra casando -> politica default ALLOW.

fw_config.num_rules = maior indice habilitado + 1: o scan do XDP para
nesse ponto, fazendo o custo escalar com N regras (experimento Q1).
"""

import ipaddress
import sys

from . import maps

# Faixa de benchmarking RFC 2544 (nao roteavel em producao) usada como src
# das regras sinteticas do `loadgen`: garante que nenhuma regra case com o
# trafego real de teste (10.0.0.0/24), isolando o custo puro do scan.
_LOADGEN_BASE_NET = ipaddress.ip_network("198.18.0.0/15")

_FW_TABLES = ["fw_rules", "fw_config", "fw_stats"]


def _open(args):
    _, tables = maps.open_tables(args.pin_dir, _FW_TABLES)
    return tables


def _refresh_num_rules(tables):
    """Recalcula fw_config.num_rules = maior indice habilitado + 1."""
    rules = tables["fw_rules"]
    num = 0
    for i in range(maps.MAX_FW_RULES):
        if rules[rules.Key(i)].enabled:
            num = i + 1
    cfg_tbl = tables["fw_config"]
    cfg = cfg_tbl.Leaf()
    cfg.num_rules = num
    cfg_tbl[cfg_tbl.Key(0)] = cfg
    return num


def cmd_add(args):
    if not 0 <= args.prio < maps.MAX_FW_RULES:
        print(f"Erro: --prio deve estar em 0..{maps.MAX_FW_RULES - 1}.",
              file=sys.stderr)
        sys.exit(1)

    tables = _open(args)
    rules = tables["fw_rules"]

    src_ip, src_mask = maps.cidr_to_ip_mask(args.src)
    dst_ip, dst_mask = maps.cidr_to_ip_mask(args.dst)

    leaf = rules.Leaf()
    leaf.src_ip = src_ip
    leaf.src_mask = src_mask
    leaf.dst_ip = dst_ip
    leaf.dst_mask = dst_mask
    leaf.src_port = maps.port_to_u16(args.sport)
    leaf.dst_port = maps.port_to_u16(args.dport)
    leaf.proto = maps.PROTO_NAMES[args.proto]
    leaf.action = (maps.FW_ACTION_DROP if args.action == "drop"
                   else maps.FW_ACTION_ALLOW)
    leaf.enabled = 1
    rules[rules.Key(args.prio)] = leaf

    num = _refresh_num_rules(tables)
    print(
        f"Regra {args.prio}: {args.action.upper()} proto={args.proto} "
        f"src={args.src}:{args.sport} dst={args.dst}:{args.dport} "
        f"(regras ativas ate o indice {num - 1})"
    )


def cmd_del(args):
    tables = _open(args)
    rules = tables["fw_rules"]
    key = rules.Key(args.prio)
    if not rules[key].enabled:
        print(f"Erro: nao ha regra no indice {args.prio}.", file=sys.stderr)
        sys.exit(1)
    rules[key] = rules.Leaf()  # zera o slot (array nao suporta delete)
    _refresh_num_rules(tables)
    print(f"Regra {args.prio} removida.")


def cmd_list(args):
    tables = _open(args)
    rules = tables["fw_rules"]
    stats = tables["fw_stats"]

    rows = []
    for i in range(maps.MAX_FW_RULES):
        r = rules[rules.Key(i)]
        if not r.enabled:
            continue
        pkts, byts = maps.sum_percpu(stats, i)
        rows.append((
            i,
            "DROP" if r.action == maps.FW_ACTION_DROP else "ALLOW",
            maps.PROTO_NUMS.get(r.proto, str(r.proto)),
            maps.ip_mask_to_cidr(r.src_ip, r.src_mask),
            maps.u16_to_port(r.src_port),
            maps.ip_mask_to_cidr(r.dst_ip, r.dst_mask),
            maps.u16_to_port(r.dst_port),
            pkts,
            byts,
        ))

    if not rows:
        print("Nenhuma regra de firewall configurada (politica default: ALLOW).")
        return

    print(f"{'PRIO':<5} {'ACAO':<6} {'PROTO':<6} {'ORIGEM':<20} {'SPORT':<6} "
          f"{'DESTINO':<20} {'DPORT':<6} {'PKTS':<10} {'BYTES'}")
    print("-" * 92)
    for row in rows:
        print(f"{row[0]:<5} {row[1]:<6} {row[2]:<6} {row[3]:<20} {row[4]:<6} "
              f"{row[5]:<20} {row[6]:<6} {row[7]:<10} {row[8]}")
    print("\nPolitica default (sem match): ALLOW")


def cmd_loadgen(args):
    """Carrega N regras sinteticas nao-casantes num unico processo.

    Usado pelos benchmarks de capacidade (1000/2000 regras): escrever N
    regras via ~N chamadas de subprocess desperdicaria minutos em overhead
    de startup/BCC. Aqui tudo roda dentro de um unico BPF() ja aberto.

    Padrao das regras (pior caso, nenhuma casa de fato): src IP sequencial
    dentro de 198.18.0.0/15 (RFC 2544), /32, proto TCP, dport 9, acao DROP.
    Todo pacote de teste percorre o scan completo e cai na politica default
    ALLOW. Sobrescreve os indices 0..N-1; assume tabela previamente
    limpa (`fw flush`) para que `fw_config.num_rules` reflita exatamente N.
    """
    n = args.n
    if not 0 <= n <= maps.MAX_FW_RULES:
        print(f"Erro: N deve estar em 0..{maps.MAX_FW_RULES}.", file=sys.stderr)
        sys.exit(1)
    if n > _LOADGEN_BASE_NET.num_addresses:
        print(
            f"Erro: N={n} excede os enderecos disponiveis em "
            f"{_LOADGEN_BASE_NET} ({_LOADGEN_BASE_NET.num_addresses}).",
            file=sys.stderr,
        )
        sys.exit(1)

    tables = _open(args)
    rules = tables["fw_rules"]

    base_ip = int(_LOADGEN_BASE_NET.network_address)
    mask_full = maps.ip_to_u32("255.255.255.255")
    dport = maps.port_to_u16(9)
    proto_tcp = maps.PROTO_NAMES["tcp"]

    for i in range(n):
        leaf = rules.Leaf()
        leaf.src_ip = maps.ip_to_u32(str(ipaddress.ip_address(base_ip + i)))
        leaf.src_mask = mask_full
        leaf.dst_port = dport
        leaf.proto = proto_tcp
        leaf.action = maps.FW_ACTION_DROP
        leaf.enabled = 1
        rules[rules.Key(i)] = leaf

    cfg_tbl = tables["fw_config"]
    cfg = cfg_tbl.Leaf()
    cfg.num_rules = n
    cfg_tbl[cfg_tbl.Key(0)] = cfg

    print(
        f"{n} regra(s) de teste carregada(s) (nao-casantes: src "
        f"{_LOADGEN_BASE_NET} sequencial /32, tcp, dport 9, DROP)."
    )


def cmd_flush(args):
    tables = _open(args)
    rules = tables["fw_rules"]
    count = 0
    for i in range(maps.MAX_FW_RULES):
        key = rules.Key(i)
        if rules[key].enabled:
            rules[key] = rules.Leaf()
            count += 1
    _refresh_num_rules(tables)
    print(f"{count} regra(s) removida(s).")


def register(sub):
    import argparse

    fw_parser = sub.add_parser(
        "fw",
        help="Firewall stateless (regras 5-tupla, ALLOW/DROP)",
        description=(
            "Gerencia as regras do firewall stateless no mapa BPF `fw_rules`.\n\n"
            "Cada regra casa por 5-tupla com wildcards:\n"
            "  --src/--dst  : IPv4 ou CIDR (ex: 10.0.0.1, 10.0.0.0/24) ou 'any'\n"
            "  --sport/--dport : porta L4 ou 'any'\n"
            "  --proto      : tcp | udp | icmp | any\n\n"
            "O indice (--prio) e a prioridade: menor indice vence (first-match).\n"
            "Sem match: politica default ALLOW. Alteracoes valem imediatamente,\n"
            "sem recarregar o programa XDP."
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    fw_sub = fw_parser.add_subparsers(dest="command", required=True)

    p_add = fw_sub.add_parser(
        "add",
        help="Adicionar/sobrescrever regra",
        epilog=(
            "Exemplos:\n"
            "  xdpunk-cli fw add --prio 0 --src 10.0.0.1/32 --dst 192.0.2.10/32 \\\n"
            "      --proto tcp --dport 5201 --action drop\n"
            "  xdpunk-cli fw add --prio 1 --proto icmp --action drop"
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    p_add.add_argument("--prio", type=int, required=True,
                       help=f"Indice/prioridade da regra (0..{maps.MAX_FW_RULES - 1})")
    p_add.add_argument("--src", default="any", help="IPv4/CIDR de origem (default: any)")
    p_add.add_argument("--dst", default="any", help="IPv4/CIDR de destino (default: any)")
    p_add.add_argument("--sport", default="any", help="Porta de origem (default: any)")
    p_add.add_argument("--dport", default="any", help="Porta de destino (default: any)")
    p_add.add_argument("--proto", default="any",
                       choices=sorted(maps.PROTO_NAMES.keys()),
                       help="Protocolo L4 (default: any)")
    p_add.add_argument("--action", required=True, choices=["allow", "drop"],
                       help="Acao da regra")
    p_add.set_defaults(func=cmd_add)

    p_del = fw_sub.add_parser("del", help="Remover regra por prioridade")
    p_del.add_argument("--prio", type=int, required=True,
                       help="Indice da regra a remover")
    p_del.set_defaults(func=cmd_del)

    p_list = fw_sub.add_parser("list",
                               help="Listar regras ativas com contadores")
    p_list.set_defaults(func=cmd_list)

    p_flush = fw_sub.add_parser("flush", help="Remover todas as regras")
    p_flush.set_defaults(func=cmd_flush)

    p_loadgen = fw_sub.add_parser(
        "loadgen",
        help="Carregar N regras sinteticas nao-casantes (benchmarks de capacidade)",
        epilog=(
            "Escreve N regras num unico processo (evita overhead de subprocess\n"
            "por regra). Todas nao-casam de proposito, isolando o custo do scan.\n"
            "Recomendado rodar `fw flush` antes.\n\n"
            "Exemplo:\n"
            "  xdpunk-cli fw flush && xdpunk-cli fw loadgen 2000"
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    p_loadgen.add_argument("n", type=int,
                           help=f"Numero de regras a carregar (0..{maps.MAX_FW_RULES})")
    p_loadgen.set_defaults(func=cmd_loadgen)
