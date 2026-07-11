"""Grupo `map` — tabela de rotas (route_table).

Fase 2: o value passou de u32 (ifindex) para struct route_entry
(ifindex + dmac + smac), pois todo redirect IPv4 reescreve MACs.
O modo --legacy opera a route_table da Fase 1 (value u32) no pin antigo.
"""

import sys

from . import maps
from .netns import get_ifindex, get_ifname, get_mac


def _open(args):
    if args.legacy:
        return maps.open_legacy_route_table(args.legacy_pin)
    _, tables = maps.open_tables(args.pin_dir, ["route_table"])
    return None, tables["route_table"]


def cmd_update(args):
    _, tbl = _open(args)
    key = tbl.Key(maps.ip_to_u32(args.ip))
    ifidx = get_ifindex(args.iface, args.netns)

    if args.legacy:
        tbl[key] = tbl.Leaf(ifidx)
        print(f"Rota atualizada: {args.ip} -> {args.iface} (ifindex={ifidx})")
        return

    if not args.dmac:
        print(
            "Erro: --dmac <MAC do host destino> e obrigatorio no layout novo\n"
            "(use --legacy para operar o mapa da Fase 1).",
            file=sys.stderr,
        )
        sys.exit(1)

    dmac = maps.mac_str_to_bytes(args.dmac)
    smac = get_mac(args.iface, args.netns)

    leaf = tbl.Leaf()
    leaf.ifindex = ifidx
    maps.set_mac_field(leaf.dmac, dmac)
    maps.set_mac_field(leaf.smac, smac)
    tbl[key] = leaf
    print(
        f"Rota atualizada: {args.ip} -> {args.iface} (ifindex={ifidx}, "
        f"dmac={maps.mac_bytes_to_str(dmac)}, smac={maps.mac_bytes_to_str(smac)})"
    )


def cmd_delete(args):
    _, tbl = _open(args)
    key = tbl.Key(maps.ip_to_u32(args.ip))
    try:
        del tbl[key]
    except KeyError:
        print(f"Erro: rota para {args.ip} nao encontrada.", file=sys.stderr)
        sys.exit(1)
    print(f"Rota removida: {args.ip}")


def cmd_lookup(args):
    _, tbl = _open(args)
    key = tbl.Key(maps.ip_to_u32(args.ip))
    try:
        leaf = tbl[key]
    except KeyError:
        print(f"Rota para {args.ip} nao encontrada.", file=sys.stderr)
        sys.exit(1)

    if args.legacy:
        ifidx = leaf.value
        print(f"{args.ip} -> {get_ifname(ifidx, args.netns)} (ifindex={ifidx})")
        return

    ifname = get_ifname(leaf.ifindex, args.netns)
    print(
        f"{args.ip} -> {ifname} (ifindex={leaf.ifindex}, "
        f"dmac={maps.mac_bytes_to_str(leaf.dmac)}, "
        f"smac={maps.mac_bytes_to_str(leaf.smac)})"
    )


def cmd_dump(args):
    _, tbl = _open(args)
    entries = list(tbl.items())
    if not entries:
        print("Tabela de rotas vazia.")
        return

    if args.legacy:
        print(f"{'IP':<18} {'Interface':<14} {'ifindex'}")
        print("-" * 42)
        for key, leaf in entries:
            ifidx = leaf.value
            print(f"{maps.u32_to_ip(key.value):<18} "
                  f"{get_ifname(ifidx, args.netns):<14} {ifidx}")
        return

    print(f"{'IP':<16} {'Interface':<10} {'ifindex':<8} {'dmac':<18} {'smac'}")
    print("-" * 72)
    for key, leaf in entries:
        print(
            f"{maps.u32_to_ip(key.value):<16} "
            f"{get_ifname(leaf.ifindex, args.netns):<10} "
            f"{leaf.ifindex:<8} "
            f"{maps.mac_bytes_to_str(leaf.dmac):<18} "
            f"{maps.mac_bytes_to_str(leaf.smac)}"
        )


def cmd_flush(args):
    _, tbl = _open(args)
    entries = list(tbl.keys())
    if not entries:
        print("Tabela ja esta vazia.")
        return
    for key in entries:
        del tbl[key]
    print(f"{len(entries)} rota(s) removida(s).")


def register(sub):
    import argparse

    map_parser = sub.add_parser(
        "map",
        help="Operacoes na tabela de rotas BPF (route_table)",
        description=(
            "Subcomandos para manipular o mapa BPF `route_table`.\n\n"
            "O mapa e um hash de 256 entradas:\n"
            "  chave : endereco IPv4 destino (u32, network byte order)\n"
            "  valor : {ifindex, dmac, smac} — MACs usados na reescrita\n"
            "          do cabecalho Ethernet antes do bpf_redirect.\n\n"
            "As alteracoes tem efeito imediato no plano de dados XDP."
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    map_sub = map_parser.add_subparsers(dest="command", required=True)

    p_update = map_sub.add_parser(
        "update",
        help="Criar ou atualizar rota para um IP",
        description=(
            "Insere ou sobrescreve uma entrada no mapa route_table.\n\n"
            "O ifindex e o MAC de origem (smac) sao resolvidos dentro do\n"
            "namespace do switch (--netns). O MAC do host destino (--dmac)\n"
            "deve ser informado (ex.: `ip -n ns1 -br link show veth1h`)."
        ),
        epilog=(
            "Exemplos:\n"
            "  xdpunk-cli map update 10.0.0.1 veth1s --dmac aa:bb:cc:dd:ee:ff\n"
            "  xdpunk-cli --legacy map update 10.0.0.3 veth3s   # lab da Fase 1"
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    p_update.add_argument("ip", help="Endereco IPv4 destino a rotear")
    p_update.add_argument(
        "iface",
        help="Interface de saida no namespace do switch (ex: veth1s)",
    )
    p_update.add_argument(
        "--dmac",
        metavar="MAC",
        help="MAC do host destino (obrigatorio, exceto com --legacy)",
    )
    p_update.set_defaults(func=cmd_update)

    p_delete = map_sub.add_parser("delete", help="Remover rota de um IP")
    p_delete.add_argument("ip", help="Endereco IPv4 destino")
    p_delete.set_defaults(func=cmd_delete)

    p_lookup = map_sub.add_parser("lookup", help="Consultar rota de um IP")
    p_lookup.add_argument("ip", help="Endereco IPv4 destino")
    p_lookup.set_defaults(func=cmd_lookup)

    p_dump = map_sub.add_parser("dump", help="Listar todas as rotas ativas")
    p_dump.set_defaults(func=cmd_dump)

    p_flush = map_sub.add_parser("flush", help="Remover todas as rotas")
    p_flush.set_defaults(func=cmd_flush)
