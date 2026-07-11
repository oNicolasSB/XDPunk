"""Grupo `lb` — balanceador de links WAN (wan_links / lb_config / wan_stats).

Slots 0..3 do array wan_links guardam {ifindex, smac, dmac, enabled}.
lb_config define o modo (hash de fluxo | round-robin), a faixa do modulo
(num_links = maior slot configurado + 1) e o liga/desliga global.
`link disable` e o failover manual: o XDP pula o link no proximo pacote.
"""

import sys

from . import maps
from .netns import get_ifindex, get_ifname, get_mac

_LB_TABLES = ["wan_links", "lb_config", "wan_stats", "rr_state"]


def _open(args):
    _, tables = maps.open_tables(args.pin_dir, _LB_TABLES)
    return tables


def _refresh_config(tables, mode=None, enabled=None):
    """Recalcula num_links e atualiza lb_config preservando o restante."""
    links = tables["wan_links"]
    num = 0
    for i in range(maps.MAX_WAN_LINKS):
        if links[links.Key(i)].ifindex:
            num = i + 1

    cfg_tbl = tables["lb_config"]
    cur = cfg_tbl[cfg_tbl.Key(0)]
    cfg = cfg_tbl.Leaf()
    cfg.mode = cur.mode if mode is None else mode
    cfg.enabled = cur.enabled if enabled is None else enabled
    cfg.num_links = num
    cfg_tbl[cfg_tbl.Key(0)] = cfg
    return cfg


def _check_slot(args):
    if not 0 <= args.index < maps.MAX_WAN_LINKS:
        print(f"Erro: indice de link deve estar em 0..{maps.MAX_WAN_LINKS - 1}.",
              file=sys.stderr)
        sys.exit(1)


def cmd_link_add(args):
    _check_slot(args)
    tables = _open(args)
    links = tables["wan_links"]

    ifidx = get_ifindex(args.iface, args.netns)
    smac = get_mac(args.iface, args.netns)
    dmac = maps.mac_str_to_bytes(args.dmac)

    leaf = links.Leaf()
    leaf.ifindex = ifidx
    maps.set_mac_field(leaf.smac, smac)
    maps.set_mac_field(leaf.dmac, dmac)
    leaf.enabled = 1
    links[links.Key(args.index)] = leaf

    cfg = _refresh_config(tables, enabled=1)
    print(
        f"Link WAN {args.index}: {args.iface} (ifindex={ifidx}, "
        f"smac={maps.mac_bytes_to_str(smac)}, "
        f"dmac={maps.mac_bytes_to_str(dmac)}) — "
        f"LB ativo com num_links={cfg.num_links}, "
        f"modo={'rr' if cfg.mode == maps.LB_MODE_RR else 'hash'}"
    )


def cmd_link_del(args):
    _check_slot(args)
    tables = _open(args)
    links = tables["wan_links"]
    key = links.Key(args.index)
    if not links[key].ifindex:
        print(f"Erro: nao ha link no slot {args.index}.", file=sys.stderr)
        sys.exit(1)
    links[key] = links.Leaf()
    cfg = _refresh_config(tables)
    print(f"Link WAN {args.index} removido (num_links={cfg.num_links}).")


def _set_link_enabled(args, value):
    _check_slot(args)
    tables = _open(args)
    links = tables["wan_links"]
    key = links.Key(args.index)
    leaf = links[key]
    if not leaf.ifindex:
        print(f"Erro: nao ha link no slot {args.index}.", file=sys.stderr)
        sys.exit(1)
    leaf.enabled = value
    links[key] = leaf
    state = "habilitado" if value else "desabilitado (failover manual)"
    print(f"Link WAN {args.index} {state}.")


def cmd_link_enable(args):
    _set_link_enabled(args, 1)


def cmd_link_disable(args):
    _set_link_enabled(args, 0)


def cmd_mode(args):
    tables = _open(args)
    mode = maps.LB_MODE_RR if args.mode == "rr" else maps.LB_MODE_HASH
    _refresh_config(tables, mode=mode)
    print(f"Modo do balanceador: {args.mode}")


def cmd_on(args):
    tables = _open(args)
    _refresh_config(tables, enabled=1)
    print("Balanceador WAN habilitado.")


def cmd_off(args):
    tables = _open(args)
    _refresh_config(tables, enabled=0)
    print("Balanceador WAN desabilitado (miss na route_table -> XDP_PASS).")


def cmd_status(args):
    tables = _open(args)
    links = tables["wan_links"]
    stats = tables["wan_stats"]
    cfg = tables["lb_config"][tables["lb_config"].Key(0)]

    mode = "rr" if cfg.mode == maps.LB_MODE_RR else "hash"
    state = "ativo" if cfg.enabled else "desativado"
    print(f"LB WAN: {state} | modo: {mode} | num_links: {cfg.num_links}")
    print()

    rows = []
    total_bytes = 0
    for i in range(maps.MAX_WAN_LINKS):
        link = links[links.Key(i)]
        if not link.ifindex:
            continue
        pkts, byts = maps.sum_percpu(stats, i)
        total_bytes += byts
        rows.append((i, link, pkts, byts))

    if not rows:
        print("Nenhum link WAN configurado.")
        return

    print(f"{'SLOT':<5} {'Interface':<10} {'ifindex':<8} {'estado':<8} "
          f"{'smac':<18} {'dmac':<18} {'PKTS':<10} {'BYTES':<12} {'%'}")
    print("-" * 100)
    for i, link, pkts, byts in rows:
        pct = (100.0 * byts / total_bytes) if total_bytes else 0.0
        print(
            f"{i:<5} {get_ifname(link.ifindex, args.netns):<10} "
            f"{link.ifindex:<8} {'on' if link.enabled else 'off':<8} "
            f"{maps.mac_bytes_to_str(link.smac):<18} "
            f"{maps.mac_bytes_to_str(link.dmac):<18} "
            f"{pkts:<10} {byts:<12} {pct:5.1f}"
        )


def register(sub):
    import argparse

    lb_parser = sub.add_parser(
        "lb",
        help="Balanceador de links WAN (hash de fluxo ou round-robin)",
        description=(
            "Gerencia o balanceador de saida WAN.\n\n"
            "Pacotes IPv4 sem rota na route_table (rota default) sao\n"
            "distribuidos entre os links WAN configurados. Modos:\n"
            "  hash : afinidade de fluxo (5-tupla), sem reordenacao\n"
            "  rr   : round-robin por pacote (distribuicao uniforme)\n\n"
            "`link disable` retira um link do balanceamento imediatamente\n"
            "(failover manual); o trafego migra para os links restantes."
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    lb_sub = lb_parser.add_subparsers(dest="command", required=True)

    link_parser = lb_sub.add_parser("link", help="Gerenciar links WAN")
    link_sub = link_parser.add_subparsers(dest="link_command", required=True)

    p_add = link_sub.add_parser(
        "add",
        help="Adicionar/atualizar link WAN em um slot",
        epilog=(
            "Exemplo:\n"
            "  xdpunk-cli lb link add 0 vethw1s --dmac 6a:00:11:22:33:44\n"
            "  (--dmac = MAC da interface do roteador do provedor;\n"
            "   smac e ifindex sao resolvidos no namespace do switch)"
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    p_add.add_argument("index", type=int, help="Slot do link (0..3)")
    p_add.add_argument("iface", help="veth WAN do switch (ex: vethw1s)")
    p_add.add_argument("--dmac", required=True, metavar="MAC",
                       help="MAC da interface do roteador do provedor")
    p_add.set_defaults(func=cmd_link_add)

    p_del = link_sub.add_parser("del", help="Remover link WAN")
    p_del.add_argument("index", type=int, help="Slot do link (0..3)")
    p_del.set_defaults(func=cmd_link_del)

    p_en = link_sub.add_parser("enable", help="Reabilitar link WAN")
    p_en.add_argument("index", type=int, help="Slot do link (0..3)")
    p_en.set_defaults(func=cmd_link_enable)

    p_dis = link_sub.add_parser(
        "disable", help="Desabilitar link WAN (failover manual)")
    p_dis.add_argument("index", type=int, help="Slot do link (0..3)")
    p_dis.set_defaults(func=cmd_link_disable)

    p_mode = lb_sub.add_parser("mode", help="Definir algoritmo do balanceador")
    p_mode.add_argument("mode", choices=["hash", "rr"],
                        help="hash = afinidade de fluxo; rr = round-robin")
    p_mode.set_defaults(func=cmd_mode)

    p_on = lb_sub.add_parser("on", help="Habilitar o balanceador")
    p_on.set_defaults(func=cmd_on)

    p_off = lb_sub.add_parser("off", help="Desabilitar o balanceador")
    p_off.set_defaults(func=cmd_off)

    p_status = lb_sub.add_parser(
        "status", help="Exibir configuracao, links e estatisticas")
    p_status.set_defaults(func=cmd_status)
