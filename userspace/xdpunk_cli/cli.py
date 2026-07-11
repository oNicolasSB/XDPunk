"""xdpunk-cli — plano de controle do XDPunk.

Fase 1: gerenciamento da tabela de rotas (grupo `map`).
Fase 2: firewall stateless (`fw`), balanceador de links WAN (`lb`) e
contadores do pipeline (`stats`).

Todos os grupos operam mapas BPF pinados no bpffs, com efeito imediato
no plano de dados XDP — sem recompilar nem recarregar o programa.
"""

import argparse

from . import fw, lb, maps, route, stats

DEFAULT_NETNS = "nssw"


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="xdpunk-cli",
        description=(
            "XDPunk CLI — plano de controle em tempo real do switch XDP.\n\n"
            "Grupos de comandos:\n"
            "  map    tabela de rotas (route_table)\n"
            "  fw     firewall stateless (regras 5-tupla ALLOW/DROP)\n"
            "  lb     balanceador de links WAN (hash | round-robin)\n"
            "  stats  contadores globais do pipeline XDP"
        ),
        epilog=(
            "Exemplos de uso:\n"
            "\n"
            "  Rotas:\n"
            "    xdpunk-cli map dump\n"
            "    xdpunk-cli map update 10.0.0.1 veth1s --dmac aa:bb:cc:dd:ee:ff\n"
            "\n"
            "  Firewall:\n"
            "    xdpunk-cli fw add --prio 0 --src 10.0.0.1/32 --dst 192.0.2.10/32 \\\n"
            "        --proto tcp --dport 5201 --action drop\n"
            "    xdpunk-cli fw list\n"
            "\n"
            "  Load balancer WAN:\n"
            "    xdpunk-cli lb link add 0 vethw1s --dmac 6a:00:11:22:33:44\n"
            "    xdpunk-cli lb mode hash\n"
            "    xdpunk-cli lb link disable 0     # failover manual\n"
            "    xdpunk-cli lb status\n"
            "\n"
            "  Contadores:\n"
            "    xdpunk-cli stats\n"
            "    xdpunk-cli stats --reset\n"
            "\n"
            "  Lab da Fase 1 (switch L3 puro, value u32):\n"
            "    xdpunk-cli --legacy map dump\n"
            "\n"
            "Requer execucao como root (acesso ao bpffs e a namespaces).\n"
            "O ambiente virtual deve ser criado previamente com:\n"
            "  sudo bash scripts/setup_xdp_fw_lb.sh       (Fase 2)\n"
            "  sudo bash scripts/setup_xdp_l3_dynamic.sh  (Fase 1, use --legacy)"
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument(
        "--netns",
        default=DEFAULT_NETNS,
        metavar="NAME",
        help=(
            "Network namespace do switch onde interfaces sao resolvidas.\n"
            f"(default: {DEFAULT_NETNS})"
        ),
    )
    parser.add_argument(
        "--map-pin",
        default=None,
        metavar="PATH",
        help=(
            "Diretorio base dos mapas BPF pinados.\n"
            f"(default: {maps.DEFAULT_PIN_DIR}; com --legacy, caminho do\n"
            f"mapa route_table da Fase 1, default {maps.LEGACY_MAP_PIN})"
        ),
    )
    parser.add_argument(
        "--legacy",
        action="store_true",
        help=(
            "Operar a route_table da Fase 1 (value u32, sem MACs),\n"
            "pinada pelo setup_xdp_l3_dynamic.sh. Apenas grupo `map`."
        ),
    )

    sub = parser.add_subparsers(dest="group", required=True)
    route.register(sub)
    fw.register(sub)
    lb.register(sub)
    stats.register(sub)

    return parser


def main():
    parser = build_parser()
    args = parser.parse_args()

    # Resolve caminhos de pin conforme o modo
    if args.legacy:
        args.legacy_pin = args.map_pin or maps.LEGACY_MAP_PIN
        args.pin_dir = maps.DEFAULT_PIN_DIR
        if args.group != "map":
            parser.error("--legacy so e suportado com o grupo `map`.")
    else:
        args.pin_dir = args.map_pin or maps.DEFAULT_PIN_DIR
        args.legacy_pin = None

    args.func(args)


if __name__ == "__main__":
    main()
