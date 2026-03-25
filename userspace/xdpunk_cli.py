#!/usr/bin/env python3
"""xdpunk-cli — manage BPF route_table map from userspace via BCC."""

import argparse
import ctypes
import ctypes.util
import os
import socket
import struct
import sys

from bcc import BPF

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

CLONE_NEWNET = 0x40000000
DEFAULT_NETNS = "nssw"
DEFAULT_MAP_PIN = "/sys/fs/bpf/xdp_fwd_maps/route_table"

# ---------------------------------------------------------------------------
# BPF map helpers
# ---------------------------------------------------------------------------

def open_map(map_pin_path: str):
    """Open the pinned route_table via BCC's BPF_TABLE_PINNED."""
    bpf_src = f'''
    BPF_TABLE_PINNED("hash", u32, u32, route_table, 256, "{map_pin_path}");
    '''
    b = BPF(text=bpf_src)
    return b, b["route_table"]


def ip_to_key(tbl, ip_str: str):
    """Convert dotted-decimal IP to a BCC map Key (u32 network byte order)."""
    try:
        raw = socket.inet_aton(ip_str)
    except OSError:
        print(f"Erro: '{ip_str}' nao e um endereco IPv4 valido.", file=sys.stderr)
        sys.exit(1)
    ip_int = struct.unpack("<I", raw)[0]
    return tbl.Key(ip_int)


def key_to_ip(key) -> str:
    """Convert a BCC map Key (u32) back to dotted-decimal IP."""
    raw = struct.pack("<I", key.value)
    return socket.inet_ntoa(raw)

# ---------------------------------------------------------------------------
# Network namespace helpers (ctypes, no subprocess)
# ---------------------------------------------------------------------------

_libc = ctypes.CDLL(ctypes.util.find_library("c"), use_errno=True)


def _setns(fd: int, nstype: int):
    if _libc.setns(fd, nstype) == -1:
        errno = ctypes.get_errno()
        raise OSError(errno, os.strerror(errno))


def _enter_netns(netns: str):
    """Enter a network namespace. Returns the fd of the *original* netns."""
    orig_fd = os.open(f"/proc/self/ns/net", os.O_RDONLY)
    try:
        target_fd = os.open(f"/var/run/netns/{netns}", os.O_RDONLY)
    except OSError:
        os.close(orig_fd)
        raise
    try:
        _setns(target_fd, CLONE_NEWNET)
    finally:
        os.close(target_fd)
    return orig_fd


def _restore_netns(orig_fd: int):
    """Restore the original network namespace."""
    try:
        _setns(orig_fd, CLONE_NEWNET)
    finally:
        os.close(orig_fd)


def get_ifindex(iface: str, netns: str) -> int:
    """Resolve interface name → ifindex inside *netns*."""
    orig_fd = _enter_netns(netns)
    try:
        return socket.if_nametoindex(iface)
    except OSError:
        print(
            f"Erro: interface '{iface}' nao encontrada no namespace '{netns}'.",
            file=sys.stderr,
        )
        sys.exit(1)
    finally:
        _restore_netns(orig_fd)


def get_ifname(ifindex: int, netns: str) -> str:
    """Resolve ifindex → interface name inside *netns*."""
    orig_fd = _enter_netns(netns)
    try:
        return socket.if_indextoname(ifindex)
    except OSError:
        return f"?(ifindex={ifindex})"
    finally:
        _restore_netns(orig_fd)

# ---------------------------------------------------------------------------
# Command handlers
# ---------------------------------------------------------------------------

def cmd_update(args):
    _, tbl = open_map(args.map_pin)
    key = ip_to_key(tbl, args.ip)
    ifidx = get_ifindex(args.iface, args.netns)
    tbl[key] = tbl.Leaf(ifidx)
    print(f"Rota atualizada: {args.ip} -> {args.iface} (ifindex={ifidx})")


def cmd_delete(args):
    _, tbl = open_map(args.map_pin)
    key = ip_to_key(tbl, args.ip)
    try:
        del tbl[key]
    except KeyError:
        print(f"Erro: rota para {args.ip} nao encontrada.", file=sys.stderr)
        sys.exit(1)
    print(f"Rota removida: {args.ip}")


def cmd_lookup(args):
    _, tbl = open_map(args.map_pin)
    key = ip_to_key(tbl, args.ip)
    try:
        leaf = tbl[key]
    except KeyError:
        print(f"Rota para {args.ip} nao encontrada.", file=sys.stderr)
        sys.exit(1)
    ifidx = leaf.value
    ifname = get_ifname(ifidx, args.netns)
    print(f"{args.ip} -> {ifname} (ifindex={ifidx})")


def cmd_dump(args):
    _, tbl = open_map(args.map_pin)
    entries = list(tbl.items())
    if not entries:
        print("Tabela de rotas vazia.")
        return
    print(f"{'IP':<18} {'Interface':<14} {'ifindex'}")
    print("-" * 42)
    for key, leaf in entries:
        ip = key_to_ip(key)
        ifidx = leaf.value
        ifname = get_ifname(ifidx, args.netns)
        print(f"{ip:<18} {ifname:<14} {ifidx}")


def cmd_flush(args):
    _, tbl = open_map(args.map_pin)
    entries = list(tbl.keys())
    if not entries:
        print("Tabela ja esta vazia.")
        return
    for key in entries:
        del tbl[key]
    print(f"{len(entries)} rota(s) removida(s).")

# ---------------------------------------------------------------------------
# Argument parser
# ---------------------------------------------------------------------------

def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="xdpunk-cli",
        description=(
            "XDPunk CLI — gerenciamento em tempo real da tabela de rotas BPF.\n\n"
            "Permite criar, atualizar, remover e consultar entradas no mapa BPF\n"
            "`route_table` carregado pelo programa XDP (xdp_forward_dynamic), sem\n"
            "necessidade de recompilar ou recarregar o programa no kernel.\n\n"
            "O mapa associa um endereco IPv4 destino (chave) ao ifindex da\n"
            "interface de saida (valor) dentro do namespace do switch."
        ),
        epilog=(
            "Exemplos de uso:\n"
            "\n"
            "  Listar todas as rotas ativas:\n"
            "    xdpunk-cli map dump\n"
            "\n"
            "  Criar ou atualizar rota para 10.0.0.3 via veth3s:\n"
            "    xdpunk-cli map update 10.0.0.3 veth3s\n"
            "\n"
            "  Redirecionar 10.0.0.2 para o mesmo enlace de 10.0.0.3:\n"
            "    xdpunk-cli map update 10.0.0.2 veth3s\n"
            "\n"
            "  Consultar para qual interface um IP esta roteado:\n"
            "    xdpunk-cli map lookup 10.0.0.1\n"
            "\n"
            "  Remover rota para 10.0.0.3:\n"
            "    xdpunk-cli map delete 10.0.0.3\n"
            "\n"
            "  Limpar toda a tabela de rotas:\n"
            "    xdpunk-cli map flush\n"
            "\n"
            "  Usar namespace e mapa alternativos:\n"
            "    xdpunk-cli --netns mynamespace --map-pin /sys/fs/bpf/meu_mapa map dump\n"
            "\n"
            "Requer execucao como root (acesso ao bpffs e a namespaces).\n"
            "O ambiente virtual deve ser criado previamente com:\n"
            "  sudo bash scripts/setup_xdp_l3_dynamic.sh"
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument(
        "--netns",
        default=DEFAULT_NETNS,
        metavar="NAME",
        help=(
            f"Nome do network namespace do switch onde as interfaces de saida\n"
            f"serao resolvidas. (default: {DEFAULT_NETNS})"
        ),
    )
    parser.add_argument(
        "--map-pin",
        default=DEFAULT_MAP_PIN,
        metavar="PATH",
        help=(
            f"Caminho absoluto do mapa BPF pinado no bpffs.\n"
            f"(default: {DEFAULT_MAP_PIN})"
        ),
    )

    sub = parser.add_subparsers(dest="group", required=True)
    map_parser = sub.add_parser(
        "map",
        help="Operacoes na tabela de rotas BPF",
        description=(
            "Subcomandos para manipular o mapa BPF `route_table`.\n\n"
            "O mapa e um hash de 256 entradas:\n"
            "  chave  : endereco IPv4 destino (u32, network byte order)\n"
            "  valor  : ifindex da interface de saida (u32)\n\n"
            "As alteracoes tem efeito imediato no plano de dados XDP."
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    map_sub = map_parser.add_subparsers(dest="command", required=True)

    # map update
    p_update = map_sub.add_parser(
        "update",
        help="Criar ou atualizar rota para um IP",
        description=(
            "Insere ou sobrescreve uma entrada no mapa BPF route_table.\n\n"
            "O ifindex da interface informada e resolvido dentro do namespace\n"
            "do switch (--netns) e armazenado como valor da entrada."
        ),
        epilog=(
            "Exemplos:\n"
            "  xdpunk-cli map update 10.0.0.3 veth3s\n"
            "  xdpunk-cli map update 10.0.0.2 veth3s   # redirecionar ns2 -> veth3s"
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    p_update.add_argument(
        "ip",
        help="Endereco IPv4 destino a rotear (ex: 10.0.0.3)",
    )
    p_update.add_argument(
        "iface",
        help=(
            "Nome exato da interface de saida no namespace do switch\n"
            "(ex: veth3s). Deve existir no namespace indicado por --netns."
        ),
    )
    p_update.set_defaults(func=cmd_update)

    # map delete
    p_delete = map_sub.add_parser(
        "delete",
        help="Remover rota de um IP",
        description=(
            "Remove a entrada correspondente ao IP informado do mapa BPF.\n\n"
            "Apos a remocao, pacotes com esse IP destino serao descartados\n"
            "ou processados pelo kernel (XDP_PASS), conforme o programa XDP."
        ),
        epilog="Exemplo:\n  xdpunk-cli map delete 10.0.0.3",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    p_delete.add_argument(
        "ip",
        help="Endereco IPv4 destino cuja rota sera removida (ex: 10.0.0.3)",
    )
    p_delete.set_defaults(func=cmd_delete)

    # map lookup
    p_lookup = map_sub.add_parser(
        "lookup",
        help="Consultar rota de um IP especifico",
        description=(
            "Consulta o mapa BPF e exibe a interface de saida associada ao\n"
            "IP informado, mostrando tanto o nome da interface quanto o ifindex."
        ),
        epilog="Exemplo:\n  xdpunk-cli map lookup 10.0.0.1",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    p_lookup.add_argument(
        "ip",
        help="Endereco IPv4 destino a consultar (ex: 10.0.0.1)",
    )
    p_lookup.set_defaults(func=cmd_lookup)

    # map dump
    p_dump = map_sub.add_parser(
        "dump",
        help="Listar todas as rotas ativas",
        description=(
            "Exibe todas as entradas presentes no mapa BPF route_table em\n"
            "formato tabular: IP destino, nome da interface e ifindex.\n\n"
            "Os nomes de interface sao resolvidos dentro do namespace do switch."
        ),
        epilog="Exemplo:\n  xdpunk-cli map dump",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    p_dump.set_defaults(func=cmd_dump)

    # map flush
    p_flush = map_sub.add_parser(
        "flush",
        help="Remover todas as rotas da tabela",
        description=(
            "Remove todas as entradas do mapa BPF route_table de uma vez.\n\n"
            "Apos o flush, nenhum pacote sera redirecionado pelo programa XDP\n"
            "ate que novas rotas sejam inseridas via 'map update'."
        ),
        epilog="Exemplo:\n  xdpunk-cli map flush",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    p_flush.set_defaults(func=cmd_flush)

    return parser


def main():
    parser = build_parser()
    args = parser.parse_args()
    args.func(args)


if __name__ == "__main__":
    main()
