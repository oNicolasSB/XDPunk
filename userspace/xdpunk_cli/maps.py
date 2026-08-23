"""Acesso aos mapas BPF pinados (via BCC) e conversoes de tipos.

Os structs C declarados aqui DEVEM espelhar byte a byte os structs de
xdp/xdp_fw_lb.c (layouts sem padding implicito). Validacao cruzada:
`bpftool map dump -j pinned /sys/fs/bpf/xdpunk/<mapa>` vs a saida da CLI.

Convencao de armazenamento (identica a Fase 1): IPs, mascaras e portas
em network byte order. Em maquinas little-endian o u32 "NBO como inteiro"
e obtido com struct.unpack("<I", socket.inet_aton(ip)).
"""

import ctypes
import os
import socket
import struct
import sys

from bcc import BPF

DEFAULT_PIN_DIR = "/sys/fs/bpf/xdpunk"
LEGACY_MAP_PIN = "/sys/fs/bpf/xdp_fwd_maps/route_table"

MAX_FW_RULES = 2048
MAX_WAN_LINKS = 4

FW_ACTION_ALLOW = 0
FW_ACTION_DROP = 1
LB_MODE_HASH = 0
LB_MODE_RR = 1

PROTO_NAMES = {"any": 0, "icmp": 1, "tcp": 6, "udp": 17}
PROTO_NUMS = {v: k for k, v in PROTO_NAMES.items()}

GLOBAL_STAT_LABELS = [
    "TOTAL",
    "ARP",
    "FW_DROP",
    "LAN_REDIRECT",
    "WAN_REDIRECT",
    "PASS",
    "LB_NO_LINK",
]

_STRUCTS_SRC = r"""
struct route_entry { u32 ifindex; unsigned char dmac[6]; unsigned char smac[6]; };
struct fw_rule { u32 src_ip; u32 src_mask; u32 dst_ip; u32 dst_mask;
                 u16 src_port; u16 dst_port; u8 proto; u8 action; u8 enabled; u8 pad; };
struct fw_config { u32 num_rules; };
struct wan_link { u32 ifindex; unsigned char smac[6]; unsigned char dmac[6];
                  u8 enabled; u8 pad[3]; };
struct lb_config { u8 mode; u8 num_links; u8 enabled; u8 pad; };
struct stat_val { u64 packets; u64 bytes; };
"""

_TABLE_DECLS = {
    "route_table": 'BPF_TABLE_PINNED("hash", u32, struct route_entry, route_table, 256, "{d}/route_table");',
    "fw_rules": f'BPF_TABLE_PINNED("array", u32, struct fw_rule, fw_rules, {MAX_FW_RULES}, "{{d}}/fw_rules");',
    "fw_config": 'BPF_TABLE_PINNED("array", u32, struct fw_config, fw_config, 1, "{d}/fw_config");',
    "fw_stats": f'BPF_TABLE_PINNED("percpu_array", u32, struct stat_val, fw_stats, {MAX_FW_RULES}, "{{d}}/fw_stats");',
    "wan_links": 'BPF_TABLE_PINNED("array", u32, struct wan_link, wan_links, 4, "{d}/wan_links");',
    "lb_config": 'BPF_TABLE_PINNED("array", u32, struct lb_config, lb_config, 1, "{d}/lb_config");',
    "rr_state": 'BPF_TABLE_PINNED("array", u32, u64, rr_state, 1, "{d}/rr_state");',
    "wan_stats": 'BPF_TABLE_PINNED("percpu_array", u32, struct stat_val, wan_stats, 4, "{d}/wan_stats");',
    "global_stats": 'BPF_TABLE_PINNED("percpu_array", u32, struct stat_val, global_stats, 7, "{d}/global_stats");',
}


def open_tables(pin_dir: str, names):
    """Abre mapas pinados em *pin_dir*. Retorna (BPF, {nome: tabela})."""
    missing = [n for n in names if not os.path.exists(os.path.join(pin_dir, n))]
    if missing:
        print(
            f"Erro: mapa(s) {', '.join(missing)} nao encontrado(s) em "
            f"{pin_dir}.\nExecute antes: sudo bash scripts/setup_xdp_fw_lb.sh",
            file=sys.stderr,
        )
        sys.exit(1)
    src = _STRUCTS_SRC + "\n".join(
        _TABLE_DECLS[n].format(d=pin_dir) for n in names
    )
    b = BPF(text=src)
    return b, {n: b[n] for n in names}


def open_legacy_route_table(pin_path: str):
    """Abre a route_table da Fase 1 (value u32 = ifindex)."""
    if not os.path.exists(pin_path):
        print(
            f"Erro: mapa nao encontrado em {pin_path}.\n"
            "Execute antes: sudo bash scripts/setup_xdp_l3_dynamic.sh",
            file=sys.stderr,
        )
        sys.exit(1)
    bpf_src = f'BPF_TABLE_PINNED("hash", u32, u32, route_table, 256, "{pin_path}");'
    b = BPF(text=bpf_src)
    return b, b["route_table"]


# ---------------------------------------------------------------------------
# Conversoes IP / CIDR / porta / MAC
# ---------------------------------------------------------------------------

def ip_to_u32(ip_str: str) -> int:
    """IPv4 pontilhado -> u32 em network byte order (como inteiro host)."""
    try:
        raw = socket.inet_aton(ip_str)
    except OSError:
        print(f"Erro: '{ip_str}' nao e um endereco IPv4 valido.", file=sys.stderr)
        sys.exit(1)
    return struct.unpack("<I", raw)[0]


def u32_to_ip(value: int) -> str:
    return socket.inet_ntoa(struct.pack("<I", value))


def cidr_to_ip_mask(text: str):
    """'10.0.0.0/24' | '10.0.0.1' | 'any' -> (ip_u32 pre-mascarado, mask_u32)."""
    if text.lower() == "any":
        return 0, 0
    import ipaddress

    try:
        net = ipaddress.ip_network(text, strict=False)
    except ValueError:
        print(f"Erro: '{text}' nao e um IPv4/CIDR valido.", file=sys.stderr)
        sys.exit(1)
    if net.version != 4:
        print("Erro: apenas IPv4 e suportado.", file=sys.stderr)
        sys.exit(1)
    ip_u32 = ip_to_u32(str(net.network_address))
    mask_u32 = ip_to_u32(str(net.netmask))
    return ip_u32, mask_u32


def ip_mask_to_cidr(ip_u32: int, mask_u32: int) -> str:
    if mask_u32 == 0:
        return "any"
    prefix = bin(mask_u32).count("1")
    return f"{u32_to_ip(ip_u32)}/{prefix}"


def port_to_u16(port) -> int:
    """Porta (int ou 'any') -> u16 em network byte order."""
    if isinstance(port, str) and port.lower() == "any":
        return 0
    p = int(port)
    if not 0 <= p <= 65535:
        print(f"Erro: porta '{port}' fora do intervalo 0-65535.", file=sys.stderr)
        sys.exit(1)
    return socket.htons(p)


def u16_to_port(value: int) -> str:
    return "any" if value == 0 else str(socket.ntohs(value))


def mac_str_to_bytes(text: str) -> bytes:
    parts = text.replace("-", ":").split(":")
    if len(parts) != 6:
        print(f"Erro: MAC '{text}' invalido (esperado aa:bb:cc:dd:ee:ff).",
              file=sys.stderr)
        sys.exit(1)
    try:
        return bytes(int(p, 16) for p in parts)
    except ValueError:
        print(f"Erro: MAC '{text}' invalido.", file=sys.stderr)
        sys.exit(1)


def mac_bytes_to_str(raw) -> str:
    return ":".join(f"{b:02x}" for b in bytes(raw))


def set_mac_field(field, raw: bytes):
    """Copia 6 bytes para um campo ctypes (c_ubyte * 6) de um Leaf BCC."""
    for i in range(6):
        field[i] = raw[i]


# ---------------------------------------------------------------------------
# Estatisticas per-CPU
# ---------------------------------------------------------------------------

def sum_percpu(tbl, idx: int):
    """Soma (packets, bytes) de um PERCPU_ARRAY no indice *idx*."""
    values = tbl[tbl.Key(idx)]
    return (
        sum(v.packets for v in values),
        sum(v.bytes for v in values),
    )


def clear_percpu(tbl):
    """Zera todas as entradas de um PERCPU_ARRAY.

    Mapas ARRAY (inclusive PERCPU_ARRAY) nao suportam delecao de elementos:
    bpf_map_delete_elem retorna EINVAL, que o bcc reporta como
    "Could not clear item". Por isso NAO usamos tbl.clear() (que apaga chaves);
    em vez disso sobrescrevemos cada entrada — todas as CPUs — com um Leaf
    zerado (tbl.Leaf() ja vem zero-inicializado e dimensionado por CPU).

    Iteramos por indices explicitos (range/tbl.Key) em vez de tbl.keys():
    em array o iterador do bcc pode emitir uma chave >= max_entries, e a
    escrita nela falha com E2BIG ("Argument list too long")."""
    zero = tbl.Leaf()
    for i in range(len(tbl)):
        tbl[tbl.Key(i)] = zero
