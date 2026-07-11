"""Comando `stats` — contadores globais do pipeline XDP (global_stats).

Contadores per-CPU somados pela CLI. `--reset` zera global_stats,
fw_stats e wan_stats (usado entre rodadas dos experimentos).
"""

from . import maps

_STAT_TABLES = ["global_stats", "fw_stats", "wan_stats"]


def cmd_stats(args):
    _, tables = maps.open_tables(args.pin_dir, _STAT_TABLES)

    if args.reset:
        for name in _STAT_TABLES:
            maps.clear_percpu(tables[name])
        print("Contadores zerados (global_stats, fw_stats, wan_stats).")
        return

    gstats = tables["global_stats"]
    print(f"{'CONTADOR':<14} {'PKTS':<14} {'BYTES'}")
    print("-" * 44)
    for idx, label in enumerate(maps.GLOBAL_STAT_LABELS):
        pkts, byts = maps.sum_percpu(gstats, idx)
        print(f"{label:<14} {pkts:<14} {byts}")


def register(sub):
    import argparse

    p_stats = sub.add_parser(
        "stats",
        help="Contadores globais do pipeline XDP",
        description=(
            "Exibe os contadores globais do plano de dados (por evento do\n"
            "pipeline: TOTAL, ARP, FW_DROP, LAN_REDIRECT, WAN_REDIRECT,\n"
            "PASS, LB_NO_LINK). Com --reset, zera tambem fw_stats e\n"
            "wan_stats — use entre rodadas de benchmark."
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    p_stats.add_argument("--reset", action="store_true",
                         help="Zerar todos os contadores")
    p_stats.set_defaults(func=cmd_stats)
