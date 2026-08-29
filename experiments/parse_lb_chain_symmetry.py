#!/usr/bin/env python3
"""parse_lb_chain_symmetry.py — deriva a taxa de simetria ida/volta a
partir de capturas tcpdump (`-n -tt`) feitas em R2 e R3 na topologia
encadeada (ver experiments/capture_lb_chain_symmetry.sh).

Cada fluxo e identificado pela porta de origem do lado A (fixada por
fluxo via `iperf3 --cport`). Uma linha com src=A_IP indica que o
roteador dessa captura foi escolhido por R1 (ida); uma linha com
src=B_IP indica que foi escolhido por R4 (volta) — o dst-port dessa
linha e a porta que identifica o fluxo.
"""
import re
import sys

LINE_RE = re.compile(
    r"IP (?P<src>\d+\.\d+\.\d+\.\d+)\.(?P<sport>\d+) > "
    r"(?P<dst>\d+\.\d+\.\d+\.\d+)\.(?P<dport>\d+):"
)


def parse_capture(path, a_ip, b_ip, router_name, forward, reverse):
    with open(path) as f:
        for line in f:
            m = LINE_RE.search(line)
            if not m:
                continue
            src, sport, dport = m["src"], int(m["sport"]), int(m["dport"])
            if src == a_ip:
                forward.setdefault(sport, router_name)
            elif src == b_ip:
                reverse.setdefault(dport, router_name)


def compute_symmetry(forward, reverse):
    flows = sorted(set(forward) & set(reverse))
    if not flows:
        return flows, 0, 0.0
    symmetric = sum(1 for p in flows if forward[p] == reverse[p])
    return flows, symmetric, symmetric / len(flows)


def _selftest():
    import tempfile
    from pathlib import Path

    a_ip, b_ip = "10.10.1.1", "10.10.2.1"
    with tempfile.TemporaryDirectory() as d:
        r2 = Path(d) / "r2.txt"
        r3 = Path(d) / "r3.txt"
        # Fluxo 10001: ida por R2 (src=A), volta por R2 (src=B, dport=10001) -> simetrico.
        # Fluxo 10002: ida por R2 (src=A), sem linha de volta em nenhum arquivo -> ignorado.
        r2.write_text(
            "1.0 IP 10.10.1.1.10001 > 10.10.2.1.5201: Flags [S]\n"
            "2.0 IP 10.10.2.1.5201 > 10.10.1.1.10001: Flags [S.]\n"
            "3.0 IP 10.10.1.1.10002 > 10.10.2.1.5201: Flags [S]\n"
        )
        # Fluxo 10003: ida por R3 (src=A em r3.txt), volta por R2 (src=B em r2.txt) -> assimetrico.
        r2.write_text(r2.read_text() +
                       "4.0 IP 10.10.2.1.5201 > 10.10.1.1.10003: Flags [S.]\n")
        r3.write_text(
            "5.0 IP 10.10.1.1.10003 > 10.10.2.1.5201: Flags [S]\n"
        )

        forward, reverse = {}, {}
        parse_capture(str(r2), a_ip, b_ip, "R2", forward, reverse)
        parse_capture(str(r3), a_ip, b_ip, "R3", forward, reverse)

        flows, symmetric, rate = compute_symmetry(forward, reverse)
        assert flows == [10001, 10003], flows
        assert symmetric == 1, symmetric
        assert rate == 0.5, rate
    print("selftest OK")


def main():
    if len(sys.argv) == 2 and sys.argv[1] == "--selftest":
        _selftest()
        return

    if len(sys.argv) != 5:
        print(f"Uso: {sys.argv[0]} <r2.txt> <r3.txt> <A_IP> <B_IP>",
              file=sys.stderr)
        sys.exit(1)

    r2_file, r3_file, a_ip, b_ip = sys.argv[1:5]
    forward, reverse = {}, {}
    parse_capture(r2_file, a_ip, b_ip, "R2", forward, reverse)
    parse_capture(r3_file, a_ip, b_ip, "R3", forward, reverse)

    flows, symmetric, rate = compute_symmetry(forward, reverse)
    if not flows:
        print("Nenhum fluxo com ida E volta capturadas — nada a calcular.")
        sys.exit(1)

    print(f"{'PORTA':<8} {'IDA (R1)':<10} {'VOLTA (R4)':<10} {'SIMETRICO'}")
    for p in flows:
        print(f"{p:<8} {forward[p]:<10} {reverse[p]:<10} "
              f"{'sim' if forward[p] == reverse[p] else 'nao'}")
    print()
    print(f"Fluxos observados (ida e volta capturadas): {len(flows)}")
    print(f"Taxa de simetria observada: {rate:.4f} ({symmetric}/{len(flows)})")


if __name__ == "__main__":
    main()
