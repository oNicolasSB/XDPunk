# XDPunk Server

Protótipo de aplicação de controle de fluxo em redes programáveis utilizando eBPF e XDP

## Visão rápida do projeto

O projeto cria um ambiente de rede virtual com namespaces Linux, carrega programas eBPF (XDP ou TC) e permite testar redirecionamento de tráfego L3 entre interfaces virtuais.

## Scripts shell (.sh)

- `scripts/install.sh`: instala dependências de compilação e execução (clang/llvm, bpftool, libbpf e Python BCC).
- `scripts/reset.sh`: remove namespaces, veths, programas anexados e limpa pins/mapas em `/sys/fs/bpf`.
- `scripts/setup_xdp_l3_static.sh`: sobe o laboratório e carrega XDP com rotas estáticas definidas no código.
- `scripts/setup_xdp_l3_dynamic.sh`: sobe o laboratório e carrega XDP com mapa `route_table` dinâmico (rotas alteráveis em runtime).
- `scripts/setup_tc_l3_static.sh`: cenário equivalente usando TC (Traffic Control) com rotas estáticas.
- `scripts/setup_tc_sw.sh`: cenário TC simplificado de switch entre namespaces.

Fluxo recomendado:
1. `sudo bash scripts/install.sh`
2. `sudo bash scripts/reset.sh`
3. `sudo bash scripts/setup_xdp_l3_dynamic.sh`

## CLI Python (`xdpunk-cli`)

A CLI em `userspace/xdpunk_cli.py` gerencia o mapa BPF pinado (`/sys/fs/bpf/xdp_fwd_maps/route_table`) sem depender de comandos `bpftool` no terminal para update/delete/consulta.

Como funciona:
- A chave do mapa é o IPv4 de destino (`u32` em network byte order).
- O valor é o `ifindex` da interface de saída.
- A CLI resolve nome de interface no namespace do switch (`--netns`, padrão `nssw`) e escreve direto no mapa via biblioteca Python/BCC.

Comandos principais:
- `xdpunk-cli map dump`: lista todas as rotas.
- `xdpunk-cli map lookup <ip>`: consulta uma rota.
- `xdpunk-cli map update <ip> <iface>`: cria/atualiza uma rota.
- `xdpunk-cli map delete <ip>`: remove uma rota.
- `xdpunk-cli map flush`: limpa toda a tabela.

Exemplos:
- `sudo xdpunk-cli map dump`
- `sudo xdpunk-cli map update 10.0.0.3 veth3s`
- `sudo xdpunk-cli map delete 10.0.0.3`
- `sudo xdpunk-cli --help`

## Trabalho de Conclusão de Curso

- Aluno:
    ## Nícolas Sanson Bassini

- Professor orientador:
    ## Dr. Rafael Silva Guimarães
- Professor coorientador:
    ## Dr. Everson Scherrer Borges

