#!/bin/bash
set -e

# Diretório raiz do repositório (independente de onde o script é chamado)
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_DIR="$(dirname "$SCRIPT_DIR")"

sudo apt update
sudo apt install -y clang
sudo apt install -y gcc-multilib
sudo apt install -y linux-headers-$(uname -r) build-essential clang llvm
sudo apt install -y libbpf-dev linux-libc-dev
sudo apt install -y python3-bpfcc python3-pip python3-venv pipx
# Fase 2: benchmarks (iperf3), parsing de JSON (jq), offloads (ethtool)
sudo apt install -y iperf3 jq ethtool

# ---------------------------------------------------------------------------
# bpftool: no Ubuntu 24.04 (noble) é um pacote virtual, fornecido por
# linux-tools-*. Tentamos, em ordem: o pacote da versão do kernel em execução,
# o metapacote genérico e, por fim, o wrapper comum. Não abortamos se algum
# candidato não existir (kernels HWE nem sempre têm linux-tools casado).
# ---------------------------------------------------------------------------
echo "==> Instalando bpftool (via linux-tools)"
sudo apt install -y "linux-tools-$(uname -r)" \
    || sudo apt install -y linux-tools-generic linux-tools-common \
    || echo "AVISO: não foi possível instalar bpftool via apt; instale manualmente se necessário."

if command -v bpftool >/dev/null 2>&1; then
    echo "==> bpftool disponível: $(command -v bpftool)"
else
    echo "AVISO: 'bpftool' não está no PATH. Verifique 'linux-tools-*' para o seu kernel ($(uname -r))."
fi

# ---------------------------------------------------------------------------
# Instalação do CLI de plano de controle (xdpunk-cli)
#
# Distros com Python 3.11+ (PEP 668) marcam o ambiente como
# "externally-managed" e bloqueiam `pip install` system-wide. Além disso, o
# CLI depende de `bcc` (python3-bpfcc), instalado via apt e ausente no PyPI —
# por isso a instalação precisa enxergar os pacotes do sistema
# (--system-site-packages). Usamos pipx para gerenciar o venv e expor o
# comando `xdpunk-cli` globalmente.
# ---------------------------------------------------------------------------
export PIPX_HOME=/opt/pipx
export PIPX_BIN_DIR=/usr/local/bin

echo "==> Instalando xdpunk-cli via pipx (com acesso aos pacotes do sistema)"
sudo env PIPX_HOME="$PIPX_HOME" PIPX_BIN_DIR="$PIPX_BIN_DIR" \
    pipx install --force --system-site-packages "$REPO_DIR/userspace"

echo
echo "==> xdpunk-cli instalado. Verifique com: sudo xdpunk-cli --help"
