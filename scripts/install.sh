#!/bin/bash
sudo apt install -y clang
sudo apt install -y gcc-multilib
sudo apt install -y linux-headers-$(uname -r) build-essential clang llvm
sudo apt install -y libbpf-dev bpftool linux-libc-dev
