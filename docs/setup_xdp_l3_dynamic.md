# setup_xdp_l3_dynamic.sh — Documentação Técnica

## Visão Geral

`scripts/setup_xdp_l3_dynamic.sh` é o script de inicialização do ambiente de laboratório virtual do XDPunk. Ele constrói do zero uma topologia de rede isolada usando namespaces Linux, compila o programa XDP em bytecode eBPF, carrega esse programa no kernel e popula a tabela de rotas inicial no mapa BPF — deixando o switch L3 pronto para encaminhar pacotes em espaço de kernel via XDP.

Toda a cadeia de setup é executada como uma única transação: um trap em `EXIT` garante limpeza automática se qualquer etapa falhar.

---

## Topologia Criada

```
  ┌──────────┐        ┌───────────────────────────────────┐        ┌──────────┐
  │   ns1    │        │              nssw                 │        │   ns2    │
  │          │        │  ┌─────────┐       ┌─────────┐    │        │          │
  │ veth1h   ├────────┤  │ veth1s  │       │ veth2s  │    ├────────┤ veth2h   │
  │10.0.0.1  │        │  └─────────┘       └─────────┘    │        │10.0.0.2  │
  └──────────┘        │        XDP: xdp_forward_dynamic   │        └──────────┘
                      │       ┌─────────┐                 │
  ┌──────────┐        │       │ veth3s  │                 │
  │   ns3    │        │       └─────────┘                 │
  │          ├────────┤                                   │
  │ veth3h   │        └───────────────────────────────────┘
  │10.0.0.3  │
  └──────────┘
```

Quatro namespaces de rede isolados. Três pares veth conectam os hosts ao switch. O programa XDP roda em cada interface do lado do switch (`veth1s`, `veth2s`, `veth3s`).

---

## Pré-requisitos Verificados

```bash
need_cmd ip
need_cmd clang
need_cmd bpftool
need_cmd nsenter
```

A função `need_cmd` verifica se cada binário está no `PATH` antes de qualquer operação destrutiva. Falha imediatamente com mensagem de erro se algum estiver ausente.

---

## Variáveis de Configuração

| Variável | Valor | Descrição |
|----------|-------|-----------|
| `NS1`, `NS2`, `NS3` | `ns1`, `ns2`, `ns3` | Namespaces dos hosts |
| `NSSW` | `nssw` | Namespace do switch |
| `VETH1H`/`VETH1S` | `veth1h`/`veth1s` | Par veth do host 1 (H=host, S=switch) |
| `VETH2H`/`VETH2S` | `veth2h`/`veth2s` | Par veth do host 2 |
| `VETH3H`/`VETH3S` | `veth3h`/`veth3s` | Par veth do host 3 |
| `IP1`, `IP2`, `IP3` | `10.0.0.1/24`… | Endereços dos hosts |
| `BPF_PIN` | `/sys/fs/bpf/xdp_fwd` | Caminho de pin do programa XDP |
| `BPF_MAP_DIR` | `/sys/fs/bpf/xdp_fwd_maps` | Diretório onde os mapas são pinados |
| `XDP_SRC` | `../xdp/xdp_forward_dynamic.c` | Fonte C do programa XDP |
| `XDP_OBJ` | `/tmp/xdp_forward_dynamic.o` | Bytecode compilado (temporário) |

O caminho do fonte é resolvido relativamente ao diretório do próprio script via `SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"`, garantindo que o script funcione independente do diretório de trabalho atual.

---

## Opções de Shell

```bash
set -euo pipefail
```

- `-e`: aborta na primeira falha de comando (exit code ≠ 0).
- `-u`: trata variáveis não definidas como erro.
- `-o pipefail`: propaga falhas dentro de pipelines (o exit code do pipe é o do primeiro comando que falhou).

---

## Funções Auxiliares

### `need_cmd <comando>`

```bash
need_cmd() {
  command -v "$1" >/dev/null 2>&1 || {
    echo "ERRO: comando '$1' nao encontrado."
    exit 1
  }
}
```

Verifica existência de um binário no `PATH`. `command -v` é preferível a `which` por ser um builtin POSIX, sem dependências externas.

---

### `le32 <inteiro>`

```bash
le32() {
  printf '%02x %02x %02x %02x' \
    $(($1 & 0xff)) \
    $((($1 >> 8) & 0xff)) \
    $((($1 >> 16) & 0xff)) \
    $((($1 >> 24) & 0xff))
}
```

Converte um inteiro para sua representação hexadecimal em **little-endian** de 4 bytes, separada por espaços — o formato que `bpftool map update key hex ... value hex ...` espera.

**Por que little-endian:** o mapa BPF armazena o `ifindex` como `__u32` em little-endian (byte order da CPU x86/x86-64). Ao inserir via `bpftool hex`, os bytes são escritos diretamente na memória do mapa na ordem fornecida. Sem essa conversão, o valor seria interpretado pelo programa XDP como um ifindex com bytes invertidos — causando redirecionamento para a interface errada ou retornando `XDP_PASS` (ifindex não encontrado).

**Exemplo:** ifindex `5` (0x00000005) → `le32 5` → `"05 00 00 00"`.

---

### `cleanup()`

```bash
cleanup() {
  set +e
  for dev in "$VETH1S" "$VETH2S" "$VETH3S"; do
    ip -n "$NSSW" link set dev "$dev" xdpgeneric off 2>/dev/null || true
  done
  rm -f "$BPF_PIN"
  rm -rf "$BPF_MAP_DIR"
  ip netns del "$NS1" 2>/dev/null
  ip netns del "$NS2" 2>/dev/null
  ip netns del "$NS3" 2>/dev/null
  ip netns del "$NSSW" 2>/dev/null
  rm -f "$XDP_OBJ"
}
trap cleanup EXIT
```

Registrada no trap `EXIT`, essa função é chamada automaticamente **sempre que o script termina** — seja por erro em qualquer etapa, seja por conclusão normal.

**`set +e` dentro do cleanup:** desabilita o `-e` herdado para que falhas nas operações de limpeza (ex: namespace já inexistente) não interrompam as demais. Cada comando usa `2>/dev/null || true` pelo mesmo motivo.

**Ao final do script**, o trap é explicitamente removido com `trap - EXIT`. Isso evita que o cleanup seja executado novamente após a conclusão bem-sucedida — que destruiria o ambiente que acabou de ser criado.

---

## Passo a Passo

### [1/7] Criando Namespaces

```bash
ip netns add "$NS1"
ip netns add "$NS2"
ip netns add "$NS3"
ip netns add "$NSSW"
```

`ip netns add` cria um namespace de rede isolado e registra um bind mount em `/var/run/netns/<name>`. Esse arquivo é o que permite que outros processos entrem no namespace via `setns()` ou `nsenter` usando o caminho `/var/run/netns/<name>`.

Cada namespace possui suas próprias interfaces, tabelas de roteamento, regras iptables e sockets — completamente isolados do namespace raiz e entre si.

---

### [2/7] Criando Veth Pairs

```bash
ip link add "$VETH1H" type veth peer name "$VETH1S"
ip link add "$VETH2H" type veth peer name "$VETH2S"
ip link add "$VETH3H" type veth peer name "$VETH3S"

ip link set "$VETH1H" netns "$NS1"
ip link set "$VETH2H" netns "$NS2"
ip link set "$VETH3H" netns "$NS3"

ip link set "$VETH1S" netns "$NSSW"
ip link set "$VETH2S" netns "$NSSW"
ip link set "$VETH3S" netns "$NSSW"
```

Um par veth funciona como um cabo de rede virtual: tudo o que entra em uma ponta sai pela outra. Os pares são criados no namespace raiz e em seguida movidos para os namespaces corretos com `ip link set ... netns`.

Após a movimentação:
- `veth1h`, `veth2h`, `veth3h` existem nos respectivos namespaces de host.
- `veth1s`, `veth2s`, `veth3s` existem no namespace do switch `nssw`.

---

### [3/7] Subindo Interfaces

```bash
for ns in "$NS1" "$NS2" "$NS3" "$NSSW"; do
  ip -n "$ns" link set lo up
done

ip -n "$NS1" addr add "$IP1" dev "$VETH1H"
# ... (NS2, NS3 analogamente)

ip -n "$NS1" link set "$VETH1H" up
# ... (NS2, NS3, NSSW analogamente)
```

A flag `-n <namespace>` do `ip` é equivalente a `ip netns exec <namespace> ip ...`, mas sem criar um processo filho separado — mais eficiente. Interfaces recém-criadas começam no estado `DOWN`; `link set ... up` as ativa.

O loopback (`lo`) de cada namespace também é ativado — necessário para comunicação interna ao namespace e para o funcionamento correto da pilha TCP/IP.

**Importante:** o namespace `nssw` (switch) **não recebe endereço IP** em suas interfaces. Ele opera puramente em L2/L3 no plano de dados XDP, sem pilha IP própria nessas interfaces — endereços IPs nos hosts são suficientes para roteamento.

---

### [4/7] Compilando o Programa eBPF

```bash
clang -O2 -g -target bpf \
  -c "$XDP_SRC" -o "$XDP_OBJ"
```

| Flag | Significado |
|------|-------------|
| `-O2` | Otimização necessária — o verificador eBPF rejeita código não otimizado com loops ou redundâncias que ele não consegue provar que terminam |
| `-g` | Inclui informações de debug BTF (BPF Type Format) no objeto, usadas pelo `bpftool` para exibir nomes de campos e tipos |
| `-target bpf` | Instrui o LLVM a gerar bytecode eBPF em vez de código nativo x86 |
| `-c` | Compila apenas (sem linkar) — programas eBPF não têm main nem linker convencional |

O arquivo resultante `xdp_forward_dynamic.o` é um ELF padrão com seções especiais:
- `xdp`: contém o bytecode da função `xdp_forward`.
- `.maps`: descreve o mapa `route_table`.
- `license`: contém a string `"GPL"`, obrigatória para usar helpers do kernel como `bpf_redirect`.

---

### [5/7] Descobrindo ifindex

```bash
IF1=$(ip netns exec "$NSSW" cat /sys/class/net/"$VETH1S"/ifindex)
IF2=$(ip netns exec "$NSSW" cat /sys/class/net/"$VETH2S"/ifindex)
IF3=$(ip netns exec "$NSSW" cat /sys/class/net/"$VETH3S"/ifindex)
```

O `ifindex` é um identificador inteiro único que o kernel atribui a cada interface dentro de um namespace. Ele é **namespace-específico**: a mesma interface física tem ifindex diferentes em namespaces diferentes.

A leitura é feita via `/sys/class/net/<iface>/ifindex` dentro do namespace `nssw` (usando `ip netns exec`) porque é lá que as interfaces `vethXs` residem. Esses valores são usados no passo 7 para popular o mapa BPF.

---

### [6/7] Carregando e Anexando o Programa XDP

#### Montagem do bpffs

```bash
if ! mountpoint -q /sys/fs/bpf 2>/dev/null; then
  mount -t bpf bpf /sys/fs/bpf/
fi
```

O BPF filesystem (`bpffs`) é um pseudo-sistema de arquivos do kernel que permite "pinar" objetos BPF (programas e mapas) como arquivos, mantendo-os vivos além do processo que os criou. Em sistemas modernos ele já é montado automaticamente pelo systemd, mas o check garante compatibilidade com ambientes mínimos.

#### Carregamento e Pin do Programa

```bash
bpftool prog load "$XDP_OBJ" "$BPF_PIN" pinmaps "$BPF_MAP_DIR"
```

Este único comando faz três coisas:

1. **Carrega** o bytecode eBPF no kernel via `bpf(BPF_PROG_LOAD, ...)` — o verificador do kernel valida o programa neste momento.
2. **Pina o programa** em `$BPF_PIN` (`/sys/fs/bpf/xdp_fwd`) — cria um arquivo no bpffs que mantém uma referência ao programa carregado. Sem isso, o programa seria destruído ao fechar o fd.
3. **Pina os mapas** automaticamente em `$BPF_MAP_DIR` (`/sys/fs/bpf/xdp_fwd_maps/`) — o `bpftool` cria um arquivo por mapa declarado no objeto (neste caso, `route_table`).

O resultado em disco:
```
/sys/fs/bpf/
├── xdp_fwd                          ← programa XDP pinado
└── xdp_fwd_maps/
    └── route_table                  ← mapa BPF pinado
```

#### Anexo às Interfaces do Switch

```bash
for dev in "$VETH1S" "$VETH2S" "$VETH3S"; do
  nsenter --net=/var/run/netns/"$NSSW" \
    ip link set dev "$dev" xdpgeneric pinned "$BPF_PIN"
done
```

**Por que `nsenter` e não `ip netns exec`:**

`ip netns exec` cria um processo filho que entra no namespace de rede **e também troca o mount namespace** para um namespace privado, isolando o bpffs. Nesse contexto, `/sys/fs/bpf/xdp_fwd` (do namespace raiz) ficaria inacessível.

`nsenter --net=...` faz apenas `setns(CLONE_NEWNET)` — troca somente o namespace de rede, mantendo o mount namespace do processo pai. Assim, o pin em `/sys/fs/bpf/` permanece visível e o `ip link set ... xdpgeneric pinned` consegue referenciar o programa.

**`xdpgeneric`** é o modo de operação XDP que executa o programa na camada de socket do kernel (após o driver), sem exigir suporte nativo do driver de rede. É o modo correto para interfaces virtuais como veth, que não suportam XDP nativo.

---

### [7/7] Populando a Tabela de Rotas

```bash
bpftool map update pinned "$BPF_MAP_DIR/route_table" \
  key hex 0a 00 00 01 value hex $(le32 "$IF1")

bpftool map update pinned "$BPF_MAP_DIR/route_table" \
  key hex 0a 00 00 02 value hex $(le32 "$IF2")

bpftool map update pinned "$BPF_MAP_DIR/route_table" \
  key hex 0a 00 00 03 value hex $(le32 "$IF3")
```

#### Representação das Chaves (IP)

O mapa BPF armazena o IP destino como `__u32` em **network byte order (big-endian)**, conforme declarado em `xdp_forward_dynamic.c`:

```c
__type(key, __u32); /* IP destino (network byte order) */
```

O `bpftool hex` escreve bytes na ordem fornecida diretamente na memória. Portanto, `10.0.0.1` é inserido como `0a 00 00 01` — que em memória é `0x0a, 0x00, 0x00, 0x01`, correspondendo ao big-endian de `10.0.0.1`.

| IP | Hex big-endian (chave) |
|----|------------------------|
| `10.0.0.1` | `0a 00 00 01` |
| `10.0.0.2` | `0a 00 00 02` |
| `10.0.0.3` | `0a 00 00 03` |

#### Representação dos Valores (ifindex)

O mapa armazena o ifindex como `__u32` em **little-endian** (byte order da CPU). `le32 $IFx` gera os 4 bytes na ordem correta. Se o ifindex do `veth1s` for `5`:

```
$(le32 5)  →  "05 00 00 00"
```

Bpftool insere esses bytes diretamente, e o kernel os interpreta como `uint32_t` little-endian = `5`.

---

## Relação com o Programa XDP

O script e o programa C (`xdp_forward_dynamic.c`) compartilham estado exclusivamente via o mapa BPF pinado. O programa XDP acessa o mapa pelo símbolo `route_table` resolvido em tempo de load; o script e o `xdpunk-cli` acessam pelo caminho `/sys/fs/bpf/xdp_fwd_maps/route_table`. Ambos referenciam o mesmo objeto no kernel.

Quando o programa XDP processa um pacote:

```c
__u32 *ifidx = bpf_map_lookup_elem(&route_table, &lookup_ip);
if (!ifidx)
    return XDP_PASS;
return bpf_redirect(*ifidx, 0);
```

O `lookup_ip` é o `daddr` do cabeçalho IP — já em network byte order. A chave inserida pelo script também está em network byte order (`0a 00 00 01`). A correspondência é direta, sem conversão no caminho crítico do kernel.

---

## Diagrama do Fluxo Completo

```
setup_xdp_l3_dynamic.sh
│
├─ [1/7] ip netns add (×4)
│         └─ cria bind mounts em /var/run/netns/
│
├─ [2/7] ip link add veth peer + ip link set netns
│         └─ distribui extremidades dos pares nos namespaces corretos
│
├─ [3/7] ip addr add + ip link set up (dentro de cada ns)
│         └─ ativa interfaces e atribui IPs aos hosts
│
├─ [4/7] clang -target bpf
│         └─ gera ELF com bytecode eBPF + BTF + declaração do mapa
│
├─ [5/7] cat /sys/class/net/vethXs/ifindex (dentro de nssw)
│         └─ obtém ifindex reais das interfaces do switch
│
├─ [6/7] bpftool prog load ... pinmaps
│         ├─ verifica e carrega o programa no kernel
│         ├─ pina programa em /sys/fs/bpf/xdp_fwd
│         └─ pina mapa em /sys/fs/bpf/xdp_fwd_maps/route_table
│
│         nsenter --net + ip link set xdpgeneric pinned (×3)
│         └─ anexa o programa às interfaces veth1s, veth2s, veth3s
│
└─ [7/7] bpftool map update (×3)
          └─ insere IP→ifindex no mapa BPF (efeito imediato no plano de dados)
```

---

## Limpeza — reset.sh

`scripts/reset.sh` desfaz todas as etapas acima em ordem inversa segura:

1. Remove XDP e filtros TC das interfaces do switch.
2. Deleta os quatro namespaces (`ip netns del`) — o kernel automaticamente destrói as interfaces dentro deles.
3. Remove veths residuais no namespace raiz (caso algum não tenha sido movido).
4. Remove XDP de interfaces no namespace raiz (limpeza de execuções anteriores).
5. Apaga pins BPF em `/sys/fs/bpf/xdp_fwd_maps/` e arquivos temporários em `/tmp/`.
6. Exibe programas e mapas BPF restantes via `bpftool` (informativo).

Cada operação usa `|| true` para ser idempotente — pode ser executado mesmo com o ambiente parcialmente destruído ou nunca inicializado.
