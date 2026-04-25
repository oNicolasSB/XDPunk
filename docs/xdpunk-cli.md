# xdpunk-cli — Documentação Técnica

## Visão Geral

`xdpunk-cli` é a ferramenta de plano de controle do projeto XDPunk. Ela opera inteiramente em espaço de usuário e se comunica com o kernel Linux por meio de um mapa BPF compartilhado, permitindo gerenciar em tempo real a tabela de rotas utilizada pelo programa XDP (`xdp_forward_dynamic`) — sem necessidade de recompilar ou recarregar o programa no kernel.

O script está localizado em `userspace/xdpunk_cli.py` e é instalado como executável `xdpunk-cli` via `pyproject.toml`.

---

## Instalação

O pacote usa `setuptools` como backend de build:

```toml
# userspace/pyproject.toml
[project.scripts]
xdpunk-cli = "xdpunk_cli:main"
```

Para instalar o comando `xdpunk-cli` no sistema:

```bash
cd userspace
pip install -e .
```

Após a instalação, o comando fica disponível globalmente (requer `root` para acessar o BPF filesystem e namespaces de rede).

---

## Dependências

| Biblioteca | Uso |
|------------|-----|
| `bcc` (BCC/libbpf) | Abre e manipula mapas BPF pinados via `BPF_TABLE_PINNED` |
| `ctypes` / `ctypes.util` | Chama `setns()` da libc diretamente, sem subprocess |
| `socket` | Converte endereços IP (`inet_aton`, `inet_ntoa`, `if_nametoindex`, `if_indextoname`) |
| `struct` | Reinterpreta bytes do endereço IP entre representações |
| `argparse` | Constrói o parser de linha de comando hierárquico |
| `os` | Abre descritores de arquivo de namespaces (`/proc/self/ns/net`, `/var/run/netns/`) |

---

## Arquitetura

O script é organizado em quatro camadas independentes:

```
┌─────────────────────────────────────────────────┐
│               CLI (argparse)                    │  ← entrada do usuário
├─────────────────────────────────────────────────┤
│          Command Handlers (cmd_*)               │  ← lógica de cada subcomando
├──────────────────────┬──────────────────────────┤
│   BPF Map Helpers    │  Namespace Helpers        │  ← acesso ao kernel
│  (open_map, ip_to_* │  (_enter_netns, get_if*)  │
└──────────────────────┴──────────────────────────┘
```

- **BPF Map Helpers**: interagem com o mapa `route_table` no kernel via BCC.
- **Namespace Helpers**: entram temporariamente no namespace de rede do switch para resolver nomes de interface.
- **Command Handlers**: orquestram as duas camadas abaixo para executar cada operação.
- **CLI**: parseia argumentos e despacha para o handler correto.

---

## Constantes Globais

```python
CLONE_NEWNET = 0x40000000   # flag do syscall clone/setns para namespace de rede
DEFAULT_NETNS = "nssw"      # namespace do switch criado pelo setup script
DEFAULT_MAP_PIN = "/sys/fs/bpf/xdp_fwd_maps/route_table"  # caminho do mapa pinado
```

`CLONE_NEWNET` é a flag passada para `setns()` indicando que a troca é de namespace de rede (e não de PID, mount, etc.). Os valores padrão correspondem ao ambiente criado por `scripts/setup_xdp_l3_dynamic.sh`.

---

## BPF Map Helpers

### `open_map(map_pin_path: str)`

Abre o mapa BPF `route_table` a partir do caminho pinado no BPF filesystem.

```python
def open_map(map_pin_path: str):
    bpf_src = f'''
    BPF_TABLE_PINNED("hash", u32, u32, route_table, 256, "{map_pin_path}");
    '''
    b = BPF(text=bpf_src)
    return b, b["route_table"]
```

**Como funciona:**

- `BPF_TABLE_PINNED` é uma macro do BCC que instrui o kernel a reutilizar um mapa BPF já existente no bpffs, em vez de criar um novo.
- O tipo `"hash"` corresponde a `BPF_MAP_TYPE_HASH`, o mesmo tipo declarado no programa C.
- Os tipos de chave e valor (`u32, u32`) precisam coincidir exatamente com a declaração do mapa no kernel.
- O limite `256` é o `max_entries` do mapa — deve ser igual ao definido em `xdp_forward_dynamic.c`.
- O objeto `b["route_table"]` retornado é uma `TableBase` do BCC, que expõe uma interface de dicionário Python para o mapa do kernel.

---

### `ip_to_key(tbl, ip_str: str) → Key`

Converte um endereço IP no formato dotted-decimal (`"10.0.0.1"`) para a chave BCC que o mapa espera.

```python
def ip_to_key(tbl, ip_str: str):
    raw = socket.inet_aton(ip_str)   # 4 bytes em network byte order (big-endian)
    ip_int = struct.unpack("<I", raw)[0]  # reinterpreta como little-endian u32
    return tbl.Key(ip_int)
```

**Detalhe crítico — representação de bytes:**

`socket.inet_aton("10.0.0.1")` retorna `b'\x0a\x00\x00\x01'` (big-endian, network byte order). O BCC, porém, armazena a chave como `u32` em little-endian (byte order da CPU x86). Por isso o `struct.unpack("<I", raw)` reinterpreta os mesmos bytes como little-endian antes de passar para `tbl.Key()`. Sem essa conversão, a chave ficaria invertida e não corresponderia às entradas inseridas pelo programa XDP no kernel.

---

### `key_to_ip(key) → str`

Operação inversa: converte uma chave do mapa de volta para dotted-decimal.

```python
def key_to_ip(key) -> str:
    raw = struct.pack("<I", key.value)  # reinterpreta u32 como bytes little-endian
    return socket.inet_ntoa(raw)        # interpreta como big-endian para exibição
```

Aplica a mesma lógica de conversão no sentido inverso. `key.value` é o inteiro armazenado pelo BCC (little-endian). `struct.pack("<I", ...)` serializa de volta para os 4 bytes originais, e `inet_ntoa` converte para a string legível.

---

## Namespace Helpers

O plano de controle precisa resolver nomes de interface (ex: `"veth3s"`) para `ifindex` — um número inteiro atribuído pelo kernel a cada interface dentro de um namespace específico. Como o switch opera no namespace `nssw`, a resolução precisa acontecer dentro desse namespace.

Para isso, o processo atual troca temporariamente seu próprio namespace de rede usando o syscall `setns()`, sem criar processos filhos.

### `_setns(fd: int, nstype: int)`

Wrapper direto sobre o syscall `setns()` via `ctypes`:

```python
_libc = ctypes.CDLL(ctypes.util.find_library("c"), use_errno=True)

def _setns(fd: int, nstype: int):
    if _libc.setns(fd, nstype) == -1:
        errno = ctypes.get_errno()
        raise OSError(errno, os.strerror(errno))
```

`ctypes.util.find_library("c")` localiza a libc no sistema (ex: `libc.so.6`). `use_errno=True` permite que o errno do C seja acessível via `ctypes.get_errno()` após chamadas que falham.

---

### `_enter_netns(netns: str) → int`

Entra no namespace de rede especificado e retorna o descritor de arquivo do namespace **original** (para restauração posterior).

```python
def _enter_netns(netns: str):
    orig_fd = os.open("/proc/self/ns/net", os.O_RDONLY)  # salva namespace atual
    target_fd = os.open(f"/var/run/netns/{netns}", os.O_RDONLY)
    try:
        _setns(target_fd, CLONE_NEWNET)  # troca para o namespace alvo
    finally:
        os.close(target_fd)
    return orig_fd
```

- `/proc/self/ns/net` é o arquivo especial que representa o namespace de rede atual do processo. Ao abrir um fd para ele **antes** da troca, é possível voltar ao namespace original depois.
- `/var/run/netns/<name>` é onde o `ip netns add` registra namespaces com nome — o kernel utiliza bind mounts nesse diretório.
- O `target_fd` é fechado logo após o `setns()` pois não é mais necessário; o namespace se mantém referenciado pelo processo que está nele.

---

### `_restore_netns(orig_fd: int)`

Restaura o namespace original e fecha o fd salvo:

```python
def _restore_netns(orig_fd: int):
    try:
        _setns(orig_fd, CLONE_NEWNET)
    finally:
        os.close(orig_fd)
```

O bloco `finally` garante que o fd seja fechado mesmo se o `setns()` falhar, evitando vazamento de descritores.

---

### `get_ifindex(iface: str, netns: str) → int`

Resolve nome de interface para `ifindex` dentro do namespace indicado:

```python
def get_ifindex(iface: str, netns: str) -> int:
    orig_fd = _enter_netns(netns)
    try:
        return socket.if_nametoindex(iface)
    except OSError:
        print(f"Erro: interface '{iface}' nao encontrada no namespace '{netns}'.")
        sys.exit(1)
    finally:
        _restore_netns(orig_fd)
```

`socket.if_nametoindex()` chama o syscall `if_nametoindex` que consulta o kernel pelo índice da interface **no namespace atual do processo**. Por isso a troca de namespace antes da chamada é obrigatória — chamar isso no namespace padrão retornaria o ifindex errado (ou falharia se a interface não existisse lá).

---

### `get_ifname(ifindex: int, netns: str) → str`

Operação inversa: resolve `ifindex` para nome de interface:

```python
def get_ifname(ifindex: int, netns: str) -> str:
    orig_fd = _enter_netns(netns)
    try:
        return socket.if_indextoname(ifindex)
    except OSError:
        return f"?(ifindex={ifindex})"  # fallback caso a interface não exista mais
    finally:
        _restore_netns(orig_fd)
```

O fallback `?(ifindex=N)` é usado no `cmd_dump` para o caso onde uma rota aponta para um ifindex de uma interface que foi removida — evita que um erro interrompa a listagem completa.

---

## Command Handlers

Cada subcomando da CLI tem um handler dedicado. Todos recebem o objeto `args` do argparse (com os campos `args.map_pin`, `args.netns`, e os argumentos posicionais do subcomando).

### `cmd_update(args)` — Inserir ou Atualizar Rota

```python
def cmd_update(args):
    _, tbl = open_map(args.map_pin)
    key = ip_to_key(tbl, args.ip)
    ifidx = get_ifindex(args.iface, args.netns)
    tbl[key] = tbl.Leaf(ifidx)
    print(f"Rota atualizada: {args.ip} -> {args.iface} (ifindex={ifidx})")
```

**Fluxo:**
1. Abre o mapa BPF via BCC.
2. Converte o IP destino para chave u32.
3. Resolve o nome da interface para ifindex dentro do namespace do switch.
4. Insere/sobrescreve a entrada no mapa com `tbl[key] = tbl.Leaf(ifidx)`.

A atribuição via `[]` no objeto `TableBase` do BCC mapeia para `bpf_map_update_elem()` no kernel, com flag `BPF_ANY` (insert or update). A mudança é imediatamente visível para o programa XDP em execução.

---

### `cmd_delete(args)` — Remover Rota

```python
def cmd_delete(args):
    _, tbl = open_map(args.map_pin)
    key = ip_to_key(tbl, args.ip)
    try:
        del tbl[key]
    except KeyError:
        print(f"Erro: rota para {args.ip} nao encontrada.")
        sys.exit(1)
    print(f"Rota removida: {args.ip}")
```

`del tbl[key]` invoca `bpf_map_delete_elem()`. Se a chave não existir, o BCC lança `KeyError`, que é capturado para exibir uma mensagem de erro legível.

---

### `cmd_lookup(args)` — Consultar Rota

```python
def cmd_lookup(args):
    _, tbl = open_map(args.map_pin)
    key = ip_to_key(tbl, args.ip)
    try:
        leaf = tbl[key]
    except KeyError:
        print(f"Rota para {args.ip} nao encontrada.")
        sys.exit(1)
    ifidx = leaf.value
    ifname = get_ifname(ifidx, args.netns)
    print(f"{args.ip} -> {ifname} (ifindex={ifidx})")
```

`tbl[key]` chama `bpf_map_lookup_elem()`. O `leaf.value` extrai o inteiro `u32` armazenado (o ifindex). Em seguida, `get_ifname` resolve o número para o nome da interface para exibição humana.

---

### `cmd_dump(args)` — Listar Todas as Rotas

```python
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
```

`tbl.items()` itera sobre todas as entradas do mapa via `bpf_map_get_next_key()` + `bpf_map_lookup_elem()`. A listagem é materializada em memória (`list(...)`) antes da iteração de exibição para evitar problemas com modificações concorrentes durante a iteração.

---

### `cmd_flush(args)` — Limpar Todas as Rotas

```python
def cmd_flush(args):
    _, tbl = open_map(args.map_pin)
    entries = list(tbl.keys())
    if not entries:
        print("Tabela ja esta vazia.")
        return
    for key in entries:
        del tbl[key]
    print(f"{len(entries)} rota(s) removida(s).")
```

As chaves são coletadas primeiro (`list(tbl.keys())`) para evitar modificação do mapa durante a iteração. Depois, cada entrada é deletada individualmente — o BPF não oferece uma operação de "flush atômico" nativa para hashmaps.

---

## CLI (argparse)

### Hierarquia de Subcomandos

```
xdpunk-cli [--netns NAME] [--map-pin PATH]
    map
        update  <ip> <iface>
        delete  <ip>
        lookup  <ip>
        dump
        flush
```

O grupo `map` é o único grupo de subcomandos atualmente. A estrutura foi projetada para permitir adição de outros grupos (ex: `stats`, `debug`) sem conflito.

### Opções Globais

| Opção | Padrão | Descrição |
|-------|--------|-----------|
| `--netns NAME` | `nssw` | Namespace de rede do switch para resolução de interfaces |
| `--map-pin PATH` | `/sys/fs/bpf/xdp_fwd_maps/route_table` | Caminho do mapa BPF no bpffs |

Essas opções são globais (definidas no parser raiz) e ficam disponíveis em todos os subcomandos via `args.netns` e `args.map_pin`.

### Despacho de Subcomandos

```python
def main():
    parser = build_parser()
    args = parser.parse_args()
    args.func(args)
```

Cada subcomando registra seu handler com `set_defaults(func=cmd_*)`. Após o parse, `args.func` já aponta para o handler correto — o `main()` apenas o invoca.

---

## Fluxo Completo de uma Operação

Exemplo: `sudo xdpunk-cli map update 10.0.0.3 veth3s`

```
1. argparse parseia → args.ip="10.0.0.3", args.iface="veth3s",
                       args.netns="nssw", args.map_pin=DEFAULT_MAP_PIN
                       args.func = cmd_update

2. cmd_update():
   ├─ open_map(DEFAULT_MAP_PIN)
   │    └─ BCC compila BPF_TABLE_PINNED e anexa ao mapa existente no kernel
   ├─ ip_to_key(tbl, "10.0.0.3")
   │    ├─ inet_aton("10.0.0.3") → b'\x0a\x00\x00\x03'
   │    ├─ struct.unpack("<I", ...) → 0x0300000a (little-endian u32)
   │    └─ tbl.Key(0x0300000a)
   ├─ get_ifindex("veth3s", "nssw")
   │    ├─ _enter_netns("nssw") → salva fd do namespace atual, entra em nssw
   │    ├─ socket.if_nametoindex("veth3s") → ex: 5
   │    └─ _restore_netns(orig_fd) → volta ao namespace original
   └─ tbl[key] = tbl.Leaf(5)
        └─ bpf_map_update_elem(map_fd, &key, &5, BPF_ANY) [syscall no kernel]
```

Após a etapa final, o programa XDP rodando no kernel já enxerga a nova entrada — não há delay, buffer, ou necessidade de sinalização adicional.

---

## Considerações de Segurança e Privilégios

- O script requer `root` (ou `CAP_SYS_ADMIN` + `CAP_NET_ADMIN`) porque:
  - Acesso ao BPF filesystem (`/sys/fs/bpf/`) exige `CAP_SYS_ADMIN`.
  - Trocar de namespace de rede com `setns()` exige `CAP_SYS_ADMIN`.
  - `socket.if_nametoindex()` dentro de um namespace externo depende dos privilégios de entrada nele.
- O mapa BPF aceita no máximo 256 entradas (`max_entries`). Tentativas de inserção além desse limite falharão com `ENOMEM` no lado do kernel.
