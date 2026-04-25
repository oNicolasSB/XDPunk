# xdp_forward_dynamic.c — Documentação Técnica

## Visão Geral

`xdp/xdp_forward_dynamic.c` é o programa do plano de dados do XDPunk. Ele roda diretamente no kernel Linux como um programa eBPF do tipo XDP (_eXpress Data Path_), sendo invocado para cada pacote que chega em uma das interfaces do switch virtual antes mesmo que a pilha de rede do kernel o processe.

Sua função é simples e deliberadamente mínima: extrair o IP destino do pacote, consultar o mapa BPF `route_table`, e redirecionar o pacote para a interface de saída correspondente — tudo em espaço de kernel, sem cópias, sem contexto de usuário.

---

## Posição no Pipeline de Rede

```
  NIC / veth
      │
      ▼
 ┌──────────────────────────────────────┐
 │  XDP hook  ← xdp_forward() roda aqui │  ← antes do sk_buff, antes do netif_receive_skb
 └──────────────────────────────────────┘
      │ XDP_REDIRECT  ─────────────────────────► interface de saída
      │ XDP_PASS      ─────────────────────────► pilha TCP/IP normal do kernel
```

No modo `xdpgeneric` (usado neste projeto), o hook ocorre na camada de socket do kernel, após o driver de rede, mas ainda antes do processamento da pilha IP. Em NIC com suporte nativo, o hook ocorreria diretamente no driver — ainda mais cedo.

---

## Includes e Dependências

```c
#include <linux/bpf.h>        // tipos e constantes BPF (XDP_PASS, XDP_REDIRECT, ...)
#include <linux/if_ether.h>   // struct ethhdr, ETH_P_IP, ETH_P_ARP
#include <linux/ip.h>         // struct iphdr (cabeçalho IPv4)
#include <linux/if_arp.h>     // ETH_P_ARP (identificação do protocolo ARP)
#include <bpf/bpf_helpers.h>  // SEC(), bpf_redirect(), bpf_map_lookup_elem()
#include <bpf/bpf_endian.h>   // bpf_htons() — conversão de byte order portável
```

Os headers `linux/` vêm do kernel e definem estruturas de pacote em memória. Os headers `bpf/` vêm da libbpf e expõem helpers e macros específicos do ambiente eBPF.

---

## Mapa BPF — `route_table`

```c
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 256);
    __type(key, __u32);   /* IP destino (network byte order) */
    __type(value, __u32); /* ifindex da interface de saída   */
} route_table SEC(".maps");
```

### Tipo e Capacidade

`BPF_MAP_TYPE_HASH` é uma tabela hash no kernel com complexidade de busca O(1). O limite de `256` entradas é suficiente para a topologia de laboratório e é declarado em tempo de compilação — o kernel aloca recursos para esse máximo na carga do programa.

### Semântica da Chave

A chave é um `__u32` contendo o IP destino em **network byte order (big-endian)**, exatamente como ele aparece no cabeçalho IPv4 no fio. Isso elimina qualquer conversão no caminho crítico: `iph->daddr` é lido diretamente do pacote e usado como chave sem transformação.

### Semântica do Valor

O valor é o `ifindex` da interface de saída — um inteiro `__u32` que o kernel usa internamente para identificar interfaces dentro de um namespace. `bpf_redirect(ifindex, 0)` recebe esse valor diretamente.

### Seção `.maps`

A macro `SEC(".maps")` instrui o compilador a colocar esse objeto em uma seção ELF especial. Quando `bpftool prog load` processa o arquivo `.o`, ele lê essa seção para criar o mapa no kernel e reescrever as referências ao símbolo `route_table` no bytecode com o fd real do mapa.

---

## Ponto de Entrada — `xdp_forward`

```c
SEC("xdp")
int xdp_forward(struct xdp_md *ctx)
```

`SEC("xdp")` coloca a função na seção `xdp` do ELF, identificando-a como um programa XDP para o kernel. O nome `xdp_forward` é arbitrário; o que determina o tipo do programa é a seção.

`struct xdp_md` é o contexto passado pelo kernel ao programa. Seus campos relevantes:

| Campo | Tipo | Descrição |
|-------|------|-----------|
| `ctx->data` | `__u32` | Ponteiro (como inteiro) para o início do pacote na memória |
| `ctx->data_end` | `__u32` | Ponteiro para o byte após o fim do pacote |

---

## Fluxo de Processamento

### 1. Acesso ao Buffer do Pacote

```c
void *data     = (void *)(long)ctx->data;
void *data_end = (void *)(long)ctx->data_end;
```

O cast `(void *)(long)` é necessário porque `ctx->data` e `ctx->data_end` são `__u32` (ponteiros como inteiros de 32 bits no contexto BPF), mas ponteiros em C são 64 bits em arquiteturas modernas. O cast via `long` evita truncamento.

### 2. Validação do Cabeçalho Ethernet

```c
struct ethhdr *eth = data;
if ((void *)(eth + 1) > data_end)
    return XDP_PASS;
```

O verificador eBPF do kernel **exige** que todo acesso à memória do pacote seja precedido de uma verificação de bounds. A expressão `(eth + 1)` é equivalente a `data + sizeof(struct ethhdr)` — verifica se há pelo menos 14 bytes de cabeçalho Ethernet disponíveis. Se não houver, o pacote passa para a pilha normal via `XDP_PASS`.

Essa verificação não é opcional: sem ela o verificador rejeita o programa na carga, pois não consegue provar que o acesso a `eth->h_proto` é seguro.

### 3. Extração do IP Destino

O campo `eth->h_proto` identifica o protocolo encapsulado no frame Ethernet (em network byte order). O programa trata dois casos:

#### Caso IPv4 (`ETH_P_IP = 0x0800`)

```c
} else if (eth->h_proto == bpf_htons(ETH_P_IP)) {
    struct iphdr *iph = (void *)(eth + 1);
    if ((void *)(iph + 1) > data_end)
        return XDP_PASS;
    lookup_ip = iph->daddr;
}
```

`bpf_htons(ETH_P_IP)` converte a constante `0x0800` para network byte order de forma portável — em arquiteturas big-endian o valor não muda; em little-endian (x86) inverte os bytes. `iph->daddr` é o IP destino já em network byte order, pronto para ser usado como chave.

#### Caso ARP (`ETH_P_ARP = 0x0806`)

```c
if (eth->h_proto == bpf_htons(ETH_P_ARP)) {
    if (data + sizeof(struct ethhdr) + 28 > data_end)
        return XDP_PASS;
    lookup_ip = *(__u32 *)(data + sizeof(struct ethhdr) + 24);
}
```

Pacotes ARP precisam ser redirecionados para que o host destino receba a requisição e possa responder — sem isso, o ARP não resolve e o ping falha mesmo que o encaminhamento IP esteja correto.

O IP alvo (`ar_tip`, _target IP address_) está em um offset fixo dentro do payload ARP. A estrutura completa de um pacote ARP para Ethernet/IPv4:

```
Ethernet header       : 14 bytes  (sizeof(struct ethhdr))
ARP header (arphdr)   :  8 bytes  (hw type, proto type, hw len, proto len, opcode)
Sender HW address     :  6 bytes  (sha)
Sender IP address     :  4 bytes  (sip)
Target HW address     :  6 bytes  (tha)
Target IP address     :  4 bytes  (tip)  ← offset 24 a partir de *após* o ethhdr
```

O acesso é feito diretamente pelo offset `24` (sem usar `struct arphdr`) para manter o código simples. O bounds check verifica `28` bytes a partir do fim do ethhdr (8 + 6 + 4 + 6 + 4 = 28), cobrindo toda a estrutura ARP Ethernet/IPv4.

#### Outros protocolos

```c
} else {
    return XDP_PASS;
}
```

Qualquer outro protocolo (IPv6, VLAN, MPLS, etc.) é passado para a pilha normal sem processamento.

### 4. Consulta ao Mapa e Redirecionamento

```c
__u32 *ifidx = bpf_map_lookup_elem(&route_table, &lookup_ip);
if (!ifidx)
    return XDP_PASS;

return bpf_redirect(*ifidx, 0);
```

`bpf_map_lookup_elem` retorna um **ponteiro** para o valor dentro do mapa (acesso direto à memória do kernel), ou `NULL` se a chave não existir. Usar o ponteiro diretamente (em vez de copiar o valor) é a forma correta e segura — o verificador entende esse padrão.

Se a rota não existir, o pacote é passado para a pilha IP do kernel (`XDP_PASS`), que o descartará normalmente (não há rota configurada no namespace do switch).

`bpf_redirect(ifidx, 0)` instrui o kernel a redirecionar o pacote para a interface identificada pelo ifindex, **sem modificar nenhum campo do pacote** — reencaminhamento puro de L3. O segundo argumento `0` indica ausência de flags especiais. O retorno é sempre `XDP_REDIRECT` quando o redirecionamento é válido.

---

## Licença GPL

```c
char _license[] SEC("license") = "GPL";
```

O kernel exige que programas eBPF que usam helpers "GPL-only" declarem licença GPL. `bpf_redirect()` é um helper GPL-only — sem essa declaração, o `bpf(BPF_PROG_LOAD, ...)` retorna `EPERM` e o programa é rejeitado. A string `"GPL"` é lida diretamente da seção `license` do ELF pelo kernel na carga.

---

## Códigos de Retorno XDP

| Código | Valor | Efeito |
|--------|-------|--------|
| `XDP_PASS` | 2 | Entrega o pacote à pilha de rede normal do kernel |
| `XDP_REDIRECT` | 4 | Redireciona para outra interface (retornado implicitamente por `bpf_redirect`) |

O programa nunca descarta pacotes (`XDP_DROP`) — apenas encaminha ou passa adiante.

---

## Verificador eBPF e Restrições

O verificador do kernel analisa o bytecode em tempo de carga e rejeita programas que violem regras de segurança. As principais restrições que moldam este código:

**Bounds checking obrigatório:** todo ponteiro derivado de `ctx->data` deve ser verificado contra `ctx->data_end` antes do acesso. As três verificações no código (`eth + 1`, `iph + 1`, `ethhdr + 28`) existem para satisfazer o verificador — não são defesas opcionais.

**Sem loops não terminantes:** o verificador precisa provar que o programa termina em tempo finito. Este programa não tem loops, o que simplifica a análise.

**Sem chamadas de função arbitrárias:** apenas helpers listados na API BPF podem ser chamados (`bpf_map_lookup_elem`, `bpf_redirect`). Funções da libc são inacessíveis.

**Registradores tipados:** o verificador rastreia o tipo de cada registrador (ponteiro para pacote, ponteiro para mapa, escalar, etc.) e rejeita operações inconsistentes com o tipo.

---

## Diagrama do Fluxo de Decisão

```
pacote chega em veth1s / veth2s / veth3s
           │
           ▼
    [eth header válido?] ──── não ──── XDP_PASS
           │ sim
           ▼
    [h_proto == ARP?] ──── sim ──── [ARP payload válido?] ── não ── XDP_PASS
           │                                   │ sim
           │                         lookup_ip = ar_tip
           │
    [h_proto == IPv4?] ── não ──── XDP_PASS
           │ sim
    [IP header válido?] ── não ── XDP_PASS
           │ sim
     lookup_ip = iph->daddr
           │
           ▼ (ambos os caminhos convergem aqui)
    [route_table[lookup_ip] existe?] ── não ── XDP_PASS
           │ sim
           ▼
    bpf_redirect(ifidx, 0)
           │
           ▼
    XDP_REDIRECT → pacote sai pela interface correta
```

---

## Relacionamento com os Outros Componentes

| Componente | Interação |
|------------|-----------|
| `setup_xdp_l3_dynamic.sh` | Compila este arquivo com `clang -target bpf`, carrega no kernel com `bpftool prog load`, e popula o `route_table` com as rotas iniciais via `bpftool map update` |
| `xdpunk-cli` | Lê e modifica o `route_table` em tempo real via BCC sem recarregar o programa |
| Kernel Linux | Invoca `xdp_forward()` para cada pacote recebido nas interfaces do switch; o verificador valida o bytecode na carga |
