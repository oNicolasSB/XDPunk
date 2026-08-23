/*
 * xdp_fw_lb.c — XDPunk Fase 2: firewall stateless + balanceador de links WAN.
 *
 * Pipeline por pacote (programa anexado a todas as veths do switch):
 *
 *   parse ethhdr
 *   ├─ ARP  → lê target IP → lookup route_table → redirect | XDP_PASS
 *   ├─ IPv4 → parse iphdr + portas TCP/UDP (ICMP/outros: portas = 0)
 *   │   ├─ firewall: scan linear em fw_rules, first-match (índice = prioridade)
 *   │   ├─ hit na route_table  → reescreve MACs → bpf_redirect  (LAN)
 *   │   └─ miss na route_table → LB WAN (hash de fluxo ou round-robin)
 *   │        → reescreve MACs → bpf_redirect(wan_links[idx].ifindex)
 *   └─ outro EtherType → XDP_PASS
 *
 * Decisões de projeto:
 *   - miss na route_table = rota default = sai pela WAN via LB;
 *   - bpf_redirect() não reescreve MACs e os provedores WAN roteiam em L3,
 *     logo todo redirect IPv4 reescreve h_dest/h_source com valores
 *     pré-configurados nos mapas (route_entry e wan_link);
 *   - sem reescrita de IP → sem recomputação de checksum e sem NAT
 *     (simplificação de laboratório documentada na monografia);
 *   - TTL não é decrementado (comportamento de switch).
 */
#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <linux/in.h>
#include <linux/if_arp.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

#define MAX_FW_RULES  2048
#define MAX_WAN_LINKS 4

#define FW_ACTION_ALLOW 0
#define FW_ACTION_DROP  1

#define LB_MODE_HASH 0
#define LB_MODE_RR   1

/* Índices de global_stats */
enum {
    STAT_TOTAL = 0,
    STAT_ARP,
    STAT_FW_DROP,
    STAT_LAN_REDIRECT,
    STAT_WAN_REDIRECT,
    STAT_PASS,
    STAT_LB_NO_LINK,
    STAT_MAX,
};

/*
 * Structs compartilhados com o plano de controle (xdpunk-cli).
 * Layouts sem padding implícito — qualquer mudança aqui exige mudança
 * espelhada em userspace/xdpunk_cli/maps.py.
 */
struct route_entry {
    __u32 ifindex;                /* interface de saída no switch          */
    __u8  dmac[6];                /* MAC do próximo salto (host LAN)       */
    __u8  smac[6];                /* MAC da interface de saída do switch   */
};                                /* 16 bytes */

struct fw_rule {
    __u32 src_ip;                 /* NBO, pré-mascarado (endereço de rede) */
    __u32 src_mask;               /* NBO; 0 = wildcard                     */
    __u32 dst_ip;
    __u32 dst_mask;
    __u16 src_port;               /* NBO; 0 = wildcard                     */
    __u16 dst_port;
    __u8  proto;                  /* 0 = any; IPPROTO_TCP/UDP/ICMP         */
    __u8  action;                 /* FW_ACTION_ALLOW | FW_ACTION_DROP      */
    __u8  enabled;                /* 0 = slot vazio                        */
    __u8  pad;
};                                /* 24 bytes */

struct fw_config {
    __u32 num_rules;              /* maior índice habilitado + 1; o scan
                                     para aqui — faz o custo do firewall
                                     escalar com N no experimento Q1       */
};

struct wan_link {
    __u32 ifindex;                /* veth WAN do switch                    */
    __u8  smac[6];                /* MAC da veth WAN do switch             */
    __u8  dmac[6];                /* MAC do roteador do provedor           */
    __u8  enabled;                /* 0 = link fora (failover manual)       */
    __u8  pad[3];
};                                /* 20 bytes */

struct lb_config {
    __u8 mode;                    /* LB_MODE_HASH | LB_MODE_RR             */
    __u8 num_links;               /* faixa do módulo (1..MAX_WAN_LINKS)    */
    __u8 enabled;                 /* 0 = LB desligado (miss → XDP_PASS)    */
    __u8 pad;
};

struct stat_val {
    __u64 packets;
    __u64 bytes;
};

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 256);
    __type(key, __u32);           /* IP destino (network byte order) */
    __type(value, struct route_entry);
} route_table SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, MAX_FW_RULES);
    __type(key, __u32);           /* índice = prioridade (menor vence) */
    __type(value, struct fw_rule);
} fw_rules SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, struct fw_config);
} fw_config SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, MAX_FW_RULES);
    __type(key, __u32);
    __type(value, struct stat_val);
} fw_stats SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, MAX_WAN_LINKS);
    __type(key, __u32);
    __type(value, struct wan_link);
} wan_links SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, struct lb_config);
} lb_config SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, __u64);         /* contador round-robin (atômico) */
} rr_state SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, MAX_WAN_LINKS);
    __type(key, __u32);
    __type(value, struct stat_val);
} wan_stats SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, STAT_MAX);
    __type(key, __u32);
    __type(value, struct stat_val);
} global_stats SEC(".maps");

/* Contadores per-CPU: sem atomics no hot path; a CLI soma os CPUs. */
static __always_inline void bump_stat(void *map, __u32 idx, __u64 bytes)
{
    struct stat_val *v = bpf_map_lookup_elem(map, &idx);

    if (v) {
        v->packets++;
        v->bytes += bytes;
    }
}

static __always_inline void rewrite_macs(struct ethhdr *eth,
                                         const __u8 *dmac, const __u8 *smac)
{
    __builtin_memcpy(eth->h_dest, (void *)dmac, ETH_ALEN);
    __builtin_memcpy(eth->h_source, (void *)smac, ETH_ALEN);
}

/*
 * Contexto e callback do scan de firewall via bpf_loop().
 *
 * bpf_loop() verifica o corpo do callback UMA ÚNICA VEZ (subprograma
 * independente), em vez de o verificador explorar N iterações do loop
 * estaticamente — isso evita estourar BPF_COMPLEXITY_LIMIT_JMP_SEQ (8192)
 * para MAX_FW_RULES grande. A iteração real acontece em runtime no kernel.
 */
struct fw_scan_ctx {
    __u32 saddr, daddr;
    __u16 sport, dport;
    __u8  proto;
    __u8  drop;         /* 1 = pacote deve ser dropado */
    __u8  matched;       /* 1 = alguma regra deu match (parou o scan) */
    __u32 matched_idx;   /* índice da regra que deu match (p/ fw_stats) */
};

static long fw_scan_cb(__u32 i, void *ctx)
{
    struct fw_scan_ctx *c = ctx;
    struct fw_rule *r = bpf_map_lookup_elem(&fw_rules, &i);

    if (!r || !r->enabled)
        return 0;
    if (r->proto && r->proto != c->proto)
        return 0;
    if ((c->saddr & r->src_mask) != r->src_ip)
        return 0;
    if ((c->daddr & r->dst_mask) != r->dst_ip)
        return 0;
    if (r->src_port && r->src_port != c->sport)
        return 0;
    if (r->dst_port && r->dst_port != c->dport)
        return 0;

    c->matched = 1;
    c->matched_idx = i;
    if (r->action == FW_ACTION_DROP)
        c->drop = 1;
    return 1;   /* first-match: para o loop */
}

SEC("xdp")
int xdp_fw_lb(struct xdp_md *ctx)
{
    void *data     = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;
    __u64 pkt_len  = data_end - data;

    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end)
        return XDP_PASS;

    bump_stat(&global_stats, STAT_TOTAL, pkt_len);

    if (eth->h_proto == bpf_htons(ETH_P_ARP)) {
        /*
         * ARP para Ethernet/IPv4:
         *   arphdr (8 bytes) + sha(6) + sip(4) + tha(6) + tip(4) = 28
         * target IP (ar_tip) está no offset 24 a partir do cabeçalho ARP.
         *
         * ARP nunca passa pelo LB: miss → XDP_PASS deixa o kernel do
         * switch responder pelos IPs das veths WAN (172.16.x.1).
         * Redirect de ARP não reescreve MACs (requests são broadcast e
         * replies já carregam o MAC unicast correto do solicitante).
         */
        bump_stat(&global_stats, STAT_ARP, pkt_len);

        if (data + sizeof(struct ethhdr) + 28 > data_end)
            return XDP_PASS;
        __u32 tip = *(__u32 *)(data + sizeof(struct ethhdr) + 24);

        struct route_entry *re = bpf_map_lookup_elem(&route_table, &tip);
        if (!re) {
            bump_stat(&global_stats, STAT_PASS, pkt_len);
            return XDP_PASS;
        }
        return bpf_redirect(re->ifindex, 0);
    }

    if (eth->h_proto != bpf_htons(ETH_P_IP)) {
        bump_stat(&global_stats, STAT_PASS, pkt_len);
        return XDP_PASS;
    }

    struct iphdr *iph = (void *)(eth + 1);
    if ((void *)(iph + 1) > data_end)
        return XDP_PASS;

    __u32 saddr = iph->saddr;
    __u32 daddr = iph->daddr;
    __u8  proto = iph->protocol;
    __u16 sport = 0, dport = 0;

    /*
     * Portas L4 (TCP/UDP). Fragmentos não-iniciais não carregam o
     * cabeçalho L4 → portas ficam 0 (limitação documentada: regras com
     * porta não casam fragmentos não-iniciais).
     */
    __u32 ihl = iph->ihl & 0xf;
    if (ihl < 5)
        return XDP_PASS;

    int is_frag = iph->frag_off & bpf_htons(0x1FFF);
    void *l4 = (void *)iph + ihl * 4;

    if (!is_frag && proto == IPPROTO_TCP) {
        struct tcphdr *tcph = l4;
        if ((void *)(tcph + 1) <= data_end) {
            sport = tcph->source;
            dport = tcph->dest;
        }
    } else if (!is_frag && proto == IPPROTO_UDP) {
        struct udphdr *udph = l4;
        if ((void *)(udph + 1) <= data_end) {
            sport = udph->source;
            dport = udph->dest;
        }
    }

    /*
     * FIREWALL — scan linear, first-match; índice do array = prioridade.
     * Nenhuma regra casando → política default ALLOW.
     * O loop para em fw_config.num_rules, executado via bpf_loop() (kernel
     * 5.17+) para não estourar BPF_COMPLEXITY_LIMIT_JMP_SEQ com N grande.
     */
    __u32 zero = 0;
    struct fw_config *fc = bpf_map_lookup_elem(&fw_config, &zero);
    __u32 num_rules = fc ? fc->num_rules : 0;
    if (num_rules > MAX_FW_RULES)
        num_rules = MAX_FW_RULES;

    struct fw_scan_ctx fw_ctx = {
        .saddr = saddr, .daddr = daddr,
        .sport = sport, .dport = dport, .proto = proto,
    };
    bpf_loop(num_rules, fw_scan_cb, &fw_ctx, 0);

    if (fw_ctx.matched) {
        bump_stat(&fw_stats, fw_ctx.matched_idx, pkt_len);
        if (fw_ctx.drop) {
            bump_stat(&global_stats, STAT_FW_DROP, pkt_len);
            return XDP_DROP;
        }
    }

    /* Rede local conhecida: hit na route_table → redirect com MAC rewrite. */
    struct route_entry *re = bpf_map_lookup_elem(&route_table, &daddr);
    if (re) {
        rewrite_macs(eth, re->dmac, re->smac);
        bump_stat(&global_stats, STAT_LAN_REDIRECT, pkt_len);
        return bpf_redirect(re->ifindex, 0);
    }

    /* Rota default: balanceamento entre links WAN. */
    struct lb_config *cfg = bpf_map_lookup_elem(&lb_config, &zero);
    if (!cfg || !cfg->enabled || cfg->num_links == 0 ||
        cfg->num_links > MAX_WAN_LINKS) {
        bump_stat(&global_stats, STAT_PASS, pkt_len);
        return XDP_PASS;
    }
    __u32 num_links = cfg->num_links;

    __u32 idx;
    if (cfg->mode == LB_MODE_RR) {
        /*
         * Round-robin por pacote: distribuição uniforme, mas pacotes do
         * mesmo fluxo podem alternar de link (reordenação TCP — efeito
         * medido no experimento F5). Contador compartilhado com
         * fetch-and-add atômico.
         */
        __u64 *ctr = bpf_map_lookup_elem(&rr_state, &zero);
        if (!ctr) {
            bump_stat(&global_stats, STAT_PASS, pkt_len);
            return XDP_PASS;
        }
        idx = (__u32)__sync_fetch_and_add(ctr, 1) % num_links;
    } else {
        /*
         * Hash de fluxo (5-tupla) multiplicativo de Fibonacci/Knuth:
         * afinidade de fluxo análoga ao ECMP L4 do kernel. ICMP tem
         * portas 0 → afinidade pelo par origem/destino.
         */
        __u32 h = saddr ^ daddr ^ (((__u32)sport << 16) | dport) ^ proto;
        h *= 0x9E3779B1U;
        idx = (h >> 16) % num_links;
    }

    /* Failover: pula links desabilitados a partir do escolhido. */
    struct wan_link *link = NULL;
    __u32 chosen = 0;
    for (__u32 k = 0; k < MAX_WAN_LINKS; k++) {
        __u32 j = (idx + k) % num_links;
        j &= MAX_WAN_LINKS - 1;
        struct wan_link *cand = bpf_map_lookup_elem(&wan_links, &j);
        if (cand && cand->enabled && cand->ifindex) {
            link = cand;
            chosen = j;
            break;
        }
    }
    if (!link) {
        bump_stat(&global_stats, STAT_LB_NO_LINK, pkt_len);
        return XDP_DROP;
    }

    rewrite_macs(eth, link->dmac, link->smac);
    bump_stat(&wan_stats, chosen, pkt_len);
    bump_stat(&global_stats, STAT_WAN_REDIRECT, pkt_len);
    return bpf_redirect(link->ifindex, 0);
}

char _license[] SEC("license") = "GPL";
