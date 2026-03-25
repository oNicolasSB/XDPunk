#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/if_arp.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 256);
    __type(key, __u32);   /* IP destino (network byte order) */
    __type(value, __u32); /* ifindex da interface de saída   */
} route_table SEC(".maps");

SEC("xdp")
int xdp_forward(struct xdp_md *ctx)
{
    void *data     = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;

    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end)
        return XDP_PASS;

    __u32 lookup_ip;

    if (eth->h_proto == bpf_htons(ETH_P_ARP)) {
        /*
         * ARP para Ethernet/IPv4:
         *   arphdr (8 bytes) + sha(6) + sip(4) + tha(6) + tip(4) = 28
         * target IP (ar_tip) está no offset 24 a partir do cabeçalho ARP.
         */
        if (data + sizeof(struct ethhdr) + 28 > data_end)
            return XDP_PASS;
        lookup_ip = *(__u32 *)(data + sizeof(struct ethhdr) + 24);
    } else if (eth->h_proto == bpf_htons(ETH_P_IP)) {
        struct iphdr *iph = (void *)(eth + 1);
        if ((void *)(iph + 1) > data_end)
            return XDP_PASS;
        lookup_ip = iph->daddr;
    } else {
        return XDP_PASS;
    }

    __u32 *ifidx = bpf_map_lookup_elem(&route_table, &lookup_ip);
    if (!ifidx)
        return XDP_PASS;

    return bpf_redirect(*ifidx, 0);
}

char _license[] SEC("license") = "GPL";
