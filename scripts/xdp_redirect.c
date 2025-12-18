#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

#define INPUT_PORT 4
#define OUTPUT_PORT 4

SEC("xdp")
int xdp_redirect_prog(struct xdp_md *ctx)
{

    if (OUTPUT_PORT == 0)
        return XDP_PASS;

    return bpf_redirect(ifindex_out, 0);
}

char _license[] SEC("license") = "GPL";
