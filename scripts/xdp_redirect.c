#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

SEC("xdp")
int xdp_redirect_prog(struct xdp_md *ctx)
{
    return bpf_redirect(4, 0);
}

char _license[] SEC("license") = "GPL";