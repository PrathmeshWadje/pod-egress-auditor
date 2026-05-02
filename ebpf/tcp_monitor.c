// ebpf/tcp_monitor.c

#include "vmlinux.h"          // All kernel type definitions, generated via bpftool
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

// The event we emit to userspace for each TCP write
struct data_t {
    __u64 bytes;    // Payload size (3rd argument of tcp_sendmsg)
    __u32 saddr;    // Source IP — identifies which pod is sending
    __u32 daddr;    // Destination IP — used to filter internal traffic
};

// Our channel from kernel-space to userspace
struct {
    __uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
} events SEC(".maps");

SEC("kprobe/tcp_sendmsg")
int kprobe__tcp_sendmsg(struct pt_regs *ctx) {
    struct data_t data = {};
    struct sock *sk;

    // Read the 3rd argument: size_t size (bytes being sent)
    data.bytes = PT_REGS_PARM3(ctx);

    // Read the 1st argument: struct sock *sk
    sk = (struct sock *)PT_REGS_PARM1(ctx);

    // skc_rcv_saddr = locally bound IPv4 address = the pod's own IP (source)
    data.saddr = BPF_CORE_READ(sk, __sk_common.skc_rcv_saddr);

    // skc_daddr = foreign IPv4 address = where the traffic is going (destination)
    data.daddr = BPF_CORE_READ(sk, __sk_common.skc_daddr);

    if (data.bytes > 0) {
        bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU, &data, sizeof(data));
    }

    return 0;
}

char LICENSE[] SEC("license") = "GPL";