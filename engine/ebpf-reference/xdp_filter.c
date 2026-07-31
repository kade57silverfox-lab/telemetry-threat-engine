/*
 * xdp_filter.c -- kernel-level packet capture and early filtering.
 *
 * WHY THIS FILE EXISTS BUT DOES NOT RUN IN THIS PROJECT'S SANDBOX:
 * Loading an XDP program requires CAP_BPF/CAP_NET_ADMIN, a real network
 * interface, and a kernel with BPF JIT enabled -- none of which are
 * available in a container without root and a NIC. This file is the real,
 * correct design for the capture layer described in docs/DESIGN.md. The
 * rest of the engine (engine/src/ingestion.rs) swaps in a userspace
 * event simulator that produces the exact same NetworkEvent struct, so
 * every downstream stage (queue, detection, API) is unchanged whether
 * events originate here or from the simulator.
 *
 * WHAT THIS PROGRAM ACTUALLY DOES:
 * It runs *inside the kernel*, attached to a NIC's RX path, and is invoked
 * once per incoming packet before the normal network stack (sockets, TCP/IP
 * stack) ever sees it. Two responsibilities, both in-kernel:
 *
 *   1. Cheap, early rejection: malformed packets or protocols we don't care
 *      about (see `should_forward_to_userspace` below) are dropped (XDP_DROP)
 *      right here, so they never cost a userspace copy or a detection-thread
 *      cycle at all.
 *   2. Zero-copy handoff: everything else is redirected (XDP_REDIRECT) into
 *      an AF_XDP socket's UMEM ring -- a region of memory shared between the
 *      kernel and userspace -- so userspace reads packet bytes directly out
 *      of that shared memory instead of the kernel copying them into a
 *      socket buffer first.
 *
 * eBPF VERIFIER CONSTRAINTS (why this is written the way it is):
 * The kernel's BPF verifier statically proves this program terminates and
 * never accesses memory out of bounds before it's allowed to load. That
 * means:
 *   - No unbounded loops (the loop below is bounded and unrolled by the
 *     verifier/compiler).
 *   - Every pointer read from packet data must be bounds-checked against
 *     `data_end` *before* the read, on every single access -- the verifier
 *     rejects the program otherwise. This is the single most common reason
 *     a first attempt at an XDP program fails to load.
 *   - No arbitrary kernel memory access; only whitelisted "helper functions"
 *     (bpf_redirect_map, bpf_xdp_adjust_head, etc.) are callable.
 *
 * BUILD (on a real Linux box with clang/llvm and libbpf-dev installed):
 *   clang -O2 -target bpf -c xdp_filter.c -o xdp_filter.o
 *   sudo ip link set dev eth0 xdp obj xdp_filter.o sec xdp
 *
 * In the Rust project this corresponds to the `libbpf-rs` crate loading and
 * attaching this same object file, then reading matched frames out of the
 * AF_XDP UMEM via an `xsk_socket` -- the memory-mapped region referenced
 * throughout the project as the "memory-mapped files" claim.
 */

#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/in.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <bpf/bpf_helpers.h>

/* BPF_MAP_TYPE_XSKMAP: maps a queue index -> an AF_XDP socket file
 * descriptor. `bpf_redirect_map` uses this to hand a packet off to the
 * specific userspace socket registered for the RX queue it arrived on,
 * which is what makes multi-queue (multi-core) capture scale: each NIC
 * RX queue's packets go to a different AF_XDP socket / CPU core without
 * any shared lock between them.
 */
struct {
    __uint(type, BPF_MAP_TYPE_XSKMAP);
    __uint(max_entries, 64); /* one entry per NIC RX queue we support */
    __uint(key_size, sizeof(__u32));
    __uint(value_size, sizeof(__u32));
} xsks_map SEC(".maps");

/* Simple per-CPU counters so `bpftool prog show` / a userspace stats reader
 * can report drop vs. forward counts without needing to inspect packets --
 * this is the in-kernel half of the "IT support / operability" story: an
 * operator can check whether the XDP layer itself is dropping heavily
 * before ever looking at the userspace engine.
 */
struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 2); /* 0 = dropped, 1 = forwarded */
    __type(key, __u32);
    __type(value, __u64);
} counters SEC(".maps");

static __always_inline void bump_counter(__u32 idx) {
    __u64 *count = bpf_map_lookup_elem(&counters, &idx);
    if (count) {
        __sync_fetch_and_add(count, 1);
    }
}

/*
 * Decide, using only the IP/TCP/UDP header (never the payload -- that's
 * inspected in userspace by the signature/CEP detectors, which is a
 * deliberate cost tradeoff: header parsing is cheap and verifier-friendly,
 * full payload inspection in-kernel is neither), whether a packet is worth
 * forwarding to userspace at all.
 *
 * Every single pointer dereference below is preceded by a bounds check
 * against `data_end`. This is not defensive style choice -- the verifier
 * will refuse to load this program if any read is not provably in-bounds.
 */
static __always_inline int should_forward_to_userspace(void *data, void *data_end) {
    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end) {
        return 0; /* truncated frame, not even a full Ethernet header */
    }

    if (eth->h_proto != __constant_htons(ETH_P_IP)) {
        return 0; /* only IPv4 is in scope for this engine; drop the rest */
    }

    struct iphdr *ip = (void *)(eth + 1);
    if ((void *)(ip + 1) > data_end) {
        return 0;
    }

    if (ip->protocol == IPPROTO_TCP) {
        struct tcphdr *tcp = (void *)ip + (ip->ihl * 4);
        if ((void *)(tcp + 1) > data_end) {
            return 0;
        }
        /* Forward all TCP -- SYN/ACK/RST flag state is exactly what the
         * anomaly (SYN-flood) and CEP (probe-then-exploit sequence)
         * detectors need, so we can't filter further here without
         * throwing away detection signal. */
        return 1;
    }

    if (ip->protocol == IPPROTO_UDP) {
        struct udphdr *udp = (void *)ip + (ip->ihl * 4);
        if ((void *)(udp + 1) > data_end) {
            return 0;
        }
        return 1;
    }

    /* ICMP and anything else: forward too, at low volume this costs little
     * and some scan/recon techniques rely on ICMP. */
    return 1;
}

SEC("xdp")
int xdp_filter_prog(struct xdp_md *ctx) {
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;

    if (!should_forward_to_userspace(data, data_end)) {
        bump_counter(0);
        return XDP_DROP;
    }

    bump_counter(1);

    /* Redirect into the AF_XDP socket registered for this RX queue.
     * `ctx->rx_queue_index` is what makes this scale across cores: each
     * queue's traffic lands in a different userspace socket/ring with no
     * cross-core contention at this layer. If no socket is registered for
     * this queue (xsks_map lookup fails), XDP_PASS lets the packet continue
     * through the normal kernel network stack instead of being lost.
     */
    return bpf_redirect_map(&xsks_map, ctx->rx_queue_index, XDP_PASS);
}

char _license[] SEC("license") = "GPL";
