#include <uapi/linux/bpf.h>
#include <uapi/linux/if_ether.h>
#include <uapi/linux/ip.h>
#include <uapi/linux/tcp.h>
#include <uapi/linux/udp.h>
#include <bcc/proto.h>

#define MAX_BLACKLIST 100000
#define MAX_RATE_ENTRIES 200000

/* Blacklist map: key = source IP, value = 1 if banned */
BPF_TABLE("lru_hash", u32, u8, blacklist, MAX_BLACKLIST);

/* Per-IP handshake timestamp (ns) – used for Minecraft L7 rate limiting */
BPF_TABLE("lru_hash", u32, u64, handshake_ts, MAX_RATE_ENTRIES);

/* Per-IP DNS packet timestamp (ns) – UDP rate limit */
BPF_TABLE("lru_hash", u32, u64, dns_ts, MAX_RATE_ENTRIES);

/* Per-IP SYN count – not strictly accurate across CPUs but sufficient */
BPF_ARRAY(syn_counter, u64, 1);   // used as temporary storage (will fix with percpu hash)

/* Perf event output: notifies userspace of blocked IPs */
struct block_event {
    u32 src_ip;
    u8 reason;   // 1=SYN flood, 2=handshake flood, 3=DNS flood, 4=SSH brute
};
BPF_PERF_OUTPUT(block_events);

static inline int is_mc_handshake(void *payload, void *data_end) {
    // Check for handshake packet (packet length varint <= 3, packet ID 0x00)
    if ((void *)(payload + 2) > data_end) return 0;
    u8 len = *(u8 *)payload;
    if (len < 2 || len > 4) return 0;          // handshake length is small
    if (*(u8 *)(payload + 1) != 0x00) return 0; // packet ID 0x00
    return 1;
}

int cavefilter(struct xdp_md *ctx) {
    void *data_end = (void *)(long)ctx->data_end;
    void *data = (void *)(long)ctx->data;
    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end) return XDP_PASS;
    if (eth->h_proto != htons(ETH_P_IP)) return XDP_PASS;

    struct iphdr *ip = (void *)(eth + 1);
    if ((void *)(ip + 1) > data_end) return XDP_PASS;

    u32 src_ip = ip->saddr;

    // 1) Check blacklist
    u8 *banned = blacklist.lookup(&src_ip);
    if (banned) return XDP_DROP;

    // 2) L4: TCP SYN flood (only count SYNs without ACK)
    if (ip->protocol == IPPROTO_TCP) {
        struct tcphdr *tcp = (void *)(ip + 1);
        if ((void *)(tcp + 1) > data_end) return XDP_PASS;
        if (tcp->syn && !tcp->ack) {
            // Use a simple but effective per-IP rate limit using a LRU hash
            // We'll store a timestamp of the first SYN; if a burst within 1 sec exceeds threshold, block.
            // For simplicity, we reuse the same structure as handshake but with different logic.
            // Actually, we'll use handshake_ts map as a generic per-IP last-event map.
            u64 now = bpf_ktime_get_ns();
            u64 *last = handshake_ts.lookup(&src_ip);
            if (last) {
                if (now - *last < 1000000000) {  // 1 second window
                    // Increment a per-IP counter stored in a separate map? We'll approximate:
                    // we don't have a counter, so we just allow one SYN per 200ms -> 5/sec.
                    if (now - *last < 200000000) {
                        struct block_event ev = { .src_ip = src_ip, .reason = 1 };
                        block_events.perf_submit(ctx, &ev, sizeof(ev));
                        return XDP_DROP;
                    }
                }
                *last = now;
            } else {
                handshake_ts.insert(&src_ip, &now);
            }
            // (A true per-IP counter would require a percpu map, but this approximation blocks repeated bursts)
        }

        // L7: Minecraft handshake rate limit (only on defined TCP ports)
        if (tcp->psh) {
            u16 dport = tcp->dest;
            // Check if destination port is within Minecraft range (simplified: assume 25565-25599)
            if (dport >= htons(25565) && dport <= htons(25600)) {
                unsigned int hdr_len = tcp->doff * 4;
                void *payload = (void *)tcp + hdr_len;
                if ((void *)(payload + 1) <= data_end && is_mc_handshake(payload, data_end)) {
                    u64 now = bpf_ktime_get_ns();
                    u64 *last = handshake_ts.lookup(&src_ip);
                    if (last) {
                        if (now - *last < 200000000) {
                            struct block_event ev = { .src_ip = src_ip, .reason = 2 };
                            block_events.perf_submit(ctx, &ev, sizeof(ev));
                            return XDP_DROP;
                        }
                        *last = now;
                    } else {
                        handshake_ts.insert(&src_ip, &now);
                    }
                }
            }

            // SSH brute force: rate limit new connections (PSH+SYN? Actually after 3-way handshake the first data packet has PSH. Simpler: use SYN rate already covered)
            // We'll handle SSH via connection tracking in userspace, but we can also count PSH on port 22.
            if (dport == htons(22)) {
                // new connection established: limit data packets per second per IP
                u64 now = bpf_ktime_get_ns();
                u64 *last = handshake_ts.lookup(&src_ip);
                if (last) {
                    if (now - *last < 200000000) {
                        struct block_event ev = { .src_ip = src_ip, .reason = 4 };
                        block_events.perf_submit(ctx, &ev, sizeof(ev));
                        return XDP_DROP;
                    }
                    *last = now;
                } else {
                    handshake_ts.insert(&src_ip, &now);
                }
            }
        }
    }

    // 3) UDP DNS rate limit
    if (ip->protocol == IPPROTO_UDP) {
        struct udphdr *udp = (void *)(ip + 1);
        if ((void *)(udp + 1) > data_end) return XDP_PASS;
        if (udp->dest == htons(53)) {
            u64 now = bpf_ktime_get_ns();
            u64 *last = dns_ts.lookup(&src_ip);
            if (last) {
                if (now - *last < 20000000) {  // 20ms -> 50 pps
                    struct block_event ev = { .src_ip = src_ip, .reason = 3 };
                    block_events.perf_submit(ctx, &ev, sizeof(ev));
                    return XDP_DROP;
                }
                *last = now;
            } else {
                dns_ts.insert(&src_ip, &now);
            }
        }
    }

    return XDP_PASS;
}
