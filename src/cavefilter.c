#include <uapi/linux/bpf.h>
#include <uapi/linux/if_ether.h>
#include <uapi/linux/ip.h>
#include <uapi/linux/tcp.h>
#include <uapi/linux/udp.h>
#include <bcc/proto.h>

#define MAX_BLACKLIST 100000
#define MAX_RATE_ENTRIES 200000

// thresholds (tunable)
#define SYN_WINDOW_NS 1000000000ULL   // 1 second
#define SYN_THRESHOLD 100

#define UDP_WINDOW_NS 1000000000ULL   // 1 second
#define UDP_THRESHOLD 200
#define DNS_THRESHOLD 50

#define HANDSHAKE_WINDOW_NS 200000000ULL // 200 ms
#define HANDSHAKE_THRESHOLD 5

struct ip_state {
    u64 last_ts;
    u32 count;
};

/* Blacklist map: key = source IP, value = 1 if banned */
BPF_TABLE("lru_hash", u32, u8, blacklist, MAX_BLACKLIST);

/* Per-IP SYN state */
BPF_TABLE("lru_hash", u32, struct ip_state, syn_state_map, MAX_RATE_ENTRIES);
/* Per-IP UDP state */
BPF_TABLE("lru_hash", u32, struct ip_state, udp_state_map, MAX_RATE_ENTRIES);
/* Per-IP handshake state */
BPF_TABLE("lru_hash", u32, struct ip_state, handshake_state_map, MAX_RATE_ENTRIES);

/* Perf event output: notifies userspace of blocked IPs */
struct block_event {
    u32 src_ip;
    u8 reason;   // 1=SYN flood, 2=handshake flood, 3=DNS flood, 4=SSH brute, 5=port-scan
};
BPF_PERF_OUTPUT(block_events);

/* Port event: report SYN with destination port to userspace for port-scan detection */
struct port_event {
    u32 src_ip;
    u16 dport;
};
BPF_PERF_OUTPUT(port_events);

static inline int safe_load_u8(void *ptr, void *data_end, u8 *out) {
    if ((void *)ptr + 1 > data_end) return 0;
    *out = *(u8 *)ptr;
    return 1;
}

static inline int is_mc_handshake(void *payload, void *data_end) {
    // Minimal safe check for Minecraft handshake: length varint (1 byte) + packet id
    u8 len;
    if (!safe_load_u8(payload, data_end, &len)) return 0;
    // ensure at least one more byte for packet id and that the full packet fits
    if ((void *)payload + 1 + 1 > data_end) return 0;
    // very conservative: require payload to contain at least len+1 bytes
    if ((void *)payload + 1 + (u32)len > data_end) return 0;
    u8 pid = *(u8 *)((char *)payload + 1);
    return pid == 0x00;
}

int cavefilter(struct xdp_md *ctx) {
    void *data_end = (void *)(long)ctx->data_end;
    void *data = (void *)(long)ctx->data;
    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end) return XDP_PASS;
    if (eth->h_proto != htons(ETH_P_IP)) return XDP_PASS;

    struct iphdr *ip = (void *)(eth + 1);
    if ((void *)(ip + 1) > data_end) return XDP_PASS;
    // validate IP header length
    u32 ip_hdr_len = ip->ihl * 4;
    if ((void *)ip + ip_hdr_len > data_end) return XDP_PASS;

    u32 src_ip = ip->saddr;

    // Check blacklist
    u8 *banned = blacklist.lookup(&src_ip);
    if (banned) return XDP_DROP;

    u64 now = bpf_ktime_get_ns();

    // TCP handling
    if (ip->protocol == IPPROTO_TCP) {
        struct tcphdr *tcp = (void *)((char *)ip + ip_hdr_len);
        if ((void *)(tcp + 1) > data_end) return XDP_PASS;
        u32 tcp_hdr_len = tcp->doff * 4;
        if ((void *)tcp + tcp_hdr_len > data_end) return XDP_PASS;

        // Report SYNs to userspace (for port-scan detection)
        if (tcp->syn && !tcp->ack) {
            struct port_event pe = { .src_ip = src_ip, .dport = tcp->dest };
            port_events.perf_submit(ctx, &pe, sizeof(pe));

            // SYN rate limiting
            struct ip_state *st = syn_state_map.lookup(&src_ip);
            if (st) {
                if (now - st->last_ts <= SYN_WINDOW_NS) {
                    st->count++;
                } else {
                    st->count = 1;
                }
                st->last_ts = now;
                if (st->count > SYN_THRESHOLD) {
                    u8 one = 1;
                    blacklist.update(&src_ip, &one);
                    struct block_event ev = { .src_ip = src_ip, .reason = 1 };
                    block_events.perf_submit(ctx, &ev, sizeof(ev));
                    return XDP_DROP;
                }
            } else {
                struct ip_state new = { .last_ts = now, .count = 1 };
                syn_state_map.update(&src_ip, &new);
            }
        }

        // L7: Minecraft handshake detection on PSH (safely)
        if (tcp->psh) {
            u16 dport = tcp->dest;
            unsigned int hdr_len = tcp->doff * 4;
            void *payload = (void *)tcp + hdr_len;
            if (payload < data_end && (void *)payload + 1 <= data_end) {
                // check if destination port in Minecraft range
                if (dport >= htons(25565) && dport <= htons(25600)) {
                    if (is_mc_handshake(payload, data_end)) {
                        struct ip_state *st = handshake_state_map.lookup(&src_ip);
                        if (st) {
                            if (now - st->last_ts <= HANDSHAKE_WINDOW_NS) {
                                st->count++;
                            } else {
                                st->count = 1;
                            }
                            st->last_ts = now;
                            if (st->count > HANDSHAKE_THRESHOLD) {
                                u8 one = 1;
                                blacklist.update(&src_ip, &one);
                                struct block_event ev = { .src_ip = src_ip, .reason = 2 };
                                block_events.perf_submit(ctx, &ev, sizeof(ev));
                                return XDP_DROP;
                            }
                        } else {
                            struct ip_state new = { .last_ts = now, .count = 1 };
                            handshake_state_map.update(&src_ip, &new);
                        }
                    }
                }

                // SSH brute detection (simple PSH rate limit on port 22)
                if (dport == htons(22)) {
                    struct ip_state *st = handshake_state_map.lookup(&src_ip);
                    if (st) {
                        if (now - st->last_ts <= HANDSHAKE_WINDOW_NS) {
                            st->count++;
                        } else {
                            st->count = 1;
                        }
                        st->last_ts = now;
                        if (st->count > HANDSHAKE_THRESHOLD) {
                            u8 one = 1;
                            blacklist.update(&src_ip, &one);
                            struct block_event ev = { .src_ip = src_ip, .reason = 4 };
                            block_events.perf_submit(ctx, &ev, sizeof(ev));
                            return XDP_DROP;
                        }
                    } else {
                        struct ip_state new = { .last_ts = now, .count = 1 };
                        handshake_state_map.update(&src_ip, &new);
                    }
                }
            }
        }
    }

    // UDP handling
    if (ip->protocol == IPPROTO_UDP) {
        struct udphdr *udp = (void *)((char *)ip + ip_hdr_len);
        if ((void *)(udp + 1) > data_end) return XDP_PASS;
        u16 dport = udp->dest;

        struct ip_state *st = udp_state_map.lookup(&src_ip);
        if (st) {
            if (now - st->last_ts <= UDP_WINDOW_NS) {
                st->count++;
            } else {
                st->count = 1;
            }
            st->last_ts = now;
            u32 threshold = UDP_THRESHOLD;
            if (dport == htons(53)) threshold = DNS_THRESHOLD;
            if (st->count > threshold) {
                u8 one = 1;
                blacklist.update(&src_ip, &one);
                struct block_event ev = { .src_ip = src_ip, .reason = 3 };
                block_events.perf_submit(ctx, &ev, sizeof(ev));
                return XDP_DROP;
            }
        } else {
            struct ip_state new = { .last_ts = now, .count = 1 };
            udp_state_map.update(&src_ip, &new);
        }
    }

    return XDP_PASS;
}
