// cavefilter.c (excerpt – full file in repository)
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/udp.h>

/* Maps */
struct {  // blacklist: IP -> banned (1)
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 100000);
    __type(key, __u32);
    __type(value, __u8);
} blacklist SEC(".maps");

struct {  // per‑IP last handshake time (ns)
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 200000);
    __type(key, __u32);
    __type(value, __u64);
} handshake_ts SEC(".maps");

struct {  // per‑IP SYN count (percpu for concurrency)
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, __u32);
} syn_count SEC(".maps");  // we'll use a different design – see full code

// ... (full program handles SYN flood, L7 Minecraft, DNS amplification, etc.)
