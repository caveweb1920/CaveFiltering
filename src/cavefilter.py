#!/usr/bin/env python3
import os, sys, time, redis, json, struct, socket, subprocess, configparser, signal
from bcc import BPF

CONF_PATH = "/opt/cavefilter/config/cavefilter.conf"
REDIS_HOST = "localhost"

def load_config():
    cfg = configparser.ConfigParser()
    cfg.read(CONF_PATH)
    return cfg

def ip_to_int(ip_str):
    return struct.unpack("!I", socket.inet_aton(ip_str))[0]

def int_to_ip(ip_int):
    return socket.inet_ntoa(struct.pack("!I", ip_int))

class CaveDaemon:
    def __init__(self):
        self.cfg = load_config()
        self.iface = self.cfg["network"]["interface"]
        self.xdp_mode = int(self.cfg["xdp_mode"]["mode"])
        self.r = redis.Redis(host=REDIS_HOST, decode_responses=True)
        self.b = None
        self.fn = None

        # prepare ipset
        try:
            subprocess.run(["ipset", "create", "cave_blacklist", "hash:ip",
                            "timeout", self.cfg["ban"]["duration"]], check=True)
        except subprocess.CalledProcessError:
            pass
        subprocess.run(["iptables", "-I", "INPUT", "-m", "set",
                        "--match-set", "cave_blacklist", "src", "-j", "DROP"],
                       check=False)

    def load_bpf(self):
        self.b = BPF(src_file="/opt/cavefilter/src/cavefilter.c")
        self.fn = self.b.load_func("cavefilter", BPF.XDP)
        self.b.attach_xdp(self.iface, self.fn, self.xdp_mode)
        self.b["block_events"].open_perf_buffer(self._handle_event, page_cnt=64)
        print(f"[+] XDP attached to {self.iface}")

    def _handle_event(self, cpu, data, size):
        event = self.b["block_events"].event(data)
        ip_int = event.src_ip
        reason = event.reason
        ip_str = int_to_ip(ip_int)
        # add to BPF blacklist
        self.b["blacklist"][ip_int] = 1
        # add to ipset
        subprocess.run(["ipset", "add", "cave_blacklist", ip_str], check=False)
        # record in Redis
        self.r.hset("banned_ips", ip_str, json.dumps({
            "time": time.time(),
            "reason": {1:"SYN flood",2:"Handshake flood",3:"DNS flood",4:"SSH brute"}.get(reason,"Unknown")
        }))
        print(f"[!] Banned {ip_str} - {reason}")

    def process_unban_queue(self):
        while True:
            ip = self.r.spop("unban_queue")
            if not ip:
                break
            ip_int = ip_to_int(ip)
            try:
                del self.b["blacklist"][ip_int]
            except:
                pass
            subprocess.run(["ipset", "del", "cave_blacklist", ip], check=False)
            self.r.hdel("banned_ips", ip)
            print(f"[✓] Unbanned {ip}")

    def run(self):
        self.load_bpf()
        print("[+] Daemon running, Ctrl+C to stop")
        while True:
            try:
                self.b.perf_buffer_poll(timeout=10)
                self.process_unban_queue()
                time.sleep(0.1)
            except KeyboardInterrupt:
                break
        self.b.remove_xdp(self.iface)
        subprocess.run(["iptables", "-D", "INPUT", "-m", "set",
                        "--match-set", "cave_blacklist", "src", "-j", "DROP"], check=False)

if __name__ == "__main__":
    daemon = CaveDaemon()
    daemon.run()
