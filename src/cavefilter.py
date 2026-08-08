#!/usr/bin/env python3
import os, sys, time, json, struct, socket, subprocess, configparser, signal, logging
from bcc import BPF

CONF_PATH = "/opt/cavefilter/config/cavefilter.conf"
REDIS_HOST = "localhost"

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s: %(message)s")

def load_config():
    cfg = configparser.ConfigParser()
    if os.path.exists(CONF_PATH):
        cfg.read(CONF_PATH)
    else:
        logging.warning("Config not found at %s — using defaults", CONF_PATH)
    # Provide defaults to avoid KeyErrors
    defaults = {
        "network": {"interface": "eth0"},
        "xdp_mode": {"mode": "0"},
        "ban": {"duration": "3600"},
        "dashboard": {"bind": "127.0.0.1", "port": "5000"}
    }
    for section, pairs in defaults.items():
        if section not in cfg:
            cfg[section] = {}
        for k, v in pairs.items():
            cfg[section].setdefault(k, v)
    return cfg

def ip_to_int(ip_str):
    try:
        return struct.unpack("!I", socket.inet_aton(ip_str))[0]
    except Exception:
        return None

def int_to_ip(ip_int):
    return socket.inet_ntoa(struct.pack("!I", ip_int))

class CaveDaemon:
    def __init__(self):
        self.cfg = load_config()
        self.iface = self.cfg["network"]["interface"]
        self.xdp_mode = int(self.cfg["xdp_mode"]["mode"])
        self.b = None
        self.fn = None
        # redis optional: host from config
        import redis
        redis_host = self.cfg.get("redis", {}).get("host", REDIS_HOST)
        try:
            self.r = redis.Redis(host=redis_host, decode_responses=True)
        except Exception as e:
            logging.warning("Redis init failed: %s", e)
            self.r = None
        # ensure ipset exists (idempotent)
        duration = str(self.cfg["ban"]["duration"])
        try:
            subprocess.run(["ipset", "-exist", "create", "cave_blacklist", "hash:ip", "timeout", duration], check=False)
        except Exception as e:
            logging.warning("ipset create failed (nonfatal): %s", e)
        # ensure iptables rule exists (check then insert)
        try:
            subprocess.run(["iptables", "-C", "INPUT", "-m", "set", "--match-set", "cave_blacklist", "src", "-j", "DROP"], check=True)
        except subprocess.CalledProcessError:
            subprocess.run(["iptables", "-I", "INPUT", "-m", "set", "--match-set", "cave_blacklist", "src", "-j", "DROP"], check=False)

        # signal handlers to cleanup
        signal.signal(signal.SIGINT, self._sigterm)
        signal.signal(signal.SIGTERM, self._sigterm)
        self.stopping = False

    def load_bpf(self):
        bpf_path = "/opt/cavefilter/src/cavefilter.c"
        if not os.path.exists(bpf_path):
            logging.error("BPF source not found: %s", bpf_path)
            sys.exit(1)
        self.b = BPF(src_file=bpf_path)
        self.fn = self.b.load_func("cavefilter", BPF.XDP)
        self.b.attach_xdp(self.iface, self.fn, self.xdp_mode)
        self.b["block_events"].open_perf_buffer(self._handle_event, page_cnt=64)
        logging.info("XDP attached to %s", self.iface)

    def _handle_event(self, cpu, data, size):
        try:
            event = self.b["block_events"].event(data)
            ip_int = event.src_ip
            reason = int(event.reason)
            ip_str = int_to_ip(ip_int)
            # add to BPF blacklist map (idempotent)
            try:
                self.b["blacklist"][ip_int] = 1
            except Exception:
                pass
            # add to ipset (ignore failures)
            subprocess.run(["ipset", "add", "cave_blacklist", ip_str], check=False)
            # record in Redis
            try:
                if self.r:
                    self.r.hset("banned_ips", ip_str, json.dumps({
                        "time": time.time(),
                        "reason": {1:"SYN flood",2:"Handshake flood",3:"DNS flood",4:"SSH brute"}.get(reason,"Unknown")
                    }))
            except Exception as e:
                logging.warning("Redis hset failed: %s", e)
            logging.info("Banned %s - reason=%s", ip_str, reason)
        except Exception as e:
            logging.exception("Error handling perf event: %s", e)

    def process_unban_queue(self):
        while True:
            if not self.r:
                break
            ip = None
            try:
                ip = self.r.spop("unban_queue")
            except Exception:
                break
            if not ip:
                break
            ip_int = ip_to_int(ip)
            if ip_int is None:
                logging.warning("Invalid IP in unban_queue: %s", ip)
                continue
            try:
                try:
                    del self.b["blacklist"][ip_int]
                except Exception:
                    pass
                subprocess.run(["ipset", "del", "cave_blacklist", ip], check=False)
                try:
                    self.r.hdel("banned_ips", ip)
                except Exception:
                    pass
                logging.info("Unbanned %s", ip)
            except Exception as e:
                logging.warning("Failed to unban %s: %s", ip, e)

    def _sigterm(self, signum, frame):
        logging.info("Received signal %s, shutting down", signum)
        self.stopping = True

    def run(self):
        try:
            self.load_bpf()
            logging.info("Daemon running")
            while not self.stopping:
                try:
                    self.b.perf_buffer_poll(timeout=100)
                except Exception:
                    pass
                self.process_unban_queue()
                time.sleep(0.1)
        finally:
            try:
                if self.b:
                    self.b.remove_xdp(self.iface)
            except Exception:
                logging.warning("Failed to remove XDP (ignored)")
            subprocess.run(["iptables", "-D", "INPUT", "-m", "set", "--match-set", "cave_blacklist", "src", "-j", "DROP"], check=False)
            logging.info("Shutdown complete")

if __name__ == "__main__":
    daemon = CaveDaemon()
    daemon.run()
