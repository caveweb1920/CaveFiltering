#!/usr/bin/env python3
import os, json, time, socket, subprocess, threading, logging, configparser
from flask import Flask, render_template, request, jsonify, abort
from flask_socketio import SocketIO, emit
import redis, psutil

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s: %(message)s")

# Config
CONF_PATH = "/opt/cavefilter/config/cavefilter.conf"
cfg = configparser.ConfigParser()
if os.path.exists(CONF_PATH):
    cfg.read(CONF_PATH)
else:
    logging.warning("Config not found at %s — using defaults", CONF_PATH)

# Provide safe defaults
if "network" not in cfg:
    cfg["network"] = {}
if "dashboard" not in cfg:
    cfg["dashboard"] = {}

IFACE = cfg["network"].get("interface", "eth0")
DASH_PORT = int(cfg["dashboard"].get("port", "5000"))
BIND = cfg["dashboard"].get("bind", "127.0.0.1")
# Optional token — if set, POST /api/unban requires X-Auth-Token header
DASH_TOKEN = os.environ.get("DASH_TOKEN") or cfg["dashboard"].get("token", "")
if not DASH_TOKEN:
    DASH_TOKEN = None

# Redis
redis_host = cfg.get("redis", {}).get("host", "localhost")
try:
    r = redis.Redis(host=redis_host, decode_responses=True)
except Exception:
    r = None

app = Flask(__name__)
# Let SocketIO choose best async mode available; fallback to eventlet if present
socketio = SocketIO(app)

# Previous counters for rate calculation
_prev = {
    "rx_bytes": None,
    "tx_bytes": None,
    "rx_pkts": None,
    "tx_pkts": None,
    "ts": None
}


@app.route('/')
def index():
    return render_template('index.html')


def _require_unban_auth():
    # If a token is configured, require it
    if DASH_TOKEN:
        token = request.headers.get("X-Auth-Token")
        if not token or token != DASH_TOKEN:
            abort(403)
    else:
        # No token configured: only allow localhost callers
        if request.remote_addr not in ("127.0.0.1", "::1"):
            abort(403)


@app.route('/api/unban', methods=['POST'])
def unban():
    _require_unban_auth()
    data = request.get_json(silent=True) or {}
    ip = data.get('ip')
    if not ip:
        return jsonify({"error": "No IP"}), 400
    if r:
        try:
            r.sadd("unban_queue", ip)
        except Exception as e:
            logging.warning("Redis unavailable: %s", e)
            return jsonify({"error": "backend error"}), 500
    return jsonify({"status": "queued", "ip": ip})


def _read_stat(path):
    try:
        with open(path) as f:
            return int(f.read().strip())
    except Exception:
        return None


def get_stats():
    # Read absolute counters from sysfs
    rx_bytes_path = f"/sys/class/net/{IFACE}/statistics/rx_bytes"
    tx_bytes_path = f"/sys/class/net/{IFACE}/statistics/tx_bytes"
    rx_pkts_path = f"/sys/class/net/{IFACE}/statistics/rx_packets"
    tx_pkts_path = f"/sys/class/net/{IFACE}/statistics/tx_packets"

    rx_bytes = _read_stat(rx_bytes_path) or 0
    tx_bytes = _read_stat(tx_bytes_path) or 0
    rx_pkts = _read_stat(rx_pkts_path) or 0
    tx_pkts = _read_stat(tx_pkts_path) or 0

    now = time.time()
    # Initialize prev values if missing
    if _prev['ts'] is None:
        _prev['rx_bytes'] = rx_bytes
        _prev['tx_bytes'] = tx_bytes
        _prev['rx_pkts'] = rx_pkts
        _prev['tx_pkts'] = tx_pkts
        _prev['ts'] = now

    elapsed = max(now - _prev['ts'], 1e-6)
    rx_rate_bps = (rx_bytes - (_prev['rx_bytes'] or rx_bytes)) / elapsed
    tx_rate_bps = (tx_bytes - (_prev['tx_bytes'] or tx_bytes)) / elapsed
    rx_pps = (rx_pkts - (_prev['rx_pkts'] or rx_pkts)) / elapsed
    tx_pps = (tx_pkts - (_prev['tx_pkts'] or tx_pkts)) / elapsed

    _prev['rx_bytes'] = rx_bytes
    _prev['tx_bytes'] = tx_bytes
    _prev['rx_pkts'] = rx_pkts
    _prev['tx_pkts'] = tx_pkts
    _prev['ts'] = now

    # Ping to 1.1.1.1 (best-effort)
    try:
        ping_res = subprocess.check_output("ping -c 1 -W 1 1.1.1.1 | tail -1 | awk '{print $4}' | cut -d '/' -f 2", shell=True)
        ping_ms = float(ping_res.strip())
    except Exception:
        ping_ms = None

    cpu = psutil.cpu_percent()
    mem = psutil.virtual_memory().percent

    banned_list = []
    try:
        if r:
            banned = r.hgetall("banned_ips") or {}
            banned_list = [{"ip": k, "info": json.loads(v)} for k, v in banned.items()]
    except Exception:
        banned_list = []

    return {
        "rx_bytes": rx_bytes,
        "tx_bytes": tx_bytes,
        "rx_rate_bps": rx_rate_bps,
        "tx_rate_bps": tx_rate_bps,
        "rx_pps": rx_pps,
        "tx_pps": tx_pps,
        "ping_ms": ping_ms,
        "cpu": cpu,
        "memory": mem,
        "banned": banned_list,
        "banned_count": len(banned_list)
    }


def stats_loop():
    while True:
        try:
            socketio.emit('stats', get_stats())
        except Exception as e:
            logging.exception("Error emitting stats: %s", e)
        time.sleep(0.5)


@socketio.on('connect')
def handle_connect():
    emit('stats', get_stats())


if __name__ == '__main__':
    t = threading.Thread(target=stats_loop, daemon=True)
    t.start()
    logging.info("Starting dashboard on %s:%s", BIND, DASH_PORT)
    socketio.run(app, host=BIND, port=DASH_PORT)
