#!/usr/bin/env python3
import os, json, time, redis, subprocess, threading, psutil, configparser
from flask import Flask, render_template, request, jsonify
from flask_socketio import SocketIO, emit

app = Flask(__name__)
socketio = SocketIO(app, async_mode='gevent')
r = redis.Redis(decode_responses=True)

cfg = configparser.ConfigParser()
cfg.read("/opt/cavefilter/config/cavefilter.conf")
IFACE = cfg["network"]["interface"]
DASH_PORT = int(cfg["dashboard"]["port"])
BIND = cfg["dashboard"]["bind"]

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/api/unban', methods=['POST'])
def unban():
    ip = request.json.get('ip')
    if not ip:
        return jsonify({"error": "No IP"}), 400
    r.sadd("unban_queue", ip)
    return jsonify({"status": "queued", "ip": ip})

def get_stats():
    # Bandwidth bytes since last check
    rx_bytes_path = f"/sys/class/net/{IFACE}/statistics/rx_bytes"
    tx_bytes_path = f"/sys/class/net/{IFACE}/statistics/tx_bytes"
    rx_pkts_path = f"/sys/class/net/{IFACE}/statistics/rx_packets"
    tx_pkts_path = f"/sys/class/net/{IFACE}/statistics/tx_packets"
    try:
        with open(rx_bytes_path) as f: rx_bytes = int(f.read())
        with open(tx_bytes_path) as f: tx_bytes = int(f.read())
        with open(rx_pkts_path) as f: rx_pkts = int(f.read())
        with open(tx_pkts_path) as f: tx_pkts = int(f.read())
    except:
        rx_bytes = tx_bytes = rx_pkts = tx_pkts = 0

    # Ping to 1.1.1.1
    try:
        ping_res = subprocess.check_output("ping -c 1 -W 1 1.1.1.1 | tail -1 | awk '{print $4}' | cut -d '/' -f 2", shell=True)
        ping_ms = float(ping_res.strip())
    except:
        ping_ms = None

    # CPU & RAM
    cpu = psutil.cpu_percent()
    mem = psutil.virtual_memory().percent

    banned = r.hgetall("banned_ips")
    banned_list = [{"ip": k, "info": json.loads(v)} for k,v in banned.items()]

    return {
        "rx_bytes": rx_bytes,
        "tx_bytes": tx_bytes,
        "rx_pkts": rx_pkts,
        "tx_pkts": tx_pkts,
        "ping_ms": ping_ms,
        "cpu": cpu,
        "memory": mem,
        "banned": banned_list,
        "banned_count": len(banned_list)
    }

def stats_loop():
    while True:
        socketio.emit('stats', get_stats())
        time.sleep(0.5)

@socketio.on('connect')
def handle_connect():
    emit('stats', get_stats())

if __name__ == '__main__':
    threading.Thread(target=stats_loop, daemon=True).start()
    socketio.run(app, host=BIND, port=DASH_PORT)
