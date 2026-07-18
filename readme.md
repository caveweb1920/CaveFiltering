# 🪨 CaveFiltering

**Kernel‑level DDoS protection for your entire server.**  
Built on XDP & eBPF – drops attacks inside the NIC driver, before they ever touch your applications.

[![MIT License](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![Kernel](https://img.shields.io/badge/Kernel-%E2%89%A55.15-blue)](https://kernel.org)
[![eBPF](https://img.shields.io/badge/eBPF-XDP-red)](https://ebpf.io)

---

## 🚀 Quick Start

```bash
git clone https://github.com/caveweb1920/CaveFiltering.git
cd CaveFiltering
sudo bash install.sh
```

Open `http://<your-server-ip>:5000` – your shield is live.

---

## 🔒 What It Protects

| Service            | Port(s)            | Protection Type                         |
|--------------------|--------------------|-----------------------------------------|
| Minecraft (Java)   | 25565‑25600        | SYN flood + handshake rate limit        |
| SSH                | 22                 | Connection rate limit                   |
| DNS (UDP)          | 53                 | PPS limit (amplification defence)       |
| HTTP/HTTPS         | 80, 443            | SYN flood + connection rate             |
| Any custom service | your range         | Define in config                        |

---

## 🧠 How It Works

```
[ Internet ]
    │
    ▼
┌─────────────────┐
│  NIC driver     │ ← XDP program (drop at line rate)
│  (eBPF)         │
└────────┬────────┘
         │ clean traffic
    ┌────▼─────┐
    │  Kernel   │ → your apps (Pterodactyl, SSH, DNS …)
    └──────────┘
```

- **XDP/eBPF** inspects every packet *in the driver* – zero kernel overhead.
- **Automatic banning** when an IP exceeds your thresholds.
- **Dashboard** gives you live traffic, ping, and one‑click unban.

---

## ⚙️ Configuration

Edit `/opt/cavefilter/config/cavefilter.conf` after installation:

```ini
[network]
interface = eth0

[services]
tcp_ports = 22,25565-25600,80,443
udp_ports = 53

[rate_limits]
syn_per_sec = 100
handshake_per_sec = 5
dns_pps = 50
ssh_new_conn_per_sec = 5

[ban]
duration = 3600

[dashboard]
bind = 0.0.0.0
port = 5000

[xdp_mode]
mode = 0          # 0 = generic (works everywhere), 2 = native (10‑40 Mpps)
```

Restart to apply:
```bash
sudo systemctl restart cavefilter cavefilter-dash
```

---

## 🖥️ Dashboard Features

- **Live bandwidth** (in/out Mbps) with a line chart
- **Ping latency** to `1.1.1.1`
- **CPU & RAM** usage
- **Banned IPs** table with reason and **one‑click unban**
- **Dark / light theme** toggle (persistent)

---

## 🔓 Unban an IP

From the dashboard, click **Unban** – or use the API:

```bash
curl -X POST http://localhost:5000/api/unban \
  -H "Content-Type: application/json" \
  -d '{"ip":"1.2.3.4"}'
```

---

## 📈 Performance

| Mode         | Max pps / core | Requirements                     |
|--------------|----------------|----------------------------------|
| XDP generic  | ~1‑2 Mpps      | Any VPS (default)                |
| XDP native   | 10‑40 Mpps     | Supported NIC (e.g., Intel X710) |

Memory footprint < 50 MB even under heavy attack.

---

## 🧪 Test It

```bash
# SYN flood test
hping3 -S -p 25565 --flood <your-server-ip>
```

The attacker IP appears in the dashboard block list within seconds.

---

## 🤝 Contributing

Pull requests welcome. Areas of interest:

- New L7 protocol parsers (HTTP slowloris, QUIC)
- Prometheus / Grafana metrics
- Discord/Slack webhook alerts
- GeoIP country blocking

Open an issue to discuss large changes.

---

## 📜 License

MIT – see [LICENSE](LICENSE).

---

**Give it a ⭐ if it saved your server!**
