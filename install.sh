#!/bin/bash
set -e

# --------------------------
# CaveFiltering Installer
# --------------------------

if [ "$EUID" -ne 0 ]; then
    echo "Please run as root: sudo bash install.sh [--break-system-packages]"
    exit 1
fi

MODE="venv"   # default: virtual environment
if [ "$1" == "--break-system-packages" ]; then
    MODE="system"
    echo "⚠️  WARNING: Installing system‑wide with --break-system-packages"
    echo "   This may break your OS Python environment."
    echo "   Press Ctrl+C within 5 seconds to cancel..."
    sleep 5
fi

# ---------- OS detection & dependencies ----------
if [ -f /etc/os-release ]; then
    . /etc/os-release
    OS=$ID
else
    echo "Unsupported OS"
    exit 1
fi

echo "==> Installing system packages..."
if [ "$OS" = "ubuntu" ] || [ "$OS" = "debian" ]; then
    apt update
    apt install -y \
        clang llvm libbpf-dev linux-headers-$(uname -r) \
        build-essential python3-pip python3-venv \
        python3-bpfcc bpfcc-tools \
        redis-server iptables ipset net-tools
elif [ "$OS" = "centos" ] || [ "$OS" = "rhel" ]; then
    yum install -y clang llvm bpftool kernel-headers python3-pip \
        redis iptables ipset net-tools
else
    echo "Unsupported OS"
    exit 1
fi

# ---------- Prepare target directory ----------
mkdir -p /opt/cavefilter/config /opt/cavefilter/src/dashboard/templates

# Copy project files (assumes you are in repo root)
cp config/cavefilter.conf /opt/cavefilter/config/
cp src/cavefilter.c /opt/cavefilter/src/
cp src/cavefilter.py /opt/cavefilter/src/
cp src/dashboard/app.py /opt/cavefilter/src/dashboard/
cp src/dashboard/templates/index.html /opt/cavefilter/src/dashboard/templates/

# ---------- Python environment ----------
if [ "$MODE" = "venv" ]; then
    echo "==> Creating virtual environment..."
    python3 -m venv /opt/cavefilter/venv
    PYTHON_BIN="/opt/cavefilter/venv/bin/python"
    PIP_BIN="/opt/cavefilter/venv/bin/pip"
else
    PYTHON_BIN="/usr/bin/python3"
    PIP_BIN="pip3"
fi

echo "==> Installing Python dependencies..."
$PIP_BIN install $([ "$MODE" = "system" ] && echo "--break-system-packages") \
    flask flask-socketio redis psutil gevent gevent-websocket

# ---------- Create systemd units (dynamic) ----------
echo "==> Setting up systemd services..."

# cavefilter.service
cat > /etc/systemd/system/cavefilter.service <<EOF
[Unit]
Description=CaveFiltering XDP DDoS Shield Daemon
After=network.target redis-server.service

[Service]
Type=simple
ExecStart=$PYTHON_BIN /opt/cavefilter/src/cavefilter.py
Restart=always
RestartSec=5
StandardOutput=journal
Environment=PYTHONUNBUFFERED=1

[Install]
WantedBy=multi-user.target
EOF

# cavefilter-dash.service
cat > /etc/systemd/system/cavefilter-dash.service <<EOF
[Unit]
Description=CaveFiltering Web Dashboard
After=network.target cavefilter.service

[Service]
Type=simple
ExecStart=$PYTHON_BIN /opt/cavefilter/src/dashboard/app.py
Restart=always
RestartSec=5
StandardOutput=journal

[Install]
WantedBy=multi-user.target
EOF

# ---------- Enable & start ----------
systemctl daemon-reload
systemctl enable redis-server
systemctl start redis-server

echo "==> Starting CaveFiltering services..."
systemctl enable cavefilter
systemctl start cavefilter
systemctl enable cavefilter-dash
systemctl start cavefilter-dash

echo ""
echo "======================================"
echo " CaveFiltering installed successfully!"
echo " Dashboard: http://$(hostname -I | awk '{print $1}'):5000"
echo " Python mode: $MODE"
echo "======================================"
