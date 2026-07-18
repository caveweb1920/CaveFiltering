#!/bin/bash
set -e

# CaveFiltering Installer (default: system-wide with --break-system-packages)

if [ "$EUID" -ne 0 ]; then
    echo "Run as root: sudo bash install.sh [--use-venv]"
    exit 1
fi

USE_VENV=false
if [ "$1" == "--use-venv" ]; then
    USE_VENV=true
    echo "==> Using Python virtual environment"
else
    echo "==> Installing system-wide (--break-system-packages)"
    sleep 2
fi

# OS detection
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
    apt install -y clang llvm libbpf-dev linux-headers-$(uname -r) \
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

# Prepare target directory
mkdir -p /opt/cavefilter/config /opt/cavefilter/src/dashboard/templates

# Copy project files (from current directory, assumed to be repo root)
cp config/cavefilter.conf /opt/cavefilter/config/
cp src/cavefilter.c /opt/cavefilter/src/
cp src/cavefilter.py /opt/cavefilter/src/
cp src/dashboard/app.py /opt/cavefilter/src/dashboard/
cp src/dashboard/templates/index.html /opt/cavefilter/src/dashboard/templates/

# Python setup
if [ "$USE_VENV" = true ]; then
    python3 -m venv /opt/cavefilter/venv
    PYTHON_BIN="/opt/cavefilter/venv/bin/python"
    PIP_BIN="/opt/cavefilter/venv/bin/pip"
    PIP_EXTRA=""
else
    PYTHON_BIN="/usr/bin/python3"
    PIP_BIN="pip3"
    PIP_EXTRA="--break-system-packages"
fi

echo "==> Installing Python dependencies..."
$PIP_BIN install $PIP_EXTRA flask flask-socketio redis psutil gevent gevent-websocket

# Create systemd services dynamically
echo "==> Creating systemd units..."

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

# Reload and start
systemctl daemon-reload
systemctl enable redis-server
systemctl start redis-server

echo "==> Starting CaveFiltering..."
systemctl enable cavefilter
systemctl start cavefilter
systemctl enable cavefilter-dash
systemctl start cavefilter-dash

echo ""
echo "======================================"
echo " CaveFiltering installed!"
echo " Dashboard: http://$(hostname -I | awk '{print $1}'):5000"
echo " Python mode: $([ "$USE_VENV" = true ] && echo 'venv' || echo 'system')"
echo "======================================"
