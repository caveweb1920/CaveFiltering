#!/bin/bash
set -e

echo "==> CaveFiltering Installer"
echo "Detecting OS..."

if [ -f /etc/os-release ]; then
    . /etc/os-release
    OS=$ID
else
    echo "Unsupported OS"
    exit 1
fi

# Install dependencies
if [ "$OS" = "ubuntu" ] || [ "$OS" = "debian" ]; then
    apt update
    apt install -y clang llvm libbpf-dev linux-headers-$(uname -r) \
        build-essential python3-pip python3-bpfcc bpfcc-tools \
        redis-server iptables ipset net-tools
elif [ "$OS" = "centos" ] || [ "$OS" = "rhel" ]; then
    yum install -y clang llvm bpftool kernel-headers python3-pip \
        redis iptables ipset net-tools
    pip3 install bcc
else
    echo "Unsupported OS"
    exit 1
fi

pip3 install flask flask-socketio redis psutil gevent gevent-websocket

# Create directory structure
mkdir -p /opt/cavefilter/{config,src/dashboard/templates,systemd}
cp config/cavefilter.conf /opt/cavefilter/config/
cp src/cavefilter.c /opt/cavefilter/src/
cp src/cavefilter.py /opt/cavefilter/src/
cp src/dashboard/app.py /opt/cavefilter/src/dashboard/
cp src/dashboard/templates/index.html /opt/cavefilter/src/dashboard/templates/
cp systemd/cavefilter.service /opt/cavefilter/systemd/
cp systemd/cavefilter-dash.service /opt/cavefilter/systemd/

# Replace placeholder paths in config and services
sed -i "s|/opt/cavefilter|/opt/cavefilter|g" /opt/cavefilter/systemd/cavefilter.service
sed -i "s|/opt/cavefilter|/opt/cavefilter|g" /opt/cavefilter/systemd/cavefilter-dash.service

# Install systemd units
cp /opt/cavefilter/systemd/*.service /etc/systemd/system/
systemctl daemon-reload
systemctl enable redis-server
systemctl start redis-server
systemctl enable cavefilter
systemctl start cavefilter
systemctl enable cavefilter-dash
systemctl start cavefilter-dash

echo "==> CaveFiltering installed and running."
echo "Dashboard: http://$(hostname -I | awk '{print $1}'):5000"
