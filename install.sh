#!/bin/bash
# ZoyaChat Relay Server — One-line Installer
# Usage: curl -fsSL https://raw.githubusercontent.com/jason-zoyachat/zoyachat-relay/main/install.sh | bash

set -e

echo "=== ZoyaChat Relay Installer ==="

# 1. Install Node.js 20 if not present
if ! command -v node &>/dev/null || [[ $(node -v | cut -d. -f1 | tr -d v) -lt 20 ]]; then
  echo "[1/5] Installing Node.js 20..."
  curl -fsSL https://deb.nodesource.com/setup_20.x | sudo -E bash -
  sudo apt install -y nodejs
else
  echo "[1/5] Node.js $(node -v) already installed"
fi

# 2. Install PM2 if not present
if ! command -v pm2 &>/dev/null; then
  echo "[2/5] Installing PM2..."
  sudo npm install -g pm2
else
  echo "[2/5] PM2 already installed"
fi

# 3. Download relay code
echo "[3/5] Downloading ZoyaChat Relay..."
sudo mkdir -p /opt/relay
cd /opt/relay
if [ -d ".git" ]; then
  sudo git pull
else
  sudo git clone https://github.com/jason-zoyachat/zoyachat-relay.git .
fi

# 4. Install dependencies
echo "[4/5] Installing dependencies..."
sudo npm install --production

# 5. Start with PM2
echo "[5/5] Starting Relay..."
pm2 delete zoyachat-relay 2>/dev/null || true
pm2 start relay-ws.mjs --name zoyachat-relay
pm2 save
pm2 startup systemd -u root --hp /root 2>/dev/null || true

# Open firewall
sudo ufw allow 9090/tcp 2>/dev/null || true
sudo ufw allow 9091/tcp 2>/dev/null || true
sudo ufw --force enable 2>/dev/null || true

# Verify
echo ""
echo "=== Installation Complete ==="
IP=$(curl -s ifconfig.me 2>/dev/null || echo "YOUR_IP")
echo "Relay address: ws://${IP}:9090"
echo "Health check:  http://${IP}:9091/health"
echo ""
curl -s http://localhost:9091/health 2>/dev/null && echo "Relay is running!" || echo "Waiting for startup..."
