#!/usr/bin/env bash
set -euo pipefail

DOMAIN=""
EMAIL=""
PASSWORD=""
DRY_RUN=0
RELEASE_REPO="ericyiu9819/Ericyiu420"
RELEASE_VERSION="latest"

usage() {
  cat <<'USAGE'
Usage:
  sudo bash scripts/install-trojan.sh --domain example.com --email admin@example.com --password 'strong-password'

Options:
  --domain     Domain name pointing to this VPS
  --email      ACME registration email
  --password   Trojan password used by Shadowrocket
  --repo       GitHub repo for prebuilt binary, default ericyiu9819/Ericyiu420
  --version    Release tag or latest, default latest
  --dry-run    Render checks and config without changing the system
USAGE
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --domain) DOMAIN="${2:-}"; shift 2 ;;
    --email) EMAIL="${2:-}"; shift 2 ;;
    --password) PASSWORD="${2:-}"; shift 2 ;;
    --repo) RELEASE_REPO="${2:-}"; shift 2 ;;
    --version) RELEASE_VERSION="${2:-}"; shift 2 ;;
    --dry-run) DRY_RUN=1; shift ;;
    -h|--help) usage; exit 0 ;;
    *) echo "Unknown option: $1" >&2; usage; exit 2 ;;
  esac
done

if [[ -z "$DOMAIN" || -z "$EMAIL" || -z "$PASSWORD" ]]; then
  usage
  exit 2
fi

if [[ "${EUID}" -ne 0 && "$DRY_RUN" -eq 0 ]]; then
  echo "Run as root, or pass --dry-run." >&2
  exit 1
fi

if command -v ss >/dev/null 2>&1 && ss -ltn "( sport = :443 )" | grep -q ':443'; then
  if [[ "$DRY_RUN" -eq 1 ]]; then
    echo "[dry-run] Port 443 is currently in use."
  else
    echo "Port 443 is already in use. Stop the existing service before running this installer." >&2
    exit 1
  fi
fi

CONFIG_DIR="/etc/lowprint"
CONFIG_PATH="${CONFIG_DIR}/server.toml"
SERVICE_PATH="/etc/systemd/system/lowprint-trojan.service"
BIN_PATH="/usr/local/bin/proxy-server"
CERT_PATH="/etc/letsencrypt/live/${DOMAIN}/fullchain.pem"
KEY_PATH="/etc/letsencrypt/live/${DOMAIN}/privkey.pem"
NODE_NAME="lowprint-${DOMAIN}"

toml_string() {
  python3 -c 'import json, sys; print(json.dumps(sys.argv[1]))' "$1"
}

render_config() {
  cat <<EOF_CONFIG
log_level = "info"
listen = "0.0.0.0:443"
domain = $(toml_string "$DOMAIN")
password = $(toml_string "$PASSWORD")
cert_path = $(toml_string "$CERT_PATH")
key_path = $(toml_string "$KEY_PATH")
node_name = $(toml_string "$NODE_NAME")
tcp_nodelay = true
EOF_CONFIG
}

render_service() {
  cat <<EOF_SERVICE
[Unit]
Description=Lowprint Trojan Server
After=network-online.target
Wants=network-online.target

[Service]
ExecStart=${BIN_PATH} --config ${CONFIG_PATH}
Restart=on-failure
RestartSec=3
LimitNOFILE=1048576
NoNewPrivileges=true

[Install]
WantedBy=multi-user.target
EOF_SERVICE
}

if [[ "$DRY_RUN" -eq 1 ]]; then
  echo "[dry-run] Would install packages: certbot ca-certificates python3"
  echo "[dry-run] Would download prebuilt binary from ${RELEASE_REPO} release ${RELEASE_VERSION}"
  echo "[dry-run] Would request certificate for ${DOMAIN} with ${EMAIL}"
  echo "[dry-run] Would write ${CONFIG_PATH}:"
  render_config
  echo "[dry-run] Would write ${SERVICE_PATH}:"
  render_service
  echo "[dry-run] Shadowrocket URI:"
  DOMAIN="$DOMAIN" PASSWORD="$PASSWORD" NODE_NAME="$NODE_NAME" python3 - <<'PY'
import os
from urllib.parse import quote
domain = os.environ["DOMAIN"]
password = os.environ["PASSWORD"]
node_name = os.environ["NODE_NAME"]
print(f"trojan://{quote(password)}@{domain}:443?sni={quote(domain)}#{quote(node_name)}")
PY
  exit 0
fi

apt-get update
apt-get install -y certbot ca-certificates python3 curl

certbot certonly --standalone --non-interactive --agree-tos --email "$EMAIL" -d "$DOMAIN"

download_release_binary() {
  local url
  if [[ "$RELEASE_VERSION" == "latest" ]]; then
    url="https://github.com/${RELEASE_REPO}/releases/latest/download/proxy-server-linux-amd64"
  else
    url="https://github.com/${RELEASE_REPO}/releases/download/${RELEASE_VERSION}/proxy-server-linux-amd64"
  fi
  curl -fL --retry 3 --connect-timeout 10 -o "$BIN_PATH" "$url"
  chmod 0755 "$BIN_PATH"
}

if download_release_binary; then
  :
elif [[ -x "./target/release/proxy-server" ]]; then
  install -m 0755 ./target/release/proxy-server "$BIN_PATH"
elif [[ -x "./bin/proxy-server-linux-amd64" ]]; then
  install -m 0755 ./bin/proxy-server-linux-amd64 "$BIN_PATH"
elif [[ -f "./bin/proxy-server-linux-amd64.b64" ]]; then
  base64 -d ./bin/proxy-server-linux-amd64.b64 > "$BIN_PATH"
  chmod 0755 "$BIN_PATH"
elif command -v cargo >/dev/null 2>&1; then
  cargo build --release --bin proxy-server
  install -m 0755 ./target/release/proxy-server "$BIN_PATH"
else
  echo "Missing compiled binary, base64 binary, and cargo is not installed." >&2
  exit 1
fi

install -d -m 0755 "$CONFIG_DIR"
render_config > "$CONFIG_PATH"
chmod 0600 "$CONFIG_PATH"
render_service > "$SERVICE_PATH"

cat >/etc/sysctl.d/99-lowprint.conf <<'EOF_SYSCTL'
net.ipv4.tcp_congestion_control=bbr
net.core.default_qdisc=fq
net.core.somaxconn=65535
net.ipv4.tcp_fastopen=3
EOF_SYSCTL
sysctl --system >/dev/null || true

systemctl daemon-reload
systemctl enable --now lowprint-trojan.service

install -d -m 0755 /etc/letsencrypt/renewal-hooks/deploy
cat >/etc/letsencrypt/renewal-hooks/deploy/lowprint-trojan-restart.sh <<'EOF_RENEW'
#!/usr/bin/env bash
systemctl restart lowprint-trojan.service
EOF_RENEW
chmod 0755 /etc/letsencrypt/renewal-hooks/deploy/lowprint-trojan-restart.sh

echo "Shadowrocket URI:"
"$BIN_PATH" --config "$CONFIG_PATH" uri
