#!/usr/bin/env bash
set -euo pipefail

SERVER_URL="${APM_SERVER_URL:-${SERVER_URL:-{{SERVER_URL}}}}"
TOKEN="${APM_TOKEN:-${APM_ENROLL_TOKEN:-${ENROLLMENT_TOKEN:-{{ENROLLMENT_TOKEN}}}}}"
STATE_DIR="/var/lib/ns8-policy-agent"
BIN_PATH="/usr/local/bin/ns8-policy-agent"
SERVICE_PATH="/etc/systemd/system/ns8-policy-agent.service"

while [[ $# -gt 0 ]]; do
  case "$1" in
    --server)
      SERVER_URL="$2"
      shift 2
      ;;
    --token)
      TOKEN="$2"
      shift 2
      ;;
    --state-dir)
      STATE_DIR="$2"
      shift 2
      ;;
    *)
      echo "Unknown option: $1" >&2
      exit 1
      ;;
  esac
done

if [[ "$(id -u)" -ne 0 ]]; then
  echo "Error: install-linux.sh must be executed as root (use sudo)." >&2
  exit 1
fi

if [[ -z "$SERVER_URL" || "$SERVER_URL" == "{{"*"}}" ]]; then
  echo "Error: Server URL is required (--server <URL> or APM_SERVER_URL)." >&2
  exit 1
fi

if [[ -z "$TOKEN" || "$TOKEN" == "{{"*"}}" ]]; then
  echo "Error: Enrollment token is required (--token <TOKEN> or APM_ENROLL_TOKEN)." >&2
  exit 1
fi

SERVER_URL="${SERVER_URL%/}"
UNAME_M="$(uname -m)"
case "$UNAME_M" in
  x86_64|amd64)
    ARCH="x86_64"
    ;;
  aarch64|arm64)
    ARCH="aarch64"
    ;;
  *)
    ARCH="x86_64"
    ;;
esac

DOWNLOAD_URL="${SERVER_URL}/api/v1/installers/binaries/linux/${ARCH}"
echo "[ns8-policy-agent] Downloading agent binary from ${DOWNLOAD_URL} ..."

mkdir -p /usr/local/bin
mkdir -p -m 0700 "$STATE_DIR"

TMP_BIN="$(mktemp /tmp/ns8-policy-agent.XXXXXX)"
trap 'rm -f "$TMP_BIN"' EXIT

if command -v curl >/dev/null 2>&1; then
  curl -fsSL "$DOWNLOAD_URL" -o "$TMP_BIN"
elif command -v wget >/dev/null 2>&1; then
  wget -qO "$TMP_BIN" "$DOWNLOAD_URL"
else
  echo "Error: Neither curl nor wget is installed." >&2
  exit 1
fi

systemctl stop ns8-policy-agent.service >/dev/null 2>&1 || true
install -m 0755 "$TMP_BIN" "$BIN_PATH"

echo "[ns8-policy-agent] Enrolling with ${SERVER_URL} ..."
"$BIN_PATH" enroll --server "$SERVER_URL" --token "$TOKEN" --state-dir "$STATE_DIR"

cat > "$SERVICE_PATH" <<EOF
[Unit]
Description=NS8 Advanced Policy Manager Client Agent
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
ExecStart=${BIN_PATH} daemon --state-dir ${STATE_DIR}
Restart=always
RestartSec=15
User=root

[Install]
WantedBy=multi-user.target
EOF

chmod 0644 "$SERVICE_PATH"
systemctl daemon-reload
systemctl enable --now ns8-policy-agent.service

echo "[ns8-policy-agent] Linux systemd service installed and started successfully."
