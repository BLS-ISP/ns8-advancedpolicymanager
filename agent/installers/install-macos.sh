#!/usr/bin/env bash
set -euo pipefail

SERVER_URL="${APM_SERVER_URL:-${SERVER_URL:-{{SERVER_URL}}}}"
TOKEN="${APM_TOKEN:-${APM_ENROLL_TOKEN:-${ENROLLMENT_TOKEN:-{{ENROLLMENT_TOKEN}}}}}"
STATE_DIR="/Library/Application Support/NS8PolicyAgent"
BIN_PATH="/usr/local/bin/ns8-policy-agent"
PLIST_PATH="/Library/LaunchDaemons/org.nethserver.policyagent.plist"

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
  echo "Error: install-macos.sh must be executed as root (use sudo)." >&2
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
if [[ "$UNAME_M" == "arm64" || "$UNAME_M" == "aarch64" ]]; then
  ARCH="aarch64"
else
  ARCH="x86_64"
fi

mkdir -p /usr/local/bin
mkdir -p -m 0700 "$STATE_DIR"

TMP_BIN="$(mktemp /tmp/ns8-policy-agent.XXXXXX)"
trap 'rm -f "$TMP_BIN"' EXIT

DOWNLOAD_URL="${SERVER_URL}/api/v1/installers/binaries/macos/${ARCH}"
echo "[ns8-policy-agent] Downloading macOS agent binary from ${DOWNLOAD_URL} ..."
if ! curl -fsSL "$DOWNLOAD_URL" -o "$TMP_BIN"; then
  if [[ "$ARCH" == "aarch64" ]]; then
    FALLBACK_URL="${SERVER_URL}/api/v1/installers/binaries/macos/x86_64"
    echo "[ns8-policy-agent] Falling back to x86_64 binary via ${FALLBACK_URL} ..."
    curl -fsSL "$FALLBACK_URL" -o "$TMP_BIN"
  else
    exit 1
  fi
fi

launchctl bootout system "$PLIST_PATH" >/dev/null 2>&1 || true
install -m 0755 "$TMP_BIN" "$BIN_PATH"

echo "[ns8-policy-agent] Enrolling Mac with ${SERVER_URL} ..."
"$BIN_PATH" enroll --server "$SERVER_URL" --token "$TOKEN" --state-dir "$STATE_DIR"

cat > "$PLIST_PATH" <<EOF
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>Label</key>
  <string>org.nethserver.policyagent</string>
  <key>ProgramArguments</key>
  <array>
    <string>${BIN_PATH}</string>
    <string>daemon</string>
    <string>--state-dir</string>
    <string>${STATE_DIR}</string>
  </array>
  <key>RunAtLoad</key>
  <true/>
  <key>KeepAlive</key>
  <true/>
  <key>StandardOutPath</key>
  <string>/var/log/ns8-policy-agent.log</string>
  <key>StandardErrorPath</key>
  <string>/var/log/ns8-policy-agent.err.log</string>
</dict>
</plist>
EOF

chown root:wheel "$PLIST_PATH"
chmod 0644 "$PLIST_PATH"
launchctl bootstrap system "$PLIST_PATH" >/dev/null 2>&1 || launchctl load -w "$PLIST_PATH"

echo "[ns8-policy-agent] macOS LaunchDaemon org.nethserver.policyagent installed and loaded."
