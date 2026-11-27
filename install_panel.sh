#!/usr/bin/env bash
set -euo pipefail

APP_DIR=${APP_DIR:-/opt/vps-panel}
SRC_DIR=${SRC_DIR:-/opt/vps-panel-src}
REPO_URL=${REPO_URL:-https://github.com/laijunquan216/VPS-.git}
PYTHON_BIN=${PYTHON_BIN:-python3}
PANEL_PORT=${PANEL_PORT:-5000}
PANEL_HOST=${PANEL_HOST:-127.0.0.1}
CHECK_INTERVAL_MINUTES=${CHECK_INTERVAL_MINUTES:-60}
PANEL_COOKIE_SECURE=${PANEL_COOKIE_SECURE:-0}

# Preserve a previously generated strong key across updates; replace known weak defaults.
EXISTING_FLASK_SECRET=""
if [ -f "$APP_DIR/.env" ]; then
  EXISTING_FLASK_SECRET="$(sed -n 's/^FLASK_SECRET=//p' "$APP_DIR/.env" | tail -n 1)"
fi
if [ -n "${FLASK_SECRET:-}" ]; then
  PANEL_FLASK_SECRET="$FLASK_SECRET"
elif [ "${#EXISTING_FLASK_SECRET}" -ge 64 ] && [ "$EXISTING_FLASK_SECRET" != "change-me" ] && [ "$EXISTING_FLASK_SECRET" != "change-me-please" ]; then
  PANEL_FLASK_SECRET="$EXISTING_FLASK_SECRET"
else
  PANEL_FLASK_SECRET="$("$PYTHON_BIN" -c 'import secrets; print(secrets.token_hex(32))')"
  echo "[SECURITY] Generated a new random FLASK_SECRET."
fi

install_python_venv_deps() {
  if "$PYTHON_BIN" -m ensurepip --version >/dev/null 2>&1; then
    return
  fi

  echo "[INFO] 检测到 ensurepip 不可用，尝试自动安装 python3-venv/python3-pip ..."
  if command -v apt-get >/dev/null 2>&1; then
    export DEBIAN_FRONTEND=noninteractive
    apt-get update -y
    apt-get install -y python3-venv python3-pip
  elif command -v dnf >/dev/null 2>&1; then
    dnf install -y python3 python3-pip
  elif command -v yum >/dev/null 2>&1; then
    yum install -y python3 python3-pip
  else
    echo "[ERROR] 无法自动安装 Python 依赖，请手动安装 python3-venv 和 python3-pip 后重试。"
    exit 1
  fi
}

if ! command -v "$PYTHON_BIN" >/dev/null 2>&1; then
  echo "[ERROR] python3 未安装，请先安装 Python 3.10+"
  exit 1
fi

install_python_venv_deps

mkdir -p "$APP_DIR"
cp -f app.py requirements.txt "$APP_DIR"/
mkdir -p "$APP_DIR/templates" "$APP_DIR/static"
cp -f templates/*.html "$APP_DIR/templates/"
cp -f static/style.css "$APP_DIR/static/"

cd "$APP_DIR"

# 兼容上次失败后留下的半成品 .venv 目录
if [ ! -x .venv/bin/python ] || [ ! -f .venv/bin/activate ]; then
  rm -rf .venv
  "$PYTHON_BIN" -m venv .venv
fi

source .venv/bin/activate
pip install --upgrade pip
pip install -r requirements.txt

cat > "$APP_DIR/.env" <<EOF
VPS_PANEL_DB=$APP_DIR/panel.db
CHECK_INTERVAL_MINUTES=$CHECK_INTERVAL_MINUTES
FLASK_SECRET=$PANEL_FLASK_SECRET
PANEL_HOST=$PANEL_HOST
PANEL_PORT=$PANEL_PORT
PANEL_COOKIE_SECURE=$PANEL_COOKIE_SECURE
SSH_RECONNECT_TIMEOUT_SECONDS=${SSH_RECONNECT_TIMEOUT_SECONDS:-1800}
SSH_RETRY_INTERVAL_SECONDS=${SSH_RETRY_INTERVAL_SECONDS:-15}
POST_REINSTALL_WAIT_SECONDS=${POST_REINSTALL_WAIT_SECONDS:-30}
EOF
chmod 600 "$APP_DIR/.env"
mkdir -p "$APP_DIR/uploaded_data"
chmod 700 "$APP_DIR/uploaded_data"

cat > /etc/systemd/system/vps-panel.service <<EOF
[Unit]
Description=VPS Auto Reset Panel
After=network.target

[Service]
Type=simple
WorkingDirectory=$APP_DIR
EnvironmentFile=$APP_DIR/.env
ExecStart=$APP_DIR/.venv/bin/python $APP_DIR/app.py
Restart=always
RestartSec=3
UMask=0077

[Install]
WantedBy=multi-user.target
EOF

# 提供持久化更新命令，避免 /tmp 目录重启后丢失
cat > /usr/local/bin/vps-panel-update <<EOF
#!/usr/bin/env bash
set -euo pipefail
mkdir -p "$SRC_DIR"
if [ ! -d "$SRC_DIR/.git" ]; then
  rm -rf "$SRC_DIR"
  git clone "$REPO_URL" "$SRC_DIR"
else
  git -C "$SRC_DIR" pull --ff-only
fi
cd "$SRC_DIR"
sudo bash install_panel.sh
EOF
chmod +x /usr/local/bin/vps-panel-update

systemctl daemon-reload
systemctl enable vps-panel.service
# 更新安装时重启面板服务即可，无需重启整台服务器
systemctl restart vps-panel.service

echo "[OK] 安装完成"
echo "[INFO] 面板服务已重启"
echo "[INFO] 面板默认仅监听 127.0.0.1:$PANEL_PORT，请通过 HTTPS 反向代理访问。"
echo "[INFO] 服务状态: systemctl status vps-panel.service"
echo "[INFO] 后续更新命令: sudo vps-panel-update"
