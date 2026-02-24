# VPS 自动重置与 PT 部署面板

轻量 Web 面板，用于统一管理多台 VPS 的定时重置、SSH 自动化任务、流量统计与通知。

## 快速安装

```bash
git clone https://github.com/laijunquan216/VPS-.git /opt/vps-panel-src
cd /opt/vps-panel-src
sudo bash install_panel.sh
```

安装后：
- 访问：`http://<你的服务器IP>:5000`
- 服务：`vps-panel.service`
- 查看状态：`systemctl status vps-panel.service`
- 查看日志：`journalctl -u vps-panel.service -f`

更新：

```bash
cd /opt/vps-panel-src
git pull
sudo bash install_panel.sh
```

## 核心功能

- 三个页面：`服务器详情`、`服务器设置`、`面板管理`。
- 全局任务：重置任务 + SSH任务2 + SSH任务3（一次配置，多机复用）。
- 定时重置：按每台服务器自定义 `重置日 + 时/分` 执行。
- 强容错队列：串行执行、失败可重试（可配置次数与退避秒数）、重启后自动恢复未完成任务。
- 状态控制：续租中自动跳过定时重置；支持已出租/未出租标记。
- 自动密码处理：
  - DD 重装命令 `InstallNET.sh -pwd` 自动替换随机 root 密码并回写。
  - SSH任务2 固定 `-p` 自动替换为随机 12 位密码。
- 内置 Agent 流量统计：显示上传/下载/总流量（按重置周期）。
- 邮件通知：
  - 支持 SMTP 配置 + 测试邮件按钮。
  - 定时重置按同一时间批次合并发送一封汇总邮件（成功/失败/跳过）。
- 备份与恢复：支持面板数据导出/导入迁移。
- 面板登录保护：默认密码 `admin`，可在面板管理页修改。

## 使用要点

### 1) DD 重装密码自动注入
当重置任务中包含 `InstallNET.sh -pwd` 时，面板会自动注入随机密码并回写服务器密码字段。

### 2) Agent 上报地址
请在全局任务中正确填写“面板公网地址（Agent上报地址）”，例如：

```text
http://你的面板IP:5000
```

否则远端 VPS 无法回传流量数据。

### 3) 邮件通知说明
- 手动“立即执行”：按单台任务结果记录。
- 定时任务：同一时刻触发的服务器会合并成一封汇总邮件，避免刷屏。

## 环境变量

- `VPS_PANEL_DB`：数据库路径（默认 `panel.db`）
- `FLASK_SECRET`：会话密钥（建议修改）
- `PANEL_HOST`：监听地址（默认 `0.0.0.0`）
- `PANEL_PORT`：监听端口（默认 `5000`）
- `SSH_RECONNECT_TIMEOUT_SECONDS`：重连超时秒数（默认 `1800`）
- `SSH_RETRY_INTERVAL_SECONDS`：重连重试间隔秒数（默认 `15`）
- `DEFAULT_MAX_RETRIES`：默认重试次数（默认 `2`）
- `DEFAULT_RETRY_BACKOFF_SECONDS`：默认退避秒数（默认 `60,180`）

## 常见问题

### 1) 更新后源码目录丢失
请固定使用 `/opt/vps-panel-src`，不要放在 `/tmp`（重启可能被清空）。

### 2) 缺少 venv/pip
Debian/Ubuntu 可执行：

```bash
sudo apt-get update
sudo apt-get install -y python3-venv python3-pip
```

### 3) 服务异常

```bash
systemctl status vps-panel.service --no-pager
journalctl -u vps-panel.service -n 200 --no-pager
sudo systemctl restart vps-panel.service
```
