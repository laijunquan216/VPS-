# VPS 自动重置与 PT 盒子部署面板

这是一个轻量化 Web 控制面板，用于管理多台 VPS 的到期重置与脚本化部署。

## 你关心的问题

### 1) 面板现在能不能安装？
可以。仓库已经包含完整代码与一键安装脚本 `install_panel.sh`，可直接在一台 Linux VPS（建议 Ubuntu 22.04+/Debian 12+）部署。

### 2) 如何在一台 VPS 上安装？

#### 方式A：推荐（一键安装）

```bash
git clone https://github.com/laijunquan216/VPS-.git /tmp/vps-panel-src
cd /tmp/vps-panel-src
sudo bash install_panel.sh
```

安装完成后：

- 服务名：`vps-panel.service`
- 访问：`http://<你的VPS公网IP>:5000`
- 查看状态：`systemctl status vps-panel.service`
- 查看日志：`journalctl -u vps-panel.service -f`

> 如需修改端口/密钥，可安装前设置环境变量，例如：

```bash
sudo PANEL_PORT=8080 FLASK_SECRET='请改成随机长串' bash install_panel.sh
```

#### 方式B：手动安装

```bash
mkdir -p /opt/vps-panel
cp app.py requirements.txt /opt/vps-panel/
cp -r templates static /opt/vps-panel/
cd /opt/vps-panel
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
python app.py
```

默认监听 `0.0.0.0:5000`。

### 3) 仓库地址（用于同步更新）

- GitHub：`https://github.com/laijunquan216/VPS-`
- 后续每次有新改动，直接在服务器执行：

```bash
cd /tmp/vps-panel-src
git pull
sudo bash install_panel.sh
```

---


## DD 重装密码自动化（重要）

如果你在 SSH任务栏里使用类似下面命令：

```bash
wget --no-check-certificate -qO InstallNET.sh 'https://raw.githubusercontent.com/leitbogioro/Tools/master/Linux_reinstall/InstallNET.sh' && chmod a+x InstallNET.sh && bash InstallNET.sh -debian 11 -pwd 'YwjnPc28j6l2p1'
```

系统会在执行时自动把 `-pwd` 替换为随机密码，并回写到面板中的 root 密码字段（显示板块也会同步展示）。

## 功能

- Web UI 分为设置板块和显示板块，设置板块支持填写名称/IP/root密码/重置日期/SSH代码1~3。
- 按月自动检测到期服务器（北京时间凌晨1点检测），支持开启/关闭每台服务器自动重置。
- SSH任务栏支持代码1、代码2、代码3按顺序执行，并自动抽取Vertex/qBittorrent/FileBrowser结果摘要到显示板块。
- 若SSH任务中包含 `InstallNET.sh ... -pwd`，系统会在每次执行时自动生成随机 root 密码，替换命令中的 `-pwd` 参数并自动回写到面板。
- 支持手动触发单台服务器重置任务。

## 配置

可通过环境变量配置：

- `VPS_PANEL_DB`：数据库路径，默认 `panel.db`
- `CHECK_INTERVAL_MINUTES`：计划任务检测间隔（分钟），默认 `60`
- `FLASK_SECRET`：Flask 会话密钥（务必修改）
- `PANEL_HOST`：监听地址，默认 `0.0.0.0`
- `PANEL_PORT`：监听端口，默认 `5000`

## 安全建议（强烈建议）

1. 请把面板放在仅你可访问的管理机上（配合安全组/IP 白名单）。
2. 初次部署后立即修改 `FLASK_SECRET`。
3. 建议反向代理到 HTTPS（Nginx/Caddy）。
4. 脚本中避免打印敏感 Token（日志会保存输出）。

## 注意事项

1. DD 系统命令可能导致机器重启、断开 SSH，这是预期行为。
2. 受目标机器网络、镜像源、系统兼容性影响，DD/安装脚本可能失败，请从日志排查。


## 常见安装问题

### 报错：`ensurepip is not available` / `python3-venv` 缺失

这个项目的安装脚本现在会自动尝试安装 `python3-venv` 和 `python3-pip`（Debian/Ubuntu 会走 `apt-get`）。
如果你的系统源有问题，也可以手动执行：

```bash
sudo apt-get update
sudo apt-get install -y python3-venv python3-pip
```

然后重新执行：

```bash
cd /tmp/vps-panel-src
sudo bash install_panel.sh
```


如果你之前执行失败过，可能会留下损坏的 `.venv` 目录。新版脚本会自动重建；你也可以手动清理后重试：

```bash
cd /opt/vps-panel
sudo rm -rf .venv
cd /tmp/vps-panel-src
sudo bash install_panel.sh
```


