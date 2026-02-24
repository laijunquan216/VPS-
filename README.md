# VPS 自动重置与 PT 盒子部署面板

这是一个轻量化 Web 控制面板，用于管理多台 VPS 的到期重置与脚本化部署。

## 你关心的问题


### 0) 重启后 /tmp 丢失导致无法更新（你这次遇到的问题）

`/tmp` 是临时目录，重启后可能被清空，所以之前放在 `/tmp/vps-panel-src` 的源码目录会消失。
现在建议固定使用 `/opt/vps-panel-src`，并使用内置更新命令：

```bash
sudo vps-panel-update
```

如果是首次恢复，请执行：

```bash
git clone https://github.com/laijunquan216/VPS-.git /opt/vps-panel-src
cd /opt/vps-panel-src
sudo bash install_panel.sh
```

服务排查命令：

```bash
systemctl status vps-panel.service --no-pager
journalctl -u vps-panel.service -n 200 --no-pager
sudo systemctl restart vps-panel.service
```

### 1) 面板现在能不能安装？
可以。仓库已经包含完整代码与一键安装脚本 `install_panel.sh`，可直接在一台 Linux VPS（建议 Ubuntu 22.04+/Debian 12+）部署。

### 2) 如何在一台 VPS 上安装？

#### 方式A：推荐（一键安装）

```bash
git clone https://github.com/laijunquan216/VPS-.git /opt/vps-panel-src
cd /opt/vps-panel-src
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
cd /opt/vps-panel-src
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

- 页面分为三个独立页面：`服务器详情`、`服务器设置` 与 `面板管理`。
- `服务器设置` 页面可维护服务器基础信息（名称/IP/root密码/重置日/自动重置）。
- 重置任务、SSH任务2、SSH任务3 改为“全局任务”，只需在一个位置配置一次，所有服务器共用。
- 重置任务与SSH任务分离：先执行“重置任务”，重连后再执行 SSH任务2、SSH任务3。
- 当重置任务是 `InstallNET.sh -pwd` 时，会自动生成随机 root 密码并回写到面板。
- 重装后重连会优先尝试新生成密码，同时回退尝试旧密码；若最终可登录密码与预设不同，会自动回写面板。
- 系统会自动纠正常见中文引号（“”‘’），避免命令粘贴后执行异常。
- SSH任务执行时会自动设置 `TERM=xterm`，并清理 ANSI 颜色控制符；`tput`、虚拟化提示、防火墙放行建议等非致命告警会归类为提示，不再误报为错误。
- SSH任务2中的 `-p` 参数会在每次执行时自动替换为随机 12 位密码，避免固定密码。
- 服务器详情摘要支持“一键复制结果”。
- `服务器设置` 中完整任务日志改为按服务器分组展示，并支持折叠/展开查看。
- `面板管理` 支持数据备份下载与恢复，便于迁移到新服务器。
- 新增面板登录密码保护（初始密码 `admin`），可在 `面板管理` 页面修改。
- `服务器详情` 页面展示运行状态、摘要信息和一键执行入口，任务启动后状态会显示“执行中”。
- 多台服务器同一时段触发时会进入队列按顺序依次执行，避免面板主机并发过高导致失败（状态会先显示“排队中”再进入“执行中”）。
- `服务器详情` 每台服务器新增“是否续租”开关：开启续租后将跳过该服务器的定时重置；关闭后恢复按计划重置。
- `服务器详情` 支持“已出租/未出租”状态切换，并以卡片底色区分：未出租浅绿、已出租浅红，便于快速管理。
- `服务器设置` 支持手动填写“排序序号”，可自定义服务器显示顺序（序号越小越靠前）。
- `服务器详情` 移动端布局已优化（导航换行、卡片化展示、按钮栅格），安卓浏览器可更正常显示。
- 规则说明：`到期自动重置` 仅表示“允许进入定时重置流程”；若该服务器在详情页被切为`续租中`，则会被优先跳过，不会自动重置。

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
cd /opt/vps-panel-src
sudo bash install_panel.sh
```


如果你之前执行失败过，可能会留下损坏的 `.venv` 目录。新版脚本会自动重建；你也可以手动清理后重试：

```bash
cd /opt/vps-panel
sudo rm -rf .venv
cd /opt/vps-panel-src
sudo bash install_panel.sh
```


