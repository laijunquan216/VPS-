import os
import re
import secrets
import shlex
import sqlite3
import string
import threading
import time
from queue import Queue
from contextlib import closing
from datetime import datetime, timedelta
from functools import wraps
from io import BytesIO
from zoneinfo import ZoneInfo

import paramiko
from apscheduler.schedulers.background import BackgroundScheduler
from flask import (
    Flask,
    flash,
    redirect,
    render_template,
    request,
    send_file,
    Response,
    jsonify,
    session,
    url_for,
)
from werkzeug.security import check_password_hash, generate_password_hash

DB_PATH = os.environ.get("VPS_PANEL_DB", "panel.db")
PANEL_HOST = os.environ.get("PANEL_HOST", "0.0.0.0")
PANEL_PORT = int(os.environ.get("PANEL_PORT", "5000"))
TIMEZONE = ZoneInfo("Asia/Shanghai")

SSH_RECONNECT_TIMEOUT_SECONDS = int(os.environ.get("SSH_RECONNECT_TIMEOUT_SECONDS", "1800"))
SSH_RETRY_INTERVAL_SECONDS = int(os.environ.get("SSH_RETRY_INTERVAL_SECONDS", "15"))
POST_REINSTALL_WAIT_SECONDS = int(os.environ.get("POST_REINSTALL_WAIT_SECONDS", "30"))
AGENT_REPORT_INTERVAL_SECONDS = int(os.environ.get("AGENT_REPORT_INTERVAL_SECONDS", "60"))

app = Flask(__name__)
app.secret_key = os.environ.get("FLASK_SECRET", "change-me")
ANSI_ESCAPE_RE = re.compile(r"\x1B(?:[@-Z\-_]|\[[0-?]*[ -/]*[@-~]|\][^\x07]*(?:\x07|\x1B\\)|\([A-Za-z0-9])")
TASK_QUEUE = Queue()


def get_conn():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def ensure_column(conn, table_name, col_def):
    col_name = col_def.split()[0]
    current_cols = {row["name"] for row in conn.execute(f"PRAGMA table_info({table_name})").fetchall()}
    if col_name not in current_cols:
        conn.execute(f"ALTER TABLE {table_name} ADD COLUMN {col_def}")


def init_db():
    with closing(get_conn()) as conn:
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS servers (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                name TEXT NOT NULL,
                ip TEXT NOT NULL,
                ssh_port INTEGER NOT NULL DEFAULT 22,
                ssh_user TEXT NOT NULL DEFAULT 'root',
                ssh_password TEXT NOT NULL,
                reset_day INTEGER NOT NULL,
                auto_reset INTEGER NOT NULL DEFAULT 1,
                is_renewed INTEGER NOT NULL DEFAULT 0,
                is_rented INTEGER NOT NULL DEFAULT 0,
                sort_order INTEGER NOT NULL DEFAULT 0,
                agent_token TEXT NOT NULL DEFAULT '',
                period_key TEXT NOT NULL DEFAULT '',
                period_upload_bytes INTEGER NOT NULL DEFAULT 0,
                period_download_bytes INTEGER NOT NULL DEFAULT 0,
                last_agent_rx_bytes INTEGER NOT NULL DEFAULT 0,
                last_agent_tx_bytes INTEGER NOT NULL DEFAULT 0,
                last_agent_report_at TEXT,
                last_reset_at TEXT
            )
            """
        )
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS global_config (
                id INTEGER PRIMARY KEY CHECK (id = 1),
                reset_command TEXT NOT NULL DEFAULT '',
                ssh_command_2 TEXT NOT NULL DEFAULT '',
                ssh_command_3 TEXT NOT NULL DEFAULT '',
                agent_install_command TEXT NOT NULL DEFAULT '',
                panel_base_url TEXT NOT NULL DEFAULT '',
                panel_password_hash TEXT,
                updated_at TEXT
            )
            """
        )
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS job_logs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                server_id INTEGER NOT NULL,
                status TEXT NOT NULL,
                summary TEXT NOT NULL DEFAULT '',
                output TEXT NOT NULL,
                created_at TEXT NOT NULL,
                FOREIGN KEY(server_id) REFERENCES servers(id)
            )
            """
        )

        ensure_column(conn, "servers", "last_reset_at TEXT")
        ensure_column(conn, "servers", "is_renewed INTEGER NOT NULL DEFAULT 0")
        ensure_column(conn, "servers", "is_rented INTEGER NOT NULL DEFAULT 0")
        ensure_column(conn, "servers", "sort_order INTEGER NOT NULL DEFAULT 0")
        ensure_column(conn, "servers", "agent_token TEXT NOT NULL DEFAULT ''")
        ensure_column(conn, "servers", "period_key TEXT NOT NULL DEFAULT ''")
        ensure_column(conn, "servers", "period_upload_bytes INTEGER NOT NULL DEFAULT 0")
        ensure_column(conn, "servers", "period_download_bytes INTEGER NOT NULL DEFAULT 0")
        ensure_column(conn, "servers", "last_agent_rx_bytes INTEGER NOT NULL DEFAULT 0")
        ensure_column(conn, "servers", "last_agent_tx_bytes INTEGER NOT NULL DEFAULT 0")
        ensure_column(conn, "servers", "last_agent_report_at TEXT")
        ensure_column(conn, "job_logs", "summary TEXT NOT NULL DEFAULT ''")
        ensure_column(conn, "global_config", "panel_password_hash TEXT")
        ensure_column(conn, "global_config", "agent_install_command TEXT NOT NULL DEFAULT ''")
        ensure_column(conn, "global_config", "panel_base_url TEXT NOT NULL DEFAULT ''")
        conn.execute("INSERT OR IGNORE INTO global_config(id) VALUES (1)")
        current_hash = conn.execute("SELECT panel_password_hash FROM global_config WHERE id = 1").fetchone()[0]
        if not current_hash:
            conn.execute(
                "UPDATE global_config SET panel_password_hash = ?, updated_at = ? WHERE id = 1",
                (generate_password_hash("admin"), datetime.now(TIMEZONE).strftime("%Y-%m-%d %H:%M:%S")),
            )
        conn.commit()

def list_servers():
    with closing(get_conn()) as conn:
        return conn.execute("SELECT * FROM servers ORDER BY sort_order ASC, id ASC").fetchall()


def get_server(server_id):
    with closing(get_conn()) as conn:
        return conn.execute("SELECT * FROM servers WHERE id=?", (server_id,)).fetchone()


def get_global_config():
    with closing(get_conn()) as conn:
        conn.execute("INSERT OR IGNORE INTO global_config(id) VALUES (1)")
        row = conn.execute("SELECT * FROM global_config WHERE id=1").fetchone()
        conn.commit()
        return row


def update_global_config(reset_command, ssh_command_2, ssh_command_3, agent_install_command, panel_base_url):
    with closing(get_conn()) as conn:
        conn.execute(
            """
            UPDATE global_config
            SET reset_command=?, ssh_command_2=?, ssh_command_3=?, agent_install_command=?, panel_base_url=?, updated_at=?
            WHERE id=1
            """,
            (
                reset_command.strip(),
                ssh_command_2.strip(),
                ssh_command_3.strip(),
                agent_install_command.strip(),
                panel_base_url.strip(),
                datetime.now(TIMEZONE).strftime("%Y-%m-%d %H:%M:%S"),
            ),
        )
        conn.commit()


def verify_panel_password(password):
    global_cfg = get_global_config()
    stored_hash = global_cfg["panel_password_hash"] if global_cfg else None
    if not stored_hash:
        return password == "admin"
    return check_password_hash(stored_hash, password)


def update_panel_password(new_password):
    with closing(get_conn()) as conn:
        conn.execute(
            "UPDATE global_config SET panel_password_hash = ?, updated_at = ? WHERE id = 1",
            (generate_password_hash(new_password), datetime.now(TIMEZONE).strftime("%Y-%m-%d %H:%M:%S")),
        )
        conn.commit()


def list_logs(limit=200):
    with closing(get_conn()) as conn:
        return conn.execute(
            """
            SELECT l.*, s.name AS server_name
            FROM job_logs l
            JOIN servers s ON s.id = l.server_id
            ORDER BY l.id DESC
            LIMIT ?
            """,
            (limit,),
        ).fetchall()


def list_logs_grouped_by_server(limit_per_server=50):
    with closing(get_conn()) as conn:
        servers = conn.execute("SELECT id, name, ip FROM servers ORDER BY sort_order ASC, id ASC").fetchall()
        grouped = []
        for server in servers:
            logs = conn.execute(
                """
                SELECT id, status, summary, output, created_at
                FROM job_logs
                WHERE server_id = ?
                ORDER BY id DESC
                LIMIT ?
                """,
                (server["id"], limit_per_server),
            ).fetchall()
            grouped.append({"server": server, "logs": logs})
        return grouped


def list_detail_rows():
    with closing(get_conn()) as conn:
        return conn.execute(
            """
            SELECT s.id, s.name, s.ip, s.ssh_password, s.reset_day,
                   s.auto_reset, s.is_renewed, s.is_rented, s.sort_order,
                   s.period_upload_bytes, s.period_download_bytes, s.last_agent_report_at,
                   l.summary, l.status, l.created_at AS latest_run_at
            FROM servers s
            LEFT JOIN job_logs l ON l.id = (
                SELECT l2.id FROM job_logs l2
                WHERE l2.server_id = s.id
                ORDER BY l2.id DESC
                LIMIT 1
            )
            ORDER BY s.sort_order ASC, s.id ASC
            """
        ).fetchall()


def export_backup_payload():
    with closing(get_conn()) as conn:
        servers = [dict(row) for row in conn.execute("SELECT * FROM servers ORDER BY sort_order ASC, id ASC").fetchall()]
        logs = [dict(row) for row in conn.execute("SELECT * FROM job_logs ORDER BY id").fetchall()]
        global_cfg = conn.execute("SELECT * FROM global_config WHERE id = 1").fetchone()

    payload = {
        "meta": {
            "exported_at": datetime.now(TIMEZONE).strftime("%Y-%m-%d %H:%M:%S"),
            "version": 1,
        },
        "global_config": dict(global_cfg) if global_cfg else {},
        "servers": servers,
        "job_logs": logs,
    }
    return payload


def restore_backup_payload(payload):
    if not isinstance(payload, dict):
        raise ValueError("备份文件格式无效")

    servers = payload.get("servers")
    logs = payload.get("job_logs")
    global_cfg = payload.get("global_config")

    if not isinstance(servers, list) or not isinstance(logs, list) or not isinstance(global_cfg, dict):
        raise ValueError("备份文件缺少必要字段")

    with closing(get_conn()) as conn:
        conn.execute("DELETE FROM job_logs")
        conn.execute("DELETE FROM servers")
        conn.execute("DELETE FROM global_config")

        conn.execute(
            """
            INSERT INTO global_config(id, reset_command, ssh_command_2, ssh_command_3, agent_install_command, panel_base_url, panel_password_hash, updated_at)
            VALUES(1,?,?,?,?,?,?,?)
            """,
            (
                global_cfg.get("reset_command", ""),
                global_cfg.get("ssh_command_2", ""),
                global_cfg.get("ssh_command_3", ""),
                global_cfg.get("agent_install_command", ""),
                global_cfg.get("panel_base_url", ""),
                global_cfg.get("panel_password_hash") or generate_password_hash("admin"),
                global_cfg.get("updated_at"),
            ),
        )

        for server in servers:
            conn.execute(
                """
                INSERT INTO servers(id, name, ip, ssh_port, ssh_user, ssh_password, reset_day, auto_reset, is_renewed, is_rented, sort_order, agent_token, period_key, period_upload_bytes, period_download_bytes, last_agent_rx_bytes, last_agent_tx_bytes, last_agent_report_at, last_reset_at)
                VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
                """,
                (
                    server.get("id"),
                    server.get("name", ""),
                    server.get("ip", ""),
                    int(server.get("ssh_port", 22)),
                    server.get("ssh_user", "root") or "root",
                    server.get("ssh_password", ""),
                    int(server.get("reset_day", 1)),
                    int(server.get("auto_reset", 0)),
                    int(server.get("is_renewed", 0)),
                    int(server.get("is_rented", 0)),
                    int(server.get("sort_order", 0)),
                    server.get("agent_token", ""),
                    server.get("period_key", ""),
                    int(server.get("period_upload_bytes", 0)),
                    int(server.get("period_download_bytes", 0)),
                    int(server.get("last_agent_rx_bytes", 0)),
                    int(server.get("last_agent_tx_bytes", 0)),
                    server.get("last_agent_report_at"),
                    server.get("last_reset_at"),
                ),
            )

        for log in logs:
            conn.execute(
                """
                INSERT INTO job_logs(id, server_id, status, summary, output, created_at)
                VALUES(?,?,?,?,?,?)
                """,
                (
                    log.get("id"),
                    log.get("server_id"),
                    log.get("status", "failed"),
                    log.get("summary", ""),
                    log.get("output", ""),
                    log.get("created_at") or datetime.now(TIMEZONE).strftime("%Y-%m-%d %H:%M:%S"),
                ),
            )
        conn.commit()


def save_log(server_id, status, summary, output):
    with closing(get_conn()) as conn:
        cur = conn.execute(
            "INSERT INTO job_logs(server_id, status, summary, output, created_at) VALUES(?,?,?,?,?)",
            (
                server_id,
                status,
                summary,
                output,
                datetime.now(TIMEZONE).strftime("%Y-%m-%d %H:%M:%S"),
            ),
        )
        conn.commit()
        return cur.lastrowid


def update_log(log_id, status, summary, output):
    with closing(get_conn()) as conn:
        conn.execute(
            "UPDATE job_logs SET status=?, summary=?, output=?, created_at=? WHERE id=?",
            (
                status,
                summary,
                output,
                datetime.now(TIMEZONE).strftime("%Y-%m-%d %H:%M:%S"),
                log_id,
            ),
        )
        conn.commit()


def update_last_reset(server_id):
    with closing(get_conn()) as conn:
        conn.execute(
            "UPDATE servers SET last_reset_at = ? WHERE id = ?",
            (datetime.now(TIMEZONE).strftime("%Y-%m-%d %H:%M:%S"), server_id),
        )
        conn.commit()


def update_server_password(server_id, new_password):
    with closing(get_conn()) as conn:
        conn.execute("UPDATE servers SET ssh_password = ? WHERE id = ?", (new_password, server_id))
        conn.commit()


def generate_agent_token(length=40):
    alphabet = string.ascii_letters + string.digits
    return "".join(secrets.choice(alphabet) for _ in range(length))


def ensure_server_agent_token(server_id):
    with closing(get_conn()) as conn:
        row = conn.execute("SELECT agent_token FROM servers WHERE id = ?", (server_id,)).fetchone()
        if not row:
            return None
        token = (row["agent_token"] or "").strip()
        if token:
            return token
        token = generate_agent_token()
        conn.execute("UPDATE servers SET agent_token = ? WHERE id = ?", (token, server_id))
        conn.commit()
        return token


def month_day_safe(year, month, day):
    import calendar

    return min(day, calendar.monthrange(year, month)[1])


def get_traffic_period_start(reset_day, now_dt):
    day_this_month = month_day_safe(now_dt.year, now_dt.month, reset_day)
    this_start = now_dt.replace(day=day_this_month, hour=1, minute=0, second=0, microsecond=0)
    if now_dt >= this_start:
        return this_start

    if now_dt.month == 1:
        prev_year, prev_month = now_dt.year - 1, 12
    else:
        prev_year, prev_month = now_dt.year, now_dt.month - 1
    day_prev_month = month_day_safe(prev_year, prev_month, reset_day)
    return now_dt.replace(year=prev_year, month=prev_month, day=day_prev_month, hour=1, minute=0, second=0, microsecond=0)


def current_period_key(reset_day, now_dt):
    start = get_traffic_period_start(reset_day, now_dt)
    return start.strftime("%Y-%m-%d %H:%M:%S")


def format_bytes(num):
    units = ["B", "KB", "MB", "GB", "TB", "PB"]
    value = float(max(num or 0, 0))
    for unit in units:
        if value < 1024 or unit == units[-1]:
            return f"{value:.2f} {unit}" if unit != "B" else f"{int(value)} B"
        value /= 1024


def resolve_panel_base_url(global_cfg, request_obj=None):
    configured = (global_cfg["panel_base_url"] or "").strip()
    if configured:
        return configured.rstrip("/")
    if request_obj:
        return request_obj.url_root.rstrip("/")
    return f"http://127.0.0.1:{PANEL_PORT}"


def build_agent_install_command(base_url, token):
    install_url = f"{base_url}/api/agent/install.sh?token={token}"
    return f"curl -fsSL {shlex.quote(install_url)} | bash"

def generate_root_password(length=16):
    alphabet = string.ascii_letters + string.digits
    return "".join(secrets.choice(alphabet) for _ in range(length))


def inject_random_password_if_needed(command, server_row, generated_password):
    if "InstallNET.sh" not in command or "-pwd" not in command:
        return command, generated_password

    pwd = generated_password or generate_root_password()
    command = re.sub(r"-pwd\s+'[^']*'", f"-pwd '{pwd}'", command)
    command = re.sub(r'-pwd\s+"[^"]*"', f'-pwd "{pwd}"', command)
    command = re.sub(r"-pwd\s+([^\s'\"]+)", f"-pwd '{pwd}'", command)
    update_server_password(server_row["id"], pwd)
    return command, pwd


def inject_random_ssh2_password_if_needed(command):
    if "qb_fb_vertex_installer.sh" not in command:
        return command, None

    pwd = generate_root_password(12)
    if "-p" in command:
        command = re.sub(r"-p\s+'[^']*'", f"-p '{pwd}'", command)
        command = re.sub(r'-p\s+"[^"]*"', f'-p "{pwd}"', command)
        command = re.sub(r"-p\s+([^\s'\"]+)", f"-p '{pwd}'", command)
    else:
        command = f"{command} -p '{pwd}'"

    return command, pwd


def normalize_shell_command(command):
    return command.replace("“", '"').replace("”", '"').replace("‘", "'").replace("’", "'")


def render_agent_install_command(command, server_row):
    if not command:
        return command
    return command.replace("{ip}", server_row["ip"]).replace("{name}", server_row["name"]).replace("{ssh_user}", server_row["ssh_user"])


def sanitize_terminal_text(text):
    if not text:
        return ""
    text = ANSI_ESCAPE_RE.sub("", text)
    text = text.replace("\x1b(B", "")
    text = text.replace("\x1b[m", "")
    text = text.replace("\r", "")
    return text


def refresh_server_traffic(server_row):
    now_dt = datetime.now(TIMEZONE)
    period_key = current_period_key(int(server_row["reset_day"]), now_dt)

    command = "awk -F'[: ]+' 'NR>2 && $1!=\"lo\" {rx+=$3; tx+=$11} END{printf \"%d %d\", rx+0, tx+0}' /proc/net/dev"
    client = connect_ssh(server_row, timeout=15)
    try:
        _, stdout, stderr = client.exec_command(command)
        out = stdout.read().decode("utf-8", errors="ignore").strip()
        err = stderr.read().decode("utf-8", errors="ignore").strip()
        if err:
            raise RuntimeError(err)
        parts = out.split()
        if len(parts) != 2:
            raise RuntimeError(f"无法解析网卡统计输出: {out}")
        rx_now = int(parts[0])
        tx_now = int(parts[1])
    finally:
        client.close()

    with closing(get_conn()) as conn:
        row = conn.execute(
            "SELECT period_key, period_upload_bytes, period_download_bytes, last_agent_rx_bytes, last_agent_tx_bytes FROM servers WHERE id = ?",
            (server_row["id"],),
        ).fetchone()
        if not row:
            return

        upload = int(row["period_upload_bytes"] or 0)
        download = int(row["period_download_bytes"] or 0)
        last_rx = int(row["last_agent_rx_bytes"] or 0)
        last_tx = int(row["last_agent_tx_bytes"] or 0)

        if row["period_key"] != period_key:
            upload = 0
            download = 0
            last_rx = rx_now
            last_tx = tx_now
        else:
            delta_rx = rx_now - last_rx
            delta_tx = tx_now - last_tx
            if delta_rx < 0:
                delta_rx = rx_now
            if delta_tx < 0:
                delta_tx = tx_now
            download += delta_rx
            upload += delta_tx
            last_rx = rx_now
            last_tx = tx_now

        conn.execute(
            """
            UPDATE servers
            SET period_key=?, period_upload_bytes=?, period_download_bytes=?,
                last_agent_rx_bytes=?, last_agent_tx_bytes=?, last_agent_report_at=?
            WHERE id=?
            """,
            (
                period_key,
                upload,
                download,
                last_rx,
                last_tx,
                now_dt.strftime("%Y-%m-%d %H:%M:%S"),
                server_row["id"],
            ),
        )
        conn.commit()


def refresh_all_traffic_data():
    with closing(get_conn()) as conn:
        rows = conn.execute("SELECT * FROM servers ORDER BY sort_order ASC, id ASC").fetchall()
    for row in rows:
        try:
            refresh_server_traffic(row)
        except Exception:
            continue


def should_reset(server_row):
    now = datetime.now(TIMEZONE)
    if not server_row["auto_reset"]:
        return False
    if server_row["is_renewed"]:
        return False
    if server_row["reset_day"] != now.day:
        return False
    if now.hour != 1:
        return False

    if not server_row["last_reset_at"]:
        return True

    try:
        last = datetime.strptime(server_row["last_reset_at"], "%Y-%m-%d %H:%M:%S").replace(tzinfo=TIMEZONE)
    except ValueError:
        return True

    return not (last.year == now.year and last.month == now.month)


def is_reinstall_command(command):
    return "InstallNET.sh" in command and "-pwd" in command


def connect_ssh(server_row, timeout=20):
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    client.connect(
        hostname=server_row["ip"],
        port=server_row["ssh_port"],
        username=server_row["ssh_user"],
        password=server_row["ssh_password"],
        timeout=timeout,
    )
    return client


def wait_for_ssh_reconnect(server_row, output_lines, password_candidates):
    output_lines.append("等待服务器重装并重启后重新连线...")
    deadline = time.time() + SSH_RECONNECT_TIMEOUT_SECONDS
    while time.time() < deadline:
        for pwd in password_candidates:
            try:
                trial = dict(server_row)
                trial["ssh_password"] = pwd
                client = connect_ssh(trial, timeout=15)
                output_lines.append(f"服务器已重新上线，SSH重连成功（密码候选: {pwd[:3]}***）")
                return client, pwd
            except Exception as exc:
                output_lines.append(f"等待重连中({pwd[:3]}***): {exc}")
        time.sleep(SSH_RETRY_INTERVAL_SECONDS)

    raise TimeoutError("等待服务器重连超时，请检查重装是否成功")


def execute_command_and_collect(client, title, command, output_lines):
    output_lines.append(f"执行 {title}: {command}")

    wrapped_command = f"export TERM=xterm; {command}"
    _, stdout, stderr = client.exec_command(wrapped_command)
    out = sanitize_terminal_text(stdout.read().decode("utf-8", errors="ignore"))
    err = sanitize_terminal_text(stderr.read().decode("utf-8", errors="ignore"))

    if out:
        output_lines.append(f"{title}输出:\n{out}")

    if err:
        benign_patterns = (
            "tput: No value for $TERM",
            "检测到虚拟化环境,跳过部分硬件优化",
            "建议重启系统以确保所有优化生效",
            "如果无法打开网页，可能是防火墙没有放通端口",
        )

        benign_lines = []
        real_error_lines = []
        for line in err.splitlines():
            line = line.strip()
            if not line:
                continue
            if any(pattern in line for pattern in benign_patterns):
                benign_lines.append(line)
            else:
                real_error_lines.append(line)

        if real_error_lines:
            output_lines.append(f"{title}错误:\n" + "\n".join(real_error_lines))
        if benign_lines:
            output_lines.append(f"{title}提示:\n" + "\n".join(dict.fromkeys(benign_lines)))


def extract_summary(server_row, raw_output):
    raw_output = sanitize_terminal_text(raw_output)
    ip_match = re.search(r"IP\s*address\s*:\s*([\d\.]+)", raw_output, flags=re.IGNORECASE)
    pass_match = re.search(r"Your new root passw(?:o|or)t\s+is\s*([^\n\r]+)", raw_output, flags=re.IGNORECASE)

    vertex = re.search(r"🌐\s*Vertex[\s\S]*?--------", raw_output)
    qb = re.search(r"🧩\s*qBittorrent[\s\S]*?--------", raw_output)
    fb = re.search(r"📁\s*FileBrowser[\s\S]*?--------", raw_output)

    lines = [
        f"{server_row['name']}（名称），{server_row['reset_day']}日凌晨1点（北京时间）服务器重置",
        f"IP address: {ip_match.group(1) if ip_match else server_row['ip']}",
        f"Your new root passwort is {pass_match.group(1).strip() if pass_match else server_row['ssh_password']}",
    ]

    for block in (vertex, qb, fb):
        if block:
            lines.append(block.group(0).strip())

    return "\n".join(lines)


def run_remote(server_row, running_log_id):
    title = f"[{server_row['name']} - {server_row['ip']}]"
    output_lines = [f"开始执行重置任务 {title}"]
    client = None

    try:
        mutable_server = dict(server_row)
        generated_password = None
        original_password = mutable_server["ssh_password"]
        global_cfg = get_global_config()

        reset_command = normalize_shell_command((global_cfg["reset_command"] or "").strip())
        ssh_command_2 = normalize_shell_command((global_cfg["ssh_command_2"] or "").strip())
        ssh_command_3 = normalize_shell_command((global_cfg["ssh_command_3"] or "").strip())
        agent_install_command = normalize_shell_command((global_cfg["agent_install_command"] or "").strip())
        panel_base_url = resolve_panel_base_url(global_cfg)

        client = connect_ssh(mutable_server)
        output_lines.append("SSH 连接成功")

        reinstall_triggered = False
        if reset_command:
            reset_command, generated_password = inject_random_password_if_needed(
                reset_command,
                mutable_server,
                generated_password,
            )
            if generated_password:
                mutable_server["ssh_password"] = generated_password
                output_lines.append(f"检测到DD重装命令，已自动生成新root密码: {generated_password}")

            if is_reinstall_command(reset_command):
                reinstall_triggered = True
                wrapped = f"nohup bash -lc {shlex.quote(reset_command)} >/root/panel_reset.log 2>&1 &"
                output_lines.append(f"执行 重置任务(后台): {reset_command}")
                client.exec_command(wrapped)
                output_lines.append("重置任务已后台启动，等待后续重连")
                client.close()
                client = None
                time.sleep(POST_REINSTALL_WAIT_SECONDS)
                if ssh_command_2 or ssh_command_3:
                    passwords = []
                    if generated_password:
                        passwords.append(generated_password)
                    passwords.append(original_password)
                    client, connected_pwd = wait_for_ssh_reconnect(mutable_server, output_lines, passwords)
                    if connected_pwd != mutable_server["ssh_password"]:
                        mutable_server["ssh_password"] = connected_pwd
                        update_server_password(mutable_server["id"], connected_pwd)
                        output_lines.append("检测到实际可登录密码与预设不同，已自动回写面板")
            else:
                execute_command_and_collect(client, "重置任务", reset_command, output_lines)

        if reinstall_triggered:
            token = ensure_server_agent_token(mutable_server["id"])
            builtin_agent_command = build_agent_install_command(panel_base_url, token)
            if client is None:
                client = connect_ssh(mutable_server)
                output_lines.append("执行 Agent安装任务 前重新建立SSH连接成功")
            execute_command_and_collect(client, "Agent安装任务", builtin_agent_command, output_lines)

            if agent_install_command:
                prepared_agent_command = render_agent_install_command(agent_install_command, mutable_server)
                execute_command_and_collect(client, "自定义Agent安装任务", prepared_agent_command, output_lines)

        if ssh_command_2:
            ssh_command_2, ssh2_password = inject_random_ssh2_password_if_needed(ssh_command_2)
            if ssh2_password:
                output_lines.append(f"SSH任务2检测到固定密码参数，已替换为随机12位密码: {ssh2_password}")
            if client is None:
                client = connect_ssh(mutable_server)
                output_lines.append("执行 SSH任务2 前重新建立SSH连接成功")
            execute_command_and_collect(client, "SSH任务2", ssh_command_2, output_lines)

        if ssh_command_3:
            if client is None:
                client = connect_ssh(mutable_server)
                output_lines.append("执行 SSH任务3 前重新建立SSH连接成功")
            execute_command_and_collect(client, "SSH任务3", ssh_command_3, output_lines)

        output_lines.append("任务执行完成")
        all_output = "\n\n".join(output_lines)
        summary = extract_summary(mutable_server, all_output)
        update_log(running_log_id, "success", summary, all_output)
        update_last_reset(server_row["id"])
    except Exception as exc:
        output_lines.append(f"任务失败: {exc}")
        all_output = "\n\n".join(output_lines)
        summary = extract_summary(locals().get("mutable_server", dict(server_row)), all_output)
        update_log(running_log_id, "failed", summary, all_output)
    finally:
        if client:
            client.close()


def has_pending_or_running(server_id):
    with closing(get_conn()) as conn:
        row = conn.execute(
            """
            SELECT status FROM job_logs
            WHERE server_id = ?
            ORDER BY id DESC
            LIMIT 1
            """,
            (server_id,),
        ).fetchone()
    return bool(row and row["status"] in ("queued", "running"))


def task_worker_loop():
    while True:
        server_id, log_id = TASK_QUEUE.get()
        try:
            row = get_server(server_id)
            if not row:
                update_log(log_id, "failed", "任务失败：服务器不存在", "任务失败: 服务器不存在或已删除")
                continue

            update_log(
                log_id,
                "running",
                "任务执行中，请稍后刷新查看结果...",
                f"开始执行重置任务 [{row['name']} - {row['ip']}]\n\n状态: 执行中",
            )
            run_remote(row, log_id)
        finally:
            TASK_QUEUE.task_done()


def start_task_worker():
    threading.Thread(target=task_worker_loop, daemon=True).start()


def run_for_server(server_id):
    row = get_server(server_id)
    if not row:
        return False, "服务器不存在"

    if has_pending_or_running(server_id):
        return False, "该服务器已有排队/执行中的任务，已跳过重复提交"

    log_id = save_log(
        row["id"],
        "queued",
        "任务已进入队列，等待前序服务器执行完成...",
        f"开始执行重置任务 [{row['name']} - {row['ip']}]\n\n状态: 排队中（将按顺序依次执行）",
    )
    TASK_QUEUE.put((row["id"], log_id))
    return True, "任务已加入队列，将按顺序依次执行"


def check_scheduled_jobs():
    with closing(get_conn()) as conn:
        rows = conn.execute("SELECT * FROM servers").fetchall()
    for row in rows:
        if should_reset(row):
            run_for_server(row["id"])


def login_required(func):
    @wraps(func)
    def wrapper(*args, **kwargs):
        if not session.get("logged_in"):
            return redirect(url_for("login_page"))
        return func(*args, **kwargs)

    return wrapper


@app.before_request
def require_login():
    public_endpoints = {"login_page", "login_submit", "static", "agent_install_script", "agent_report"}
    if request.endpoint in public_endpoints:
        return None
    if not session.get("logged_in"):
        return redirect(url_for("login_page"))
    return None


@app.route("/login", methods=["GET"])
def login_page():
    if session.get("logged_in"):
        return redirect(url_for("details_page"))
    return render_template("login.html", title="面板登录")


@app.route("/login", methods=["POST"])
def login_submit():
    password = request.form.get("password", "")
    if verify_panel_password(password):
        session["logged_in"] = True
        flash("登录成功", "success")
        return redirect(url_for("details_page"))
    flash("密码错误", "error")
    return redirect(url_for("login_page"))


@app.route("/logout", methods=["POST"])
def logout_submit():
    session.clear()
    flash("已退出登录", "success")
    return redirect(url_for("login_page"))


@app.route("/")
@login_required
def home():
    return redirect(url_for("details_page"))


@app.route("/details")
@login_required
def details_page():
    rows = list_detail_rows()
    normalized_rows = []
    for r in rows:
        item = dict(r)
        upload = int(item.get("period_upload_bytes") or 0)
        download = int(item.get("period_download_bytes") or 0)
        item["traffic_upload_text"] = format_bytes(upload)
        item["traffic_download_text"] = format_bytes(download)
        item["traffic_total_text"] = format_bytes(upload + download)
        normalized_rows.append(item)

    total = len(normalized_rows)
    success = len([r for r in normalized_rows if r["status"] == "success"])
    failed = len([r for r in normalized_rows if r["status"] == "failed"])
    never = len([r for r in normalized_rows if not r["latest_run_at"]])
    return render_template(
        "details.html",
        rows=normalized_rows,
        total=total,
        success=success,
        failed=failed,
        never=never,
    )


@app.route("/settings")
@login_required
def settings_page():
    return render_template(
        "settings.html",
        servers=list_servers(),
        logs_grouped=list_logs_grouped_by_server(),
        global_cfg=get_global_config(),
    )


@app.route("/management")
@login_required
def management_page():
    return render_template("management.html", title="面板管理")


@app.route("/management/change-password", methods=["POST"])
@login_required
def change_panel_password():
    current_password = request.form.get("current_password", "")
    new_password = request.form.get("new_password", "")
    confirm_password = request.form.get("confirm_password", "")

    if not verify_panel_password(current_password):
        flash("当前密码不正确", "error")
        return redirect(url_for("management_page"))

    if len(new_password) < 4:
        flash("新密码至少 4 位", "error")
        return redirect(url_for("management_page"))

    if new_password != confirm_password:
        flash("两次输入的新密码不一致", "error")
        return redirect(url_for("management_page"))

    update_panel_password(new_password)
    flash("面板登录密码修改成功", "success")
    return redirect(url_for("management_page"))


@app.route("/management/backup", methods=["GET"])
@login_required
def download_backup():
    import json

    payload = export_backup_payload()
    content = json.dumps(payload, ensure_ascii=False, indent=2).encode("utf-8")
    buf = BytesIO(content)
    ts = datetime.now(TIMEZONE).strftime("%Y%m%d-%H%M%S")
    return send_file(
        buf,
        as_attachment=True,
        download_name=f"vps-panel-backup-{ts}.json",
        mimetype="application/json",
    )


@app.route("/management/restore", methods=["POST"])
@login_required
def restore_backup():
    import json

    file = request.files.get("backup_file")
    if not file or not file.filename:
        flash("请先选择备份文件", "error")
        return redirect(url_for("management_page"))

    try:
        payload = json.load(file.stream)
        restore_backup_payload(payload)
        flash("数据恢复成功", "success")
    except Exception as exc:
        flash(f"数据恢复失败: {exc}", "error")

    return redirect(url_for("management_page"))


@app.get("/api/agent/install.sh")
def agent_install_script():
    token = (request.args.get("token") or "").strip()
    if not token:
        return Response("missing token\n", status=400, mimetype="text/plain")

    with closing(get_conn()) as conn:
        row = conn.execute("SELECT id FROM servers WHERE agent_token = ?", (token,)).fetchone()
        if not row:
            return Response("invalid token\n", status=403, mimetype="text/plain")

    base_url = resolve_panel_base_url(get_global_config(), request)
    report_url = f"{base_url}/api/agent/report"
    script = f"""#!/usr/bin/env bash
set -euo pipefail
cat >/usr/local/bin/vps-panel-agent.sh <<'AGENT'
#!/usr/bin/env bash
set -euo pipefail
TOKEN={token}
REPORT_URL={report_url}
collect() {{
  awk -F'[: ]+' 'NR>2 && $1!="lo" {{rx+=$3; tx+=$11}} END{{printf "%d %d", rx+0, tx+0}}' /proc/net/dev
}}
read -r RX TX < <(collect)
curl -fsS -m 20 -H 'Content-Type: application/json' -d "{{\\"token\\":\\"$TOKEN\\",\\"rx_bytes\\":$RX,\\"tx_bytes\\":$TX}}" "$REPORT_URL" >/dev/null || true
AGENT
chmod +x /usr/local/bin/vps-panel-agent.sh

cat >/etc/systemd/system/vps-panel-agent.service <<'UNIT'
[Unit]
Description=VPS Panel Agent Reporter
After=network-online.target

[Service]
Type=oneshot
ExecStart=/usr/local/bin/vps-panel-agent.sh
UNIT

cat >/etc/systemd/system/vps-panel-agent.timer <<'UNIT'
[Unit]
Description=Run VPS Panel Agent reporter

[Timer]
OnBootSec=30s
OnUnitActiveSec={AGENT_REPORT_INTERVAL_SECONDS}s
AccuracySec=5s
Unit=vps-panel-agent.service

[Install]
WantedBy=timers.target
UNIT

systemctl daemon-reload
systemctl enable --now vps-panel-agent.timer
systemctl restart vps-panel-agent.timer
echo "[OK] vps-panel-agent installed"
"""
    return Response(script, mimetype="text/x-shellscript")


@app.post("/api/agent/report")
def agent_report():
    payload = request.get_json(silent=True) or {}
    token = str(payload.get("token", "")).strip()
    if not token:
        return jsonify({"ok": False, "error": "missing token"}), 400

    try:
        rx_now = int(payload.get("rx_bytes", 0))
        tx_now = int(payload.get("tx_bytes", 0))
    except (TypeError, ValueError):
        return jsonify({"ok": False, "error": "invalid rx/tx"}), 400

    now_dt = datetime.now(TIMEZONE)
    with closing(get_conn()) as conn:
        row = conn.execute("SELECT * FROM servers WHERE agent_token = ?", (token,)).fetchone()
        if not row:
            return jsonify({"ok": False, "error": "invalid token"}), 403

        period_key = current_period_key(int(row["reset_day"]), now_dt)
        upload = int(row["period_upload_bytes"] or 0)
        download = int(row["period_download_bytes"] or 0)
        last_rx = int(row["last_agent_rx_bytes"] or 0)
        last_tx = int(row["last_agent_tx_bytes"] or 0)

        if row["period_key"] != period_key:
            upload = 0
            download = 0
            last_rx = rx_now
            last_tx = tx_now
        else:
            delta_rx = rx_now - last_rx
            delta_tx = tx_now - last_tx
            if delta_rx < 0:
                delta_rx = rx_now
            if delta_tx < 0:
                delta_tx = tx_now
            download += delta_rx
            upload += delta_tx
            last_rx = rx_now
            last_tx = tx_now

        conn.execute(
            """
            UPDATE servers
            SET period_key=?, period_upload_bytes=?, period_download_bytes=?,
                last_agent_rx_bytes=?, last_agent_tx_bytes=?, last_agent_report_at=?
            WHERE id=?
            """,
            (
                period_key,
                upload,
                download,
                last_rx,
                last_tx,
                now_dt.strftime("%Y-%m-%d %H:%M:%S"),
                row["id"],
            ),
        )
        conn.commit()

    return jsonify({"ok": True})


@app.route("/global-tasks", methods=["POST"])
@login_required
def update_global_tasks():
    form = request.form
    update_global_config(
        form.get("reset_command", ""),
        form.get("ssh_command_2", ""),
        form.get("ssh_command_3", ""),
        form.get("agent_install_command", ""),
        form.get("panel_base_url", ""),
    )
    flash("全局任务配置已更新", "success")
    return redirect(url_for("settings_page"))


def get_next_sort_order(conn):
    row = conn.execute("SELECT COALESCE(MAX(sort_order), 0) AS max_order FROM servers").fetchone()
    return int(row["max_order"]) + 1


@app.route("/servers", methods=["POST"])
@login_required
def add_server():
    form = request.form
    with closing(get_conn()) as conn:
        sort_order_input = (form.get("sort_order") or "").strip()
        sort_order = int(sort_order_input) if sort_order_input else get_next_sort_order(conn)
        conn.execute(
            """
            INSERT INTO servers(name, ip, ssh_port, ssh_user, ssh_password, reset_day, auto_reset, is_renewed, is_rented, sort_order, agent_token, period_key, period_upload_bytes, period_download_bytes, last_agent_rx_bytes, last_agent_tx_bytes, last_agent_report_at)
            VALUES(?,?,?,?,?,?,?,0,0,?,?,?,?,?,?,?,?)
            """,
            (
                form["name"].strip(),
                form["ip"].strip(),
                int(form.get("ssh_port", 22)),
                form.get("ssh_user", "root").strip() or "root",
                form["ssh_password"],
                int(form["reset_day"]),
                1 if form.get("auto_reset") == "on" else 0,
                sort_order,
                generate_agent_token(),
                "",
                0,
                0,
                0,
                0,
                None,
            ),
        )
        conn.commit()
    flash("服务器已添加", "success")
    return redirect(url_for("settings_page"))


@app.route("/servers/<int:server_id>/update", methods=["POST"])
@login_required
def update_server(server_id):
    form = request.form
    with closing(get_conn()) as conn:
        conn.execute(
            """
            UPDATE servers
            SET name=?, ip=?, ssh_port=?, ssh_user=?, ssh_password=?, reset_day=?, auto_reset=?, sort_order=?
            WHERE id=?
            """,
            (
                form["name"].strip(),
                form["ip"].strip(),
                int(form.get("ssh_port", 22)),
                form.get("ssh_user", "root").strip() or "root",
                form["ssh_password"],
                int(form["reset_day"]),
                1 if form.get("auto_reset") == "on" else 0,
                int(form.get("sort_order", 0)),
                server_id,
            ),
        )
        conn.commit()
    flash("服务器信息已更新", "success")
    return redirect(url_for("settings_page"))


@app.route("/servers/<int:server_id>/delete", methods=["POST"])
@login_required
def delete_server(server_id):
    with closing(get_conn()) as conn:
        conn.execute("DELETE FROM servers WHERE id = ?", (server_id,))
        conn.execute("DELETE FROM job_logs WHERE server_id = ?", (server_id,))
        conn.commit()
    flash("服务器已删除", "success")
    return redirect(url_for("settings_page"))


@app.route("/servers/<int:server_id>/toggle-renew", methods=["POST"])
@login_required
def toggle_renew(server_id):
    with closing(get_conn()) as conn:
        row = conn.execute("SELECT is_renewed FROM servers WHERE id = ?", (server_id,)).fetchone()
        if not row:
            flash("服务器不存在", "error")
            return redirect(url_for("details_page"))
        next_state = 0 if row["is_renewed"] else 1
        conn.execute("UPDATE servers SET is_renewed = ? WHERE id = ?", (next_state, server_id))
        conn.commit()
    flash("已切换为续租状态，后续将跳过定时重置" if next_state else "已关闭续租状态，恢复按计划重置", "success")
    return redirect(url_for("details_page"))


@app.route("/servers/<int:server_id>/toggle-rent", methods=["POST"])
@login_required
def toggle_rent(server_id):
    with closing(get_conn()) as conn:
        row = conn.execute("SELECT is_rented FROM servers WHERE id = ?", (server_id,)).fetchone()
        if not row:
            flash("服务器不存在", "error")
            return redirect(url_for("details_page"))
        next_state = 0 if row["is_rented"] else 1
        conn.execute("UPDATE servers SET is_rented = ? WHERE id = ?", (next_state, server_id))
        conn.commit()
    flash("已标记为已出租" if next_state else "已标记为未出租", "success")
    return redirect(url_for("details_page"))


@app.route("/servers/<int:server_id>/run", methods=["POST"])
@login_required
def run_now(server_id):
    ok, msg = run_for_server(server_id)
    flash(msg, "success" if ok else "error")
    return redirect(url_for("details_page"))


def start_scheduler():
    scheduler = BackgroundScheduler(timezone=TIMEZONE)
    scheduler.add_job(check_scheduled_jobs, "cron", minute="*/5")
    scheduler.add_job(refresh_all_traffic_data, "interval", minutes=5)
    scheduler.start()
    return scheduler


if __name__ == "__main__":
    init_db()
    start_task_worker()
    scheduler = start_scheduler()
    try:
        app.run(host=PANEL_HOST, port=PANEL_PORT, debug=False)
    finally:
        scheduler.shutdown()
