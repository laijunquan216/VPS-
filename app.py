import os
import re
import secrets
import shlex
import sqlite3
import string
import threading
import time
from contextlib import closing
from datetime import datetime
from zoneinfo import ZoneInfo

import paramiko
from apscheduler.schedulers.background import BackgroundScheduler
from flask import Flask, flash, redirect, render_template, request, url_for

DB_PATH = os.environ.get("VPS_PANEL_DB", "panel.db")
PANEL_HOST = os.environ.get("PANEL_HOST", "0.0.0.0")
PANEL_PORT = int(os.environ.get("PANEL_PORT", "5000"))
TIMEZONE = ZoneInfo("Asia/Shanghai")

SSH_RECONNECT_TIMEOUT_SECONDS = int(os.environ.get("SSH_RECONNECT_TIMEOUT_SECONDS", "1800"))
SSH_RETRY_INTERVAL_SECONDS = int(os.environ.get("SSH_RETRY_INTERVAL_SECONDS", "15"))
POST_REINSTALL_WAIT_SECONDS = int(os.environ.get("POST_REINSTALL_WAIT_SECONDS", "30"))

app = Flask(__name__)
app.secret_key = os.environ.get("FLASK_SECRET", "change-me")


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

        # migration for old db versions
        ensure_column(conn, "servers", "last_reset_at TEXT")
        ensure_column(conn, "job_logs", "summary TEXT NOT NULL DEFAULT ''")
        conn.execute("INSERT OR IGNORE INTO global_config(id) VALUES (1)")
        conn.commit()


def list_servers():
    with closing(get_conn()) as conn:
        return conn.execute("SELECT * FROM servers ORDER BY id").fetchall()


def get_server(server_id):
    with closing(get_conn()) as conn:
        return conn.execute("SELECT * FROM servers WHERE id=?", (server_id,)).fetchone()


def get_global_config():
    with closing(get_conn()) as conn:
        conn.execute("INSERT OR IGNORE INTO global_config(id) VALUES (1)")
        row = conn.execute("SELECT * FROM global_config WHERE id=1").fetchone()
        conn.commit()
        return row


def update_global_config(reset_command, ssh_command_2, ssh_command_3):
    with closing(get_conn()) as conn:
        conn.execute(
            """
            UPDATE global_config
            SET reset_command=?, ssh_command_2=?, ssh_command_3=?, updated_at=?
            WHERE id=1
            """,
            (
                reset_command.strip(),
                ssh_command_2.strip(),
                ssh_command_3.strip(),
                datetime.now(TIMEZONE).strftime("%Y-%m-%d %H:%M:%S"),
            ),
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


def list_detail_rows():
    with closing(get_conn()) as conn:
        return conn.execute(
            """
            SELECT s.id, s.name, s.ip, s.ssh_password, s.reset_day,
                   s.auto_reset, l.summary, l.status, l.created_at AS latest_run_at
            FROM servers s
            LEFT JOIN job_logs l ON l.id = (
                SELECT l2.id FROM job_logs l2
                WHERE l2.server_id = s.id
                ORDER BY l2.id DESC
                LIMIT 1
            )
            ORDER BY s.id
            """
        ).fetchall()


def save_log(server_id, status, summary, output):
    with closing(get_conn()) as conn:
        conn.execute(
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
    # 针对 PT 安装脚本自动生成 12 位随机面板密码
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
    # 兼容从网页复制时出现的中文引号
    return (
        command.replace("“", '"')
        .replace("”", '"')
        .replace("‘", "'")
        .replace("’", "'")
    )


def should_reset(server_row):
    now = datetime.now(TIMEZONE)
    if not server_row["auto_reset"]:
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
    out = stdout.read().decode("utf-8", errors="ignore")
    err = stderr.read().decode("utf-8", errors="ignore")

    if out:
        output_lines.append(f"{title}输出:\n{out}")

    if err:
        benign_lines = []
        real_error_lines = []
        for line in err.splitlines():
            if "tput: No value for $TERM" in line:
                benign_lines.append(line)
            elif line.strip():
                real_error_lines.append(line)

        if real_error_lines:
            output_lines.append(f"{title}错误:\n" + "\n".join(real_error_lines))
        elif benign_lines:
            output_lines.append(f"{title}提示: 终端变量告警已忽略({len(benign_lines)}条)")


def extract_summary(server_row, raw_output):
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


def run_remote(server_row):
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

        client = connect_ssh(mutable_server)
        output_lines.append("SSH 连接成功")

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
        save_log(server_row["id"], "success", summary, all_output)
        update_last_reset(server_row["id"])
    except Exception as exc:
        output_lines.append(f"任务失败: {exc}")
        all_output = "\n\n".join(output_lines)
        summary = extract_summary(locals().get("mutable_server", dict(server_row)), all_output)
        save_log(server_row["id"], "failed", summary, all_output)
    finally:
        if client:
            client.close()


def run_for_server(server_id):
    row = get_server(server_id)
    if row:
        threading.Thread(target=run_remote, args=(row,), daemon=True).start()


def check_scheduled_jobs():
    with closing(get_conn()) as conn:
        rows = conn.execute("SELECT * FROM servers").fetchall()
    for row in rows:
        if should_reset(row):
            run_for_server(row["id"])


@app.route("/")
def home():
    return redirect(url_for("details_page"))


@app.route("/details")
def details_page():
    rows = list_detail_rows()
    total = len(rows)
    success = len([r for r in rows if r["status"] == "success"])
    failed = len([r for r in rows if r["status"] == "failed"])
    never = len([r for r in rows if not r["latest_run_at"]])
    return render_template(
        "details.html",
        rows=rows,
        total=total,
        success=success,
        failed=failed,
        never=never,
    )


@app.route("/settings")
def settings_page():
    return render_template(
        "settings.html",
        servers=list_servers(),
        logs=list_logs(),
        global_cfg=get_global_config(),
    )


@app.route("/global-tasks", methods=["POST"])
def update_global_tasks():
    form = request.form
    update_global_config(
        form.get("reset_command", ""),
        form.get("ssh_command_2", ""),
        form.get("ssh_command_3", ""),
    )
    flash("全局任务配置已更新", "success")
    return redirect(url_for("settings_page"))


@app.route("/servers", methods=["POST"])
def add_server():
    form = request.form
    with closing(get_conn()) as conn:
        conn.execute(
            """
            INSERT INTO servers(name, ip, ssh_port, ssh_user, ssh_password, reset_day, auto_reset)
            VALUES(?,?,?,?,?,?,?)
            """,
            (
                form["name"].strip(),
                form["ip"].strip(),
                int(form.get("ssh_port", 22)),
                form.get("ssh_user", "root").strip() or "root",
                form["ssh_password"],
                int(form["reset_day"]),
                1 if form.get("auto_reset") == "on" else 0,
            ),
        )
        conn.commit()
    flash("服务器已添加", "success")
    return redirect(url_for("settings_page"))


@app.route("/servers/<int:server_id>/update", methods=["POST"])
def update_server(server_id):
    form = request.form
    with closing(get_conn()) as conn:
        conn.execute(
            """
            UPDATE servers
            SET name=?, ip=?, ssh_port=?, ssh_user=?, ssh_password=?, reset_day=?, auto_reset=?
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
                server_id,
            ),
        )
        conn.commit()
    flash("服务器信息已更新", "success")
    return redirect(url_for("settings_page"))


@app.route("/servers/<int:server_id>/delete", methods=["POST"])
def delete_server(server_id):
    with closing(get_conn()) as conn:
        conn.execute("DELETE FROM servers WHERE id = ?", (server_id,))
        conn.execute("DELETE FROM job_logs WHERE server_id = ?", (server_id,))
        conn.commit()
    flash("服务器已删除", "success")
    return redirect(url_for("settings_page"))


@app.route("/servers/<int:server_id>/run", methods=["POST"])
def run_now(server_id):
    run_for_server(server_id)
    flash("任务已开始执行，请稍后查看结果", "success")
    return redirect(url_for("details_page"))


def start_scheduler():
    scheduler = BackgroundScheduler(timezone=TIMEZONE)
    scheduler.add_job(check_scheduled_jobs, "cron", minute="*/5")
    scheduler.start()
    return scheduler


if __name__ == "__main__":
    init_db()
    scheduler = start_scheduler()
    try:
        app.run(host=PANEL_HOST, port=PANEL_PORT, debug=False)
    finally:
        scheduler.shutdown()
