import os
import re
import secrets
import sqlite3
import string
import threading
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
                ssh_command_1 TEXT NOT NULL DEFAULT '',
                ssh_command_2 TEXT NOT NULL DEFAULT '',
                ssh_command_3 TEXT NOT NULL DEFAULT '',
                last_reset_at TEXT
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

        # migration for existing db
        ensure_column(conn, "servers", "ssh_command_1 TEXT NOT NULL DEFAULT ''")
        ensure_column(conn, "servers", "ssh_command_2 TEXT NOT NULL DEFAULT ''")
        ensure_column(conn, "servers", "ssh_command_3 TEXT NOT NULL DEFAULT ''")
        ensure_column(conn, "job_logs", "summary TEXT NOT NULL DEFAULT ''")
        conn.commit()


def list_servers():
    with closing(get_conn()) as conn:
        return conn.execute("SELECT * FROM servers ORDER BY id").fetchall()


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


def list_display_rows():
    with closing(get_conn()) as conn:
        return conn.execute(
            """
            SELECT s.id, s.name, s.ip, s.ssh_password, s.reset_day,
                   l.summary, l.created_at AS latest_run_at
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
    return ''.join(secrets.choice(alphabet) for _ in range(length))


def inject_random_password_if_needed(command, server_row, generated_password):
    # 支持 InstallNET.sh -pwd 'xxx' / -pwd "xxx" / -pwd xxx
    if "InstallNET.sh" not in command or "-pwd" not in command:
        return command, generated_password

    pwd = generated_password or generate_root_password()
    command = re.sub(r"-pwd\s+'[^']*'", f"-pwd '{pwd}'", command)
    command = re.sub(r'-pwd\s+"[^"]*"', f'-pwd "{pwd}"', command)
    command = re.sub(r"-pwd\s+([^\s'\"]+)", f"-pwd '{pwd}'", command)

    update_server_password(server_row["id"], pwd)
    return command, pwd


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


def extract_summary(server_row, raw_output):
    ip_match = re.search(r"IP\s*address\s*:\s*([\d\.]+)", raw_output, flags=re.IGNORECASE)
    pass_match = re.search(r"Your new root passw(?:o|or)t\s+is\s*([^\n\r]+)", raw_output, flags=re.IGNORECASE)

    vertex = re.search(r"🌐\s*Vertex[\s\S]*?--------", raw_output)
    qb = re.search(r"🧩\s*qBittorrent[\s\S]*?--------", raw_output)
    fb = re.search(r"📁\s*FileBrowser[\s\S]*?--------", raw_output)

    lines = [
        f"{server_row['name']}（名称），{server_row['reset_day']}日凌晨1点（北京时间）刷新流量",
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
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())

    try:
        client.connect(
            hostname=server_row["ip"],
            port=server_row["ssh_port"],
            username=server_row["ssh_user"],
            password=server_row["ssh_password"],
            timeout=20,
        )
        output_lines.append("SSH 连接成功")

        generated_password = None
        mutable_server = dict(server_row)

        for idx in (1, 2, 3):
            command = (mutable_server.get(f"ssh_command_{idx}") or "").strip()
            if not command:
                continue

            command, generated_password = inject_random_password_if_needed(command, mutable_server, generated_password)
            if generated_password:
                mutable_server["ssh_password"] = generated_password
                output_lines.append(f"检测到DD重装命令，已自动生成新root密码: {generated_password}")

            output_lines.append(f"执行 SSH 任务代码{idx}: {command}")
            _, stdout, stderr = client.exec_command(command)
            out = stdout.read().decode("utf-8", errors="ignore")
            err = stderr.read().decode("utf-8", errors="ignore")
            if out:
                output_lines.append(f"代码{idx}输出:\n{out}")
            if err:
                output_lines.append(f"代码{idx}错误:\n{err}")

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
        client.close()


def run_for_server(server_id):
    with closing(get_conn()) as conn:
        row = conn.execute("SELECT * FROM servers WHERE id = ?", (server_id,)).fetchone()
    if row:
        threading.Thread(target=run_remote, args=(row,), daemon=True).start()


def check_scheduled_jobs():
    with closing(get_conn()) as conn:
        rows = conn.execute("SELECT * FROM servers").fetchall()
    for row in rows:
        if should_reset(row):
            run_for_server(row["id"])


@app.route("/")
def index():
    return render_template(
        "index.html",
        servers=list_servers(),
        display_rows=list_display_rows(),
        logs=list_logs(),
    )


@app.route("/servers", methods=["POST"])
def add_server():
    form = request.form
    with closing(get_conn()) as conn:
        conn.execute(
            """
            INSERT INTO servers(
                name, ip, ssh_port, ssh_user, ssh_password, reset_day,
                auto_reset, ssh_command_1, ssh_command_2, ssh_command_3
            ) VALUES(?,?,?,?,?,?,?,?,?,?)
            """,
            (
                form["name"].strip(),
                form["ip"].strip(),
                int(form.get("ssh_port", 22)),
                form.get("ssh_user", "root").strip() or "root",
                form["ssh_password"],
                int(form["reset_day"]),
                1 if form.get("auto_reset") == "on" else 0,
                form.get("ssh_command_1", "").strip(),
                form.get("ssh_command_2", "").strip(),
                form.get("ssh_command_3", "").strip(),
            ),
        )
        conn.commit()
    flash("服务器已添加", "success")
    return redirect(url_for("index"))


@app.route("/servers/<int:server_id>/update", methods=["POST"])
def update_server(server_id):
    form = request.form
    with closing(get_conn()) as conn:
        conn.execute(
            """
            UPDATE servers
            SET name=?, ip=?, ssh_port=?, ssh_user=?, ssh_password=?,
                reset_day=?, auto_reset=?, ssh_command_1=?, ssh_command_2=?, ssh_command_3=?
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
                form.get("ssh_command_1", "").strip(),
                form.get("ssh_command_2", "").strip(),
                form.get("ssh_command_3", "").strip(),
                server_id,
            ),
        )
        conn.commit()
    flash("服务器信息已更新", "success")
    return redirect(url_for("index"))


@app.route("/servers/<int:server_id>/delete", methods=["POST"])
def delete_server(server_id):
    with closing(get_conn()) as conn:
        conn.execute("DELETE FROM servers WHERE id = ?", (server_id,))
        conn.execute("DELETE FROM job_logs WHERE server_id = ?", (server_id,))
        conn.commit()
    flash("服务器已删除", "success")
    return redirect(url_for("index"))


@app.route("/servers/<int:server_id>/run", methods=["POST"])
def run_now(server_id):
    run_for_server(server_id)
    flash("任务已开始执行，请稍后查看结果", "success")
    return redirect(url_for("index"))


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
