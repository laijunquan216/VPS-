import os
import sqlite3
import threading
from contextlib import closing
from dataclasses import dataclass
from datetime import datetime

import paramiko
from apscheduler.schedulers.background import BackgroundScheduler
from flask import Flask, flash, redirect, render_template, request, url_for

DB_PATH = os.environ.get("VPS_PANEL_DB", "panel.db")
CHECK_INTERVAL_MINUTES = int(os.environ.get("CHECK_INTERVAL_MINUTES", "60"))
PANEL_HOST = os.environ.get("PANEL_HOST", "0.0.0.0")
PANEL_PORT = int(os.environ.get("PANEL_PORT", "5000"))

app = Flask(__name__)
app.secret_key = os.environ.get("FLASK_SECRET", "change-me")


@dataclass
class Server:
    id: int
    name: str
    ip: str
    ssh_port: int
    ssh_user: str
    ssh_password: str
    reset_day: int
    auto_reset: int
    dd_command: str
    install_script: str
    last_reset_at: str


def get_conn():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def init_db():
    with closing(get_conn()) as conn:
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS servers (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                name TEXT NOT NULL,
                ip TEXT NOT NULL,
                ssh_port INTEGER NOT NULL DEFAULT 22,
                ssh_user TEXT NOT NULL,
                ssh_password TEXT NOT NULL,
                reset_day INTEGER NOT NULL,
                auto_reset INTEGER NOT NULL DEFAULT 1,
                dd_command TEXT NOT NULL,
                install_script TEXT NOT NULL,
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
                output TEXT NOT NULL,
                created_at TEXT NOT NULL,
                FOREIGN KEY(server_id) REFERENCES servers(id)
            )
            """
        )
        conn.commit()


def list_servers():
    with closing(get_conn()) as conn:
        rows = conn.execute("SELECT * FROM servers ORDER BY id").fetchall()
    return rows


def list_logs(limit=200):
    with closing(get_conn()) as conn:
        rows = conn.execute(
            """
            SELECT l.*, s.name AS server_name
            FROM job_logs l
            JOIN servers s ON s.id = l.server_id
            ORDER BY l.id DESC
            LIMIT ?
            """,
            (limit,),
        ).fetchall()
    return rows


def save_log(server_id: int, status: str, output: str):
    with closing(get_conn()) as conn:
        conn.execute(
            "INSERT INTO job_logs(server_id, status, output, created_at) VALUES(?,?,?,?)",
            (server_id, status, output, datetime.now().strftime("%Y-%m-%d %H:%M:%S")),
        )
        conn.commit()


def update_last_reset(server_id: int):
    with closing(get_conn()) as conn:
        conn.execute(
            "UPDATE servers SET last_reset_at = ? WHERE id = ?",
            (datetime.now().strftime("%Y-%m-%d %H:%M:%S"), server_id),
        )
        conn.commit()


def should_reset(server_row):
    now = datetime.now()
    if not server_row["auto_reset"]:
        return False
    if server_row["reset_day"] != now.day:
        return False
    if not server_row["last_reset_at"]:
        return True

    try:
        last = datetime.strptime(server_row["last_reset_at"], "%Y-%m-%d %H:%M:%S")
    except ValueError:
        return True

    return not (last.year == now.year and last.month == now.month)


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

        dd_command = server_row["dd_command"].strip()
        if dd_command:
            output_lines.append(f"执行 DD 指令: {dd_command}")
            _, stdout, stderr = client.exec_command(dd_command)
            dd_out = stdout.read().decode("utf-8", errors="ignore")
            dd_err = stderr.read().decode("utf-8", errors="ignore")
            if dd_out:
                output_lines.append("DD输出:\n" + dd_out)
            if dd_err:
                output_lines.append("DD错误:\n" + dd_err)

        install_script = server_row["install_script"].strip()
        if install_script:
            output_lines.append("开始执行 PT 盒子安装脚本")
            _, stdout, stderr = client.exec_command(install_script)
            inst_out = stdout.read().decode("utf-8", errors="ignore")
            inst_err = stderr.read().decode("utf-8", errors="ignore")
            if inst_out:
                output_lines.append("安装输出:\n" + inst_out)
            if inst_err:
                output_lines.append("安装错误:\n" + inst_err)

        output_lines.append("任务执行完成")
        save_log(server_row["id"], "success", "\n\n".join(output_lines))
        update_last_reset(server_row["id"])
    except Exception as exc:
        output_lines.append(f"任务失败: {exc}")
        save_log(server_row["id"], "failed", "\n\n".join(output_lines))
    finally:
        client.close()


def run_for_server(server_id: int):
    with closing(get_conn()) as conn:
        server_row = conn.execute("SELECT * FROM servers WHERE id = ?", (server_id,)).fetchone()

    if not server_row:
        return

    threading.Thread(target=run_remote, args=(server_row,), daemon=True).start()


def check_scheduled_jobs():
    with closing(get_conn()) as conn:
        rows = conn.execute("SELECT * FROM servers").fetchall()

    for row in rows:
        if should_reset(row):
            run_for_server(row["id"])


@app.route("/")
def index():
    return render_template("index.html", servers=list_servers(), logs=list_logs())


@app.route("/servers", methods=["POST"])
def add_server():
    form = request.form
    with closing(get_conn()) as conn:
        conn.execute(
            """
            INSERT INTO servers(
                name, ip, ssh_port, ssh_user, ssh_password,
                reset_day, auto_reset, dd_command, install_script
            ) VALUES(?,?,?,?,?,?,?,?,?)
            """,
            (
                form["name"].strip(),
                form["ip"].strip(),
                int(form.get("ssh_port", 22)),
                form["ssh_user"].strip(),
                form["ssh_password"],
                int(form["reset_day"]),
                1 if form.get("auto_reset") == "on" else 0,
                form.get("dd_command", "").strip(),
                form.get("install_script", "").strip(),
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
                reset_day=?, auto_reset=?, dd_command=?, install_script=?
            WHERE id=?
            """,
            (
                form["name"].strip(),
                form["ip"].strip(),
                int(form.get("ssh_port", 22)),
                form["ssh_user"].strip(),
                form["ssh_password"],
                int(form["reset_day"]),
                1 if form.get("auto_reset") == "on" else 0,
                form.get("dd_command", "").strip(),
                form.get("install_script", "").strip(),
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
        conn.commit()

    flash("服务器已删除", "success")
    return redirect(url_for("index"))


@app.route("/servers/<int:server_id>/run", methods=["POST"])
def run_now(server_id):
    run_for_server(server_id)
    flash("任务已开始执行，请稍后查看日志", "success")
    return redirect(url_for("index"))


def start_scheduler():
    scheduler = BackgroundScheduler()
    scheduler.add_job(check_scheduled_jobs, "interval", minutes=CHECK_INTERVAL_MINUTES)
    scheduler.start()
    return scheduler


if __name__ == "__main__":
    init_db()
    scheduler = start_scheduler()
    try:
        app.run(host=PANEL_HOST, port=PANEL_PORT, debug=False)
    finally:
        scheduler.shutdown()
