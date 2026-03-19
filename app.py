import json
import os
import re
import secrets
import zipfile
import shlex
import smtplib
import socket
import sqlite3
import string
import statistics
import threading
import time
from concurrent.futures import ThreadPoolExecutor as FuturesThreadPoolExecutor, as_completed
from queue import Queue
from contextlib import closing
from datetime import datetime, timedelta
from functools import wraps
from io import BytesIO
from urllib import error as urlerror
from urllib import parse as urlparse
from urllib import request as urlrequest
from email.message import EmailMessage
from zoneinfo import ZoneInfo

import paramiko
from apscheduler.schedulers.background import BackgroundScheduler
from apscheduler.executors.pool import ThreadPoolExecutor
from flask import (
    Flask,
    flash,
    redirect,
    render_template,
    request,
    send_file,
    send_from_directory,
    Response,
    jsonify,
    session,
    url_for,
)
from werkzeug.security import check_password_hash, generate_password_hash
from markupsafe import Markup, escape
from werkzeug.utils import secure_filename
from werkzeug.serving import make_server

DB_PATH = os.environ.get("VPS_PANEL_DB", "panel.db")
PANEL_HOST = os.environ.get("PANEL_HOST", "0.0.0.0")
PANEL_PORT = int(os.environ.get("PANEL_PORT", "5000"))
PUBLIC_STOCK_PORT = int(os.environ.get("PUBLIC_STOCK_PORT", "5001"))
PANEL_BASE_URL = os.environ.get("PANEL_BASE_URL", "").strip()
TIMEZONE = ZoneInfo("Asia/Shanghai")

SSH_RECONNECT_TIMEOUT_SECONDS = int(os.environ.get("SSH_RECONNECT_TIMEOUT_SECONDS", "1800"))
SSH_RETRY_INTERVAL_SECONDS = int(os.environ.get("SSH_RETRY_INTERVAL_SECONDS", "15"))
POST_REINSTALL_WAIT_SECONDS = int(os.environ.get("POST_REINSTALL_WAIT_SECONDS", "30"))
# Backward compatibility: older deployments may still reference this name.
BIN_REINSTALL_REBOOT_DELAY_SECONDS = int(
    os.environ.get("BIN_REINSTALL_REBOOT_DELAY_SECONDS", str(POST_REINSTALL_WAIT_SECONDS))
)
DD_NEW_PASSWORD_GRACE_SECONDS = int(os.environ.get("DD_NEW_PASSWORD_GRACE_SECONDS", "900"))
AGENT_REPORT_INTERVAL_SECONDS = int(os.environ.get("AGENT_REPORT_INTERVAL_SECONDS", "60"))
DEFAULT_MAX_RETRIES = int(os.environ.get("DEFAULT_MAX_RETRIES", "2"))
DEFAULT_RETRY_BACKOFF_SECONDS = os.environ.get("DEFAULT_RETRY_BACKOFF_SECONDS", "60,180")
UPLOAD_DATA_DIR = os.environ.get("VPS_PANEL_UPLOAD_DATA_DIR", os.path.join(os.getcwd(), "uploaded_data"))
os.makedirs(UPLOAD_DATA_DIR, exist_ok=True)

app = Flask(__name__)
app.secret_key = os.environ.get("FLASK_SECRET", "change-me")
public_app = Flask("public_stock")
ANSI_ESCAPE_RE = re.compile(r"\x1B(?:[@-Z\-_]|\[[0-?]*[ -/]*[@-~]|\][^\x07]*(?:\x07|\x1B\\)|\([A-Za-z0-9])")
TASK_QUEUE = Queue()
API_IMAGE_REFRESH_LOCK = threading.Lock()
TRAFFIC_REFRESH_LOCK = threading.Lock()
TRAFFIC_REFRESH_STATE = {
    "running": False,
    "started_at": "",
    "finished_at": "",
    "ok_count": 0,
    "fail_count": 0,
    "message": "",
}


def get_conn():
    conn = sqlite3.connect(DB_PATH, timeout=30)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA busy_timeout=30000")
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
                renew_until_date TEXT NOT NULL DEFAULT '',
                next_rent_status TEXT NOT NULL DEFAULT 'unknown',
                last_month_tenant TEXT NOT NULL DEFAULT '',
                rental_rollover_key TEXT NOT NULL DEFAULT '',
                renter_name TEXT NOT NULL DEFAULT '',
                renter_email TEXT NOT NULL DEFAULT '',
                delivery_email_sent_at TEXT,
                renew_notice_sent_keys TEXT NOT NULL DEFAULT '',
                server_note TEXT NOT NULL DEFAULT '',
                sort_order INTEGER NOT NULL DEFAULT 0,
                agent_token TEXT NOT NULL DEFAULT '',
                period_key TEXT NOT NULL DEFAULT '',
                period_upload_bytes INTEGER NOT NULL DEFAULT 0,
                period_download_bytes INTEGER NOT NULL DEFAULT 0,
                last_agent_rx_bytes INTEGER NOT NULL DEFAULT 0,
                last_agent_tx_bytes INTEGER NOT NULL DEFAULT 0,
                last_agent_report_at TEXT,
                last_traffic_sync_at TEXT,
                traffic_throttled INTEGER NOT NULL DEFAULT 0,
                last_reset_at TEXT,
                ssh_status TEXT NOT NULL DEFAULT 'unknown',
                ssh_checked_at TEXT,
                scp_image_catalog TEXT NOT NULL DEFAULT '',
                scp_selected_image TEXT NOT NULL DEFAULT ''
            )
            """
        )
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS server_groups (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                name TEXT NOT NULL,
                description TEXT NOT NULL DEFAULT '',
                sort_order INTEGER NOT NULL DEFAULT 0,
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL
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
                notify_email_enabled INTEGER NOT NULL DEFAULT 0,
                smtp_host TEXT NOT NULL DEFAULT '',
                smtp_port INTEGER NOT NULL DEFAULT 587,
                smtp_user TEXT NOT NULL DEFAULT '',
                smtp_password TEXT NOT NULL DEFAULT '',
                smtp_from TEXT NOT NULL DEFAULT '',
                notify_email_to TEXT NOT NULL DEFAULT '',
                traffic_sample_interval_minutes INTEGER NOT NULL DEFAULT 60,
                backup_email_enabled INTEGER NOT NULL DEFAULT 0,
                backup_email_to TEXT NOT NULL DEFAULT '',
                backup_interval_days INTEGER NOT NULL DEFAULT 7,
                backup_last_sent_at TEXT,
                data_zip_url TEXT NOT NULL DEFAULT '',
                data_zip_enabled INTEGER NOT NULL DEFAULT 0,
                data_zip_source TEXT NOT NULL DEFAULT 'original',
                local_vt_data_path TEXT NOT NULL DEFAULT '',
                local_vt_data_zip_url TEXT NOT NULL DEFAULT '',
                local_setting_json_path TEXT NOT NULL DEFAULT '',
                local_setting_json_enabled INTEGER NOT NULL DEFAULT 0,
                api_failure_notify_enabled INTEGER NOT NULL DEFAULT 0,
                panel_password_hash TEXT,
                renew_notice_days TEXT NOT NULL DEFAULT '5,2',
                stock_page_title TEXT NOT NULL DEFAULT '库存展示',
                public_stock_port INTEGER NOT NULL DEFAULT 5001,
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
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS task_queue (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                server_id INTEGER NOT NULL,
                log_id INTEGER NOT NULL,
                attempt INTEGER NOT NULL DEFAULT 0,
                max_attempts INTEGER NOT NULL DEFAULT 2,
                backoff_plan TEXT NOT NULL DEFAULT '',
                status TEXT NOT NULL DEFAULT 'queued',
                next_run_at TEXT NOT NULL,
                last_error TEXT NOT NULL DEFAULT '',
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL
            )
            """
        )
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS scp_accounts (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                name TEXT NOT NULL,
                username TEXT NOT NULL,
                password TEXT NOT NULL,
                refresh_token TEXT NOT NULL DEFAULT '',
                api_endpoint TEXT NOT NULL DEFAULT 'https://www.servercontrolpanel.de/scp-core/api/v1',
                api_status TEXT NOT NULL DEFAULT 'unknown',
                api_checked_at TEXT,
                api_last_error TEXT NOT NULL DEFAULT '',
                api_last_notified_at TEXT,
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL
            )
            """
        )
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS notification_batches (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                batch_key TEXT NOT NULL UNIQUE,
                scheduled_for TEXT NOT NULL,
                notified INTEGER NOT NULL DEFAULT 0,
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL
            )
            """
        )
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS notification_batch_items (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                batch_key TEXT NOT NULL,
                server_id INTEGER NOT NULL,
                server_name TEXT NOT NULL,
                server_ip TEXT NOT NULL,
                status TEXT NOT NULL,
                note TEXT NOT NULL DEFAULT '',
                log_id INTEGER,
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL
            )
            """
        )
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS api_image_refresh_jobs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                status TEXT NOT NULL DEFAULT 'running',
                total_count INTEGER NOT NULL DEFAULT 0,
                processed_count INTEGER NOT NULL DEFAULT 0,
                success_count INTEGER NOT NULL DEFAULT 0,
                failed_count INTEGER NOT NULL DEFAULT 0,
                output TEXT NOT NULL DEFAULT '',
                created_at TEXT NOT NULL,
                started_at TEXT NOT NULL,
                finished_at TEXT
            )
            """
        )

        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS system_events (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                level TEXT NOT NULL DEFAULT 'info',
                event_type TEXT NOT NULL,
                message TEXT NOT NULL,
                details TEXT NOT NULL DEFAULT '',
                server_id INTEGER,
                account_id INTEGER,
                created_at TEXT NOT NULL
            )
            """
        )
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS email_history (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                category TEXT NOT NULL DEFAULT 'general',
                recipient TEXT NOT NULL,
                subject TEXT NOT NULL,
                status TEXT NOT NULL,
                error_message TEXT NOT NULL DEFAULT '',
                body_text TEXT NOT NULL DEFAULT '',
                created_at TEXT NOT NULL
            )
            """
        )
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS traffic_metrics_cache (
                server_id INTEGER PRIMARY KEY,
                generated_at TEXT NOT NULL,
                windows_json TEXT NOT NULL DEFAULT '{}',
                daily_rows_json TEXT NOT NULL DEFAULT '[]',
                steps_json TEXT NOT NULL DEFAULT '{}',
                samples_json TEXT NOT NULL DEFAULT '{}'
            )
            """
        )

        ensure_column(conn, "servers", "last_reset_at TEXT")
        ensure_column(conn, "servers", "is_renewed INTEGER NOT NULL DEFAULT 0")
        ensure_column(conn, "servers", "is_rented INTEGER NOT NULL DEFAULT 0")
        ensure_column(conn, "servers", "renew_until_date TEXT NOT NULL DEFAULT ''")
        ensure_column(conn, "servers", "next_rent_status TEXT NOT NULL DEFAULT 'unknown'")
        ensure_column(conn, "servers", "last_month_tenant TEXT NOT NULL DEFAULT ''")
        ensure_column(conn, "servers", "rental_rollover_key TEXT NOT NULL DEFAULT ''")
        ensure_column(conn, "servers", "renter_name TEXT NOT NULL DEFAULT ''")
        ensure_column(conn, "servers", "renter_email TEXT NOT NULL DEFAULT ''")
        ensure_column(conn, "servers", "delivery_email_sent_at TEXT")
        ensure_column(conn, "servers", "renew_notice_sent_keys TEXT NOT NULL DEFAULT ''")
        ensure_column(conn, "servers", "server_note TEXT NOT NULL DEFAULT ''")
        ensure_column(conn, "servers", "server_group_id INTEGER")
        ensure_column(conn, "servers", "sort_order INTEGER NOT NULL DEFAULT 0")
        ensure_column(conn, "servers", "agent_token TEXT NOT NULL DEFAULT ''")
        ensure_column(conn, "servers", "period_key TEXT NOT NULL DEFAULT ''")
        ensure_column(conn, "servers", "period_upload_bytes INTEGER NOT NULL DEFAULT 0")
        ensure_column(conn, "servers", "period_download_bytes INTEGER NOT NULL DEFAULT 0")
        ensure_column(conn, "servers", "last_agent_rx_bytes INTEGER NOT NULL DEFAULT 0")
        ensure_column(conn, "servers", "last_agent_tx_bytes INTEGER NOT NULL DEFAULT 0")
        ensure_column(conn, "servers", "last_agent_report_at TEXT")
        ensure_column(conn, "servers", "last_traffic_sync_at TEXT")
        ensure_column(conn, "servers", "traffic_throttled INTEGER NOT NULL DEFAULT 0")
        ensure_column(conn, "servers", "ssh_status TEXT NOT NULL DEFAULT 'unknown'")
        ensure_column(conn, "servers", "ssh_checked_at TEXT")
        ensure_column(conn, "servers", "scp_image_catalog TEXT NOT NULL DEFAULT ''")
        ensure_column(conn, "servers", "scp_selected_image TEXT NOT NULL DEFAULT ''")
        ensure_column(conn, "servers", "reset_hour INTEGER NOT NULL DEFAULT 1")
        ensure_column(conn, "servers", "reset_minute INTEGER NOT NULL DEFAULT 0")
        ensure_column(conn, "servers", "max_retries INTEGER NOT NULL DEFAULT 2")
        ensure_column(conn, "servers", "retry_backoff_seconds TEXT NOT NULL DEFAULT '60,180'")
        ensure_column(conn, "servers", "scp_account_id INTEGER")
        ensure_column(conn, "servers", "scp_server_id TEXT NOT NULL DEFAULT ''")
        ensure_column(conn, "servers", "reinstall_mode TEXT NOT NULL DEFAULT 'ssh'")
        ensure_column(conn, "scp_accounts", "refresh_token TEXT NOT NULL DEFAULT ''")
        ensure_column(conn, "scp_accounts", "api_status TEXT NOT NULL DEFAULT 'unknown'")
        ensure_column(conn, "scp_accounts", "api_checked_at TEXT")
        ensure_column(conn, "scp_accounts", "api_last_error TEXT NOT NULL DEFAULT ''")
        ensure_column(conn, "scp_accounts", "api_last_notified_at TEXT")
        ensure_column(conn, "job_logs", "summary TEXT NOT NULL DEFAULT ''")
        ensure_column(conn, "task_queue", "trigger_type TEXT NOT NULL DEFAULT 'manual'")
        ensure_column(conn, "task_queue", "batch_key TEXT NOT NULL DEFAULT ''")
        ensure_column(conn, "global_config", "panel_password_hash TEXT")
        ensure_column(conn, "global_config", "renew_notice_days TEXT NOT NULL DEFAULT '5,2'")
        ensure_column(conn, "global_config", "stock_page_title TEXT NOT NULL DEFAULT '库存展示'")
        ensure_column(conn, "global_config", "public_stock_port INTEGER NOT NULL DEFAULT 5001")
        ensure_column(conn, "global_config", "agent_install_command TEXT NOT NULL DEFAULT ''")
        ensure_column(conn, "global_config", "panel_base_url TEXT NOT NULL DEFAULT ''")
        ensure_column(conn, "global_config", "notify_email_enabled INTEGER NOT NULL DEFAULT 0")
        ensure_column(conn, "global_config", "smtp_host TEXT NOT NULL DEFAULT ''")
        ensure_column(conn, "global_config", "smtp_port INTEGER NOT NULL DEFAULT 587")
        ensure_column(conn, "global_config", "smtp_user TEXT NOT NULL DEFAULT ''")
        ensure_column(conn, "global_config", "smtp_password TEXT NOT NULL DEFAULT ''")
        ensure_column(conn, "global_config", "smtp_from TEXT NOT NULL DEFAULT ''")
        ensure_column(conn, "global_config", "notify_email_to TEXT NOT NULL DEFAULT ''")
        ensure_column(conn, "global_config", "traffic_sample_interval_minutes INTEGER NOT NULL DEFAULT 60")
        ensure_column(conn, "global_config", "backup_email_enabled INTEGER NOT NULL DEFAULT 0")
        ensure_column(conn, "global_config", "backup_email_to TEXT NOT NULL DEFAULT ''")
        ensure_column(conn, "global_config", "backup_interval_days INTEGER NOT NULL DEFAULT 7")
        ensure_column(conn, "global_config", "backup_last_sent_at TEXT")
        ensure_column(conn, "global_config", "data_zip_url TEXT NOT NULL DEFAULT ''")
        ensure_column(conn, "global_config", "data_zip_enabled INTEGER NOT NULL DEFAULT 0")
        ensure_column(conn, "global_config", "data_zip_source TEXT NOT NULL DEFAULT 'original'")
        ensure_column(conn, "global_config", "local_vt_data_path TEXT NOT NULL DEFAULT ''")
        ensure_column(conn, "global_config", "local_vt_data_zip_url TEXT NOT NULL DEFAULT ''")
        ensure_column(conn, "global_config", "local_setting_json_path TEXT NOT NULL DEFAULT ''")
        ensure_column(conn, "global_config", "local_setting_json_enabled INTEGER NOT NULL DEFAULT 0")
        ensure_column(conn, "global_config", "api_failure_notify_enabled INTEGER NOT NULL DEFAULT 0")
        ensure_column(conn, "email_history", "body_text TEXT NOT NULL DEFAULT ''")
        conn.execute("INSERT OR IGNORE INTO global_config(id) VALUES (1)")
        current_hash = conn.execute("SELECT panel_password_hash FROM global_config WHERE id = 1").fetchone()[0]
        if not current_hash:
            conn.execute(
                "UPDATE global_config SET panel_password_hash = ?, updated_at = ? WHERE id = 1",
                (generate_password_hash("admin"), datetime.now(TIMEZONE).strftime("%Y-%m-%d %H:%M:%S")),
            )
        conn.commit()



def create_api_image_refresh_job(total_count):
    now_text = datetime.now(TIMEZONE).strftime("%Y-%m-%d %H:%M:%S")
    with closing(get_conn()) as conn:
        cur = conn.execute(
            """
            INSERT INTO api_image_refresh_jobs(status, total_count, processed_count, success_count, failed_count, output, created_at, started_at)
            VALUES('running', ?, 0, 0, 0, '', ?, ?)
            """,
            (max(0, int(total_count or 0)), now_text, now_text),
        )
        conn.commit()
        return cur.lastrowid


def append_api_image_refresh_job_output(job_id, message, processed_count=None, success_count=None, failed_count=None, status=None, finished=False):
    now_text = datetime.now(TIMEZONE).strftime("%Y-%m-%d %H:%M:%S")
    with closing(get_conn()) as conn:
        row = conn.execute("SELECT output, processed_count, success_count, failed_count, status FROM api_image_refresh_jobs WHERE id = ?", (job_id,)).fetchone()
        if not row:
            return
        output = (row["output"] or "").strip()
        output = (output + "\n" + message).strip() if output else message
        proc = int(processed_count if processed_count is not None else (row["processed_count"] or 0))
        succ = int(success_count if success_count is not None else (row["success_count"] or 0))
        fail = int(failed_count if failed_count is not None else (row["failed_count"] or 0))
        st = (status or row["status"] or "running").strip()
        finished_at = now_text if finished else None
        conn.execute(
            """
            UPDATE api_image_refresh_jobs
            SET output = ?, processed_count = ?, success_count = ?, failed_count = ?, status = ?, finished_at = ?
            WHERE id = ?
            """,
            (output, proc, succ, fail, st, finished_at, job_id),
        )
        conn.commit()


def get_latest_api_image_refresh_job():
    with closing(get_conn()) as conn:
        return conn.execute("SELECT * FROM api_image_refresh_jobs ORDER BY id DESC LIMIT 1").fetchone()


def run_api_image_refresh_job(job_id):
    rows = list_servers()
    total = len(rows)
    processed = 0
    success = 0
    failed = 0
    append_api_image_refresh_job_output(job_id, f"开始刷新服务器API可用镜像，总计 {total} 台", processed_count=0, success_count=0, failed_count=0, status='running')
    log_system_event("api_image_refresh", f"开始刷新服务器镜像，总计{total}台")

    for row in rows:
        try:
            refresh_server_api_images(row)
            success += 1
            append_api_image_refresh_job_output(job_id, f"[{row['name']}] 镜像刷新成功", processed_count=processed + 1, success_count=success, failed_count=failed, status='running')
            log_system_event("api_image_refresh", f"镜像刷新成功: {row['name']}", server_id=row["id"])
        except Exception as exc:
            failed += 1
            append_api_image_refresh_job_output(job_id, f"[{row['name']}] 镜像刷新失败: {exc}", processed_count=processed + 1, success_count=success, failed_count=failed, status='running')
            log_system_event("api_image_refresh", f"镜像刷新失败: {row['name']}", level="error", server_id=row["id"], details=str(exc))
        processed += 1

    final_status = 'success' if failed == 0 else 'failed'
    append_api_image_refresh_job_output(
        job_id,
        f"刷新完成：成功 {success} 台，失败 {failed} 台",
        processed_count=processed,
        success_count=success,
        failed_count=failed,
        status=final_status,
        finished=True,
    )
    log_system_event("api_image_refresh", f"镜像刷新完成：成功{success}台，失败{failed}台")


def start_api_image_refresh_background_job():
    if API_IMAGE_REFRESH_LOCK.locked():
        return None
    rows = list_servers()
    job_id = create_api_image_refresh_job(len(rows))

    def _runner():
        with API_IMAGE_REFRESH_LOCK:
            run_api_image_refresh_job(job_id)

    thread = threading.Thread(target=_runner, daemon=True)
    thread.start()
    return job_id

def list_servers():
    with closing(get_conn()) as conn:
        return conn.execute(
            """
            SELECT s.*, g.name AS group_name, g.description AS group_description, g.sort_order AS group_sort_order
            FROM servers s
            LEFT JOIN server_groups g ON g.id = s.server_group_id
            ORDER BY s.sort_order ASC, s.id ASC
            """
        ).fetchall()


def list_server_groups():
    with closing(get_conn()) as conn:
        return conn.execute("SELECT * FROM server_groups ORDER BY sort_order ASC, id ASC").fetchall()


def load_traffic_metrics_cache_map():
    with closing(get_conn()) as conn:
        rows = conn.execute("SELECT * FROM traffic_metrics_cache").fetchall()
    out = {}
    for row in rows:
        try:
            windows = json.loads(row["windows_json"] or "{}")
        except Exception:
            windows = {}
        try:
            daily_rows = json.loads(row["daily_rows_json"] or "[]")
        except Exception:
            daily_rows = []
        try:
            steps = json.loads(row["steps_json"] or "{}")
        except Exception:
            steps = {}
        try:
            samples = json.loads(row["samples_json"] or "{}")
        except Exception:
            samples = {}
        out[row["server_id"]] = {
            "generated_at": row["generated_at"],
            "windows": windows,
            "daily_rows": daily_rows,
            "steps": steps,
            "samples": samples,
        }
    return out


def save_traffic_metrics_cache(server_id, windows, daily_rows, steps, samples):
    now_text = datetime.now(TIMEZONE).strftime("%Y-%m-%d %H:%M:%S")
    with closing(get_conn()) as conn:
        conn.execute(
            """
            INSERT INTO traffic_metrics_cache(server_id, generated_at, windows_json, daily_rows_json, steps_json, samples_json)
            VALUES(?, ?, ?, ?, ?, ?)
            ON CONFLICT(server_id) DO UPDATE SET
                generated_at=excluded.generated_at,
                windows_json=excluded.windows_json,
                daily_rows_json=excluded.daily_rows_json,
                steps_json=excluded.steps_json,
                samples_json=excluded.samples_json
            """,
            (
                server_id,
                now_text,
                json.dumps(windows or {}, ensure_ascii=False),
                json.dumps(daily_rows or [], ensure_ascii=False),
                json.dumps(steps or {}, ensure_ascii=False),
                json.dumps(samples or {}, ensure_ascii=False),
            ),
        )
        conn.commit()


def load_traffic_metrics_cache_map():
    with closing(get_conn()) as conn:
        rows = conn.execute("SELECT * FROM traffic_metrics_cache").fetchall()
    out = {}
    for row in rows:
        try:
            windows = json.loads(row["windows_json"] or "{}")
        except Exception:
            windows = {}
        try:
            daily_rows = json.loads(row["daily_rows_json"] or "[]")
        except Exception:
            daily_rows = []
        try:
            steps = json.loads(row["steps_json"] or "{}")
        except Exception:
            steps = {}
        try:
            samples = json.loads(row["samples_json"] or "{}")
        except Exception:
            samples = {}
        out[row["server_id"]] = {
            "generated_at": row["generated_at"],
            "windows": windows,
            "daily_rows": daily_rows,
            "steps": steps,
            "samples": samples,
        }
    return out


def save_traffic_metrics_cache(server_id, windows, daily_rows, steps, samples):
    now_text = datetime.now(TIMEZONE).strftime("%Y-%m-%d %H:%M:%S")
    with closing(get_conn()) as conn:
        conn.execute(
            """
            INSERT INTO traffic_metrics_cache(server_id, generated_at, windows_json, daily_rows_json, steps_json, samples_json)
            VALUES(?, ?, ?, ?, ?, ?)
            ON CONFLICT(server_id) DO UPDATE SET
                generated_at=excluded.generated_at,
                windows_json=excluded.windows_json,
                daily_rows_json=excluded.daily_rows_json,
                steps_json=excluded.steps_json,
                samples_json=excluded.samples_json
            """,
            (
                server_id,
                now_text,
                json.dumps(windows or {}, ensure_ascii=False),
                json.dumps(daily_rows or [], ensure_ascii=False),
                json.dumps(steps or {}, ensure_ascii=False),
                json.dumps(samples or {}, ensure_ascii=False),
            ),
        )
        conn.commit()


def get_server(server_id):
    with closing(get_conn()) as conn:
        return conn.execute("SELECT * FROM servers WHERE id=?", (server_id,)).fetchone()


def _normalize_next_rent_status(value):
    text = str(value or "unknown").strip().lower()
    if text in {"confirmed", "unknown", "non_renew"}:
        return text
    return "unknown"


def normalize_renew_notice_days_text(value):
    raw = str(value or "").replace("，", ",")
    days = []
    for token in raw.split(","):
        token = token.strip()
        if not token or not token.isdigit():
            continue
        day = int(token)
        if day <= 0 or day > 120:
            continue
        if day not in days:
            days.append(day)
    if not days:
        days = [5, 2]
    return ",".join(str(day) for day in days)


def parse_renew_notice_days(value):
    return [int(item) for item in normalize_renew_notice_days_text(value).split(",") if item.isdigit()]


def _parse_notice_key_set(raw_text):
    return {item.strip() for item in str(raw_text or "").split("|") if item.strip()}


def _compose_notice_key(target_reset_dt, days_before):
    return f"{target_reset_dt.strftime('%Y-%m-%d %H:%M')}#{int(days_before)}"


def _format_next_month_tenant(row):
    renter = str(row["renter_name"] or "").strip()
    status = _normalize_next_rent_status(row["next_rent_status"])
    if status == "unknown" and int(row["is_renewed"] or 0) == 1:
        status = "confirmed"
    if status == "confirmed":
        if renter:
            if "（续费）" in renter:
                return renter
            return f"{renter}（续费）"
        return "已确认续租（待补充租户）"
    if status == "non_renew":
        return "不续租"
    return "未知"


def _rental_cycle_key(now_dt):
    return f"{now_dt.year:04d}-{now_dt.month:02d}"


def _server_rental_cycle_key(server_row, now_dt=None):
    now_dt = now_dt or datetime.now(TIMEZONE)
    if isinstance(server_row, sqlite3.Row):
        row_keys = set(server_row.keys())
        reset_day = int(server_row["reset_day"] if "reset_day" in row_keys else 1)
        reset_hour = int(server_row["reset_hour"] if "reset_hour" in row_keys else 1)
        reset_minute = int(server_row["reset_minute"] if "reset_minute" in row_keys else 0)
    else:
        data = server_row or {}
        reset_day = int(data.get("reset_day") or 1)
        reset_hour = int(data.get("reset_hour") or 1)
        reset_minute = int(data.get("reset_minute") or 0)

    current_month_day = month_day_safe(now_dt.year, now_dt.month, reset_day)
    current_refresh_dt = now_dt.replace(day=current_month_day, hour=reset_hour, minute=reset_minute, second=0, microsecond=0)
    if now_dt >= current_refresh_dt:
        return _rental_cycle_key(now_dt)

    if now_dt.month == 1:
        prev_year, prev_month = now_dt.year - 1, 12
    else:
        prev_year, prev_month = now_dt.year, now_dt.month - 1
    return f"{prev_year:04d}-{prev_month:02d}"


def apply_monthly_rental_rollover_if_needed(now_dt=None):
    now_dt = now_dt or datetime.now(TIMEZONE)
    with closing(get_conn()) as conn:
        rows = conn.execute(
            "SELECT id, name, reset_day, reset_hour, reset_minute, is_rented, is_renewed, renew_until_date, renter_name, renter_email, next_rent_status, rental_rollover_key, delivery_email_sent_at, renew_notice_sent_keys FROM servers ORDER BY sort_order ASC, id ASC"
        ).fetchall()
        changed = 0
        for row in rows:
            cycle_key = _server_rental_cycle_key(row, now_dt)
            if str(row["rental_rollover_key"] or "").strip() == cycle_key:
                continue

            renew_until = _parse_date_text(row["renew_until_date"])
            if renew_until and now_dt.date() < renew_until:
                current_tenant = str(row["renter_name"] or "").strip()
                current_email = str(row["renter_email"] or "").strip()
                next_current_tenant = current_tenant if int(row["is_rented"] or 0) == 1 else ""
                next_current_email = current_email if int(row["is_rented"] or 0) == 1 else ""
                conn.execute(
                    """
                    UPDATE servers
                    SET last_month_tenant = ?,
                        renter_name = ?,
                        renter_email = ?,
                        next_rent_status = 'unknown',
                        delivery_email_sent_at = CASE WHEN ? <> '' THEN delivery_email_sent_at ELSE NULL END,
                        renew_notice_sent_keys = CASE WHEN ? <> '' THEN renew_notice_sent_keys ELSE '' END,
                        rental_rollover_key = ?
                    WHERE id = ?
                    """,
                    (current_tenant, next_current_tenant, next_current_email, next_current_email, next_current_email, cycle_key, row["id"]),
                )
                changed += 1
                continue

            current_tenant = str(row["renter_name"] or "").strip()
            current_email = str(row["renter_email"] or "").strip()
            status = _normalize_next_rent_status(row["next_rent_status"])
            next_current_tenant = ""
            next_current_email = ""
            if int(row["is_rented"] or 0) == 1 and status == "confirmed":
                next_current_tenant = current_tenant
                next_current_email = current_email

            conn.execute(
                """
                UPDATE servers
                SET last_month_tenant = ?,
                    renter_name = ?,
                    renter_email = ?,
                    next_rent_status = 'unknown',
                    is_renewed = 0,
                    delivery_email_sent_at = CASE WHEN ? <> '' THEN delivery_email_sent_at ELSE NULL END,
                    renew_notice_sent_keys = CASE WHEN ? <> '' THEN renew_notice_sent_keys ELSE '' END,
                    rental_rollover_key = ?
                WHERE id = ?
                """,
                (current_tenant, next_current_tenant, next_current_email, next_current_email, next_current_email, cycle_key, row["id"]),
            )
            changed += 1

        if changed:
            conn.commit()
            log_system_event("rental_rollover", f"出租管理月度迁移完成：{changed}台")


def list_rental_management_rows():
    rows = list_servers()
    out = []
    for row in rows:
        item = dict(row)
        item["next_rent_status"] = _normalize_next_rent_status(item.get("next_rent_status"))
        if item["next_rent_status"] == "unknown" and int(item.get("is_renewed") or 0) == 1:
            item["next_rent_status"] = "confirmed"
        item["next_month_tenant_text"] = _format_next_month_tenant(item)
        item["last_month_tenant_text"] = str(item.get("last_month_tenant") or "").strip()
        item["refresh_day_text"] = f"{int(item.get('reset_day') or 1)}号"
        item["status_card_class"] = {
            "confirmed": "rental-card-confirmed",
            "non_renew": "rental-card-non-renew",
        }.get(item["next_rent_status"], "rental-card-unknown")
        out.append(item)
    return out


def list_scp_accounts():
    with closing(get_conn()) as conn:
        return conn.execute("SELECT * FROM scp_accounts ORDER BY id ASC").fetchall()


def get_scp_account(account_id):
    if not account_id:
        return None
    with closing(get_conn()) as conn:
        return conn.execute("SELECT * FROM scp_accounts WHERE id=?", (account_id,)).fetchone()


def bind_scp_server(server_id, account_id, scp_server_id):
    with closing(get_conn()) as conn:
        conn.execute(
            "UPDATE servers SET scp_account_id = ?, scp_server_id = ? WHERE id = ?",
            (account_id, str(scp_server_id or "").strip(), server_id),
        )
        conn.commit()




def save_server_scp_images(server_id, images, selected_key=""):
    payload = json.dumps(images or [], ensure_ascii=False)
    with closing(get_conn()) as conn:
        conn.execute(
            "UPDATE servers SET scp_image_catalog = ?, scp_selected_image = ? WHERE id = ?",
            (payload, str(selected_key or "").strip(), server_id),
        )
        conn.commit()


def load_server_scp_images(server_row):
    if isinstance(server_row, sqlite3.Row):
        text = str(server_row["scp_image_catalog"] or "").strip()
    else:
        text = str((server_row or {}).get("scp_image_catalog") or "").strip()
    if not text:
        return []
    try:
        data = json.loads(text)
    except Exception:
        return []
    if isinstance(data, list):
        return data
    return []


def make_scp_image_option_key(option):
    flavour = str(option.get("imageFlavourId") or "").strip()
    image = str(option.get("imageId") or "").strip()
    if flavour:
        return f"flavour:{flavour}"
    if image:
        return f"image:{image}"
    return ""


def pick_scp_image_option_by_key(options, key):
    key_text = str(key or "").strip()
    if not key_text:
        return None
    for item in options or []:
        if make_scp_image_option_key(item) == key_text:
            return item
    return None

def _scp_endpoint_candidates(api_endpoint):
    raw = (api_endpoint or "").strip()
    if not raw:
        raw = "https://www.servercontrolpanel.de/scp-core/api/v1"

    cleaned = raw.split("?", 1)[0].rstrip("/")
    if not cleaned:
        cleaned = "https://www.servercontrolpanel.de"

    if "WSEndUser" in cleaned:
        host = cleaned.split("/WSEndUser", 1)[0].rstrip("/")
    elif "/scp-core/api/" in cleaned:
        host = cleaned.split("/scp-core/api/", 1)[0].rstrip("/")
    elif "/api/" in cleaned:
        host = cleaned.split("/api/", 1)[0].rstrip("/")
    else:
        host = cleaned

    out = []
    for candidate in (
        cleaned,
        f"{host}/scp-core/api/v1",
        f"{host}/scp-core/api",
        f"{host}/api/v1",
        f"{host}/api",
        host,
    ):
        c = (candidate or "").rstrip("/")
        if c and c not in out:
            out.append(c)

    for default_base in (
        "https://www.servercontrolpanel.de/scp-core/api/v1",
        "https://www.servercontrolpanel.de/api/v1",
    ):
        if default_base not in out:
            out.append(default_base)
    return out


def _scp_rest_base_endpoint(api_endpoint):
    for candidate in _scp_endpoint_candidates(api_endpoint):
        if "/scp-core/api" in candidate:
            return candidate
        if "/api" in candidate:
            return candidate
    return "https://www.servercontrolpanel.de/scp-core/api/v1"


def _scp_rest_extract_token(data):
    if not isinstance(data, dict):
        return None
    for key in ("token", "access_token", "jwt", "session", "session_id", "sessionId"):
        val = data.get(key)
        if isinstance(val, str) and val.strip():
            return val.strip()
    nested = data.get("data")
    if isinstance(nested, dict):
        return _scp_rest_extract_token(nested)
    return None


def _scp_rest_refresh_access_token(account_row, timeout_seconds=60):
    refresh_token = (account_row["refresh_token"] or "").strip()
    if not refresh_token:
        return None

    token_url = "https://www.servercontrolpanel.de/realms/scp/protocol/openid-connect/token"
    body = urlparse.urlencode(
        {
            "client_id": "scp",
            "refresh_token": refresh_token,
            "grant_type": "refresh_token",
        }
    ).encode("utf-8")
    req = urlrequest.Request(
        token_url,
        data=body,
        headers={"Content-Type": "application/x-www-form-urlencoded", "Accept": "application/json"},
        method="POST",
    )
    with urlrequest.urlopen(req, timeout=timeout_seconds) as resp:
        data = json.loads(resp.read().decode("utf-8", errors="ignore") or "{}")
    token = _scp_rest_extract_token(data)
    if not token:
        raise RuntimeError("SCP OIDC 刷新成功但未返回access_token")
    return token


def scp_rest_login(account_row, timeout_seconds=60):
    try:
        token = _scp_rest_refresh_access_token(account_row, timeout_seconds=timeout_seconds)
        if not token:
            raise RuntimeError("SCP REST登录失败: 未配置可用的 OIDC Refresh Token")
        account_id = account_row["id"] if isinstance(account_row, sqlite3.Row) else account_row.get("id")
        if account_id:
            update_scp_account_api_status(account_id, "ok", "")
        return _scp_rest_base_endpoint(account_row["api_endpoint"]), token
    except Exception as exc:
        account_id = account_row["id"] if isinstance(account_row, sqlite3.Row) else account_row.get("id")
        if account_id:
            update_scp_account_api_status(account_id, "failed", str(exc))
            notify_scp_api_failure_if_needed(account_row, str(exc))
        raise


def scp_rest_request(account_row, method, path, token=None, payload=None, endpoint_base=None, timeout_seconds=60):
    endpoint = (endpoint_base or "").rstrip("/") or _scp_rest_base_endpoint(account_row["api_endpoint"])
    url = f"{endpoint}/{path.lstrip('/')}"
    headers = {"Accept": "application/json"}
    if token:
        headers["Authorization"] = f"Bearer {token}"
        headers["X-Auth-Token"] = token
    data = None
    if payload is not None:
        headers["Content-Type"] = "application/json"
        data = json.dumps(payload).encode("utf-8")
    req = urlrequest.Request(url, data=data, headers=headers, method=method.upper())
    with urlrequest.urlopen(req, timeout=timeout_seconds) as resp:
        raw = resp.read().decode("utf-8", errors="ignore")
    return json.loads(raw) if raw else {}


def _scp_collect_server_entries(data):
    if isinstance(data, list):
        for item in data:
            yield from _scp_collect_server_entries(item)
        return
    if not isinstance(data, dict):
        return
    if any(k in data for k in ("id", "serverId", "vserverid", "vserver")):
        yield data
    for key in ("items", "servers", "vservers", "data", "result"):
        nested = data.get(key)
        if nested is not None:
            yield from _scp_collect_server_entries(nested)


def _scp_extract_ips(server_item):
    ips = []
    for key in ("ip", "ipv4", "primary_ip", "primaryIp", "mainIp"):
        val = server_item.get(key)
        if isinstance(val, str) and val.strip():
            ips.append(val.strip())
    for key in ("ips", "ipAddresses", "addresses"):
        val = server_item.get(key)
        if isinstance(val, list):
            for entry in val:
                if isinstance(entry, str):
                    ips.append(entry.strip())
                elif isinstance(entry, dict):
                    cand = entry.get("ip") or entry.get("address") or entry.get("ipv4")
                    if isinstance(cand, str) and cand.strip():
                        ips.append(cand.strip())
    # parse interfaces payloads from SCP REST (`/servers/{id}/interfaces`).
    interfaces = server_item.get("interfaces")
    if isinstance(interfaces, list):
        for nic in interfaces:
            if not isinstance(nic, dict):
                continue
            for key in ("ipv4", "ipv6", "addresses", "routedIps", "routed_ips"):
                value = nic.get(key)
                if isinstance(value, list):
                    for item in value:
                        if isinstance(item, str) and item.strip():
                            ips.append(item.strip())
                        elif isinstance(item, dict):
                            cand = item.get("ip") or item.get("address")
                            if isinstance(cand, str) and cand.strip():
                                ips.append(cand.strip())
                elif isinstance(value, dict):
                    cand = value.get("ip") or value.get("address")
                    if isinstance(cand, str) and cand.strip():
                        ips.append(cand.strip())
    return [x for x in ips if x]


def _scp_extract_server_id(server_item):
    for key in ("id", "serverId", "server_id", "vserverid", "vserver"):
        val = server_item.get(key)
        if val is None:
            continue
        text = str(val).strip()
        if text:
            return text
    return ""


def _scp_rest_fetch_server_ips(account, endpoint_base, token, server_id):
    if not server_id:
        return []
    detail_paths = (
        f"servers/{server_id}",
        f"servers/{server_id}/ips",
        f"servers/{server_id}/ip-addresses",
        f"servers/{server_id}/interfaces",
        f"vservers/{server_id}",
    )
    for path in detail_paths:
        try:
            data = scp_rest_request(account, "GET", path, token=token, endpoint_base=endpoint_base)
        except Exception:
            continue

        # details may be object or list; reuse extraction helpers.
        for item in _scp_collect_server_entries(data):
            ips = _scp_extract_ips(item)
            if ips:
                return ips
        if isinstance(data, dict):
            ips = _scp_extract_ips(data)
            if ips:
                return ips
        elif isinstance(data, list):
            for entry in data:
                if isinstance(entry, str) and "." in entry:
                    return [entry.strip()]
                if isinstance(entry, dict):
                    ips = _scp_extract_ips(entry)
                    if ips:
                        return ips
    return []




def _scp_rest_list_server_images(account, endpoint_base, token, server_id):
    paths = (f"servers/{server_id}/imageflavours", f"servers/{server_id}/images", "imageflavours")
    options = []
    seen = set()

    def _pick_first(*values):
        for value in values:
            if value is None:
                continue
            text = str(value).strip()
            if text:
                return text
        return ""

    for path in paths:
        try:
            data = scp_rest_request(account, "GET", path, token=token, endpoint_base=endpoint_base)
        except Exception:
            continue

        candidates = []
        if isinstance(data, list):
            candidates = data
        elif isinstance(data, dict):
            for key in ("items", "data", "result", "imageflavours", "images"):
                nested = data.get(key)
                if isinstance(nested, list):
                    candidates.extend(nested)
            if not candidates and any(k in data for k in ("id", "imageId", "imageFlavourId", "flavourId", "name", "displayName", "text")):
                candidates = [data]

        for item in candidates:
            if not isinstance(item, dict):
                continue
            image_meta = item.get("image") if isinstance(item.get("image"), dict) else {}
            flavour_id = _pick_first(item.get("id"), item.get("imageFlavourId"), item.get("flavourId"))
            image_id = _pick_first(item.get("imageId"), image_meta.get("id"), item.get("key"))
            image_name = _pick_first(
                image_meta.get("name"),
                item.get("name"),
                item.get("displayName"),
                item.get("text"),
                item.get("label"),
                item.get("slug"),
            )
            distribution = _pick_first(image_meta.get("distribution"), item.get("distribution"))
            version = _pick_first(image_meta.get("version"), item.get("version"))
            if not flavour_id and not image_id:
                continue

            option = {
                "imageFlavourId": flavour_id,
                "imageId": image_id,
                "name": image_name or "未命名镜像",
                "distribution": distribution,
                "version": version,
            }
            key = make_scp_image_option_key(option)
            if not key or key in seen:
                continue
            seen.add(key)
            options.append(option)

    options.sort(key=lambda x: (str(x.get("distribution") or "").lower(), str(x.get("version") or "").lower(), str(x.get("name") or "").lower()))
    return options


def _scp_rest_find_debian11_image(account, endpoint_base, token, server_id):
    paths = (f"servers/{server_id}/imageflavours", f"servers/{server_id}/images", "imageflavours")
    best = None

    def _pick_first(*values):
        for value in values:
            if value is None:
                continue
            text = str(value).strip()
            if text:
                return text
        return ""

    for path in paths:
        try:
            data = scp_rest_request(account, "GET", path, token=token, endpoint_base=endpoint_base)
        except Exception:
            continue

        candidates = []
        if isinstance(data, list):
            candidates = data
        elif isinstance(data, dict):
            for key in ("items", "data", "result", "imageflavours", "images"):
                val = data.get(key)
                if isinstance(val, list):
                    candidates = val
                    break

        for item in candidates:
            if not isinstance(item, dict):
                continue
            image_meta = item.get("image") if isinstance(item.get("image"), dict) else {}
            haystack = " ".join(
                str(item.get(k) or "") for k in ("name", "label", "displayName", "distribution", "version", "slug", "key", "alias", "text")
            ).lower()
            image_haystack = " ".join(
                str(image_meta.get(k) or "") for k in ("name", "label", "displayName", "distribution", "version", "slug", "key")
            ).lower()
            all_text = f"{haystack} {image_haystack}".strip()
            if "debian" not in all_text or ("11" not in all_text and "bullseye" not in all_text):
                continue

            score = 0
            if "debian (11) bullseye" in all_text:
                score += 50
            if "bullseye" in all_text:
                score += 20
            if "debian" in all_text and "11" in all_text:
                score += 15
            if str(item.get("name") or "").strip().lower() == "minimal":
                score += 5

            flavour_id = _pick_first(item.get("id"), item.get("imageFlavourId"), item.get("flavourId"))
            image_id = _pick_first(item.get("imageId"), image_meta.get("id"), item.get("key"))
            image_name = _pick_first(image_meta.get("name"), item.get("name"), item.get("displayName"), item.get("text"))
            candidate = {
                "score": score,
                "flavour_id": flavour_id,
                "image_id": image_id,
                "image_name": image_name,
            }
            if best is None or candidate["score"] > best["score"]:
                best = candidate

    if best:
        return best
    return {"score": 0, "flavour_id": "", "image_id": "", "image_name": ""}


def _scp_extract_task_uuid(task_data):
    if not isinstance(task_data, dict):
        return ""
    for key in ("uuid", "taskId", "task_id", "id"):
        value = task_data.get(key)
        if value is None:
            continue
        text = str(value).strip()
        if text:
            return text
    for key in ("task", "taskInfo", "data", "result"):
        nested = task_data.get(key)
        if isinstance(nested, dict):
            value = _scp_extract_task_uuid(nested)
            if value:
                return value
    return ""


def _scp_wait_task_finished(account, task_uuid, output_lines, timeout_seconds=1800):
    if not task_uuid:
        return
    deadline = time.time() + max(60, int(timeout_seconds or 1800))
    last_state = ""
    while time.time() < deadline:
        endpoint_base, token = scp_rest_login(account)
        data = scp_rest_request(account, "GET", f"tasks/{task_uuid}", token=token, endpoint_base=endpoint_base)
        state = str((data or {}).get("state") or "").upper()
        progress = ""
        if isinstance(data, dict):
            task_progress = data.get("taskProgress") or {}
            if isinstance(task_progress, dict):
                progress = str(task_progress.get("progressInPercent") or "").strip()
        if state != last_state:
            output_lines.append(f"SCP任务状态更新: uuid={task_uuid}, state={state or '-'}, progress={progress or '-'}")
            last_state = state
        if state == "FINISHED":
            return data
        if state in ("ERROR", "FAILED", "CANCELED"):
            raise RuntimeError(f"SCP任务失败: uuid={task_uuid}, state={state}, detail={str(data)[:500]}")
        time.sleep(10)
    raise RuntimeError(f"SCP任务超时: uuid={task_uuid} 在限定时间内未完成")


def _scp_extract_root_password(task_data):
    if not isinstance(task_data, dict):
        return ""
    result = task_data.get("result")
    if isinstance(result, dict):
        pwd = result.get("rootPassword") or result.get("root_password")
        if pwd:
            return str(pwd).strip()
    pwd = task_data.get("rootPassword") or task_data.get("root_password")
    return str(pwd).strip() if pwd else ""


def find_scp_server_id_by_ip(server_ip, output_lines=None, account_candidates=None):
    ip_text = str(server_ip or "").strip()
    if not ip_text:
        return None, None

    candidates = account_candidates if account_candidates is not None else list_scp_accounts()
    for account in candidates:
        scanned_server_ids = set()
        try:
            endpoint_base, token = scp_rest_login(account)
            if output_lines is not None:
                output_lines.append(f"SCP账号[{account['name']}] REST鉴权成功，endpoint={endpoint_base}")

            for path in (f"servers?ip={urlparse.quote(ip_text)}", "servers", "servers?limit=200"):
                try:
                    data = scp_rest_request(account, "GET", path, token=token, endpoint_base=endpoint_base)
                except Exception as exc:
                    if output_lines is not None:
                        output_lines.append(f"SCP账号[{account['name']}] REST列表调用失败 path={path}: {exc}")
                    continue

                seen = 0
                for server_item in _scp_collect_server_entries(data):
                    seen += 1
                    server_id = _scp_extract_server_id(server_item)
                    if server_id and server_id in scanned_server_ids:
                        continue
                    if server_id:
                        scanned_server_ids.add(server_id)

                    if path.startswith("servers?ip=") and server_id:
                        if output_lines is not None:
                            output_lines.append(f"SCP账号[{account['name']}] REST按IP查询直接命中 server_id={server_id}, ip={ip_text}")
                        return account, server_id

                    candidate_ips = _scp_extract_ips(server_item)
                    if not candidate_ips and server_id:
                        candidate_ips = _scp_rest_fetch_server_ips(account, endpoint_base, token, server_id)
                    if ip_text in candidate_ips and server_id:
                        if output_lines is not None:
                            output_lines.append(f"SCP账号[{account['name']}] REST匹配成功 path={path}, server_id={server_id}, ip={ip_text}")
                        return account, server_id

                if output_lines is not None:
                    output_lines.append(f"SCP账号[{account['name']}] REST列表完成 path={path}, entries={seen}")
        except Exception as exc:
            if output_lines is not None:
                output_lines.append(f"SCP账号[{account['name']}] REST识别失败: {exc}")

    return None, None


# 旧版 SOAP/JSON 接口已移除：仅保留 OIDC Refresh Token + REST OpenAPI 流程。


def refresh_server_api_images(server_row, output_lines=None):
    mutable_server = dict(server_row)
    account = get_scp_account(mutable_server.get("scp_account_id"))
    scp_server_id = (mutable_server.get("scp_server_id") or "").strip()

    if not scp_server_id:
        account_scope = [account] if account else None
        account, scp_server_id = find_scp_server_id_by_ip(mutable_server.get("ip"), output_lines, account_candidates=account_scope)
        if not account or not scp_server_id:
            if account_scope:
                raise RuntimeError(f"未能在指定SCP账号[{account_scope[0]['name']}]中按IP匹配到目标服务器")
            raise RuntimeError("未能在已配置SCP账号中按IP匹配到目标服务器")
        bind_scp_server(mutable_server["id"], account["id"], scp_server_id)
        mutable_server["scp_server_id"] = scp_server_id
        mutable_server["scp_account_id"] = account["id"]
        if output_lines is not None:
            output_lines.append(f"已按IP自动匹配SCP服务器并绑定: 账号[{account['name']}] server_id={scp_server_id}")
    elif not account:
        raise RuntimeError("已填写SCP服务器ID，但未绑定SCP账号，请在服务器设置中选择SCP账号")

    endpoint_base, token = scp_rest_login(account)
    options = _scp_rest_list_server_images(account, endpoint_base, token, scp_server_id)
    selected_key = ""
    if options:
        selected = pick_scp_image_option_by_key(options, mutable_server.get("scp_selected_image"))
        if not selected:
            selected = options[0]
        selected_key = make_scp_image_option_key(selected)
    save_server_scp_images(mutable_server["id"], options, selected_key=selected_key)
    if output_lines is not None:
        output_lines.append(f"镜像刷新完成: {mutable_server['name']} 可用镜像 {len(options)} 个")
    return options


def scp_reinstall_debian11(server_row, output_lines, preferred_image=None):
    if isinstance(server_row, sqlite3.Row):
        account_id = server_row["scp_account_id"]
        scp_server_id = str(server_row["scp_server_id"] or "").strip()
    else:
        account_id = (server_row or {}).get("scp_account_id")
        scp_server_id = str((server_row or {}).get("scp_server_id") or "").strip()
    account = get_scp_account(account_id)

    if scp_server_id and account:
        output_lines.append(f"已使用面板已配置SCP绑定: 账号[{account['name']}], server_id={scp_server_id}")
    elif scp_server_id and not account:
        raise RuntimeError("已填写SCP服务器ID，但未绑定SCP账号，请在服务器设置中选择SCP账号")
    else:
        account_scope = [account] if account else None
        account, scp_server_id = find_scp_server_id_by_ip(server_row["ip"], output_lines, account_candidates=account_scope)
        if not account or not scp_server_id:
            if account_scope:
                raise RuntimeError(f"未能在指定SCP账号[{account_scope[0]['name']}]中按IP匹配到目标服务器")
            raise RuntimeError("未能在已配置SCP账号中按IP匹配到目标服务器")
        bind_scp_server(server_row["id"], account["id"], scp_server_id)
        output_lines.append(f"已按IP自动匹配SCP服务器并绑定: 账号[{account['name']}] server_id={scp_server_id}")

    try:
        endpoint_base, token = scp_rest_login(account)
        output_lines.append(f"SCP REST鉴权成功，endpoint={endpoint_base}")
        payload_variants = []
        preferred = preferred_image if isinstance(preferred_image, dict) else {}
        preferred_flavour = str(preferred.get("imageFlavourId") or "").strip()
        preferred_image_id = str(preferred.get("imageId") or "").strip()
        preferred_name = str(preferred.get("name") or "").strip()
        if preferred_flavour or preferred_image_id:
            output_lines.append(
                "SCP REST使用手动选择镜像: "
                f"name={preferred_name or '-'}, flavour_id={preferred_flavour or '-'}, image_id={preferred_image_id or '-'}"
            )
            if preferred_flavour:
                payload_variants.append({"imageFlavourId": int(preferred_flavour) if preferred_flavour.isdigit() else preferred_flavour})
            if preferred_image_id:
                payload_variants.append({"imageId": int(preferred_image_id) if preferred_image_id.isdigit() else preferred_image_id})
        else:
            image_pick = _scp_rest_find_debian11_image(account, endpoint_base, token, scp_server_id)
            flavour_id = (image_pick.get("flavour_id") or "").strip()
            image_id = (image_pick.get("image_id") or "").strip()
            if flavour_id or image_id:
                output_lines.append(
                    "SCP REST检测到 Debian11镜像候选: "
                    f"flavour_id={flavour_id or '-'}, image_id={image_id or '-'}, name={image_pick.get('image_name') or '-'}"
                )
            else:
                output_lines.append("SCP REST未检测到明确 Debian11 镜像ID，将使用通用payload尝试")
            if flavour_id:
                payload_variants.append({"imageFlavourId": int(flavour_id) if str(flavour_id).isdigit() else flavour_id})
            if image_id:
                payload_variants.append({"imageId": int(image_id) if str(image_id).isdigit() else image_id})
        if not payload_variants:
            raise RuntimeError("未找到可用镜像ID，无法按SCP文档接口执行重装")

        output_lines.append("SCP REST将按文档接口执行: POST /servers/{serverId}/image + imageFlavourId/imageId")
        for path in (f"servers/{scp_server_id}/image",):
            try:
                for payload in payload_variants:
                    result = scp_rest_request(account, "POST", path, token=token, payload=payload, endpoint_base=endpoint_base)
                    request_id = "-"
                    task_uuid = _scp_extract_task_uuid(result)
                    root_password = _scp_extract_root_password(result)
                    if isinstance(result, dict):
                        request_id = str(
                            result.get("request_id")
                            or result.get("job_id")
                            or result.get("taskId")
                            or result.get("uuid")
                            or result.get("id")
                            or "-"
                        )
                    if task_uuid:
                        output_lines.append(f"SCP REST重装任务已创建: uuid={task_uuid}，开始轮询任务状态")
                        task_result = _scp_wait_task_finished(account, task_uuid, output_lines)
                        if not root_password:
                            root_password = _scp_extract_root_password(task_result)
                    if root_password:
                        server_row["ssh_password"] = root_password
                        update_server_password(server_row["id"], root_password)
                        output_lines.append("SCP返回了root密码，已自动回写到面板并用于后续SSH重连")
                    output_lines.append(f"SCP REST重装请求已提交: request_id={request_id}, server_id={scp_server_id}, os=debian11, path={path}")
                    return
            except Exception as exc:
                output_lines.append(f"SCP REST重装调用失败 path={path}: {exc}")
                continue
        raise RuntimeError("SCP REST重装提交失败：已尝试 /servers/{id}/image 但全部失败")
    except Exception as rest_exc:
        raise RuntimeError(f"SCP REST重装提交失败: {rest_exc}")


def get_global_config():
    with closing(get_conn()) as conn:
        row = conn.execute("SELECT * FROM global_config WHERE id=1").fetchone()
        if row:
            return row
        now_text = datetime.now(TIMEZONE).strftime("%Y-%m-%d %H:%M:%S")
        conn.execute("INSERT OR IGNORE INTO global_config(id, updated_at) VALUES (1, ?)", (now_text,))
        conn.commit()
        return conn.execute("SELECT * FROM global_config WHERE id=1").fetchone()




def update_backup_email_config(enabled, backup_email_to, interval_days):
    with closing(get_conn()) as conn:
        conn.execute(
            """
            UPDATE global_config
            SET backup_email_enabled=?, backup_email_to=?, backup_interval_days=?, updated_at=?
            WHERE id=1
            """,
            (
                int(enabled),
                (backup_email_to or "").strip(),
                max(1, int(interval_days)),
                datetime.now(TIMEZONE).strftime("%Y-%m-%d %H:%M:%S"),
            ),
        )
        conn.commit()
def update_global_config(reset_command, ssh_command_2, ssh_command_3, agent_install_command, panel_base_url, notify_email_enabled, smtp_host, smtp_port, smtp_user, smtp_password, smtp_from, notify_email_to, traffic_sample_interval_minutes, data_zip_enabled, data_zip_source, local_vt_data_path, local_setting_json_enabled, api_failure_notify_enabled, renew_notice_days):
    with closing(get_conn()) as conn:
        conn.execute(
            """
            UPDATE global_config
            SET reset_command=?, ssh_command_2=?, ssh_command_3=?, agent_install_command=?, panel_base_url=?, notify_email_enabled=?, smtp_host=?, smtp_port=?, smtp_user=?, smtp_password=?, smtp_from=?, notify_email_to=?, traffic_sample_interval_minutes=?, data_zip_enabled=?, data_zip_source=?, local_vt_data_path=?, local_setting_json_enabled=?, api_failure_notify_enabled=?, renew_notice_days=?, updated_at=?
            WHERE id=1
            """,
            (
                reset_command.strip(),
                ssh_command_2.strip(),
                ssh_command_3.strip(),
                agent_install_command.strip(),
                panel_base_url.strip(),
                int(notify_email_enabled),
                smtp_host.strip(),
                int(smtp_port),
                smtp_user.strip(),
                smtp_password,
                smtp_from.strip(),
                notify_email_to.strip(),
                max(1, int(traffic_sample_interval_minutes)),
                int(data_zip_enabled),
                (data_zip_source or "original").strip() if (data_zip_source or "original").strip() in {"original", "uploaded", "local_pack"} else "original",
                (local_vt_data_path or "").strip(),
                int(local_setting_json_enabled),
                int(api_failure_notify_enabled),
                normalize_renew_notice_days_text(renew_notice_days),
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
            SELECT s.id, s.name, s.renter_name, s.renter_email, s.delivery_email_sent_at, s.server_note, s.ip, s.ssh_password, s.reset_day, s.reset_hour, s.reset_minute,
                   s.auto_reset, s.is_renewed, s.is_rented, s.renew_until_date, s.next_rent_status, s.sort_order,
                   s.period_upload_bytes, s.period_download_bytes, s.last_traffic_sync_at, s.traffic_throttled,
                   s.ssh_status, s.ssh_checked_at, s.scp_image_catalog, s.scp_selected_image,
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
        queued_tasks = [dict(row) for row in conn.execute("SELECT * FROM task_queue ORDER BY id").fetchall()]
        notification_batches = [dict(row) for row in conn.execute("SELECT * FROM notification_batches ORDER BY id").fetchall()]
        notification_batch_items = [dict(row) for row in conn.execute("SELECT * FROM notification_batch_items ORDER BY id").fetchall()]
        global_cfg = conn.execute("SELECT * FROM global_config WHERE id = 1").fetchone()
        scp_accounts = [dict(row) for row in conn.execute("SELECT * FROM scp_accounts ORDER BY id").fetchall()]
        server_groups = [dict(row) for row in conn.execute("SELECT * FROM server_groups ORDER BY sort_order ASC, id ASC").fetchall()]

    payload = {
        "meta": {
            "exported_at": datetime.now(TIMEZONE).strftime("%Y-%m-%d %H:%M:%S"),
            "version": 2,
        },
        "global_config": dict(global_cfg) if global_cfg else {},
        "servers": servers,
        "job_logs": logs,
        "task_queue": queued_tasks,
        "notification_batches": notification_batches,
        "notification_batch_items": notification_batch_items,
        "scp_accounts": scp_accounts,
        "server_groups": server_groups,
    }
    return payload


def restore_backup_payload(payload):
    if not isinstance(payload, dict):
        raise ValueError("备份文件格式无效")

    servers = payload.get("servers")
    logs = payload.get("job_logs")
    queued_tasks = payload.get("task_queue", [])
    notification_batches = payload.get("notification_batches", [])
    notification_batch_items = payload.get("notification_batch_items", [])
    global_cfg = payload.get("global_config")
    scp_accounts = payload.get("scp_accounts", [])
    server_groups = payload.get("server_groups", [])

    if not isinstance(servers, list) or not isinstance(logs, list) or not isinstance(global_cfg, dict) or not isinstance(queued_tasks, list) or not isinstance(notification_batches, list) or not isinstance(notification_batch_items, list) or not isinstance(scp_accounts, list) or not isinstance(server_groups, list):
        raise ValueError("备份文件缺少必要字段")

    with closing(get_conn()) as conn:
        conn.execute("DELETE FROM job_logs")
        conn.execute("DELETE FROM servers")
        conn.execute("DELETE FROM global_config")
        conn.execute("DELETE FROM task_queue")
        conn.execute("DELETE FROM notification_batch_items")
        conn.execute("DELETE FROM notification_batches")
        conn.execute("DELETE FROM scp_accounts")
        conn.execute("DELETE FROM server_groups")

        conn.execute(
            """
            INSERT INTO global_config(id, reset_command, ssh_command_2, ssh_command_3, agent_install_command, panel_base_url, notify_email_enabled, smtp_host, smtp_port, smtp_user, smtp_password, smtp_from, notify_email_to, traffic_sample_interval_minutes, backup_email_enabled, backup_email_to, backup_interval_days, backup_last_sent_at, data_zip_url, data_zip_enabled, data_zip_source, local_vt_data_path, local_vt_data_zip_url, local_setting_json_path, local_setting_json_enabled, api_failure_notify_enabled, panel_password_hash, renew_notice_days, stock_page_title, public_stock_port, updated_at)
            VALUES(1,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
            """,
            (
                global_cfg.get("reset_command", ""),
                global_cfg.get("ssh_command_2", ""),
                global_cfg.get("ssh_command_3", ""),
                global_cfg.get("agent_install_command", ""),
                global_cfg.get("panel_base_url", ""),
                int(global_cfg.get("notify_email_enabled", 0)),
                global_cfg.get("smtp_host", ""),
                int(global_cfg.get("smtp_port", 587) or 587),
                global_cfg.get("smtp_user", ""),
                global_cfg.get("smtp_password", ""),
                global_cfg.get("smtp_from", ""),
                global_cfg.get("notify_email_to", ""),
                int(global_cfg.get("traffic_sample_interval_minutes", 60) or 60),
                int(global_cfg.get("backup_email_enabled", 0) or 0),
                global_cfg.get("backup_email_to", ""),
                int(global_cfg.get("backup_interval_days", 7) or 7),
                global_cfg.get("backup_last_sent_at"),
                global_cfg.get("data_zip_url", ""),
                int(global_cfg.get("data_zip_enabled", 0) or 0),
                global_cfg.get("data_zip_source", "original"),
                global_cfg.get("local_vt_data_path", ""),
                global_cfg.get("local_vt_data_zip_url", ""),
                global_cfg.get("local_setting_json_path", ""),
                int(global_cfg.get("local_setting_json_enabled", 0) or 0),
                int(global_cfg.get("api_failure_notify_enabled", 0) or 0),
                global_cfg.get("panel_password_hash") or generate_password_hash("admin"),
                normalize_renew_notice_days_text(global_cfg.get("renew_notice_days", "5,2")),
                (global_cfg.get("stock_page_title", "库存展示") or "库存展示").strip(),
                int(global_cfg.get("public_stock_port", PUBLIC_STOCK_PORT) or PUBLIC_STOCK_PORT),
                global_cfg.get("updated_at"),
            ),
        )

        for server in servers:
            conn.execute(
                """
                INSERT INTO servers(id, name, ip, ssh_port, ssh_user, ssh_password, reset_day, reset_hour, reset_minute, auto_reset, is_renewed, is_rented, renew_until_date, next_rent_status, last_month_tenant, rental_rollover_key, renter_name, renter_email, delivery_email_sent_at, renew_notice_sent_keys, server_note, server_group_id, sort_order, max_retries, retry_backoff_seconds, scp_account_id, scp_server_id, reinstall_mode, agent_token, period_key, period_upload_bytes, period_download_bytes, last_agent_rx_bytes, last_agent_tx_bytes, last_agent_report_at, last_reset_at, ssh_status, ssh_checked_at)
                VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
                """,
                (
                    server.get("id"),
                    server.get("name", ""),
                    server.get("ip", ""),
                    int(server.get("ssh_port", 22)),
                    server.get("ssh_user", "root") or "root",
                    server.get("ssh_password", ""),
                    int(server.get("reset_day", 1)),
                    int(server.get("reset_hour", 1)),
                    int(server.get("reset_minute", 0)),
                    int(server.get("auto_reset", 0)),
                    int(server.get("is_renewed", 0)),
                    int(server.get("is_rented", 0)),
                    server.get("renew_until_date", ""),
                    _normalize_next_rent_status(server.get("next_rent_status", "unknown")),
                    (server.get("last_month_tenant", "") or "").strip(),
                    (server.get("rental_rollover_key", "") or "").strip(),
                    (server.get("renter_name", "") or "").strip(),
                    (server.get("renter_email", "") or "").strip(),
                    server.get("delivery_email_sent_at"),
                    (server.get("renew_notice_sent_keys", "") or "").strip(),
                    (server.get("server_note", "") or "").strip(),
                    server.get("server_group_id"),
                    int(server.get("sort_order", 0)),
                    int(server.get("max_retries", 2)),
                    str(server.get("retry_backoff_seconds", "60,180")),
                    server.get("scp_account_id"),
                    server.get("scp_server_id", ""),
                    (server.get("reinstall_mode") or "ssh"),
                    server.get("agent_token", ""),
                    server.get("period_key", ""),
                    int(server.get("period_upload_bytes", 0)),
                    int(server.get("period_download_bytes", 0)),
                    int(server.get("last_agent_rx_bytes", 0)),
                    int(server.get("last_agent_tx_bytes", 0)),
                    server.get("last_agent_report_at"),
                    server.get("last_reset_at"),
                    (server.get("ssh_status", "unknown") or "unknown"),
                    server.get("ssh_checked_at"),
                ),
            )

        for account in scp_accounts:
            now_text = datetime.now(TIMEZONE).strftime("%Y-%m-%d %H:%M:%S")
            conn.execute(
                "INSERT INTO scp_accounts(id, name, username, password, refresh_token, api_endpoint, created_at, updated_at) VALUES(?,?,?,?,?,?,?,?)",
                (
                    account.get("id"),
                    account.get("name", ""),
                    account.get("username", ""),
                    account.get("password", ""),
                    account.get("refresh_token", ""),
                    account.get("api_endpoint") or "https://www.servercontrolpanel.de/scp-core/api/v1",
                    account.get("created_at") or now_text,
                    account.get("updated_at") or now_text,
                ),
            )


        for group in server_groups:
            now_text = datetime.now(TIMEZONE).strftime("%Y-%m-%d %H:%M:%S")
            conn.execute(
                "INSERT INTO server_groups(id, name, description, sort_order, created_at, updated_at) VALUES(?,?,?,?,?,?)",
                (
                    group.get("id"),
                    (group.get("name") or "").strip(),
                    (group.get("description") or "").strip(),
                    int(group.get("sort_order", 0) or 0),
                    group.get("created_at") or now_text,
                    group.get("updated_at") or now_text,
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

        for task in queued_tasks:
            conn.execute(
                """
                INSERT INTO task_queue(id, server_id, log_id, attempt, max_attempts, backoff_plan, status, next_run_at, last_error, trigger_type, batch_key, created_at, updated_at)
                VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?)
                """,
                (
                    task.get("id"),
                    int(task.get("server_id")),
                    int(task.get("log_id")),
                    int(task.get("attempt", 0)),
                    int(task.get("max_attempts", 2)),
                    task.get("backoff_plan", "60,180"),
                    task.get("status", "queued"),
                    task.get("next_run_at") or datetime.now(TIMEZONE).strftime("%Y-%m-%d %H:%M:%S"),
                    task.get("last_error", ""),
                    task.get("trigger_type", "manual"),
                    task.get("batch_key", ""),
                    task.get("created_at") or datetime.now(TIMEZONE).strftime("%Y-%m-%d %H:%M:%S"),
                    task.get("updated_at") or datetime.now(TIMEZONE).strftime("%Y-%m-%d %H:%M:%S"),
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



def month_day_safe(year, month, day):
    import calendar

    return min(day, calendar.monthrange(year, month)[1])


def build_server_reset_datetime(server_row, ref_dt):
    reset_day = int(server_row["reset_day"] if isinstance(server_row, sqlite3.Row) else (server_row or {}).get("reset_day") or 1)
    reset_hour = int(server_row["reset_hour"] if isinstance(server_row, sqlite3.Row) else (server_row or {}).get("reset_hour") or 1)
    reset_minute = int(server_row["reset_minute"] if isinstance(server_row, sqlite3.Row) else (server_row or {}).get("reset_minute") or 0)

    current_day = month_day_safe(ref_dt.year, ref_dt.month, reset_day)
    current_target = ref_dt.replace(day=current_day, hour=reset_hour, minute=reset_minute, second=0, microsecond=0)
    if current_target > ref_dt:
        return current_target

    if ref_dt.month == 12:
        next_year, next_month = ref_dt.year + 1, 1
    else:
        next_year, next_month = ref_dt.year, ref_dt.month + 1
    next_day = month_day_safe(next_year, next_month, reset_day)
    return ref_dt.replace(year=next_year, month=next_month, day=next_day, hour=reset_hour, minute=reset_minute, second=0, microsecond=0)


def build_effective_reset_datetime(server_row, ref_dt):
    candidate = build_server_reset_datetime(server_row, ref_dt)
    renew_until = _parse_date_text(server_row["renew_until_date"] if isinstance(server_row, sqlite3.Row) else (server_row or {}).get("renew_until_date"))
    if not renew_until:
        return candidate

    safety = 0
    while candidate.date() < renew_until and safety < 36:
        candidate = build_server_reset_datetime(server_row, candidate + timedelta(minutes=1))
        safety += 1
    return candidate


def mask_server_ip(ip_text):
    ip = (ip_text or "").strip()
    parts = ip.split(".")
    if len(parts) == 4 and all(part.isdigit() for part in parts):
        return f"{parts[0]}.{parts[1]}.*.*"
    if len(ip) > 4:
        return ip[:-4] + "****"
    return "****"


def format_reset_datetime_text(dt_obj):
    return dt_obj.strftime("%Y-%m-%d %H:%M")




def render_public_description_markdown(text):
    raw_text = (text or "").strip()
    if not raw_text:
        return Markup("无")

    safe_text = str(escape(raw_text))
    safe_text = re.sub(r"\*\*(.+?)\*\*", r"<strong>\1</strong>", safe_text)
    safe_text = re.sub(r"__(.+?)__", r"<strong>\1</strong>", safe_text)
    safe_text = re.sub(r"==(.+?)==", r"<span class=\"md-red\">\1</span>", safe_text)
    safe_text = safe_text.replace("\n", "<br>")
    return Markup(safe_text)

def format_public_stock_day_label(target_dt, now_dt, section="in_stock"):
    day_text = f"{target_dt.month}月{target_dt.day}号"
    if section == "in_stock":
        return f"今天-{day_text}"

    now_date = now_dt.date()
    target_date = target_dt.date()
    if target_date == now_date:
        return f"今天-{day_text}"
    if target_date == now_date + timedelta(days=1):
        return f"明天-{day_text}"
    return day_text


def _build_public_inventory_server_rows(now_dt=None):
    now_dt = now_dt or datetime.now(TIMEZONE)
    rows = list_servers()
    in_stock = []
    reservable = []
    for row in rows:
        item = dict(row)
        item["ip_masked"] = mask_server_ip(item.get("ip"))
        item["price_text"] = "60元"
        item["group_id"] = int(item.get("server_group_id") or 0)
        item["group_name"] = (item.get("group_name") or "未分组").strip() or "未分组"
        item["group_description"] = (item.get("group_description") or "").strip() or "无"
        next_reset = build_effective_reset_datetime(item, now_dt)
        item["next_reset_text"] = format_reset_datetime_text(next_reset)
        item["usable_until_text"] = f"现在租用，可用到 {item['next_reset_text']}（北京时间）"

        if int(item.get("is_rented") or 0) == 0:
            in_stock.append(item)
            continue

        if int(item.get("is_renewed") or 0) == 0 and not is_before_renew_until(item, now_dt):
            start_dt = next_reset
            end_dt = build_effective_reset_datetime(item, start_dt + timedelta(minutes=1))
            item["book_window_text"] = f"可预订档期：{format_reset_datetime_text(start_dt)} ~ {format_reset_datetime_text(end_dt)}（北京时间）"
            reservable.append(item)

    return in_stock, reservable


def _group_public_inventory_rows(rows, now_dt, section):
    grouped = {}
    for item in rows:
        gid = int(item.get("group_id") or 0)
        if gid not in grouped:
            grouped[gid] = {
                "group_id": gid,
                "group_name": item.get("group_name") or "未分组",
                "group_description": item.get("group_description") or "无",
                "group_description_html": render_public_description_markdown(item.get("group_description") or "无"),
                "count": 0,
                "time_buckets": {},
            }
        grouped[gid]["count"] += 1

        next_reset_dt = build_effective_reset_datetime(item, now_dt)
        bucket_key = next_reset_dt.strftime("%Y-%m-%d")
        bucket = grouped[gid]["time_buckets"].setdefault(
            bucket_key,
            {
                "sort_ts": next_reset_dt,
                "day_label": format_public_stock_day_label(next_reset_dt, now_dt, section),
                "count": 0,
                "start_label": f"{next_reset_dt.month}月{next_reset_dt.day}号",
                "end_label": "",
            },
        )
        bucket["count"] += 1

        if section == "reservable" and not bucket["end_label"]:
            end_dt = build_effective_reset_datetime(item, next_reset_dt + timedelta(minutes=1))
            bucket["end_label"] = f"{end_dt.month}月{end_dt.day}号"

    result = sorted(grouped.values(), key=lambda x: (0 if x["group_id"] == 0 else 1, x["group_name"]))
    for group in result:
        bucket_list = sorted(group.pop("time_buckets").values(), key=lambda x: x["sort_ts"])
        for bucket in bucket_list:
            bucket["sort_ts"] = bucket["sort_ts"].strftime("%Y-%m-%d %H:%M")
        group["timeline"] = bucket_list
    return result


def build_public_inventory_group_cards(now_dt=None):
    now_dt = now_dt or datetime.now(TIMEZONE)
    in_stock_rows, reservable_rows = _build_public_inventory_server_rows(now_dt)
    return _group_public_inventory_rows(in_stock_rows, now_dt, "in_stock"), _group_public_inventory_rows(reservable_rows, now_dt, "reservable")


def build_public_inventory_group_detail(section, group_id, now_dt=None):
    in_stock_rows, reservable_rows = _build_public_inventory_server_rows(now_dt)
    section_rows = in_stock_rows if section == "in_stock" else reservable_rows
    filtered = [r for r in section_rows if int(r.get("group_id") or 0) == int(group_id or 0)]
    if filtered:
        group_name = filtered[0].get("group_name") or "未分组"
        group_description = filtered[0].get("group_description") or "无"
    else:
        group_name = "未分组" if int(group_id or 0) == 0 else f"分组#{group_id}"
        group_description = "无"
    return {
        "group_id": int(group_id or 0),
        "group_name": group_name,
        "group_description": group_description,
    }, filtered


def get_public_stock_settings():
    cfg = get_global_config()
    title = (cfg["stock_page_title"] or "库存展示").strip() if cfg else "库存展示"
    port = int(cfg["public_stock_port"] or PUBLIC_STOCK_PORT) if cfg else PUBLIC_STOCK_PORT
    return title, port


def build_public_stock_base_url(request_obj=None):
    title, port = get_public_stock_settings()
    if request_obj:
        host = (request_obj.host or "").split(":", 1)[0]
        if host:
            scheme = request_obj.scheme or "http"
            return title, f"{scheme}://{host}:{port}"
    return title, f"http://127.0.0.1:{port}"


def get_current_renter_text(server_id):
    with closing(get_conn()) as conn:
        row = conn.execute("SELECT renter_name FROM servers WHERE id = ?", (server_id,)).fetchone()
    return (row["renter_name"] or "未填写") if row else "未填写"


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


def _request_public_base_url(request_obj):
    forwarded_host = (request_obj.headers.get("X-Forwarded-Host") or "").strip()
    forwarded_proto = (request_obj.headers.get("X-Forwarded-Proto") or "").strip()
    host = forwarded_host.split(",", 1)[0].strip() or (request_obj.host or "").strip()
    scheme = forwarded_proto.split(",", 1)[0].strip() or (request_obj.scheme or "http")
    if host:
        return f"{scheme}://{host}".rstrip("/")
    return ""


def resolve_panel_base_url(global_cfg, request_obj=None):
    configured = (global_cfg["panel_base_url"] or "").strip()
    if configured:
        return configured.rstrip("/")
    if PANEL_BASE_URL:
        return PANEL_BASE_URL.rstrip("/")
    if request_obj:
        from_request = _request_public_base_url(request_obj)
        if from_request:
            return from_request
    return f"http://127.0.0.1:{PANEL_PORT}"


def detect_panel_public_base_url(request_obj=None):
    if request_obj:
        from_request = _request_public_base_url(request_obj)
        if from_request:
            return from_request
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.connect(("8.8.8.8", 80))
        local_ip = sock.getsockname()[0]
        sock.close()
        return f"http://{local_ip}:{PANEL_PORT}"
    except Exception:
        return f"http://127.0.0.1:{PANEL_PORT}"


def has_running_logs():
    with closing(get_conn()) as conn:
        row = conn.execute("SELECT 1 FROM job_logs WHERE status='running' LIMIT 1").fetchone()
        return bool(row)

def generate_root_password(length=16):
    alphabet = string.ascii_letters + string.digits
    return "".join(secrets.choice(alphabet) for _ in range(length))


def inject_random_password_if_needed(command, server_row, generated_password):
    is_installnet = "InstallNET.sh" in command and "-pwd" in command
    is_bin_reinstall = "reinstall/main/reinstall.sh" in command and "--password" in command
    if not is_installnet and not is_bin_reinstall:
        return command, generated_password

    pwd = generated_password or generate_root_password()
    if is_installnet:
        command = re.sub(r"-pwd\s+'[^']*'", f"-pwd '{pwd}'", command)
        command = re.sub(r'-pwd\s+"[^"]*"', f'-pwd "{pwd}"', command)
        command = re.sub(r'-pwd\s+([^\s\'"]+)', f"-pwd '{pwd}'", command)
    if is_bin_reinstall:
        command = re.sub(r"--password\s+'[^']*'", f"--password '{pwd}'", command)
        command = re.sub(r'--password\s+"[^"]*"', f'--password "{pwd}"', command)
        command = re.sub(r'--password\s+([^\s\'"]+)', f"--password '{pwd}'", command)

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



BIN_REINSTALL_CHOICES = {
    "debian-9": ("debian", "9"),
    "debian-10": ("debian", "10"),
    "debian-11": ("debian", "11"),
    "debian-12": ("debian", "12"),
    "debian-13": ("debian", "13"),
    "ubuntu-16.04": ("ubuntu", "16.04"),
    "ubuntu-18.04": ("ubuntu", "18.04"),
    "ubuntu-20.04": ("ubuntu", "20.04"),
    "ubuntu-22.04": ("ubuntu", "22.04"),
    "ubuntu-24.04": ("ubuntu", "24.04"),
    "ubuntu-25.1": ("ubuntu", "25.1"),
}


def parse_bin_reinstall_choice(trigger_type):
    text = str(trigger_type or "").strip()
    if not text.startswith("binreinstall:"):
        return None
    choice = text.split(":", 1)[1].strip().lower()
    if choice in BIN_REINSTALL_CHOICES:
        return choice
    return None




def is_api_reinstall_trigger(trigger_type):
    return str(trigger_type or "").strip().lower() == "apireinstall"


def get_selected_scp_image(server_row):
    options = load_server_scp_images(server_row)
    if isinstance(server_row, sqlite3.Row):
        selected_key = server_row["scp_selected_image"]
    else:
        selected_key = (server_row or {}).get("scp_selected_image")
    selected = pick_scp_image_option_by_key(options, selected_key)
    if selected:
        return selected
    return options[0] if options else None

def build_bin_reinstall_command(choice, root_password):
    distro, version = BIN_REINSTALL_CHOICES[choice]
    script_url = "https://raw.githubusercontent.com/bin456789/reinstall/main/reinstall.sh"
    return (
        "bash -lc "
        + shlex.quote(
            f"if ! command -v curl >/dev/null 2>&1 && ! command -v wget >/dev/null 2>&1; then "
            f"export DEBIAN_FRONTEND=noninteractive; "
            f"if command -v apt-get >/dev/null 2>&1; then apt-get update -y >/dev/null 2>&1; apt-get install -y curl wget >/dev/null 2>&1; "
            f"elif command -v dnf >/dev/null 2>&1; then dnf install -y curl wget >/dev/null 2>&1; "
            f"elif command -v yum >/dev/null 2>&1; then yum install -y curl wget >/dev/null 2>&1; "
            f"elif command -v apk >/dev/null 2>&1; then apk add --no-cache curl wget >/dev/null 2>&1; "
            f"fi; "
            f"fi; "
            f"if command -v curl >/dev/null 2>&1; then "
                f"bash <(curl -fsSL {script_url}) {distro} {version} --password {shlex.quote(root_password)}; "
            f"elif command -v wget >/dev/null 2>&1; then "
                f"bash <(wget -qO- {script_url}) {distro} {version} --password {shlex.quote(root_password)}; "
            f"else echo '缺少 curl/wget 且自动安装失败，无法执行 bin456789 重装'; exit 127; "
            f"fi; sync; reboot"
        )
    )

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


def log_system_event(event_type, message, level="info", server_id=None, account_id=None, details=""):
    now_text = datetime.now(TIMEZONE).strftime("%Y-%m-%d %H:%M:%S")
    try:
        with closing(get_conn()) as conn:
            conn.execute(
                """
                INSERT INTO system_events(level, event_type, message, details, server_id, account_id, created_at)
                VALUES(?,?,?,?,?,?,?)
                """,
                (str(level or "info")[:16], str(event_type or "general")[:64], str(message or "")[:500], str(details or "")[:4000], server_id, account_id, now_text),
            )
            conn.commit()
    except sqlite3.OperationalError as exc:
        print(f"[system_events] write skipped due to DB lock: {exc}")


def list_system_events(limit=300):
    with closing(get_conn()) as conn:
        return conn.execute("SELECT * FROM system_events ORDER BY id DESC LIMIT ?", (int(limit),)).fetchall()


def record_email_history(category, recipient, subject, status, error_message="", body_text=""):
    now_text = datetime.now(TIMEZONE).strftime("%Y-%m-%d %H:%M:%S")
    with closing(get_conn()) as conn:
        conn.execute(
            """
            INSERT INTO email_history(category, recipient, subject, status, error_message, body_text, created_at)
            VALUES(?,?,?,?,?,?,?)
            """,
            (str(category or "general")[:64], str(recipient or "")[:255], str(subject or "")[:255], str(status or "unknown")[:16], str(error_message or "")[:1000], str(body_text or "")[:50000], now_text),
        )
        conn.commit()


def list_email_history(limit=200):
    with closing(get_conn()) as conn:
        return conn.execute("SELECT * FROM email_history ORDER BY id DESC LIMIT ?", (int(limit),)).fetchall()

    log_system_event("traffic_sampling_summary", f"本轮流量采样完成，成功{ok_count}台，失败{fail_count}台")

def update_scp_account_api_status(account_id, status, error_message=""):
    now_text = datetime.now(TIMEZONE).strftime("%Y-%m-%d %H:%M:%S")
    with closing(get_conn()) as conn:
        conn.execute(
            "UPDATE scp_accounts SET api_status=?, api_checked_at=?, api_last_error=?, updated_at=? WHERE id=?",
            ((status or "unknown")[:16], now_text, str(error_message or "")[:500], now_text, account_id),
        )
        conn.commit()

def update_scp_account_api_status(account_id, status, error_message=""):
    now_text = datetime.now(TIMEZONE).strftime("%Y-%m-%d %H:%M:%S")
    with closing(get_conn()) as conn:
        conn.execute(
            "UPDATE scp_accounts SET api_status=?, api_checked_at=?, api_last_error=?, updated_at=? WHERE id=?",
            ((status or "unknown")[:16], now_text, str(error_message or "")[:500], now_text, account_id),
        )
        conn.commit()

def notify_scp_api_failure_if_needed(account, error_message):
    cfg = get_global_config()
    if not cfg or not int(cfg["api_failure_notify_enabled"] or 0):
        return
    account_id = account["id"] if isinstance(account, sqlite3.Row) else account.get("id")
    now_text = datetime.now(TIMEZONE).strftime("%Y-%m-%d %H:%M:%S")
    with closing(get_conn()) as conn:
        row = conn.execute("SELECT api_last_notified_at FROM scp_accounts WHERE id=?", (account_id,)).fetchone()
        if row and row["api_last_notified_at"]:
            try:
                last_dt = datetime.strptime(row["api_last_notified_at"], "%Y-%m-%d %H:%M:%S")
                if datetime.now(TIMEZONE) - last_dt.replace(tzinfo=TIMEZONE) < timedelta(hours=6):
                    return
            except Exception:
                pass
        conn.execute("UPDATE scp_accounts SET api_last_notified_at=? WHERE id=?", (now_text, account_id))
        conn.commit()

    subject = f"[VPS面板] SCP账号API连接失败: {account['name']}"
    body = f"账号: {account['name']} ({account['username']})\n时间: {now_text}\n错误: {error_message}"
    send_email_message(subject, body, category="scp_api_failure")


def check_scp_account_connection(account):
    try:
        endpoint_base, token = scp_rest_login(account)
        scp_rest_request(account, "GET", "servers?limit=1", token=token, endpoint_base=endpoint_base)
        update_scp_account_api_status(account["id"], "ok", "")
        log_system_event("scp_api_check", f"SCP账号[{account['name']}] API连接正常", account_id=account["id"])
        return True, "连接正常"
    except Exception as exc:
        msg = str(exc)
        update_scp_account_api_status(account["id"], "failed", msg)
        log_system_event("scp_api_check", f"SCP账号[{account['name']}] API连接失败", level="error", account_id=account["id"], details=msg)
        notify_scp_api_failure_if_needed(account, msg)
        return False, msg




def _parse_scp_metric_timestamp(ts_text):
    if not ts_text:
        return None
    text = str(ts_text).strip()
    if not text:
        return None
    if text.endswith("Z"):
        text = text[:-1] + "+00:00"
    try:
        dt = datetime.fromisoformat(text)
    except Exception:
        return None
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=ZoneInfo("UTC"))
    return dt.astimezone(TIMEZONE)


def _normalize_network_metrics_points(payload):
    if not isinstance(payload, dict):
        return []
    points = []
    for ts_text, metric_map in payload.items():
        dt_local = _parse_scp_metric_timestamp(ts_text)
        if not dt_local or not isinstance(metric_map, dict):
            continue
        rx_bps = 0.0
        tx_bps = 0.0
        for key, value in metric_map.items():
            try:
                val = float(value or 0)
            except Exception:
                continue
            upper = str(key).upper()
            if upper.endswith(" RX"):
                rx_bps += val
            elif upper.endswith(" TX"):
                tx_bps += val
        points.append({"ts": dt_local, "rx_bps": max(rx_bps, 0.0), "tx_bps": max(tx_bps, 0.0)})
    points.sort(key=lambda item: item["ts"])
    return points


def _infer_metric_step_seconds(points, default_seconds=600):
    if len(points) < 2:
        return default_seconds
    diffs = []
    for idx in range(1, len(points)):
        diff = int((points[idx]["ts"] - points[idx - 1]["ts"]).total_seconds())
        if diff > 0:
            diffs.append(diff)
    if not diffs:
        return default_seconds
    try:
        median_val = int(statistics.median(diffs))
    except Exception:
        median_val = default_seconds
    return max(60, min(median_val, 3600))


def _integrate_points(points, start_dt, end_dt, step_seconds):
    rx = 0.0
    tx = 0.0
    for item in points:
        ts = item["ts"]
        if ts < start_dt or ts > end_dt:
            continue
        rx += item["rx_bps"] * step_seconds
        tx += item["tx_bps"] * step_seconds
    return int(max(rx, 0.0)), int(max(tx, 0.0))


def _hours_since_today_start(now_dt):
    today_start = now_dt.replace(hour=0, minute=0, second=0, microsecond=0)
    hours = int((now_dt - today_start).total_seconds() // 3600) + 1
    return max(1, min(hours, 24))


def _calc_daily_rows(points, now_dt):
    step_seconds = _infer_metric_step_seconds(points)
    daily_rows = []
    for offset in range(30, -1, -1):
        day_start = (now_dt - timedelta(days=offset)).replace(hour=0, minute=0, second=0, microsecond=0)
        day_end = min(day_start + timedelta(days=1), now_dt)
        if day_end <= day_start:
            continue
        rx, tx = _integrate_points(points, day_start, day_end, step_seconds)
        daily_rows.append({
            "date": day_start.strftime("%Y-%m-%d"),
            "rx": rx,
            "tx": tx,
            "total": rx + tx,
        })
    return daily_rows, step_seconds


def _fetch_server_network_metrics(server_row, now_dt=None, timeout_seconds=60):
    account_id = server_row["scp_account_id"] if isinstance(server_row, sqlite3.Row) else (server_row or {}).get("scp_account_id")
    scp_server_id = str(server_row["scp_server_id"] if isinstance(server_row, sqlite3.Row) else (server_row or {}).get("scp_server_id") or "").strip()
    if not account_id or not scp_server_id:
        raise RuntimeError("缺少SCP账号绑定或服务器ID")

    account = get_scp_account(account_id)
    if not account:
        raise RuntimeError("SCP账号不存在")

    endpoint_base, token = scp_rest_login(account, timeout_seconds=timeout_seconds)
    now_dt = now_dt or datetime.now(TIMEZONE)
    hours_map = {
        "today": _hours_since_today_start(now_dt),
        "6h": 6,
        "24h": 24,
        "7d": 24 * 7,
        "31d": 24 * 31,
    }

    windows = {}
    steps = {}
    samples = {}
    metrics_path = f"servers/{urlparse.quote(scp_server_id)}/metrics/network?hours={{hours}}"

    for key in ("today", "6h", "24h", "7d", "31d"):
        hours = int(hours_map[key])
        payload = scp_rest_request(
            account,
            "GET",
            metrics_path.format(hours=hours),
            token=token,
            endpoint_base=endpoint_base,
            timeout_seconds=timeout_seconds,
        )
        points = _normalize_network_metrics_points(payload)
        step_seconds = _infer_metric_step_seconds(points)
        start_dt = now_dt - timedelta(hours=hours)
        if key == "today":
            start_dt = now_dt.replace(hour=0, minute=0, second=0, microsecond=0)
        rx, tx = _integrate_points(points, start_dt, now_dt, step_seconds)
        windows[key] = {"rx": rx, "tx": tx, "total": rx + tx}
        steps[key] = step_seconds
        samples[key] = len(points)

    payload_31d = scp_rest_request(
        account,
        "GET",
        metrics_path.format(hours=24 * 31),
        token=token,
        endpoint_base=endpoint_base,
        timeout_seconds=timeout_seconds,
    )
    points_31d = _normalize_network_metrics_points(payload_31d)
    daily_rows, daily_step_seconds = _calc_daily_rows(points_31d, now_dt)
    steps["daily_31d"] = daily_step_seconds
    samples["daily_31d"] = len(points_31d)

    return windows, daily_rows, steps, samples

def refresh_server_traffic_via_scp(server_row):
    account_id = server_row["scp_account_id"] if isinstance(server_row, sqlite3.Row) else (server_row or {}).get("scp_account_id")
    scp_server_id = str(server_row["scp_server_id"] if isinstance(server_row, sqlite3.Row) else (server_row or {}).get("scp_server_id") or "").strip()
    if not account_id or not scp_server_id:
        raise RuntimeError("缺少SCP账号绑定或服务器ID")

    account = get_scp_account(account_id)
    if not account:
        raise RuntimeError("SCP账号不存在")

    endpoint_base, token = scp_rest_login(account)
    payload = scp_rest_request(
        account,
        "GET",
        f"servers/{urlparse.quote(scp_server_id)}?loadServerLiveInfo=true",
        token=token,
        endpoint_base=endpoint_base,
    )

    live = payload.get("serverLiveInfo") if isinstance(payload, dict) else {}
    interfaces = live.get("interfaces") if isinstance(live, dict) else []
    if not isinstance(interfaces, list):
        interfaces = []

    rx_monthly_mib = 0.0
    tx_monthly_mib = 0.0
    throttled = False
    for item in interfaces:
        if not isinstance(item, dict):
            continue
        try:
            rx_monthly_mib += float(item.get("rxMonthlyInMiB") or 0)
        except Exception:
            pass
        try:
            tx_monthly_mib += float(item.get("txMonthlyInMiB") or 0)
        except Exception:
            pass
        throttled = throttled or bool(item.get("trafficThrottled"))

    upload_bytes = int(max(tx_monthly_mib, 0) * 1024 * 1024)
    download_bytes = int(max(rx_monthly_mib, 0) * 1024 * 1024)
    now_text = datetime.now(TIMEZONE).strftime("%Y-%m-%d %H:%M:%S")

    with closing(get_conn()) as conn:
        conn.execute(
            """
            UPDATE servers
            SET period_key=?, period_upload_bytes=?, period_download_bytes=?,
                last_traffic_sync_at=?, traffic_throttled=?
            WHERE id=?
            """,
            (
                datetime.now(TIMEZONE).strftime("%Y-%m"),
                upload_bytes,
                download_bytes,
                now_text,
                1 if throttled else 0,
                server_row["id"],
            ),
        )
        conn.commit()


def refresh_all_traffic_data_via_scp(now_dt=None):
    cfg = get_global_config()
    interval = int(cfg["traffic_sample_interval_minutes"] or 60) if cfg else 60
    if interval <= 0:
        return

    now_dt = now_dt or datetime.now(TIMEZONE)
    minutes_since_midnight = now_dt.hour * 60 + now_dt.minute
    if minutes_since_midnight % interval != 0:
        return

    with closing(get_conn()) as conn:
        rows = conn.execute("SELECT * FROM servers ORDER BY sort_order ASC, id ASC").fetchall()

    ok_count = 0
    fail_count = 0
    for row in rows:
        try:
            refresh_server_traffic_via_scp(row)
            ok_count += 1
            log_system_event("traffic_sampling", f"流量采样成功: {row['name']} ({row['ip']})", server_id=row["id"])
        except Exception as exc:
            fail_count += 1
            log_system_event("traffic_sampling", f"流量采样失败: {row['name']} ({row['ip']})", level="error", server_id=row["id"], details=str(exc))
            continue

    log_system_event("traffic_sampling_summary", f"本轮流量采样完成，成功{ok_count}台，失败{fail_count}台")


def refresh_scp_account_statuses():
    accounts = list_scp_accounts()
    if not accounts:
        return
    ok_count = 0
    fail_count = 0
    for account in accounts:
        ok, msg = check_scp_account_connection(account)
        if ok:
            ok_count += 1
        else:
            fail_count += 1
    log_system_event("scp_api_check_summary", f"SCP账号连通性巡检完成：正常{ok_count}个，失败{fail_count}个")


def update_server_ssh_status(server_id, is_online):
    now_text = datetime.now(TIMEZONE).strftime("%Y-%m-%d %H:%M:%S")
    status = "online" if is_online else "offline"
    with closing(get_conn()) as conn:
        conn.execute("UPDATE servers SET ssh_status = ?, ssh_checked_at = ? WHERE id = ?", (status, now_text, server_id))
        conn.commit()


def check_server_ssh_connectivity(server_row, timeout=8):
    try:
        client = connect_ssh(server_row, timeout=timeout)
        client.close()
        update_server_ssh_status(server_row["id"], True)
        return True
    except Exception:
        update_server_ssh_status(server_row["id"], False)
        return False


def _parse_date_text(date_text):
    text = str(date_text or "").strip()
    if not text:
        return None
    try:
        return datetime.strptime(text, "%Y-%m-%d").date()
    except Exception:
        return None


def _one_month_before(date_obj):
    year, month = date_obj.year, date_obj.month - 1
    if month <= 0:
        month = 12
        year -= 1
    day = month_day_safe(year, month, date_obj.day)
    return datetime(year, month, day).date()


def is_before_renew_until(server_row, now_dt):
    renew_until = _parse_date_text(server_row["renew_until_date"] if isinstance(server_row, sqlite3.Row) else (server_row or {}).get("renew_until_date"))
    if not renew_until:
        return False
    return now_dt.date() < renew_until


def should_reset(server_row):
    now = datetime.now(TIMEZONE)
    if not server_row["auto_reset"]:
        return False
    if server_row["is_renewed"]:
        return False
    if is_before_renew_until(server_row, now):
        return False
    if server_row["reset_day"] != now.day:
        return False
    if now.hour != int(server_row["reset_hour"] or 1):
        return False
    if now.minute != int(server_row["reset_minute"] or 0):
        return False
    return True


def _integrate_points(points, start_dt, end_dt, step_seconds):
    rx = 0.0
    tx = 0.0
    for item in points:
        ts = item["ts"]
        if ts < start_dt or ts > end_dt:
            continue
        rx += item["rx_bps"] * step_seconds
        tx += item["tx_bps"] * step_seconds
    return int(max(rx, 0.0)), int(max(tx, 0.0))


def _hours_since_today_start(now_dt):
    today_start = now_dt.replace(hour=0, minute=0, second=0, microsecond=0)
    hours = int((now_dt - today_start).total_seconds() // 3600) + 1
    return max(1, min(hours, 24))


def _calc_daily_rows(points, now_dt):
    step_seconds = _infer_metric_step_seconds(points)
    daily_rows = []
    for offset in range(30, -1, -1):
        day_start = (now_dt - timedelta(days=offset)).replace(hour=0, minute=0, second=0, microsecond=0)
        day_end = min(day_start + timedelta(days=1), now_dt)
        if day_end <= day_start:
            continue
        rx, tx = _integrate_points(points, day_start, day_end, step_seconds)
        daily_rows.append({
            "date": day_start.strftime("%Y-%m-%d"),
            "rx": rx,
            "tx": tx,
            "total": rx + tx,
        })
    return daily_rows, step_seconds


def _fetch_server_network_metrics(server_row, now_dt=None, timeout_seconds=60):
    account_id = server_row["scp_account_id"] if isinstance(server_row, sqlite3.Row) else (server_row or {}).get("scp_account_id")
    scp_server_id = str(server_row["scp_server_id"] if isinstance(server_row, sqlite3.Row) else (server_row or {}).get("scp_server_id") or "").strip()
    if not account_id or not scp_server_id:
        raise RuntimeError("缺少SCP账号绑定或服务器ID")

    account = get_scp_account(account_id)
    if not account:
        raise RuntimeError("SCP账号不存在")

    endpoint_base, token = scp_rest_login(account, timeout_seconds=timeout_seconds)
    now_dt = now_dt or datetime.now(TIMEZONE)
    hours_map = {
        "today": _hours_since_today_start(now_dt),
        "6h": 6,
        "24h": 24,
        "7d": 24 * 7,
        "31d": 24 * 31,
    }

    windows = {}
    steps = {}
    samples = {}
    metrics_path = f"servers/{urlparse.quote(scp_server_id)}/metrics/network?hours={{hours}}"

    for key in ("today", "6h", "24h", "7d", "31d"):
        hours = int(hours_map[key])
        payload = scp_rest_request(
            account,
            "GET",
            metrics_path.format(hours=hours),
            token=token,
            endpoint_base=endpoint_base,
            timeout_seconds=timeout_seconds,
        )
        points = _normalize_network_metrics_points(payload)
        step_seconds = _infer_metric_step_seconds(points)
        start_dt = now_dt - timedelta(hours=hours)
        if key == "today":
            start_dt = now_dt.replace(hour=0, minute=0, second=0, microsecond=0)
        rx, tx = _integrate_points(points, start_dt, now_dt, step_seconds)
        windows[key] = {"rx": rx, "tx": tx, "total": rx + tx}
        steps[key] = step_seconds
        samples[key] = len(points)

    payload_31d = scp_rest_request(
        account,
        "GET",
        metrics_path.format(hours=24 * 31),
        token=token,
        endpoint_base=endpoint_base,
        timeout_seconds=timeout_seconds,
    )
    points_31d = _normalize_network_metrics_points(payload_31d)
    daily_rows, daily_step_seconds = _calc_daily_rows(points_31d, now_dt)
    steps["daily_31d"] = daily_step_seconds
    samples["daily_31d"] = len(points_31d)

    return windows, daily_rows, steps, samples

def refresh_server_traffic_via_scp(server_row):
    account_id = server_row["scp_account_id"] if isinstance(server_row, sqlite3.Row) else (server_row or {}).get("scp_account_id")
    scp_server_id = str(server_row["scp_server_id"] if isinstance(server_row, sqlite3.Row) else (server_row or {}).get("scp_server_id") or "").strip()
    if not account_id or not scp_server_id:
        raise RuntimeError("缺少SCP账号绑定或服务器ID")

    account = get_scp_account(account_id)
    if not account:
        raise RuntimeError("SCP账号不存在")

    endpoint_base, token = scp_rest_login(account)
    payload = scp_rest_request(
        account,
        "GET",
        f"servers/{urlparse.quote(scp_server_id)}?loadServerLiveInfo=true",
        token=token,
        endpoint_base=endpoint_base,
    )

    live = payload.get("serverLiveInfo") if isinstance(payload, dict) else {}
    interfaces = live.get("interfaces") if isinstance(live, dict) else []
    if not isinstance(interfaces, list):
        interfaces = []

    rx_monthly_mib = 0.0
    tx_monthly_mib = 0.0
    throttled = False
    for item in interfaces:
        if not isinstance(item, dict):
            continue
        try:
            rx_monthly_mib += float(item.get("rxMonthlyInMiB") or 0)
        except Exception:
            pass
        try:
            tx_monthly_mib += float(item.get("txMonthlyInMiB") or 0)
        except Exception:
            pass
        throttled = throttled or bool(item.get("trafficThrottled"))

    upload_bytes = int(max(tx_monthly_mib, 0) * 1024 * 1024)
    download_bytes = int(max(rx_monthly_mib, 0) * 1024 * 1024)
    now_text = datetime.now(TIMEZONE).strftime("%Y-%m-%d %H:%M:%S")

    with closing(get_conn()) as conn:
        conn.execute(
            """
            UPDATE servers
            SET period_key=?, period_upload_bytes=?, period_download_bytes=?,
                last_traffic_sync_at=?, traffic_throttled=?
            WHERE id=?
            """,
            (
                datetime.now(TIMEZONE).strftime("%Y-%m"),
                upload_bytes,
                download_bytes,
                now_text,
                1 if throttled else 0,
                server_row["id"],
            ),
        )
        conn.commit()


def refresh_all_traffic_data_via_scp(now_dt=None):
    cfg = get_global_config()
    interval = int(cfg["traffic_sample_interval_minutes"] or 60) if cfg else 60
    if interval <= 0:
        return

    now_dt = now_dt or datetime.now(TIMEZONE)
    minutes_since_midnight = now_dt.hour * 60 + now_dt.minute
    if minutes_since_midnight % interval != 0:
        return

    with closing(get_conn()) as conn:
        rows = conn.execute("SELECT * FROM servers ORDER BY sort_order ASC, id ASC").fetchall()

    ok_count = 0
    fail_count = 0
    for row in rows:
        try:
            refresh_server_traffic_via_scp(row)
            ok_count += 1
            log_system_event("traffic_sampling", f"流量采样成功: {row['name']} ({row['ip']})", server_id=row["id"])
        except Exception as exc:
            fail_count += 1
            log_system_event("traffic_sampling", f"流量采样失败: {row['name']} ({row['ip']})", level="error", server_id=row["id"], details=str(exc))
            continue

    log_system_event("traffic_sampling_summary", f"本轮流量采样完成，成功{ok_count}台，失败{fail_count}台")


def refresh_scp_account_statuses():
    accounts = list_scp_accounts()
    if not accounts:
        return
    ok_count = 0
    fail_count = 0
    for account in accounts:
        ok, msg = check_scp_account_connection(account)
        if ok:
            ok_count += 1
        else:
            fail_count += 1
    log_system_event("scp_api_check_summary", f"SCP账号连通性巡检完成：正常{ok_count}个，失败{fail_count}个")


def update_server_ssh_status(server_id, is_online):
    now_text = datetime.now(TIMEZONE).strftime("%Y-%m-%d %H:%M:%S")
    status = "online" if is_online else "offline"
    with closing(get_conn()) as conn:
        conn.execute("UPDATE servers SET ssh_status = ?, ssh_checked_at = ? WHERE id = ?", (status, now_text, server_id))
        conn.commit()


def check_server_ssh_connectivity(server_row, timeout=8):
    try:
        client = connect_ssh(server_row, timeout=timeout)
        client.close()
        update_server_ssh_status(server_row["id"], True)
        return True
    except Exception:
        update_server_ssh_status(server_row["id"], False)
        return False


def _parse_date_text(date_text):
    text = str(date_text or "").strip()
    if not text:
        return None
    try:
        return datetime.strptime(text, "%Y-%m-%d").date()
    except Exception:
        return None


def _one_month_before(date_obj):
    year, month = date_obj.year, date_obj.month - 1
    if month <= 0:
        month = 12
        year -= 1
    day = month_day_safe(year, month, date_obj.day)
    return datetime(year, month, day).date()


def is_before_renew_until(server_row, now_dt):
    renew_until = _parse_date_text(server_row["renew_until_date"] if isinstance(server_row, sqlite3.Row) else (server_row or {}).get("renew_until_date"))
    if not renew_until:
        return False
    return now_dt.date() < renew_until


def should_reset(server_row):
    now = datetime.now(TIMEZONE)
    if not server_row["auto_reset"]:
        return False
    if server_row["is_renewed"]:
        return False
    if is_before_renew_until(server_row, now):
        return False
    if server_row["reset_day"] != now.day:
        return False
    if now.hour != int(server_row["reset_hour"] or 1):
        return False
    if now.minute != int(server_row["reset_minute"] or 0):
        return False
    return True


def is_reinstall_command(command):
    text = str(command or "")
    is_installnet = "InstallNET.sh" in text and "-pwd" in text
    is_bin_reinstall = "reinstall/main/reinstall.sh" in text and "--password" in text
    return is_installnet or is_bin_reinstall


def wrap_installnet_with_downloader_bootstrap(command):
    text = str(command or "").strip()
    if not text or "InstallNET.sh" not in text:
        return text

    bootstrap = (
        'missing=""; '
        'command -v curl >/dev/null 2>&1 || missing="$missing curl"; '
        'command -v wget >/dev/null 2>&1 || missing="$missing wget"; '
        'if [ -n "$missing" ]; then '
        'export DEBIAN_FRONTEND=noninteractive; '
        'if command -v apt-get >/dev/null 2>&1; then apt-get update -y >/dev/null 2>&1; apt-get install -y $missing >/dev/null 2>&1; '
        'elif command -v dnf >/dev/null 2>&1; then dnf install -y $missing >/dev/null 2>&1; '
        'elif command -v yum >/dev/null 2>&1; then yum install -y $missing >/dev/null 2>&1; '
        'elif command -v apk >/dev/null 2>&1; then apk add --no-cache $missing >/dev/null 2>&1; '
        "else echo '缺少 curl/wget 且无法自动安装，继续执行原始重装命令'; "
        'fi; '
        'command -v curl >/dev/null 2>&1 || command -v wget >/dev/null 2>&1 || echo "自动安装后仍未检测到curl/wget，继续执行原始重装命令"; '
        'fi'
    )
    return f"{bootstrap}; {text}"



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


def wait_for_ssh_reconnect(server_row, output_lines, password_candidates, timeout_seconds=None, require_ready=False):
    output_lines.append("等待服务器重装并重启后重新连线...")
    timeout_value = timeout_seconds if timeout_seconds is not None else SSH_RECONNECT_TIMEOUT_SECONDS
    deadline = time.time() + max(1, int(timeout_value))
    while time.time() < deadline:
        for pwd in password_candidates:
            try:
                trial = dict(server_row)
                trial["ssh_password"] = pwd
                client = connect_ssh(trial, timeout=15)
                if require_ready and not is_post_reset_environment_ready(client):
                    output_lines.append("已连上SSH，但系统仍在DD切换阶段（基础Shell未就绪），继续等待...")
                    client.close()
                    continue
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
            "Created symlink",
            "vps-panel-agent.timer",
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
        f"{server_row['name']}（名称），{server_row['reset_day']}日 {int(server_row['reset_hour'] or 1):02d}:{int(server_row['reset_minute'] or 0):02d}（北京时间）重置，需要续租请提前下单",
        f"IP address: {ip_match.group(1) if ip_match else server_row['ip']}",
        f"Your new root passwort is {pass_match.group(1).strip() if pass_match else server_row['ssh_password']}",
    ]

    for block in (vertex, qb, fb):
        if block:
            lines.append(block.group(0).strip())

    return "\n".join(lines)


def get_smtp_config():
    cfg = get_global_config()
    if not int(cfg["notify_email_enabled"] or 0):
        return None

    smtp_host = (cfg["smtp_host"] or "").strip()
    smtp_user = (cfg["smtp_user"] or "").strip()
    smtp_password = cfg["smtp_password"] or ""
    smtp_from = (cfg["smtp_from"] or "").strip()
    smtp_to = (cfg["notify_email_to"] or "").strip()
    smtp_port = int(cfg["smtp_port"] or 587)
    if not (smtp_host and smtp_from and smtp_to):
        return None
    return {
        "host": smtp_host,
        "user": smtp_user,
        "password": smtp_password,
        "from": smtp_from,
        "to": smtp_to,
        "port": smtp_port,
    }


def _smtp_send_with_mode(host, port, user, password, msg, mode):
    timeout = 20
    mode = str(mode or "").strip().lower()
    if mode == "ssl":
        with smtplib.SMTP_SSL(host, port, timeout=timeout) as server:
            server.ehlo()
            if user:
                server.login(user, password)
            server.send_message(msg)
        return

    if mode != "starttls":
        raise ValueError(f"unsupported smtp mode: {mode}")

    with smtplib.SMTP(host, port, timeout=timeout) as server:
        server.ehlo()
        server.starttls()
        server.ehlo()
        if user:
            server.login(user, password)
        server.send_message(msg)


def _smtp_mode_candidates(port):
    try:
        p = int(port)
    except Exception:
        p = 0
    if p == 465:
        return ["ssl", "starttls"]
    if p == 587:
        return ["starttls", "ssl"]
    return ["starttls", "ssl"]


def _smtp_send_with_fallback(host, port, user, password, msg):
    errors = []
    for mode in _smtp_mode_candidates(port):
        try:
            _smtp_send_with_mode(host, port, user, password, msg, mode)
            return True, ""
        except Exception as exc:
            errors.append(f"{mode}: {exc}")
    return False, " | ".join(errors) if errors else "unknown smtp error"


def send_email_message(subject, body, category="general", return_error=False):
    smtp = get_smtp_config()
    if not smtp:
        record_email_history(category, "", subject, "skipped", "SMTP未配置", body)
        return (False, "SMTP未配置") if return_error else False

    msg = EmailMessage()
    msg["Subject"] = subject
    msg["From"] = smtp["from"]
    msg["To"] = smtp["to"]
    msg.set_content(body)

    ok, err_text = _smtp_send_with_fallback(
        smtp["host"], smtp["port"], smtp["user"], smtp["password"], msg
    )
    if ok:
        record_email_history(category, smtp["to"], subject, "success", "", body)
        return (True, "") if return_error else True
    record_email_history(category, smtp.get("to", ""), subject, "failed", err_text, body)
    return (False, err_text) if return_error else False


def send_email_to_recipient(subject, body, to_email, category="tenant_notice"):
    recipient = str(to_email or "").strip()
    if not recipient:
        record_email_history(category, "", subject, "skipped", "收件人为空", body)
        return False

    cfg = get_global_config()
    if not int(cfg["notify_email_enabled"] or 0):
        record_email_history(category, recipient, subject, "skipped", "邮件通知未启用", body)
        return False

    smtp_host = (cfg["smtp_host"] or "").strip()
    smtp_user = (cfg["smtp_user"] or "").strip()
    smtp_password = cfg["smtp_password"] or ""
    smtp_from = (cfg["smtp_from"] or "").strip()
    smtp_port = int(cfg["smtp_port"] or 587)
    if not (smtp_host and smtp_from):
        record_email_history(category, recipient, subject, "skipped", "SMTP未配置", body)
        return False

    msg = EmailMessage()
    msg["Subject"] = subject
    msg["From"] = smtp_from
    msg["To"] = recipient
    msg.set_content(body)

    ok, err_text = _smtp_send_with_fallback(smtp_host, smtp_port, smtp_user, smtp_password, msg)
    if ok:
        record_email_history(category, recipient, subject, "success", "", body)
        return True
    record_email_history(category, recipient, subject, "failed", err_text, body)
    return False


def send_email_with_attachment(subject, body, attachment_name, attachment_bytes, to_email=None, category="backup"):
    smtp = get_smtp_config()
    if not smtp:
        record_email_history(category, (to_email or ""), subject, "skipped", "SMTP未配置", body)
        return False

    msg = EmailMessage()
    msg["Subject"] = subject
    msg["From"] = smtp["from"]
    msg["To"] = (to_email or smtp["to"]).strip()
    msg.set_content(body)
    msg.add_attachment(attachment_bytes, maintype="application", subtype="json", filename=attachment_name)

    ok, err_text = _smtp_send_with_fallback(
        smtp["host"], smtp["port"], smtp["user"], smtp["password"], msg
    )
    if ok:
        record_email_history(category, msg["To"], subject, "success", "", body)
        return True
    record_email_history(category, msg["To"], subject, "failed", err_text, body)
    return False


def run_scheduled_backup_email(now_dt=None):
    cfg = get_global_config()
    if not cfg or not int(cfg["backup_email_enabled"] or 0):
        return

    to_email = (cfg["backup_email_to"] or cfg["notify_email_to"] or "").strip()
    if not to_email:
        return

    interval_days = max(1, int(cfg["backup_interval_days"] or 7))
    now_dt = now_dt or datetime.now(TIMEZONE)
    last_sent_raw = (cfg["backup_last_sent_at"] or "").strip()

    if last_sent_raw:
        try:
            last_sent = datetime.strptime(last_sent_raw, "%Y-%m-%d %H:%M:%S").replace(tzinfo=TIMEZONE)
            if now_dt < (last_sent + timedelta(days=interval_days)):
                return
        except Exception:
            pass

    payload = export_backup_payload()
    content = json.dumps(payload, ensure_ascii=False, indent=2).encode("utf-8")
    ts = now_dt.strftime("%Y%m%d-%H%M%S")
    ok = send_email_with_attachment(
        subject=f"[VPS面板] 定期备份文件 {ts}",
        body=(
            "这是系统自动发送的数据备份附件。\n"
            f"发送时间: {now_dt.strftime('%Y-%m-%d %H:%M:%S')}\n"
            f"备份周期: 每 {interval_days} 天一次\n"
        ),
        attachment_name=f"vps-panel-backup-{ts}.json",
        attachment_bytes=content,
        to_email=to_email,
    )

    if ok:
        with closing(get_conn()) as conn:
            conn.execute(
                "UPDATE global_config SET backup_last_sent_at=?, updated_at=? WHERE id=1",
                (now_dt.strftime("%Y-%m-%d %H:%M:%S"), now_dt.strftime("%Y-%m-%d %H:%M:%S")),
            )
            conn.commit()
def send_result_email(server_row, status, summary, output):
    title_state = "成功" if status == "success" else "失败"
    body = (
        f"服务器: {server_row['name']} ({server_row['ip']})\\n"
        f"状态: {title_state}\\n"
        f"时间: {datetime.now(TIMEZONE).strftime('%Y-%m-%d %H:%M:%S')}\\n\\n"
        f"摘要:\\n{summary}\\n\\n"
        f"完整输出:\\n{output[:30000]}"
    )
    return send_email_message(f"[VPS面板] {server_row['name']} 重置任务{title_state}", body)


def ensure_notification_batch(batch_key, scheduled_for):
    now_text = datetime.now(TIMEZONE).strftime("%Y-%m-%d %H:%M:%S")
    with closing(get_conn()) as conn:
        conn.execute(
            """
            INSERT OR IGNORE INTO notification_batches(batch_key, scheduled_for, notified, created_at, updated_at)
            VALUES(?,?,0,?,?)
            """,
            (batch_key, scheduled_for, now_text, now_text),
        )
        conn.commit()


def upsert_notification_batch_item(batch_key, server_row, status, note="", log_id=None):
    now_text = datetime.now(TIMEZONE).strftime("%Y-%m-%d %H:%M:%S")
    with closing(get_conn()) as conn:
        row = conn.execute(
            "SELECT id FROM notification_batch_items WHERE batch_key = ? AND server_id = ?",
            (batch_key, server_row["id"]),
        ).fetchone()
        if row:
            conn.execute(
                "UPDATE notification_batch_items SET status=?, note=?, log_id=?, updated_at=? WHERE id=?",
                (status, note, log_id, now_text, row["id"]),
            )
        else:
            conn.execute(
                """
                INSERT INTO notification_batch_items(batch_key, server_id, server_name, server_ip, status, note, log_id, created_at, updated_at)
                VALUES(?,?,?,?,?,?,?,?,?)
                """,
                (batch_key, server_row["id"], server_row["name"], server_row["ip"], status, note, log_id, now_text, now_text),
            )
        conn.commit()


def maybe_send_batch_email(batch_key):
    with closing(get_conn()) as conn:
        batch = conn.execute("SELECT * FROM notification_batches WHERE batch_key = ?", (batch_key,)).fetchone()
        if not batch or int(batch["notified"] or 0):
            return
        items = conn.execute(
            "SELECT * FROM notification_batch_items WHERE batch_key = ? ORDER BY server_id ASC",
            (batch_key,),
        ).fetchall()

    if not items:
        return

    statuses = [item["status"] for item in items]
    if any(st in ("pending", "queued", "running", "retrying") for st in statuses):
        return

    success_count = len([st for st in statuses if st == "success"])
    failed_count = len([st for st in statuses if st == "failed"])
    skipped_count = len([st for st in statuses if st == "skipped"])
    total_count = len(statuses)

    lines = [
        f"批次: {batch_key}",
        f"总计: {total_count}",
        f"成功: {success_count}",
        f"失败: {failed_count}",
        f"跳过: {skipped_count}",
        "",
        "明细:",
    ]
    for item in items:
        note = f"（{item['note']}）" if item["note"] else ""
        lines.append(f"- {item['server_name']} ({item['server_ip']}，目前租赁人: {get_current_renter_text(item['server_id'])}): {item['status']}{note}")

    sent = send_email_message(
        f"[VPS面板] {batch_key} 重置批次结果（成功{success_count}/失败{failed_count}/跳过{skipped_count}）",
        "\n".join(lines),
    )
    if sent:
        with closing(get_conn()) as conn:
            conn.execute(
                "UPDATE notification_batches SET notified = 1, updated_at = ? WHERE batch_key = ?",
                (datetime.now(TIMEZONE).strftime("%Y-%m-%d %H:%M:%S"), batch_key),
            )
            conn.commit()


class LiveLogBuffer(list):
    def __init__(self, log_id, flush_interval_seconds=10):
        super().__init__()
        self.log_id = log_id
        self.flush_interval_seconds = max(1, int(flush_interval_seconds or 10))
        self.last_flush_at = 0.0

    def append(self, item):
        super().append(item)
        now = time.time()
        if self.log_id and now - self.last_flush_at >= self.flush_interval_seconds:
            update_log(self.log_id, "running", "任务执行中", "\n\n".join(self))
            self.last_flush_at = now


def run_remote(server_row, running_log_id, notify_on_failure=True, notify_on_success=True, reset_command_override=None, force_reinstall=False, preset_password=None, force_api_reinstall=False, selected_api_image=None, skip_post_deploy=False):
    title = f"[{server_row['name']} - {server_row['ip']}]"
    output_lines = LiveLogBuffer(running_log_id, flush_interval_seconds=10)
    output_lines.append(f"开始执行重置任务 {title}")
    client = None

    try:
        mutable_server = dict(server_row)
        generated_password = None
        original_password = mutable_server["ssh_password"]
        global_cfg = get_global_config()
        reinstall_mode = (mutable_server.get("reinstall_mode") or "ssh").strip().lower()
        if reinstall_mode not in ("ssh", "scp_api"):
            output_lines.append(f"检测到未知重置模式[{reinstall_mode}]，已自动回退为 ssh")
            reinstall_mode = "ssh"
        if force_api_reinstall:
            reinstall_mode = "scp_api"

        reset_command = normalize_shell_command((global_cfg["reset_command"] or "").strip())
        ssh_command_2 = normalize_shell_command((global_cfg["ssh_command_2"] or "").strip())
        ssh_command_3 = normalize_shell_command((global_cfg["ssh_command_3"] or "").strip())
        agent_install_command = normalize_shell_command((global_cfg["agent_install_command"] or "").strip())
        output_lines.append(
            "任务配置: "
            f"mode={reinstall_mode}, "
            f"has_reset_command={bool(reset_command)}, "
            f"has_ssh2={bool(ssh_command_2)}, "
            f"has_ssh3={bool(ssh_command_3)}"
        )
        if reinstall_mode == "scp_api":
            output_lines.append(
                "SCP配置: "
                f"scp_account_id={mutable_server.get('scp_account_id')}, "
                f"scp_server_id={(mutable_server.get('scp_server_id') or '').strip() or '<empty>'}"
            )

        if reinstall_mode == "ssh" and not any([reset_command, ssh_command_2, ssh_command_3]):
            raise RuntimeError("未配置任何SSH任务命令（reset_command/ssh_command_2/ssh_command_3均为空）")
        if reset_command_override:
            reset_command = normalize_shell_command(reset_command_override)
            ssh_command_2 = ""
            ssh_command_3 = ""
            agent_install_command = ""
            output_lines.append("已使用 bin456789 一键重装命令执行本次重置")
        panel_base_url = resolve_panel_base_url(global_cfg)

        if reinstall_mode == "scp_api":
            output_lines.append("SCP API 模式：跳过重置前SSH连通性要求，先执行API重置")
        else:
            client = connect_ssh(mutable_server)
            output_lines.append("SSH 连接成功")

        reinstall_triggered = False
        if preset_password:
            generated_password = preset_password
            mutable_server["ssh_password"] = generated_password
            update_server_password(mutable_server["id"], generated_password)
            output_lines.append(f"已为本次重装生成随机root密码: {generated_password}")

        if reinstall_mode == "scp_api":
            reinstall_triggered = True
            output_lines.append("本服务器已启用 SCP API 重置模式，准备调用SCP重装 Debian11")
            if force_api_reinstall and selected_api_image:
                output_lines.append(f"一键API重置已指定镜像: {selected_api_image.get('name') or '-'}")
            scp_reinstall_debian11(mutable_server, output_lines, preferred_image=selected_api_image)
            output_lines.append("SCP重装命令已提交，等待后续重连")
            time.sleep(POST_REINSTALL_WAIT_SECONDS)
            client, connected_pwd = wait_for_ssh_reconnect(mutable_server, output_lines, [mutable_server["ssh_password"]], timeout_seconds=SSH_RECONNECT_TIMEOUT_SECONDS)
            if connected_pwd and connected_pwd != mutable_server["ssh_password"]:
                mutable_server["ssh_password"] = connected_pwd
                update_server_password(mutable_server["id"], connected_pwd)
                output_lines.append("检测到实际可登录密码与预设不同，已自动回写面板")

        elif reset_command:
            if not preset_password:
                reset_command, generated_password = inject_random_password_if_needed(
                reset_command,
                mutable_server,
                generated_password,
            )
            if generated_password:
                mutable_server["ssh_password"] = generated_password
                output_lines.append(f"检测到DD重装命令，已自动生成新root密码: {generated_password}")

            if force_reinstall or is_reinstall_command(reset_command):
                reinstall_triggered = True
                if "InstallNET.sh" in reset_command:
                    reset_command = wrap_installnet_with_downloader_bootstrap(reset_command)
                    output_lines.append("检测到InstallNET重装命令，已执行curl/wget缺失项自动安装兜底")
                wrapped = f"nohup bash -lc {shlex.quote(reset_command)} >/root/panel_reset.log 2>&1 &"
                output_lines.append(f"执行 重置任务(后台): {reset_command}")
                client.exec_command(wrapped)
                if force_reinstall:
                    reboot_delay = max(30, BIN_REINSTALL_REBOOT_DELAY_SECONDS)
                    reboot_cmd = f"nohup bash -lc 'sleep {reboot_delay}; sync; reboot' >/root/panel_reboot.log 2>&1 &"
                    client.exec_command(reboot_cmd)
                    output_lines.append(f"已为一键DD重置安排延迟重启（{reboot_delay}s后），避免打断DD前半段流程")
                output_lines.append("重置任务已后台启动，等待后续重连")
                client.close()
                client = None
                time.sleep(POST_REINSTALL_WAIT_SECONDS)
                if force_reinstall or ssh_command_2 or ssh_command_3:
                    connected_pwd = None
                    if generated_password:
                        output_lines.append("重连阶段先使用新密码校验DD结果，若长时间失败再回退旧密码判定是否重置失败")
                        try:
                            new_pwd_wait = min(SSH_RECONNECT_TIMEOUT_SECONDS, max(60, DD_NEW_PASSWORD_GRACE_SECONDS))
                            client, connected_pwd = wait_for_ssh_reconnect(
                                mutable_server,
                                output_lines,
                                [generated_password],
                                timeout_seconds=new_pwd_wait,
                            )
                        except Exception as reconnect_exc:
                            if original_password and original_password != generated_password:
                                output_lines.append("新密码在宽限期内未连通，开始尝试旧密码用于判定DD是否失败")
                                client, old_pwd_connected = wait_for_ssh_reconnect(
                                    mutable_server,
                                    output_lines,
                                    [original_password],
                                    timeout_seconds=180,
                                )
                                mutable_server["ssh_password"] = old_pwd_connected
                                update_server_password(mutable_server["id"], old_pwd_connected)
                                raise RuntimeError("DD重置疑似失败：旧密码仍可登录（old password still valid）") from reconnect_exc
                            raise
                    elif force_reinstall:
                        client, connected_pwd = wait_for_ssh_reconnect(mutable_server, output_lines, [], timeout_seconds=300)
                    else:
                        client, connected_pwd = wait_for_ssh_reconnect(mutable_server, output_lines, [original_password])

                    if connected_pwd and connected_pwd != mutable_server["ssh_password"]:
                        mutable_server["ssh_password"] = connected_pwd
                        update_server_password(mutable_server["id"], connected_pwd)
                        output_lines.append("检测到实际可登录密码与预设不同，已自动回写面板")
            else:
                execute_command_and_collect(client, "重置任务", reset_command, output_lines)

        if reinstall_triggered and not force_reinstall:
            if skip_post_deploy:
                output_lines.append("本次任务为一键API重置：仅执行系统重装，跳过SSH任务2/SSH任务3")
            elif agent_install_command:
                if client is None:
                    client = connect_ssh(mutable_server)
                    output_lines.append("执行自定义部署任务前重新建立SSH连接成功")
                prepared_agent_command = render_agent_install_command(agent_install_command, mutable_server)
                execute_command_and_collect(client, "自定义部署任务", prepared_agent_command, output_lines)

        if ssh_command_2 and not skip_post_deploy:
            if int(global_cfg["data_zip_enabled"] or 0):
                data_zip_source = (global_cfg["data_zip_source"] or "original").strip()
                selected_zip_url = ""
                if data_zip_source == "uploaded":
                    selected_zip_url = (global_cfg["data_zip_url"] or "").strip()
                elif data_zip_source == "local_pack":
                    selected_zip_url = (global_cfg["local_vt_data_zip_url"] or "").strip()
                if selected_zip_url:
                    ssh_command_2 = _inject_data_zip_url_into_ssh2(ssh_command_2, selected_zip_url)
                    output_lines.append(f"SSH任务2已按数据源[{data_zip_source}]注入VT数据压缩包链接")
            ssh_command_2, ssh2_password = inject_random_ssh2_password_if_needed(ssh_command_2)
            if ssh2_password:
                output_lines.append(f"SSH任务2检测到固定密码参数，已替换为随机12位密码: {ssh2_password}")
            if client is None:
                client = connect_ssh(mutable_server)
                output_lines.append("执行 SSH任务2 前重新建立SSH连接成功")
            execute_command_and_collect(client, "SSH任务2", ssh_command_2, output_lines)

        if ssh_command_3 and not skip_post_deploy:
            if client is None:
                client = connect_ssh(mutable_server)
                output_lines.append("执行 SSH任务3 前重新建立SSH连接成功")
            execute_command_and_collect(client, "SSH任务3", ssh_command_3, output_lines)

        output_lines.append("任务执行完成")
        all_output = "\n\n".join(output_lines)
        summary = extract_summary(mutable_server, all_output)
        update_log(running_log_id, "success", summary, all_output)
        update_last_reset(server_row["id"])
        try:
            if notify_on_success:
                send_result_email(mutable_server, "success", summary, all_output)
        except Exception as mail_exc:
            output_lines.append(f"邮件通知发送失败: {mail_exc}")
    except Exception as exc:
        output_lines.append(f"任务失败: {exc}")
        all_output = "\n\n".join(output_lines)
        summary = extract_summary(locals().get("mutable_server", dict(server_row)), all_output)
        update_log(running_log_id, "failed", summary, all_output)
        try:
            if notify_on_failure:
                send_result_email(locals().get("mutable_server", dict(server_row)), "failed", summary, all_output)
        except Exception:
            pass
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
    return bool(row and row["status"] in ("queued", "running", "retrying"))




def _inject_data_zip_url_into_ssh2(command_text, data_zip_url):
    command = (command_text or "").strip()
    if not command:
        return f'-d "{data_zip_url}"'

    pattern = r'-d\s+(?:"[^"]*"|\'[^\']*\'|\S+)'
    if re.search(pattern, command):
        return re.sub(pattern, f'-d "{data_zip_url}"', command, count=1)
    return f'{command} -d "{data_zip_url}"'


def save_uploaded_data_zip(file_storage, request_obj=None):
    if not file_storage or not file_storage.filename:
        raise ValueError("请先选择数据压缩包")

    original_name = secure_filename(file_storage.filename)
    if not original_name.lower().endswith('.zip'):
        raise ValueError("仅支持上传 .zip 压缩包")

    ts = datetime.now(TIMEZONE).strftime("%Y%m%d-%H%M%S")
    token = secrets.token_hex(6)
    saved_name = f"{ts}-{token}-{original_name}"
    save_path = os.path.join(UPLOAD_DATA_DIR, saved_name)
    file_storage.save(save_path)

    base_url = resolve_panel_base_url(get_global_config(), request_obj)
    direct_url = f"{base_url.rstrip('/')}" + url_for("uploaded_data_file", filename=saved_name)

    with closing(get_conn()) as conn:
        conn.execute(
            "UPDATE global_config SET data_zip_url=?, updated_at=? WHERE id=1",
            (direct_url, datetime.now(TIMEZONE).strftime("%Y-%m-%d %H:%M:%S")),
        )
        conn.commit()

    return direct_url


def _resolve_uploaded_local_setting_json_path(stored_value):
    value = (stored_value or "").strip()
    if not value:
        return ""

    if os.path.isabs(value) and os.path.isfile(value):
        return value

    candidate = os.path.join(UPLOAD_DATA_DIR, os.path.basename(value))
    if os.path.isfile(candidate):
        return candidate
    return ""


def save_uploaded_local_setting_json(file_storage):
    if not file_storage or not file_storage.filename:
        raise ValueError("请先选择 setting.json 文件")

    original_name = secure_filename(file_storage.filename)
    if original_name.lower() != "setting.json":
        raise ValueError("仅允许上传文件名为 setting.json 的 JSON 文件")

    ts = datetime.now(TIMEZONE).strftime("%Y%m%d-%H%M%S")
    token = secrets.token_hex(4)
    saved_name = f"local-setting-{ts}-{token}-setting.json"
    save_path = os.path.join(UPLOAD_DATA_DIR, saved_name)
    file_storage.save(save_path)

    try:
        with open(save_path, "r", encoding="utf-8") as f:
            json.load(f)
    except Exception as exc:
        try:
            os.remove(save_path)
        except OSError:
            pass
        raise ValueError(f"setting.json 不是合法JSON: {exc}")

    with closing(get_conn()) as conn:
        conn.execute(
            "UPDATE global_config SET local_setting_json_path=?, updated_at=? WHERE id=1",
            (saved_name, datetime.now(TIMEZONE).strftime("%Y-%m-%d %H:%M:%S")),
        )
        conn.commit()

    return saved_name


def package_local_vt_data_to_zip(source_dir, request_obj=None):
    source_dir = (source_dir or "").strip()
    if not source_dir:
        raise ValueError("请填写本机VT数据目录")
    if not os.path.isabs(source_dir):
        raise ValueError("VT数据目录必须使用绝对路径")
    if not os.path.isdir(source_dir):
        raise ValueError("VT数据目录不存在或不可访问")

    ts = datetime.now(TIMEZONE).strftime("%Y%m%d-%H%M%S")
    token = secrets.token_hex(4)
    saved_name = f"local-vt-{ts}-{token}.zip"
    archive_path = os.path.join(UPLOAD_DATA_DIR, saved_name)

    normalized_source = os.path.normpath(source_dir)
    source_parent = os.path.dirname(normalized_source)
    source_base_name = os.path.basename(normalized_source)

    global_cfg = get_global_config()
    replace_setting_json = int(global_cfg["local_setting_json_enabled"] or 0) == 1
    uploaded_setting_path = _resolve_uploaded_local_setting_json_path(global_cfg["local_setting_json_path"])
    if replace_setting_json and not uploaded_setting_path:
        raise ValueError("已启用替换 setting.json，但未上传可用的 setting.json 文件，请重新上传")

    setting_arcname = f"{source_base_name}/setting.json"
    with zipfile.ZipFile(archive_path, "w", compression=zipfile.ZIP_DEFLATED) as zipf:
        for root, dirs, files in os.walk(normalized_source, followlinks=True):
            rel_dir = os.path.relpath(root, source_parent)
            if rel_dir != ".":
                zipf.writestr(f"{rel_dir}/", "")
            for filename in files:
                file_path = os.path.join(root, filename)
                arcname = os.path.relpath(file_path, source_parent)
                if replace_setting_json and arcname == setting_arcname:
                    continue
                zipf.write(file_path, arcname)

        if not os.listdir(normalized_source):
            zipf.writestr(f"{source_base_name}/", "")

        if replace_setting_json:
            zipf.write(uploaded_setting_path, setting_arcname)

    base_url = resolve_panel_base_url(get_global_config(), request_obj)
    direct_url = f"{base_url.rstrip('/')}" + url_for("uploaded_data_file", filename=saved_name)
    now_text = datetime.now(TIMEZONE).strftime("%Y-%m-%d %H:%M:%S")

    with closing(get_conn()) as conn:
        conn.execute(
            "UPDATE global_config SET local_vt_data_path=?, local_vt_data_zip_url=?, updated_at=? WHERE id=1",
            (source_dir, direct_url, now_text),
        )
        conn.commit()

    return direct_url
def parse_backoff_plan(text):
    values = []
    for piece in str(text or "").split(","):
        piece = piece.strip()
        if piece.isdigit() and int(piece) >= 0:
            values.append(int(piece))
    if not values:
        values = [int(x.strip()) for x in DEFAULT_RETRY_BACKOFF_SECONDS.split(",") if x.strip().isdigit()]
    return values or [60, 180]


def normalize_backoff_plan_text(text):
    return ",".join(str(v) for v in parse_backoff_plan(text))


def parse_int_form_field(form, field_name, default=None, min_value=None, max_value=None):
    raw = form.get(field_name, default)
    try:
        value = int(raw)
    except (TypeError, ValueError):
        raise ValueError(f"{field_name} 必须是整数")

    if min_value is not None and value < min_value:
        raise ValueError(f"{field_name} 不能小于 {min_value}")
    if max_value is not None and value > max_value:
        raise ValueError(f"{field_name} 不能大于 {max_value}")
    return value


def is_retryable_failure(output_text):
    text = (output_text or "").lower()
    patterns = (
        "timed out",
        "timeout",
        "unable to connect to port",
        "connection reset",
        "connection refused",
        "network is unreachable",
        "no route to host",
        "temporarily unavailable",
        "sshexception",
        "error reading ssh protocol banner",
        "old password still valid",
        "旧密码仍可登录",
    )
    return any(pattern in text for pattern in patterns)


def enqueue_task(server_row, log_id, trigger_type="manual", batch_key=""):
    trigger_type = (trigger_type or "manual").strip()
    batch_key = (batch_key or "").strip()
    now_text = datetime.now(TIMEZONE).strftime("%Y-%m-%d %H:%M:%S")
    max_attempts = max(1, int(server_row["max_retries"] or DEFAULT_MAX_RETRIES))
    backoff_plan = (server_row["retry_backoff_seconds"] or DEFAULT_RETRY_BACKOFF_SECONDS).strip()
    with closing(get_conn()) as conn:
        cur = conn.execute(
            """
            INSERT INTO task_queue(server_id, log_id, attempt, max_attempts, backoff_plan, status, next_run_at, last_error, trigger_type, batch_key, created_at, updated_at)
            VALUES(?,?,?,?,?,'queued',?,?,?,?,?,?)
            """,
            (server_row["id"], log_id, 0, max_attempts, backoff_plan, now_text, "", trigger_type, batch_key, now_text, now_text),
        )
        conn.commit()
        task_id = cur.lastrowid
    TASK_QUEUE.put(task_id)


def requeue_pending_tasks_on_startup():
    now_text = datetime.now(TIMEZONE).strftime("%Y-%m-%d %H:%M:%S")
    with closing(get_conn()) as conn:
        conn.execute(
            "UPDATE task_queue SET status='queued', updated_at=? WHERE status IN ('queued','running','retrying')",
            (now_text,),
        )
        rows = conn.execute("SELECT id FROM task_queue WHERE status='queued' ORDER BY id ASC").fetchall()
        conn.commit()
    for row in rows:
        TASK_QUEUE.put(row["id"])


def task_worker_loop():
    while True:
        task_id = TASK_QUEUE.get()
        try:
            with closing(get_conn()) as conn:
                task = conn.execute("SELECT * FROM task_queue WHERE id = ?", (task_id,)).fetchone()
            if not task or task["status"] not in ("queued", "retrying"):
                continue

            next_run_at = datetime.strptime(task["next_run_at"], "%Y-%m-%d %H:%M:%S").replace(tzinfo=TIMEZONE)
            now_dt = datetime.now(TIMEZONE)
            if next_run_at > now_dt:
                TASK_QUEUE.put(task_id)
                time.sleep(min((next_run_at - now_dt).total_seconds(), 1))
                continue

            row = get_server(task["server_id"])
            if not row:
                update_log(task["log_id"], "failed", "任务失败：服务器不存在", "任务失败: 服务器不存在或已删除")
                with closing(get_conn()) as conn:
                    conn.execute(
                        "UPDATE task_queue SET status='failed', last_error=?, updated_at=? WHERE id=?",
                        ("server missing", datetime.now(TIMEZONE).strftime("%Y-%m-%d %H:%M:%S"), task_id),
                    )
                    conn.commit()
                continue

            with closing(get_conn()) as conn:
                conn.execute(
                    "UPDATE task_queue SET status='running', updated_at=? WHERE id=?",
                    (datetime.now(TIMEZONE).strftime("%Y-%m-%d %H:%M:%S"), task_id),
                )
                conn.commit()

            attempt_no = int(task["attempt"] or 0) + 1
            max_attempts = int(task["max_attempts"] or 1)
            update_log(
                task["log_id"],
                "running",
                f"任务执行中（第{attempt_no}/{max_attempts}次尝试）...",
                f"开始执行重置任务 [{row['name']} - {row['ip']}]\n\n状态: 执行中（第{attempt_no}/{max_attempts}次尝试）",
            )
            dd_choice = parse_bin_reinstall_choice(task["trigger_type"])
            api_reinstall = is_api_reinstall_trigger(task["trigger_type"])
            dd_password = None
            dd_command = None
            selected_api_image = None
            if dd_choice:
                dd_password = generate_root_password()
                dd_command = build_bin_reinstall_command(dd_choice, dd_password)
            if api_reinstall:
                selected_api_image = get_selected_scp_image(row)
            run_remote(
                row,
                task["log_id"],
                notify_on_failure=(attempt_no >= max_attempts and not task["batch_key"]),
                notify_on_success=(not task["batch_key"]),
                reset_command_override=dd_command,
                force_reinstall=bool(dd_choice),
                preset_password=dd_password,
                force_api_reinstall=api_reinstall,
                selected_api_image=selected_api_image,
                skip_post_deploy=api_reinstall,
            )

            with closing(get_conn()) as conn:
                latest = conn.execute("SELECT status, output FROM job_logs WHERE id = ?", (task["log_id"],)).fetchone()

            if latest and latest["status"] == "success":
                with closing(get_conn()) as conn:
                    conn.execute(
                        "UPDATE task_queue SET status='success', attempt=?, updated_at=? WHERE id=?",
                        (attempt_no, datetime.now(TIMEZONE).strftime("%Y-%m-%d %H:%M:%S"), task_id),
                    )
                    if str(task["trigger_type"] or "").strip().lower() == "scheduled":
                        conn.execute(
                            "UPDATE servers SET is_rented = 0, is_renewed = 0, renew_until_date = '', renter_name = '', renter_email = '', delivery_email_sent_at = NULL, renew_notice_sent_keys = '' WHERE id = ?",
                            (row["id"],),
                        )
                    conn.commit()
                if task["batch_key"]:
                    note = "任务执行完成"
                    if str(task["trigger_type"] or "").strip().lower() == "scheduled":
                        note = "任务执行完成；已自动切换为未出租、未续租"
                    upsert_notification_batch_item(task["batch_key"], row, "success", note=note, log_id=task["log_id"])
                    maybe_send_batch_email(task["batch_key"])
                continue

            output = latest["output"] if latest else ""
            retryable = is_retryable_failure(output)
            if retryable and attempt_no < max_attempts:
                backoff_values = parse_backoff_plan(task["backoff_plan"])
                wait_seconds = backoff_values[min(attempt_no - 1, len(backoff_values) - 1)]
                next_time = datetime.now(TIMEZONE) + timedelta(seconds=wait_seconds)
                with closing(get_conn()) as conn:
                    conn.execute(
                        "UPDATE task_queue SET status='retrying', attempt=?, next_run_at=?, last_error=?, updated_at=? WHERE id=?",
                        (
                            attempt_no,
                            next_time.strftime("%Y-%m-%d %H:%M:%S"),
                            "retryable failure",
                            datetime.now(TIMEZONE).strftime("%Y-%m-%d %H:%M:%S"),
                            task_id,
                        ),
                    )
                    conn.commit()
                update_log(
                    task["log_id"],
                    "retrying",
                    f"检测到可重试错误，已加入队列尾部，最早在 {wait_seconds}s 后重试（第{attempt_no + 1}/{max_attempts}次）",
                    (output or "") + f"\n\n系统提示: 重试任务已回到队列尾部，最早 {wait_seconds}s 后执行（全局串行，仅同时执行一台）",
                )
                TASK_QUEUE.put(task_id)
            else:
                fail_reason = "retry exhausted" if retryable else "non-retryable"
                with closing(get_conn()) as conn:
                    conn.execute(
                        "UPDATE task_queue SET status='failed', attempt=?, last_error=?, updated_at=? WHERE id=?",
                        (
                            attempt_no,
                            fail_reason,
                            datetime.now(TIMEZONE).strftime("%Y-%m-%d %H:%M:%S"),
                            task_id,
                        ),
                    )
                    conn.commit()
                if task["batch_key"]:
                    upsert_notification_batch_item(task["batch_key"], row, "failed", note=fail_reason, log_id=task["log_id"])
                    maybe_send_batch_email(task["batch_key"])
        finally:
            TASK_QUEUE.task_done()


def start_task_worker():
    requeue_pending_tasks_on_startup()
    threading.Thread(target=task_worker_loop, daemon=True).start()


def run_for_server(server_id, trigger_type="manual", batch_key=""):
    trigger_type = (trigger_type or "manual").strip()
    batch_key = (batch_key or "").strip()
    row = get_server(server_id)
    if not row:
        return False, "服务器不存在", None

    if has_pending_or_running(server_id):
        return False, "该服务器已有排队/执行中的任务，已跳过重复提交", None

    log_id = save_log(
        row["id"],
        "queued",
        "任务已进入队列，等待前序服务器执行完成...",
        f"开始执行重置任务 [{row['name']} - {row['ip']}]\n\n状态: 排队中（将按顺序依次执行）",
    )
    if batch_key:
        upsert_notification_batch_item(batch_key, row, "queued", note="已加入执行队列", log_id=log_id)
    enqueue_task(row, log_id, trigger_type=trigger_type, batch_key=batch_key)
    return True, "任务已加入队列，将按顺序依次执行", log_id


def compose_renew_notice_message(row, reset_dt):
    subject = f"[VPS续费提醒] {row['name']} 将于 {reset_dt.strftime('%m-%d %H:%M')} 重置"
    body = (
        f"客户您好，您于闲鱼或论坛租赁的 {row['name']} 服务器，即将于 {reset_dt.strftime('%Y-%m-%d %H:%M')}（北京时间）重置，"
        "届时服务器将清空，请及时备份相关数据，如需续租，请提前在闲鱼下单，否则可能会预定给其他用户。感谢您的配合。"
    )
    return subject, body


def compose_missing_renter_email_notice(row, reset_dt, days_left):
    renter_name = (row["renter_name"] or "").strip() or "未填写"
    reset_clock = f"每月{int(row['reset_day'] or 1)}日 {int(row['reset_hour'] or 1):02d}:{int(row['reset_minute'] or 0):02d}"
    subject = f"[VPS面板] 续费提醒未发送（缺少租赁人邮箱）- {row['name']}"
    body = (
        "以下服务器本应发送自动续费提醒，但因未填写租赁人邮箱而跳过。请尽快联系客户确认是否续租。\n\n"
        f"服务器名称：{row['name']}\n"
        f"刷新日：{reset_clock}\n"
        f"本次预计重置时间：{reset_dt.strftime('%Y-%m-%d %H:%M')}（北京时间）\n"
        f"触发提醒档位：重置前{days_left}天\n"
        f"租赁人：{renter_name}\n"
        "建议操作：尽快询问客户是否续租，并补充租赁人邮箱或将状态调整为不续租。"
    )
    return subject, body


def run_scheduled_renew_notice_email(now_dt=None):
    now_dt = now_dt or datetime.now(TIMEZONE)
    cfg = get_global_config()
    notice_days = parse_renew_notice_days(cfg["renew_notice_days"] if cfg else "")
    if not notice_days:
        return

    rows = list_servers()
    for row in rows:
        if not int(row["auto_reset"] or 0):
            continue
        if int(row["is_renewed"] or 0) == 1:
            continue

        reset_dt = build_effective_reset_datetime(row, now_dt)
        if now_dt.hour != int(row["reset_hour"] or 1) or now_dt.minute != int(row["reset_minute"] or 0):
            continue

        days_left = (reset_dt.date() - now_dt.date()).days
        if days_left not in notice_days:
            continue

        recipient = (row["renter_email"] or "").strip()
        if _normalize_next_rent_status(row["next_rent_status"]) == "non_renew":
            log_system_event(
                "renew_notice",
                f"服务器[{row['name']}] 已标记不续租，跳过重置前{days_left}天续费提醒",
                server_id=row["id"],
                details=recipient,
            )
            continue

        sent_keys = _parse_notice_key_set(row["renew_notice_sent_keys"])
        notice_key = _compose_notice_key(reset_dt, days_left)
        missing_recipient_key = f"{notice_key}#missing_recipient"

        if not recipient:
            if missing_recipient_key in sent_keys:
                continue
            subject, body = compose_missing_renter_email_notice(row, reset_dt, days_left)
            ok = send_email_message(subject, body, category="renew_notice_missing_recipient")
            if not ok:
                log_system_event(
                    "renew_notice",
                    f"服务器[{row['name']}] 缺少租赁人邮箱，给管理员的提醒邮件发送失败",
                    level="error",
                    server_id=row["id"],
                )
                continue

            sent_keys.add(missing_recipient_key)
            sent_text = "|".join(sorted(sent_keys))
            with closing(get_conn()) as conn:
                conn.execute("UPDATE servers SET renew_notice_sent_keys = ? WHERE id = ?", (sent_text, row["id"]))
                conn.commit()
            log_system_event(
                "renew_notice",
                f"服务器[{row['name']}] 缺少租赁人邮箱，已通知管理员跟进续租",
                level="warning",
                server_id=row["id"],
            )
            continue

        if notice_key in sent_keys:
            continue

        subject, body = compose_renew_notice_message(row, reset_dt)
        ok = send_email_to_recipient(subject, body, recipient, category="renew_notice")
        if not ok:
            log_system_event("renew_notice", f"服务器[{row['name']}] 续费提醒邮件发送失败", level="error", server_id=row["id"], details=recipient)
            continue

        sent_keys.add(notice_key)
        sent_text = "|".join(sorted(sent_keys))
        with closing(get_conn()) as conn:
            conn.execute("UPDATE servers SET renew_notice_sent_keys = ? WHERE id = ?", (sent_text, row["id"]))
            conn.commit()
        log_system_event("renew_notice", f"服务器[{row['name']}] 已发送重置前{days_left}天续费提醒邮件", server_id=row["id"], details=recipient)


def check_scheduled_jobs():
    now = datetime.now(TIMEZONE)
    run_scheduled_backup_email(now)
    run_scheduled_renew_notice_email(now)
    batch_key = now.strftime("%Y-%m-%d %H:%M")
    scheduled_for = now.strftime("%Y-%m-%d %H:%M:%S")

    with closing(get_conn()) as conn:
        rows = conn.execute("SELECT * FROM servers ORDER BY sort_order ASC, id ASC").fetchall()

    # 长期续费：在到期日前一个月的同一天，自动取消“续租中”状态。
    long_renew_events = []
    with closing(get_conn()) as conn:
        for row in rows:
            renew_until = _parse_date_text(row["renew_until_date"])
            if not renew_until:
                continue
            one_month_before = _one_month_before(renew_until)
            if now.date() >= one_month_before and now.date() < renew_until and int(row["is_renewed"] or 0) == 1:
                conn.execute("UPDATE servers SET is_renewed = 0 WHERE id = ?", (row["id"],))
                long_renew_events.append((row["id"], row["name"]))
        conn.commit()
        rows = conn.execute("SELECT * FROM servers ORDER BY sort_order ASC, id ASC").fetchall()

    for sid, sname in long_renew_events:
        log_system_event("long_renew", f"服务器[{sname}] 已到续费日前一月，自动切换为未续租", server_id=sid)

    due_rows = [row for row in rows if row["auto_reset"] and row["reset_day"] == now.day and int(row["reset_hour"] or 1) == now.hour and int(row["reset_minute"] or 0) == now.minute]
    if not due_rows:
        return

    ensure_notification_batch(batch_key, scheduled_for)

    for row in due_rows:
        if is_before_renew_until(row, now):
            upsert_notification_batch_item(batch_key, row, "skipped", note=f"长期续费保护中（续费至{row['renew_until_date']}），已跳过定时重置")
            log_system_event("scheduled_reset", f"服务器[{row['name']}] 因长期续费保护跳过定时重置", server_id=row["id"], details=row["renew_until_date"])
            continue

        if row["is_renewed"]:
            with closing(get_conn()) as conn:
                conn.execute("UPDATE servers SET is_renewed = 0 WHERE id = ?", (row["id"],))
                conn.commit()
            upsert_notification_batch_item(batch_key, row, "skipped", note="续租中，已跳过定时重置；已自动切换为未续租")
            log_system_event("scheduled_reset", f"服务器[{row['name']}] 因续租状态跳过定时重置", server_id=row["id"])
            continue

        if not should_reset(row):
            upsert_notification_batch_item(batch_key, row, "skipped", note="未开启定时自动执行或不在预定时间")
            continue

        ok, msg, log_id = run_for_server(row["id"], trigger_type="scheduled", batch_key=batch_key)
        log_system_event("scheduled_reset", f"服务器[{row['name']}] 已触发定时重置任务", server_id=row["id"], details=msg)
        if not ok:
            upsert_notification_batch_item(batch_key, row, "skipped", note=msg, log_id=log_id)

    maybe_send_batch_email(batch_key)


@public_app.route("/")
def public_stock_page_root():
    return public_stock_page()


@public_app.route("/inventory")
def public_stock_page():
    title, _ = get_public_stock_settings()
    in_stock_groups, reservable_groups = build_public_inventory_group_cards()
    return render_template(
        "public_inventory.html",
        title=title,
        in_stock_groups=in_stock_groups,
        reservable_groups=reservable_groups,
        generated_at=datetime.now(TIMEZONE).strftime("%Y-%m-%d %H:%M:%S"),
    )


@public_app.route("/inventory/group/<section>/<int:group_id>")
def public_stock_group_page(section, group_id):
    return redirect(url_for("public_stock_page"))


def login_required(func):
    @wraps(func)
    def wrapper(*args, **kwargs):
        if not session.get("logged_in"):
            return redirect(url_for("login_page"))
        return func(*args, **kwargs)

    return wrapper


@app.before_request
def require_login():
    public_endpoints = {"login_page", "login_submit", "static", "uploaded_data_file"}
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
        item["traffic_throttled"] = bool(item.get("traffic_throttled"))
        image_options = load_server_scp_images(item)
        for opt in image_options:
            distro = str(opt.get("distribution") or "").strip()
            version = str(opt.get("version") or "").strip()
            name = str(opt.get("name") or "未命名镜像").strip()
            tags = " ".join(x for x in (distro, version) if x).strip()
            opt["key"] = make_scp_image_option_key(opt)
            opt["label"] = f"{name} ({tags})" if tags else name
        item["api_image_options"] = image_options
        item["scp_selected_image"] = (item.get("scp_selected_image") or "").strip()
        normalized_rows.append(item)

    rented_rows = [r for r in normalized_rows if r["is_rented"]]
    unrented_rows = [r for r in normalized_rows if not r["is_rented"]]

    total = len(normalized_rows)
    rented_count = len(rented_rows)
    unrented_count = len(unrented_rows)
    success = len([r for r in normalized_rows if r["status"] == "success"])
    failed = len([r for r in normalized_rows if r["status"] == "failed"])
    never = len([r for r in normalized_rows if not r["latest_run_at"]])
    return render_template(
        "details.html",
        rented_rows=rented_rows,
        unrented_rows=unrented_rows,
        total=total,
        rented_count=rented_count,
        unrented_count=unrented_count,
        success=success,
        failed=failed,
        never=never,
        latest_api_image_refresh_job=get_latest_api_image_refresh_job(),
    )




@app.route("/traffic")
@login_required
def traffic_page():
    rows = list_servers()
    cache_map = load_traffic_metrics_cache_map()
    report_rows = []

    for row in rows:
        item = dict(row)
        item["metrics_error"] = ""
        item["windows"] = {}
        item["daily_rows"] = []
        item["sample_steps"] = {}
        item["sample_counts"] = {}
        cached = cache_map.get(item["id"])
        if cached:
            item["generated_at"] = cached.get("generated_at") or ""
            item["windows"] = cached.get("windows") or {}
            item["daily_rows"] = cached.get("daily_rows") or []
            item["sample_steps"] = cached.get("steps") or {}
            item["sample_counts"] = cached.get("samples") or {}
        else:
            item["generated_at"] = ""
            item["metrics_error"] = "暂无缓存数据，请点击上方“手动更新数据”"

        windows = item["windows"]
        if windows:
            item["today_total_text"] = format_bytes((windows.get("today") or {}).get("total") or 0)
            item["h6_total_text"] = format_bytes((windows.get("6h") or {}).get("total") or 0)
            item["h24_total_text"] = format_bytes((windows.get("24h") or {}).get("total") or 0)
            item["d7_total_text"] = format_bytes((windows.get("7d") or {}).get("total") or 0)
            item["d31_total_text"] = format_bytes((windows.get("31d") or {}).get("total") or 0)
            for key in ("today", "6h", "24h", "7d", "31d"):
                block = windows.get(key) or {}
                item[f"{key}_rx_text"] = format_bytes(block.get("rx") or 0)
                item[f"{key}_tx_text"] = format_bytes(block.get("tx") or 0)
        for daily in item["daily_rows"]:
            daily["rx_text"] = format_bytes(daily.get("rx") or 0)
            daily["tx_text"] = format_bytes(daily.get("tx") or 0)
            daily["total_text"] = format_bytes(daily.get("total") or 0)
        report_rows.append(item)

    with TRAFFIC_REFRESH_LOCK:
        refresh_state = dict(TRAFFIC_REFRESH_STATE)

    return render_template(
        "traffic.html",
        rows=report_rows,
        refresh_state=refresh_state,
    )


def refresh_traffic_metrics_cache_job():
    now_dt = datetime.now(TIMEZONE)
    ok_count = 0
    fail_count = 0
    rows = list_servers()

    max_workers = min(4, max(1, len(rows)))
    with FuturesThreadPoolExecutor(max_workers=max_workers) as pool:
        future_map = {
            pool.submit(_fetch_server_network_metrics, row, now_dt, 20): row
            for row in rows
        }
        for future in as_completed(future_map):
            row = future_map[future]
            try:
                windows, daily_rows, steps, samples = future.result()
                save_traffic_metrics_cache(row["id"], windows, daily_rows, steps, samples)
                ok_count += 1
            except Exception as exc:
                fail_count += 1
                log_system_event("traffic_cache_refresh", f"流量缓存刷新失败: {row['name']} ({row['ip']})", level="error", server_id=row["id"], details=str(exc))

    with TRAFFIC_REFRESH_LOCK:
        TRAFFIC_REFRESH_STATE["running"] = False
        TRAFFIC_REFRESH_STATE["finished_at"] = datetime.now(TIMEZONE).strftime("%Y-%m-%d %H:%M:%S")
        TRAFFIC_REFRESH_STATE["ok_count"] = ok_count
        TRAFFIC_REFRESH_STATE["fail_count"] = fail_count
        TRAFFIC_REFRESH_STATE["message"] = f"流量缓存更新完成：成功{ok_count}台，失败{fail_count}台"

    log_system_event("traffic_cache_refresh", f"流量缓存更新完成：成功{ok_count}台，失败{fail_count}台")


@app.post("/traffic/refresh")
@login_required
def refresh_traffic_page_data():
    with TRAFFIC_REFRESH_LOCK:
        if TRAFFIC_REFRESH_STATE["running"]:
            flash("流量数据刷新任务已在执行中，请稍后再看结果", "info")
            return redirect(url_for("traffic_page"))
        TRAFFIC_REFRESH_STATE["running"] = True
        TRAFFIC_REFRESH_STATE["started_at"] = datetime.now(TIMEZONE).strftime("%Y-%m-%d %H:%M:%S")
        TRAFFIC_REFRESH_STATE["finished_at"] = ""
        TRAFFIC_REFRESH_STATE["ok_count"] = 0
        TRAFFIC_REFRESH_STATE["fail_count"] = 0
        TRAFFIC_REFRESH_STATE["message"] = "流量缓存更新任务已启动"

    thread = threading.Thread(target=refresh_traffic_metrics_cache_job, daemon=True)
    thread.start()
    flash("已启动流量缓存更新，请稍后刷新本页查看结果", "success")
    return redirect(url_for("traffic_page"))


@app.route("/settings")
@login_required
def settings_page():
    global_cfg = get_global_config()
    panel_base_url_default = detect_panel_public_base_url(request)
    return render_template(
        "settings.html",
        servers=list_servers(),
        logs_grouped=list_logs_grouped_by_server(),
        global_cfg=global_cfg,
        panel_base_url_default=panel_base_url_default,
        has_running_logs=has_running_logs(),
        scp_accounts=list_scp_accounts(),
        server_groups=list_server_groups(),
    )


@app.route("/rentals")
@login_required
def rentals_page():
    apply_monthly_rental_rollover_if_needed()
    global_cfg = get_global_config()
    return render_template("rentals.html", rows=list_rental_management_rows(), global_cfg=global_cfg)




@app.post("/rentals/renew-notice-days")
@login_required
def update_renew_notice_days():
    days_text = normalize_renew_notice_days_text(request.form.get("renew_notice_days"))
    with closing(get_conn()) as conn:
        conn.execute(
            "UPDATE global_config SET renew_notice_days = ?, updated_at = ? WHERE id = 1",
            (days_text, datetime.now(TIMEZONE).strftime("%Y-%m-%d %H:%M:%S")),
        )
        conn.commit()
    flash(f"续费提醒天数已更新：{days_text}", "success")
    return redirect(url_for("rentals_page"))

@app.post("/rentals/<int:server_id>/send-renew-email")
@login_required
def send_manual_renew_notice_email(server_id):
    row = get_server(server_id)
    if not row:
        flash("服务器不存在", "error")
        return redirect(url_for("rentals_page"))

    recipient = (row["renter_email"] or "").strip()
    if not recipient:
        flash(f"[{row['name']}] 未填写租赁人邮箱", "error")
        return redirect(url_for("rentals_page"))

    if not int(row["auto_reset"] or 0):
        flash(f"[{row['name']}] 未开启自动重置，未发送续费提醒", "error")
        return redirect(url_for("rentals_page"))

    now_dt = datetime.now(TIMEZONE)
    reset_dt = build_effective_reset_datetime(row, now_dt)
    subject, body = compose_renew_notice_message(row, reset_dt)
    ok = send_email_to_recipient(subject, body, recipient, category="renew_notice_manual")
    if not ok:
        flash(f"[{row['name']}] 续费邮件发送失败", "error")
        return redirect(url_for("rentals_page"))

    log_system_event("renew_notice", f"服务器[{row['name']}] 已手动发送续费提醒邮件", server_id=row["id"], details=recipient)
    flash(f"[{row['name']}] 已手动发送续费邮件（按预计重置时间 {reset_dt.strftime('%Y-%m-%d %H:%M')}）", "success")
    return redirect(url_for("rentals_page"))


@app.post("/rentals/<int:server_id>/next-status")
@login_required
def update_rental_next_status(server_id):
    status = _normalize_next_rent_status(request.form.get("next_rent_status"))
    with closing(get_conn()) as conn:
        row = conn.execute("SELECT id, name, renter_name FROM servers WHERE id = ?", (server_id,)).fetchone()
        if not row:
            flash("服务器不存在", "error")
            return redirect(url_for("rentals_page"))

        is_renewed = 1 if status == "confirmed" else 0
        conn.execute(
            "UPDATE servers SET next_rent_status = ?, is_renewed = ? WHERE id = ?",
            (status, is_renewed, server_id),
        )
        conn.commit()

    if status == "confirmed":
        flash(f"[{row['name']}] 下月租户已标记为确认续租，服务器详情已切换为已续租", "success")
    elif status == "non_renew":
        flash(f"[{row['name']}] 已标记不续租，服务器详情已切换为未续租", "success")
    else:
        flash(f"[{row['name']}] 下月租户状态已设置为未知，服务器详情已切换为未续租", "success")
    return redirect(url_for("rentals_page"))




@app.route("/files/<path:filename>")
def uploaded_data_file(filename):
    return send_from_directory(UPLOAD_DATA_DIR, filename, as_attachment=False)


@app.route("/settings/upload-local-setting-json", methods=["POST"])
@login_required
def upload_local_setting_json_for_packaging():
    file = request.files.get("local_setting_json_file")
    try:
        save_path = save_uploaded_local_setting_json(file)
        flash(f"setting.json 上传成功: {save_path}", "success")
    except Exception as exc:
        flash(f"setting.json 上传失败: {exc}", "error")
    return redirect(url_for("settings_page"))


@app.route("/settings/package-local-vt-data", methods=["POST"])
@login_required
def package_local_vt_data_for_ssh2():
    source_dir = (request.form.get("local_vt_data_path") or "").strip()
    try:
        direct_url = package_local_vt_data_to_zip(source_dir, request_obj=request)
        flash(f"本机VT数据已打包并托管成功: {direct_url}", "success")
    except Exception as exc:
        flash(f"打包本机VT数据失败: {exc}", "error")
    return redirect(url_for("settings_page"))


@app.route("/settings/upload-data-zip", methods=["POST"])
@login_required
def upload_data_zip_for_ssh2():
    file = request.files.get("data_zip_file")
    try:
        direct_url = save_uploaded_data_zip(file, request_obj=request)
        flash(f"数据压缩包上传成功，直链已写入SSH任务2: {direct_url}", "success")
    except Exception as exc:
        flash(f"上传失败: {exc}", "error")
    return redirect(url_for("settings_page"))
@app.route("/management")
@login_required
def management_page():
    global_cfg = get_global_config()
    stock_title, stock_url = build_public_stock_base_url(request)
    return render_template(
        "management.html",
        title="面板管理",
        global_cfg=global_cfg,
        stock_title=stock_title,
        stock_url=stock_url,
        system_events=list_system_events(300),
        email_history=list_email_history(200),
    )




@app.route("/management/backup-email", methods=["POST"])
@login_required
def update_backup_email_settings():
    form = request.form
    try:
        interval_days = parse_int_form_field(form, "backup_interval_days", default=7, min_value=1, max_value=365)
    except ValueError as exc:
        flash(f"备份邮件配置保存失败: {exc}", "error")
        return redirect(url_for("management_page"))

    update_backup_email_config(
        1 if form.get("backup_email_enabled") == "on" else 0,
        form.get("backup_email_to", ""),
        interval_days,
    )
    flash("定期备份邮件配置已更新", "success")
    return redirect(url_for("management_page"))
@app.route("/management/public-stock", methods=["POST"])
@login_required
def update_public_stock_settings():
    form = request.form
    title = (form.get("stock_page_title") or "库存展示").strip() or "库存展示"
    try:
        public_port = parse_int_form_field(form, "public_stock_port", default=PUBLIC_STOCK_PORT, min_value=1, max_value=65535)
    except ValueError as exc:
        flash(f"库存展示配置保存失败: {exc}", "error")
        return redirect(url_for("management_page"))

    with closing(get_conn()) as conn:
        conn.execute(
            "UPDATE global_config SET stock_page_title = ?, public_stock_port = ?, updated_at = ? WHERE id = 1",
            (title, public_port, datetime.now(TIMEZONE).strftime("%Y-%m-%d %H:%M:%S")),
        )
        conn.commit()

    flash("库存展示配置已更新（端口修改需重启面板服务生效）", "success")
    return redirect(url_for("management_page"))

    with closing(get_conn()) as conn:
        conn.execute(
            "UPDATE global_config SET stock_page_title = ?, public_stock_port = ?, updated_at = ? WHERE id = 1",
            (title, public_port, datetime.now(TIMEZONE).strftime("%Y-%m-%d %H:%M:%S")),
        )
        conn.commit()

    flash("库存展示配置已更新（端口修改需重启面板服务生效）", "success")
    return redirect(url_for("management_page"))

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



@app.route("/scp-accounts", methods=["POST"])
@login_required
def add_scp_account():
    form = request.form
    name = (form.get("name") or "").strip()
    username = (form.get("username") or "").strip()
    refresh_token = (form.get("refresh_token") or "").strip()
    api_endpoint = (form.get("api_endpoint") or "").strip() or "https://www.servercontrolpanel.de/scp-core/api/v1"
    if not name or not username:
        flash("新增SCP账号失败: 名称/账号均为必填", "error")
        return redirect(url_for("settings_page"))
    if not refresh_token:
        flash("新增SCP账号失败: OIDC Refresh Token 为必填", "error")
        return redirect(url_for("settings_page"))

    now_text = datetime.now(TIMEZONE).strftime("%Y-%m-%d %H:%M:%S")
    with closing(get_conn()) as conn:
        conn.execute(
            "INSERT INTO scp_accounts(name, username, password, refresh_token, api_endpoint, created_at, updated_at) VALUES(?,?,?,?,?,?,?)",
            (name, username, "", refresh_token, api_endpoint, now_text, now_text),
        )
        conn.commit()

    flash("SCP账号已添加", "success")
    with closing(get_conn()) as c2:
        added = c2.execute("SELECT * FROM scp_accounts ORDER BY id DESC LIMIT 1").fetchone()
    if added:
        check_scp_account_connection(added)
        log_system_event("scp_account", f"新增SCP账号: {added['name']}", account_id=added["id"])
    return redirect(url_for("settings_page"))


@app.route("/scp-accounts/<int:account_id>/update", methods=["POST"])
@login_required
def update_scp_account(account_id):
    form = request.form
    name = (form.get("name") or "").strip()
    username = (form.get("username") or "").strip()
    refresh_token = (form.get("refresh_token") or "").strip()
    api_endpoint = (form.get("api_endpoint") or "").strip() or "https://www.servercontrolpanel.de/scp-core/api/v1"

    if not name or not username or not refresh_token:
        flash("更新SCP账号失败: 名称、账号、Refresh Token 均为必填", "error")
        return redirect(url_for("settings_page"))

    now_text = datetime.now(TIMEZONE).strftime("%Y-%m-%d %H:%M:%S")
    with closing(get_conn()) as conn:
        conn.execute(
            "UPDATE scp_accounts SET name=?, username=?, password='', refresh_token=?, api_endpoint=?, updated_at=? WHERE id=?",
            (name, username, refresh_token, api_endpoint, now_text, account_id),
        )
        conn.commit()

    updated = get_scp_account(account_id)
    if updated:
        check_scp_account_connection(updated)
        log_system_event("scp_account", f"更新SCP账号: {updated['name']}", account_id=account_id)
    flash("SCP账号已更新", "success")
    return redirect(url_for("settings_page"))


@app.route("/scp-accounts/<int:account_id>/delete", methods=["POST"])
@login_required
def delete_scp_account(account_id):
    with closing(get_conn()) as conn:
        conn.execute("UPDATE servers SET scp_account_id = NULL, scp_server_id = '' WHERE scp_account_id = ?", (account_id,))
        conn.execute("DELETE FROM scp_accounts WHERE id = ?", (account_id,))
        conn.commit()

    log_system_event("scp_account", f"删除SCP账号 id={account_id}", account_id=account_id)
    flash("SCP账号已删除，相关服务器绑定已清空", "success")
    return redirect(url_for("settings_page"))


@app.route("/scp-accounts/<int:account_id>/check", methods=["POST"])
@login_required
def check_scp_account(account_id):
    account = get_scp_account(account_id)
    if not account:
        flash("SCP账号不存在", "error")
        return redirect(url_for("settings_page"))
    ok, msg = check_scp_account_connection(account)
    flash(f"SCP账号[{account['name']}] 连接正常" if ok else f"SCP账号[{account['name']}] 连接失败: {msg}", "success" if ok else "error")
    return redirect(url_for("settings_page"))


@app.route("/global-tasks", methods=["POST"])
@login_required
def update_global_tasks():
    form = request.form
    try:
        smtp_port = parse_int_form_field(form, "smtp_port", default=587, min_value=1, max_value=65535)
        traffic_sample_interval_minutes = parse_int_form_field(form, "traffic_sample_interval_minutes", default=60, min_value=1, max_value=1440)
    except ValueError as exc:
        flash(f"全局配置保存失败: {exc}", "error")
        return redirect(url_for("settings_page"))

    update_global_config(
        form.get("reset_command", ""),
        form.get("ssh_command_2", ""),
        form.get("ssh_command_3", ""),
        form.get("agent_install_command", ""),
        form.get("panel_base_url", ""),
        1 if form.get("notify_email_enabled") == "on" else 0,
        form.get("smtp_host", ""),
        smtp_port,
        form.get("smtp_user", ""),
        form.get("smtp_password", ""),
        form.get("smtp_from", ""),
        form.get("notify_email_to", ""),
        traffic_sample_interval_minutes,
        1 if form.get("data_zip_enabled") == "on" else 0,
        form.get("data_zip_source", "original"),
        form.get("local_vt_data_path", ""),
        1 if form.get("local_setting_json_enabled") == "on" else 0,
        1 if form.get("api_failure_notify_enabled") == "on" else 0,
        form.get("renew_notice_days", ""),
    )
    flash("全局任务配置已更新", "success")
    return redirect(url_for("settings_page"))


@app.route("/notify/test", methods=["POST"])
@login_required
def test_notify_email():
    try:
        ok, err_text = send_email_message(
            "[VPS面板] 邮件通知测试",
            (
                "这是一封来自 VPS 管理面板的测试邮件。\n"
                f"发送时间: {datetime.now(TIMEZONE).strftime('%Y-%m-%d %H:%M:%S')}\n"
                "若你收到本邮件，说明 SMTP 配置可用。"
            ),
            return_error=True,
        )
        if ok:
            flash("测试邮件已发送，请检查收件箱", "success")
        else:
            flash(f"测试邮件发送失败: {err_text or '请先开启邮件通知并完整填写 SMTP 配置'}", "error")
    except Exception as exc:
        flash(f"测试邮件发送失败: {exc}", "error")
    return redirect(url_for("settings_page"))


def get_next_sort_order(conn):
    row = conn.execute("SELECT COALESCE(MAX(sort_order), 0) AS max_order FROM servers").fetchone()
    return int(row["max_order"]) + 1


@app.route("/server-groups", methods=["POST"])
@login_required
def add_server_group():
    form = request.form
    name = (form.get("name") or "").strip()
    description = (form.get("description") or "").strip()
    if not name:
        flash("分组名称不能为空", "error")
        return redirect(url_for("settings_page"))
    sort_order_text = (form.get("sort_order") or "").strip()
    try:
        sort_order = int(sort_order_text) if sort_order_text else 0
    except ValueError:
        flash("分组排序必须是整数", "error")
        return redirect(url_for("settings_page"))
    now_text = datetime.now(TIMEZONE).strftime("%Y-%m-%d %H:%M:%S")
    with closing(get_conn()) as conn:
        conn.execute(
            "INSERT INTO server_groups(name, description, sort_order, created_at, updated_at) VALUES(?,?,?,?,?)",
            (name, description, sort_order, now_text, now_text),
        )
        conn.commit()
    flash("服务器分组已添加", "success")
    return redirect(url_for("settings_page"))


@app.route("/server-groups/<int:group_id>/update", methods=["POST"])
@login_required
def update_server_group(group_id):
    form = request.form
    name = (form.get("name") or "").strip()
    description = (form.get("description") or "").strip()
    if not name:
        flash("分组名称不能为空", "error")
        return redirect(url_for("settings_page"))
    try:
        sort_order = parse_int_form_field(form, "sort_order", default=0)
    except ValueError as exc:
        flash(f"分组更新失败: {exc}", "error")
        return redirect(url_for("settings_page"))

    with closing(get_conn()) as conn:
        conn.execute(
            "UPDATE server_groups SET name=?, description=?, sort_order=?, updated_at=? WHERE id=?",
            (name, description, sort_order, datetime.now(TIMEZONE).strftime("%Y-%m-%d %H:%M:%S"), group_id),
        )
        conn.commit()
    flash("服务器分组已更新", "success")
    return redirect(url_for("settings_page"))


@app.route("/server-groups/<int:group_id>/delete", methods=["POST"])
@login_required
def delete_server_group(group_id):
    with closing(get_conn()) as conn:
        conn.execute("UPDATE servers SET server_group_id = NULL WHERE server_group_id = ?", (group_id,))
        conn.execute("DELETE FROM server_groups WHERE id = ?", (group_id,))
        conn.commit()
    flash("服务器分组已删除，原分组服务器已变为未分组", "success")
    return redirect(url_for("settings_page"))


@app.route("/servers", methods=["POST"])
@login_required
def add_server():
    form = request.form
    try:
        ssh_port = parse_int_form_field(form, "ssh_port", default=22, min_value=1, max_value=65535)
        reset_day = parse_int_form_field(form, "reset_day", min_value=1, max_value=31)
        reset_hour = parse_int_form_field(form, "reset_hour", default=1, min_value=0, max_value=23)
        reset_minute = parse_int_form_field(form, "reset_minute", default=0, min_value=0, max_value=59)
        max_retries = parse_int_form_field(form, "max_retries", default=DEFAULT_MAX_RETRIES, min_value=1, max_value=10)
        scp_account_id_raw = (form.get("scp_account_id") or "").strip()
        scp_account_id = int(scp_account_id_raw) if scp_account_id_raw.isdigit() else None
        server_group_id = parse_int_form_field(form, "server_group_id", default=0, min_value=0)
        reinstall_mode = (form.get("reinstall_mode") or "ssh").strip().lower()
        if reinstall_mode not in ("ssh", "scp_api"):
            raise ValueError("重置方式仅支持 ssh 或 scp_api")
    except ValueError as exc:
        flash(f"添加服务器失败: {exc}", "error")
        return redirect(url_for("settings_page"))

    with closing(get_conn()) as conn:
        sort_order_input = (form.get("sort_order") or "").strip()
        try:
            sort_order = int(sort_order_input) if sort_order_input else get_next_sort_order(conn)
        except ValueError:
            flash("添加服务器失败: sort_order 必须是整数", "error")
            return redirect(url_for("settings_page"))

        conn.execute(
            """
            INSERT INTO servers(name, ip, ssh_port, ssh_user, ssh_password, reset_day, reset_hour, reset_minute, auto_reset, is_renewed, is_rented, renter_name, renter_email, server_group_id, sort_order, max_retries, retry_backoff_seconds, scp_account_id, scp_server_id, reinstall_mode, agent_token, period_key, period_upload_bytes, period_download_bytes, last_agent_rx_bytes, last_agent_tx_bytes, last_agent_report_at)
            VALUES(?,?,?,?,?,?,?,?,?,0,0,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
            """,
            (
                form["name"].strip(),
                form["ip"].strip(),
                ssh_port,
                form.get("ssh_user", "root").strip() or "root",
                form["ssh_password"],
                reset_day,
                reset_hour,
                reset_minute,
                1 if form.get("auto_reset") == "on" else 0,
                (form.get("renter_name") or "").strip(),
                (form.get("renter_email") or "").strip(),
                server_group_id or None,
                sort_order,
                max_retries,
                normalize_backoff_plan_text(form.get("retry_backoff_seconds") or DEFAULT_RETRY_BACKOFF_SECONDS),
                scp_account_id,
                (form.get("scp_server_id") or "").strip(),
                reinstall_mode,
                "",
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
    try:
        ssh_port = parse_int_form_field(form, "ssh_port", default=22, min_value=1, max_value=65535)
        reset_day = parse_int_form_field(form, "reset_day", min_value=1, max_value=31)
        reset_hour = parse_int_form_field(form, "reset_hour", default=1, min_value=0, max_value=23)
        reset_minute = parse_int_form_field(form, "reset_minute", default=0, min_value=0, max_value=59)
        sort_order = parse_int_form_field(form, "sort_order", default=0)
        max_retries = parse_int_form_field(form, "max_retries", default=DEFAULT_MAX_RETRIES, min_value=1, max_value=10)
        scp_account_id_raw = (form.get("scp_account_id") or "").strip()
        scp_account_id = int(scp_account_id_raw) if scp_account_id_raw.isdigit() else None
        server_group_id = parse_int_form_field(form, "server_group_id", default=0, min_value=0)
        reinstall_mode = (form.get("reinstall_mode") or "ssh").strip().lower()
        if reinstall_mode not in ("ssh", "scp_api"):
            raise ValueError("重置方式仅支持 ssh 或 scp_api")
    except ValueError as exc:
        flash(f"更新服务器失败: {exc}", "error")
        return redirect(url_for("settings_page"))

    with closing(get_conn()) as conn:
        conn.execute(
            """
            UPDATE servers
            SET name=?, ip=?, ssh_port=?, ssh_user=?, ssh_password=?, reset_day=?, reset_hour=?, reset_minute=?, auto_reset=?, renter_name=?, renter_email=?, server_group_id=?, sort_order=?, max_retries=?, retry_backoff_seconds=?, scp_account_id=?, scp_server_id=?, reinstall_mode=?
            WHERE id=?
            """,
            (
                form["name"].strip(),
                form["ip"].strip(),
                ssh_port,
                form.get("ssh_user", "root").strip() or "root",
                form["ssh_password"],
                reset_day,
                reset_hour,
                reset_minute,
                1 if form.get("auto_reset") == "on" else 0,
                (form.get("renter_name") or "").strip(),
                (form.get("renter_email") or "").strip(),
                server_group_id or None,
                sort_order,
                max_retries,
                normalize_backoff_plan_text(form.get("retry_backoff_seconds") or DEFAULT_RETRY_BACKOFF_SECONDS),
                scp_account_id,
                (form.get("scp_server_id") or "").strip(),
                reinstall_mode,
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
        conn.execute("DELETE FROM task_queue WHERE server_id = ?", (server_id,))
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


@app.route("/servers/<int:server_id>/renew-until", methods=["POST"])
@login_required
def set_renew_until(server_id):
    date_text = (request.form.get("renew_until_date") or "").strip()
    renew_until = _parse_date_text(date_text)
    if date_text and not renew_until:
        flash("长期续费日期格式错误，请使用 YYYY-MM-DD", "error")
        return redirect(url_for("details_page"))
    with closing(get_conn()) as conn:
        row = conn.execute("SELECT id, name FROM servers WHERE id = ?", (server_id,)).fetchone()
        if not row:
            flash("服务器不存在", "error")
            return redirect(url_for("details_page"))
        conn.execute("UPDATE servers SET renew_until_date=? WHERE id=?", (date_text, server_id))
        conn.commit()
    log_system_event("long_renew", f"服务器[{row['name']}] 设置长期续费至 {date_text or '空'}", server_id=server_id)
    flash(f"长期续费日期已更新为 {date_text or '未设置'}", "success")
    return redirect(url_for("details_page"))


@app.route("/servers/<int:server_id>/check-ssh", methods=["POST"])
@login_required
def check_ssh_now(server_id):
    row = get_server(server_id)
    if not row:
        flash("服务器不存在", "error")
        return redirect(url_for("details_page"))

    online = check_server_ssh_connectivity(row)
    flash("SSH在线" if online else "SSH失联", "success" if online else "error")
    return redirect(url_for("details_page"))


@app.route("/servers/<int:server_id>/renter", methods=["POST"])
@login_required
def update_renter(server_id):
    renter_name = (request.form.get("renter_name") or "").strip()
    renter_email = (request.form.get("renter_email") or "").strip()
    now_dt = datetime.now(TIMEZONE)
    with closing(get_conn()) as conn:
        row = conn.execute("SELECT id, reset_day, reset_hour, reset_minute FROM servers WHERE id = ?", (server_id,)).fetchone()
        if not row:
            flash("服务器不存在", "error")
            return redirect(url_for("details_page"))
        rollover_key = _server_rental_cycle_key(row, now_dt) if (renter_name or renter_email) else ""
        conn.execute(
            "UPDATE servers SET renter_name = ?, renter_email = ?, delivery_email_sent_at = NULL, rental_rollover_key = ? WHERE id = ?",
            (renter_name, renter_email, rollover_key, server_id),
        )
        conn.commit()
    flash("租赁人信息已更新" if (renter_name or renter_email) else "已清空租赁人信息", "success")
    return redirect(url_for("details_page"))




@app.route("/servers/<int:server_id>/send-delivery-email", methods=["POST"])
@login_required
def send_delivery_email(server_id):
    row = get_server(server_id)
    if not row:
        flash("服务器不存在", "error")
        return redirect(url_for("details_page"))

    renter_email = (row["renter_email"] or "").strip()
    if not renter_email:
        flash("请先填写租赁人邮箱", "error")
        return redirect(url_for("details_page"))

    latest = ""
    with closing(get_conn()) as conn:
        latest_log = conn.execute(
            "SELECT summary FROM job_logs WHERE server_id = ? ORDER BY id DESC LIMIT 1",
            (server_id,),
        ).fetchone()
        latest = (latest_log["summary"] if latest_log else "") or "暂无输出详情"

    subject = f"[服务器发货] {row['name']}"
    body = latest

    ok = send_email_to_recipient(subject, body, renter_email, category="delivery")
    if not ok:
        flash("邮件发货失败，请检查SMTP配置和收件人邮箱", "error")
        return redirect(url_for("details_page"))

    now_text = datetime.now(TIMEZONE).strftime("%Y-%m-%d %H:%M:%S")
    with closing(get_conn()) as conn:
        conn.execute("UPDATE servers SET delivery_email_sent_at = ? WHERE id = ?", (now_text, server_id))
        conn.commit()
    flash(f"[{row['name']}] 发货邮件已发送到 {renter_email}", "success")
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
        if next_state:
            conn.execute("UPDATE servers SET is_rented = ? WHERE id = ?", (next_state, server_id))
        else:
            conn.execute(
                "UPDATE servers SET is_rented = 0, renter_name = '', renter_email = '', delivery_email_sent_at = NULL, renew_notice_sent_keys = '' WHERE id = ?",
                (server_id,),
            )
        conn.commit()
    flash("已标记为已出租" if next_state else "已标记为未出租", "success")
    return redirect(url_for("details_page"))




@app.route("/servers/refresh-api-images", methods=["POST"])
@login_required
def refresh_api_images_all_servers():
    rows = list_servers()
    if not rows:
        flash("暂无服务器，无需刷新", "error")
        return redirect(url_for("details_page"))

    job_id = start_api_image_refresh_background_job()
    if not job_id:
        flash("已有镜像刷新任务在后台执行，请稍后刷新页面查看进度", "error")
    else:
        flash(f"镜像刷新任务已在后台启动（任务ID: {job_id}），页面刷新/关闭不会中断", "success")
    return redirect(url_for("details_page"))


@app.route("/servers/<int:server_id>/run-api-reinstall", methods=["POST"])
@login_required
def run_api_reinstall(server_id):
    row = get_server(server_id)
    if not row:
        flash("服务器不存在", "error")
        return redirect(url_for("details_page"))

    selected_key = (request.form.get("api_image_key") or "").strip()
    options = load_server_scp_images(dict(row))
    selected = pick_scp_image_option_by_key(options, selected_key)
    if not selected:
        flash("请先更新镜像列表并选择有效镜像", "error")
        return redirect(url_for("details_page"))

    with closing(get_conn()) as conn:
        conn.execute("UPDATE servers SET scp_selected_image = ? WHERE id = ?", (selected_key, server_id))
        conn.commit()

    ok, msg, _ = run_for_server(server_id, trigger_type="apireinstall")
    flash(msg if ok else f"提交失败: {msg}", "success" if ok else "error")
    return redirect(url_for("details_page"))

@app.route("/servers/<int:server_id>/run-bin-reinstall", methods=["POST"])
@login_required
def run_bin_reinstall(server_id):
    choice = (request.form.get("reinstall_choice") or "").strip().lower()
    if choice not in BIN_REINSTALL_CHOICES:
        flash("请选择有效的重装系统版本", "error")
        return redirect(url_for("details_page"))

    ok, msg, _ = run_for_server(server_id, trigger_type=f"binreinstall:{choice}")
    flash(msg if ok else f"提交失败: {msg}", "success" if ok else "error")
    return redirect(url_for("details_page"))


@app.route("/servers/<int:server_id>/run", methods=["POST"])
@login_required
def run_now(server_id):
    ok, msg, _ = run_for_server(server_id)
    flash(msg, "success" if ok else "error")
    return redirect(url_for("details_page"))


def start_public_stock_server():
    _, public_port = get_public_stock_settings()
    if public_port == PANEL_PORT:
        log_system_event("public_stock", f"库存展示端口与管理面板端口冲突: {public_port}", level="error")
        return None
    try:
        server = make_server(PANEL_HOST, public_port, public_app)
    except Exception as exc:
        log_system_event("public_stock", f"库存展示服务启动失败: {exc}", level="error")
        return None

    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    log_system_event("public_stock", f"库存展示服务已启动: {PANEL_HOST}:{public_port}")
    return server


def start_scheduler():
    scheduler = BackgroundScheduler(timezone=TIMEZONE, executors={"default": ThreadPoolExecutor(1)})
    scheduler.add_job(check_scheduled_jobs, "cron", minute="*", max_instances=1, coalesce=True)
    scheduler.add_job(refresh_all_traffic_data_via_scp, "cron", minute="*", max_instances=1, coalesce=True)
    scheduler.start()
    return scheduler


if __name__ == "__main__":
    init_db()
    start_task_worker()
    scheduler = start_scheduler()
    public_server = start_public_stock_server()
    try:
        app.run(host=PANEL_HOST, port=PANEL_PORT, debug=False)
    finally:
        scheduler.shutdown()
        if public_server:
            public_server.shutdown()
