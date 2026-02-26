import json
import os
import re
import secrets
import shlex
import smtplib
import sqlite3
import string
import threading
import time
from queue import Queue
from contextlib import closing
from datetime import datetime, timedelta
from functools import wraps
from io import BytesIO
from urllib import error as urlerror
from urllib import parse as urlparse
from urllib import request as urlrequest
from xml.sax.saxutils import escape as xml_escape
from email.message import EmailMessage
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
# Backward compatibility: older deployments may still reference this name.
BIN_REINSTALL_REBOOT_DELAY_SECONDS = int(
    os.environ.get("BIN_REINSTALL_REBOOT_DELAY_SECONDS", str(POST_REINSTALL_WAIT_SECONDS))
)
DD_NEW_PASSWORD_GRACE_SECONDS = int(os.environ.get("DD_NEW_PASSWORD_GRACE_SECONDS", "900"))
AGENT_REPORT_INTERVAL_SECONDS = int(os.environ.get("AGENT_REPORT_INTERVAL_SECONDS", "60"))
DEFAULT_MAX_RETRIES = int(os.environ.get("DEFAULT_MAX_RETRIES", "2"))
DEFAULT_RETRY_BACKOFF_SECONDS = os.environ.get("DEFAULT_RETRY_BACKOFF_SECONDS", "60,180")

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
                renter_name TEXT NOT NULL DEFAULT '',
                sort_order INTEGER NOT NULL DEFAULT 0,
                agent_token TEXT NOT NULL DEFAULT '',
                period_key TEXT NOT NULL DEFAULT '',
                period_upload_bytes INTEGER NOT NULL DEFAULT 0,
                period_download_bytes INTEGER NOT NULL DEFAULT 0,
                last_agent_rx_bytes INTEGER NOT NULL DEFAULT 0,
                last_agent_tx_bytes INTEGER NOT NULL DEFAULT 0,
                last_agent_report_at TEXT,
                last_reset_at TEXT,
                ssh_status TEXT NOT NULL DEFAULT 'unknown',
                ssh_checked_at TEXT
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
                traffic_data_source TEXT NOT NULL DEFAULT 'agent',
                ssh_check_interval_minutes INTEGER NOT NULL DEFAULT 120,
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

        ensure_column(conn, "servers", "last_reset_at TEXT")
        ensure_column(conn, "servers", "is_renewed INTEGER NOT NULL DEFAULT 0")
        ensure_column(conn, "servers", "is_rented INTEGER NOT NULL DEFAULT 0")
        ensure_column(conn, "servers", "renter_name TEXT NOT NULL DEFAULT ''")
        ensure_column(conn, "servers", "sort_order INTEGER NOT NULL DEFAULT 0")
        ensure_column(conn, "servers", "agent_token TEXT NOT NULL DEFAULT ''")
        ensure_column(conn, "servers", "period_key TEXT NOT NULL DEFAULT ''")
        ensure_column(conn, "servers", "period_upload_bytes INTEGER NOT NULL DEFAULT 0")
        ensure_column(conn, "servers", "period_download_bytes INTEGER NOT NULL DEFAULT 0")
        ensure_column(conn, "servers", "last_agent_rx_bytes INTEGER NOT NULL DEFAULT 0")
        ensure_column(conn, "servers", "last_agent_tx_bytes INTEGER NOT NULL DEFAULT 0")
        ensure_column(conn, "servers", "last_agent_report_at TEXT")
        ensure_column(conn, "servers", "ssh_status TEXT NOT NULL DEFAULT 'unknown'")
        ensure_column(conn, "servers", "ssh_checked_at TEXT")
        ensure_column(conn, "servers", "reset_hour INTEGER NOT NULL DEFAULT 1")
        ensure_column(conn, "servers", "reset_minute INTEGER NOT NULL DEFAULT 0")
        ensure_column(conn, "servers", "max_retries INTEGER NOT NULL DEFAULT 2")
        ensure_column(conn, "servers", "retry_backoff_seconds TEXT NOT NULL DEFAULT '60,180'")
        ensure_column(conn, "servers", "scp_account_id INTEGER")
        ensure_column(conn, "servers", "scp_server_id TEXT NOT NULL DEFAULT ''")
        ensure_column(conn, "servers", "reinstall_mode TEXT NOT NULL DEFAULT 'ssh'")
        ensure_column(conn, "scp_accounts", "refresh_token TEXT NOT NULL DEFAULT ''")
        ensure_column(conn, "job_logs", "summary TEXT NOT NULL DEFAULT ''")
        ensure_column(conn, "task_queue", "trigger_type TEXT NOT NULL DEFAULT 'manual'")
        ensure_column(conn, "task_queue", "batch_key TEXT NOT NULL DEFAULT ''")
        ensure_column(conn, "global_config", "panel_password_hash TEXT")
        ensure_column(conn, "global_config", "agent_install_command TEXT NOT NULL DEFAULT ''")
        ensure_column(conn, "global_config", "panel_base_url TEXT NOT NULL DEFAULT ''")
        ensure_column(conn, "global_config", "notify_email_enabled INTEGER NOT NULL DEFAULT 0")
        ensure_column(conn, "global_config", "smtp_host TEXT NOT NULL DEFAULT ''")
        ensure_column(conn, "global_config", "smtp_port INTEGER NOT NULL DEFAULT 587")
        ensure_column(conn, "global_config", "smtp_user TEXT NOT NULL DEFAULT ''")
        ensure_column(conn, "global_config", "smtp_password TEXT NOT NULL DEFAULT ''")
        ensure_column(conn, "global_config", "smtp_from TEXT NOT NULL DEFAULT ''")
        ensure_column(conn, "global_config", "notify_email_to TEXT NOT NULL DEFAULT ''")
        ensure_column(conn, "global_config", "traffic_data_source TEXT NOT NULL DEFAULT 'agent'")
        ensure_column(conn, "global_config", "ssh_check_interval_minutes INTEGER NOT NULL DEFAULT 120")
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


def list_scp_accounts():
    with closing(get_conn()) as conn:
        return conn.execute("SELECT * FROM scp_accounts ORDER BY id ASC").fetchall()


def get_scp_account(account_id):
    if not account_id:
        return None
    with closing(get_conn()) as conn:
        return conn.execute("SELECT * FROM scp_accounts WHERE id=?", (account_id,)).fetchone()


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


def _scp_rest_refresh_access_token(account_row):
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
    with urlrequest.urlopen(req, timeout=60) as resp:
        data = json.loads(resp.read().decode("utf-8", errors="ignore") or "{}")
    token = _scp_rest_extract_token(data)
    if not token:
        raise RuntimeError("SCP OIDC 刷新成功但未返回access_token")
    return token


def scp_rest_login(account_row):
    try:
        token = _scp_rest_refresh_access_token(account_row)
        if token:
            return _scp_rest_base_endpoint(account_row["api_endpoint"]), token
    except Exception:
        pass

    endpoint_candidates = _scp_endpoint_candidates(account_row["api_endpoint"])
    login_urls = []
    for endpoint in endpoint_candidates:
        for suffix in ("auth/login", "login", "session", "auth/session"):
            url = f"{endpoint}/{suffix}".rstrip("/")
            if url not in login_urls:
                login_urls.append(url)
    payloads = [
        {"username": account_row["username"], "password": account_row["password"]},
        {"login": account_row["username"], "password": account_row["password"]},
        {"customer_number": account_row["username"], "password": account_row["password"]},
    ]
    last_exc = None
    for url in login_urls:
        for payload in payloads:
            req = urlrequest.Request(
                url,
                data=json.dumps(payload).encode("utf-8"),
                headers={"Content-Type": "application/json", "Accept": "application/json"},
                method="POST",
            )
            try:
                with urlrequest.urlopen(req, timeout=60) as resp:
                    data = json.loads(resp.read().decode("utf-8", errors="ignore") or "{}")
            except Exception as exc:
                last_exc = exc
                continue
            token = _scp_rest_extract_token(data)
            if token:
                endpoint = url
                for suffix in ("/auth/login", "/login", "/session", "/auth/session"):
                    if endpoint.endswith(suffix):
                        endpoint = endpoint[: -len(suffix)]
                        break
                return endpoint.rstrip("/"), token
    raise RuntimeError(f"SCP REST登录失败: {last_exc}")


def scp_rest_request(account_row, method, path, token=None, payload=None, endpoint_base=None):
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
    with urlrequest.urlopen(req, timeout=60) as resp:
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
            return
        if state in ("ERROR", "FAILED", "CANCELED"):
            raise RuntimeError(f"SCP任务失败: uuid={task_uuid}, state={state}, detail={str(data)[:500]}")
        time.sleep(10)
    raise RuntimeError(f"SCP任务超时: uuid={task_uuid} 在限定时间内未完成")


def find_scp_server_id_by_ip(server_ip, output_lines=None, account_candidates=None):
    ip_text = str(server_ip or "").strip()
    if not ip_text:
        return None, None

    candidates = account_candidates if account_candidates is not None else list_scp_accounts()

    for account in candidates:
        rest_errors = []
        scanned_server_ids = set()
        try:
            endpoint_base, token = scp_rest_login(account)
            if output_lines is not None:
                output_lines.append(f"SCP账号[{account['name']}] REST鉴权成功，endpoint={endpoint_base}")
            rest_paths = [
                f"servers?ip={urlparse.quote(ip_text)}",
                "servers",
                "servers?limit=200",
                "vservers",
                "virtual-machines",
            ]
            for path in rest_paths:
                try:
                    data = scp_rest_request(account, "GET", path, token=token, endpoint_base=endpoint_base)
                except Exception as exc:
                    rest_errors.append(f"{path}: {exc}")
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
                        if output_lines is not None:
                            output_lines.append(f"SCP账号[{account['name']}] REST列表项无IP，尝试详情查询 server_id={server_id}")
                        candidate_ips = _scp_rest_fetch_server_ips(account, endpoint_base, token, server_id)
                        if output_lines is not None and candidate_ips:
                            output_lines.append(f"SCP账号[{account['name']}] REST详情查询命中IP server_id={server_id}, ips={','.join(candidate_ips[:3])}")
                    if ip_text in candidate_ips and server_id:
                        if output_lines is not None:
                            output_lines.append(f"SCP账号[{account['name']}] REST匹配成功 path={path}, server_id={server_id}, ip={ip_text}")
                        return account, server_id
                    if output_lines is not None and seen <= 3:
                        ip_preview = ",".join(candidate_ips[:3]) if candidate_ips else "<none>"
                        output_lines.append(f"SCP账号[{account['name']}] REST候选 path={path}, server_id={server_id or '-'}, ips={ip_preview}")
                if output_lines is not None:
                    output_lines.append(f"SCP账号[{account['name']}] REST列表完成 path={path}, entries={seen}")
            if output_lines is not None:
                tail = " | ".join(rest_errors[-2:]) if rest_errors else "接口返回成功但未匹配到目标IP"
                output_lines.append(f"SCP账号[{account['name']}] REST识别未匹配，转SOAP/JSON尝试: {tail}")
        except Exception as rest_exc:
            if output_lines is not None:
                output_lines.append(f"SCP账号[{account['name']}] REST识别失败，转SOAP/JSON尝试: {rest_exc}")
        try:
            for vserver_name in scp_soap_get_vservers(account):
                ips = scp_soap_get_vserver_ips(account, vserver_name)
                if any(str(ip).strip() == ip_text for ip in ips):
                    return account, vserver_name
        except Exception as soap_exc:
            if output_lines is not None:
                output_lines.append(f"SCP账号[{account['name']}] SOAP识别失败，转JSON尝试: {soap_exc}")
            try:
                session_id = scp_api_login(account)
                session_payload = {"session_id": session_id, "sessionid": session_id, "apisessionid": session_id}

                try:
                    data = scp_api_call(account, "listVServers", session_payload)
                except Exception:
                    data = scp_api_call(account, "getVServers", session_payload)

                if isinstance(data, dict):
                    servers = data.get("vservers") or data.get("servers") or []
                elif isinstance(data, list):
                    servers = data
                else:
                    servers = []

                for item in servers:
                    if isinstance(item, dict):
                        item_ip = str(item.get("ip") or item.get("ipv4") or item.get("primary_ip") or "").strip()
                        if item_ip == ip_text:
                            server_id = str(item.get("vserverid") or item.get("id") or item.get("serverid") or "").strip()
                            if server_id:
                                return account, server_id
                    else:
                        vserver_name = str(item or "").strip()
                        if not vserver_name:
                            continue
                        info = scp_api_call(
                            account,
                            "getVServerInformation",
                            {
                                "session_id": session_id,
                                "sessionid": session_id,
                                "apisessionid": session_id,
                                "vservername": vserver_name,
                            },
                        )
                        info_ips = []
                        if isinstance(info, dict):
                            info_ips = info.get("ips") or []
                        if any(str(ip).strip() == ip_text for ip in info_ips):
                            return account, vserver_name
            except Exception as json_exc:
                if output_lines is not None:
                    output_lines.append(f"SCP账号[{account['name']}] JSON识别也失败: {json_exc}")
    return None, None


def bind_scp_server(server_id, account_id, scp_server_id):
    with closing(get_conn()) as conn:
        conn.execute(
            "UPDATE servers SET scp_account_id=?, scp_server_id=? WHERE id=?",
            (account_id, str(scp_server_id or "").strip(), server_id),
        )
        conn.commit()


def _xml_local_name(tag):
    return tag.split("}", 1)[-1] if "}" in tag else tag


def _scp_soap_endpoint(api_endpoint):
    candidates = _scp_endpoint_candidates(api_endpoint)
    for candidate in candidates:
        if "WSEndUser" in candidate:
            return candidate
    first = candidates[0]
    host = first
    for marker in ("/scp-core/api/", "/api/"):
        if marker in host:
            host = host.split(marker, 1)[0]
            break
    return f"{host.rstrip('/')}/WSEndUser"


def scp_soap_call(account_row, method_name, params):
    endpoint = _scp_soap_endpoint(account_row["api_endpoint"])
    ns_candidates = [
        "http://enduser.service.web.vserver.pcs.servercontrolpanel.de/",
        "http://enduser.service.web.vserver.pcs.servercontrolpanel.de",
    ]

    body_parts = []
    for k, v in (params or {}).items():
        body_parts.append(f"<{k}>{xml_escape(str(v or ''))}</{k}>")

    soap_actions = []
    for ns in ns_candidates:
        soap_actions.extend([f'"{ns}{method_name}"', f'"{method_name}"', method_name, ""])

    envelope_variants = []
    for ns in ns_candidates:
        envelope_variants.append(
            (
                (
                    '<?xml version="1.0" encoding="UTF-8"?>'
                    '<soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/" '
                    f'xmlns:ws="{ns}">'
                    '<soapenv:Header/><soapenv:Body>'
                    f'<ws:{method_name}>' + "".join(body_parts) + f'</ws:{method_name}>'
                    '</soapenv:Body></soapenv:Envelope>'
                ).encode("utf-8"),
                ns,
                True,
            )
        )
        envelope_variants.append(
            (
                (
                    '<?xml version="1.0" encoding="UTF-8"?>'
                    '<soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/">'
                    '<soapenv:Header/><soapenv:Body>'
                    f'<{method_name}>' + "".join(body_parts) + f'</{method_name}>'
                    '</soapenv:Body></soapenv:Envelope>'
                ).encode("utf-8"),
                ns,
                False,
            )
        )

    import xml.etree.ElementTree as ET
    last_exc = None
    for envelope, ns, _ in envelope_variants:
        for action in soap_actions:
            headers = {"Content-Type": "text/xml; charset=utf-8"}
            if action:
                headers["SOAPAction"] = action
            req = urlrequest.Request(endpoint, data=envelope, headers=headers)
            try:
                with urlrequest.urlopen(req, timeout=60) as resp:
                    raw = resp.read().decode("utf-8", errors="ignore")
            except urlerror.HTTPError as exc:
                detail = exc.read().decode("utf-8", errors="ignore") if hasattr(exc, "read") else ""
                last_exc = RuntimeError(f"SCP SOAP错误[{exc.code}]: {detail or exc.reason}")
                continue
            except urlerror.URLError as exc:
                last_exc = RuntimeError(f"SCP SOAP网络异常: {exc}")
                continue

            try:
                root = ET.fromstring(raw)
            except Exception as exc:
                last_exc = RuntimeError(f"SCP SOAP返回非XML: {raw[:300]}")
                continue

            fault_text = ""
            for el in root.iter():
                if _xml_local_name(el.tag) == "Fault":
                    fault_text = " ".join((x.text or "").strip() for x in el.iter() if (x.text or "").strip())
                    break
            if fault_text:
                last_exc = RuntimeError(f"SCP SOAP调用失败[{method_name}]: {fault_text}")
                continue

            returns = []
            for el in root.iter():
                if _xml_local_name(el.tag) == "return":
                    returns.append((el.text or "").strip())
            return returns

    if last_exc:
        raise last_exc
    raise RuntimeError(f"SCP SOAP调用失败[{method_name}]: 未知错误")


def scp_soap_get_vservers(account_row):
    auth_payload = {"loginName": account_row["username"], "password": account_row["password"]}
    method_candidates = ["getVServers", "getVServer", "getVServerNames"]
    last_exc = None
    for method in method_candidates:
        try:
            rows = [x for x in scp_soap_call(account_row, method, auth_payload) if x]
            if rows:
                return rows
        except Exception as exc:
            last_exc = exc
            continue
    if last_exc:
        raise last_exc
    return []


def scp_soap_get_vserver_ips(account_row, vserver_name):
    payload = {"loginName": account_row["username"], "password": account_row["password"], "vservername": vserver_name}
    method_candidates = ["getVServerInformation", "getVServerInfo"]
    last_exc = None
    for method in method_candidates:
        try:
            rows = [x for x in scp_soap_call(account_row, method, payload) if x and "." in x]
            if rows:
                return rows
        except Exception as exc:
            last_exc = exc
            continue
    if last_exc:
        raise last_exc
    return []


def scp_api_call(account_row, action, payload):
    endpoint_candidates = []
    for base in _scp_endpoint_candidates(account_row["api_endpoint"]):
        if "WSEndUser" in base:
            endpoint = base
        else:
            endpoint = base.rstrip("/") + "/WSEndUser"
        endpoint = endpoint.rstrip("?")
        if "?" not in endpoint:
            endpoint = endpoint + "?JSON"
        if endpoint not in endpoint_candidates:
            endpoint_candidates.append(endpoint)

    param_payload = payload or {}
    request_variants = [
        (
            json.dumps({"action": action, "param": param_payload}).encode("utf-8"),
            {"Content-Type": "application/json; charset=utf-8", "Accept": "application/json"},
        ),
        (
            json.dumps({"action": action, "param": param_payload}).encode("utf-8"),
            {"Content-Type": "application/json", "Accept": "application/json"},
        ),
        (
            urlparse.urlencode({"action": action, "param": json.dumps(param_payload)}).encode("utf-8"),
            {"Content-Type": "application/x-www-form-urlencoded", "Accept": "application/json"},
        ),
        (
            urlparse.urlencode({"action": action, "param": json.dumps(param_payload)}).encode("utf-8"),
            {"Accept": "application/json"},
        ),
    ]

    raw = ""
    last_exc = None
    for endpoint in endpoint_candidates:
        for body, headers in request_variants:
            req = urlrequest.Request(endpoint, data=body, headers=headers)
            for _ in range(2):
                try:
                    with urlrequest.urlopen(req, timeout=60) as resp:
                        raw = resp.read().decode("utf-8", errors="ignore")
                        break
                except urlerror.HTTPError as exc:
                    detail = exc.read().decode("utf-8", errors="ignore") if hasattr(exc, "read") else ""
                    last_exc = RuntimeError(f"SCP API HTTP错误[{exc.code}]: {detail or exc.reason}")
                    # 400/404/415 usually indicate endpoint/payload/media-type mismatch.
                    break
                except urlerror.URLError as exc:
                    last_exc = RuntimeError(f"SCP API网络异常: {exc}")
                    if "timed out" in str(exc).lower():
                        continue
                    break
            if raw:
                break
        if raw:
            break
    else:
        if last_exc:
            raise last_exc
        raise RuntimeError("SCP API请求失败: 未知错误")

    try:
        data = json.loads(raw)
    except Exception as exc:
        raise RuntimeError(f"SCP API返回非JSON: {raw[:300]}") from exc

    if isinstance(data, list):
        return data

    status = str(data.get("status") or "").lower()
    if status and status != "success":
        long_msg = data.get("longmessage") or data.get("message") or raw[:300]
        raise RuntimeError(f"SCP API调用失败[{action}]: {long_msg}")
    return data.get("responsedata") or {}


def scp_api_login(account_row):
    login_variants = [
        {"username": account_row["username"], "password": account_row["password"]},
        {"loginName": account_row["username"], "password": account_row["password"]},
        {"customernumber": account_row["username"], "password": account_row["password"]},
    ]

    last_exc = None
    for login_payload in login_variants:
        try:
            resp = scp_api_call(account_row, "login", login_payload)
            if isinstance(resp, dict):
                session_id = resp.get("apisessionid") or resp.get("sessionid") or resp.get("session_id")
                if session_id:
                    return session_id
        except Exception as exc:
            last_exc = exc
            continue

    if last_exc:
        raise RuntimeError(f"SCP API登录失败: {last_exc}")
    raise RuntimeError("SCP API登录成功但未返回session id")


def scp_reinstall_debian11(server_row, output_lines):
    account = get_scp_account(server_row.get("scp_account_id"))
    scp_server_id = (server_row.get("scp_server_id") or "").strip()

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
<<<<<<< codex/analyze-reset-task-error-21swky
        payload_variants = []
        if flavour_id:
            payload_variants.append({"imageFlavourId": int(flavour_id) if str(flavour_id).isdigit() else flavour_id})
        if image_id:
            payload_variants.append({"imageId": int(image_id) if str(image_id).isdigit() else image_id})
        if not payload_variants:
            raise RuntimeError("未找到 Debian11 可用 imageFlavourId，无法按SCP文档接口执行重装")

        output_lines.append("SCP REST将按文档接口执行: POST /servers/{serverId}/image + imageFlavourId/imageId")
        for path in (f"servers/{scp_server_id}/image",):
=======
        payload_variants = [
            {
                "hostname": server_row["name"],
                "rootPassword": server_row["ssh_password"],
                "password": server_row["ssh_password"],
                "distribution": "debian",
                "version": "11",
                "os": "debian11",
                "image": "debian-11",
            }
        ]
        if flavour_id or image_id:
            preferred_payloads = []
            if flavour_id:
                preferred_payloads.append({"imageFlavourId": int(flavour_id) if str(flavour_id).isdigit() else flavour_id})
            if image_id:
                preferred_payloads.append({"imageId": int(image_id) if str(image_id).isdigit() else image_id})
            payload_variants = [
                {
                    "hostname": server_row["name"],
                    "rootPassword": server_row["ssh_password"],
                    "password": server_row["ssh_password"],
                    **extra,
                }
                for extra in preferred_payloads
            ] + payload_variants
            payload_variants.extend(
                [
                    {"hostname": server_row["name"], "rootPassword": server_row["ssh_password"], "imageFlavourId": flavour_id},
                    {"hostname": server_row["name"], "rootPassword": server_row["ssh_password"], "imageId": image_id},
                    {"hostname": server_row["name"], "rootPassword": server_row["ssh_password"], "image": {"id": image_id}},
                    {"hostname": server_row["name"], "rootPassword": server_row["ssh_password"], "image": {"id": image_id, "name": image_pick.get("image_name")}},
                ]
            )
            payload_variants = [x for x in payload_variants if not ("imageFlavourId" in x and not x.get("imageFlavourId"))]
            payload_variants = [x for x in payload_variants if not ("imageId" in x and not x.get("imageId"))]
            filtered_variants = []
            for payload in payload_variants:
                if "image" not in payload:
                    filtered_variants.append(payload)
                    continue
                image_field = payload.get("image")
                if isinstance(image_field, dict):
                    if image_field.get("id"):
                        filtered_variants.append(payload)
                    continue
                if isinstance(image_field, str):
                    if image_field.strip():
                        filtered_variants.append(payload)
                    continue
            payload_variants = filtered_variants

        for path in (f"servers/{scp_server_id}/image", f"servers/{scp_server_id}/reinstall", f"servers/{scp_server_id}/os", f"vservers/{scp_server_id}/reinstall"):
>>>>>>> main
            try:
                for payload in payload_variants:
                    result = scp_rest_request(account, "POST", path, token=token, payload=payload, endpoint_base=endpoint_base)
                    request_id = "-"
                    task_uuid = _scp_extract_task_uuid(result)
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
                        _scp_wait_task_finished(account, task_uuid, output_lines)
                    output_lines.append(f"SCP REST重装请求已提交: request_id={request_id}, server_id={scp_server_id}, os=debian11, path={path}")
                    return
            except Exception as exc:
                output_lines.append(f"SCP REST重装调用失败 path={path}: {exc}")
                continue
        output_lines.append("SCP REST重装接口未命中，转SOAP/JSON尝试")
    except Exception as rest_exc:
        output_lines.append(f"SCP REST重装提交失败，转SOAP/JSON尝试: {rest_exc}")

    soap_errors = []
    for method in ["reinstallVServer", "setVServerOs", "setVServerOS"]:
        for payload in [
            {"loginName": account["username"], "password": account["password"], "vservername": scp_server_id, "distribution": "debian", "version": "11", "language": "en", "hostname": server_row["name"], "newRootPassword": server_row["ssh_password"]},
            {"loginName": account["username"], "password": account["password"], "vservername": scp_server_id, "distribution": "debian", "version": "11", "language": "en", "hostname": server_row["name"], "password": server_row["ssh_password"]},
        ]:
            try:
                ret = scp_soap_call(account, method, payload)
                output_lines.append(f"SCP SOAP重装请求已提交: method={method}, server_id={scp_server_id}, return={ret[:1] if ret else ['OK']}")
                return
            except Exception as exc:
                soap_errors.append(str(exc))

    output_lines.append(f"SCP SOAP重装提交失败，转JSON尝试: {' | '.join(soap_errors[-2:])}")

    session_id = scp_api_login(account)
    output_lines.append(f"SCP API登录成功: 账号[{account['name']}] 会话已建立")

    payload_variants = [
        {
            "session_id": session_id,
            "vserverid": scp_server_id,
            "distribution": "debian",
            "version": "11",
            "language": "en",
            "hostname": server_row["name"],
            "password": server_row["ssh_password"],
        },
        {
            "sessionid": session_id,
            "vserverid": scp_server_id,
            "distribution": "debian",
            "version": "11",
            "language": "en",
            "hostname": server_row["name"],
            "password": server_row["ssh_password"],
        },
        {
            "session_id": session_id,
            "vservername": scp_server_id,
            "distribution": "debian",
            "version": "11",
            "language": "en",
            "hostname": server_row["name"],
            "password": server_row["ssh_password"],
        },
    ]

    actions = ["setVServerOs", "reinstallVServer", "setVServerOS"]
    result = None
    last_exc = None
    for action in actions:
        for payload in payload_variants:
            try:
                result = scp_api_call(account, action, payload)
                break
            except Exception as exc:
                last_exc = exc
                continue
        if result is not None:
            break

    if result is None:
        raise RuntimeError(f"SCP重装提交失败: {last_exc}; SOAP优先与JSON回退均失败")

    request_id = result.get("requestid") if isinstance(result, dict) else None
    request_id = request_id or (result.get("jobid") if isinstance(result, dict) else None) or "-"
    output_lines.append(f"SCP JSON重装请求已提交: request_id={request_id}, server_id={scp_server_id}, os=debian11")


def get_global_config():
    with closing(get_conn()) as conn:
        conn.execute("INSERT OR IGNORE INTO global_config(id) VALUES (1)")
        row = conn.execute("SELECT * FROM global_config WHERE id=1").fetchone()
        conn.commit()
        return row


def update_global_config(reset_command, ssh_command_2, ssh_command_3, agent_install_command, panel_base_url, notify_email_enabled, smtp_host, smtp_port, smtp_user, smtp_password, smtp_from, notify_email_to, traffic_data_source, ssh_check_interval_minutes):
    with closing(get_conn()) as conn:
        conn.execute(
            """
            UPDATE global_config
            SET reset_command=?, ssh_command_2=?, ssh_command_3=?, agent_install_command=?, panel_base_url=?, notify_email_enabled=?, smtp_host=?, smtp_port=?, smtp_user=?, smtp_password=?, smtp_from=?, notify_email_to=?, traffic_data_source=?, ssh_check_interval_minutes=?, updated_at=?
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
                normalize_traffic_data_source(traffic_data_source),
                max(0, int(ssh_check_interval_minutes)),
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
            SELECT s.id, s.name, s.renter_name, s.ip, s.ssh_password, s.reset_day, s.reset_hour, s.reset_minute,
                   s.auto_reset, s.is_renewed, s.is_rented, s.sort_order,
                   s.period_upload_bytes, s.period_download_bytes, s.last_agent_report_at,
                   s.ssh_status, s.ssh_checked_at,
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

    if not isinstance(servers, list) or not isinstance(logs, list) or not isinstance(global_cfg, dict) or not isinstance(queued_tasks, list) or not isinstance(notification_batches, list) or not isinstance(notification_batch_items, list) or not isinstance(scp_accounts, list):
        raise ValueError("备份文件缺少必要字段")

    with closing(get_conn()) as conn:
        conn.execute("DELETE FROM job_logs")
        conn.execute("DELETE FROM servers")
        conn.execute("DELETE FROM global_config")
        conn.execute("DELETE FROM task_queue")
        conn.execute("DELETE FROM notification_batch_items")
        conn.execute("DELETE FROM notification_batches")
        conn.execute("DELETE FROM scp_accounts")

        conn.execute(
            """
            INSERT INTO global_config(id, reset_command, ssh_command_2, ssh_command_3, agent_install_command, panel_base_url, notify_email_enabled, smtp_host, smtp_port, smtp_user, smtp_password, smtp_from, notify_email_to, traffic_data_source, ssh_check_interval_minutes, panel_password_hash, updated_at)
            VALUES(1,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
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
                normalize_traffic_data_source(global_cfg.get("traffic_data_source", "agent")),
                int(global_cfg.get("ssh_check_interval_minutes", 120) or 120),
                global_cfg.get("panel_password_hash") or generate_password_hash("admin"),
                global_cfg.get("updated_at"),
            ),
        )

        for server in servers:
            conn.execute(
                """
                INSERT INTO servers(id, name, ip, ssh_port, ssh_user, ssh_password, reset_day, reset_hour, reset_minute, auto_reset, is_renewed, is_rented, renter_name, sort_order, max_retries, retry_backoff_seconds, scp_account_id, scp_server_id, reinstall_mode, agent_token, period_key, period_upload_bytes, period_download_bytes, last_agent_rx_bytes, last_agent_tx_bytes, last_agent_report_at, last_reset_at, ssh_status, ssh_checked_at)
                VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
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
                    (server.get("renter_name", "") or "").strip(),
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
    cfg = get_global_config()
    if normalize_traffic_data_source(cfg["traffic_data_source"] if cfg else "agent") != "ssh":
        return

    with closing(get_conn()) as conn:
        rows = conn.execute("SELECT * FROM servers ORDER BY sort_order ASC, id ASC").fetchall()
    for row in rows:
        try:
            refresh_server_traffic(row)
        except Exception:
            continue




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


def run_scheduled_ssh_checks(now_dt=None):
    cfg = get_global_config()
    interval = int(cfg["ssh_check_interval_minutes"] or 0) if cfg else 0
    if interval <= 0:
        return

    now_dt = now_dt or datetime.now(TIMEZONE)
    minutes_since_midnight = now_dt.hour * 60 + now_dt.minute
    if minutes_since_midnight % interval != 0:
        return

    with closing(get_conn()) as conn:
        rows = conn.execute("SELECT * FROM servers ORDER BY sort_order ASC, id ASC").fetchall()

    for row in rows:
        check_server_ssh_connectivity(row)

def should_reset(server_row):
    now = datetime.now(TIMEZONE)
    if not server_row["auto_reset"]:
        return False
    if server_row["is_renewed"]:
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
        f"{server_row['name']}（名称），{server_row['reset_day']}日 {int(server_row.get('reset_hour', 1)):02d}:{int(server_row.get('reset_minute', 0)):02d}（北京时间）重置，需要续租请提前下单",
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


def send_email_message(subject, body):
    smtp = get_smtp_config()
    if not smtp:
        return False

    msg = EmailMessage()
    msg["Subject"] = subject
    msg["From"] = smtp["from"]
    msg["To"] = smtp["to"]
    msg.set_content(body)

    with smtplib.SMTP(smtp["host"], smtp["port"], timeout=20) as server:
        server.starttls()
        if smtp["user"]:
            server.login(smtp["user"], smtp["password"])
        server.send_message(msg)
    return True


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
        lines.append(f"- {item['server_name']} ({item['server_ip']}): {item['status']}{note}")

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


def run_remote(server_row, running_log_id, notify_on_failure=True, notify_on_success=True, reset_command_override=None, force_reinstall=False, preset_password=None):
    title = f"[{server_row['name']} - {server_row['ip']}]"
    output_lines = [f"开始执行重置任务 {title}"]
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
            scp_reinstall_debian11(mutable_server, output_lines)
            output_lines.append("SCP重装命令已提交，等待后续重连")
            if client:
                client.close()
                client = None
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


def normalize_traffic_data_source(value):
    return "ssh" if str(value or "").strip().lower() == "ssh" else "agent"


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
            dd_password = None
            dd_command = None
            if dd_choice:
                dd_password = generate_root_password()
                dd_command = build_bin_reinstall_command(dd_choice, dd_password)
            run_remote(
                row,
                task["log_id"],
                notify_on_failure=(attempt_no >= max_attempts and not task["batch_key"]),
                notify_on_success=(not task["batch_key"]),
                reset_command_override=dd_command,
                force_reinstall=bool(dd_choice),
                preset_password=dd_password,
            )

            with closing(get_conn()) as conn:
                latest = conn.execute("SELECT status, output FROM job_logs WHERE id = ?", (task["log_id"],)).fetchone()

            if latest and latest["status"] == "success":
                with closing(get_conn()) as conn:
                    conn.execute(
                        "UPDATE task_queue SET status='success', attempt=?, updated_at=? WHERE id=?",
                        (attempt_no, datetime.now(TIMEZONE).strftime("%Y-%m-%d %H:%M:%S"), task_id),
                    )
                    conn.commit()
                if task["batch_key"]:
                    upsert_notification_batch_item(task["batch_key"], row, "success", note="任务执行完成", log_id=task["log_id"])
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


def check_scheduled_jobs():
    now = datetime.now(TIMEZONE)
    run_scheduled_ssh_checks(now)
    batch_key = now.strftime("%Y-%m-%d %H:%M")
    scheduled_for = now.strftime("%Y-%m-%d %H:%M:%S")

    with closing(get_conn()) as conn:
        rows = conn.execute("SELECT * FROM servers ORDER BY sort_order ASC, id ASC").fetchall()

    due_rows = [row for row in rows if row["auto_reset"] and row["reset_day"] == now.day and int(row["reset_hour"] or 1) == now.hour and int(row["reset_minute"] or 0) == now.minute]
    if not due_rows:
        return

    ensure_notification_batch(batch_key, scheduled_for)

    for row in due_rows:
        if row["is_renewed"]:
            upsert_notification_batch_item(batch_key, row, "skipped", note="续租中，已跳过定时重置")
            continue

        if not should_reset(row):
            upsert_notification_batch_item(batch_key, row, "skipped", note="未开启定时自动执行或不在预定时间")
            continue

        ok, msg, log_id = run_for_server(row["id"], trigger_type="scheduled", batch_key=batch_key)
        if not ok:
            upsert_notification_batch_item(batch_key, row, "skipped", note=msg, log_id=log_id)

    maybe_send_batch_email(batch_key)


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
    )


@app.route("/settings")
@login_required
def settings_page():
    return render_template(
        "settings.html",
        servers=list_servers(),
        logs_grouped=list_logs_grouped_by_server(),
        global_cfg=get_global_config(),
        scp_accounts=list_scp_accounts(),
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

    cfg = get_global_config()
    if normalize_traffic_data_source(cfg["traffic_data_source"] if cfg else "agent") != "agent":
        return jsonify({"ok": True, "ignored": True, "reason": "traffic source is ssh"})

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


@app.route("/scp-accounts", methods=["POST"])
@login_required
def add_scp_account():
    form = request.form
    name = (form.get("name") or "").strip()
    username = (form.get("username") or "").strip()
    password = form.get("password") or ""
    refresh_token = (form.get("refresh_token") or "").strip()
    api_endpoint = (form.get("api_endpoint") or "").strip() or "https://www.servercontrolpanel.de/scp-core/api/v1"
    if not name or not username:
        flash("新增SCP账号失败: 名称/账号均为必填", "error")
        return redirect(url_for("settings_page"))
    if not password and not refresh_token:
        flash("新增SCP账号失败: SCP密码 与 OIDC Refresh Token 至少填写一个", "error")
        return redirect(url_for("settings_page"))

    now_text = datetime.now(TIMEZONE).strftime("%Y-%m-%d %H:%M:%S")
    with closing(get_conn()) as conn:
        conn.execute(
            "INSERT INTO scp_accounts(name, username, password, refresh_token, api_endpoint, created_at, updated_at) VALUES(?,?,?,?,?,?,?)",
            (name, username, password, refresh_token, api_endpoint, now_text, now_text),
        )
        conn.commit()

    flash("SCP账号已添加", "success")
    return redirect(url_for("settings_page"))


@app.route("/scp-accounts/<int:account_id>/delete", methods=["POST"])
@login_required
def delete_scp_account(account_id):
    with closing(get_conn()) as conn:
        conn.execute("UPDATE servers SET scp_account_id = NULL, scp_server_id = '' WHERE scp_account_id = ?", (account_id,))
        conn.execute("DELETE FROM scp_accounts WHERE id = ?", (account_id,))
        conn.commit()

    flash("SCP账号已删除，相关服务器绑定已清空", "success")
    return redirect(url_for("settings_page"))


@app.route("/global-tasks", methods=["POST"])
@login_required
def update_global_tasks():
    form = request.form
    try:
        smtp_port = parse_int_form_field(form, "smtp_port", default=587, min_value=1, max_value=65535)
        ssh_check_interval_minutes = parse_int_form_field(form, "ssh_check_interval_minutes", default=120, min_value=0, max_value=1440)
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
        form.get("traffic_data_source", "agent"),
        ssh_check_interval_minutes,
    )
    flash("全局任务配置已更新", "success")
    return redirect(url_for("settings_page"))


@app.route("/notify/test", methods=["POST"])
@login_required
def test_notify_email():
    try:
        ok = send_email_message(
            "[VPS面板] 邮件通知测试",
            (
                "这是一封来自 VPS 管理面板的测试邮件。\n"
                f"发送时间: {datetime.now(TIMEZONE).strftime('%Y-%m-%d %H:%M:%S')}\n"
                "若你收到本邮件，说明 SMTP 配置可用。"
            ),
        )
        if ok:
            flash("测试邮件已发送，请检查收件箱", "success")
        else:
            flash("测试邮件未发送：请先开启邮件通知并完整填写 SMTP 配置", "error")
    except Exception as exc:
        flash(f"测试邮件发送失败: {exc}", "error")
    return redirect(url_for("settings_page"))


def get_next_sort_order(conn):
    row = conn.execute("SELECT COALESCE(MAX(sort_order), 0) AS max_order FROM servers").fetchone()
    return int(row["max_order"]) + 1


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
            INSERT INTO servers(name, ip, ssh_port, ssh_user, ssh_password, reset_day, reset_hour, reset_minute, auto_reset, is_renewed, is_rented, renter_name, sort_order, max_retries, retry_backoff_seconds, scp_account_id, scp_server_id, reinstall_mode, agent_token, period_key, period_upload_bytes, period_download_bytes, last_agent_rx_bytes, last_agent_tx_bytes, last_agent_report_at)
            VALUES(?,?,?,?,?,?,?,?,?,0,0,?,?,?,?,?,?,?,?,?,?,?,?,?)
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
                sort_order,
                max_retries,
                normalize_backoff_plan_text(form.get("retry_backoff_seconds") or DEFAULT_RETRY_BACKOFF_SECONDS),
                scp_account_id,
                (form.get("scp_server_id") or "").strip(),
                reinstall_mode,
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
    try:
        ssh_port = parse_int_form_field(form, "ssh_port", default=22, min_value=1, max_value=65535)
        reset_day = parse_int_form_field(form, "reset_day", min_value=1, max_value=31)
        reset_hour = parse_int_form_field(form, "reset_hour", default=1, min_value=0, max_value=23)
        reset_minute = parse_int_form_field(form, "reset_minute", default=0, min_value=0, max_value=59)
        sort_order = parse_int_form_field(form, "sort_order", default=0)
        max_retries = parse_int_form_field(form, "max_retries", default=DEFAULT_MAX_RETRIES, min_value=1, max_value=10)
        scp_account_id_raw = (form.get("scp_account_id") or "").strip()
        scp_account_id = int(scp_account_id_raw) if scp_account_id_raw.isdigit() else None
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
            SET name=?, ip=?, ssh_port=?, ssh_user=?, ssh_password=?, reset_day=?, reset_hour=?, reset_minute=?, auto_reset=?, renter_name=?, sort_order=?, max_retries=?, retry_backoff_seconds=?, scp_account_id=?, scp_server_id=?, reinstall_mode=?
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
    with closing(get_conn()) as conn:
        row = conn.execute("SELECT id FROM servers WHERE id = ?", (server_id,)).fetchone()
        if not row:
            flash("服务器不存在", "error")
            return redirect(url_for("details_page"))
        conn.execute("UPDATE servers SET renter_name = ? WHERE id = ?", (renter_name, server_id))
        conn.commit()
    flash("租赁人已更新" if renter_name else "已清空租赁人", "success")
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


def start_scheduler():
    scheduler = BackgroundScheduler(timezone=TIMEZONE)
    scheduler.add_job(check_scheduled_jobs, "cron", minute="*")
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
