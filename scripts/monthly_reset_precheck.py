#!/usr/bin/env python3
"""Preflight checks for monthly scheduled resets.

Usage example:
  python3 scripts/monthly_reset_precheck.py --db /opt/vps-panel/panel.db --target "2026-03-13 01:00"
"""

from __future__ import annotations

import argparse
import sqlite3
from contextlib import closing
from datetime import datetime
from calendar import monthrange


def parse_target(value: str | None) -> datetime:
    if not value:
        return datetime.now().replace(second=0, microsecond=0)
    for fmt in ("%Y-%m-%d %H:%M", "%Y-%m-%d %H:%M:%S"):
        try:
            return datetime.strptime(value, fmt)
        except ValueError:
            continue
    raise SystemExit("--target 格式错误，支持: YYYY-MM-DD HH:MM 或 YYYY-MM-DD HH:MM:SS")


def one_month_before(day: datetime) -> datetime:
    year = day.year
    month = day.month - 1
    if month == 0:
        month = 12
        year -= 1
    dom = min(day.day, monthrange(year, month)[1])
    return day.replace(year=year, month=month, day=dom)


def parse_date_text(text: str) -> datetime | None:
    t = (text or "").strip()
    if not t:
        return None
    for fmt in ("%Y-%m-%d", "%Y-%m-%d %H:%M:%S"):
        try:
            return datetime.strptime(t, fmt)
        except ValueError:
            continue
    return None


def db_lock_check(db_path: str) -> tuple[bool, str]:
    try:
        conn = sqlite3.connect(db_path, timeout=1)
        with closing(conn):
            conn.execute("PRAGMA busy_timeout=1000")
            conn.execute("BEGIN IMMEDIATE")
            conn.execute("ROLLBACK")
        return True, "可获取写锁（BEGIN IMMEDIATE 成功）"
    except sqlite3.OperationalError as exc:
        return False, f"写锁检查失败: {exc}"


def get_global_config(conn: sqlite3.Connection) -> dict:
    cols = {r[1] for r in conn.execute("PRAGMA table_info(global_config)")}
    if not cols:
        return {}
    row = conn.execute("SELECT * FROM global_config WHERE id=1").fetchone()
    if not row:
        return {}
    return {k: row[k] for k in row.keys()}


def describe_due_server(row: sqlite3.Row, target: datetime) -> str:
    renew_until = parse_date_text(row["renew_until_date"])
    is_renewed = int(row["is_renewed"] or 0)

    if renew_until and target.date() < renew_until.date():
        one_month = one_month_before(renew_until)
        if is_renewed and target.date() >= one_month.date():
            return f"长期续费保护期内（续费至{renew_until.date()}），本轮会先自动切未续租，再跳过重置"
        return f"长期续费保护期内（续费至{renew_until.date()}），本轮会跳过重置"

    if is_renewed:
        return "续租中，本轮会跳过重置并自动切为未续租"

    return "会执行定时重置"


def main() -> None:
    parser = argparse.ArgumentParser(description="每月重置前自检脚本")
    parser.add_argument("--db", default="/opt/vps-panel/panel.db", help="panel.db 路径")
    parser.add_argument("--target", default=None, help="待检查时间点，如 2026-03-13 01:00")
    args = parser.parse_args()

    target = parse_target(args.target)

    print("=" * 70)
    print(f"[自检时间点] {target}")
    print(f"[数据库路径] {args.db}")
    print("=" * 70)

    ok, lock_msg = db_lock_check(args.db)
    print("[DB写锁状态]", "正常" if ok else "异常")
    print("  -", lock_msg)

    with closing(sqlite3.connect(args.db)) as conn:
        conn.row_factory = sqlite3.Row
        journal_mode = conn.execute("PRAGMA journal_mode").fetchone()[0]
        busy_timeout = conn.execute("PRAGMA busy_timeout").fetchone()[0]
        print(f"[SQLite参数] journal_mode={journal_mode}, busy_timeout={busy_timeout}ms")

        cfg = get_global_config(conn)
        print("\n[邮件配置状态]")
        notify_enabled = int(cfg.get("notify_email_enabled", 0) or 0)
        smtp_ready = all((cfg.get("smtp_host"), cfg.get("smtp_user"), cfg.get("smtp_from")))
        notify_to = (cfg.get("notify_email_to") or "").strip()
        print(f"  - 任务通知开关: {'开启' if notify_enabled else '关闭'}")
        print(f"  - SMTP参数完整: {'是' if smtp_ready else '否'}")
        print(f"  - 通知收件人: {notify_to or '未设置'}")

        backup_enabled = int(cfg.get("backup_email_enabled", 0) or 0)
        backup_to = (cfg.get("backup_email_to") or "").strip()
        print(f"  - 备份邮件开关: {'开启' if backup_enabled else '关闭'}")
        print(f"  - 备份收件人: {backup_to or '未设置'}")

        rows = conn.execute(
            """
            SELECT id,name,ip,auto_reset,reset_day,reset_hour,reset_minute,is_renewed,renew_until_date,is_rented
            FROM servers
            WHERE auto_reset=1
              AND reset_day=?
              AND reset_hour=?
              AND reset_minute=?
            ORDER BY sort_order ASC, id ASC
            """,
            (target.day, target.hour, target.minute),
        ).fetchall()

        print("\n[本轮应触发服务器清单]")
        print(f"  - 命中数量: {len(rows)}")
        for r in rows:
            action = describe_due_server(r, target)
            print(
                f"  - id={r['id']} name={r['name']} ip={r['ip']} "
                f"is_rented={r['is_rented']} is_renewed={r['is_renewed']} renew_until={r['renew_until_date'] or '-'}"
            )
            print(f"      预期动作: {action}")

        if not rows:
            print("  - 当前时间点无待处理服务器（这是正常结果之一）")

    print("\n[建议] 若 DB写锁状态异常，请先排查 journalctl 中 sqlite3 'database is locked' 错误。")


if __name__ == "__main__":
    main()
