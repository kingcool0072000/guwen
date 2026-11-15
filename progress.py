"""学习进度存储：SQLite。

- 表 progress(user, rev, snapshot, updated_at)：每用户一行 upsert，
  snapshot 是前端整包快照的 JSON 文本（后端不解释内部结构）
- 表 event_count(user, day, n)：按天累计 /api/log 事件数，备日后统计
- 连接每请求新建；写操作用模块级 threading.Lock 串行化
  （sync 路由跑在线程池里，async 路由跑在事件循环里，锁保证互斥）
"""
from __future__ import annotations

import json
import sqlite3
import threading
from datetime import datetime

from auth import data_dir

_lock = threading.Lock()

_SCHEMA = """
CREATE TABLE IF NOT EXISTS progress (
    user       TEXT PRIMARY KEY,
    rev        INTEGER,
    snapshot   TEXT,
    updated_at TEXT
);
CREATE TABLE IF NOT EXISTS event_count (
    user TEXT,
    day  TEXT,
    n    INTEGER,
    PRIMARY KEY (user, day)
);
"""


def _now_iso() -> str:
    return datetime.now().astimezone().isoformat(timespec="seconds")


def _connect() -> sqlite3.Connection:
    path = data_dir() / "guwen.db"
    path.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(path)
    conn.executescript(_SCHEMA)
    return conn


def get_progress(user: str) -> dict | None:
    """返回 {"rev", "snapshot", "updated_at"}；该用户从未保存过则 None。"""
    with _lock:
        conn = _connect()
        try:
            row = conn.execute(
                "SELECT rev, snapshot, updated_at FROM progress WHERE user = ?", (user,)
            ).fetchone()
        finally:
            conn.close()
    if not row:
        return None
    try:
        snapshot = json.loads(row[1])
    except Exception:
        snapshot = None
    return {"rev": row[0], "snapshot": snapshot, "updated_at": row[2]}


def save_progress(user: str, snapshot: dict, rev: int) -> dict:
    """带 rev 冲突检查的单行 upsert（检查 + 写入在同一把锁内，原子）。

    - body.rev >= 库内 rev：接受，覆盖保存，返回 {"ok": True, "saved_at": iso}
    - body.rev <  库内 rev：拒绝，返回 {"ok": False, "server_snapshot": 库内快照}，
      客户端拿 server_snapshot 合并后加 rev 重试
    """
    now = _now_iso()
    with _lock:
        conn = _connect()
        try:
            row = conn.execute(
                "SELECT rev, snapshot FROM progress WHERE user = ?", (user,)
            ).fetchone()
            server_rev = row[0] if row else 0
            if rev < server_rev:
                try:
                    server_snapshot = json.loads(row[1]) if row else None
                except Exception:
                    server_snapshot = None
                return {"ok": False, "server_snapshot": server_snapshot}
            conn.execute(
                "INSERT INTO progress (user, rev, snapshot, updated_at) VALUES (?, ?, ?, ?) "
                "ON CONFLICT(user) DO UPDATE SET "
                "rev = excluded.rev, snapshot = excluded.snapshot, updated_at = excluded.updated_at",
                (user, rev, json.dumps(snapshot, ensure_ascii=False), now),
            )
            conn.commit()
        finally:
            conn.close()
    return {"ok": True, "saved_at": now}


def bump_event_count(user: str, day: str, n: int) -> None:
    """按天累计事件数（/api/log 每次请求调用一次，n 为该批条数）。"""
    if n <= 0:
        return
    with _lock:
        conn = _connect()
        try:
            conn.execute(
                "INSERT INTO event_count (user, day, n) VALUES (?, ?, ?) "
                "ON CONFLICT(user, day) DO UPDATE SET n = n + excluded.n",
                (user, day, n),
            )
            conn.commit()
        finally:
            conn.close()
