"""学习日志：append-only JSONL，按月分文件。

- 文件：``data/logs/learn-YYYYMM.log``（按写入当月命名，UTF-8）
- 每行一条事件，字段：服务端时间 ts、用户 user、客户端毫秒时间戳 client_t、
  事件类型 type，以及事件里其余字段原样平铺
- 单进程 uvicorn --workers 1，append 模式追加写即可，无需文件锁
"""
from __future__ import annotations

import json
from collections import deque
from datetime import datetime
from pathlib import Path

from auth import data_dir


def log_path(now: datetime | None = None) -> Path:
    """当月日志文件路径。"""
    now = now or datetime.now().astimezone()
    return data_dir() / "logs" / f"learn-{now:%Y%m}.log"


def append(user: str, events: list[dict]) -> int:
    """把一批事件追加写入当月日志，返回写入条数。

    每行结构：服务端计算 ts/user，事件里的 t 映射为 client_t、type 保留，
    其余字段平铺；服务端字段后写，保证不被事件里的同名字段覆盖。
    """
    now = datetime.now().astimezone()
    ts = now.isoformat(timespec="seconds")
    lines = []
    for ev in events:
        rec = {k: v for k, v in ev.items() if k not in ("t", "type")}
        rec.update({
            "ts": ts,
            "user": user,
            "client_t": ev.get("t"),
            "type": ev.get("type"),
        })
        lines.append(json.dumps(rec, ensure_ascii=False))
    path = log_path(now)
    path.parent.mkdir(parents=True, exist_ok=True)
    with open(path, "a", encoding="utf-8") as f:
        for line in lines:
            f.write(line + "\n")
    return len(lines)


def tail(n: int, user: str | None = None) -> list[dict]:
    """读最近 n 行日志（可选按 user 过滤），从新到旧跨月文件拼齐。

    只给排障/查重用，不暴露成 API。
    """
    logs_dir = data_dir() / "logs"
    files = sorted(logs_dir.glob("learn-*.log"), reverse=True)
    out: list[dict] = []
    for p in files:
        buf: deque = deque(maxlen=max(n, 1))
        try:
            with open(p, encoding="utf-8") as f:
                for line in f:
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        rec = json.loads(line)
                    except Exception:
                        continue  # 半行/坏行跳过
                    if user and rec.get("user") != user:
                        continue
                    buf.append(rec)
        except OSError:
            continue
        if buf:
            out = list(buf) + out
        if len(out) >= n:
            break
    return out[-n:] if n > 0 else []
