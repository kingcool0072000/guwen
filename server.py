"""诗文通关后端服务（FastAPI）。

本地启动（在 guwen/ 目录下）：
    .venv/bin/python -m uvicorn server:app --port 8765
或  .venv/bin/python server.py        # 端口取环境变量 GUWEN_PORT，默认 8765

线上由反向代理挂在 /guwen 前缀下。应用内不写死前缀：
- API 路由都在应用根路径下（/api/...），静态以相对方式挂根（html=True 挂 "/"）
- 代理侧二选一：strip /guwen 后转发；或不剥前缀、uvicorn --root-path /guwen
  （python server.py 方式用环境变量 GUWEN_ROOT_PATH 等效设置）
前端页面里的静态资源引用用相对路径（前端的责任），前后端即可两边通吃。

接口契约：
- POST /api/login   {user, password} → {token, user, role}；错 401
- GET  /api/me      → {user, role, exp}
- GET  /api/progress        → 库内快照原样（从未存过返回 {}）
- PUT  /api/progress        整包快照 ≤256KB（超 413）；body.rev >= 库内 rev 才接受，
                            否则 409 {detail:"stale", server_snapshot: 库内快照}
- POST /api/log     {events:[...]} ≤1000 条/次 → {ok, accepted}；追加按月 JSONL
- GET  /api/works   → {count, works}；读 web/works.json，缺失/损坏返回空不报错
除 /api/login 和静态文件外都要 Authorization: Bearer <token>，无效 401 unauthorized。
"""
from __future__ import annotations

import json
import os
from contextlib import asynccontextmanager
from datetime import datetime
from pathlib import Path

from fastapi import Depends, FastAPI, HTTPException, Request
from fastapi.responses import JSONResponse
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel

import auth
import learnlog
import progress
from auth import read_token

MAX_SNAPSHOT_BYTES = 256 * 1024      # PUT /api/progress 体积上限
MAX_EVENTS_PER_REQUEST = 1000        # POST /api/log 单次条数上限

WEB_DIR = Path(__file__).resolve().parent / "web"

_store = auth.UserStore()


@asynccontextmanager
async def lifespan(_app: FastAPI):
    auth.data_dir().mkdir(parents=True, exist_ok=True)
    (auth.data_dir() / "logs").mkdir(parents=True, exist_ok=True)
    print("guwen listening", flush=True)
    yield


app = FastAPI(title="guwen", lifespan=lifespan)

_bearer = HTTPBearer(auto_error=False)


def current_user(cred: HTTPAuthorizationCredentials | None = Depends(_bearer)) -> dict:
    """校验 Authorization: Bearer <token>，无效一律 401 unauthorized。"""
    payload = read_token(cred.credentials) if cred is not None else None
    if not payload:
        raise HTTPException(status_code=401, detail="unauthorized")
    return payload


class LoginBody(BaseModel):
    user: str
    password: str


class LogBody(BaseModel):
    events: list[dict]


@app.post("/api/login")
def api_login(body: LoginBody):
    role = _store.verify(body.user or "", body.password or "")
    if not role:
        raise HTTPException(status_code=401, detail="用户名或密码错误")
    return {"token": auth.make_token(body.user, role), "user": body.user, "role": role}


@app.get("/api/me")
def api_me(user: dict = Depends(current_user)):
    return {"user": user.get("user"), "role": user.get("role"), "exp": user.get("exp")}


@app.get("/api/progress")
def api_get_progress(user: dict = Depends(current_user)):
    row = progress.get_progress(user["user"])
    return row["snapshot"] if row and row["snapshot"] is not None else {}


@app.put("/api/progress")
async def api_put_progress(request: Request, user: dict = Depends(current_user)):
    # async 读原始 body 才能按字节数卡 256KB 上限
    raw = await request.body()
    if len(raw) > MAX_SNAPSHOT_BYTES:
        raise HTTPException(status_code=413, detail="snapshot too large")
    try:
        snap = json.loads(raw)
    except Exception:
        raise HTTPException(status_code=400, detail="invalid json")
    if not isinstance(snap, dict):
        raise HTTPException(status_code=400, detail="snapshot must be an object")
    try:
        rev = int(snap.get("rev") or 0)
    except (TypeError, ValueError):
        rev = 0
    result = progress.save_progress(user["user"], snap, rev)
    if not result["ok"]:
        return JSONResponse(
            status_code=409,
            content={"detail": "stale", "server_snapshot": result["server_snapshot"]},
        )
    return {"ok": True, "saved_at": result["saved_at"]}


@app.post("/api/log")
def api_log(body: LogBody, user: dict = Depends(current_user)):
    if len(body.events) > MAX_EVENTS_PER_REQUEST:
        raise HTTPException(status_code=400, detail="too many events")
    accepted = learnlog.append(user["user"], body.events)
    if accepted:
        day = datetime.now().astimezone().strftime("%Y-%m-%d")
        progress.bump_event_count(user["user"], day, accepted)
    return {"ok": True, "accepted": accepted}


@app.get("/api/works")
def api_works(user: dict = Depends(current_user)):
    """题目数据：web/works.json（前端生成），缺失/损坏返回空，不报错。"""
    try:
        data = json.loads((WEB_DIR / "works.json").read_text(encoding="utf-8"))
    except Exception:
        return {"count": 0, "works": []}
    if isinstance(data, dict) and isinstance(data.get("works"), list):
        items = data["works"]
    elif isinstance(data, list):
        items = data
    else:
        items = []
    return {"count": len(items), "works": items}


# 静态文件相对挂根（html=True 让 / 直接出 index.html）；API 路由在上面，
# 挂载放最后兜底。应用整体可挂任意前缀代理，代码里无 /guwen 字样。
app.mount("/", StaticFiles(directory=WEB_DIR, html=True), name="web")


if __name__ == "__main__":
    import uvicorn

    uvicorn.run(
        app,
        host=os.environ.get("GUWEN_HOST", "0.0.0.0"),
        port=int(os.environ.get("GUWEN_PORT", "8765")),
        root_path=os.environ.get("GUWEN_ROOT_PATH", ""),
    )
