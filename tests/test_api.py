"""诗文通关后端接口测试。

运行（guwen/ 目录下）：
    .venv/bin/python -m pytest tests/ -v

用 TestClient + monkeypatch 把 GUWEN_DATA_DIR 指到各自 tmp_path，
测试之间数据目录、签名密钥完全隔离。
"""
import json
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from fastapi.testclient import TestClient  # noqa: E402


@pytest.fixture()
def data_dir(tmp_path, monkeypatch):
    d = tmp_path / "data"
    monkeypatch.setenv("GUWEN_DATA_DIR", str(d))
    import auth
    auth._reset_secret_cache()
    return d


@pytest.fixture()
def client(data_dir):
    from server import app
    with TestClient(app) as c:
        yield c


def _login(client):
    r = client.post("/api/login", json={"user": "__REDACTED__", "password": "__REDACTED__"})
    assert r.status_code == 200
    return r.json()


def _auth(token):
    return {"Authorization": f"Bearer {token}"}


# ---------- 登录 / token ----------

def test_login_success(client):
    body = _login(client)
    assert body["user"] == "__REDACTED__"
    assert body["role"] == "student"
    assert body["token"]


def test_login_wrong_password(client):
    r = client.post("/api/login", json={"user": "__REDACTED__", "password": "wrong"})
    assert r.status_code == 401
    assert r.json() == {"detail": "用户名或密码错误"}


def test_login_unknown_user(client):
    r = client.post("/api/login", json={"user": "nobody", "password": "whatever"})
    assert r.status_code == 401
    assert r.json() == {"detail": "用户名或密码错误"}


def test_me_without_token_unauthorized(client):
    r = client.get("/api/me")
    assert r.status_code == 401
    assert r.json() == {"detail": "unauthorized"}


def test_me_with_bad_token_unauthorized(client):
    r = client.get("/api/me", headers={"Authorization": "Bearer bogus.token"})
    assert r.status_code == 401
    assert r.json() == {"detail": "unauthorized"}


def test_me_ok(client):
    token = _login(client)["token"]
    r = client.get("/api/me", headers=_auth(token))
    assert r.status_code == 200
    body = r.json()
    assert body["user"] == "__REDACTED__"
    assert body["role"] == "student"
    assert body["exp"] > 0


# ---------- 学习进度 ----------

def test_progress_roundtrip(client):
    token = _login(client)["token"]
    h = _auth(token)
    snap = {"stats": {"total": 3}, "wrong": [1], "days": ["2026-11-15"],
            "mastered": [2], "daily": {"2026-11-15": 5}, "rev": 1}
    r = client.put("/api/progress", json=snap, headers=h)
    assert r.status_code == 200
    body = r.json()
    assert body["ok"] is True
    assert body["saved_at"]
    r = client.get("/api/progress", headers=h)
    assert r.status_code == 200
    assert r.json() == snap


def test_progress_empty_then_get(client):
    token = _login(client)["token"]
    r = client.get("/api/progress", headers=_auth(token))
    assert r.status_code == 200
    assert r.json() == {}


def test_progress_stale_conflict_409(client):
    token = _login(client)["token"]
    h = _auth(token)
    assert client.put("/api/progress", json={"rev": 5, "stats": {"a": 1}}, headers=h).status_code == 200
    r = client.put("/api/progress", json={"rev": 3, "stats": {"a": 2}}, headers=h)
    assert r.status_code == 409
    body = r.json()
    assert body["detail"] == "stale"
    assert body["server_snapshot"]["rev"] == 5
    assert body["server_snapshot"]["stats"] == {"a": 1}
    # 客户端合并后以更高 rev 重试 → 成功
    merged = dict(body["server_snapshot"])
    merged["rev"] = 6
    assert client.put("/api/progress", json=merged, headers=h).status_code == 200
    assert client.get("/api/progress", headers=h).json()["rev"] == 6


def test_progress_equal_rev_overwrites(client):
    token = _login(client)["token"]
    h = _auth(token)
    assert client.put("/api/progress", json={"rev": 2, "stats": {}}, headers=h).status_code == 200
    assert client.put("/api/progress", json={"rev": 2, "stats": {"v": 9}}, headers=h).status_code == 200
    assert client.get("/api/progress", headers=h).json()["stats"] == {"v": 9}


def test_progress_too_large_413(client):
    token = _login(client)["token"]
    big = {"rev": 1, "pad": "x" * (256 * 1024 + 1)}
    r = client.put("/api/progress", json=big, headers=_auth(token))
    assert r.status_code == 413


# ---------- 学习日志 ----------

def test_log_written_jsonl(client, data_dir):
    token = _login(client)["token"]
    events = [
        {"t": 1731628800000, "type": "answer", "wid": "w1", "q": 3, "correct": True},
        {"t": 1731628801000, "type": "page", "page": "list"},
    ]
    r = client.post("/api/log", json={"events": events}, headers=_auth(token))
    assert r.status_code == 200
    assert r.json() == {"ok": True, "accepted": 2}
    files = list((data_dir / "logs").glob("learn-*.log"))
    assert len(files) == 1
    lines = files[0].read_text(encoding="utf-8").strip().splitlines()
    assert len(lines) == 2
    recs = [json.loads(x) for x in lines]  # 每行都是合法 JSON
    assert recs[0]["user"] == "__REDACTED__"
    assert recs[0]["client_t"] == 1731628800000
    assert recs[0]["type"] == "answer"
    assert recs[0]["wid"] == "w1"
    assert recs[0]["correct"] is True
    assert "ts" in recs[0]
    assert recs[1]["type"] == "page" and recs[1]["page"] == "list"


def test_log_too_many_events_rejected(client, data_dir):
    token = _login(client)["token"]
    events = [{"t": 1, "type": "page"}] * 1001
    r = client.post("/api/log", json={"events": events}, headers=_auth(token))
    assert r.status_code == 400
    assert not (data_dir / "logs").exists() or not list((data_dir / "logs").glob("learn-*.log"))


def test_log_requires_token(client):
    r = client.post("/api/log", json={"events": [{"t": 1, "type": "page"}]})
    assert r.status_code == 401


# ---------- 题目数据 ----------

def test_works_missing_file_ok(client, tmp_path, monkeypatch):
    # 指到空 tmp 目录，不依赖真实 web/（前端会放真实 works.json 进来）
    import server as server_mod
    web = tmp_path / "web_empty"
    web.mkdir()
    monkeypatch.setattr(server_mod, "WEB_DIR", web)
    token = _login(client)["token"]
    r = client.get("/api/works", headers=_auth(token))
    assert r.status_code == 200
    assert r.json() == {"count": 0, "works": []}


def test_works_from_json_array(client, tmp_path, monkeypatch):
    import server as server_mod
    web = tmp_path / "web"
    web.mkdir()
    (web / "works.json").write_text(json.dumps([
        {"id": "w1", "title": "静夜思"},
        {"id": "w2", "title": "春晓"},
    ], ensure_ascii=False), encoding="utf-8")
    monkeypatch.setattr(server_mod, "WEB_DIR", web)
    token = _login(client)["token"]
    r = client.get("/api/works", headers=_auth(token))
    assert r.status_code == 200
    body = r.json()
    assert body["count"] == 2
    assert body["works"][0]["title"] == "静夜思"
