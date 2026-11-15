"""登录认证：本地账号 + HMAC 签名 token。

移植自 grammar-kb 的 auth.py，同一套设计：
- 账号存 ``data/users.json``（用户名 → {salt, hash, role}，PBKDF2-SHA256 60k 迭代），
  文件不存在时自动播种默认账号（见 ``DEFAULT_USERS``）
- 签名密钥存 ``data/auth_secret.key``（首次随机生成，跨重启保持 token 有效）
- token 为 ``base64url(payload).base64url(hmac)``，payload 含 user/role/exp；
  30 天 TTL；无状态校验，不落库

默认账号（家庭本地工具，首次启动播种，可删 users.json 重置后改密码）：
- __REDACTED__ / __REDACTED__（学生）

数据目录固定为项目内 ``data/``，环境变量 ``GUWEN_DATA_DIR`` 可覆盖（测试用）；
每次调用动态解析，进程内切换环境变量立即生效。
"""
from __future__ import annotations

import base64
import hashlib
import hmac
import json
import os
import secrets
import time
from pathlib import Path

DEFAULT_USERS = {
    "__REDACTED__": ("__REDACTED__", "student"),
}
TOKEN_TTL = 30 * 24 * 3600  # 30 天


def data_dir() -> Path:
    """运行时数据目录：GUWEN_DATA_DIR 优先，否则项目内 data/。"""
    env = os.environ.get("GUWEN_DATA_DIR")
    return Path(env) if env else Path(__file__).resolve().parent / "data"


def _pbkdf2(password: str, salt: str) -> str:
    return hashlib.pbkdf2_hmac("sha256", password.encode(), salt.encode(), 60_000).hex()


class UserStore:
    """users.json 的读写与校验。"""

    def __init__(self, path: Path | None = None):
        self._fixed_path = Path(path) if path else None
        self._users: dict | None = None

    @property
    def path(self) -> Path:
        # 每次访问动态解析，GUWEN_DATA_DIR 切换后立即生效（测试隔离用）
        return self._fixed_path if self._fixed_path else data_dir() / "users.json"

    def _load(self) -> dict:
        if self._users is not None:
            return self._users
        path = self.path
        if path.exists():
            try:
                self._users = json.loads(path.read_text(encoding="utf-8"))
                return self._users
            except Exception:
                pass  # 损坏则重建（重播种默认账号）
        users = {}
        for name, (pwd, role) in DEFAULT_USERS.items():
            salt = secrets.token_hex(8)
            users[name] = {"salt": salt, "hash": _pbkdf2(pwd, salt), "role": role}
        self._users = users
        try:
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(json.dumps(users, ensure_ascii=False, indent=2), encoding="utf-8")
        except Exception:
            pass  # 只读环境也能跑（每次进程内重建）
        return users

    def list_users(self) -> list[dict]:
        return [{"user": k, "role": v.get("role", "student")}
                for k, v in self._load().items()]

    def add_user(self, user: str, password: str, role: str = "student") -> None:
        import re as _re
        user = (user or "").strip()
        if not _re.fullmatch(r"[A-Za-z0-9_-]{2,32}", user):
            raise ValueError("用户名须为 2-32 位字母/数字/_/-")
        if len(password or "") < 4:
            raise ValueError("密码至少 4 位")
        users = self._load()
        if user in users:
            raise ValueError("用户已存在")
        salt = secrets.token_hex(8)
        users[user] = {"salt": salt, "hash": _pbkdf2(password, salt),
                       "role": role if role in ("student", "teacher") else "student"}
        self._save(users)

    def delete_user(self, user: str) -> None:
        users = self._load()
        if user not in users:
            raise ValueError("用户不存在")
        if users[user].get("role") == "teacher":
            raise ValueError("教师账号不可删除")
        del users[user]
        self._save(users)

    def _save(self, users: dict) -> None:
        self._users = users
        path = self.path
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(users, ensure_ascii=False, indent=2),
                        encoding="utf-8")

    def verify(self, user: str, password: str) -> str | None:
        """校验成功返回角色，失败返回 None。"""
        rec = self._load().get(user)
        if not rec:
            return None
        if hmac.compare_digest(_pbkdf2(password, rec["salt"]), rec["hash"]):
            return rec.get("role", "student")
        return None


# 签名秘钥进程内缓存（路径 → 内容）：签发/校验每个请求都要读秘钥，
# 秘钥启动后不变，首次读入内存即可。按路径做键——测试把 GUWEN_DATA_DIR
# 指到各自 tmp 路径时各取各的，互不串味；调 _reset_secret_cache() 可失效缓存。
_secret_cache: dict[str, bytes] = {}


def _secret_path() -> Path:
    return data_dir() / "auth_secret.key"


def _load_secret() -> bytes:
    p = _secret_path()
    key = str(p)
    cached = _secret_cache.get(key)
    if cached is not None:
        return cached
    if p.exists():
        s = p.read_bytes()
    else:
        s = secrets.token_bytes(32)
        try:
            p.parent.mkdir(parents=True, exist_ok=True)
            p.write_bytes(s)
        except Exception:
            pass
    _secret_cache[key] = s
    return s


def _reset_secret_cache() -> None:
    """测试/换钥钩子：清空秘钥缓存，下次 _load_secret 重新读盘/生成。"""
    _secret_cache.clear()


def make_token(user: str, role: str, ttl: int = TOKEN_TTL) -> str:
    payload = json.dumps(
        {"user": user, "role": role, "exp": int(time.time()) + ttl}, separators=(",", ":")
    ).encode()
    body = base64.urlsafe_b64encode(payload)
    sig = hmac.new(_load_secret(), body, hashlib.sha256).digest()
    return f"{body.decode()}.{base64.urlsafe_b64encode(sig).decode()}"


def read_token(token: str) -> dict | None:
    """校验签名与过期时间；有效返回 payload，无效返回 None。"""
    try:
        body_b64, sig_b64 = token.split(".", 1)
        body = body_b64.encode()
        expect = hmac.new(_load_secret(), body, hashlib.sha256).digest()
        if not hmac.compare_digest(base64.urlsafe_b64decode(sig_b64), expect):
            return None
        payload = json.loads(base64.urlsafe_b64decode(body))
        if payload.get("exp", 0) < time.time():
            return None
        return payload
    except Exception:
        return None
