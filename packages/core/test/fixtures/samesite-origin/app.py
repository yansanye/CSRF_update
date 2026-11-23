import sqlite3
from contextlib import closing
from pathlib import Path

from flask import Flask, jsonify, request, session
from werkzeug.security import generate_password_hash, check_password_hash

app = Flask(__name__)
app.config.update(
    SECRET_KEY="local-csrf-lab-only",
    SESSION_COOKIE_NAME="csrf_lab_session",
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="Strict",
    SESSION_COOKIE_SECURE=False,
)

DB = Path(__file__).with_name("lab.db")

with closing(sqlite3.connect(DB)) as db:
    db.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL
        )
    """)
    db.commit()


SAFE_METHODS = {"GET", "HEAD", "OPTIONS"}
ALLOWED_ORIGINS = {"http://127.0.0.1:5173", "http://localhost:5173"}


@app.before_request
def verify_origin():
    """方案 C：状态变更请求的 Origin（缺失时用 Referer）必须在白名单内。"""
    if request.method in SAFE_METHODS:
        return None
    origin = request.headers.get("Origin")
    if not origin:
        referer = request.headers.get("Referer", "")
        origin = "/".join(referer.split("/")[:3]) if referer else None
    if origin not in ALLOWED_ORIGINS:
        return jsonify(error="请求来源不被允许"), 403
    return None


@app.post("/api/register")
def register():
    username = request.form.get("username", "").strip()
    password = request.form.get("password", "")

    if not username or len(password) < 8:
        return jsonify(error="用户名不能为空，密码至少 8 位"), 400

    with closing(sqlite3.connect(DB)) as db:
        try:
            db.execute(
                "INSERT INTO users(username, password_hash) VALUES (?, ?)",
                (username, generate_password_hash(password)),
            )
            db.commit()
        except sqlite3.IntegrityError:
            return jsonify(error="用户名已存在"), 409

    return jsonify(message="注册成功"), 201


@app.post("/api/login")
def login():
    username = request.form.get("username", "").strip()
    password = request.form.get("password", "")

    with closing(sqlite3.connect(DB)) as db:
        user = db.execute(
            "SELECT id, password_hash FROM users WHERE username = ?",
            (username,),
        ).fetchone()

    if user is None or not check_password_hash(user[1], password):
        return jsonify(error="用户名或密码错误"), 401

    session.clear()
    session["user_id"] = user[0]
    return jsonify(message="登录成功")


@app.get("/api/me")
def me():
    user_id = session.get("user_id")
    if not user_id:
        return jsonify(error="未登录"), 401

    with closing(sqlite3.connect(DB)) as db:
        user = db.execute(
            "SELECT username FROM users WHERE id = ?", (user_id,)
        ).fetchone()

    if user is None:
        session.clear()
        return jsonify(error="用户不存在"), 401

    return jsonify(username=user[0])


@app.post("/api/change-password")
def change_password():
    user_id = session.get("user_id")
    if not user_id:
        return jsonify(error="未登录"), 401

    new_password = request.form.get("new_password", "")
    if len(new_password) < 8:
        return jsonify(error="新密码至少 8 位"), 400

    # 靶场故意不检查 CSRF Token、请求来源或旧密码。
    with closing(sqlite3.connect(DB)) as db:
        result = db.execute(
            "UPDATE users SET password_hash = ? WHERE id = ?",
            (generate_password_hash(new_password), user_id),
        )
        db.commit()

    if result.rowcount != 1:
        session.clear()
        return jsonify(error="用户不存在"), 401

    return jsonify(message="密码修改成功")


@app.post("/api/logout")
def logout():
    session.clear()
    return jsonify(message="已退出")


if __name__ == "__main__":
    app.run(host="127.0.0.1", port=5000, debug=False)
