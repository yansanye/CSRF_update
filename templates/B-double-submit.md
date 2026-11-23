# 方案 B：Double Submit Cookie（无状态）

## 适用场景
不想在服务端存 token 的无状态/多实例服务；前后端分离且前端能读 Cookie。

## 原理
1) 服务端下发一个 JS 可读（非 HttpOnly）的 `csrf_token` Cookie；2) 前端把同一个值放进 `X-CSRF-Token` 头；3) 服务端比对 Cookie 与请求头。攻击页无法读取目标站 Cookie，也无法跨站带自定义头。

## 后端改动（`backend/app.py`）
```diff
diff --git a/backend/app.py b/backend/app.py
index 0347a63..d70a86a 100644
--- a/backend/app.py
+++ b/backend/app.py
@@ -1,2 +1,3 @@
+import secrets
 import sqlite3
 from contextlib import closing
@@ -28,4 +29,29 @@ with closing(sqlite3.connect(DB)) as db:
 
 
+SAFE_METHODS = {"GET", "HEAD", "OPTIONS"}
+
+
+@app.after_request
+def set_csrf_cookie(resp):
+    """方案 B：没有 csrf_token Cookie 时下发一个（必须允许 JS 读取，所以不设 HttpOnly）。"""
+    if "csrf_token" not in request.cookies:
+        resp.set_cookie(
+            "csrf_token", secrets.token_urlsafe(32), samesite="Lax", httponly=False
+        )
+    return resp
+
+
+@app.before_request
+def verify_double_submit():
+    """状态变更请求：请求头 X-CSRF-Token 必须与 csrf_token Cookie 一致。"""
+    if request.method in SAFE_METHODS:
+        return None
+    cookie = request.cookies.get("csrf_token", "")
+    header = request.headers.get("X-CSRF-Token", "")
+    if not cookie or not secrets.compare_digest(cookie, header):
+        return jsonify(error="CSRF token 不匹配"), 403
+    return None
+
+
 @app.post("/api/register")
 def register():
```

## 前端改动（`frontend/src/App.jsx`）
```diff
diff --git a/frontend/src/App.jsx b/frontend/src/App.jsx
index 3193719..03199de 100644
--- a/frontend/src/App.jsx
+++ b/frontend/src/App.jsx
@@ -1,4 +1,11 @@
 import { useState } from 'react'
 
+function getCookie(name) {
+  return document.cookie
+    .split('; ')
+    .find(row => row.startsWith(name + '='))
+    ?.split('=')[1]
+}
+
 export default function App() {
   const [username, setUsername] = useState('alice')
@@ -15,6 +22,11 @@ export default function App() {
 
       if (data !== undefined) {
+        // 首次 POST 前浏览器可能还没有 csrf_token Cookie，先发一个 GET 让后端下发
+        if (!getCookie('csrf_token')) {
+          await fetch('/api/me', { credentials: 'include' })
+        }
         options.headers = {
           'Content-Type': 'application/x-www-form-urlencoded',
+          'X-CSRF-Token': getCookie('csrf_token'),
         }
         options.body = new URLSearchParams(data)
```

## 验证方法
同方案 A。额外检查：首次 POST 前浏览器没有该 Cookie，前端应先发一次 GET 让后端下发。

## 已知局限
- 该方案只证明“两个值相等”，不绑定会话；若攻击者能向受害者浏览器写入 Cookie（子域名被控、网络中间人），可伪造一对相等的值。进阶做法：用 HMAC 把 token 与 session id 绑定。
- Cookie 不区分端口，同主机不同端口的页面可读写该 Cookie。
- 必须保证 token Cookie 不是 HttpOnly。

## 来源
分支 `fix/double-submit` 相对 `main` 的 diff。
