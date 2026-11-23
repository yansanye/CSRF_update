# 方案 A：Synchronizer Token（服务端 session 存 token）

## 适用场景
服务端本来就有 session（Flask session / 服务端会话）的应用；表单和 AJAX 皆可。最推荐的默认方案。

## 原理
1) 服务端为每个 session 生成随机 token 并存在 session 里；2) 前端在发状态变更请求前通过 GET 取得 token，放进 `X-CSRF-Token` 头；3) 服务端用 `compare_digest` 比对，不一致返回 403。攻击页拿不到 token，且跨站带自定义头会触发预检并被拒绝。

## 后端改动（`backend/app.py`）
```diff
diff --git a/backend/app.py b/backend/app.py
index 0347a63..eb06878 100644
--- a/backend/app.py
+++ b/backend/app.py
@@ -1,2 +1,3 @@
+import secrets
 import sqlite3
 from contextlib import closing
@@ -28,4 +29,28 @@ with closing(sqlite3.connect(DB)) as db:
 
 
+SAFE_METHODS = {"GET", "HEAD", "OPTIONS"}
+
+
+@app.get("/api/csrf-token")
+def csrf_token():
+    """方案 A：为当前 session 生成（或返回已有的）CSRF token。"""
+    token = session.get("csrf_token")
+    if not token:
+        token = session["csrf_token"] = secrets.token_urlsafe(32)
+    return jsonify(csrf_token=token)
+
+
+@app.before_request
+def verify_csrf():
+    """所有状态变更请求必须带上与 session 中一致的 X-CSRF-Token。"""
+    if request.method in SAFE_METHODS:
+        return None
+    sent = request.headers.get("X-CSRF-Token", "")
+    expected = session.get("csrf_token", "")
+    if not expected or not secrets.compare_digest(sent, expected):
+        return jsonify(error="CSRF token 无效"), 403
+    return None
+
+
 @app.post("/api/register")
 def register():
```

## 前端改动（`frontend/src/App.jsx`）
```diff
diff --git a/frontend/src/App.jsx b/frontend/src/App.jsx
index 3193719..8ef82c9 100644
--- a/frontend/src/App.jsx
+++ b/frontend/src/App.jsx
@@ -15,6 +15,12 @@ export default function App() {
 
       if (data !== undefined) {
+        // 每次 POST 前取最新 token（login/logout 会 session.clear()，token 会失效）
+        const tokenRes = await fetch('/api/csrf-token', {
+          credentials: 'include',
+        })
+        const { csrf_token } = await tokenRes.json()
         options.headers = {
           'Content-Type': 'application/x-www-form-urlencoded',
+          'X-CSRF-Token': csrf_token,
         }
         options.body = new URLSearchParams(data)
```

## 验证方法
启动该分支后端，运行 `python attacker/verify.py`：三种 CSRF 均为“已拦截”，正常业务流程“通过”；再用浏览器打开 `attack.html` 点击，应返回 403。

## 已知局限
- `session.clear()`（登录/登出）会清掉 token，前端必须在每次 POST 前重新获取（本模板就是这么做的）。
- 依赖 session 存储；多实例部署需共享 session。
- 若存在 XSS，攻击者可读取 token，该方案无法抵御。

## 来源
分支 `fix/synchronizer-token` 相对 `main` 的 diff。
