# 方案 C：SameSite=Strict + Origin/Referer 白名单

## 适用场景
改造成本最低，不想改前端；作为纵深防御与方案 A/B 叠加也很合适。

## 原理
1) 会话 Cookie 设为 `SameSite=Strict`，跨站请求浏览器不会携带；2) 服务端校验 `Origin`（缺失时用 `Referer`）必须在白名单内，否则 403。

## 后端改动（`backend/app.py`）
```diff
diff --git a/backend/app.py b/backend/app.py
index 0347a63..f6449fa 100644
--- a/backend/app.py
+++ b/backend/app.py
@@ -11,5 +11,5 @@ app.config.update(
     SESSION_COOKIE_NAME="csrf_lab_session",
     SESSION_COOKIE_HTTPONLY=True,
-    SESSION_COOKIE_SAMESITE="Lax",
+    SESSION_COOKIE_SAMESITE="Strict",
     SESSION_COOKIE_SECURE=False,
 )
@@ -28,4 +28,22 @@ with closing(sqlite3.connect(DB)) as db:
 
 
+SAFE_METHODS = {"GET", "HEAD", "OPTIONS"}
+ALLOWED_ORIGINS = {"http://127.0.0.1:5173", "http://localhost:5173"}
+
+
+@app.before_request
+def verify_origin():
+    """方案 C：状态变更请求的 Origin（缺失时用 Referer）必须在白名单内。"""
+    if request.method in SAFE_METHODS:
+        return None
+    origin = request.headers.get("Origin")
+    if not origin:
+        referer = request.headers.get("Referer", "")
+        origin = "/".join(referer.split("/")[:3]) if referer else None
+    if origin not in ALLOWED_ORIGINS:
+        return jsonify(error="请求来源不被允许"), 403
+    return None
+
+
 @app.post("/api/register")
 def register():
```

## 前端改动（`frontend/src/App.jsx`）
无需改动。

## 验证方法
`verify.py` 只能验证 Origin 校验部分。SameSite 的效果必须在真实浏览器里验证：用 `localhost:8000` 托管攻击页、`127.0.0.1:5173` 访问靶场（跨站），Cookie 不应被携带。

## 已知局限
- 依赖浏览器正确发送 Origin/Referer 与支持 SameSite；老旧浏览器或被隐私插件剥离 Referer 时可能误拦或失效。
- SameSite 以“站点”为单位（忽略端口）：同站的其他应用/子域被攻破时，SameSite 不提供保护。
- 白名单必须精确匹配完整 origin，不要用 `startswith`。

## 来源
分支 `fix/samesite-origin` 相对 `main` 的 diff。
