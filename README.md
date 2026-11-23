# CSRF 靶场

一个故意不做 CSRF 防护的登录、注册、改密码小项目：前端 React（Vite），后端 Flask。只在本机的 127.0.0.1 环境使用。

## 运行方式

开三个终端（Windows）：

```
cd backend
..\.venv\Scripts\python app.py        # 后端 http://127.0.0.1:5000

cd frontend
npm run dev                            # 前端 http://127.0.0.1:5173，/api 会被代理到后端

cd attacker
python -m http.server 8000 --bind 127.0.0.1    # 攻击页 http://127.0.0.1:8000
```

## 分支

三种防御方案的代码改动都放在 `templates/` 里：
- `A-synchronizer-token.md`：服务端在 session 里存 token，请求头带 `X-CSRF-Token`。
- `B-double-submit.md`：双重提交 Cookie。
- `C-samesite-origin.md`：`SameSite=Strict` 加 Origin / Referer 白名单。

每个修复分支相对 `main` 的 diff 只包含防御代码，后面做 AI 修复时会拿它们当参考答案。

## 攻击页（attacker/）

- `attack.html`：表单提交改密码
- `attack_fetch.html`：用 fetch 改密码
- `attack_logout.html`：强制登出
- `attack_login.html`：登录 CSRF，需要先注册一个 `attacker` / `AttackerPass123!`

## 自动验证

在某个分支启动后端后，运行 `python attacker/verify.py`；这只验证服务端逻辑，SameSite 的效果在浏览器里验证。

## 其他目录

- `packages/core`：检测规则的原型，`npm test` 可以跑测试
- `templates/`：三种修复方案的说明和代码改动
- `docs/`：设计笔记和验证记录
