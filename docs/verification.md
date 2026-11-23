# 验证记录

## 自动验证

用 `attacker/verify.py` 对每个分支各跑了一遍，每次都是单独启动后端。脚本模拟浏览器的做法：正常用户带着 token 和合法前端的 Origin；攻击页带着 Cookie 和攻击页的 Origin，但没有 token。

| 场景 | main | A（synchronizer-token） | B（double-submit） | C（samesite-origin） |
|---|---|---|---|---|
| 正常业务流程（注册、登录、改密、退出） | 通过 | 通过 | 通过 | 通过 |
| 改密码 CSRF（attack.html、attack_fetch.html） | 成功 | 拦截 | 拦截 | 拦截 |
| 登出 CSRF | 成功 | 拦截 | 拦截 | 拦截 |
| 登录 CSRF | 成功 | 拦截 | 拦截 | 拦截 |

## 两点说明

脚本里的 cookie jar 不会按 SameSite 过滤，所以 C 分支的自动验证其实只验证了 Origin 校验这一层。

`127.0.0.1:8000` 和靶场是 same-site（同主机，端口不参与判断），main 能被复现正是靠这一点。如果攻击页换成 `localhost`，原来的 Lax 配置就会把攻击拦下来。
