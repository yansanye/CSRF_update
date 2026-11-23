#!/usr/bin/env python3
"""
CSRF 靶场自动验证脚本（仅标准库）。
用法：先在某个分支启动后端（127.0.0.1:5000），再运行：  python attacker/verify.py

它模拟浏览器：
  - 合法前端：Origin=http://127.0.0.1:5173，并按该分支的方式带上 CSRF token（自动探测）
  - 攻击页  ：Origin=http://127.0.0.1:8000，浏览器自动带 Cookie，但拿不到/不会带 token
注意：脚本只能验证"服务端逻辑"。SameSite 属于浏览器行为，脚本里的 cookie jar 不会按
SameSite 过滤，所以 SameSite 的效果仍需用真实浏览器手动验证。
"""
import json, sys, uuid
import urllib.request, urllib.error, urllib.parse, http.cookiejar

BASE = "http://127.0.0.1:5000"
GOOD = "http://127.0.0.1:5173"
EVIL = "http://127.0.0.1:8000"


class Client:
    def __init__(self):
        self.jar = http.cookiejar.CookieJar()
        self.op = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(self.jar))

    def req(self, method, path, form=None, headers=None):
        data = urllib.parse.urlencode(form).encode() if form is not None else None
        r = urllib.request.Request(BASE + path, data=data, method=method, headers=headers or {})
        if data is not None:
            r.add_header("Content-Type", "application/x-www-form-urlencoded")
        try:
            resp = self.op.open(r)
        except urllib.error.HTTPError as e:
            resp = e
        raw = resp.read()
        try:
            body = json.loads(raw)
        except Exception:
            body = {}
        return resp.code, body

    def cookie(self, name):
        for c in self.jar:
            if c.name == name:
                return c.value
        return None


def legit_post(c, path, form):
    """模拟合法前端：自动探测并带上该分支要求的 token。"""
    h = {"Origin": GOOD}
    st, body = c.req("GET", "/api/csrf-token")
    if st == 200 and "csrf_token" in body:          # 方案 A：服务端 session token
        h["X-CSRF-Token"] = body["csrf_token"]
    else:                                            # 方案 B：双重提交 Cookie
        c.req("GET", "/api/me")
        t = c.cookie("csrf_token")
        if t:
            h["X-CSRF-Token"] = t
    return c.req("POST", path, form, h)


def attack_post(c, path, form):
    """模拟攻击页：浏览器自动带 Cookie，Origin 是攻击页，没有自定义头。"""
    return c.req("POST", path, form, {"Origin": EVIL})


def login_ok(user, pw):
    c = Client()
    return legit_post(c, "/api/login", {"username": user, "password": pw})[0] == 200, c


def main():
    sfx = uuid.uuid4().hex[:6]
    user, attacker = f"victim_{sfx}", f"attacker_{sfx}"
    pw0, pw_legit, pw_evil, pw_att = "Original123!", "Normal456!", "ChangedByCSRF123!", "AttackerPass123!"
    res = {}

    # 0) 正常业务流程必须始终可用
    c = Client()
    ok = legit_post(c, "/api/register", {"username": user, "password": pw0})[0] == 201
    ok &= legit_post(c, "/api/register", {"username": attacker, "password": pw_att})[0] == 201
    ok &= legit_post(c, "/api/login", {"username": user, "password": pw0})[0] == 200
    ok &= c.req("GET", "/api/me")[1].get("username") == user
    ok &= legit_post(c, "/api/change-password", {"new_password": pw_legit})[0] == 200
    ok &= legit_post(c, "/api/logout", {})[0] == 200
    ok &= login_ok(user, pw_legit)[0]
    res["正常业务流程"] = "通过" if ok else "失败"
    current = pw_legit

    # 1) 改密码 CSRF（attack.html / attack_fetch.html，线上请求相同）
    _, victim = login_ok(user, current)
    attack_post(victim, "/api/change-password", {"new_password": pw_evil})
    if login_ok(user, pw_evil)[0]:
        res["改密码 CSRF"] = "攻击成功"
        current = pw_evil
    else:
        res["改密码 CSRF"] = "已拦截"

    # 2) 登出 CSRF（attack_logout.html）
    _, victim = login_ok(user, current)
    attack_post(victim, "/api/logout", {})
    res["登出 CSRF"] = "攻击成功" if victim.req("GET", "/api/me")[0] == 401 else "已拦截"

    # 3) 登录 CSRF（attack_login.html）
    victim = Client()
    victim.req("GET", "/api/me")                      # 受害者先访问过站点
    attack_post(victim, "/api/login", {"username": attacker, "password": pw_att})
    who = victim.req("GET", "/api/me")[1].get("username")
    res["登录 CSRF"] = "攻击成功" if who == attacker else "已拦截"

    width = max(len(k) for k in res)
    for k, v in res.items():
        print(f"  {k:<{width}}  {v}")
    print("RESULT " + json.dumps(res, ensure_ascii=False))


if __name__ == "__main__":
    try:
        main()
    except urllib.error.URLError as e:
        sys.exit(f"连不上 {BASE}，请先启动后端：{e}")
