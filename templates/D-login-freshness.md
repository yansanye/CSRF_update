# 方案 D：登录新鲜度（敏感操作二次验证）— 设计稿

> 状态：设计稿，尚未在靶场分支实现和验证。实现后请用真实 diff 替换下方示意代码。
> 对应规则：S6（建议类，low）。详见 `docs/design.md` §2.5。

## 适用场景
改密码、改邮箱等敏感操作；不想强制用户输入旧密码（用户可能忘记）。

## 原理
登录时记录时间，敏感操作要求登录时间在窗口内（默认 15 分钟），否则要求重新登录。

## 后端示意（Flask，未验证）
```python
import time
FRESH_SECONDS = 15 * 60

# login() 中，session.clear() 之后：
session["login_at"] = int(time.time())

# change_password() 开头，已确认登录之后：
if time.time() - session.get("login_at", 0) > FRESH_SECONDS:
    return jsonify(error="需要重新登录后再修改密码", code="reauth_required"), 403
```

## 前端示意（fetch，未验证）
识别响应里的 `code === "reauth_required"`，提示重新登录，不要与 CSRF 的 403 混淆。

## 验证方法（待实现后补充）
1. 登录后立即改密码：成功。
2. 把 `FRESH_SECONDS` 临时改为 5 秒，等待后改密码：返回 `reauth_required`。
3. 重新登录后再改密码：成功。

## 已知局限
- 不能防止新鲜窗口内的攻击，必须与 CSRF 防护叠加。
- 窗口时长需要在安全与体验间权衡。
- 忘记密码的用户需要走独立的重置流程。
- “改密码后使其他会话失效”需要数据库迁移，默认不自动应用。
