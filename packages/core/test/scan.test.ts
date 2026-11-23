import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { scan } from "../src/scan.ts";
import type { SourceFile } from "../src/types.ts";

const load = (name: string): SourceFile[] => [
  { path: "backend/app.py", content: readFileSync(new URL(`./fixtures/${name}/app.py`, import.meta.url), "utf8") },
  { path: "frontend/src/App.jsx", content: readFileSync(new URL(`./fixtures/${name}/App.jsx`, import.meta.url), "utf8") },
];
const ids = (fs: ReturnType<typeof scan>) => fs.map((f) => f.ruleId);
const py = (content: string): SourceFile[] => [{ path: "app.py", content }];

test("main（漏洞版）：4 个 POST 路由各报 S1，另有 S4、S6", () => {
  const f = scan(load("main"));
  assert.equal(ids(f).filter((x) => x === "S1").length, 4);
  assert.equal(ids(f).filter((x) => x === "S4").length, 1);
  assert.equal(ids(f).filter((x) => x === "S6").length, 1);
  assert.equal(f.some((x) => x.ruleId === "S2"), false); // main 是 Lax，不应报 S2
  const s4 = f.find((x) => x.ruleId === "S4")!;
  assert.equal(s4.location.file, "frontend/src/App.jsx");
  assert.match(s4.evidence, /credentials/);
});

for (const name of ["synchronizer-token", "double-submit", "samesite-origin"]) {
  test(`${name}：不再报 S1 / S4，只剩 S6（三个分支都没要求旧密码）`, () => {
    assert.deepEqual(ids(scan(load(name))), ["S6"]);
  });
}

test("识别 @app.route(..., methods=[POST]) 写法", () => {
  const f = scan(py(`@app.route("/pay", methods=["GET", "POST"])\ndef pay():\n    return "ok"\n`));
  assert.deepEqual(ids(f), ["S1"]);
});

test("CSRFProtect 视为已保护", () => {
  const f = scan(py(`csrf = CSRFProtect(app)\n\n@app.post("/pay")\ndef pay():\n    return "ok"\n`));
  assert.deepEqual(ids(f), []);
});

test("before_request 里没做任何校验，不算保护", () => {
  const f = scan(py(`@app.before_request\ndef log():\n    print("hi")\n\n@app.post("/pay")\ndef pay():\n    return "ok"\n`));
  assert.deepEqual(ids(f), ["S1"]);
});

test("SameSite=None 报 S2", () => {
  const f = scan(py(`app = Flask(__name__)\napp.config.update(SESSION_COOKIE_SAMESITE="None")\n`));
  assert.deepEqual(ids(f), ["S2"]);
  assert.equal(f[0].severity, "high");
});

test("改密码接口读取了旧密码则不报 S6", () => {
  const f = scan(py(`@app.post("/api/change-password")\ndef change_password():\n    old_password = request.form["old_password"]\n`));
  assert.equal(ids(f).includes("S6"), false);
});
