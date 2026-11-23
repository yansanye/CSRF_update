import type { Finding, SourceFile } from "../types.ts";

const STATE_METHODS = new Set(["post", "put", "patch", "delete"]);

export interface Route {
  file: string;
  path: string;
  methods: string[];
  funcName: string;
  /** 装饰器所在行（1 起） */
  line: number;
  decorator: string;
  body: string;
}

export interface Protection {
  protected: boolean;
  evidence?: string;
  file?: string;
  line?: number;
}

const splitLines = (c: string): string[] => c.split(/\r?\n/);

/** 取 defIdx 之后的缩进代码块（遇到顶格的非空行结束） */
function blockAfter(ls: string[], defIdx: number): string {
  const out: string[] = [];
  for (let k = defIdx + 1; k < ls.length; k++) {
    if (/^\S/.test(ls[k])) break;
    out.push(ls[k]);
  }
  return out.join("\n");
}

export function extractRoutes(file: SourceFile): Route[] {
  const ls = splitLines(file.content);
  const routes: Route[] = [];
  for (let i = 0; i < ls.length; i++) {
    let path = "";
    let methods: string[] | null = null;

    // @app.post("/x")  /  @bp.delete("/x")
    let m = ls[i].match(/^\s*@\w+\.(post|put|patch|delete|get)\(\s*["']([^"']+)["']/);
    if (m) {
      methods = [m[1]];
      path = m[2];
    } else {
      // @app.route("/x", methods=["POST", ...])
      m = ls[i].match(/^\s*@\w+\.route\(\s*["']([^"']+)["'](.*)\)/);
      if (m) {
        path = m[1];
        const mm = m[2].match(/methods\s*=\s*\[([^\]]*)\]/);
        methods = mm ? [...mm[1].matchAll(/["'](\w+)["']/g)].map((x) => x[1].toLowerCase()) : ["get"];
      }
    }
    if (!methods) continue;

    let j = i + 1;
    while (j < ls.length && /^\s*@/.test(ls[j])) j++;
    const f = ls[j]?.match(/^\s*def\s+(\w+)/);
    routes.push({
      file: file.path,
      path,
      methods,
      funcName: f ? f[1] : "",
      line: i + 1,
      decorator: ls[i].trim(),
      body: f ? blockAfter(ls, j) : "",
    });
  }
  return routes;
}

export const isStateChanging = (r: Route): boolean => r.methods.some((m) => STATE_METHODS.has(m));

/** 是否存在“全局”CSRF 校验：CSRFProtect，或 before_request 钩子里校验 token / Origin / Referer */
export function detectProtection(files: SourceFile[]): Protection {
  for (const file of files) {
    const ls = splitLines(file.content);
    for (let i = 0; i < ls.length; i++) {
      if (/\bCSRFProtect\s*\(/.test(ls[i])) {
        return { protected: true, evidence: ls[i].trim(), file: file.path, line: i + 1 };
      }
      if (/^\s*@\w+\.before_request\b/.test(ls[i])) {
        let j = i + 1;
        while (j < ls.length && /^\s*@/.test(ls[j])) j++;
        if (!/^\s*def\s+/.test(ls[j] ?? "")) continue;
        if (/csrf|xsrf|origin|referer/i.test(blockAfter(ls, j))) {
          return { protected: true, evidence: ls[j].trim(), file: file.path, line: j + 1 };
        }
      }
    }
  }
  return { protected: false };
}

/** S1：状态变更路由缺少全局 CSRF 校验（每个路由一条） */
export function ruleS1(routes: Route[], prot: Protection): Finding[] {
  if (prot.protected) return [];
  return routes.filter(isStateChanging).map((r) => ({
    ruleId: "S1" as const,
    severity: "high" as const,
    title: `状态变更接口 ${r.methods.join("/").toUpperCase()} ${r.path} 缺少 CSRF 校验`,
    location: { file: r.file, line: r.line },
    evidence: r.decorator,
    fixTemplateId: "synchronizer-token" as const,
  }));
}

/** S2：会话 Cookie 的 SameSite 为 None，或 Flask 应用完全没有显式配置 */
export function ruleS2(files: SourceFile[]): Finding[] {
  const out: Finding[] = [];
  for (const file of files) {
    if (!/\bFlask\s*\(/.test(file.content)) continue;
    const ls = splitLines(file.content);
    const idx = ls.findIndex((l) => /SESSION_COOKIE_SAMESITE/.test(l));
    if (idx === -1) {
      out.push({
        ruleId: "S2",
        severity: "low",
        title: "未显式配置 SESSION_COOKIE_SAMESITE",
        location: { file: file.path, line: 1 },
        evidence: "未找到 SESSION_COOKIE_SAMESITE",
        fixTemplateId: "samesite-origin",
      });
      continue;
    }
    const v = ls[idx].match(/SESSION_COOKIE_SAMESITE["']?\s*[=:]\s*["']?(\w+)/)?.[1];
    if (v && v.toLowerCase() === "none") {
      out.push({
        ruleId: "S2",
        severity: "high",
        title: "会话 Cookie 设为 SameSite=None，跨站请求会携带 Cookie",
        location: { file: file.path, line: idx + 1 },
        evidence: ls[idx].trim(),
        fixTemplateId: "samesite-origin",
      });
    }
  }
  return out;
}

/** S6：改密码类接口不要求旧密码 */
export function ruleS6(routes: Route[]): Finding[] {
  return routes
    .filter(isStateChanging)
    .filter((r) => /(change|update|reset)[-_]?password/i.test(r.path + " " + r.funcName))
    .filter((r) => !/old_?password|current_?password|oldPassword|old_pwd/i.test(r.body))
    .map((r) => ({
      ruleId: "S6" as const,
      severity: "medium" as const,
      title: `敏感操作 ${r.path} 没有要求旧密码（二次验证）`,
      location: { file: r.file, line: r.line },
      evidence: r.decorator,
    }));
}
