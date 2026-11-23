import type { Finding, SourceFile } from "../types.ts";

const FRONTEND_EXT = /\.(jsx?|tsx?)$/;

/** S4：前端用 credentials:"include" 发状态变更请求，但文件里没有任何 CSRF token 处理 */
export function ruleS4(files: SourceFile[]): Finding[] {
  const out: Finding[] = [];
  for (const file of files) {
    if (!FRONTEND_EXT.test(file.path)) continue;
    const ls = file.content.split(/\r?\n/);
    const idx = ls.findIndex((l) => /credentials\s*:\s*["']include["']/.test(l));
    if (idx === -1) continue;
    const sendsState = /["'](POST|PUT|PATCH|DELETE)["']/i.test(file.content);
    // 只认真正的 token 头 / 变量名，页面文案里出现 "CSRF" 一词不算
    const hasToken = /x-csrf|x-xsrf|csrf[_-]?token|xsrf[_-]?token/i.test(file.content);
    if (sendsState && !hasToken) {
      out.push({
        ruleId: "S4",
        severity: "high",
        title: "前端携带凭证发起状态变更请求，但没有 CSRF token",
        location: { file: file.path, line: idx + 1 },
        evidence: ls[idx].trim(),
        fixTemplateId: "synchronizer-token",
      });
    }
  }
  return out;
}
