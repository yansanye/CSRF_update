import type { Finding, SourceFile } from "./types.ts";
import { detectProtection, extractRoutes, isStateChanging, ruleS1, ruleS2, ruleS6 } from "./rules/flask.ts";
import { ruleS4 } from "./rules/frontend.ts";

const ORDER = { high: 0, medium: 1, low: 2 } as const;

export function scan(files: SourceFile[]): Finding[] {
  const py = files.filter((f) => f.path.endsWith(".py"));
  const routes = py.flatMap(extractRoutes);
  const prot = detectProtection(py);
  const hasStateRoutes = routes.some(isStateChanging);

  const findings: Finding[] = [...ruleS1(routes, prot), ...ruleS2(py), ...ruleS6(routes)];
  // 只有后端确实没有保护时，前端缺 token 才是问题（方案 C 不需要前端 token）
  if (hasStateRoutes && !prot.protected) findings.push(...ruleS4(files));

  return findings.sort((a, b) => ORDER[a.severity] - ORDER[b.severity]);
}
