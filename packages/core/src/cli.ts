// 用法：node src/cli.ts <项目目录>   —— 扫描目录下的 .py / .js / .jsx / .ts / .tsx
import { readdirSync, readFileSync, statSync } from "node:fs";
import { join, relative } from "node:path";
import { scan } from "./scan.ts";
import type { SourceFile } from "./types.ts";

const SKIP = new Set(["node_modules", ".venv", ".git", "dist", "__pycache__", "fixtures"]);

function walk(dir: string, root: string, out: SourceFile[]): void {
  for (const name of readdirSync(dir)) {
    if (SKIP.has(name)) continue;
    const full = join(dir, name);
    if (statSync(full).isDirectory()) walk(full, root, out);
    else if (/\.(py|jsx?|tsx?)$/.test(name)) {
      out.push({ path: relative(root, full).replaceAll("\\", "/"), content: readFileSync(full, "utf8") });
    }
  }
}

const root = process.argv[2] ?? ".";
const files: SourceFile[] = [];
walk(root, root, files);
const findings = scan(files);
for (const f of findings) {
  console.log(`[${f.severity.toUpperCase()}] ${f.ruleId} ${f.location.file}:${f.location.line}  ${f.title}`);
  console.log(`    证据: ${f.evidence}`);
  if (f.fixTemplateId) console.log(`    建议模板: ${f.fixTemplateId}`);
}
console.log(`共 ${findings.length} 条发现`);
