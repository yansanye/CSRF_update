export type Severity = "high" | "medium" | "low";

/** 与 templates/ 目录下的三份修复模板一一对应 */
export type FixTemplateId = "synchronizer-token" | "double-submit" | "samesite-origin";

export interface SourceFile {
  /** 相对路径，用于在结果里定位 */
  path: string;
  content: string;
}

export interface Finding {
  ruleId: "S1" | "S2" | "S4" | "S6";
  severity: Severity;
  title: string;
  location: { file?: string; line?: number; url?: string };
  /** 命中的代码片段（动态检测时为请求摘要） */
  evidence: string;
  /** 推荐的修复模板；没有对应模板时为空 */
  fixTemplateId?: FixTemplateId;
}
