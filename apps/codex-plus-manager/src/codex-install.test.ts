import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import path from "node:path";
import test from "node:test";
import ts from "typescript";

/**
 * 「一键安装 Codex」的接线契约（只做静态检查，不启动 Tauri、不联网）。
 *
 * 容易静默坏掉的地方：
 * 1. Rust 命令没注册到 `generate_handler!`，前端 invoke 运行期才报 command not found；
 * 2. 面板挂载或轮询时误触发安装——安装要下载近 1 GB，必须只由按钮触发；
 * 3. 概览「未检测到 Codex」时没有入口指向安装面板。
 */

const root = path.resolve(import.meta.dirname, "..");
const text = readFileSync(path.join(root, "src/App.tsx"), "utf8");
const app = ts.createSourceFile("App.tsx", text, ts.ScriptTarget.Latest, true, ts.ScriptKind.TSX);
const libSource = readFileSync(path.join(root, "src-tauri/src/lib.rs"), "utf8");
const commandsSource = readFileSync(path.join(root, "src-tauri/src/commands.rs"), "utf8");
const dictionary = readFileSync(path.join(root, "src/i18n-en.ts"), "utf8");

const COMMANDS = [
  ["codex_install_status", "pub fn"],
  ["install_codex_desktop", "pub async fn"],
  ["cancel_codex_install", "pub fn"],
  ["open_codex_store_page", "pub fn"],
] as const;

function functionSource(name: string) {
  const declaration = app.statements.find(
    (statement): statement is ts.FunctionDeclaration => ts.isFunctionDeclaration(statement) && statement.name?.text === name,
  );
  assert.ok(declaration, `${name} should exist`);
  return declaration;
}

function descendants(node: ts.Node): ts.Node[] {
  const nodes: ts.Node[] = [];
  const visit = (child: ts.Node) => {
    nodes.push(child);
    ts.forEachChild(child, visit);
  };
  ts.forEachChild(node, visit);
  return nodes;
}

test("codex install commands are defined and registered in the tauri handler", () => {
  for (const [command, signature] of COMMANDS) {
    assert.ok(commandsSource.includes(`${signature} ${command}(`), `commands.rs 缺少 #[tauri::command] ${command}`);
    assert.ok(libSource.includes(`commands::${command},`), `lib.rs 的 generate_handler! 没有注册 ${command}`);
    assert.ok(text.includes(`"${command}"`), `App.tsx 没有调用 ${command}`);
  }
});

test("install panel polls status on mount and installs only from the button", () => {
  const panel = functionSource("CodexInstallPanel");
  const effects = descendants(panel)
    .filter(ts.isCallExpression)
    .filter((node) => node.expression.getText(app) === "useEffect");
  assert.ok(effects.some((effect) => effect.getText(app).includes('"codex_install_status"')));
  for (const effect of effects) {
    assert.ok(!effect.getText(app).includes("install_codex_desktop"), "挂载/轮询不能触发安装");
  }
  const button = descendants(panel)
    .filter(ts.isJsxOpeningElement)
    .find((element) => element.getText(app).includes("installCodex()"));
  assert.ok(button, "安装必须由按钮触发");
  assert.match(button.getText(app), /disabled=\{running \|\| detected\}/, "安装中或已检测到 Codex 时按钮要禁用");
});

test("install page sits in the workspace sidebar right above Codex multi-launch", () => {
  assert.match(text, /\{ id: "codexInstall", label: t\("一键安装Codex"\), icon: Download, tool: "codex" \}/);
  assert.match(text, /routes: \["overview", "relay", "codexInstall", "multiLaunch", "grok", "claude"\]/);
  assert.match(text, /route === "codexInstall" \? <CodexInstallPanel overview=\{overview\} actions=\{actions\} \/> : null/);
  assert.doesNotMatch(functionSource("MaintenanceScreen").getText(app), /CodexInstallPanel/, "安装面板已移到独立页面");
});

test("overview links to the install page when Codex is missing", () => {
  const overview = functionSource("OverviewScreen").getText(app);
  assert.match(overview, /codex_app\.status === "missing"/);
  assert.match(overview, /actions\.openCodexInstall\(\)/);
  assert.match(text, /const openCodexInstall = \(\) => navigate\("codexInstall"\);/);
});

test("install copy has English translations", () => {
  for (const key of [
    "一键安装Codex",
    "安装 Codex 桌面应用",
    "一键安装 Codex",
    "安装 Codex",
    "取消安装",
    "在微软商店打开",
    "Codex 安装进度",
    "{0}（已下载 {1} / {2}）",
    "正在校验 OpenAI 签名…",
  ]) {
    assert.ok(dictionary.includes(`"${key}":`), `i18n-en.ts 缺少「${key}」的英文条目`);
  }
});
