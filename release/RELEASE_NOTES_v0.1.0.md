# v0.1.0 - 2026-06-09

首个 Windows 桌面版发布。

## 新增

- 企业 SSO Codex 中文 WebView 控制台。
- Windows x64 发布包：`CompanySSOCodexGUI-windows-x64.zip`。
- 输入 SSO 域名后运行企业 SSO / Codex OAuth / 令牌生成流程。
- 支持仅保存令牌、Sub2API、CPA、全部导出。
- 默认读取 Windows 系统代理，保留“不使用代理”开关。
- MiSans 字体和 Apple 风格中文 UI。

## 修复

- OpenAI `unsupported_country_region_territory` 不再误报为“纯 HTTP 流程遇到无法自动处理的页面”。
- 企业 SSO 服务器不可达时明确显示 `company_sso_http`。

## 验证

- `python -m pytest -q`：154 passed。
- 已做 Windows GUI 真实点击测试。

## 致谢

- 基于 `supperzl/ita` 二次开发。
- 感谢原项目作者、iDP 协议作者与注册机作者。
