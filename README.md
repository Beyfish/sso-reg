# 企业 SSO Codex 控制台

Windows 桌面工具：输入企业 SSO 域名后，自动执行员工账号准备、OpenAI/Codex OAuth 授权流程、令牌产物生成，并可按需导出到 Sub2API 或 CLIProxyAPI。

本仓库基于开源项目 [`supperzl/ita`](https://github.com/supperzl/ita) 二次开发，新增了企业 SSO 注册流程、中文 GUI、Windows exe 打包、系统代理识别、GUI 测试和发布包。感谢原项目作者与协议实现者的工作。

## 使用范围

仅用于你有权限管理或测试的企业 SSO 域名、账号与导出服务。不要用于未授权的账号创建、绕过访问控制或第三方系统操作。

## 直接使用 Windows 软件

下载或在仓库中找到：

```text
release/CompanySSOCodexGUI-windows-x64.zip
```

解压后运行：

```text
CompanySSOCodexGUI/CompanySSOCodexGUI.exe
```

注意：这是 PyInstaller one-dir 包，不能只复制单个 exe。exe 旁边的 `_internal` 目录必须保留。

## GUI 功能

- 输入一个 SSO 域名即可启动单次流程。
- 自动生成开发员工账号，或显式填写员工邮箱与初始密码。
- 可选择仅保存令牌、导出 Sub2API、导出 CPA、同时导出。
- 默认跟随 Windows 系统代理；勾选“不使用代理”可强制直连。
- 运行日志实时显示步骤、产物目录和错误原因。
- 使用 MiSans 字体和 Apple 风格中文界面。

## 当前网络行为

新版程序会自动读取 Windows 系统代理，解决 OpenAI 授权请求直连时可能出现的：

```text
Country, region, or territory not supported
```

如果 OpenAI 返回区域限制，程序会明确显示 `openai_network_blocked`，不再误报为“纯 HTTP 流程遇到无法自动处理的页面”。

如果企业 SSO 服务器本身不可达，程序会显示 `company_sso_http`，并提示检查 SSO 域名、端口和 OpenAI/WorkOS SSO 配置。

## 本机开发运行

安装依赖：

```bash
python -m pip install -e .
python -m pip install pywebview pytest
```

启动 GUI 服务：

```bash
python gui/server.py --host 127.0.0.1 --port 8765
```

启动 WebView 桌面壳：

```bash
python gui/webview_app.py
```

## 命令行运行

仅生成令牌，不导出：

```bash
python scripts/run_company_sso_codex.py --sso-domain hegiw77632.cloud-ip.cc --export-targets none --timeout 60
```

导出到 Sub2API：

```bash
python scripts/run_company_sso_codex.py --sso-domain hegiw77632.cloud-ip.cc --export-targets sub2api --timeout 60
```

禁用代理：

```bash
python scripts/run_company_sso_codex.py --sso-domain hegiw77632.cloud-ip.cc --export-targets none --no-proxy
```

## 打包

```powershell
python -m PyInstaller --noconfirm --clean --windowed --name CompanySSOCodexGUI --add-data "gui;gui" --collect-all curl_cffi --collect-all webview --collect-all clr_loader --collect-all pythonnet gui\webview_app.py
```

生成目录：

```text
dist/CompanySSOCodexGUI/
```

发布 zip：

```text
release/CompanySSOCodexGUI-windows-x64.zip
```

## 测试

```bash
python -m pytest -q
```

当前验证：

```text
154 passed
```

已做过真实 GUI 点击测试：打开 exe、输入 SSO 域名、修改 seed/timeout、切换导航与导出选项、点击开始运行、检查状态卡、队列和运行日志。

## 目录

```text
gui/
├── index.html          # 中文 WebView UI
├── styles.css          # Apple 风格布局和 MiSans 字体
├── app.js              # 前端状态、命令预览、运行轮询
├── server.py           # 本地 GUI API
└── webview_app.py      # Windows 桌面入口

lib/
├── company_sso_cli.py  # 企业 SSO CLI 编排
├── company_sso_flow.py # 企业 SSO 页面/WorkOS 流程处理
├── sso_http_flow.py    # OAuth/HTTP 驱动
└── config.py           # 配置、系统代理解析

release/
└── CompanySSOCodexGUI-windows-x64.zip
```

## 致谢

- 上游项目：[`supperzl/ita`](https://github.com/supperzl/ita)
- 原项目作者、iDP 协议作者与注册机作者
- MiSans 字体项目

本仓库保留上游版权信息，并在二次开发基础上增加 GUI、企业 SSO、打包和测试能力。
