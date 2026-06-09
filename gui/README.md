# 企业 SSO Codex 图形界面

本目录提供本地 Web GUI 和桌面 WebView GUI。桌面版会启动内置本地服务，并在 exe 自己的窗口里加载同一套 `index.html` / `styles.css` / `app.js`，因此界面与 Open Design 预览保持一致。

Web GUI 自托管 MiSans 字体文件，来源为小米 HyperOS 官方字体包。使用时请保留字体文件随附的版权与许可要求。

## 启动桌面 GUI

```powershell
cd F:\sso-reg\.worktrees\company-sso-registration
python gui\webview_app.py
```

## 启动 Web GUI

```powershell
cd F:\sso-reg\.worktrees\company-sso-registration
python gui\server.py --host 127.0.0.1 --port 8765
```

打开：

```text
http://127.0.0.1:8765
```

## 行为

- 默认只需要输入 SSO 域名。
- 未填写员工邮箱和密码时，后端 CLI 会自动生成测试员工资料。
- Sub2API 和 CPA 密钥通过进程环境变量传递，不出现在命令预览里。
- 运行产物写入 `artifacts/gui_company_sso/<run-id>/`。
- 打包后的桌面 exe 会把产物写入 exe 同级的 `artifacts/gui_company_sso/<run-id>/`。

## 安全

- 服务默认监听 `127.0.0.1`。
- 后端使用参数列表调用 Python，不使用 shell 拼接。
- `token.json`、`employee.private.json` 和 `network.jsonl` 仍是敏感产物。

## Web 点击测试

先启动 GUI server，再运行：

```powershell
node gui\click-test.mjs
```

测试会启动独立 headless Chrome，真实点击“单次运行”“批量注册”“健康检查”“运行产物”、账号模式和导出目标控件。“开始运行”会使用无效本地域名验证前端错误路径，不触发真实外部 SSO。
