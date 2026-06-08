# Copyright (c) 2026 Idp Team Automation.
# iDP 协议作者：@该隐；注册机作者：@朴圣佑。
# 二开请保留版权；二开不保留版权，以后写代码都是bug。

"""Command-line orchestration for company SSO -> Codex OAuth -> export targets."""
from __future__ import annotations

import argparse
import json
import re
import sys
import urllib.parse
from pathlib import Path
from typing import Any, Callable

from .cli import _build_export_record, _export_record, _write_json
from .codex_oauth import generate_oauth_start, public_token_result
from .company_account import CompanyAccount, generate_dev_account
from .company_sso_flow import CompanySSOHttpFlow
from .config import PROJECT_ROOT, RuntimeConfig, env_first, load_dotenv, normalize_export_targets, parse_float
from .errors import ConfigError, IdpTeamAutomationError, OAuthFlowError
from .logging_utils import JsonlLogger, redact, utc_now_iso

ProgressFn = Callable[[str, dict[str, Any] | None], None]


def _progress(message: str, data: dict[str, Any] | None = None) -> None:
    suffix = ""
    if data:
        safe = redact(data)
        visible = {key: value for key, value in safe.items() if value not in ("", None, [], {})}
        if visible:
            suffix = " " + json.dumps(visible, ensure_ascii=False, sort_keys=True, default=str)
    print(f"[{utc_now_iso()}] {message}{suffix}", file=sys.stderr, flush=True)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="公司 SSO 员工注册 -> Codex OAuth refresh token -> 导出目标推送")
    parser.add_argument("--sso-domain", help="公司 SSO 允许域名，例如 sso.company.test")

    parser.add_argument("--dev-generate", action="store_true", help="开发模式：按 seed 生成测试员工账号")
    parser.add_argument("--email-domain", help="开发模式员工邮箱后缀，例如 company.test")
    parser.add_argument("--seed", default="", help="开发模式确定性 seed")
    parser.add_argument("--password-length", default="16", help="开发模式密码长度，最小 12")

    parser.add_argument("--username", help="员工用户名；不填则取 email @ 前缀")
    parser.add_argument("--email", help="员工邮箱")
    parser.add_argument("--password", help="员工初始密码")
    parser.add_argument("--first-name", dest="first_name", help="员工名；不填则从 username 前缀推断")
    parser.add_argument("--last-name", dest="last_name", help="员工姓；不填则为 Employee")
    parser.add_argument("--employee-id", help="员工编号")

    parser.add_argument("--codex-client-id", help="Codex OAuth client_id")
    parser.add_argument("--codex-redirect-uri", help="Codex OAuth redirect_uri")
    parser.add_argument("--codex-scope", help="Codex OAuth scope")

    parser.add_argument("--sub2api-url", help="Sub2API base URL")
    parser.add_argument("--sub2api-email", help="Sub2API 管理员邮箱")
    parser.add_argument("--sub2api-password", help="Sub2API 管理员密码")
    parser.add_argument("--sub2api-group", help="Sub2API 分组 ID，多个用逗号")
    parser.add_argument("--model-whitelist", help="Sub2API model whitelist，多个用逗号")
    parser.add_argument("--export-targets", help="导出目标：sub2api / cpa / sub2api,cpa / none；默认读取 EXPORT_TARGETS 或 sub2api")
    parser.add_argument("--cpa-url", help="CLIProxyAPI base URL")
    parser.add_argument("--cpa-management-key", help="CLIProxyAPI Management API key")
    parser.add_argument("--cpa-note", help="CPA auth 文件备注")
    parser.add_argument("--no-sub2api", action="store_true", help="只获取 token，不推送 Sub2API")

    parser.add_argument("--artifact-dir", help="artifact 输出目录，默认 artifacts/company_sso_codex")
    parser.add_argument("--timeout", help="HTTP timeout 秒数")
    parser.add_argument("--proxy", help="HTTP/HTTPS proxy")
    parser.add_argument("--no-proxy", action="store_true", help="禁用 proxy")
    return parser


def _resolve_artifact_dir(value: str | None) -> Path:
    raw = str(value or "").strip()
    if not raw:
        return PROJECT_ROOT / "artifacts" / "company_sso_codex"
    path = Path(raw)
    if path.is_absolute():
        return path
    return PROJECT_ROOT / path


def _positive_int(value: Any, default: int) -> int:
    try:
        return max(1, int(float(str(value).strip())))
    except (TypeError, ValueError):
        return default


def _default_first_name(username: str) -> str:
    prefix = re.split(r"[._+\-]+", str(username or "").strip(), maxsplit=1)[0]
    letters = re.sub(r"[^A-Za-z]+", "", prefix)
    if not letters:
        return "User"
    return letters[:1].upper() + letters[1:].lower()


def _explicit_account_from_args(args: argparse.Namespace) -> CompanyAccount:
    email = str(args.email or "").strip()
    password = str(args.password or "")
    if not email:
        raise ConfigError("显式员工输入缺少 --email", stage="config")
    if not password:
        raise ConfigError("显式员工输入缺少 --password", stage="config")
    username = str(args.username or "").strip() or email.split("@", 1)[0].strip()
    first_name = str(args.first_name or "").strip() or _default_first_name(username)
    last_name = str(args.last_name or "").strip() or "Employee"
    return CompanyAccount(
        username=username,
        email=email,
        password=password,
        first_name=first_name,
        last_name=last_name,
        employee_id=str(args.employee_id or "").strip(),
    )


def _account_from_args(args: argparse.Namespace) -> CompanyAccount:
    if args.dev_generate:
        email_domain = str(args.email_domain or "").strip()
        if not email_domain:
            raise ConfigError("开发模式缺少 --email-domain", stage="config")
        try:
            return generate_dev_account(
                email_domain=email_domain,
                seed=str(args.seed or ""),
                password_length=_positive_int(args.password_length, 16),
            )
        except ValueError as exc:
            raise ConfigError(str(exc), stage="config") from exc
    return _explicit_account_from_args(args)


def _runtime_config_from_args(args: argparse.Namespace) -> RuntimeConfig:
    load_dotenv()
    raw_export_targets = args.export_targets
    if raw_export_targets is None:
        raw_export_targets = env_first("EXPORT_TARGETS", default="")
    targets = normalize_export_targets(raw_export_targets or None, no_sub2api=bool(args.no_sub2api))
    proxy = "" if args.no_proxy else (args.proxy or env_first("HTTPS_PROXY", "HTTP_PROXY", default=""))
    return RuntimeConfig(
        codex_client_id=args.codex_client_id or env_first("CODEX_CLIENT_ID", default="app_EMoamEEZ73f0CkXaXp7hrann"),
        codex_redirect_uri=args.codex_redirect_uri or env_first("CODEX_REDIRECT_URI", default="http://localhost:1455/auth/callback"),
        codex_scope=args.codex_scope or env_first("CODEX_SCOPE", default="openid profile email offline_access"),
        sub2api_url=args.sub2api_url or env_first("SUB2API_URL"),
        sub2api_email=args.sub2api_email or env_first("SUB2API_EMAIL"),
        sub2api_password=args.sub2api_password or env_first("SUB2API_PASSWORD"),
        sub2api_group=args.sub2api_group or env_first("SUB2API_GROUP"),
        sub2api_model_whitelist=args.model_whitelist or env_first("SUB2API_MODEL_WHITELIST"),
        export_targets=targets,
        cpa_url=args.cpa_url or env_first("CPA_URL"),
        cpa_management_key=args.cpa_management_key or env_first("CPA_MANAGEMENT_KEY"),
        cpa_note=args.cpa_note or env_first("CPA_NOTE", default="Idp Team Automation"),
        artifact_dir=_resolve_artifact_dir(args.artifact_dir),
        timeout=parse_float(args.timeout or env_first("REQUEST_TIMEOUT", default="30"), 30.0, minimum=1.0),
        proxy=proxy,
        export_sub2api="sub2api" in targets,
    )


def _validate_export_config(cfg: RuntimeConfig) -> None:
    targets = cfg.selected_export_targets
    if "sub2api" in targets:
        missing = []
        if not cfg.sub2api_url:
            missing.append("SUB2API_URL")
        if not cfg.sub2api_email:
            missing.append("SUB2API_EMAIL")
        if not cfg.sub2api_password:
            missing.append("SUB2API_PASSWORD")
        if missing:
            raise ConfigError("缺少 Sub2API 配置：" + ", ".join(missing), stage="config")
    if "cpa" in targets:
        missing = []
        if not cfg.cpa_url:
            missing.append("CPA_URL")
        if not cfg.cpa_management_key:
            missing.append("CPA_MANAGEMENT_KEY")
        if missing:
            raise ConfigError("缺少 CPA 配置：" + ", ".join(missing), stage="config")


def _redacted_oauth_auth_url(auth_url: str) -> str:
    parsed = urllib.parse.urlparse(auth_url)
    pairs = urllib.parse.parse_qsl(parsed.query, keep_blank_values=True)
    safe_pairs = [
        (key, "***REDACTED***" if key in {"state"} else value)
        for key, value in pairs
    ]
    safe_query = urllib.parse.urlencode(safe_pairs)
    return urllib.parse.urlunparse(parsed._replace(query=safe_query))


def _oauth_start_public(oauth: Any) -> dict[str, Any]:
    return {
        "auth_url": redact(_redacted_oauth_auth_url(oauth.auth_url)),
        "state": "***REDACTED***",
        "redirect_uri": oauth.redirect_uri,
        "client_id": oauth.client_id,
        "scope": oauth.scope,
    }


def _result_payload(cfg: RuntimeConfig, account: CompanyAccount, token_public: dict[str, Any], exports: dict[str, dict[str, Any]]) -> dict[str, Any]:
    return {
        "status": "success",
        "finished_at": utc_now_iso(),
        "artifact_dir": str(cfg.artifact_dir),
        "account": account.as_public_dict(),
        "token": token_public,
        "exports": exports,
    }


def run(cfg: RuntimeConfig, account: CompanyAccount, *, sso_domain: str, progress: ProgressFn | None = _progress) -> dict[str, Any]:
    sso_domain = str(sso_domain or "").strip()
    if not sso_domain:
        raise ConfigError("缺少 --sso-domain", stage="config")
    _validate_export_config(cfg)

    cfg.artifact_dir.mkdir(parents=True, exist_ok=True)
    logger = JsonlLogger(cfg.artifact_dir / "network.jsonl")
    if progress:
        progress("步骤 1/6：初始化公司 SSO 运行环境", {
            "artifact_dir": str(cfg.artifact_dir),
            "sso_domain": sso_domain,
            "export_targets": list(cfg.selected_export_targets),
        })
    logger.write("run_start", {"artifact_dir": str(cfg.artifact_dir), "sso_domain": sso_domain, "account": account.as_public_dict(), "export_targets": list(cfg.selected_export_targets)})

    _write_json(cfg.artifact_dir / "employee.public.json", account.as_public_dict())
    _write_json(cfg.artifact_dir / "employee.private.json", account.as_private_dict())
    if progress:
        progress("步骤 2/6：员工账号已准备", account.as_public_dict())

    oauth = generate_oauth_start(
        redirect_uri=cfg.codex_redirect_uri,
        client_id=cfg.codex_client_id,
        scope=cfg.codex_scope,
    )
    _write_json(cfg.artifact_dir / "oauth_start.public.json", _oauth_start_public(oauth))
    if progress:
        progress("步骤 3/6：Codex OAuth/PKCE 授权 URL 已生成", {"client_id": oauth.client_id, "redirect_uri": oauth.redirect_uri})

    flow = CompanySSOHttpFlow(
        company_sso_domain=sso_domain,
        timeout=cfg.timeout,
        proxy=cfg.proxy,
        artifact_dir=cfg.artifact_dir,
        logger=logger,
    )
    if progress:
        progress("步骤 4/6：执行公司 SSO 注册 + Codex OAuth 授权流程", None)
    generated_account = account.to_generated_account()
    token_config = flow.authorize_codex(oauth, generated_account)
    if not str(token_config.get("refresh_token") or "").strip():
        raise OAuthFlowError("OAuth token 响应缺少 refresh_token", stage="token_exchange", data={"token": redact(token_config)})
    token_public = public_token_result(token_config)
    _write_json(cfg.artifact_dir / "token.public.json", token_public)
    _write_json(cfg.artifact_dir / "token.json", token_config)
    if progress:
        progress("步骤 5/6：Codex token 获取完成", token_public)

    exports: dict[str, dict[str, Any]] = {}
    if cfg.selected_export_targets:
        record = _build_export_record(token_config, generated_account, cfg)
        exports = _export_record(cfg, logger, record, progress=progress)
    elif progress:
        progress("跳过导出", {"reason": "export_targets=none"})

    result = _result_payload(cfg, account, token_public, exports)
    _write_json(cfg.artifact_dir / "result.json", result)
    logger.write("run_success", result)
    if progress:
        progress("步骤 6/6：全部完成", {"artifact_dir": str(cfg.artifact_dir), "status": "success"})
    return result


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    try:
        args = parser.parse_args(argv)
        account = _account_from_args(args)
        cfg = _runtime_config_from_args(args)
        result = run(cfg, account, sso_domain=str(args.sso_domain or ""))
    except IdpTeamAutomationError as exc:
        payload = {"status": "failed", "stage": exc.stage, "error": str(exc), "retryable": exc.retryable, "data": redact(exc.data)}
        print(json.dumps(payload, ensure_ascii=False, indent=2, sort_keys=True, default=str), file=sys.stderr)
        return 1
    except Exception as exc:
        payload = {"status": "failed", "stage": "unexpected", "error": str(exc)}
        print(json.dumps(payload, ensure_ascii=False, indent=2, sort_keys=True, default=str), file=sys.stderr)
        return 1
    print(json.dumps(result, ensure_ascii=False, indent=2, sort_keys=True, default=str))
    return 0


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
