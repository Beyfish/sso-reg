from __future__ import annotations

import json

import pytest

from lib import company_sso_cli
from lib.errors import OAuthFlowError
from lib.logging_utils import redact


def _parse_stdout_json(capsys):
    captured = capsys.readouterr()
    return json.loads(captured.out), captured


def _parse_stderr_json(stderr: str) -> dict:
    lines = stderr.splitlines()
    for idx, line in enumerate(lines):
        if line.strip() == "{":
            try:
                return json.loads("\n".join(lines[idx:]))
            except json.JSONDecodeError:
                continue
    raise AssertionError(stderr)


def test_dev_generate_writes_artifacts_and_success_stdout(monkeypatch, tmp_path, capsys):
    seen = {}

    class FakeFlow:
        def __init__(self, *, company_sso_domain, artifact_dir, logger, timeout, proxy, **kwargs):
            assert company_sso_domain == "sso.company.test"
            assert artifact_dir == tmp_path
            assert logger is not None
            assert timeout >= 1
            assert proxy == ""

        def authorize_codex(self, oauth, account):
            assert account.email.endswith("@company.test")
            assert account.password
            assert account.raw["username"].startswith("dev.user.")
            assert account.raw["employee_id"].startswith("DEV")
            seen["email"] = account.email
            return {
                "type": "codex",
                "email": account.email,
                "account_id": "acct_cli",
                "user_id": "user_cli",
                "access_token": "acc",
                "refresh_token": "ref",
                "id_token": "",
                "client_id": oauth.client_id,
                "expired": "2026-06-08T10:00:00Z",
                "last_refresh": "2026-06-08T09:00:00Z",
            }

    def fail_export(*args, **kwargs):
        raise AssertionError("export-targets=none should skip export")

    monkeypatch.setattr(company_sso_cli, "CompanySSOHttpFlow", FakeFlow)
    monkeypatch.setattr(company_sso_cli, "_export_record", fail_export)

    code = company_sso_cli.main(
        [
            "--sso-domain",
            "sso.company.test",
            "--dev-generate",
            "--email-domain",
            "company.test",
            "--seed",
            "cli-case",
            "--password-length",
            "16",
            "--artifact-dir",
            str(tmp_path),
            "--export-targets",
            "none",
            "--no-proxy",
        ]
    )

    assert code == 0
    stdout, _captured = _parse_stdout_json(capsys)
    assert stdout["status"] == "success"
    assert stdout["account"]["email"] == seen["email"]
    assert "password" not in stdout["account"]
    assert stdout["token"]["has_refresh_token"] is True
    assert stdout["exports"] == {}
    assert '"refresh_token": "ref"' not in json.dumps(stdout)

    employee_public = json.loads((tmp_path / "employee.public.json").read_text(encoding="utf-8"))
    employee_private = json.loads((tmp_path / "employee.private.json").read_text(encoding="utf-8"))
    token_private = json.loads((tmp_path / "token.json").read_text(encoding="utf-8"))
    oauth_public = json.loads((tmp_path / "oauth_start.public.json").read_text(encoding="utf-8"))
    result = json.loads((tmp_path / "result.json").read_text(encoding="utf-8"))

    assert "password" not in employee_public
    assert employee_private["password"]
    assert len(employee_private["password"]) == 16
    assert token_private["refresh_token"] == "ref"
    assert oauth_public["state"] == "***REDACTED***"
    assert "code_verifier" not in oauth_public
    assert result["status"] == "success"
    assert '"refresh_token": "ref"' not in json.dumps(result)
    assert (tmp_path / "network.jsonl").exists()


def test_explicit_employee_input_uses_defaults(monkeypatch, tmp_path, capsys):
    seen = {}

    class FakeFlow:
        def __init__(self, **kwargs):
            pass

        def authorize_codex(self, oauth, account):
            seen["raw"] = dict(account.raw)
            seen["email"] = account.email
            seen["password"] = account.password
            return {
                "type": "codex",
                "email": account.email,
                "account_id": "acct_explicit",
                "user_id": "",
                "access_token": "acc",
                "refresh_token": "ref",
                "id_token": "",
                "client_id": oauth.client_id,
            }

    monkeypatch.setattr(company_sso_cli, "CompanySSOHttpFlow", FakeFlow)
    monkeypatch.setattr(company_sso_cli, "_export_record", lambda *args, **kwargs: {})

    code = company_sso_cli.main(
        [
            "--sso-domain",
            "sso.company.test",
            "--email",
            "jane.smith@company.test",
            "--password",
            "InitPass123!",
            "--employee-id",
            "E-100",
            "--artifact-dir",
            str(tmp_path),
            "--export-targets",
            "none",
            "--no-proxy",
        ]
    )

    assert code == 0
    stdout, _captured = _parse_stdout_json(capsys)
    assert stdout["account"]["username"] == "jane.smith"
    assert stdout["account"]["first_name"] == "Jane"
    assert stdout["account"]["last_name"] == "Employee"
    assert stdout["account"]["employee_id"] == "E-100"
    assert seen["email"] == "jane.smith@company.test"
    assert seen["password"] == "InitPass123!"
    assert seen["raw"]["username"] == "jane.smith"


def test_dev_generate_requires_email_domain(tmp_path, capsys):
    code = company_sso_cli.main(
        [
            "--sso-domain",
            "sso.company.test",
            "--dev-generate",
            "--artifact-dir",
            str(tmp_path),
            "--export-targets",
            "none",
        ]
    )

    assert code == 1
    captured = capsys.readouterr()
    payload = _parse_stderr_json(captured.err)
    assert payload["status"] == "failed"
    assert payload["stage"] == "config"
    assert payload["retryable"] is False
    assert "email-domain" in payload["error"]


@pytest.mark.parametrize(
    "args, message",
    [
        (["--password", "InitPass123!"], "email"),
        (["--email", "jane.smith@company.test"], "password"),
    ],
)
def test_explicit_employee_input_requires_email_and_password(args, message, tmp_path, capsys):
    code = company_sso_cli.main(
        [
            "--sso-domain",
            "sso.company.test",
            "--artifact-dir",
            str(tmp_path),
            "--export-targets",
            "none",
            *args,
        ]
    )

    assert code == 1
    captured = capsys.readouterr()
    payload = _parse_stderr_json(captured.err)
    assert payload["status"] == "failed"
    assert payload["stage"] == "config"
    assert message in payload["error"]


def test_idp_team_error_returns_redacted_stderr_json(monkeypatch, tmp_path, capsys):
    class FakeFlow:
        def __init__(self, **kwargs):
            pass

        def authorize_codex(self, oauth, account):
            raise OAuthFlowError(
                "authorization failed password=PlainPass123! token=raw_token_123 code=raw_code_123",
                stage="company_sso_authorize",
                retryable=True,
                data={"email": account.email, "password": account.password},
            )

    monkeypatch.setattr(company_sso_cli, "CompanySSOHttpFlow", FakeFlow)

    code = company_sso_cli.main(
        [
            "--sso-domain",
            "sso.company.test",
            "--email",
            "jane.smith@company.test",
            "--password",
            "InitPass123!",
            "--artifact-dir",
            str(tmp_path),
            "--export-targets",
            "none",
        ]
    )

    assert code == 1
    captured = capsys.readouterr()
    payload = _parse_stderr_json(captured.err)
    assert payload["status"] == "failed"
    assert payload["stage"] == "company_sso_authorize"
    assert payload["retryable"] is True
    assert "***REDACTED***" in payload["error"]
    assert payload["data"] == {"email": "jane.smith@company.test", "password": "***REDACTED***"}
    assert "PlainPass123!" not in captured.err
    assert "raw_token_123" not in captured.err
    assert "raw_code_123" not in captured.err


def test_idp_team_error_redacts_json_dict_and_colon_secret_strings(monkeypatch, tmp_path, capsys):
    class FakeFlow:
        def __init__(self, **kwargs):
            pass

        def authorize_codex(self, oauth, account):
            raise OAuthFlowError(
                '{"refresh_token":"raw_ref","password":"raw_pw"} {\'access_token\': \'raw_acc\'} authorization: raw_auth code: raw_code',
                stage="company_sso_authorize",
                retryable=False,
            )

    monkeypatch.setattr(company_sso_cli, "CompanySSOHttpFlow", FakeFlow)

    code = company_sso_cli.main(
        [
            "--sso-domain",
            "sso.company.test",
            "--email",
            "jane.smith@company.test",
            "--password",
            "InitPass123!",
            "--artifact-dir",
            str(tmp_path),
            "--export-targets",
            "none",
        ]
    )

    assert code == 1
    captured = capsys.readouterr()
    payload = _parse_stderr_json(captured.err)
    assert payload["stage"] == "company_sso_authorize"
    assert "***REDACTED***" in payload["error"]
    for secret in ("raw_ref", "raw_pw", "raw_acc", "raw_auth", "raw_code"):
        assert secret not in captured.err


def test_unexpected_error_redacts_secret_in_stderr(monkeypatch, tmp_path, capsys):
    class FakeFlow:
        def __init__(self, **kwargs):
            pass

        def authorize_codex(self, oauth, account):
            raise RuntimeError("boom password=PlainPass123! token=raw_token_123")

    monkeypatch.setattr(company_sso_cli, "CompanySSOHttpFlow", FakeFlow)

    code = company_sso_cli.main(
        [
            "--sso-domain",
            "sso.company.test",
            "--email",
            "jane.smith@company.test",
            "--password",
            "InitPass123!",
            "--artifact-dir",
            str(tmp_path),
            "--export-targets",
            "none",
        ]
    )

    assert code == 1
    captured = capsys.readouterr()
    payload = _parse_stderr_json(captured.err)
    assert payload["status"] == "failed"
    assert payload["stage"] == "unexpected"
    assert "***REDACTED***" in payload["error"]
    assert "PlainPass123!" not in captured.err
    assert "raw_token_123" not in captured.err


def test_unexpected_error_redacts_json_dict_and_colon_secret_strings(monkeypatch, tmp_path, capsys):
    class FakeFlow:
        def __init__(self, **kwargs):
            pass

        def authorize_codex(self, oauth, account):
            raise RuntimeError(
                '{"id_token":"raw_id"} {\'cpa_management_key\': \'raw_key\'} cookie: raw_cookie password: raw_pw'
            )

    monkeypatch.setattr(company_sso_cli, "CompanySSOHttpFlow", FakeFlow)

    code = company_sso_cli.main(
        [
            "--sso-domain",
            "sso.company.test",
            "--email",
            "jane.smith@company.test",
            "--password",
            "InitPass123!",
            "--artifact-dir",
            str(tmp_path),
            "--export-targets",
            "none",
        ]
    )

    assert code == 1
    captured = capsys.readouterr()
    payload = _parse_stderr_json(captured.err)
    assert payload["stage"] == "unexpected"
    assert "***REDACTED***" in payload["error"]
    for secret in ("raw_id", "raw_key", "raw_cookie", "raw_pw"):
        assert secret not in captured.err


def test_redact_preserves_business_state_but_redacts_inline_oauth_state():
    assert redact({"state": "healthy"}) == {"state": "healthy"}
    assert redact("https://example.test/callback?state=raw_state&code=raw_code") == (
        "https://example.test/callback?state=***REDACTED***&code=***REDACTED***"
    )
    assert redact("state=raw_state") == "state=***REDACTED***"


def test_network_jsonl_redacts_oauth_url_secrets(monkeypatch, tmp_path, capsys):
    class FakeFlow:
        def __init__(self, *, logger, **kwargs):
            self.logger = logger

        def authorize_codex(self, oauth, account):
            self.logger.write(
                "flow_url",
                {
                    "url": "https://auth.example/callback?state=raw_state_123&code=raw_code_123&token=raw_token_123&password=raw_pw_123&authorization=raw_auth_123&cookie=raw_cookie_123"
                },
            )
            return {
                "type": "codex",
                "email": account.email,
                "account_id": "acct_log",
                "user_id": "",
                "access_token": "acc",
                "refresh_token": "ref",
                "id_token": "",
                "client_id": oauth.client_id,
            }

    monkeypatch.setattr(company_sso_cli, "CompanySSOHttpFlow", FakeFlow)
    monkeypatch.setattr(company_sso_cli, "_export_record", lambda *args, **kwargs: {})

    code = company_sso_cli.main(
        [
            "--sso-domain",
            "sso.company.test",
            "--email",
            "jane.smith@company.test",
            "--password",
            "InitPass123!",
            "--artifact-dir",
            str(tmp_path),
            "--export-targets",
            "none",
        ]
    )

    assert code == 0
    capsys.readouterr()
    text = (tmp_path / "network.jsonl").read_text(encoding="utf-8")
    assert "***REDACTED***" in text
    assert "raw_state_123" not in text
    assert "raw_code_123" not in text
    assert "raw_token_123" not in text
    assert "raw_pw_123" not in text
    assert "raw_auth_123" not in text
    assert "raw_cookie_123" not in text


def test_runtime_config_preserves_export_env_overrides(monkeypatch, tmp_path):
    artifact_dir = tmp_path / "env-artifacts"
    monkeypatch.setenv("ARTIFACT_DIR", str(artifact_dir))
    monkeypatch.setenv("SUB2API_CONCURRENCY", "17")
    monkeypatch.setenv("SUB2API_PRIORITY", "3")
    monkeypatch.setenv("SUB2API_RATE_MULTIPLIER", "2.5")
    monkeypatch.setenv("CPA_PRIORITY", "4")

    args = company_sso_cli.build_parser().parse_args(
        [
            "--sso-domain",
            "sso.company.test",
            "--email",
            "jane.smith@company.test",
            "--password",
            "InitPass123!",
            "--export-targets",
            "none",
        ]
    )

    cfg = company_sso_cli._runtime_config_from_args(args)

    assert cfg.artifact_dir == artifact_dir
    assert cfg.sub2api_concurrency == 17
    assert cfg.sub2api_priority == 3
    assert cfg.sub2api_rate_multiplier == 2.5
    assert cfg.cpa_priority == 4


def test_export_targets_dispatch_builds_company_source_record(monkeypatch, tmp_path, capsys):
    calls = []

    class FakeFlow:
        def __init__(self, **kwargs):
            pass

        def authorize_codex(self, oauth, account):
            return {
                "type": "codex",
                "email": account.email,
                "account_id": "acct_export",
                "user_id": "user_export",
                "access_token": "acc",
                "refresh_token": "ref",
                "id_token": "",
                "client_id": oauth.client_id,
            }

    def fake_export(cfg, logger, record, *, progress=None):
        calls.append(record)
        return {"cpa": {"status": "success", "email": record.email}}

    monkeypatch.setattr(company_sso_cli, "CompanySSOHttpFlow", FakeFlow)
    monkeypatch.setattr(company_sso_cli, "_export_record", fake_export)

    code = company_sso_cli.main(
        [
            "--sso-domain",
            "sso.company.test",
            "--email",
            "jane.smith@company.test",
            "--password",
            "InitPass123!",
            "--artifact-dir",
            str(tmp_path),
            "--export-targets",
            "cpa",
            "--cpa-url",
            "https://cpa.example",
            "--cpa-management-key",
            "mgmt",
        ]
    )

    assert code == 0
    stdout, _captured = _parse_stdout_json(capsys)
    assert stdout["exports"]["cpa"]["status"] == "success"
    assert len(calls) == 1
    record = calls[0]
    assert record.email == "jane.smith@company.test"
    assert record.secret["refresh_token"] == "ref"
    assert record.metadata["source"] == "company_sso_codex"


@pytest.mark.parametrize(
    "args, message",
    [
        (["--email", "not-an-email", "--password", "InitPass123!"], "email"),
        (["--email", "jane.smith@company.test", "--password", "InitPass123!", "--username", "  "], "username"),
    ],
)
def test_explicit_employee_input_validates_email_and_username(monkeypatch, args, message, tmp_path, capsys):
    class FakeFlow:
        def __init__(self, **kwargs):
            raise AssertionError("invalid employee input should fail before flow starts")

    monkeypatch.setattr(company_sso_cli, "CompanySSOHttpFlow", FakeFlow)

    code = company_sso_cli.main(
        [
            "--sso-domain",
            "sso.company.test",
            "--artifact-dir",
            str(tmp_path),
            "--export-targets",
            "none",
            *args,
        ]
    )

    assert code == 1
    payload = _parse_stderr_json(capsys.readouterr().err)
    assert payload["status"] == "failed"
    assert payload["stage"] == "config"
    assert message in payload["error"]
