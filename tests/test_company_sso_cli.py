from __future__ import annotations

import json

import pytest

from lib import company_sso_cli
from lib.errors import OAuthFlowError


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
    payload = _parse_stderr_json(capsys.readouterr().err)
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
    payload = _parse_stderr_json(capsys.readouterr().err)
    assert payload["status"] == "failed"
    assert payload["stage"] == "config"
    assert message in payload["error"]


def test_idp_team_error_returns_redacted_stderr_json(monkeypatch, tmp_path, capsys):
    class FakeFlow:
        def __init__(self, **kwargs):
            pass

        def authorize_codex(self, oauth, account):
            raise OAuthFlowError(
                "authorization failed",
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
    payload = _parse_stderr_json(capsys.readouterr().err)
    assert payload["status"] == "failed"
    assert payload["stage"] == "company_sso_authorize"
    assert payload["retryable"] is True
    assert payload["data"] == {"email": "jane.smith@company.test", "password": "***REDACTED***"}
