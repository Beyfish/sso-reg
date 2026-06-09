from __future__ import annotations

import sys
from pathlib import Path

import pytest

from gui.server import GuiError, build_company_sso_command, redact_command, validate_payload


def test_gui_builds_domain_only_company_sso_command(tmp_path):
    command, env = build_company_sso_command(
        {
            "sso_domain": "hegiw77632.cloud-ip.cc",
            "seed": "smoke-001",
            "export_targets": "none",
            "timeout": "60",
        },
        tmp_path,
    )

    assert command[:2] == [sys.executable, str(Path.cwd() / "scripts" / "run_company_sso_codex.py")]
    assert "--sso-domain" in command
    assert "hegiw77632.cloud-ip.cc" in command
    assert "--email-domain" not in command
    assert "--email" not in command
    assert env == {}


def test_gui_frozen_command_preview_uses_embedded_runner(tmp_path, monkeypatch):
    import gui.server as server

    monkeypatch.setattr(server.sys, "frozen", True, raising=False)
    command, _env = build_company_sso_command(
        {
            "sso_domain": "hegiw77632.cloud-ip.cc",
            "seed": "smoke-001",
            "export_targets": "none",
        },
        tmp_path,
    )

    assert command[:2] == [sys.executable, "--run-company-sso"]
    assert "scripts" not in command[1].lower()


def test_gui_keeps_export_secrets_out_of_command(tmp_path):
    command, env = build_company_sso_command(
        {
            "sso_domain": "hegiw77632.cloud-ip.cc",
            "export_targets": "sub2api",
            "sub2api_url": "https://sub2api.example",
            "sub2api_email": "admin@example.com",
            "sub2api_password": "secret-password",
            "sub2api_group": "5",
        },
        tmp_path,
    )

    assert "secret-password" not in command
    assert env["SUB2API_PASSWORD"] == "secret-password"
    assert env["SUB2API_GROUP"] == "5"


def test_gui_redacts_explicit_employee_password(tmp_path):
    command, _env = build_company_sso_command(
        {
            "sso_domain": "hegiw77632.cloud-ip.cc",
            "export_targets": "none",
            "email": "new.user@hegiw77632.cloud-ip.cc",
            "password": "InitPass123!",
        },
        tmp_path,
    )

    redacted = redact_command(command)
    assert "InitPass123!" in command
    assert "InitPass123!" not in redacted
    assert "***REDACTED***" in redacted


@pytest.mark.parametrize(
    "payload",
    [
        {},
        {"sso_domain": "localhost", "export_targets": "none"},
        {"sso_domain": "hegiw77632.cloud-ip.cc", "export_targets": "bad"},
        {"sso_domain": "hegiw77632.cloud-ip.cc", "email": "not-email", "password": "x"},
    ],
)
def test_gui_rejects_invalid_payload(payload):
    with pytest.raises(GuiError):
        validate_payload(payload)
