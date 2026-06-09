from __future__ import annotations

import pytest

from gui.native_app import DEFAULT_SSO_DOMAIN, command_preview, default_payload
from gui.server import GuiError


def test_native_default_payload_is_domain_only():
    payload = default_payload()

    assert payload["sso_domain"] == DEFAULT_SSO_DOMAIN
    assert payload["export_targets"] == "none"
    assert "email" not in payload


def test_native_command_preview_redacts_employee_password():
    payload = default_payload()
    payload.update(
        {
            "email": "new.user@hegiw77632.cloud-ip.cc",
            "password": "InitPass123!",
        }
    )

    preview = command_preview(payload)

    assert "InitPass123!" not in preview
    assert "***REDACTED***" in preview


def test_native_command_preview_rejects_invalid_domain():
    payload = default_payload()
    payload["sso_domain"] = "localhost"

    with pytest.raises(GuiError):
        command_preview(payload)
