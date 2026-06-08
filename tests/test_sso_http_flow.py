# Copyright (c) 2026 Idp Team Automation.
# iDP 协议作者：@该隐；注册机作者：@朴圣佑。
# 二开请保留版权；二开不保留版权，以后写代码都是bug。

from __future__ import annotations

import json
from dataclasses import dataclass

import pytest

from lib.codex_oauth import OAuthStart
from lib.errors import OAuthFlowError
from lib.idp_client import GeneratedAccount
from lib.sso_http_flow import SSOHttpFlow, parse_html_forms, parse_html_links, populate_account_form


@dataclass
class FakeResponse:
    status_code: int
    url: str
    headers: dict
    text: str = ""
    payload: dict | None = None

    def json(self):
        if self.payload is None:
            raise ValueError("no json")
        return self.payload


class FakeSession:
    def __init__(self):
        self.calls = []

    def request(self, method, url, **kwargs):
        self.calls.append((method, url, kwargs))
        if url == "https://idp.example/start":
            return FakeResponse(200, url, {}, '<form action="/login" method="post"><input name="email"><input name="password" type="password"><button name="go" value="1"></button></form>')
        if url == "https://idp.example/login":
            assert kwargs["data"]["email"] == "u@example.com"
            assert kwargs["data"]["password"] == "Pw123!"
            return FakeResponse(302, url, {"Location": "https://idp.example/done"})
        if url == "https://idp.example/done":
            return FakeResponse(200, url, {}, "ok")
        if url.startswith("https://auth.openai.com/oauth/authorize"):
            return FakeResponse(302, url, {"Location": "http://localhost:1455/auth/callback?code=code_1&state=state_1"})
        if url == "https://auth.openai.com/oauth/token":
            return FakeResponse(200, url, {}, json.dumps({"access_token": "acc", "refresh_token": "ref", "id_token": "", "expires_in": 3600}), {"access_token": "acc", "refresh_token": "ref", "id_token": "", "expires_in": 3600})
        raise AssertionError(url)


def test_parse_and_populate_form():
    forms, links, meta = parse_html_forms('<form action="/x" method="post"><input name="username"><input name="passwd" type="password"></form>')
    assert len(forms) == 1
    account = GeneratedAccount(id=1, email="u@example.com", password="Pw123!")
    data = populate_account_form(forms[0], account)
    assert data["username"] == "u@example.com"
    assert data["passwd"] == "Pw123!"


def test_sso_http_flow_mock_end_to_end(tmp_path):
    session = FakeSession()
    flow = SSOHttpFlow(session=session, artifact_dir=tmp_path)
    account = GeneratedAccount(id=1, email="u@example.com", password="Pw123!")
    oauth = OAuthStart(
        auth_url="https://auth.openai.com/oauth/authorize?state=state_1",
        state="state_1",
        code_verifier="verifier",
        redirect_uri="http://localhost:1455/auth/callback",
        client_id="client_1",
        scope="openid",
    )
    token = flow.run(start_url="https://idp.example/start", oauth=oauth, account=account)
    assert token["refresh_token"] == "ref"
    assert any(call[1] == "https://auth.openai.com/oauth/token" for call in session.calls)


def test_parse_html_links_includes_visible_text():
    links = parse_html_links(
        '<html><body><a href="/login">Login</a><a href="/register"><span>注册新员工</span></a></body></html>'
    )

    assert [(item.href, item.text) for item in links] == [
        ("/login", "Login"),
        ("/register", "注册新员工"),
    ]


def test_parse_html_forms_captures_unchecked_checkbox_names():
    forms, _links, _meta = parse_html_forms(
        '<form action="/register" method="post">'
        '<input type="hidden" name="csrf" value="abc">'
        '<input type="checkbox" name="terms" value="yes">'
        '<input type="checkbox" name="newsletter" value="1" checked>'
        "</form>"
    )

    assert forms[0].fields["csrf"] == "abc"
    assert forms[0].fields["newsletter"] == "1"
    assert forms[0].checkbox_fields["terms"] == "yes"


def test_parse_html_links_preserves_adjacent_nested_text():
    links = parse_html_links('<a href="/x">Sign<strong>Up</strong></a>')

    assert [(item.href, item.text) for item in links] == [("/x", "SignUp")]


def test_parse_html_links_normalizes_whitespace():
    links = parse_html_links('<a href="/x">Sign\n Up</a>')

    assert [(item.href, item.text) for item in links] == [("/x", "Sign Up")]


def test_parse_html_forms_defaults_unchecked_checkbox_missing_value_to_on():
    forms, _links, _meta = parse_html_forms(
        '<form><input type="checkbox" name="terms"></form>'
    )

    assert forms[0].checkbox_fields["terms"] == "on"


def test_parse_html_forms_preserves_checked_checkbox_missing_value_as_empty():
    forms, _links, _meta = parse_html_forms(
        '<form><input type="checkbox" name="newsletter" checked></form>'
    )

    assert forms[0].fields["newsletter"] == ""


def test_parse_html_forms_preserves_radio_checked_only():
    forms, _links, _meta = parse_html_forms(
        '<form>'
        '<input type="radio" name="plan" value="basic">'
        '<input type="radio" name="plan" value="pro" checked>'
        "</form>"
    )

    assert forms[0].fields["plan"] == "pro"
    assert forms[0].checkbox_fields == {}


def test_parse_html_forms_returns_links_as_strings():
    _forms, links, _meta = parse_html_forms(
        '<html><body><a href="/login">Login</a><a href="/register">Register</a></body></html>'
    )

    assert links == ["/login", "/register"]
    assert all(isinstance(item, str) for item in links)


def test_drive_until_callback_allows_custom_page_handler(tmp_path):
    class HookSession:
        def request(self, method, url, **kwargs):
            if url == "https://auth.example/start":
                return FakeResponse(200, "https://custom.example/page", {}, "<html>custom</html>")
            if url == "https://auth.openai.com/oauth/token":
                return FakeResponse(
                    200,
                    url,
                    {},
                    json.dumps({"access_token": "acc", "refresh_token": "ref", "id_token": "", "expires_in": 3600}),
                    {"access_token": "acc", "refresh_token": "ref", "id_token": "", "expires_in": 3600},
                )
            raise AssertionError(url)

    class HookFlow(SSOHttpFlow):
        def _handle_custom_page(self, response, account, stage):
            if response.url == "https://custom.example/page":
                return "http://localhost:1455/auth/callback?code=hook_code&state=hook_state"
            return None

    flow = HookFlow(session=HookSession(), artifact_dir=tmp_path)
    account = GeneratedAccount(id=0, email="u@example.com", password="pw")
    oauth = OAuthStart(
        auth_url="https://auth.example/start",
        state="hook_state",
        code_verifier="verifier",
        redirect_uri="http://localhost:1455/auth/callback",
        client_id="client_1",
        scope="openid",
    )

    token = flow.authorize_codex(oauth, account)

    assert token["refresh_token"] == "ref"


def test_custom_page_handler_empty_string_falls_through_to_unhandled_page(tmp_path):
    class EmptyHookSession:
        def request(self, method, url, **kwargs):
            if url == "https://auth.example/start":
                return FakeResponse(200, "https://custom.example/page", {}, "<html>custom</html>")
            raise AssertionError(url)

    class EmptyHookFlow(SSOHttpFlow):
        def _handle_custom_page(self, response, account, stage):
            return ""

    flow = EmptyHookFlow(session=EmptyHookSession(), artifact_dir=tmp_path)
    account = GeneratedAccount(id=0, email="u@example.com", password="pw")
    oauth = OAuthStart(
        auth_url="https://auth.example/start",
        state="hook_state",
        code_verifier="verifier",
        redirect_uri="http://localhost:1455/auth/callback",
        client_id="client_1",
        scope="openid",
    )

    with pytest.raises(OAuthFlowError) as excinfo:
        flow.authorize_codex(oauth, account)

    assert excinfo.value.stage == "codex_authorize"
    assert "无法自动处理的页面" in str(excinfo.value)


def test_custom_page_handler_rejects_unsupported_return_type(tmp_path):
    class BadHookSession:
        def request(self, method, url, **kwargs):
            if url == "https://auth.example/start":
                return FakeResponse(200, "https://custom.example/page", {}, "<html>custom</html>")
            raise AssertionError(url)

    class BadHookFlow(SSOHttpFlow):
        def _handle_custom_page(self, response, account, stage):
            return {"url": "http://localhost:1455/auth/callback?code=hook_code&state=hook_state"}

    flow = BadHookFlow(session=BadHookSession(), artifact_dir=tmp_path)
    account = GeneratedAccount(id=0, email="u@example.com", password="pw")
    oauth = OAuthStart(
        auth_url="https://auth.example/start",
        state="hook_state",
        code_verifier="verifier",
        redirect_uri="http://localhost:1455/auth/callback",
        client_id="client_1",
        scope="openid",
    )

    with pytest.raises(OAuthFlowError) as excinfo:
        flow.authorize_codex(oauth, account)

    assert excinfo.value.stage == "codex_authorize"
    assert excinfo.value.data["return_type"] == "dict"
