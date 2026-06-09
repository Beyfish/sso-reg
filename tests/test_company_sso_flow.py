from __future__ import annotations

import json
from dataclasses import dataclass

import pytest

from lib.codex_oauth import OAuthStart
from lib.company_account import CompanyAccount
from lib.company_sso_flow import CompanySSOHttpFlow
from lib.errors import OAuthFlowError


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


class CompanyRegisterSession:
    def __init__(self):
        self.calls = []

    def request(self, method, url, **kwargs):
        self.calls.append((method, url, kwargs))
        if url == "https://auth.example/oauth":
            return FakeResponse(
                200,
                "https://sso.company.test/login",
                {},
                '<html><body><a href="/register">注册新员工</a></body></html>',
            )
        if method == "GET" and url == "https://sso.company.test/register":
            return FakeResponse(
                200,
                url,
                {},
                '<form action="/register" method="post">'
                '<input name="csrf" value="abc">'
                '<input name="username">'
                '<input name="email">'
                '<input name="first_name">'
                '<input name="last_name">'
                '<input type="password" name="password">'
                '<input type="password" name="confirm_password">'
                '<input type="checkbox" name="terms" value="yes">'
                '<button name="submit" value="1">Register</button>'
                "</form>",
            )
        raise AssertionError((method, url, kwargs))


def test_company_sso_registers_and_exchanges_token(tmp_path):
    class Session(CompanyRegisterSession):
        def request(self, method, url, **kwargs):
            if method == "POST" and url == "https://sso.company.test/register":
                body = kwargs["data"]
                assert body["csrf"] == "abc"
                assert body["username"] == "alice.zhang"
                assert body["email"] == "alice.zhang@company.test"
                assert body["first_name"] == "Alice"
                assert body["last_name"] == "Zhang"
                assert body["password"] == "InitPass123!"
                assert body["confirm_password"] == "InitPass123!"
                assert body["terms"] == "yes"
                return FakeResponse(
                    302,
                    url,
                    {"Location": "http://localhost:1455/auth/callback?code=company_code&state=company_state"},
                )
            if url == "https://auth.openai.com/oauth/token":
                return FakeResponse(
                    200,
                    url,
                    {},
                    json.dumps({"access_token": "acc", "refresh_token": "ref", "id_token": "", "expires_in": 3600}),
                    {"access_token": "acc", "refresh_token": "ref", "id_token": "", "expires_in": 3600},
                )
            return super().request(method, url, **kwargs)

    account = CompanyAccount(
        username="alice.zhang",
        email="alice.zhang@company.test",
        password="InitPass123!",
        first_name="Alice",
        last_name="Zhang",
    )
    flow = CompanySSOHttpFlow(
        company_sso_domain="sso.company.test",
        session=Session(),
        artifact_dir=tmp_path,
    )
    oauth = OAuthStart(
        auth_url="https://auth.example/oauth",
        state="company_state",
        code_verifier="verifier",
        redirect_uri="http://localhost:1455/auth/callback",
        client_id="client_1",
        scope="openid",
    )

    token = flow.authorize_codex(oauth, account.to_generated_account())

    assert token["refresh_token"] == "ref"


def test_company_sso_refuses_to_register_on_untrusted_host(tmp_path):
    class Session:
        def request(self, method, url, **kwargs):
            return FakeResponse(
                200,
                "https://evil.example/login",
                {},
                '<a href="/register">注册新员工</a>',
            )

    account = CompanyAccount(
        username="alice",
        email="alice@company.test",
        password="InitPass123!",
        first_name="Alice",
        last_name="Zhang",
    )
    flow = CompanySSOHttpFlow(
        company_sso_domain="sso.company.test",
        session=Session(),
        artifact_dir=tmp_path,
    )
    oauth = OAuthStart(
        auth_url="https://auth.example/oauth",
        state="state",
        code_verifier="verifier",
        redirect_uri="http://localhost:1455/auth/callback",
    )

    with pytest.raises(OAuthFlowError):
        flow.authorize_codex(oauth, account.to_generated_account())


def test_company_sso_does_not_submit_untrusted_login_form(tmp_path):
    class Session:
        def __init__(self):
            self.calls = []

        def request(self, method, url, **kwargs):
            self.calls.append((method, url, kwargs))
            if method == "POST" and url == "https://evil.example/login":
                raise AssertionError("untrusted host received credentials")
            return FakeResponse(
                200,
                "https://evil.example/login",
                {},
                '<form action="/login" method="post">'
                '<input name="email">'
                '<input type="password" name="password">'
                '<button name="submit" value="1">Login</button>'
                "</form>",
            )

    session = Session()
    account = CompanyAccount(
        username="alice",
        email="alice@company.test",
        password="InitPass123!",
        first_name="Alice",
        last_name="Zhang",
    )
    flow = CompanySSOHttpFlow(
        company_sso_domain="sso.company.test",
        session=session,
        artifact_dir=tmp_path,
    )
    oauth = OAuthStart(
        auth_url="https://auth.example/oauth",
        state="state",
        code_verifier="verifier",
        redirect_uri="http://localhost:1455/auth/callback",
    )

    with pytest.raises(OAuthFlowError):
        flow.authorize_codex(oauth, account.to_generated_account())

    assert not any(method == "POST" and url == "https://evil.example/login" for method, url, _kwargs in session.calls)


def test_company_sso_allows_openai_identifier_page_before_company_registration(tmp_path):
    class Session:
        def __init__(self):
            self.calls = []

        def request(self, method, url, **kwargs):
            self.calls.append((method, url, kwargs))
            if url == "https://auth.example/oauth":
                return FakeResponse(
                    200,
                    "https://auth.openai.com/log-in",
                    {},
                    '<form action="/log-in" method="post">'
                    '<input name="email">'
                    '<button name="submit" value="1">Continue</button>'
                    "</form>",
                )
            if method == "POST" and url == "https://auth.openai.com/api/accounts/authorize/continue":
                assert kwargs["json"]["username"]["value"] == "alice@company.test"
                assert kwargs["json"]["username"]["kind"] == "email"
                return FakeResponse(
                    302,
                    url,
                    {"Location": "https://sso.company.test/login"},
                )
            if method == "GET" and url == "https://sso.company.test/login":
                return FakeResponse(
                    200,
                    url,
                    {},
                    '<a href="/register">注册新员工</a>',
                )
            if method == "GET" and url == "https://sso.company.test/register":
                return FakeResponse(
                    200,
                    url,
                    {},
                    '<form action="/register" method="post">'
                    '<input name="email">'
                    '<input type="password" name="password">'
                    '<input type="password" name="confirm_password">'
                    '<button name="submit" value="1">Register</button>'
                    "</form>",
                )
            if method == "POST" and url == "https://sso.company.test/register":
                body = kwargs["data"]
                assert body["email"] == "alice@company.test"
                assert body["password"] == "InitPass123!"
                assert body["confirm_password"] == "InitPass123!"
                return FakeResponse(
                    302,
                    url,
                    {"Location": "http://localhost:1455/auth/callback?code=company_code&state=company_state"},
                )
            if url == "https://auth.openai.com/oauth/token":
                return FakeResponse(
                    200,
                    url,
                    {},
                    json.dumps({"access_token": "acc", "refresh_token": "ref", "id_token": "", "expires_in": 3600}),
                    {"access_token": "acc", "refresh_token": "ref", "id_token": "", "expires_in": 3600},
                )
            raise AssertionError((method, url, kwargs))

    session = Session()
    account = CompanyAccount(
        username="alice",
        email="alice@company.test",
        password="InitPass123!",
        first_name="Alice",
        last_name="Zhang",
    )
    flow = CompanySSOHttpFlow(
        company_sso_domain="sso.company.test",
        session=session,
        artifact_dir=tmp_path,
    )
    oauth = OAuthStart(
        auth_url="https://auth.example/oauth",
        state="company_state",
        code_verifier="verifier",
        redirect_uri="http://localhost:1455/auth/callback",
    )

    token = flow.authorize_codex(oauth, account.to_generated_account())

    assert token["refresh_token"] == "ref"
    assert any(
        method == "POST"
        and url == "https://auth.openai.com/api/accounts/authorize/continue"
        and kwargs["json"]["username"]["value"] == "alice@company.test"
        for method, url, kwargs in session.calls
    )
    assert not any(method == "POST" and url == "https://auth.openai.com/log-in" for method, url, _kwargs in session.calls)


def test_company_sso_allows_openai_sso_selector_before_company_registration(tmp_path):
    class Session:
        def __init__(self):
            self.calls = []

        def request(self, method, url, **kwargs):
            self.calls.append((method, url, kwargs))
            if url == "https://auth.example/oauth":
                return FakeResponse(
                    200,
                    "https://auth.openai.com/log-in",
                    {},
                    '<form action="/log-in" method="post">'
                    '<input name="email">'
                    '<button name="submit" value="1">Continue</button>'
                    "</form>",
                )
            if method == "POST" and url == "https://auth.openai.com/api/accounts/authorize/continue":
                assert kwargs["json"]["username"]["value"] == "alice@company.test"
                return FakeResponse(
                    200,
                    url,
                    {},
                    json.dumps({"continue_url": "https://auth.openai.com/sso"}),
                    {"continue_url": "https://auth.openai.com/sso"},
                )
            if method == "GET" and url == "https://auth.openai.com/sso":
                return FakeResponse(
                    200,
                    url,
                    {},
                    '<html><title>How do you want to log in? - OpenAI</title>'
                    '<form action="/sso/select" method="post">'
                    '<input type="hidden" name="connection" value="company">'
                    '<button name="submit" value="sso">Continue with SSO</button>'
                    "</form></html>",
                )
            if method == "POST" and url == "https://auth.openai.com/sso/select":
                assert kwargs["data"]["connection"] == "company"
                return FakeResponse(302, url, {"Location": "https://sso.company.test/login"})
            if method == "GET" and url == "https://sso.company.test/login":
                return FakeResponse(200, url, {}, '<a href="/register">注册新员工</a>')
            if method == "GET" and url == "https://sso.company.test/register":
                return FakeResponse(
                    200,
                    url,
                    {},
                    '<form action="/register" method="post">'
                    '<input name="email">'
                    '<input type="password" name="password">'
                    '<input type="password" name="confirm_password">'
                    '<button name="submit" value="1">Register</button>'
                    "</form>",
                )
            if method == "POST" and url == "https://sso.company.test/register":
                body = kwargs["data"]
                assert body["email"] == "alice@company.test"
                assert body["password"] == "InitPass123!"
                assert body["confirm_password"] == "InitPass123!"
                return FakeResponse(
                    302,
                    url,
                    {"Location": "http://localhost:1455/auth/callback?code=company_code&state=company_state"},
                )
            if url == "https://auth.openai.com/oauth/token":
                return FakeResponse(
                    200,
                    url,
                    {},
                    json.dumps({"access_token": "acc", "refresh_token": "ref", "id_token": "", "expires_in": 3600}),
                    {"access_token": "acc", "refresh_token": "ref", "id_token": "", "expires_in": 3600},
                )
            raise AssertionError((method, url, kwargs))

    session = Session()
    account = CompanyAccount(
        username="alice",
        email="alice@company.test",
        password="InitPass123!",
        first_name="Alice",
        last_name="Zhang",
    )
    flow = CompanySSOHttpFlow(
        company_sso_domain="sso.company.test",
        session=session,
        artifact_dir=tmp_path,
    )
    oauth = OAuthStart(
        auth_url="https://auth.example/oauth",
        state="company_state",
        code_verifier="verifier",
        redirect_uri="http://localhost:1455/auth/callback",
    )

    token = flow.authorize_codex(oauth, account.to_generated_account())

    visited_urls = [url for _method, url, _kwargs in session.calls]
    assert token["refresh_token"] == "ref"
    assert "https://auth.openai.com/sso" in visited_urls
    assert "https://sso.company.test/login" in visited_urls
    assert any(method == "POST" and url == "https://auth.openai.com/sso/select" for method, url, _kwargs in session.calls)
    assert any(method == "POST" and url == "https://sso.company.test/register" for method, url, _kwargs in session.calls)


def test_company_sso_uses_authorize_continue_for_openai_sso_selector_bootstrap(tmp_path):
    class Session:
        def __init__(self):
            self.calls = []
            self.authorize_continue_calls = 0

        def request(self, method, url, **kwargs):
            self.calls.append((method, url, kwargs))
            if url == "https://auth.example/oauth":
                return FakeResponse(
                    200,
                    "https://auth.openai.com/log-in",
                    {},
                    '<form action="/log-in" method="post">'
                    '<input name="email">'
                    '<button name="submit" value="1">Continue</button>'
                    "</form>",
                )
            if method == "POST" and url == "https://auth.openai.com/api/accounts/authorize/continue":
                self.authorize_continue_calls += 1
                body = kwargs["json"]
                if self.authorize_continue_calls == 1:
                    assert body == {
                        "username": {"value": "alice@company.test", "kind": "email"},
                        "screen_hint": "login_or_signup",
                    }
                    return FakeResponse(
                        200,
                        url,
                        {},
                        json.dumps({"continue_url": "https://auth.openai.com/sso"}),
                        {"continue_url": "https://auth.openai.com/sso"},
                    )
                assert body == {"connection": "conn_company", "connection_provider": 2}
                return FakeResponse(
                    200,
                    url,
                    {},
                    json.dumps({"continue_url": "https://sso.company.test/login"}),
                    {"continue_url": "https://sso.company.test/login"},
                )
            if method == "GET" and url == "https://auth.openai.com/sso":
                return FakeResponse(
                    200,
                    url,
                    {},
                    '<html><title>How do you want to log in? - OpenAI</title>'
                    '<form method="post">'
                    '<input type="hidden" name="username" value="alice@company.test">'
                    '<input type="hidden" name="screen_hint" value="login_or_signup">'
                    '<button name="ssoConnection" '
                    'value=\'{"connection_name":"conn_company","title":"codex","connection_provider":2}\'>'
                    "Continue with SSO</button>"
                    "</form></html>",
                )
            if method == "POST" and url == "https://auth.openai.com/sso":
                raise AssertionError("OpenAI SSO selector must not receive account password")
            if method == "GET" and url == "https://sso.company.test/login":
                return FakeResponse(200, url, {}, '<a href="/register">注册新员工</a>')
            if method == "GET" and url == "https://sso.company.test/register":
                return FakeResponse(
                    200,
                    url,
                    {},
                    '<form action="/register" method="post">'
                    '<input name="email">'
                    '<input type="password" name="password">'
                    '<input type="password" name="confirm_password">'
                    '<button name="submit" value="1">Register</button>'
                    "</form>",
                )
            if method == "POST" and url == "https://sso.company.test/register":
                body = kwargs["data"]
                assert body["email"] == "alice@company.test"
                assert body["password"] == "InitPass123!"
                assert body["confirm_password"] == "InitPass123!"
                return FakeResponse(
                    302,
                    url,
                    {"Location": "http://localhost:1455/auth/callback?code=company_code&state=company_state"},
                )
            if url == "https://auth.openai.com/oauth/token":
                return FakeResponse(
                    200,
                    url,
                    {},
                    json.dumps({"access_token": "acc", "refresh_token": "ref", "id_token": "", "expires_in": 3600}),
                    {"access_token": "acc", "refresh_token": "ref", "id_token": "", "expires_in": 3600},
                )
            raise AssertionError((method, url, kwargs))

    session = Session()
    account = CompanyAccount(
        username="alice",
        email="alice@company.test",
        password="InitPass123!",
        first_name="Alice",
        last_name="Zhang",
    )
    flow = CompanySSOHttpFlow(
        company_sso_domain="sso.company.test",
        session=session,
        artifact_dir=tmp_path,
    )
    oauth = OAuthStart(
        auth_url="https://auth.example/oauth",
        state="company_state",
        code_verifier="verifier",
        redirect_uri="http://localhost:1455/auth/callback",
    )

    token = flow.authorize_codex(oauth, account.to_generated_account())

    assert token["refresh_token"] == "ref"
    assert session.authorize_continue_calls == 2
    assert not any(method == "POST" and url == "https://auth.openai.com/sso" for method, url, _kwargs in session.calls)


def test_company_sso_visits_register_before_login_link(tmp_path):
    class Session:
        def __init__(self):
            self.calls = []

        def request(self, method, url, **kwargs):
            self.calls.append((method, url, kwargs))
            if url == "https://auth.example/oauth":
                return FakeResponse(
                    200,
                    "https://sso.company.test/start",
                    {},
                    '<a href="/login">Login</a><a href="/register">注册新员工</a>',
                )
            if method == "GET" and url == "https://sso.company.test/register":
                return FakeResponse(
                    200,
                    url,
                    {},
                    '<form action="/register" method="post">'
                    '<input name="email">'
                    '<input type="password" name="password">'
                    '<button name="submit" value="1">Register</button>'
                    "</form>",
                )
            if method == "POST" and url == "https://sso.company.test/register":
                return FakeResponse(
                    302,
                    url,
                    {"Location": "http://localhost:1455/auth/callback?code=company_code&state=company_state"},
                )
            if url == "https://auth.openai.com/oauth/token":
                return FakeResponse(
                    200,
                    url,
                    {},
                    json.dumps({"access_token": "acc", "refresh_token": "ref", "id_token": "", "expires_in": 3600}),
                    {"access_token": "acc", "refresh_token": "ref", "id_token": "", "expires_in": 3600},
                )
            raise AssertionError((method, url, kwargs))

    session = Session()
    account = CompanyAccount(
        username="alice",
        email="alice@company.test",
        password="InitPass123!",
        first_name="Alice",
        last_name="Zhang",
    )
    flow = CompanySSOHttpFlow(
        company_sso_domain="sso.company.test",
        session=session,
        artifact_dir=tmp_path,
    )
    oauth = OAuthStart(
        auth_url="https://auth.example/oauth",
        state="company_state",
        code_verifier="verifier",
        redirect_uri="http://localhost:1455/auth/callback",
    )

    token = flow.authorize_codex(oauth, account.to_generated_account())

    visited_urls = [url for _method, url, _kwargs in session.calls]
    assert token["refresh_token"] == "ref"
    assert "https://sso.company.test/register" in visited_urls
    assert "https://sso.company.test/login" not in visited_urls


def test_company_sso_allows_workos_saml_redirect_host_before_registration(tmp_path):
    class Session:
        def __init__(self):
            self.calls = []

        def request(self, method, url, **kwargs):
            self.calls.append((method, url, kwargs))
            if url == "https://auth.example/oauth":
                return FakeResponse(
                    302,
                    url,
                    {"Location": "https://external.auth.openai.com/sso/authorize?connection=conn_company"},
                )
            if method == "GET" and url == "https://external.auth.openai.com/sso/authorize?connection=conn_company":
                return FakeResponse(
                    302,
                    url,
                    {"Location": "http://203.0.113.10:8080/saml/sso?SAMLRequest=abc&RelayState=def"},
                )
            if method == "GET" and url == "http://203.0.113.10:8080/saml/sso?SAMLRequest=abc&RelayState=def":
                return FakeResponse(200, url, {}, '<a href="/register">注册新员工</a>')
            if method == "GET" and url == "http://203.0.113.10:8080/register":
                return FakeResponse(
                    200,
                    url,
                    {},
                    '<form action="/register" method="post">'
                    '<input name="email">'
                    '<input type="password" name="password">'
                    '<input type="password" name="confirm_password">'
                    '<button name="submit" value="1">Register</button>'
                    "</form>",
                )
            if method == "POST" and url == "http://203.0.113.10:8080/register":
                body = kwargs["data"]
                assert body["email"] == "alice@company.test"
                assert body["password"] == "InitPass123!"
                assert body["confirm_password"] == "InitPass123!"
                return FakeResponse(
                    302,
                    url,
                    {"Location": "http://localhost:1455/auth/callback?code=company_code&state=company_state"},
                )
            if url == "https://auth.openai.com/oauth/token":
                return FakeResponse(
                    200,
                    url,
                    {},
                    json.dumps({"access_token": "acc", "refresh_token": "ref", "id_token": "", "expires_in": 3600}),
                    {"access_token": "acc", "refresh_token": "ref", "id_token": "", "expires_in": 3600},
                )
            raise AssertionError((method, url, kwargs))

    session = Session()
    account = CompanyAccount(
        username="alice",
        email="alice@company.test",
        password="InitPass123!",
        first_name="Alice",
        last_name="Zhang",
    )
    flow = CompanySSOHttpFlow(
        company_sso_domain="sso.company.test",
        session=session,
        artifact_dir=tmp_path,
    )
    oauth = OAuthStart(
        auth_url="https://auth.example/oauth",
        state="company_state",
        code_verifier="verifier",
        redirect_uri="http://localhost:1455/auth/callback",
    )

    token = flow.authorize_codex(oauth, account.to_generated_account())

    assert token["refresh_token"] == "ref"
    assert any(method == "POST" and url == "http://203.0.113.10:8080/register" for method, url, _kwargs in session.calls)


def test_company_sso_submits_workos_saml_identity_form_before_registration(tmp_path):
    class Session:
        def __init__(self):
            self.calls = []

        def request(self, method, url, **kwargs):
            self.calls.append((method, url, kwargs))
            if url == "https://auth.example/oauth":
                return FakeResponse(
                    302,
                    url,
                    {"Location": "https://external.auth.openai.com/sso/authorize?connection=conn_company"},
                )
            if method == "GET" and url == "https://external.auth.openai.com/sso/authorize?connection=conn_company":
                return FakeResponse(
                    302,
                    url,
                    {"Location": "http://203.0.113.10:8080/saml/sso?SAMLRequest=abc&RelayState=def"},
                )
            if method == "GET" and url == "http://203.0.113.10:8080/saml/sso?SAMLRequest=abc&RelayState=def":
                return FakeResponse(
                    200,
                    url,
                    {},
                    '<form method="post" action="/login">'
                    '<input type="hidden" name="SAMLRequest" value="abc">'
                    '<input type="hidden" name="RelayState" value="def">'
                    '<input type="email" name="email">'
                    '<input type="text" name="userid">'
                    '<button type="submit">Sign In</button>'
                    "</form>",
                )
            if method == "POST" and url == "http://203.0.113.10:8080/login":
                body = kwargs["data"]
                assert body["SAMLRequest"] == "abc"
                assert body["RelayState"] == "def"
                assert body["email"] == "alice@company.test"
                assert body["userid"] == "DEV123"
                return FakeResponse(
                    200,
                    url,
                    {},
                    '<form method="post" action="https://external.auth.openai.com/sso/saml/acs/abc123">'
                    '<input type="hidden" name="SAMLResponse" value="saml-response">'
                    '<input type="hidden" name="RelayState" value="relay-state">'
                    '<button type="submit">Continue</button>'
                    "</form>",
                )
            if method == "POST" and url == "https://external.auth.openai.com/sso/saml/acs/abc123":
                body = kwargs["data"]
                assert body == {"SAMLResponse": "saml-response", "RelayState": "relay-state"}
                return FakeResponse(
                    302,
                    url,
                    {"Location": "http://localhost:1455/auth/callback?code=company_code&state=company_state"},
                )
            if url == "https://auth.openai.com/oauth/token":
                return FakeResponse(
                    200,
                    url,
                    {},
                    json.dumps({"access_token": "acc", "refresh_token": "ref", "id_token": "", "expires_in": 3600}),
                    {"access_token": "acc", "refresh_token": "ref", "id_token": "", "expires_in": 3600},
                )
            raise AssertionError((method, url, kwargs))

    session = Session()
    account = CompanyAccount(
        username="alice",
        email="alice@company.test",
        password="InitPass123!",
        first_name="Alice",
        last_name="Zhang",
        employee_id="DEV123",
    )
    flow = CompanySSOHttpFlow(
        company_sso_domain="sso.company.test",
        session=session,
        artifact_dir=tmp_path,
    )
    oauth = OAuthStart(
        auth_url="https://auth.example/oauth",
        state="company_state",
        code_verifier="verifier",
        redirect_uri="http://localhost:1455/auth/callback",
    )

    token = flow.authorize_codex(oauth, account.to_generated_account())

    assert token["refresh_token"] == "ref"
    assert any(method == "POST" and url == "http://203.0.113.10:8080/login" for method, url, _kwargs in session.calls)
    assert any(method == "POST" and url == "https://external.auth.openai.com/sso/saml/acs/abc123" for method, url, _kwargs in session.calls)


def test_company_sso_approves_workos_signin_consent_after_saml(tmp_path):
    class Session:
        def __init__(self):
            self.calls = []

        def request(self, method, url, **kwargs):
            self.calls.append((method, url, kwargs))
            if url == "https://auth.example/oauth":
                return FakeResponse(
                    302,
                    url,
                    {"Location": "https://external.auth.openai.com/sso/authorize?connection=conn_company"},
                )
            if method == "GET" and url == "https://external.auth.openai.com/sso/authorize?connection=conn_company":
                return FakeResponse(
                    302,
                    url,
                    {"Location": "http://203.0.113.10:8080/saml/sso?SAMLRequest=abc&RelayState=def"},
                )
            if method == "GET" and url == "http://203.0.113.10:8080/saml/sso?SAMLRequest=abc&RelayState=def":
                return FakeResponse(
                    200,
                    url,
                    {},
                    '<form method="post" action="/login">'
                    '<input type="hidden" name="SAMLRequest" value="abc">'
                    '<input type="hidden" name="RelayState" value="def">'
                    '<input type="email" name="email">'
                    '<input type="text" name="userid">'
                    '<button type="submit">Sign In</button>'
                    "</form>",
                )
            if method == "POST" and url == "http://203.0.113.10:8080/login":
                return FakeResponse(
                    200,
                    url,
                    {},
                    '<form method="post" action="https://external.auth.openai.com/sso/saml/acs/abc123">'
                    '<input type="hidden" name="SAMLResponse" value="saml-response">'
                    '<input type="hidden" name="RelayState" value="relay-state">'
                    '<button type="submit">Continue</button>'
                    "</form>",
                )
            if method == "POST" and url == "https://external.auth.openai.com/sso/saml/acs/abc123":
                return FakeResponse(
                    302,
                    url,
                    {"Location": "https://external.auth.openai.com/sso/signin-consent?token=consent-token"},
                )
            if method == "GET" and url == "https://external.auth.openai.com/sso/signin-consent?token=consent-token":
                return FakeResponse(
                    200,
                    url,
                    {},
                    '<form method="POST" action="/sso/interstitial">'
                    '<input type="hidden" name="interstitial_token" value="interstitial-token">'
                    '<input type="hidden" name="action" value="confirm">'
                    '<input type="hidden" name="csrf_token" value="csrf-token">'
                    '<button type="submit">Approve sign-in</button>'
                    "</form>"
                    '<form method="POST" action="/sso/interstitial">'
                    '<input type="hidden" name="interstitial_token" value="interstitial-token">'
                    '<input type="hidden" name="action" value="cancel">'
                    '<input type="hidden" name="csrf_token" value="csrf-token">'
                    '<button type="submit">I do not recognize this account</button>'
                    "</form>",
                )
            if method == "POST" and url == "https://external.auth.openai.com/sso/interstitial":
                body = kwargs["data"]
                assert body == {
                    "interstitial_token": "interstitial-token",
                    "action": "confirm",
                    "csrf_token": "csrf-token",
                }
                return FakeResponse(
                    302,
                    url,
                    {"Location": "https://auth.openai.com/api/accounts/callback/workos?code=workos_code&state=workos_state"},
                )
            if method == "GET" and url == "https://auth.openai.com/api/accounts/callback/workos?code=workos_code&state=workos_state":
                return FakeResponse(
                    302,
                    url,
                    {"Location": "http://localhost:1455/auth/callback?code=company_code&state=company_state"},
                )
            if url == "https://auth.openai.com/oauth/token":
                return FakeResponse(
                    200,
                    url,
                    {},
                    json.dumps({"access_token": "acc", "refresh_token": "ref", "id_token": "", "expires_in": 3600}),
                    {"access_token": "acc", "refresh_token": "ref", "id_token": "", "expires_in": 3600},
                )
            raise AssertionError((method, url, kwargs))

    session = Session()
    account = CompanyAccount(
        username="alice",
        email="alice@company.test",
        password="InitPass123!",
        first_name="Alice",
        last_name="Zhang",
        employee_id="DEV123",
    )
    flow = CompanySSOHttpFlow(
        company_sso_domain="sso.company.test",
        session=session,
        artifact_dir=tmp_path,
    )
    oauth = OAuthStart(
        auth_url="https://auth.example/oauth",
        state="company_state",
        code_verifier="verifier",
        redirect_uri="http://localhost:1455/auth/callback",
    )

    token = flow.authorize_codex(oauth, account.to_generated_account())

    assert token["refresh_token"] == "ref"
    assert any(method == "POST" and url == "https://external.auth.openai.com/sso/interstitial" for method, url, _kwargs in session.calls)


def test_company_sso_approves_openai_codex_consent_after_workos_callback(tmp_path):
    class Session:
        def __init__(self):
            self.calls = []

        def request(self, method, url, **kwargs):
            self.calls.append((method, url, kwargs))
            if url == "https://auth.example/oauth":
                return FakeResponse(
                    302,
                    url,
                    {"Location": "https://external.auth.openai.com/sso/authorize?connection=conn_company"},
                )
            if method == "GET" and url == "https://external.auth.openai.com/sso/authorize?connection=conn_company":
                return FakeResponse(
                    302,
                    url,
                    {"Location": "http://203.0.113.10:8080/saml/sso?SAMLRequest=abc&RelayState=def"},
                )
            if method == "GET" and url == "http://203.0.113.10:8080/saml/sso?SAMLRequest=abc&RelayState=def":
                return FakeResponse(
                    200,
                    url,
                    {},
                    '<form method="post" action="/login">'
                    '<input type="hidden" name="SAMLRequest" value="abc">'
                    '<input type="hidden" name="RelayState" value="def">'
                    '<input type="email" name="email">'
                    '<input type="text" name="userid">'
                    '<button type="submit">Sign In</button>'
                    "</form>",
                )
            if method == "POST" and url == "http://203.0.113.10:8080/login":
                return FakeResponse(
                    200,
                    url,
                    {},
                    '<form method="post" action="https://external.auth.openai.com/sso/saml/acs/abc123">'
                    '<input type="hidden" name="SAMLResponse" value="saml-response">'
                    '<input type="hidden" name="RelayState" value="relay-state">'
                    '<button type="submit">Continue</button>'
                    "</form>",
                )
            if method == "POST" and url == "https://external.auth.openai.com/sso/saml/acs/abc123":
                return FakeResponse(
                    302,
                    url,
                    {"Location": "https://external.auth.openai.com/sso/signin-consent?token=consent-token"},
                )
            if method == "GET" and url == "https://external.auth.openai.com/sso/signin-consent?token=consent-token":
                return FakeResponse(
                    200,
                    url,
                    {},
                    '<form method="POST" action="/sso/interstitial">'
                    '<input type="hidden" name="interstitial_token" value="interstitial-token">'
                    '<input type="hidden" name="action" value="confirm">'
                    '<input type="hidden" name="csrf_token" value="csrf-token">'
                    '<button type="submit">Approve sign-in</button>'
                    "</form>",
                )
            if method == "POST" and url == "https://external.auth.openai.com/sso/interstitial":
                return FakeResponse(
                    302,
                    url,
                    {"Location": "https://auth.openai.com/api/accounts/callback/workos?code=workos_code&state=workos_state"},
                )
            if method == "GET" and url == "https://auth.openai.com/api/accounts/callback/workos?code=workos_code&state=workos_state":
                return FakeResponse(
                    302,
                    url,
                    {"Location": "https://auth.openai.com/sign-in-with-chatgpt/codex/consent"},
                )
            if method == "GET" and url == "https://auth.openai.com/sign-in-with-chatgpt/codex/consent":
                return FakeResponse(
                    200,
                    url,
                    {},
                    '<title>Sign in to Codex with ChatGPT - OpenAI</title>'
                    '<form method="post" action="/sign-in-with-chatgpt/codex/consent">'
                    '<input type="hidden" name="workspace_id" value="79d545d1-e2bf-4415-b316-7d250b6f6031">'
                    '<button type="submit">Continue</button>'
                    "</form>",
                )
            if method == "POST" and url == "https://auth.openai.com/sign-in-with-chatgpt/codex/consent":
                raise AssertionError("Codex consent route form post returns OpenAI 500 in HTTP flow")
            if method == "POST" and url == "https://auth.openai.com/api/accounts/workspace/select":
                body = kwargs["json"]
                assert body == {"workspace_id": "79d545d1-e2bf-4415-b316-7d250b6f6031"}
                return FakeResponse(
                    302,
                    url,
                    {"Location": "http://localhost:1455/auth/callback?code=company_code&state=company_state"},
                )
            if url == "https://auth.openai.com/oauth/token":
                return FakeResponse(
                    200,
                    url,
                    {},
                    json.dumps({"access_token": "acc", "refresh_token": "ref", "id_token": "", "expires_in": 3600}),
                    {"access_token": "acc", "refresh_token": "ref", "id_token": "", "expires_in": 3600},
                )
            raise AssertionError((method, url, kwargs))

    session = Session()
    account = CompanyAccount(
        username="alice",
        email="alice@company.test",
        password="InitPass123!",
        first_name="Alice",
        last_name="Zhang",
        employee_id="DEV123",
    )
    flow = CompanySSOHttpFlow(
        company_sso_domain="sso.company.test",
        session=session,
        artifact_dir=tmp_path,
    )
    oauth = OAuthStart(
        auth_url="https://auth.example/oauth",
        state="company_state",
        code_verifier="verifier",
        redirect_uri="http://localhost:1455/auth/callback",
    )

    token = flow.authorize_codex(oauth, account.to_generated_account())

    assert token["refresh_token"] == "ref"
    assert any(
        method == "POST" and url == "https://auth.openai.com/api/accounts/workspace/select"
        for method, url, _kwargs in session.calls
    )


def test_company_sso_reports_openai_phone_required_without_submitting_form(tmp_path):
    class Session:
        def __init__(self):
            self.calls = []

        def request(self, method, url, **kwargs):
            self.calls.append((method, url, kwargs))
            if method == "POST" and url == "https://auth.openai.com/add-phone":
                raise AssertionError("phone requirement must not be auto-submitted")
            return FakeResponse(
                200,
                "https://auth.openai.com/add-phone",
                {},
                '<title>Phone number required - OpenAI</title>'
                '<form method="post" action="/add-phone">'
                '<input name="phone_number">'
                '<button type="submit">Continue</button>'
                "</form>",
            )

    session = Session()
    account = CompanyAccount(
        username="alice",
        email="alice@company.test",
        password="InitPass123!",
        first_name="Alice",
        last_name="Zhang",
    )
    flow = CompanySSOHttpFlow(
        company_sso_domain="sso.company.test",
        session=session,
        artifact_dir=tmp_path,
    )
    oauth = OAuthStart(
        auth_url="https://auth.example/oauth",
        state="company_state",
        code_verifier="verifier",
        redirect_uri="http://localhost:1455/auth/callback",
    )

    with pytest.raises(OAuthFlowError) as excinfo:
        flow.authorize_codex(oauth, account.to_generated_account())

    assert excinfo.value.stage == "openai_phone_required"
    assert "手机号" in str(excinfo.value)
    assert (tmp_path / "openai_phone_required.html").exists()
    assert not any(method == "POST" and url == "https://auth.openai.com/add-phone" for method, url, _kwargs in session.calls)


def test_company_sso_fills_literal_register_name_fields(tmp_path):
    class Session(CompanyRegisterSession):
        def request(self, method, url, **kwargs):
            if method == "GET" and url == "https://sso.company.test/register":
                return FakeResponse(
                    200,
                    url,
                    {},
                    '<form action="/register" method="post">'
                    '<input name="email">'
                    '<input name="first">'
                    '<input name="last">'
                    '<input name="display">'
                    '<input name="employee">'
                    '<input type="password" name="password">'
                    '<button name="submit" value="1">Register</button>'
                    "</form>",
                )
            if method == "POST" and url == "https://sso.company.test/register":
                body = kwargs["data"]
                assert body["first"] == "Alice"
                assert body["last"] == "Zhang"
                assert body["display"] == "Alice Zhang"
                assert body["employee"] == "DEV123"
                return FakeResponse(
                    302,
                    url,
                    {"Location": "http://localhost:1455/auth/callback?code=company_code&state=company_state"},
                )
            if url == "https://auth.openai.com/oauth/token":
                return FakeResponse(
                    200,
                    url,
                    {},
                    json.dumps({"access_token": "acc", "refresh_token": "ref", "id_token": "", "expires_in": 3600}),
                    {"access_token": "acc", "refresh_token": "ref", "id_token": "", "expires_in": 3600},
                )
            return super().request(method, url, **kwargs)

    account = CompanyAccount(
        username="alice.zhang",
        email="alice.zhang@company.test",
        password="InitPass123!",
        first_name="Alice",
        last_name="Zhang",
        employee_id="DEV123",
    )
    flow = CompanySSOHttpFlow(
        company_sso_domain="sso.company.test",
        session=Session(),
        artifact_dir=tmp_path,
    )
    oauth = OAuthStart(
        auth_url="https://auth.example/oauth",
        state="company_state",
        code_verifier="verifier",
        redirect_uri="http://localhost:1455/auth/callback",
    )

    token = flow.authorize_codex(oauth, account.to_generated_account())

    assert token["refresh_token"] == "ref"


def test_company_sso_rejects_post_registration_form_to_untrusted_host(tmp_path):
    class Session:
        def __init__(self):
            self.calls = []

        def request(self, method, url, **kwargs):
            self.calls.append((method, url, kwargs))
            if url == "https://auth.example/oauth":
                return FakeResponse(
                    200,
                    "https://sso.company.test/login",
                    {},
                    '<a href="/register">注册新员工</a>',
                )
            if method == "GET" and url == "https://sso.company.test/register":
                return FakeResponse(
                    200,
                    url,
                    {},
                    '<form action="/register" method="post">'
                    '<input name="email">'
                    '<input type="password" name="password">'
                    '<button name="submit" value="1">Register</button>'
                    "</form>",
                )
            if method == "POST" and url == "https://sso.company.test/register":
                return FakeResponse(
                    200,
                    "https://sso.company.test/login",
                    {},
                    '<form action="https://evil.example/login" method="post">'
                    '<input name="email">'
                    '<input type="password" name="password">'
                    '<button name="submit" value="1">Login</button>'
                    "</form>",
                )
            if method == "POST" and url == "https://evil.example/login":
                raise AssertionError("untrusted host received credentials")
            raise AssertionError((method, url, kwargs))

    session = Session()
    account = CompanyAccount(
        username="alice.zhang",
        email="alice.zhang@company.test",
        password="InitPass123!",
        first_name="Alice",
        last_name="Zhang",
    )
    flow = CompanySSOHttpFlow(
        company_sso_domain="sso.company.test",
        session=session,
        artifact_dir=tmp_path,
    )
    oauth = OAuthStart(
        auth_url="https://auth.example/oauth",
        state="company_state",
        code_verifier="verifier",
        redirect_uri="http://localhost:1455/auth/callback",
    )

    with pytest.raises(OAuthFlowError):
        flow.authorize_codex(oauth, account.to_generated_account())

    assert not any(method == "POST" and url == "https://evil.example/login" for method, url, _kwargs in session.calls)


def test_company_sso_does_not_submit_plain_login_form_before_registration(tmp_path):
    class Session:
        def __init__(self):
            self.calls = []

        def request(self, method, url, **kwargs):
            self.calls.append((method, url, kwargs))
            if url == "https://auth.example/oauth":
                return FakeResponse(
                    200,
                    "https://sso.company.test/login",
                    {},
                    '<form action="/login" method="post">'
                    '<input name="email">'
                    '<input type="password" name="password">'
                    '<button name="submit" value="1">Login</button>'
                    "</form>",
                )
            if method == "POST" and url == "https://sso.company.test/login":
                raise AssertionError("plain login form submitted before registration")
            raise AssertionError((method, url, kwargs))

    session = Session()
    account = CompanyAccount(
        username="alice.zhang",
        email="alice.zhang@company.test",
        password="InitPass123!",
        first_name="Alice",
        last_name="Zhang",
    )
    flow = CompanySSOHttpFlow(
        company_sso_domain="sso.company.test",
        session=session,
        artifact_dir=tmp_path,
    )
    oauth = OAuthStart(
        auth_url="https://auth.example/oauth",
        state="company_state",
        code_verifier="verifier",
        redirect_uri="http://localhost:1455/auth/callback",
    )

    with pytest.raises(OAuthFlowError):
        flow.authorize_codex(oauth, account.to_generated_account())

    assert not any(method == "POST" and url == "https://sso.company.test/login" for method, url, _kwargs in session.calls)


def test_company_sso_does_not_treat_last_login_as_registration_field(tmp_path):
    class Session:
        def __init__(self):
            self.calls = []

        def request(self, method, url, **kwargs):
            self.calls.append((method, url, kwargs))
            if url == "https://auth.example/oauth":
                return FakeResponse(
                    200,
                    "https://sso.company.test/login",
                    {},
                    '<form action="/login" method="post">'
                    '<input name="email">'
                    '<input type="password" name="password">'
                    '<input type="hidden" name="last_login" value="never">'
                    '<button name="submit" value="1">Login</button>'
                    "</form>",
                )
            if method == "POST" and url == "https://sso.company.test/login":
                raise AssertionError("last_login caused login submission before registration")
            raise AssertionError((method, url, kwargs))

    session = Session()
    account = CompanyAccount(
        username="alice.zhang",
        email="alice.zhang@company.test",
        password="InitPass123!",
        first_name="Alice",
        last_name="Zhang",
    )
    flow = CompanySSOHttpFlow(
        company_sso_domain="sso.company.test",
        session=session,
        artifact_dir=tmp_path,
    )
    oauth = OAuthStart(
        auth_url="https://auth.example/oauth",
        state="company_state",
        code_verifier="verifier",
        redirect_uri="http://localhost:1455/auth/callback",
    )

    with pytest.raises(OAuthFlowError):
        flow.authorize_codex(oauth, account.to_generated_account())

    assert not any(method == "POST" and url == "https://sso.company.test/login" for method, url, _kwargs in session.calls)


def test_company_sso_register_link_beats_meta_and_script_redirect(tmp_path):
    class Session:
        def __init__(self):
            self.calls = []

        def request(self, method, url, **kwargs):
            self.calls.append((method, url, kwargs))
            if url == "https://auth.example/oauth":
                return FakeResponse(
                    200,
                    "https://sso.company.test/start",
                    {},
                    '<meta http-equiv="refresh" content="0; url=/login">'
                    '<script>window.location="/login"</script>'
                    '<a href="/register">注册新员工</a>',
                )
            if method == "GET" and url == "https://sso.company.test/register":
                return FakeResponse(
                    200,
                    url,
                    {},
                    '<form action="/register" method="post">'
                    '<input name="email">'
                    '<input type="password" name="password">'
                    '<input type="password" name="confirm_password">'
                    '<button name="submit" value="1">Register</button>'
                    "</form>",
                )
            if method == "POST" and url == "https://sso.company.test/register":
                return FakeResponse(
                    302,
                    url,
                    {"Location": "http://localhost:1455/auth/callback?code=company_code&state=company_state"},
                )
            if url == "https://auth.openai.com/oauth/token":
                return FakeResponse(
                    200,
                    url,
                    {},
                    json.dumps({"access_token": "acc", "refresh_token": "ref", "id_token": "", "expires_in": 3600}),
                    {"access_token": "acc", "refresh_token": "ref", "id_token": "", "expires_in": 3600},
                )
            if url == "https://sso.company.test/login":
                raise AssertionError("login redirect outranked register")
            raise AssertionError((method, url, kwargs))

    session = Session()
    account = CompanyAccount(
        username="alice.zhang",
        email="alice.zhang@company.test",
        password="InitPass123!",
        first_name="Alice",
        last_name="Zhang",
    )
    flow = CompanySSOHttpFlow(
        company_sso_domain="sso.company.test",
        session=session,
        artifact_dir=tmp_path,
    )
    oauth = OAuthStart(
        auth_url="https://auth.example/oauth",
        state="company_state",
        code_verifier="verifier",
        redirect_uri="http://localhost:1455/auth/callback",
    )

    token = flow.authorize_codex(oauth, account.to_generated_account())

    visited_urls = [url for _method, url, _kwargs in session.calls]
    assert token["refresh_token"] == "ref"
    assert "https://sso.company.test/register" in visited_urls
    assert "https://sso.company.test/login" not in visited_urls


def test_company_sso_rejects_get_registration_form_with_credentials(tmp_path):
    class Session(CompanyRegisterSession):
        def request(self, method, url, **kwargs):
            if method == "GET" and url == "https://sso.company.test/register":
                return FakeResponse(
                    200,
                    url,
                    {},
                    '<form action="/register" method="get">'
                    '<input name="email">'
                    '<input type="password" name="password">'
                    '<input type="password" name="confirm_password">'
                    '<button name="submit" value="1">Register</button>'
                    "</form>",
                )
            if method == "GET" and url.startswith("https://sso.company.test/register?"):
                raise AssertionError("GET registration leaked credentials in query")
            return super().request(method, url, **kwargs)

    session = Session()
    account = CompanyAccount(
        username="alice.zhang",
        email="alice.zhang@company.test",
        password="InitPass123!",
        first_name="Alice",
        last_name="Zhang",
    )
    flow = CompanySSOHttpFlow(
        company_sso_domain="sso.company.test",
        session=session,
        artifact_dir=tmp_path,
    )
    oauth = OAuthStart(
        auth_url="https://auth.example/oauth",
        state="company_state",
        code_verifier="verifier",
        redirect_uri="http://localhost:1455/auth/callback",
    )

    with pytest.raises(OAuthFlowError) as excinfo:
        flow.authorize_codex(oauth, account.to_generated_account())

    assert excinfo.value.stage == "company_sso_register"
    assert "GET" in str(excinfo.value)
    assert not any(url.startswith("https://sso.company.test/register?") for _method, url, _kwargs in session.calls)


def test_company_sso_rejects_get_continuation_form_with_credentials(tmp_path):
    class Session:
        def __init__(self):
            self.calls = []

        def request(self, method, url, **kwargs):
            self.calls.append((method, url, kwargs))
            if url == "https://auth.example/oauth":
                return FakeResponse(200, "https://sso.company.test/login", {}, '<a href="/register">注册新员工</a>')
            if method == "GET" and url == "https://sso.company.test/register":
                return FakeResponse(
                    200,
                    url,
                    {},
                    '<form action="/register" method="post">'
                    '<input name="email">'
                    '<input type="password" name="password">'
                    '<input type="password" name="confirm_password">'
                    '<button name="submit" value="1">Register</button>'
                    "</form>",
                )
            if method == "POST" and url == "https://sso.company.test/register":
                return FakeResponse(
                    200,
                    "https://sso.company.test/login",
                    {},
                    '<form action="/login" method="get">'
                    '<input name="email">'
                    '<input type="password" name="password">'
                    '<button name="submit" value="1">Login</button>'
                    "</form>",
                )
            if method == "GET" and url.startswith("https://sso.company.test/login?"):
                raise AssertionError("GET continuation leaked credentials in query")
            raise AssertionError((method, url, kwargs))

    session = Session()
    account = CompanyAccount(
        username="alice.zhang",
        email="alice.zhang@company.test",
        password="InitPass123!",
        first_name="Alice",
        last_name="Zhang",
    )
    flow = CompanySSOHttpFlow(
        company_sso_domain="sso.company.test",
        session=session,
        artifact_dir=tmp_path,
    )
    oauth = OAuthStart(
        auth_url="https://auth.example/oauth",
        state="company_state",
        code_verifier="verifier",
        redirect_uri="http://localhost:1455/auth/callback",
    )

    with pytest.raises(OAuthFlowError) as excinfo:
        flow.authorize_codex(oauth, account.to_generated_account())

    assert excinfo.value.stage == "company_sso_continue"
    assert "GET" in str(excinfo.value)
    assert not any(url.startswith("https://sso.company.test/login?") for _method, url, _kwargs in session.calls)


def test_company_sso_rejects_untrusted_register_link_on_company_page(tmp_path):
    class Session:
        def __init__(self):
            self.calls = []

        def request(self, method, url, **kwargs):
            self.calls.append((method, url, kwargs))
            if url == "https://auth.example/oauth":
                return FakeResponse(
                    200,
                    "https://sso.company.test/login",
                    {},
                    '<a href="https://evil.example/register">注册新员工</a>',
                )
            if url.startswith("https://evil.example/"):
                raise AssertionError("untrusted register link was visited")
            raise AssertionError((method, url, kwargs))

    session = Session()
    account = CompanyAccount(
        username="alice.zhang",
        email="alice.zhang@company.test",
        password="InitPass123!",
        first_name="Alice",
        last_name="Zhang",
    )
    flow = CompanySSOHttpFlow(
        company_sso_domain="sso.company.test",
        session=session,
        artifact_dir=tmp_path,
    )
    oauth = OAuthStart(
        auth_url="https://auth.example/oauth",
        state="company_state",
        code_verifier="verifier",
        redirect_uri="http://localhost:1455/auth/callback",
    )

    with pytest.raises(OAuthFlowError) as excinfo:
        flow.authorize_codex(oauth, account.to_generated_account())

    assert excinfo.value.stage == "company_sso_register"
    assert "注册链接" in str(excinfo.value)
    assert not any(url.startswith("https://evil.example/") for _method, url, _kwargs in session.calls)


def test_company_sso_rejects_get_continuation_identifier_pass_credentials(tmp_path):
    class Session:
        def __init__(self):
            self.calls = []

        def request(self, method, url, **kwargs):
            self.calls.append((method, url, kwargs))
            if url == "https://auth.example/oauth":
                return FakeResponse(200, "https://sso.company.test/login", {}, '<a href="/register">注册新员工</a>')
            if method == "GET" and url == "https://sso.company.test/register":
                return FakeResponse(
                    200,
                    url,
                    {},
                    '<form action="/register" method="post">'
                    '<input name="email">'
                    '<input type="password" name="password">'
                    '<input type="password" name="confirm_password">'
                    '<button name="submit" value="1">Register</button>'
                    "</form>",
                )
            if method == "POST" and url == "https://sso.company.test/register":
                return FakeResponse(
                    200,
                    "https://sso.company.test/login",
                    {},
                    '<form action="/login" method="get">'
                    '<input name="identifier">'
                    '<input type="password" name="pass">'
                    '<button name="submit" value="1">Login</button>'
                    "</form>",
                )
            if method == "GET" and url.startswith("https://sso.company.test/login?"):
                raise AssertionError("GET continuation leaked identifier/pass credentials")
            raise AssertionError((method, url, kwargs))

    session = Session()
    account = CompanyAccount(
        username="alice.zhang",
        email="alice.zhang@company.test",
        password="InitPass123!",
        first_name="Alice",
        last_name="Zhang",
    )
    flow = CompanySSOHttpFlow(
        company_sso_domain="sso.company.test",
        session=session,
        artifact_dir=tmp_path,
    )
    oauth = OAuthStart(
        auth_url="https://auth.example/oauth",
        state="company_state",
        code_verifier="verifier",
        redirect_uri="http://localhost:1455/auth/callback",
    )

    with pytest.raises(OAuthFlowError) as excinfo:
        flow.authorize_codex(oauth, account.to_generated_account())

    assert excinfo.value.stage == "company_sso_continue"
    assert not any(url.startswith("https://sso.company.test/login?") for _method, url, _kwargs in session.calls)


def test_company_sso_does_not_submit_employee_id_login_form_before_registration(tmp_path):
    class Session:
        def __init__(self):
            self.calls = []

        def request(self, method, url, **kwargs):
            self.calls.append((method, url, kwargs))
            if url == "https://auth.example/oauth":
                return FakeResponse(
                    200,
                    "https://sso.company.test/login",
                    {},
                    '<form action="/login" method="post">'
                    '<input name="employee_id">'
                    '<input type="password" name="password">'
                    '<button name="submit" value="1">Login</button>'
                    "</form>",
                )
            if method == "POST" and url == "https://sso.company.test/login":
                raise AssertionError("employee_id login form submitted before registration")
            raise AssertionError((method, url, kwargs))

    session = Session()
    account = CompanyAccount(
        username="alice.zhang",
        email="alice.zhang@company.test",
        password="InitPass123!",
        first_name="Alice",
        last_name="Zhang",
        employee_id="DEV123",
    )
    flow = CompanySSOHttpFlow(
        company_sso_domain="sso.company.test",
        session=session,
        artifact_dir=tmp_path,
    )
    oauth = OAuthStart(
        auth_url="https://auth.example/oauth",
        state="company_state",
        code_verifier="verifier",
        redirect_uri="http://localhost:1455/auth/callback",
    )

    with pytest.raises(OAuthFlowError):
        flow.authorize_codex(oauth, account.to_generated_account())

    assert not any(method == "POST" and url == "https://sso.company.test/login" for method, url, _kwargs in session.calls)


def test_company_sso_login_action_with_register_submit_is_not_registration(tmp_path):
    class Session:
        def __init__(self):
            self.calls = []

        def request(self, method, url, **kwargs):
            self.calls.append((method, url, kwargs))
            if url == "https://auth.example/oauth":
                return FakeResponse(
                    200,
                    "https://sso.company.test/login",
                    {},
                    '<form action="/login" method="post">'
                    '<input name="email">'
                    '<input type="password" name="password">'
                    '<button name="register" value="register">Register</button>'
                    "</form>",
                )
            if method == "POST" and url == "https://sso.company.test/login":
                raise AssertionError("login action submitted before registration")
            raise AssertionError((method, url, kwargs))

    session = Session()
    account = CompanyAccount(
        username="alice.zhang",
        email="alice.zhang@company.test",
        password="InitPass123!",
        first_name="Alice",
        last_name="Zhang",
    )
    flow = CompanySSOHttpFlow(
        company_sso_domain="sso.company.test",
        session=session,
        artifact_dir=tmp_path,
    )
    oauth = OAuthStart(
        auth_url="https://auth.example/oauth",
        state="company_state",
        code_verifier="verifier",
        redirect_uri="http://localhost:1455/auth/callback",
    )

    with pytest.raises(OAuthFlowError):
        flow.authorize_codex(oauth, account.to_generated_account())

    assert not any(method == "POST" and url == "https://sso.company.test/login" for method, url, _kwargs in session.calls)


def test_company_sso_rejects_untrusted_location_redirect_before_registration(tmp_path):
    class Session:
        def __init__(self):
            self.calls = []

        def request(self, method, url, **kwargs):
            self.calls.append((method, url, kwargs))
            if url == "https://auth.example/oauth":
                return FakeResponse(
                    302,
                    "https://sso.company.test/login",
                    {"Location": "https://evil.example/register"},
                )
            if url.startswith("https://evil.example/"):
                raise AssertionError("untrusted redirect was visited")
            raise AssertionError((method, url, kwargs))

    session = Session()
    account = CompanyAccount(
        username="alice.zhang",
        email="alice.zhang@company.test",
        password="InitPass123!",
        first_name="Alice",
        last_name="Zhang",
    )
    flow = CompanySSOHttpFlow(
        company_sso_domain="sso.company.test",
        session=session,
        artifact_dir=tmp_path,
    )
    oauth = OAuthStart(
        auth_url="https://auth.example/oauth",
        state="company_state",
        code_verifier="verifier",
        redirect_uri="http://localhost:1455/auth/callback",
    )

    with pytest.raises(OAuthFlowError) as excinfo:
        flow.authorize_codex(oauth, account.to_generated_account())

    assert excinfo.value.stage == "company_sso_register"
    assert not any(url.startswith("https://evil.example/") for _method, url, _kwargs in session.calls)


def test_company_sso_omitted_action_login_with_register_submit_is_not_registration(tmp_path):
    class Session:
        def __init__(self):
            self.calls = []

        def request(self, method, url, **kwargs):
            self.calls.append((method, url, kwargs))
            if url == "https://auth.example/oauth":
                return FakeResponse(
                    200,
                    "https://sso.company.test/login",
                    {},
                    '<form method="post">'
                    '<input name="email">'
                    '<input type="password" name="password">'
                    '<button name="register" value="register">Register</button>'
                    "</form>",
                )
            if method == "POST" and url == "https://sso.company.test/login":
                raise AssertionError("omitted-action login form submitted before registration")
            raise AssertionError((method, url, kwargs))

    session = Session()
    account = CompanyAccount(
        username="alice.zhang",
        email="alice.zhang@company.test",
        password="InitPass123!",
        first_name="Alice",
        last_name="Zhang",
    )
    flow = CompanySSOHttpFlow(
        company_sso_domain="sso.company.test",
        session=session,
        artifact_dir=tmp_path,
    )
    oauth = OAuthStart(
        auth_url="https://auth.example/oauth",
        state="company_state",
        code_verifier="verifier",
        redirect_uri="http://localhost:1455/auth/callback",
    )

    with pytest.raises(OAuthFlowError):
        flow.authorize_codex(oauth, account.to_generated_account())

    assert not any(method == "POST" and url == "https://sso.company.test/login" for method, url, _kwargs in session.calls)


def test_company_sso_http_error_is_reported_with_company_stage(tmp_path):
    class Session:
        def __init__(self):
            self.calls = []

        def request(self, method, url, **kwargs):
            self.calls.append((method, url, kwargs))
            if url == "https://auth.example/oauth":
                return FakeResponse(302, url, {"Location": "https://sso.company.test/login"})
            if url == "https://sso.company.test/login":
                raise RuntimeError("empty reply from server")
            raise AssertionError((method, url, kwargs))

    session = Session()
    account = CompanyAccount(
        username="alice.zhang",
        email="alice.zhang@company.test",
        password="InitPass123!",
        first_name="Alice",
        last_name="Zhang",
    )
    flow = CompanySSOHttpFlow(
        company_sso_domain="sso.company.test",
        session=session,
        artifact_dir=tmp_path,
    )
    oauth = OAuthStart(
        auth_url="https://auth.example/oauth",
        state="company_state",
        code_verifier="verifier",
        redirect_uri="http://localhost:1455/auth/callback",
    )

    with pytest.raises(OAuthFlowError) as excinfo:
        flow.authorize_codex(oauth, account.to_generated_account())

    assert excinfo.value.stage == "company_sso_http"
    assert "企业 SSO 服务器无法连接" in str(excinfo.value)
