# Company SSO Registration Codex Activation Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add an authorized company-SSO registration-only flow that generates or accepts employee credentials, follows OpenAI/Codex OAuth, clicks the company SSO registration link, registers the employee account, and exchanges the OAuth callback for a Codex refresh token.

**Architecture:** Keep the existing Codex OAuth and export providers. Add a company-account model plus a `CompanySSOHttpFlow` that extends the existing pure-HTTP flow only on whitelisted company SSO domains. Add a separate CLI entrypoint so the current IDP-based flow remains untouched.

**Tech Stack:** Python 3.10+, standard library, existing `curl_cffi`, existing pytest suite.

---

## Scope

This plan implements one working path:

```text
developer mode or explicit employee input
-> Codex OAuth authorize URL
-> OpenAI email identifier page
-> company SSO login page
-> click registration link
-> fill registration form
-> continue redirects/forms
-> OAuth callback
-> token exchange
-> optional Sub2API/CPA export
```

The flow intentionally supports only company-owned SSO domains passed by configuration. It must not submit registration data to arbitrary hosts.

## File Structure

- Create `lib/company_account.py`  
  Owns `CompanyAccount`, deterministic developer-account generation, and conversion to the existing `GeneratedAccount` shape.

- Modify `lib/sso_http_flow.py`  
  Adds HTML link text parsing, unchecked checkbox capture, and a custom-page hook in `_drive_until_callback()`.

- Create `lib/company_sso_flow.py`  
  Owns company SSO registration-only behavior: detect login page, follow registration link, fill register form, then continue OAuth. Host allowlist lives here.

- Create `lib/company_sso_cli.py`  
  New command orchestration for company SSO activation, independent of `IdpClient`.

- Create `scripts/run_company_sso_codex.py`  
  Thin script entrypoint matching existing `scripts/run_idp_codex.py` style.

- Create `tests/test_company_account.py`  
  Tests deterministic developer-account generation and conversion.

- Modify `tests/test_sso_http_flow.py`  
  Tests link text parsing, checkbox capture, and custom hook behavior.

- Create `tests/test_company_sso_flow.py`  
  Tests registration-link click, form fill, host allowlist, and token exchange with a fake HTTP session.

- Create `tests/test_company_sso_cli.py`  
  Tests developer mode CLI writes employee/token artifacts and skips IDP.

---

### Task 1: Company Account Model and Developer Generator

**Files:**
- Create: `lib/company_account.py`
- Test: `tests/test_company_account.py`

- [ ] **Step 1: Write failing tests for developer account generation**

Create `tests/test_company_account.py`:

```python
from __future__ import annotations

from lib.company_account import CompanyAccount, generate_dev_account


def test_generate_dev_account_is_deterministic_with_seed():
    account = generate_dev_account(email_domain="example.com", seed="case-1", password_length=16)

    assert account.email == "dev.user.0906@example.com"
    assert account.username == "dev.user.0906"
    assert account.first_name == "Dev"
    assert account.last_name == "User0906"
    assert len(account.password) == 16
    assert any(ch.islower() for ch in account.password)
    assert any(ch.isupper() for ch in account.password)
    assert any(ch.isdigit() for ch in account.password)
    assert any(ch in "!@#$%^&*" for ch in account.password)


def test_company_account_converts_to_generated_account_with_extra_fields():
    account = CompanyAccount(
        username="alice.zhang",
        email="alice.zhang@example.com",
        password="P@ssw0rdForTest",
        first_name="Alice",
        last_name="Zhang",
        employee_id="E001",
    )

    generated = account.to_generated_account()

    assert generated.email == "alice.zhang@example.com"
    assert generated.password == "P@ssw0rdForTest"
    assert generated.given_name == "Alice"
    assert generated.family_name == "Zhang"
    assert generated.name == "Alice Zhang"
    assert generated.raw["username"] == "alice.zhang"
    assert generated.raw["display_name"] == "Alice Zhang"
    assert generated.raw["employee_id"] == "E001"


def test_public_and_private_dicts_split_password():
    account = CompanyAccount(
        username="bob.li",
        email="bob.li@example.com",
        password="Secret123!",
        first_name="Bob",
        last_name="Li",
    )

    assert "password" not in account.as_public_dict()
    assert account.as_private_dict()["password"] == "Secret123!"
```

- [ ] **Step 2: Run tests to verify they fail**

Run:

```bash
python -m pytest tests/test_company_account.py -q
```

Expected: FAIL with `ModuleNotFoundError: No module named 'lib.company_account'`.

- [ ] **Step 3: Implement `lib/company_account.py`**

Create `lib/company_account.py`:

```python
from __future__ import annotations

import hashlib
import random
import string
from dataclasses import dataclass

from .idp_client import GeneratedAccount

SPECIALS = "!@#$%^&*"
PASSWORD_ALPHABET = string.ascii_letters + string.digits + SPECIALS


@dataclass(frozen=True)
class CompanyAccount:
    username: str
    email: str
    password: str
    first_name: str
    last_name: str
    employee_id: str = ""

    @property
    def display_name(self) -> str:
        return " ".join(part for part in (self.first_name, self.last_name) if part).strip()

    def to_generated_account(self) -> GeneratedAccount:
        return GeneratedAccount(
            id=0,
            email=self.email,
            password=self.password,
            name=self.display_name,
            given_name=self.first_name,
            family_name=self.last_name,
            raw={
                "username": self.username,
                "display_name": self.display_name,
                "employee_id": self.employee_id,
                "first_name": self.first_name,
                "last_name": self.last_name,
            },
        )

    def as_public_dict(self) -> dict[str, str]:
        return {
            "username": self.username,
            "email": self.email,
            "first_name": self.first_name,
            "last_name": self.last_name,
            "display_name": self.display_name,
            "employee_id": self.employee_id,
            "has_password": bool(self.password),
        }

    def as_private_dict(self) -> dict[str, str]:
        data = self.as_public_dict()
        data["password"] = self.password
        return data


def _seed_to_number(seed: str) -> int:
    digest = hashlib.sha256(seed.encode("utf-8")).hexdigest()
    return int(digest[:12], 16)


def _password(rng: random.Random, length: int) -> str:
    length = max(12, int(length or 16))
    required = [
        rng.choice(string.ascii_lowercase),
        rng.choice(string.ascii_uppercase),
        rng.choice(string.digits),
        rng.choice(SPECIALS),
    ]
    remaining = [rng.choice(PASSWORD_ALPHABET) for _ in range(length - len(required))]
    chars = required + remaining
    rng.shuffle(chars)
    return "".join(chars)


def generate_dev_account(*, email_domain: str, seed: str = "", password_length: int = 16) -> CompanyAccount:
    domain = str(email_domain or "").strip().lstrip("@").lower()
    if not domain or "." not in domain:
        raise ValueError("email_domain must be a domain like company.com")
    seed_text = seed or domain
    number = _seed_to_number(seed_text) % 10000
    username = f"dev.user.{number:04d}"
    rng = random.Random(_seed_to_number(f"{seed_text}:password"))
    return CompanyAccount(
        username=username,
        email=f"{username}@{domain}",
        password=_password(rng, password_length),
        first_name="Dev",
        last_name=f"User{number:04d}",
        employee_id=f"DEV{number:04d}",
    )
```

- [ ] **Step 4: Run tests to verify they pass**

Run:

```bash
python -m pytest tests/test_company_account.py -q
```

Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add lib/company_account.py tests/test_company_account.py
git commit -m "feat: add company account generator"
```

---

### Task 2: HTML Link Text and Checkbox Parsing

**Files:**
- Modify: `lib/sso_http_flow.py`
- Test: `tests/test_sso_http_flow.py`

- [ ] **Step 1: Add failing tests for link text and unchecked checkboxes**

Append to `tests/test_sso_http_flow.py`:

```python
from lib.sso_http_flow import parse_html_links


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
```

- [ ] **Step 2: Run tests to verify they fail**

Run:

```bash
python -m pytest tests/test_sso_http_flow.py::test_parse_html_links_includes_visible_text tests/test_sso_http_flow.py::test_parse_html_forms_captures_unchecked_checkbox_names -q
```

Expected: FAIL because `parse_html_links` and `checkbox_fields` do not exist.

- [ ] **Step 3: Extend parser data structures**

Modify `lib/sso_http_flow.py`.

Add after `HtmlForm`:

```python
@dataclass(frozen=True)
class HtmlLink:
    href: str
    text: str = ""
```

Change `HtmlForm` to:

```python
@dataclass
class HtmlForm:
    action: str = ""
    method: str = "GET"
    fields: dict[str, str] = field(default_factory=dict)
    checkbox_fields: dict[str, str] = field(default_factory=dict)
    submit_name: str = ""
    submit_value: str = ""
```

In `_FormParser.__init__`, add:

```python
        self.link_items: list[HtmlLink] = []
        self._active_link_href: str = ""
        self._active_link_text: list[str] = []
```

In `handle_starttag`, replace the checkbox/radio input branch with:

```python
            elif typ == "checkbox":
                if attr.get("checked") is not None:
                    self._current.fields[name] = value or "on"
                else:
                    self._current.checkbox_fields[name] = value or "on"
            elif typ == "radio":
                if attr.get("checked") is not None:
                    self._current.fields[name] = value
            else:
                self._current.fields[name] = value
```

In the `elif tag == "a"` branch, add active link tracking:

```python
        elif tag == "a":
            href = html.unescape(attr.get("href", ""))
            if href:
                self.links.append(href)
                self._active_link_href = href
                self._active_link_text = []
```

Add this method to `_FormParser`:

```python
    def handle_data(self, data: str) -> None:
        if self._active_link_href:
            text = html.unescape(data or "").strip()
            if text:
                self._active_link_text.append(text)
```

In `handle_endtag`, before form handling, add:

```python
        if tag == "a" and self._active_link_href:
            self.link_items.append(HtmlLink(self._active_link_href, " ".join(self._active_link_text).strip()))
            self._active_link_href = ""
            self._active_link_text = []
```

Add function after `parse_html_forms`:

```python
def parse_html_links(text: str) -> list[HtmlLink]:
    parser = _FormParser()
    parser.feed(text or "")
    parser.close()
    return parser.link_items
```

- [ ] **Step 4: Run targeted parser tests**

Run:

```bash
python -m pytest tests/test_sso_http_flow.py::test_parse_html_links_includes_visible_text tests/test_sso_http_flow.py::test_parse_html_forms_captures_unchecked_checkbox_names -q
```

Expected: PASS.

- [ ] **Step 5: Run existing SSO tests**

Run:

```bash
python -m pytest tests/test_sso_http_flow.py -q
```

Expected: PASS.

- [ ] **Step 6: Commit**

```bash
git add lib/sso_http_flow.py tests/test_sso_http_flow.py
git commit -m "feat: parse sso links and checkboxes"
```

---

### Task 3: Custom Page Hook in HTTP OAuth Driver

**Files:**
- Modify: `lib/sso_http_flow.py`
- Test: `tests/test_sso_http_flow.py`

- [ ] **Step 1: Add failing test for a custom flow hook**

Append to `tests/test_sso_http_flow.py`:

```python
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
```

- [ ] **Step 2: Run test to verify it fails**

Run:

```bash
python -m pytest tests/test_sso_http_flow.py::test_drive_until_callback_allows_custom_page_handler -q
```

Expected: FAIL because `_handle_custom_page` is not called.

- [ ] **Step 3: Add hook to `SSOHttpFlow`**

In `lib/sso_http_flow.py`, add method inside `class SSOHttpFlow` before `_drive_until_callback`:

```python
    def _handle_custom_page(self, response: HttpResult, account: GeneratedAccount, stage: str) -> str | HttpResult | None:
        return None
```

In `_drive_until_callback()`, after the `scripted` block and before `consent = self._try_workspace_consent(response)`, insert:

```python
            custom = self._handle_custom_page(response, account, stage)
            if isinstance(custom, str) and custom:
                current = custom
                response = None
                continue
            if custom is not None:
                response = custom
                continue
```

- [ ] **Step 4: Run hook test**

Run:

```bash
python -m pytest tests/test_sso_http_flow.py::test_drive_until_callback_allows_custom_page_handler -q
```

Expected: PASS.

- [ ] **Step 5: Run full SSO tests**

Run:

```bash
python -m pytest tests/test_sso_http_flow.py -q
```

Expected: PASS.

- [ ] **Step 6: Commit**

```bash
git add lib/sso_http_flow.py tests/test_sso_http_flow.py
git commit -m "feat: add custom oauth page hook"
```

---

### Task 4: Company SSO Registration-Only Flow

**Files:**
- Create: `lib/company_sso_flow.py`
- Test: `tests/test_company_sso_flow.py`

- [ ] **Step 1: Write failing tests for registration link and form submission**

Create `tests/test_company_sso_flow.py`:

```python
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
        if url == "https://sso.company.test/register":
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
        if url == "https://sso.company.test/register" and method == "POST":
            raise AssertionError("POST route must be reached by action resolution")
        if method == "POST" and url == "https://sso.company.test/register":
            raise AssertionError("unreachable duplicate")
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
```

- [ ] **Step 2: Run tests to verify they fail**

Run:

```bash
python -m pytest tests/test_company_sso_flow.py -q
```

Expected: FAIL because `lib.company_sso_flow` does not exist.

- [ ] **Step 3: Implement `lib/company_sso_flow.py`**

Create `lib/company_sso_flow.py`:

```python
from __future__ import annotations

import urllib.parse
from typing import Any

from .errors import OAuthFlowError
from .idp_client import GeneratedAccount
from .sso_http_flow import HtmlForm, HttpResult, SSOHttpFlow, _absolute_url, parse_html_forms, parse_html_links

REGISTER_MARKERS = (
    "register",
    "signup",
    "sign-up",
    "sign_up",
    "create account",
    "create-account",
    "create_account",
    "注册",
    "新员工",
    "新用户",
    "创建账号",
)

REGISTER_FIELD_MARKERS = (
    "confirm",
    "first",
    "given",
    "last",
    "family",
    "surname",
    "employee",
    "staff",
)

TERMS_MARKERS = ("terms", "agree", "accept", "privacy", "tos", "policy")


class CompanySSOHttpFlow(SSOHttpFlow):
    def __init__(self, *, company_sso_domain: str, register_markers: tuple[str, ...] = REGISTER_MARKERS, **kwargs: Any):
        super().__init__(**kwargs)
        self.company_sso_domain = str(company_sso_domain or "").strip().lower()
        self.register_markers = tuple(marker.lower() for marker in register_markers)
        self._company_registration_submitted = False

    def _is_company_sso_url(self, url: str) -> bool:
        if not self.company_sso_domain:
            return False
        host = urllib.parse.urlparse(str(url or "")).netloc.lower().split("@")[-1].split(":")[0]
        return host == self.company_sso_domain or host.endswith("." + self.company_sso_domain)

    def _looks_like_register_text(self, value: str) -> bool:
        lowered = str(value or "").lower()
        return any(marker in lowered for marker in self.register_markers)

    def _find_register_url(self, response: HttpResult) -> str:
        for link in parse_html_links(response.text):
            if self._looks_like_register_text(link.href) or self._looks_like_register_text(link.text):
                return _absolute_url(response.url, link.href)
        return ""

    def _form_register_score(self, form: HtmlForm) -> int:
        keys = " ".join(list(form.fields) + list(form.checkbox_fields)).lower()
        action = form.action.lower()
        score = 0
        if self._looks_like_register_text(action):
            score += 10
        if "email" in keys or "username" in keys:
            score += 3
        if "password" in keys:
            score += 3
        if any(marker in keys for marker in REGISTER_FIELD_MARKERS):
            score += 5
        if any(marker in keys for marker in TERMS_MARKERS):
            score += 1
        return score

    def _account_extra(self, account: GeneratedAccount, key: str) -> str:
        raw = account.raw if isinstance(account.raw, dict) else {}
        return str(raw.get(key) or "").strip()

    def _fill_register_form(self, form: HtmlForm, account: GeneratedAccount) -> dict[str, str]:
        data = dict(form.fields)
        username = self._account_extra(account, "username") or account.email.split("@", 1)[0]
        display_name = self._account_extra(account, "display_name") or account.name
        employee_id = self._account_extra(account, "employee_id")
        first_name = self._account_extra(account, "first_name") or account.given_name
        last_name = self._account_extra(account, "last_name") or account.family_name
        for key in list(data):
            lowered = key.lower()
            if any(marker in lowered for marker in ("username", "login", "user_name", "userid", "user_id")) and "token" not in lowered:
                data[key] = username
            elif "email" in lowered or "mail" == lowered:
                data[key] = account.email
            elif "confirm" in lowered and "password" in lowered:
                data[key] = account.password
            elif "password" in lowered or lowered in {"passwd", "pwd"}:
                data[key] = account.password
            elif lowered in {"first_name", "firstname", "given_name", "givenname", "given"}:
                data[key] = first_name
            elif lowered in {"last_name", "lastname", "family_name", "familyname", "surname"}:
                data[key] = last_name
            elif lowered in {"display_name", "displayname", "full_name", "fullname", "name"}:
                data[key] = display_name
            elif lowered in {"employee_id", "employeeid", "staff_id", "staffid"}:
                data[key] = employee_id
        for key, value in form.checkbox_fields.items():
            lowered = key.lower()
            if any(marker in lowered for marker in TERMS_MARKERS):
                data[key] = value or "on"
        if form.submit_name:
            data.setdefault(form.submit_name, form.submit_value)
        return data

    def _submit_register_form(self, response: HttpResult, account: GeneratedAccount) -> HttpResult | None:
        forms, _links, _meta = parse_html_forms(response.text)
        if not forms:
            return None
        best = max(forms, key=self._form_register_score)
        if self._form_register_score(best) <= 0:
            return None
        action = _absolute_url(response.url, best.action or response.url)
        if not self._is_company_sso_url(action):
            raise OAuthFlowError("公司 SSO 注册表单 action 不在允许域名内", stage="company_sso_register")
        data = self._fill_register_form(best, account)
        method = (best.method or "GET").upper()
        self._company_registration_submitted = True
        if method == "GET":
            sep = "&" if urllib.parse.urlparse(action).query else "?"
            return self._request("GET", action + sep + urllib.parse.urlencode(data), headers={"Referer": response.url}, allow_redirects=False)
        return self._request("POST", action, headers={"Referer": response.url, "Content-Type": "application/x-www-form-urlencoded"}, data=data, allow_redirects=False)

    def _handle_custom_page(self, response: HttpResult, account: GeneratedAccount, stage: str) -> str | HttpResult | None:
        if not self._is_company_sso_url(response.url):
            return None
        if not self._company_registration_submitted:
            register_url = self._find_register_url(response)
            if register_url:
                if not self._is_company_sso_url(register_url):
                    raise OAuthFlowError("公司 SSO 注册链接不在允许域名内", stage="company_sso_register")
                return register_url
            submitted = self._submit_register_form(response, account)
            if submitted is not None:
                return submitted
            raise OAuthFlowError("公司 SSO 页面未找到注册链接或注册表单", stage="company_sso_register", data={"url": response.url})
        submitted_login = self._submit_best_form(response, account)
        if submitted_login is not None:
            return submitted_login
        return None
```

- [ ] **Step 4: Fix fake-session routing if duplicate route fails**

If `tests/test_company_sso_flow.py` fails because the fake session sees the GET register branch before the POST branch, edit the fake session so the POST branch appears first:

```python
    def request(self, method, url, **kwargs):
        self.calls.append((method, url, kwargs))
        if method == "POST" and url == "https://sso.company.test/register":
            ...
        if method == "GET" and url == "https://auth.example/oauth":
            ...
        if method == "GET" and url == "https://sso.company.test/register":
            ...
```

- [ ] **Step 5: Run company SSO flow tests**

Run:

```bash
python -m pytest tests/test_company_sso_flow.py -q
```

Expected: PASS.

- [ ] **Step 6: Run SSO regression tests**

Run:

```bash
python -m pytest tests/test_sso_http_flow.py tests/test_company_sso_flow.py -q
```

Expected: PASS.

- [ ] **Step 7: Commit**

```bash
git add lib/company_sso_flow.py tests/test_company_sso_flow.py
git commit -m "feat: add company sso registration flow"
```

---

### Task 5: Company SSO CLI Entrypoint

**Files:**
- Create: `lib/company_sso_cli.py`
- Create: `scripts/run_company_sso_codex.py`
- Test: `tests/test_company_sso_cli.py`

- [ ] **Step 1: Write failing CLI test**

Create `tests/test_company_sso_cli.py`:

```python
from __future__ import annotations

import json

from lib import company_sso_cli


def test_company_sso_cli_dev_generate_writes_artifacts(monkeypatch, tmp_path, capsys):
    class FakeFlow:
        def __init__(self, **kwargs):
            self.kwargs = kwargs

        def authorize_codex(self, oauth, account):
            assert account.email.endswith("@company.test")
            assert account.password
            return {
                "type": "codex",
                "email": account.email,
                "account_id": "acct_company",
                "user_id": "user_company",
                "access_token": "acc",
                "refresh_token": "ref",
                "id_token": "",
                "client_id": oauth.client_id,
                "expired": "2026-06-08T10:00:00Z",
                "last_refresh": "2026-06-08T09:00:00Z",
            }

    monkeypatch.setattr(company_sso_cli, "CompanySSOHttpFlow", FakeFlow)
    monkeypatch.setattr(company_sso_cli, "_export_record", lambda cfg, logger, record, progress=None: {})

    code = company_sso_cli.main([
        "--sso-domain", "sso.company.test",
        "--dev-generate",
        "--email-domain", "company.test",
        "--seed", "cli-case",
        "--artifact-dir", str(tmp_path),
        "--export-targets", "none",
    ])

    assert code == 0
    employee_public = json.loads((tmp_path / "employee.public.json").read_text(encoding="utf-8"))
    employee_private = json.loads((tmp_path / "employee.private.json").read_text(encoding="utf-8"))
    token = json.loads((tmp_path / "token.json").read_text(encoding="utf-8"))
    assert "password" not in employee_public
    assert employee_private["password"]
    assert token["refresh_token"] == "ref"
    assert json.loads(capsys.readouterr().out)["status"] == "success"
```

- [ ] **Step 2: Run CLI test to verify it fails**

Run:

```bash
python -m pytest tests/test_company_sso_cli.py -q
```

Expected: FAIL because `lib.company_sso_cli` does not exist.

- [ ] **Step 3: Implement CLI module**

Create `lib/company_sso_cli.py`:

```python
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from types import SimpleNamespace

from .cli import _build_export_record, _export_record
from .codex_oauth import generate_oauth_start, public_token_result
from .company_account import CompanyAccount, generate_dev_account
from .company_sso_flow import CompanySSOHttpFlow
from .config import PROJECT_ROOT, RuntimeConfig
from .errors import IdpTeamAutomationError
from .logging_utils import JsonlLogger, redact, utc_now_iso


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Company SSO registration -> Codex OAuth refresh token")
    parser.add_argument("--sso-domain", required=True, help="公司 SSO 域名，例如 sso.company.com")
    parser.add_argument("--dev-generate", action="store_true", help="开发者模式：随机生成员工信息")
    parser.add_argument("--email-domain", help="开发者模式邮箱域名，例如 company.com")
    parser.add_argument("--seed", default="", help="开发者模式确定性种子")
    parser.add_argument("--password-length", type=int, default=16, help="开发者模式密码长度，最小 12")
    parser.add_argument("--username", help="员工用户名")
    parser.add_argument("--email", help="员工邮箱")
    parser.add_argument("--password", help="员工初始密码")
    parser.add_argument("--first-name", help="员工名")
    parser.add_argument("--last-name", help="员工姓")
    parser.add_argument("--employee-id", default="", help="员工编号")
    parser.add_argument("--codex-client-id", help="Codex OAuth client_id")
    parser.add_argument("--codex-redirect-uri", help="Codex OAuth redirect_uri")
    parser.add_argument("--codex-scope", help="Codex OAuth scope")
    parser.add_argument("--sub2api-url", help="Sub2API base URL")
    parser.add_argument("--sub2api-email", help="Sub2API 管理员邮箱")
    parser.add_argument("--sub2api-password", help="Sub2API 管理员密码")
    parser.add_argument("--sub2api-group", help="Sub2API 分组 ID，多个用逗号")
    parser.add_argument("--model-whitelist", help="Sub2API model whitelist，多个用逗号")
    parser.add_argument("--export-targets", default="none", help="导出目标：sub2api / cpa / sub2api,cpa / none")
    parser.add_argument("--cpa-url", help="CLIProxyAPI base URL")
    parser.add_argument("--cpa-management-key", help="CLIProxyAPI Management API key")
    parser.add_argument("--cpa-note", help="CPA auth 文件备注")
    parser.add_argument("--artifact-dir", help="artifact 输出目录，默认 artifacts/company_sso_codex")
    parser.add_argument("--timeout", help="HTTP timeout 秒数")
    parser.add_argument("--proxy", help="HTTP/HTTPS proxy")
    parser.add_argument("--no-proxy", action="store_true", help="禁用 proxy")
    return parser


def _write_json(path: Path, data: object) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(data, ensure_ascii=False, indent=2, sort_keys=True, default=str), encoding="utf-8")


def _account_from_args(args: argparse.Namespace) -> CompanyAccount:
    if args.dev_generate:
        if not args.email_domain:
            raise IdpTeamAutomationError("开发者模式缺少 --email-domain", stage="company_account")
        return generate_dev_account(email_domain=args.email_domain, seed=args.seed, password_length=args.password_length)
    missing = [name for name in ("email", "password") if not str(getattr(args, name) or "").strip()]
    if missing:
        raise IdpTeamAutomationError("缺少员工字段：" + ", ".join("--" + name.replace("_", "-") for name in missing), stage="company_account")
    email = str(args.email).strip()
    username = str(args.username or email.split("@", 1)[0]).strip()
    first_name = str(args.first_name or username.split(".", 1)[0] or "User").strip()
    last_name = str(args.last_name or "Employee").strip()
    return CompanyAccount(
        username=username,
        email=email,
        password=str(args.password),
        first_name=first_name,
        last_name=last_name,
        employee_id=str(args.employee_id or ""),
    )


def _runtime_config(args: argparse.Namespace, artifact_dir: Path) -> RuntimeConfig:
    ns = SimpleNamespace(
        idp_base=None,
        idp_token="company-sso-unused",
        client_id=None,
        channel_id=None,
        domain=None,
        email="",
        given_name="",
        family_name="",
        account_id="",
        codex_client_id=args.codex_client_id,
        codex_redirect_uri=args.codex_redirect_uri,
        codex_scope=args.codex_scope,
        sub2api_url=args.sub2api_url,
        sub2api_email=args.sub2api_email,
        sub2api_password=args.sub2api_password,
        sub2api_group=args.sub2api_group,
        model_whitelist=args.model_whitelist,
        export_targets=args.export_targets,
        cpa_url=args.cpa_url,
        cpa_management_key=args.cpa_management_key,
        cpa_note=args.cpa_note,
        no_sub2api=False,
        artifact_dir=str(artifact_dir),
        timeout=args.timeout,
        proxy=args.proxy,
        no_proxy=bool(args.no_proxy),
    )
    return RuntimeConfig.from_env_and_args(ns)


def run(args: argparse.Namespace) -> dict[str, object]:
    artifact_dir = Path(args.artifact_dir) if args.artifact_dir else PROJECT_ROOT / "artifacts" / "company_sso_codex"
    if not artifact_dir.is_absolute():
        artifact_dir = PROJECT_ROOT / artifact_dir
    artifact_dir.mkdir(parents=True, exist_ok=True)
    cfg = _runtime_config(args, artifact_dir)
    account = _account_from_args(args)
    generated = account.to_generated_account()
    logger = JsonlLogger(artifact_dir / "network.jsonl")
    _write_json(artifact_dir / "employee.public.json", account.as_public_dict())
    _write_json(artifact_dir / "employee.private.json", account.as_private_dict())
    oauth = generate_oauth_start(
        redirect_uri=cfg.codex_redirect_uri,
        client_id=cfg.codex_client_id,
        scope=cfg.codex_scope,
    )
    _write_json(artifact_dir / "oauth_start.public.json", {
        "auth_url": redact(oauth.auth_url),
        "state": "***REDACTED***",
        "redirect_uri": oauth.redirect_uri,
        "client_id": oauth.client_id,
        "scope": oauth.scope,
    })
    flow = CompanySSOHttpFlow(
        company_sso_domain=args.sso_domain,
        timeout=cfg.timeout,
        proxy=cfg.proxy,
        artifact_dir=artifact_dir,
        logger=logger,
    )
    token_config = flow.authorize_codex(oauth, generated)
    token_public = public_token_result(token_config)
    _write_json(artifact_dir / "token.public.json", token_public)
    _write_json(artifact_dir / "token.json", token_config)
    exports = {}
    if cfg.selected_export_targets:
        record = _build_export_record(token_config, generated, cfg)
        exports = _export_record(cfg, logger, record, progress=None)
    result = {
        "status": "success",
        "finished_at": utc_now_iso(),
        "artifact_dir": str(artifact_dir),
        "account": account.as_public_dict(),
        "token_public": token_public,
        "exports": exports,
    }
    _write_json(artifact_dir / "result.json", result)
    logger.write("company_sso_run_success", result)
    return result


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        result = run(args)
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
```

- [ ] **Step 4: Add script entrypoint**

Create `scripts/run_company_sso_codex.py`:

```python
#!/usr/bin/env python3
from __future__ import annotations

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from lib.company_sso_cli import main


if __name__ == "__main__":
    raise SystemExit(main())
```

- [ ] **Step 5: Run CLI test**

Run:

```bash
python -m pytest tests/test_company_sso_cli.py -q
```

Expected: PASS.

- [ ] **Step 6: Run related tests**

Run:

```bash
python -m pytest tests/test_company_account.py tests/test_company_sso_flow.py tests/test_company_sso_cli.py -q
```

Expected: PASS.

- [ ] **Step 7: Commit**

```bash
git add lib/company_sso_cli.py scripts/run_company_sso_codex.py tests/test_company_sso_cli.py
git commit -m "feat: add company sso codex cli"
```

---

### Task 6: Documentation and Smoke Commands

**Files:**
- Modify: `README.md`
- Test: command-line help smoke checks

- [ ] **Step 1: Add README section**

Append to `README.md`:

```markdown
## 公司 SSO 注册模式

公司 SSO 注册模式用于已接入 OpenAI ChatGPT Business SSO 的公司域名。该模式不调用项目原有 IDP 服务，而是直接从 Codex OAuth 授权页开始，让 OpenAI 根据员工邮箱跳转到公司 SSO，再在公司 SSO 登录页寻找注册链接并提交注册表单。

开发者模式会生成随机员工信息并跑完整后续流程：

```bash
python3 scripts/run_company_sso_codex.py \
  --sso-domain sso.company.com \
  --dev-generate \
  --email-domain company.com \
  --seed local-test-001 \
  --export-targets none
```

指定员工信息：

```bash
python3 scripts/run_company_sso_codex.py \
  --sso-domain sso.company.com \
  --email new.user@company.com \
  --username new.user \
  --password 'InitPass123!' \
  --first-name New \
  --last-name User \
  --export-targets sub2api
```

安全边界：

- 只会在 `--sso-domain` 指定的域名及其子域提交公司 SSO 注册表单。
- `employee.public.json` 不包含密码。
- `employee.private.json`、`token.json` 包含敏感信息，应只写入受控运行目录。
- 如果公司 SSO 出现验证码、MFA、WebAuthn 或复杂 JavaScript 注册流程，纯 HTTP 模式会失败并保存未处理 HTML artifact。
```

- [ ] **Step 2: Run help commands**

Run:

```bash
python scripts/run_company_sso_codex.py --help
python scripts/run_idp_codex.py --help
```

Expected: both commands print usage and exit 0.

- [ ] **Step 3: Run full test suite**

Run:

```bash
python -m pytest -q
```

Expected: PASS.

- [ ] **Step 4: Commit**

```bash
git add README.md
git commit -m "docs: document company sso registration mode"
```

---

### Task 7: Manual Dry Smoke Against Company SSO Test Domain

**Files:**
- No code files if test passes
- Artifact output under `artifacts/company_sso_codex/`

- [ ] **Step 1: Run developer-mode smoke**

Run with the company test SSO domain:

```bash
python scripts/run_company_sso_codex.py ^
  --sso-domain sso.company.com ^
  --dev-generate ^
  --email-domain company.com ^
  --seed smoke-001 ^
  --artifact-dir artifacts/company_sso_smoke ^
  --export-targets none
```

Expected:

```text
stdout JSON contains "status": "success"
artifacts/company_sso_smoke/result.json exists
artifacts/company_sso_smoke/token.public.json has "has_refresh_token": true
```

- [ ] **Step 2: Inspect failed HTML if smoke fails**

If the command fails with `company_sso_register`, inspect:

```bash
dir artifacts\company_sso_smoke
```

Expected failure artifacts:

```text
unhandled_codex_authorize_*.html
max_steps_codex_authorize.html
network.jsonl
```

Use the saved HTML to add exact field-name mappings in `CompanySSOHttpFlow._fill_register_form()`. Example mapping addition:

```python
elif lowered in {"givenname_cn", "employeefirstname"}:
    data[key] = first_name
elif lowered in {"surname_cn", "employeelastname"}:
    data[key] = last_name
```

- [ ] **Step 3: Commit any smoke-specific field mapping**

If field mapping changes were needed:

```bash
git add lib/company_sso_flow.py tests/test_company_sso_flow.py
git commit -m "fix: map company sso registration fields"
```

If no changes were needed:

```bash
git status --short
```

Expected: no unstaged code changes.

---

## Self-Review

**Spec coverage**

- Company SSO already connected to OpenAI ChatGPT Business: covered by starting at Codex OAuth and letting OpenAI route by email domain.
- Registration only: covered by `CompanySSOHttpFlow` prioritizing register link before generic login form.
- Login page first, then click register link: covered by `_find_register_url()` and `parse_html_links()`.
- Developer mode generates username, password, first name, last name: covered by `generate_dev_account()` and CLI flags.
- Generated employee info runs the downstream OAuth flow: covered by CLI using generated account with `CompanySSOHttpFlow.authorize_codex()`.
- Existing IDP flow remains available: covered by separate CLI and no changes to `scripts/run_idp_codex.py`.

**Placeholder scan**

No `TBD`, `TODO`, or unspecified implementation steps remain. Any company-specific registration field mismatch is handled by a concrete smoke-test mapping edit step.

**Type consistency**

- `CompanyAccount.to_generated_account()` returns existing `GeneratedAccount`.
- `CompanySSOHttpFlow.authorize_codex()` receives `GeneratedAccount`, matching `SSOHttpFlow`.
- CLI exports reuse existing `_build_export_record()` and `_export_record()` signatures.

---

## Execution Handoff

Plan complete and saved to `docs/superpowers/plans/2026-06-08-company-sso-registration-codex.md`. Two execution options:

**1. Subagent-Driven (recommended)** - I dispatch a fresh subagent per task, review between tasks, fast iteration

**2. Inline Execution** - Execute tasks in this session using executing-plans, batch execution with checkpoints

Which approach?
