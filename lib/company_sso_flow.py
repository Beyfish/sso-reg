from __future__ import annotations

import re
import urllib.parse
from typing import Any

from .errors import OAuthFlowError
from .idp_client import GeneratedAccount
from .sso_http_flow import (
    HtmlForm,
    HttpResult,
    SSOHttpFlow,
    _absolute_url,
    _form_score,
    parse_html_forms,
    parse_html_links,
    populate_account_form,
)

REGISTER_MARKERS = (
    "register",
    "signup",
    "sign-up",
    "sign_up",
    "create",
    "create account",
    "create-account",
    "create_account",
    "注册",
    "新员工",
    "新用户",
    "创建账号",
)

CONFIRM_PASSWORD_FIELDS = ("confirm_password", "confirmpassword", "password_confirm", "password_confirmation")
FIRST_NAME_FIELDS = ("first", "first_name", "firstname", "given", "given_name", "givenname")
LAST_NAME_FIELDS = ("last", "last_name", "lastname", "family", "family_name", "familyname", "surname")
EMPLOYEE_FIELDS = ("employee", "employee_id", "employeeid", "staff", "staff_id", "staffid")
TERMS_MARKERS = ("terms", "agree", "agreement", "accept", "privacy", "tos", "policy")
SENSITIVE_GET_FIELD_NAMES = (
    "confirm",
    "confirm_password",
    "confirmpassword",
    "email",
    "employee",
    "employee_id",
    "employeeid",
    "login",
    "mail",
    "passwd",
    "password",
    "password_confirm",
    "password_confirmation",
    "pwd",
    "staff",
    "staff_id",
    "staffid",
    "token",
    "user",
    "user_id",
    "user_name",
    "userid",
    "username",
)
SENSITIVE_GET_FIELD_TOKENS = ("confirm", "email", "employee", "login", "password", "staff", "token", "user")


class CompanySSOHttpFlow(SSOHttpFlow):
    def __init__(self, *, company_sso_domain: str, register_markers: tuple[str, ...] = REGISTER_MARKERS, **kwargs: Any):
        super().__init__(**kwargs)
        self.company_sso_domain = self._normalized_host(company_sso_domain)
        self.register_markers = tuple(marker.lower() for marker in register_markers)
        self._company_registration_submitted = False

    @staticmethod
    def _normalized_host(value: str) -> str:
        raw = str(value or "").strip()
        if not raw:
            return ""
        parsed = urllib.parse.urlparse(raw if "://" in raw else "//" + raw)
        return str(parsed.hostname or "").strip().lower().rstrip(".")

    @staticmethod
    def _field_name(value: str) -> str:
        return re.sub(r"[^a-z0-9]+", "_", str(value or "").strip().lower()).strip("_")

    def _is_company_sso_url(self, url: str) -> bool:
        if not self.company_sso_domain:
            return False
        host = self._normalized_host(url)
        return host == self.company_sso_domain or host.endswith("." + self.company_sso_domain)

    def _looks_like_register_text(self, value: str) -> bool:
        lowered = str(value or "").lower()
        return any(marker in lowered for marker in self.register_markers)

    def _find_register_url(self, response: HttpResult) -> str:
        for link in parse_html_links(response.text):
            if self._looks_like_register_text(link.href) or self._looks_like_register_text(link.text):
                return _absolute_url(response.url, link.href)
        return ""

    def _form_has_register_semantics(self, form: HtmlForm) -> bool:
        field_names = {self._field_name(key) for key in form.fields}
        checkbox_names = {self._field_name(key) for key in form.checkbox_fields}
        return (
            self._looks_like_register_text(form.action)
            or self._looks_like_register_text(" ".join((form.submit_name, form.submit_value)))
            or self._has_confirm_password_field(field_names)
            or self._has_terms_checkbox(checkbox_names)
            or self._has_employee_field(field_names)
            or self._has_name_pair(field_names)
        )

    def _has_confirm_password_field(self, field_names: set[str]) -> bool:
        return bool(
            field_names.intersection(CONFIRM_PASSWORD_FIELDS)
            or any("password" in name and "confirm" in name for name in field_names)
        )

    def _has_employee_field(self, field_names: set[str]) -> bool:
        return bool(field_names.intersection(EMPLOYEE_FIELDS))

    def _has_name_pair(self, field_names: set[str]) -> bool:
        return bool(field_names.intersection(FIRST_NAME_FIELDS) and field_names.intersection(LAST_NAME_FIELDS))

    def _has_terms_checkbox(self, checkbox_names: set[str]) -> bool:
        return any(marker in name for name in checkbox_names for marker in TERMS_MARKERS)

    def _has_sensitive_get_data(self, data: dict[str, str]) -> bool:
        for key, value in data.items():
            if not str(value or ""):
                continue
            name = self._field_name(key)
            tokens = set(name.split("_"))
            if name in SENSITIVE_GET_FIELD_NAMES or tokens.intersection(SENSITIVE_GET_FIELD_TOKENS):
                return True
        return False

    def _script_or_meta_redirect(self, response: HttpResult) -> str:
        _forms, _links, meta = parse_html_forms(response.text)
        if meta:
            return _absolute_url(response.url, meta)
        patterns = (
            r"location\.href\s*=\s*['\"]([^'\"]+)['\"]",
            r"window\.location\s*=\s*['\"]([^'\"]+)['\"]",
            r"window\.location\.replace\(['\"]([^'\"]+)['\"]\)",
        )
        for pattern in patterns:
            match = re.search(pattern, response.text or "", re.I)
            if match:
                return _absolute_url(response.url, match.group(1))
        return ""

    def _extract_script_or_meta_redirect(self, response: HttpResult) -> str:
        if not self._is_company_sso_url(response.url):
            return super()._extract_script_or_meta_redirect(response)
        if not self._company_registration_submitted:
            register_url = self._find_register_url(response)
            if register_url:
                if not self._is_company_sso_url(register_url):
                    raise OAuthFlowError("公司 SSO 注册链接不在允许域名内", stage="company_sso_register")
                return register_url
            forms, _links, _meta = parse_html_forms(response.text)
            if any(self._form_register_score(form) > 0 for form in forms):
                return ""
            redirected = self._script_or_meta_redirect(response)
            if redirected:
                if not self._is_company_sso_url(redirected):
                    raise OAuthFlowError("公司 SSO 注册前跳转不在允许域名内", stage="company_sso_register")
                return redirected
            return ""
        return super()._extract_script_or_meta_redirect(response)

    def _form_register_score(self, form: HtmlForm) -> int:
        if not self._form_has_register_semantics(form):
            return 0
        field_names = {self._field_name(key) for key in form.fields}
        checkbox_names = {self._field_name(key) for key in form.checkbox_fields}
        keys = " ".join(list(field_names) + list(checkbox_names))
        action = form.action.lower()
        submit = " ".join((form.submit_name, form.submit_value)).lower()
        score = 1
        if self._looks_like_register_text(action):
            score += 10
        if self._looks_like_register_text(submit):
            score += 10
        if "email" in keys or "username" in keys:
            score += 3
        if "password" in keys:
            score += 3
        if self._has_confirm_password_field(field_names):
            score += 8
        if self._has_name_pair(field_names):
            score += 5
        if self._has_employee_field(field_names):
            score += 5
        if self._has_terms_checkbox(checkbox_names):
            score += 3
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
            elif lowered in {"first_name", "firstname", "given_name", "givenname", "given", "first"}:
                data[key] = first_name
            elif lowered in {"last_name", "lastname", "family_name", "familyname", "surname", "last"}:
                data[key] = last_name
            elif lowered in {"display_name", "displayname", "full_name", "fullname", "name", "display"}:
                data[key] = display_name
            elif lowered in {"employee_id", "employeeid", "staff_id", "staffid", "employee"}:
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
        if method == "GET":
            if self._has_sensitive_get_data(data):
                raise OAuthFlowError("公司 SSO 注册 GET 表单包含敏感字段，拒绝写入 URL", stage="company_sso_register")
            sep = "&" if urllib.parse.urlparse(action).query else "?"
            self._company_registration_submitted = True
            return self._request("GET", action + sep + urllib.parse.urlencode(data), headers={"Referer": response.url}, allow_redirects=False)
        self._company_registration_submitted = True
        return self._request("POST", action, headers={"Referer": response.url, "Content-Type": "application/x-www-form-urlencoded"}, data=data, allow_redirects=False)

    def _submit_company_form(self, response: HttpResult, account: GeneratedAccount) -> HttpResult | None:
        forms, _links, _meta = parse_html_forms(response.text)
        if not forms:
            return None
        best = max(forms, key=_form_score)
        if _form_score(best) <= 0:
            return None
        action = _absolute_url(response.url, best.action or response.url)
        if not self._is_company_sso_url(action):
            raise OAuthFlowError("公司 SSO 表单 action 不在允许域名内", stage="company_sso_continue")
        data = populate_account_form(best, account, user_token=self.user_token)
        method = (best.method or "GET").upper()
        if method == "GET":
            if self._has_sensitive_get_data(data):
                raise OAuthFlowError("公司 SSO 后续 GET 表单包含敏感字段，拒绝写入 URL", stage="company_sso_continue")
            sep = "&" if urllib.parse.urlparse(action).query else "?"
            return self._request("GET", action + sep + urllib.parse.urlencode(data), headers={"Referer": response.url}, allow_redirects=False)
        return self._request("POST", action, headers={"Referer": response.url, "Content-Type": "application/x-www-form-urlencoded"}, data=data, allow_redirects=False)

    def _handle_custom_page(self, response: HttpResult, account: GeneratedAccount, stage: str) -> str | HttpResult | None:
        if not self._is_company_sso_url(response.url):
            forms, _links, _meta = parse_html_forms(response.text)
            if forms:
                raise OAuthFlowError("公司 SSO 不会向非允许域名提交表单", stage="company_sso_register", data={"url": response.url})
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
        submitted_login = self._submit_company_form(response, account)
        if submitted_login is not None:
            return submitted_login
        return None
