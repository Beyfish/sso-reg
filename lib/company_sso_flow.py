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
