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
LOGIN_MARKERS = ("login", "log-in", "log_in", "sign in", "signin", "sign-in", "sign_in", "sso", "authenticate")
TERMS_MARKERS = ("terms", "agree", "agreement", "accept", "privacy", "tos", "policy")
OPENAI_INTERMEDIATE_PATHS = frozenset(("/log-in", "/log-in-or-create-account", "/sso"))
OPENAI_PHONE_REQUIRED_PATHS = frozenset(("/add-phone",))
OPENAI_CODEX_CONSENT_PATH = "/sign-in-with-chatgpt/codex/consent"
WORKOS_SSO_AUTHORIZE_HOST = "external.auth.openai.com"
WORKOS_SSO_AUTHORIZE_PATH = "/sso/authorize"
WORKOS_SAML_ACS_PATH_PREFIX = "/sso/saml/acs/"
WORKOS_SIGNIN_CONSENT_PATH = "/sso/signin-consent"
WORKOS_INTERSTITIAL_PATH = "/sso/interstitial"
SENSITIVE_GET_FIELD_NAMES = (
    "confirm",
    "confirm_password",
    "confirmpassword",
    "email",
    "employee",
    "employee_id",
    "employeeid",
    "identifier",
    "login",
    "mail",
    "pass",
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
SENSITIVE_GET_FIELD_TOKENS = ("confirm", "email", "employee", "identifier", "login", "pass", "password", "staff", "token", "user")


class CompanySSOHttpFlow(SSOHttpFlow):
    def __init__(self, *, company_sso_domain: str, register_markers: tuple[str, ...] = REGISTER_MARKERS, **kwargs: Any):
        super().__init__(**kwargs)
        self.company_sso_domain = self._normalized_host(company_sso_domain)
        self.register_markers = tuple(marker.lower() for marker in register_markers)
        self._company_registration_submitted = False
        self._workos_saml_hosts: set[str] = set()

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
        return (
            host == self.company_sso_domain
            or host.endswith("." + self.company_sso_domain)
            or host in self._workos_saml_hosts
        )

    def _is_openai_intermediate_url(self, url: str) -> bool:
        parsed = urllib.parse.urlparse(str(url or ""))
        return parsed.netloc == "auth.openai.com" and parsed.path in OPENAI_INTERMEDIATE_PATHS

    def _is_openai_phone_required_url(self, url: str) -> bool:
        parsed = urllib.parse.urlparse(str(url or ""))
        return parsed.netloc == "auth.openai.com" and parsed.path in OPENAI_PHONE_REQUIRED_PATHS

    def _is_openai_codex_consent_url(self, url: str) -> bool:
        parsed = urllib.parse.urlparse(str(url or ""))
        return parsed.netloc == "auth.openai.com" and parsed.path == OPENAI_CODEX_CONSENT_PATH

    def _is_workos_sso_authorize_url(self, url: str) -> bool:
        parsed = urllib.parse.urlparse(str(url or ""))
        host = str(parsed.hostname or "").strip().lower().rstrip(".")
        return host == WORKOS_SSO_AUTHORIZE_HOST and parsed.path == WORKOS_SSO_AUTHORIZE_PATH

    def _is_workos_saml_acs_url(self, url: str) -> bool:
        parsed = urllib.parse.urlparse(str(url or ""))
        host = str(parsed.hostname or "").strip().lower().rstrip(".")
        return host == WORKOS_SSO_AUTHORIZE_HOST and parsed.path.startswith(WORKOS_SAML_ACS_PATH_PREFIX)

    def _is_workos_signin_consent_url(self, url: str) -> bool:
        parsed = urllib.parse.urlparse(str(url or ""))
        host = str(parsed.hostname or "").strip().lower().rstrip(".")
        return host == WORKOS_SSO_AUTHORIZE_HOST and parsed.path == WORKOS_SIGNIN_CONSENT_PATH

    def _is_workos_interstitial_url(self, url: str) -> bool:
        parsed = urllib.parse.urlparse(str(url or ""))
        host = str(parsed.hostname or "").strip().lower().rstrip(".")
        return host == WORKOS_SSO_AUTHORIZE_HOST and parsed.path == WORKOS_INTERSTITIAL_PATH

    def _looks_like_register_text(self, value: str) -> bool:
        lowered = str(value or "").lower()
        return any(marker in lowered for marker in self.register_markers)

    def _looks_like_login_text(self, value: str) -> bool:
        lowered = str(value or "").lower()
        return any(marker in lowered for marker in LOGIN_MARKERS)

    def _find_register_url(self, response: HttpResult) -> str:
        for link in parse_html_links(response.text):
            if self._looks_like_register_text(link.href) or self._looks_like_register_text(link.text):
                return _absolute_url(response.url, link.href)
        return ""

    def _form_has_register_semantics(self, form: HtmlForm, effective_action: str) -> bool:
        field_names = {self._field_name(key) for key in form.fields}
        checkbox_names = {self._field_name(key) for key in form.checkbox_fields}
        submit = " ".join((form.submit_name, form.submit_value))
        has_strong_structure = self._has_confirm_password_field(field_names) or self._has_terms_checkbox(checkbox_names)
        if self._looks_like_register_text(effective_action):
            return True
        if self._looks_like_login_text(effective_action):
            return has_strong_structure
        if self._looks_like_register_text(submit):
            return True
        if self._looks_like_login_text(submit):
            return False
        return has_strong_structure or self._has_name_email_password_combo(field_names)

    def _has_confirm_password_field(self, field_names: set[str]) -> bool:
        return bool(
            field_names.intersection(CONFIRM_PASSWORD_FIELDS)
            or any("password" in name and "confirm" in name for name in field_names)
        )

    def _has_employee_field(self, field_names: set[str]) -> bool:
        return bool(field_names.intersection(EMPLOYEE_FIELDS))

    def _has_name_pair(self, field_names: set[str]) -> bool:
        return bool(field_names.intersection(FIRST_NAME_FIELDS) and field_names.intersection(LAST_NAME_FIELDS))

    def _has_name_email_password_combo(self, field_names: set[str]) -> bool:
        has_email = "email" in field_names or "mail" in field_names
        has_password = bool(field_names.intersection({"password", "passwd", "pwd", "pass"}))
        return bool(has_email and has_password and self._has_name_pair(field_names))

    def _has_terms_checkbox(self, checkbox_names: set[str]) -> bool:
        return any(marker in name for name in checkbox_names for marker in TERMS_MARKERS)

    def _is_workos_saml_host_url(self, url: str) -> bool:
        host = self._normalized_host(url)
        return bool(host and host in self._workos_saml_hosts)

    def _form_has_saml_context(self, form: HtmlForm) -> bool:
        field_names = {self._field_name(key) for key in form.fields}
        return "samlrequest" in field_names and "relaystate" in field_names

    def _form_has_saml_response(self, form: HtmlForm) -> bool:
        field_names = {self._field_name(key) for key in form.fields}
        return "samlresponse" in field_names

    def _form_has_workos_signin_confirm(self, form: HtmlForm) -> bool:
        field_names = {self._field_name(key) for key in form.fields}
        action_value = ""
        for key, value in form.fields.items():
            if self._field_name(key) == "action":
                action_value = str(value or "").strip().lower()
                break
        return bool({"interstitial_token", "csrf_token", "action"}.issubset(field_names) and action_value == "confirm")

    def _form_has_openai_codex_consent(self, form: HtmlForm) -> bool:
        field_names = {self._field_name(key) for key in form.fields}
        return field_names == {"workspace_id"} and bool(str(next(iter(form.fields.values()), "") or "").strip())

    def _account_sensitive_values(self, account: GeneratedAccount) -> tuple[str, ...]:
        raw = account.raw if isinstance(account.raw, dict) else {}
        values = [
            account.email,
            account.password,
            self._account_extra(account, "username") or account.email.split("@", 1)[0],
            self._account_extra(account, "employee_id"),
            self._account_extra(account, "display_name") or account.name,
            self._account_extra(account, "first_name") or account.given_name,
            self._account_extra(account, "last_name") or account.family_name,
            str(raw.get("user_token") or ""),
            self.user_token,
        ]
        return tuple(str(value).strip() for value in values if str(value or "").strip())

    def _has_sensitive_get_data(self, data: dict[str, str], account: GeneratedAccount) -> bool:
        sensitive_values = self._account_sensitive_values(account)
        for key, value in data.items():
            text_value = str(value or "")
            if not text_value:
                continue
            name = self._field_name(key)
            tokens = set(name.split("_"))
            if name in SENSITIVE_GET_FIELD_NAMES or tokens.intersection(SENSITIVE_GET_FIELD_TOKENS):
                return True
            for secret in sensitive_values:
                if secret and (text_value == secret or secret in text_value):
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

    def _redirect_location(self, response: HttpResult) -> str:
        location = super()._redirect_location(response)
        if location and self._is_workos_sso_authorize_url(response.url):
            host = self._normalized_host(location)
            if host:
                self._workos_saml_hosts.add(host)
        if (
            location
            and not self._company_registration_submitted
            and self._is_company_sso_url(response.url)
            and not self._is_company_sso_url(location)
        ):
            raise OAuthFlowError("公司 SSO 注册前 HTTP 跳转不在允许域名内", stage="company_sso_register")
        return location

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
            if any(self._form_register_score(form, response.url) > 0 for form in forms):
                return ""
            redirected = self._script_or_meta_redirect(response)
            if redirected:
                if not self._is_company_sso_url(redirected):
                    raise OAuthFlowError("公司 SSO 注册前跳转不在允许域名内", stage="company_sso_register")
                return redirected
            return ""
        return super()._extract_script_or_meta_redirect(response)

    def _form_register_score(self, form: HtmlForm, current_url: str) -> int:
        effective_action = _absolute_url(current_url, form.action or current_url)
        if not self._form_has_register_semantics(form, effective_action):
            return 0
        field_names = {self._field_name(key) for key in form.fields}
        checkbox_names = {self._field_name(key) for key in form.checkbox_fields}
        keys = " ".join(list(field_names) + list(checkbox_names))
        action = effective_action.lower()
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

    def _fill_workos_saml_form(self, form: HtmlForm, account: GeneratedAccount) -> dict[str, str]:
        data = dict(form.fields)
        username = self._account_extra(account, "username") or account.email.split("@", 1)[0]
        employee_id = self._account_extra(account, "employee_id") or username
        for key in list(data):
            lowered = self._field_name(key)
            if lowered in {"email", "mail"}:
                data[key] = account.email
            elif lowered in {"userid", "user_id", "employee", "employee_id", "employeeid", "staff", "staff_id", "staffid"}:
                data[key] = employee_id
            elif lowered in {"username", "user_name", "login"}:
                data[key] = username
        if form.submit_name:
            data.setdefault(form.submit_name, form.submit_value)
        return data

    def _submit_register_form(self, response: HttpResult, account: GeneratedAccount) -> HttpResult | None:
        forms, _links, _meta = parse_html_forms(response.text)
        if not forms:
            return None
        best = max(forms, key=lambda form: self._form_register_score(form, response.url))
        if self._form_register_score(best, response.url) <= 0:
            return None
        action = _absolute_url(response.url, best.action or response.url)
        if not self._is_company_sso_url(action):
            raise OAuthFlowError("公司 SSO 注册表单 action 不在允许域名内", stage="company_sso_register")
        data = self._fill_register_form(best, account)
        method = (best.method or "GET").upper()
        if method == "GET":
            if self._has_sensitive_get_data(data, account):
                raise OAuthFlowError("公司 SSO 注册 GET 表单包含敏感字段，拒绝写入 URL", stage="company_sso_register")
            sep = "&" if urllib.parse.urlparse(action).query else "?"
            self._company_registration_submitted = True
            return self._request("GET", action + sep + urllib.parse.urlencode(data), headers={"Referer": response.url}, allow_redirects=False)
        self._company_registration_submitted = True
        return self._request("POST", action, headers={"Referer": response.url, "Content-Type": "application/x-www-form-urlencoded"}, data=data, allow_redirects=False)

    def _submit_workos_saml_form(self, response: HttpResult, account: GeneratedAccount) -> HttpResult | None:
        if not self._is_workos_saml_host_url(response.url):
            return None
        forms, _links, _meta = parse_html_forms(response.text)
        forms = [form for form in forms if self._form_has_saml_context(form)]
        if not forms:
            return None
        best = max(forms, key=_form_score)
        action = _absolute_url(response.url, best.action or response.url)
        if not self._is_company_sso_url(action):
            raise OAuthFlowError("公司 SSO SAML 表单 action 不在允许域名内", stage="company_sso_register")
        if any("password" in self._field_name(key) or self._field_name(key) in {"passwd", "pwd"} for key in best.fields):
            raise OAuthFlowError("公司 SSO 注册前拒绝提交带密码的 SAML 登录表单", stage="company_sso_register")
        data = self._fill_workos_saml_form(best, account)
        method = (best.method or "GET").upper()
        if method == "GET":
            if self._has_sensitive_get_data(data, account):
                raise OAuthFlowError("公司 SSO SAML GET 表单包含敏感字段，拒绝写入 URL", stage="company_sso_register")
            sep = "&" if urllib.parse.urlparse(action).query else "?"
            self._company_registration_submitted = True
            return self._request("GET", action + sep + urllib.parse.urlencode(data), headers={"Referer": response.url}, allow_redirects=False)
        self._company_registration_submitted = True
        return self._request("POST", action, headers={"Referer": response.url, "Content-Type": "application/x-www-form-urlencoded"}, data=data, allow_redirects=False)

    def _submit_workos_saml_response_form(self, response: HttpResult) -> HttpResult | None:
        if not self._is_workos_saml_host_url(response.url):
            return None
        forms, _links, _meta = parse_html_forms(response.text)
        forms = [form for form in forms if self._form_has_saml_response(form)]
        if not forms:
            return None
        best = forms[0]
        action = _absolute_url(response.url, best.action or response.url)
        if not self._is_workos_saml_acs_url(action):
            raise OAuthFlowError("公司 SSO SAMLResponse 表单 action 不是 WorkOS ACS", stage="company_sso_continue")
        method = (best.method or "GET").upper()
        if method != "POST":
            raise OAuthFlowError("公司 SSO SAMLResponse 表单必须使用 POST", stage="company_sso_continue")
        data = dict(best.fields)
        if best.submit_name:
            data.setdefault(best.submit_name, best.submit_value)
        return self._request("POST", action, headers={"Referer": response.url, "Content-Type": "application/x-www-form-urlencoded"}, data=data, allow_redirects=False)

    def _submit_workos_signin_consent_form(self, response: HttpResult) -> HttpResult | None:
        if not self._company_registration_submitted or not self._is_workos_signin_consent_url(response.url):
            return None
        forms, _links, _meta = parse_html_forms(response.text)
        forms = [form for form in forms if self._form_has_workos_signin_confirm(form)]
        if not forms:
            return None
        best = forms[0]
        action = _absolute_url(response.url, best.action or response.url)
        if not self._is_workos_interstitial_url(action):
            raise OAuthFlowError("公司 SSO WorkOS 确认表单 action 不是 signin interstitial", stage="company_sso_continue")
        method = (best.method or "GET").upper()
        if method != "POST":
            raise OAuthFlowError("公司 SSO WorkOS 确认表单必须使用 POST", stage="company_sso_continue")
        return self._request(
            "POST",
            action,
            headers={
                "Referer": response.url,
                "Origin": f"https://{WORKOS_SSO_AUTHORIZE_HOST}",
                "Content-Type": "application/x-www-form-urlencoded",
            },
            data=dict(best.fields),
            allow_redirects=False,
        )

    def _submit_openai_codex_consent_form(self, response: HttpResult) -> HttpResult | None:
        if not self._company_registration_submitted or not self._is_openai_codex_consent_url(response.url):
            return None
        forms, _links, _meta = parse_html_forms(response.text)
        forms = [form for form in forms if self._form_has_openai_codex_consent(form)]
        if not forms:
            return None
        best = forms[0]
        action = _absolute_url(response.url, best.action or response.url)
        if not self._is_openai_codex_consent_url(action):
            raise OAuthFlowError("OpenAI Codex 授权表单 action 不匹配", stage="codex_consent")
        method = (best.method or "GET").upper()
        if method != "POST":
            raise OAuthFlowError("OpenAI Codex 授权表单必须使用 POST", stage="codex_consent")
        workspace_id = str(next(iter(best.fields.values()), "") or "").strip()
        return self._request(
            "POST",
            "https://auth.openai.com/api/accounts/workspace/select",
            headers={
                "accept": "application/json",
                "content-type": "application/json",
                "Referer": response.url,
                "Origin": "https://auth.openai.com",
            },
            json_body={"workspace_id": workspace_id},
            allow_redirects=False,
        )

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
            if self._has_sensitive_get_data(data, account):
                raise OAuthFlowError("公司 SSO 后续 GET 表单包含敏感字段，拒绝写入 URL", stage="company_sso_continue")
            sep = "&" if urllib.parse.urlparse(action).query else "?"
            return self._request("GET", action + sep + urllib.parse.urlencode(data), headers={"Referer": response.url}, allow_redirects=False)
        return self._request("POST", action, headers={"Referer": response.url, "Content-Type": "application/x-www-form-urlencoded"}, data=data, allow_redirects=False)

    def _handle_custom_page(self, response: HttpResult, account: GeneratedAccount, stage: str) -> str | HttpResult | None:
        if not self._is_company_sso_url(response.url):
            if account.email and self._is_openai_intermediate_url(response.url):
                return None
            if self._is_openai_phone_required_url(response.url):
                path = self._save_html("openai_phone_required.html", response)
                raise OAuthFlowError(
                    "OpenAI 要求绑定手机号，纯 HTTP 流程无法继续",
                    stage="openai_phone_required",
                    data={"url": response.url, "artifact": str(path)},
                )
            submitted_signin_consent = self._submit_workos_signin_consent_form(response)
            if submitted_signin_consent is not None:
                return submitted_signin_consent
            submitted_codex_consent = self._submit_openai_codex_consent_form(response)
            if submitted_codex_consent is not None:
                return submitted_codex_consent
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
            submitted_saml = self._submit_workos_saml_form(response, account)
            if submitted_saml is not None:
                return submitted_saml
            raise OAuthFlowError("公司 SSO 页面未找到注册链接或注册表单", stage="company_sso_register", data={"url": response.url})
        submitted_saml_response = self._submit_workos_saml_response_form(response)
        if submitted_saml_response is not None:
            return submitted_saml_response
        submitted_login = self._submit_company_form(response, account)
        if submitted_login is not None:
            return submitted_login
        return None
