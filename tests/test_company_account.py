from __future__ import annotations

import pytest

from lib.company_account import CompanyAccount, generate_dev_account


def test_generate_dev_account_is_deterministic_with_seed():
    account = generate_dev_account(email_domain="example.com", seed="case-1", password_length=16)
    same_account = generate_dev_account(email_domain="example.com", seed="case-1", password_length=16)

    assert account.email == "dev.user.0906@example.com"
    assert account.username == "dev.user.0906"
    assert account.first_name == "Dev"
    assert account.last_name == "User0906"
    assert same_account.email == account.email
    assert same_account.username == account.username
    assert same_account.password == account.password
    assert len(account.password) == 16
    assert any(ch.islower() for ch in account.password)
    assert any(ch.isupper() for ch in account.password)
    assert any(ch.isdigit() for ch in account.password)
    assert any(ch in "!@#$%^&*" for ch in account.password)


def test_generate_dev_account_accepts_valid_domains_and_normalizes_leading_at():
    root_domain = generate_dev_account(email_domain="@Example.COM", seed="case-1")
    subdomain = generate_dev_account(email_domain="sub.example.com", seed="case-1")

    assert root_domain.email == "dev.user.0906@example.com"
    assert subdomain.email == "dev.user.0906@sub.example.com"


@pytest.mark.parametrize(
    "email_domain",
    [
        "foo@bar.com",
        "example.com/path",
        ".com",
        "company.",
        "exa mple.com",
        "example .com",
    ],
)
def test_generate_dev_account_rejects_invalid_domains(email_domain):
    with pytest.raises(ValueError, match="email_domain"):
        generate_dev_account(email_domain=email_domain, seed="case-1")


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

    public = account.as_public_dict()

    assert "password" not in public
    assert public["has_password"] is True
    assert account.as_private_dict()["password"] == "Secret123!"


def test_public_dict_marks_empty_password_as_false():
    account = CompanyAccount(
        username="bob.li",
        email="bob.li@example.com",
        password="",
        first_name="Bob",
        last_name="Li",
    )

    assert account.as_public_dict()["has_password"] is False
