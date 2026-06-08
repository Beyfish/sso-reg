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
