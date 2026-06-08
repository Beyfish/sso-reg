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

    def as_public_dict(self) -> dict[str, str | bool]:
        return {
            "username": self.username,
            "email": self.email,
            "first_name": self.first_name,
            "last_name": self.last_name,
            "display_name": self.display_name,
            "employee_id": self.employee_id,
            "has_password": bool(self.password),
        }

    def as_private_dict(self) -> dict[str, str | bool]:
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


def _is_valid_domain(domain: str) -> bool:
    if not domain or "." not in domain or len(domain) > 253:
        return False
    if any(ch.isspace() for ch in domain):
        return False

    labels = domain.split(".")
    for label in labels:
        if not label or len(label) > 63:
            return False
        if label.startswith("-") or label.endswith("-"):
            return False
        if not all(ch.isascii() and (ch.isalnum() or ch == "-") for ch in label):
            return False
    return True


def generate_dev_account(*, email_domain: str, seed: str = "", password_length: int = 16) -> CompanyAccount:
    domain = str(email_domain or "").strip().lstrip("@").lower()
    if not _is_valid_domain(domain):
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
