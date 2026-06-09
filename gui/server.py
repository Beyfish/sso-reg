from __future__ import annotations

import argparse
import contextlib
import io
import json
import os
import random
import re
import string
import subprocess
import sys
import threading
import time
import urllib.parse
from dataclasses import dataclass, field
from http.server import SimpleHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any


def _project_root() -> Path:
    if getattr(sys, "frozen", False):
        return Path(sys.executable).resolve().parent
    return Path(__file__).resolve().parents[1]


PROJECT_ROOT = _project_root()
GUI_ROOT = Path(getattr(sys, "_MEIPASS", Path(__file__).resolve().parent)) / "gui" if getattr(sys, "frozen", False) else Path(__file__).resolve().parent
RUN_SCRIPT = PROJECT_ROOT / "scripts" / "run_company_sso_codex.py"
DEFAULT_ARTIFACT_ROOT = PROJECT_ROOT / "artifacts" / "gui_company_sso"
EXPORT_TARGETS = {"none", "sub2api", "cpa", "sub2api,cpa", "cpa,sub2api"}
SENSITIVE_FIELDS = {"password", "sub2api_password", "cpa_management_key"}


class GuiError(ValueError):
    pass


@dataclass
class Job:
    id: str
    status: str = "queued"
    started_at: float = field(default_factory=time.time)
    finished_at: float | None = None
    command: list[str] = field(default_factory=list)
    public_payload: dict[str, Any] = field(default_factory=dict)
    artifact_dir: str = ""
    returncode: int | None = None
    stdout: str = ""
    stderr: str = ""
    result: dict[str, Any] | None = None
    error: str = ""

    def as_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "status": self.status,
            "started_at": self.started_at,
            "finished_at": self.finished_at,
            "command": redact_command(self.command),
            "payload": self.public_payload,
            "artifact_dir": self.artifact_dir,
            "returncode": self.returncode,
            "stdout": self.stdout[-12000:],
            "stderr": self.stderr[-12000:],
            "result": self.result,
            "error": self.error,
        }


JOBS: dict[str, Job] = {}
JOBS_LOCK = threading.Lock()


def _clean_text(value: Any) -> str:
    return str(value or "").strip()


def _safe_job_id() -> str:
    suffix = "".join(random.choice(string.ascii_lowercase + string.digits) for _ in range(6))
    return time.strftime("%Y%m%d-%H%M%S", time.localtime()) + "-" + suffix


def _domain_host(value: str) -> str:
    raw = _clean_text(value)
    parsed = urllib.parse.urlparse(raw if "://" in raw else "//" + raw)
    return str(parsed.hostname or "").strip().lower().rstrip(".")


def _valid_domain(value: str) -> bool:
    host = _domain_host(value)
    if not host or "." not in host or len(host) > 253:
        return False
    labels = host.split(".")
    return all(
        label
        and len(label) <= 63
        and not label.startswith("-")
        and not label.endswith("-")
        and all(ch.isascii() and (ch.isalnum() or ch == "-") for ch in label)
        for label in labels
    )


def _valid_email(value: str) -> bool:
    text = _clean_text(value)
    if any(ch.isspace() for ch in text):
        return False
    local, sep, domain = text.partition("@")
    return bool(local and sep and _valid_domain(domain))


def _public_payload(payload: dict[str, Any]) -> dict[str, Any]:
    out: dict[str, Any] = {}
    for key, value in payload.items():
        out[key] = "***REDACTED***" if key in SENSITIVE_FIELDS and _clean_text(value) else value
    return out


def redact_command(command: list[str]) -> list[str]:
    redacted: list[str] = []
    skip_next = False
    for item in command:
        if skip_next:
            redacted.append("***REDACTED***")
            skip_next = False
            continue
        redacted.append(item)
        if item in {"--password", "--sub2api-password", "--cpa-management-key"}:
            skip_next = True
    return redacted


def _env_from_payload(payload: dict[str, Any]) -> dict[str, str]:
    mapping = {
        "sub2api_url": "SUB2API_URL",
        "sub2api_email": "SUB2API_EMAIL",
        "sub2api_password": "SUB2API_PASSWORD",
        "sub2api_group": "SUB2API_GROUP",
        "model_whitelist": "SUB2API_MODEL_WHITELIST",
        "cpa_url": "CPA_URL",
        "cpa_management_key": "CPA_MANAGEMENT_KEY",
    }
    env: dict[str, str] = {}
    for source, target in mapping.items():
        value = _clean_text(payload.get(source))
        if value:
            env[target] = value
    return env


def _company_sso_args(payload: dict[str, Any], artifact_dir: Path) -> list[str]:
    args = [
        "--sso-domain",
        _clean_text(payload.get("sso_domain")),
        "--artifact-dir",
        str(artifact_dir),
        "--export-targets",
        _clean_text(payload.get("export_targets") or "none").lower(),
    ]
    seed = _clean_text(payload.get("seed"))
    if seed:
        args.extend(["--seed", seed])
    email_domain = _clean_text(payload.get("email_domain"))
    if email_domain:
        args.extend(["--email-domain", email_domain])
    timeout = _clean_text(payload.get("timeout") or "60")
    if timeout:
        args.extend(["--timeout", timeout])
    if bool(payload.get("no_proxy")):
        args.append("--no-proxy")
    email = _clean_text(payload.get("email"))
    password = _clean_text(payload.get("password"))
    if email:
        args.extend(["--email", email, "--password", password])
        for source, flag in (
            ("username", "--username"),
            ("first_name", "--first-name"),
            ("last_name", "--last-name"),
            ("employee_id", "--employee-id"),
        ):
            value = _clean_text(payload.get(source))
            if value:
                args.extend([flag, value])
    return args


def validate_payload(payload: dict[str, Any]) -> None:
    if not isinstance(payload, dict):
        raise GuiError("请求体必须是 JSON object")
    sso_domain = _clean_text(payload.get("sso_domain"))
    if not _valid_domain(sso_domain):
        raise GuiError("SSO 域名无效")
    export_targets = _clean_text(payload.get("export_targets") or "none").lower()
    if export_targets not in EXPORT_TARGETS:
        raise GuiError("导出目标无效")
    email = _clean_text(payload.get("email"))
    password = _clean_text(payload.get("password"))
    if email or password:
        if not _valid_email(email):
            raise GuiError("员工邮箱无效")
        if not password:
            raise GuiError("显式员工模式缺少密码")
    email_domain = _clean_text(payload.get("email_domain"))
    if email_domain and not _valid_domain(email_domain):
        raise GuiError("邮箱域名无效")


def build_company_sso_command(payload: dict[str, Any], artifact_dir: Path) -> tuple[list[str], dict[str, str]]:
    validate_payload(payload)
    runner = "--run-company-sso" if getattr(sys, "frozen", False) else str(RUN_SCRIPT)
    command = [
        sys.executable,
        runner,
        *_company_sso_args(payload, artifact_dir),
    ]
    env_extra = _env_from_payload(payload)
    return command, env_extra


def _load_result(artifact_dir: str) -> dict[str, Any] | None:
    result_path = Path(artifact_dir) / "result.json"
    if not result_path.exists():
        return None
    try:
        return json.loads(result_path.read_text(encoding="utf-8"))
    except json.JSONDecodeError:
        return None


def _run_frozen_job(job: Job, env_extra: dict[str, str]) -> tuple[int, str, str]:
    from lib.company_sso_cli import main as company_sso_main

    env_previous = {key: os.environ.get(key) for key in env_extra}
    os.environ.update(env_extra)
    stdout = io.StringIO()
    stderr = io.StringIO()
    try:
        with contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(stderr):
            returncode = company_sso_main(job.command[2:])
    finally:
        for key, value in env_previous.items():
            if value is None:
                os.environ.pop(key, None)
            else:
                os.environ[key] = value
    return int(returncode), stdout.getvalue(), stderr.getvalue()


def _run_job(job: Job, env_extra: dict[str, str]) -> None:
    with JOBS_LOCK:
        job.status = "running"
    env = os.environ.copy()
    env.update(env_extra)
    try:
        if getattr(sys, "frozen", False):
            returncode, stdout, stderr = _run_frozen_job(job, env_extra)
        else:
            process = subprocess.run(
                job.command,
                cwd=PROJECT_ROOT,
                env=env,
                capture_output=True,
                text=True,
                timeout=1800,
                check=False,
            )
            returncode, stdout, stderr = process.returncode, process.stdout, process.stderr
        result = _load_result(job.artifact_dir)
        with JOBS_LOCK:
            job.returncode = returncode
            job.stdout = stdout
            job.stderr = stderr
            job.result = result
            job.status = "succeeded" if returncode == 0 else "failed"
            job.finished_at = time.time()
    except subprocess.TimeoutExpired as exc:
        with JOBS_LOCK:
            job.status = "failed"
            job.error = "运行超时"
            job.stdout = exc.stdout or ""
            job.stderr = exc.stderr or ""
            job.finished_at = time.time()
    except Exception as exc:
        with JOBS_LOCK:
            job.status = "failed"
            job.error = str(exc)
            job.finished_at = time.time()


def create_job(payload: dict[str, Any]) -> Job:
    job_id = _safe_job_id()
    artifact_dir = DEFAULT_ARTIFACT_ROOT / job_id
    command, env_extra = build_company_sso_command(payload, artifact_dir)
    job = Job(
        id=job_id,
        command=command,
        public_payload=_public_payload(payload),
        artifact_dir=str(artifact_dir),
    )
    with JOBS_LOCK:
        JOBS[job.id] = job
    thread = threading.Thread(target=_run_job, args=(job, env_extra), daemon=True)
    thread.start()
    return job


class GuiHandler(SimpleHTTPRequestHandler):
    server_version = "CompanySSOGui/0.1"

    def __init__(self, *args: Any, **kwargs: Any):
        super().__init__(*args, directory=str(GUI_ROOT), **kwargs)

    def log_message(self, format: str, *args: Any) -> None:
        return

    def _json(self, payload: Any, status: int = 200) -> None:
        raw = json.dumps(payload, ensure_ascii=False, sort_keys=True, default=str).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Cache-Control", "no-store")
        self.send_header("Content-Length", str(len(raw)))
        self.end_headers()
        self.wfile.write(raw)

    def _read_json(self) -> dict[str, Any]:
        length = int(self.headers.get("Content-Length") or "0")
        raw = self.rfile.read(min(length, 1024 * 64))
        try:
            payload = json.loads(raw.decode("utf-8") or "{}")
        except json.JSONDecodeError as exc:
            raise GuiError("JSON 格式无效") from exc
        if not isinstance(payload, dict):
            raise GuiError("请求体必须是 JSON object")
        return payload

    def do_GET(self) -> None:
        parsed = urllib.parse.urlparse(self.path)
        if parsed.path == "/api/runs":
            with JOBS_LOCK:
                jobs = [job.as_dict() for job in sorted(JOBS.values(), key=lambda item: item.started_at, reverse=True)]
            self._json({"runs": jobs})
            return
        match = re.fullmatch(r"/api/runs/([A-Za-z0-9_-]+)", parsed.path)
        if match:
            with JOBS_LOCK:
                job = JOBS.get(match.group(1))
                payload = job.as_dict() if job else None
            self._json(payload or {"error": "not_found"}, status=200 if payload else 404)
            return
        return super().do_GET()

    def do_POST(self) -> None:
        parsed = urllib.parse.urlparse(self.path)
        try:
            if parsed.path == "/api/preview":
                payload = self._read_json()
                command, _env_extra = build_company_sso_command(payload, DEFAULT_ARTIFACT_ROOT / "preview")
                self._json({"command": redact_command(command)})
                return
            if parsed.path == "/api/runs":
                payload = self._read_json()
                job = create_job(payload)
                self._json(job.as_dict(), status=202)
                return
            self._json({"error": "not_found"}, status=404)
        except GuiError as exc:
            self._json({"error": str(exc)}, status=400)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Local GUI server for company SSO Codex automation")
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=8765)
    args = parser.parse_args(argv)
    httpd = ThreadingHTTPServer((args.host, args.port), GuiHandler)
    print(f"http://{args.host}:{args.port}", flush=True)
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        return 0
    finally:
        httpd.server_close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
