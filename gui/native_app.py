from __future__ import annotations

import subprocess
import sys
import tkinter as tk
import tkinter.font as tkfont
from pathlib import Path
from tkinter import ttk
from typing import Any

PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from gui.server import (
    DEFAULT_ARTIFACT_ROOT,
    JOBS,
    JOBS_LOCK,
    GuiError,
    build_company_sso_command,
    create_job,
    redact_command,
)

DEFAULT_SSO_DOMAIN = "hegiw77632.cloud-ip.cc"
UI_FONT = "MiSans"
UI_FALLBACK_FONT = "Microsoft YaHei UI"
MONO_FONT = "Cascadia Mono"
STATUS_LABELS = {
    "queued": "排队中",
    "running": "运行中",
    "succeeded": "成功",
    "failed": "失败",
}


def default_payload() -> dict[str, Any]:
    return {
        "sso_domain": DEFAULT_SSO_DOMAIN,
        "seed": "smoke-001",
        "email_domain": "",
        "timeout": "60",
        "no_proxy": False,
        "export_targets": "none",
    }


def command_preview(payload: dict[str, Any], artifact_dir: Path | None = None) -> str:
    command, _env = build_company_sso_command(payload, artifact_dir or DEFAULT_ARTIFACT_ROOT / "preview")
    return subprocess.list2cmdline(redact_command(command))


class NativeCompanySsoApp:
    def __init__(self, root: tk.Tk) -> None:
        self.root = root
        self.root.title("企业 SSO Codex 控制台")
        self.root.geometry("1120x760")
        self.root.minsize(880, 620)
        self.root.configure(bg="#f3f5f8")

        self.account_mode = tk.StringVar(value="generated")
        self.export_target = tk.StringVar(value="none")
        self.sso_domain = tk.StringVar(value=DEFAULT_SSO_DOMAIN)
        self.seed = tk.StringVar(value="smoke-001")
        self.email_domain = tk.StringVar()
        self.timeout = tk.StringVar(value="60")
        self.no_proxy = tk.BooleanVar(value=False)
        self.email = tk.StringVar()
        self.password = tk.StringVar()
        self.first_name = tk.StringVar()
        self.last_name = tk.StringVar()
        self.employee_id = tk.StringVar()
        self.sub2api_url = tk.StringVar()
        self.sub2api_email = tk.StringVar()
        self.sub2api_password = tk.StringVar()
        self.sub2api_group = tk.StringVar()
        self.cpa_url = tk.StringVar()
        self.cpa_management_key = tk.StringVar()
        self.active_job_id = ""

        self._configure_style()
        self._build_shell()
        self._show_run()
        self._refresh_preview()

    def _configure_style(self) -> None:
        style = ttk.Style()
        style.theme_use("clam")
        families = set(tkfont.families())
        ui_font = UI_FONT if UI_FONT in families else UI_FALLBACK_FONT
        mono_font = MONO_FONT if MONO_FONT in families else "Consolas"
        self.ui_font = ui_font
        self.mono_font = mono_font
        style.configure(".", font=(ui_font, 10), background="#f4f6f9", foreground="#171a20")
        style.configure("Shell.TFrame", background="#f4f6f9")
        style.configure("Topbar.TFrame", background="#111827", bordercolor="#111827", relief="solid", borderwidth=1)
        style.configure("Panel.TFrame", background="#ffffff", bordercolor="#d9dee7", relief="solid", borderwidth=1)
        style.configure("PanelBody.TFrame", background="#ffffff")
        style.configure("Export.TFrame", background="#f9fafc", bordercolor="#d9dee7", relief="solid", borderwidth=1)
        style.configure("Title.TLabel", font=(ui_font, 20, "bold"), background="#f4f6f9", foreground="#080a0f")
        style.configure("Subtitle.TLabel", font=(ui_font, 10), background="#f4f6f9", foreground="#3e4654")
        style.configure("Brand.TLabel", font=(ui_font, 11, "bold"), background="#111827", foreground="#ffffff")
        style.configure("Domain.TLabel", font=(mono_font, 9), background="#111827", foreground="#9ca3af")
        style.configure("PanelTitle.TLabel", font=(ui_font, 12, "bold"), background="#ffffff", foreground="#080a0f")
        style.configure("Muted.TLabel", font=(ui_font, 9, "bold"), background="#ffffff", foreground="#6b7280")
        style.configure("ExportTitle.TLabel", font=(ui_font, 10, "bold"), background="#f9fafc", foreground="#080a0f")
        style.configure("Nav.TButton", padding=(12, 8), background="#111827", foreground="#d1d5db", relief="flat")
        style.map("Nav.TButton", background=[("active", "#ffffff")], foreground=[("active", "#080a0f")])
        style.configure("Primary.TButton", padding=(18, 10), background="#0b6cff", foreground="#ffffff", relief="flat")
        style.map("Primary.TButton", background=[("active", "#0051c8")])
        style.configure("Secondary.TButton", padding=(14, 9), background="#ffffff", foreground="#3e4654", relief="flat")
        style.map("Secondary.TButton", foreground=[("active", "#0b6cff")])
        style.configure("Segment.TRadiobutton", padding=(10, 7), background="#ffffff", foreground="#3e4654")
        style.configure("TEntry", fieldbackground="#ffffff", bordercolor="#cfd6e1", lightcolor="#cfd6e1", padding=(10, 8))
        style.configure("TCheckbutton", background="#ffffff", foreground="#3e4654")

    def _build_shell(self) -> None:
        shell = ttk.Frame(self.root, style="Shell.TFrame")
        shell.pack(fill="both", expand=True, padx=16, pady=14)

        topbar = ttk.Frame(shell, style="Topbar.TFrame", padding=(14, 10))
        topbar.pack(fill="x")
        brand_mark = tk.Label(
            topbar,
            text="SSO",
            bg="#11151b",
            fg="#ffffff",
            font=(self.mono_font, 9, "bold"),
            padx=9,
            pady=7,
        )
        brand_mark.pack(side="left", padx=(0, 10))
        brand_copy = ttk.Frame(topbar, style="PanelBody.TFrame")
        brand_copy.pack(side="left", padx=(0, 20))
        ttk.Label(brand_copy, text="企业 SSO 控制台", style="Brand.TLabel").pack(anchor="w")
        ttk.Label(brand_copy, textvariable=self.sso_domain, style="Domain.TLabel").pack(anchor="w")
        ttk.Button(topbar, text="单次运行", style="Nav.TButton", command=self._show_run).pack(side="left", padx=2)
        ttk.Button(topbar, text="批量注册", style="Nav.TButton", command=self._show_batch).pack(side="left", padx=2)
        ttk.Button(topbar, text="健康检查", style="Nav.TButton", command=self._show_health).pack(side="left", padx=2)
        ttk.Button(topbar, text="运行产物", style="Nav.TButton", command=self._show_artifacts).pack(side="left", padx=2)
        ttk.Button(topbar, text="开始运行", style="Primary.TButton", command=self._start_run).pack(side="right")

        self.workspace = ttk.Frame(shell, style="Shell.TFrame")
        self.workspace.pack(fill="both", expand=True, pady=(20, 0))
        self.workspace.columnconfigure(0, weight=1)
        self.workspace.rowconfigure(1, weight=1)

        header = ttk.Frame(self.workspace, style="Shell.TFrame", padding=(4, 0, 4, 18))
        header.grid(row=0, column=0, sticky="ew")
        header.columnconfigure(0, weight=1)
        ttk.Label(header, text="输入 SSO 域名，完成企业授权注册。", style="Title.TLabel").grid(row=0, column=0, sticky="w")
        ttk.Label(
            header,
            text="表单实时生成命令。运行日志、导出目标和本地产物在同一个工作台内查看。",
            style="Subtitle.TLabel",
        ).grid(row=1, column=0, sticky="w", pady=(8, 0))

        self.content = ttk.Frame(self.workspace, style="Shell.TFrame", padding=(24, 20))
        self.content.grid(row=1, column=0, sticky="nsew")
        self.content.columnconfigure(0, weight=1)
        self.content.rowconfigure(0, weight=1)

    def _clear_content(self) -> None:
        for child in self.content.winfo_children():
            child.destroy()

    def _labeled_entry(
        self,
        parent: ttk.Frame,
        label: str,
        variable: tk.StringVar,
        row: int,
        column: int = 0,
        show: str = "",
    ) -> ttk.Entry:
        frame = ttk.Frame(parent, style="PanelBody.TFrame")
        frame.grid(row=row, column=column, sticky="ew", padx=6, pady=6)
        frame.columnconfigure(0, weight=1)
        ttk.Label(frame, text=label, style="Muted.TLabel").grid(row=0, column=0, sticky="w", pady=(0, 4))
        entry = ttk.Entry(frame, textvariable=variable, show=show)
        entry.grid(row=1, column=0, sticky="ew")
        entry.bind("<KeyRelease>", lambda _event: self._refresh_preview())
        return entry

    def _show_run(self) -> None:
        self._clear_content()
        layout = ttk.Frame(self.content, style="Shell.TFrame")
        layout.grid(row=0, column=0, sticky="nsew")
        layout.columnconfigure(0, weight=3)
        layout.columnconfigure(1, weight=2)

        form_panel = ttk.Frame(layout, style="Panel.TFrame", padding=24)
        form_panel.grid(row=0, column=0, sticky="nsew", padx=(0, 20))
        form_panel.columnconfigure(0, weight=1)
        form_panel.columnconfigure(1, weight=1)
        ttk.Label(form_panel, text="运行配置", style="PanelTitle.TLabel").grid(
            row=0, column=0, columnspan=2, sticky="w", pady=(0, 12)
        )
        self._labeled_entry(form_panel, "SSO 域名", self.sso_domain, 1, 0).grid_configure(columnspan=2)

        mode_frame = ttk.Frame(form_panel, style="PanelBody.TFrame")
        mode_frame.grid(row=2, column=0, columnspan=2, sticky="ew", pady=(8, 4))
        ttk.Radiobutton(
            mode_frame,
            text="自动生成员工",
            value="generated",
            variable=self.account_mode,
            style="Segment.TRadiobutton",
            command=self._sync_sections,
        ).pack(side="left", padx=(0, 8))
        ttk.Radiobutton(
            mode_frame,
            text="使用已有员工",
            value="explicit",
            variable=self.account_mode,
            style="Segment.TRadiobutton",
            command=self._sync_sections,
        ).pack(side="left")

        self.generated_frame = ttk.Frame(form_panel, style="PanelBody.TFrame")
        self.generated_frame.grid(row=3, column=0, columnspan=2, sticky="ew")
        self.generated_frame.columnconfigure(0, weight=1)
        self.generated_frame.columnconfigure(1, weight=1)
        self._labeled_entry(self.generated_frame, "生成种子", self.seed, 0, 0)
        self._labeled_entry(self.generated_frame, "邮箱域名", self.email_domain, 0, 1)

        self.explicit_frame = ttk.Frame(form_panel, style="PanelBody.TFrame")
        self.explicit_frame.columnconfigure(0, weight=1)
        self.explicit_frame.columnconfigure(1, weight=1)
        self.explicit_frame.columnconfigure(2, weight=1)
        self._labeled_entry(self.explicit_frame, "员工邮箱", self.email, 0, 0)
        self._labeled_entry(self.explicit_frame, "初始密码", self.password, 0, 1, show="*")
        self._labeled_entry(self.explicit_frame, "名字", self.first_name, 1, 0)
        self._labeled_entry(self.explicit_frame, "姓氏", self.last_name, 1, 1)
        self._labeled_entry(self.explicit_frame, "员工编号", self.employee_id, 1, 2)

        self._labeled_entry(form_panel, "超时时间（秒）", self.timeout, 5, 0)
        ttk.Checkbutton(
            form_panel,
            text="不使用代理",
            variable=self.no_proxy,
            command=self._refresh_preview,
        ).grid(row=5, column=1, sticky="sw", padx=6, pady=10)

        ttk.Label(form_panel, text="导出目标", style="Muted.TLabel").grid(
            row=6, column=0, columnspan=2, sticky="w", padx=6, pady=(12, 2)
        )
        export_frame = ttk.Frame(form_panel, style="PanelBody.TFrame")
        export_frame.grid(row=7, column=0, columnspan=2, sticky="ew", padx=2)
        export_frame.columnconfigure(0, weight=1)
        export_frame.columnconfigure(1, weight=1)
        for index, (text, value) in enumerate(
            (("仅保存令牌", "none"), ("Sub2API", "sub2api"), ("CPA", "cpa"), ("同时导出", "sub2api,cpa"))
        ):
            ttk.Radiobutton(
                export_frame,
                text=text,
                value=value,
                variable=self.export_target,
                style="Segment.TRadiobutton",
                command=self._sync_sections,
            ).grid(row=index // 2, column=index % 2, sticky="w", padx=4, pady=2)

        self.sub2api_frame = ttk.Frame(form_panel, style="Export.TFrame", padding=16)
        self.sub2api_frame.columnconfigure(0, weight=1)
        self.sub2api_frame.columnconfigure(1, weight=1)
        ttk.Label(self.sub2api_frame, text="Sub2API", style="ExportTitle.TLabel").grid(
            row=0, column=0, columnspan=2, sticky="w"
        )
        self._labeled_entry(self.sub2api_frame, "服务地址", self.sub2api_url, 1, 0)
        self._labeled_entry(self.sub2api_frame, "分组", self.sub2api_group, 1, 1)
        self._labeled_entry(self.sub2api_frame, "管理员邮箱", self.sub2api_email, 2, 0)
        self._labeled_entry(self.sub2api_frame, "管理员密码", self.sub2api_password, 2, 1, show="*")

        self.cpa_frame = ttk.Frame(form_panel, style="Export.TFrame", padding=16)
        self.cpa_frame.columnconfigure(0, weight=1)
        self.cpa_frame.columnconfigure(1, weight=1)
        ttk.Label(self.cpa_frame, text="CLIProxyAPI", style="ExportTitle.TLabel").grid(
            row=0, column=0, columnspan=2, sticky="w"
        )
        self._labeled_entry(self.cpa_frame, "服务地址", self.cpa_url, 1, 0)
        self._labeled_entry(self.cpa_frame, "管理密钥", self.cpa_management_key, 1, 1, show="*")

        run_panel = ttk.Frame(layout, style="Panel.TFrame", padding=24)
        run_panel.grid(row=0, column=1, sticky="nsew")
        run_panel.columnconfigure(0, weight=1)
        ttk.Label(run_panel, text="运行状态", style="PanelTitle.TLabel").grid(row=0, column=0, sticky="w")
        self.state_label = ttk.Label(run_panel, text="就绪", style="Muted.TLabel")
        self.state_label.grid(row=0, column=1, sticky="e")
        self.command_text = tk.Text(
            run_panel,
            height=7,
            wrap="word",
            bg="#11151b",
            fg="#e8edf4",
            insertbackground="#e8edf4",
            relief="flat",
            bd=0,
            font=(self.mono_font, 9),
            padx=12,
            pady=12,
        )
        self.command_text.grid(row=1, column=0, columnspan=2, sticky="ew", pady=(14, 10))
        self.log_text = tk.Text(
            run_panel,
            height=15,
            wrap="word",
            bg="#11151b",
            fg="#e8edf4",
            insertbackground="#e8edf4",
            relief="flat",
            bd=0,
            font=(self.mono_font, 9),
            padx=12,
            pady=12,
        )
        self.log_text.insert("1.0", "尚未运行。")
        self.log_text.grid(row=2, column=0, columnspan=2, sticky="nsew")
        run_panel.rowconfigure(2, weight=1)

        self._sync_sections()

    def _show_batch(self) -> None:
        self._simple_view("批量命令", "python scripts\\run_batch_tui.py --mode register --count 10 --threads 3 --retries 5 --yes")

    def _show_health(self) -> None:
        self._simple_view("Sub2API 健康检查", "python scripts\\check_sub2api_group.py --group 5")

    def _show_artifacts(self) -> None:
        self._clear_content()
        panel = ttk.Frame(self.content, style="Panel.TFrame", padding=24)
        panel.grid(row=0, column=0, sticky="nsew")
        panel.columnconfigure(0, weight=1)
        ttk.Label(panel, text="运行产物", style="PanelTitle.TLabel").grid(row=0, column=0, sticky="w")
        output = tk.Text(
            panel,
            height=20,
            wrap="word",
            bg="#11151b",
            fg="#e8edf4",
            insertbackground="#e8edf4",
            relief="flat",
            bd=0,
            font=(self.mono_font, 9),
            padx=12,
            pady=12,
        )
        output.grid(row=1, column=0, sticky="nsew", pady=(14, 0))
        panel.rowconfigure(1, weight=1)
        with JOBS_LOCK:
            jobs = sorted(JOBS.values(), key=lambda item: item.started_at, reverse=True)
        output.insert(
            "1.0",
            "\n\n".join(f"{job.id} | {STATUS_LABELS.get(job.status, job.status)}\n{job.artifact_dir}" for job in jobs)
            or "暂无本地运行记录",
        )

    def _simple_view(self, title: str, command: str) -> None:
        self._clear_content()
        panel = ttk.Frame(self.content, style="Panel.TFrame", padding=24)
        panel.grid(row=0, column=0, sticky="nsew")
        panel.columnconfigure(0, weight=1)
        ttk.Label(panel, text=title, style="PanelTitle.TLabel").grid(row=0, column=0, sticky="w")
        box = tk.Text(
            panel,
            height=8,
            wrap="word",
            bg="#11151b",
            fg="#e8edf4",
            insertbackground="#e8edf4",
            relief="flat",
            bd=0,
            font=(self.mono_font, 9),
            padx=12,
            pady=12,
        )
        box.insert("1.0", command)
        box.grid(row=1, column=0, sticky="ew", pady=(14, 0))

    def _sync_sections(self) -> None:
        if hasattr(self, "generated_frame"):
            self.generated_frame.grid_remove()
            self.explicit_frame.grid_remove()
            if self.account_mode.get() == "generated":
                self.generated_frame.grid(row=3, column=0, columnspan=2, sticky="ew")
            else:
                self.explicit_frame.grid(row=4, column=0, columnspan=2, sticky="ew")
            self.sub2api_frame.grid_remove()
            self.cpa_frame.grid_remove()
            target = self.export_target.get()
            next_row = 8
            if "sub2api" in target:
                self.sub2api_frame.grid(row=next_row, column=0, columnspan=2, sticky="ew", pady=(12, 0))
                next_row += 1
            if "cpa" in target:
                self.cpa_frame.grid(row=next_row, column=0, columnspan=2, sticky="ew", pady=(12, 0))
        self._refresh_preview()

    def _payload(self) -> dict[str, Any]:
        payload = {
            "sso_domain": self.sso_domain.get(),
            "seed": self.seed.get(),
            "email_domain": self.email_domain.get(),
            "timeout": self.timeout.get() or "60",
            "no_proxy": self.no_proxy.get(),
            "export_targets": self.export_target.get(),
        }
        if self.account_mode.get() == "explicit":
            payload.update(
                {
                    "email": self.email.get(),
                    "password": self.password.get(),
                    "first_name": self.first_name.get(),
                    "last_name": self.last_name.get(),
                    "employee_id": self.employee_id.get(),
                }
            )
        if "sub2api" in self.export_target.get():
            payload.update(
                {
                    "sub2api_url": self.sub2api_url.get(),
                    "sub2api_email": self.sub2api_email.get(),
                    "sub2api_password": self.sub2api_password.get(),
                    "sub2api_group": self.sub2api_group.get(),
                }
            )
        if "cpa" in self.export_target.get():
            payload.update({"cpa_url": self.cpa_url.get(), "cpa_management_key": self.cpa_management_key.get()})
        return payload

    def _refresh_preview(self) -> None:
        if not hasattr(self, "command_text"):
            return
        self.command_text.delete("1.0", "end")
        try:
            self.command_text.insert("1.0", command_preview(self._payload()))
        except GuiError as exc:
            self.command_text.insert("1.0", str(exc))

    def _set_log(self, status: str, text: str) -> None:
        self.state_label.configure(text=status)
        self.log_text.delete("1.0", "end")
        self.log_text.insert("1.0", text)

    def _start_run(self) -> None:
        try:
            job = create_job(self._payload())
        except GuiError as exc:
            self._set_log("失败", str(exc))
            return
        self.active_job_id = job.id
        self._set_log("运行中", f"状态: {STATUS_LABELS.get(job.status, job.status)}\n产物目录: {job.artifact_dir}")
        self.root.after(1000, self._poll_job)

    def _poll_job(self) -> None:
        if not self.active_job_id:
            return
        with JOBS_LOCK:
            job = JOBS.get(self.active_job_id)
            snapshot = job.as_dict() if job else None
        if not snapshot:
            return
        lines = [f"状态: {STATUS_LABELS.get(snapshot['status'], snapshot['status'])}", f"产物目录: {snapshot['artifact_dir']}"]
        if snapshot.get("stderr"):
            lines.extend(["", snapshot["stderr"].strip()])
        if snapshot.get("stdout"):
            lines.extend(["", snapshot["stdout"].strip()])
        if snapshot.get("error"):
            lines.extend(["", snapshot["error"]])
        self._set_log(STATUS_LABELS.get(str(snapshot["status"]), str(snapshot["status"])), "\n".join(lines))
        if snapshot["status"] in {"queued", "running"}:
            self.root.after(1000, self._poll_job)


def main() -> int:
    root = tk.Tk()
    NativeCompanySsoApp(root)
    root.mainloop()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
