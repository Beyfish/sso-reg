const state = {
  accountMode: "generated",
  exportTarget: "none",
  activeJobId: "",
  pollTimer: 0,
  previewSeq: 0
};

const $ = (selector) => document.querySelector(selector);
const $$ = (selector) => Array.from(document.querySelectorAll(selector));

const form = $("#runForm");
const commandPreview = $("#commandPreview");
const batchCommand = $("#batchCommand");
const healthCommand = $("#healthCommand");
const logOutput = $("#logOutput");
const runState = $("#runState");

const accountModeLabels = {
  generated: "自动生成员工",
  explicit: "使用已有员工"
};

const exportTargetLabels = {
  none: "仅保存令牌",
  sub2api: "Sub2API",
  cpa: "CPA",
  "sub2api,cpa": "同时导出",
  "cpa,sub2api": "同时导出"
};

const statusLabels = {
  queued: "排队中",
  running: "运行中",
  succeeded: "成功",
  failed: "失败"
};

function fieldValue(name) {
  const input = form.elements[name];
  if (!input) return "";
  if (input.type === "checkbox") return input.checked;
  return input.value.trim();
}

function currentPayload() {
  const payload = {
    sso_domain: fieldValue("sso_domain"),
    seed: fieldValue("seed"),
    email_domain: fieldValue("email_domain"),
    timeout: fieldValue("timeout") || "60",
    no_proxy: fieldValue("no_proxy"),
    export_targets: state.exportTarget
  };
  if (state.accountMode === "explicit") {
    Object.assign(payload, {
      email: fieldValue("email"),
      password: fieldValue("password"),
      first_name: fieldValue("first_name"),
      last_name: fieldValue("last_name"),
      employee_id: fieldValue("employee_id")
    });
  }
  if (state.exportTarget.includes("sub2api")) {
    Object.assign(payload, {
      sub2api_url: fieldValue("sub2api_url"),
      sub2api_email: fieldValue("sub2api_email"),
      sub2api_password: fieldValue("sub2api_password"),
      sub2api_group: fieldValue("sub2api_group")
    });
  }
  if (state.exportTarget.includes("cpa")) {
    Object.assign(payload, {
      cpa_url: fieldValue("cpa_url"),
      cpa_management_key: fieldValue("cpa_management_key")
    });
  }
  return payload;
}

function shellQuote(value) {
  const text = String(value);
  if (/^[A-Za-z0-9_./:\\-]+$/.test(text)) return text;
  return `"${text.replaceAll('"', '\\"')}"`;
}

function commandFromPayload(payload) {
  const parts = [
    "python",
    "scripts\\run_company_sso_codex.py",
    "--sso-domain",
    payload.sso_domain || "hegiw77632.cloud-ip.cc",
    "--seed",
    payload.seed || "smoke-001",
    "--export-targets",
    payload.export_targets || "none",
    "--timeout",
    payload.timeout || "60"
  ];
  if (payload.email_domain) parts.push("--email-domain", payload.email_domain);
  if (payload.no_proxy) parts.push("--no-proxy");
  if (payload.email) parts.push("--email", payload.email, "--password", payload.password ? "***REDACTED***" : "");
  if (payload.first_name) parts.push("--first-name", payload.first_name);
  if (payload.last_name) parts.push("--last-name", payload.last_name);
  if (payload.employee_id) parts.push("--employee-id", payload.employee_id);
  return parts.map(shellQuote).join(" ");
}

async function refreshCommandPreview(payload) {
  const seq = state.previewSeq + 1;
  state.previewSeq = seq;
  try {
    const data = await postJson("/api/preview", payload);
    if (seq !== state.previewSeq) return;
    commandPreview.textContent = data.command.map(shellQuote).join(" ");
  } catch {
    if (seq !== state.previewSeq) return;
    commandPreview.textContent = commandFromPayload(payload);
  }
}

function updateDerivedCommands() {
  const payload = currentPayload();
  commandPreview.textContent = commandFromPayload(payload);
  refreshCommandPreview(payload);
  $("#metricTarget").textContent = exportTargetLabels[state.exportTarget] || state.exportTarget;
  $("#metricMode").textContent = accountModeLabels[state.accountMode] || state.accountMode;
  $("#metricTimeout").textContent = `${payload.timeout || "60"}s`;
  const ssoDomain = payload.sso_domain || "hegiw77632.cloud-ip.cc";
  const count = $("#batchCount").value || "10";
  const threads = $("#threads").value || "3";
  const retries = $("#retries").value || "5";
  batchCommand.textContent = [
    "python",
    "scripts\\run_batch_tui.py",
    "--mode",
    "register",
    "--count",
    count,
    "--threads",
    threads,
    "--retries",
    retries,
    "--yes",
    "--export-targets",
    state.exportTarget
  ].map(shellQuote).join(" ");
  healthCommand.textContent = [
    "python",
    "scripts\\check_sub2api_group.py",
    "--group",
    fieldValue("sub2api_group") || "5"
  ].map(shellQuote).join(" ");
  $("#serverState").textContent = ssoDomain;
  const queueDomain = $("#queueDomain");
  if (queueDomain) queueDomain.textContent = ssoDomain;
  const queueTarget = $("#queueTarget");
  if (queueTarget) queueTarget.textContent = state.exportTarget;
}

function setAccountMode(mode) {
  state.accountMode = mode;
  $$("[data-account-mode]").forEach((button) => {
    button.classList.toggle("is-selected", button.dataset.accountMode === mode);
  });
  $("#generatedFields").hidden = mode !== "generated";
  $("#explicitFields").hidden = mode !== "explicit";
  updateDerivedCommands();
}

function setExportTarget(target) {
  state.exportTarget = target;
  $$("[data-export-target]").forEach((button) => {
    button.classList.toggle("is-selected", button.dataset.exportTarget === target);
  });
  $("#sub2apiFields").hidden = !target.includes("sub2api");
  $("#cpaFields").hidden = !target.includes("cpa");
  updateDerivedCommands();
}

function showView(view) {
  $$(".nav-item").forEach((button) => {
    button.classList.toggle("is-active", button.dataset.view === view);
  });
  $$(".view").forEach((item) => {
    item.classList.toggle("is-visible", item.id === `view-${view}`);
  });
}

function setRunState(label, kind = "") {
  runState.textContent = label;
  runState.classList.toggle("is-running", kind === "running");
  runState.classList.toggle("is-failed", kind === "failed");
  const queueState = $("#queueState");
  if (queueState) {
    queueState.textContent = label;
    queueState.classList.toggle("is-failed", kind === "failed");
  }
  const metricStep = $("#metricStep");
  if (metricStep) metricStep.textContent = kind === "running" ? "1/5" : kind === "failed" ? "0/5" : label === "成功" ? "5/5" : "0/5";
  const headline = $("#statusHeadline");
  const detail = $("#statusDetail");
  if (headline) headline.textContent = kind === "failed" ? "运行失败" : kind === "running" ? "正在运行" : label === "成功" ? "运行完成" : "等待运行";
  if (detail) detail.textContent = kind === "failed" ? "请检查下方日志中的错误信息。" : kind === "running" ? "正在执行命令，日志会实时追加。" : label === "成功" ? "产物已写入本地 artifacts 目录。" : "填写或确认 SSO 域名后，点击开始运行。";
}

function toast(message) {
  const node = $("#toast");
  node.textContent = message;
  node.classList.add("is-visible");
  window.setTimeout(() => node.classList.remove("is-visible"), 2200);
}

async function postJson(url, payload) {
  const response = await fetch(url, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(payload)
  });
  const body = await response.json();
  if (!response.ok) throw new Error(body.error || "Request failed");
  return body;
}

async function getJson(url) {
  const response = await fetch(url);
  const body = await response.json();
  if (!response.ok) throw new Error(body.error || "Request failed");
  return body;
}

function renderJob(job) {
  if (!job) return;
  const lines = [];
  if (job.status) lines.push(`状态: ${statusLabels[job.status] || job.status}`);
  if (job.artifact_dir) lines.push(`产物目录: ${job.artifact_dir}`);
  if (job.stderr) lines.push("", job.stderr.trim());
  if (job.stdout) lines.push("", job.stdout.trim());
  if (job.result) lines.push("", JSON.stringify(job.result, null, 2));
  if (job.error) lines.push("", job.error);
  logOutput.textContent = lines.join("\n") || "运行中";
  if (job.status === "running" || job.status === "queued") {
    setRunState(statusLabels[job.status], "running");
  } else if (job.status === "succeeded") {
    setRunState("成功");
  } else {
    setRunState("失败", "failed");
  }
}

async function pollJob(id) {
  try {
    const job = await getJson(`/api/runs/${id}`);
    renderJob(job);
    if (job.status === "running" || job.status === "queued") {
      state.pollTimer = window.setTimeout(() => pollJob(id), 1600);
    } else {
      await refreshRuns();
    }
  } catch (error) {
    setRunState("服务离线", "failed");
    logOutput.textContent = error.message;
  }
}

async function startRun() {
  const button = $("#startRun");
  button.disabled = true;
  clearTimeout(state.pollTimer);
  try {
    const job = await postJson("/api/runs", currentPayload());
    state.activeJobId = job.id;
    renderJob(job);
    pollJob(job.id);
  } catch (error) {
    setRunState("失败", "failed");
    logOutput.textContent = error.message;
  } finally {
    button.disabled = false;
  }
}

async function copyCommand() {
  await navigator.clipboard.writeText(commandPreview.textContent);
  toast("命令已复制");
}

async function refreshRuns() {
  try {
    const data = await getJson("/api/runs");
    const list = $("#artifactList");
    if (!data.runs.length) {
      list.innerHTML = '<div class="empty-state"><strong>暂无本地运行记录</strong><span>从这个控制台启动的运行会显示在这里。</span></div>';
      return;
    }
    list.innerHTML = data.runs.map((job) => `
      <article class="artifact-item">
        <div class="artifact-title">
          <span>${job.id}</span>
          <span>${statusLabels[job.status] || job.status}</span>
        </div>
        <div class="artifact-path">${job.artifact_dir}</div>
      </article>
    `).join("");
  } catch {
    $("#artifactList").innerHTML = '<div class="empty-state"><strong>本地服务不可用</strong><span>请先启动本地 GUI 服务。</span></div>';
  }
}

$$("[data-account-mode]").forEach((button) => {
  button.addEventListener("click", () => setAccountMode(button.dataset.accountMode));
});

$$("[data-export-target]").forEach((button) => {
  button.addEventListener("click", () => setExportTarget(button.dataset.exportTarget));
});

$$(".nav-item").forEach((button) => {
  button.addEventListener("click", () => showView(button.dataset.view));
});

form.addEventListener("input", updateDerivedCommands);
$("#batchCount").addEventListener("input", updateDerivedCommands);
$("#threads").addEventListener("input", updateDerivedCommands);
$("#retries").addEventListener("input", updateDerivedCommands);
$("#startRun").addEventListener("click", startRun);
$("#copyCommand").addEventListener("click", copyCommand);
$("#refreshRuns").addEventListener("click", refreshRuns);

setAccountMode("generated");
setExportTarget("none");
updateDerivedCommands();
refreshRuns();
