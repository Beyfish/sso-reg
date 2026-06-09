import { spawn } from "node:child_process";
import { mkdir, rm } from "node:fs/promises";
import { join, resolve } from "node:path";

const repoRoot = resolve(new URL("..", import.meta.url).pathname.replace(/^\/([A-Za-z]:)/, "$1"));
const artifactsDir = join(repoRoot, "artifacts");
const chromePath = process.env.CHROME_PATH || "C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe";
const guiUrl = process.env.GUI_URL || "http://127.0.0.1:8765";
const debugPort = Number(process.env.CHROME_DEBUG_PORT || 9335);
const profileDir = join(artifactsDir, "gui-click-profile");

await mkdir(artifactsDir, { recursive: true });
await rm(profileDir, { recursive: true, force: true });
await mkdir(profileDir, { recursive: true });

const chrome = spawn(chromePath, [
  "--headless=new",
  "--disable-gpu",
  "--no-first-run",
  "--no-default-browser-check",
  `--remote-debugging-port=${debugPort}`,
  `--user-data-dir=${profileDir}`,
  "--window-size=1440,1000",
  guiUrl,
], { stdio: "ignore" });

function delay(ms) {
  return new Promise((resolveDelay) => setTimeout(resolveDelay, ms));
}

async function jsonGet(url, attempts = 50) {
  let lastError;
  for (let index = 0; index < attempts; index += 1) {
    try {
      const response = await fetch(url);
      if (response.ok) return response.json();
      lastError = new Error(`${response.status} ${response.statusText}`);
    } catch (error) {
      lastError = error;
    }
    await delay(120);
  }
  throw lastError;
}

const pages = await jsonGet(`http://127.0.0.1:${debugPort}/json/list`);
const page = pages.find((item) => item.type === "page");
if (!page?.webSocketDebuggerUrl) {
  throw new Error("No debuggable Chrome page found");
}

const ws = new WebSocket(page.webSocketDebuggerUrl);
await new Promise((resolveOpen, rejectOpen) => {
  ws.addEventListener("open", resolveOpen, { once: true });
  ws.addEventListener("error", rejectOpen, { once: true });
});

let nextId = 1;
const pending = new Map();
ws.addEventListener("message", (event) => {
  const message = JSON.parse(event.data);
  if (!message.id) return;
  const entry = pending.get(message.id);
  if (!entry) return;
  pending.delete(message.id);
  if (message.error) entry.reject(new Error(message.error.message));
  else entry.resolve(message.result);
});

function cdp(method, params = {}) {
  const id = nextId++;
  ws.send(JSON.stringify({ id, method, params }));
  return new Promise((resolveCommand, rejectCommand) => {
    pending.set(id, { resolve: resolveCommand, reject: rejectCommand });
  });
}

async function evalValue(expression) {
  const result = await cdp("Runtime.evaluate", {
    expression,
    returnByValue: true,
    awaitPromise: true,
  });
  if (result.exceptionDetails) throw new Error(result.exceptionDetails.text || "Runtime exception");
  return result.result.value;
}

async function assertEval(expression, message) {
  const ok = await evalValue(expression);
  if (!ok) throw new Error(message);
}

async function waitReady() {
  for (let index = 0; index < 80; index += 1) {
    const ready = await evalValue("document.readyState");
    if (ready === "complete" || ready === "interactive") return;
    await delay(100);
  }
  throw new Error("page did not finish loading");
}

async function center(selector) {
  const value = await evalValue(`(() => {
    const el = document.querySelector(${JSON.stringify(selector)});
    if (!el) return null;
    el.scrollIntoView({ block: "center", inline: "center" });
    const rect = el.getBoundingClientRect();
    const style = getComputedStyle(el);
    return {
      x: rect.left + rect.width / 2,
      y: rect.top + rect.height / 2,
      width: rect.width,
      height: rect.height,
      visible: rect.width > 0 && rect.height > 0 && style.visibility !== "hidden" && style.display !== "none"
    };
  })()`);
  if (!value?.visible) throw new Error(`Element is not visible: ${selector}`);
  return value;
}

async function click(selector) {
  const point = await center(selector);
  await cdp("Input.dispatchMouseEvent", { type: "mouseMoved", x: point.x, y: point.y });
  await cdp("Input.dispatchMouseEvent", { type: "mousePressed", x: point.x, y: point.y, button: "left", clickCount: 1 });
  await cdp("Input.dispatchMouseEvent", { type: "mouseReleased", x: point.x, y: point.y, button: "left", clickCount: 1 });
  await delay(120);
}

async function setInput(selector, value) {
  await click(selector);
  await evalValue(`(() => {
    const el = document.querySelector(${JSON.stringify(selector)});
    el.value = ${JSON.stringify(value)};
    el.dispatchEvent(new Event("input", { bubbles: true }));
    el.dispatchEvent(new Event("change", { bubbles: true }));
    return true;
  })()`);
  await delay(80);
}

async function screenshot(name) {
  const data = await cdp("Page.captureScreenshot", { format: "png", captureBeyondViewport: false });
  const path = join(artifactsDir, name);
  await import("node:fs/promises").then((fs) => fs.writeFile(path, Buffer.from(data.data, "base64")));
  return path;
}

try {
  await cdp("Page.enable");
  await cdp("Runtime.enable");
  await cdp("Page.navigate", { url: guiUrl });
  await waitReady();
  await assertEval("document.title === '企业 SSO Codex 控制台'", "title mismatch");
  await assertEval("document.querySelector('#ssoDomain').value === 'hegiw77632.cloud-ip.cc'", "default SSO domain missing");

  await click('[data-export-target="sub2api"]');
  await assertEval("!document.querySelector('#sub2apiFields').hidden", "Sub2API fields not shown");
  await assertEval("document.querySelector('#cpaFields').hidden", "CPA fields should remain hidden");

  await click('[data-export-target="sub2api,cpa"]');
  await assertEval("!document.querySelector('#sub2apiFields').hidden && !document.querySelector('#cpaFields').hidden", "Both export panels not visible");
  await assertEval("document.querySelector('#commandPreview').textContent.includes('sub2api,cpa')", "command preview did not update");

  await click('[data-account-mode="explicit"]');
  await assertEval("!document.querySelector('#explicitFields').hidden && document.querySelector('#generatedFields').hidden", "explicit employee mode not visible");

  await click('[data-account-mode="generated"]');
  await click('[data-export-target="none"]');
  await assertEval("document.querySelector('#generatedFields').hidden === false", "generated employee mode not restored");

  await click('[data-view="batch"]');
  await assertEval("document.querySelector('#view-batch').classList.contains('is-visible')", "batch view not visible");
  await click('[data-view="health"]');
  await assertEval("document.querySelector('#view-health').classList.contains('is-visible')", "health view not visible");
  await click('[data-view="artifacts"]');
  await assertEval("document.querySelector('#view-artifacts').classList.contains('is-visible')", "artifacts view not visible");
  await click('[data-view="run"]');
  await assertEval("document.querySelector('#view-run').classList.contains('is-visible')", "run view not visible");

  await setInput("#ssoDomain", "localhost");
  await click("#startRun");
  await delay(500);
  await assertEval("document.querySelector('#runState').textContent === '失败'", "invalid run did not fail locally");
  await assertEval("document.querySelector('#logOutput').textContent.includes('SSO 域名无效')", "validation error not shown");
  const desktop = await screenshot("gui_click_desktop.png");

  await cdp("Emulation.setDeviceMetricsOverride", {
    width: 390,
    height: 900,
    deviceScaleFactor: 1,
    mobile: true,
  });
  await cdp("Page.reload", { ignoreCache: true });
  await waitReady();
  await click('[data-export-target="sub2api,cpa"]');
  await assertEval("document.documentElement.scrollWidth <= window.innerWidth", "mobile layout has horizontal overflow");
  const mobile = await screenshot("gui_click_mobile.png");

  console.log(JSON.stringify({ status: "passed", desktop, mobile }, null, 2));
} finally {
  ws.close();
  chrome.kill();
}
