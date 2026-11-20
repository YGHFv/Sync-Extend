"use strict";

const commands = Object.freeze({
  status: "/system/bin/sh /data/adb/modules/sync_extend/action.sh status",
  stop: "/system/bin/sh /data/adb/modules/sync_extend/action.sh stop",
  stopped: "/system/bin/sh /data/adb/modules/sync_extend/action.sh wait-stopped",
  gateway: "/system/bin/sh /data/adb/modules/sync_extend/webroot/gateway.sh",
});

const fields = {};
[
  "service-state", "service-detail", "gateway-state", "gateway-detail", "exports", "refresh",
  "verify-stop", "ask-stop", "stop-confirmation", "stop", "cancel-stop",
].forEach((id) => { fields[id] = document.getElementById(id); });

const canUseBridge = Boolean(window.ksu && typeof window.ksu.exec === "function");
let nextRequest = 0;
let busy = false;
let activeOwner = false;

function readJson(operation) {
  return new Promise((resolve, reject) => {
    const command = commands[operation];
    if (!canUseBridge || !Object.prototype.hasOwnProperty.call(commands, operation)) {
      reject(new Error("KernelSU bridge unavailable"));
      return;
    }
    const callback = `syncExtendResult_${Date.now()}_${nextRequest++}`;
    function finish() {
      clearTimeout(timeout);
      delete window[callback];
    }
    const timeout = setTimeout(() => {
      finish();
      reject(new Error("Module operation timed out"));
    }, 8000);
    window[callback] = (code, output) => {
      finish();
      if (code !== 0 || typeof output !== "string" || output.length > 65536) {
        reject(new Error("Module operation refused"));
        return;
      }
      try {
        resolve(JSON.parse(output));
      } catch (error) {
        reject(error);
      }
    };
    try {
      window.ksu.exec(command, "{}", callback);
    } catch (error) {
      finish();
      reject(error);
    }
  });
}

function setStatus(category, label, detail, tone = "neutral") {
  const state = fields[`${category}-state`];
  state.textContent = label;
  state.dataset.tone = tone;
  fields[`${category}-detail`].textContent = detail;
}

function setBusy(value) {
  busy = value;
  fields.refresh.disabled = busy || !canUseBridge;
  fields["verify-stop"].disabled = busy || !canUseBridge;
  fields["ask-stop"].disabled = busy || !activeOwner || !canUseBridge;
  fields.stop.disabled = busy || !activeOwner || !canUseBridge;
}

function hideConfirmation() {
  fields["stop-confirmation"].hidden = true;
}

function showOwner(value) {
  if (!value || value.format_version !== 1 || value.kernel_owner_authenticated !== true ||
      typeof value.stop_requested !== "boolean" || typeof value.ready !== "boolean" ||
      !Number.isSafeInteger(value.owner_pid) || value.owner_pid < 1) {
    throw new Error("Invalid lifecycle response");
  }
  activeOwner = !value.stop_requested;
  if (value.stop_requested) {
    setStatus("service", "正在停止", "停止请求已接受。进程退出后可确认停止。");
  } else if (value.ready) {
    setStatus("service", "已就绪", "本机后台资源已就绪。", "ready");
  } else {
    setStatus("service", "等待资源", "已连接后台进程，当前资源尚未就绪。");
  }
}

function exportRow(item) {
  if (!item || !/^[A-Za-z0-9_-]{1,64}$/.test(item.name) ||
      typeof item.writable !== "boolean" || typeof item.url !== "string") {
    throw new Error("Invalid export response");
  }
  const address = new URL(item.url);
  if (address.protocol !== "http:" || address.username || address.password || address.search ||
      address.hash || !/^(127(?:\.\d{1,3}){3}|\[::1\])$/.test(address.hostname) ||
      address.pathname !== `/${item.name}/`) {
    throw new Error("Invalid export address");
  }

  const row = document.createElement("li");
  const heading = document.createElement("div");
  const name = document.createElement("span");
  const access = document.createElement("span");
  const url = document.createElement("code");
  heading.className = "export-summary";
  access.className = "export-access";
  name.textContent = item.name;
  access.textContent = item.writable ? "读写许可" : "只读";
  url.textContent = address.href;
  heading.append(name, access);
  row.append(heading, url);
  return row;
}

function showGateway(value) {
  if (!value || value.format_version !== 1 || !Object.prototype.hasOwnProperty.call(value, "webdav")) {
    throw new Error("Invalid gateway response");
  }
  if (!value.webdav || value.webdav.enabled === false) {
    setStatus("gateway", "未启用", "当前模块配置未启用 WebDAV。");
    return;
  }
  if (value.webdav.enabled !== true || !Array.isArray(value.webdav.exports) ||
      value.webdav.exports.length < 1 || value.webdav.exports.length > 64) {
    throw new Error("Invalid gateway export list");
  }
  const rows = value.webdav.exports.map(exportRow);
  for (const row of rows) fields.exports.appendChild(row);
  fields.exports.hidden = false;
  setStatus("gateway", "配置已开启", "在本机 WebDAV 应用中填入导出地址和已授予的账号。", "ready");
}

async function refresh() {
  if (busy) return;
  hideConfirmation();
  setBusy(true);
  activeOwner = false;
  fields.exports.textContent = "";
  fields.exports.hidden = true;
  try {
    await readJson("status").then(showOwner).catch(() => {
      setStatus("service", "无法读取", "未收到服务状态。若已停止，可使用“确认已停止”。", "warn");
    });
    await readJson("gateway").then(showGateway).catch(() => {
      setStatus("gateway", "无法读取", "请检查模块私有目录中的部署和网关配置。", "warn");
    });
  } finally {
    setBusy(false);
  }
}

fields.refresh.addEventListener("click", refresh);
fields["ask-stop"].addEventListener("click", () => {
  if (!busy && activeOwner) {
    fields["stop-confirmation"].hidden = false;
    fields.stop.focus();
  }
});
fields["cancel-stop"].addEventListener("click", hideConfirmation);
fields.stop.addEventListener("click", async () => {
  if (busy || !activeOwner || fields["stop-confirmation"].hidden) return;
  hideConfirmation();
  setBusy(true);
  try {
    const value = await readJson("stop");
    if (!value || value.stop_requested !== true) throw new Error("Stop was not accepted");
    showOwner(value);
  } catch (error) {
    activeOwner = false;
    setStatus("service", "未确认停止", "无法确认停止请求，请刷新状态。", "warn");
  } finally {
    setBusy(false);
  }
});
fields["verify-stop"].addEventListener("click", async () => {
  if (busy) return;
  hideConfirmation();
  setBusy(true);
  try {
    const value = await readJson("stopped");
    if (!value || value.control_owner_terminal !== true || value.stale_pid_adopted !== false) {
      throw new Error("The service is not confirmed stopped");
    }
    activeOwner = false;
    setStatus("service", "已停止", "当前没有持有模块控制权的后台服务。", "ready");
  } catch (error) {
    setStatus("service", "未确认停止", "后台服务可能仍在运行或正在退出。", "warn");
  } finally {
    setBusy(false);
  }
});

if (canUseBridge) {
  refresh();
} else {
  setBusy(false);
  setStatus("service", "未连接模块", "请在 KernelSU 管理器中打开此页面。", "warn");
  setStatus("gateway", "未连接模块", "网关配置由 KernelSU 模块提供。");
}
