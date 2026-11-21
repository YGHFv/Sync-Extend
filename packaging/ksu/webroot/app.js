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
  "verify-stop", "ask-stop", "stop-confirmation", "stop", "cancel-stop", "probe-result",
  "workspace-state", "workspace-detail", "workspace-summary",
  "storage-state", "storage-detail", "storage-summary", "network-state", "network-detail", "network-summary",
  "easytier-state", "easytier-detail", "easytier-summary",
  "recovery-state", "recovery-detail", "recovery-summary", "recovery-guide",
].forEach((id) => { fields[id] = document.getElementById(id); });

const canUseBridge = Boolean(window.ksu && typeof window.ksu.exec === "function");
let nextRequest = 0;
let busy = false;
let activeOwner = false;
let ownerReady = false;
let probeButtons = [];
let exportResults = new Map();
let gatewayConfigured = false;
let gatewayDisabled = false;
let currentOwnerPid = null;
let liveGateway = null;
const validExportName = (name) => typeof name === "string" && name.length >= 1 &&
  name.length <= 64 && !/[^A-Za-z0-9_-]/.test(name);

function readJson(operation, selectedExport) {
  return new Promise((resolve, reject) => {
    let command;
    if (Object.prototype.hasOwnProperty.call(commands, operation)) {
      command = commands[operation];
    } else if (operation === "probe" && validExportName(selectedExport)) {
      // The only dynamic command segment is a validated literal export name.
      command = `/system/bin/sh /data/adb/modules/sync_extend/action.sh probe-webdav '${selectedExport}'`;
    }
    if (!canUseBridge || !command) {
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
      if (code !== 0 || typeof output !== "string" ||
          output.length > (operation === "gateway" ? 65536 : 16384)) {
        reject(new Error("Module operation refused"));
        return;
      }
      try {
        const value = JSON.parse(output);
        // The CLI pretty-prints native control JSON. Its display whitespace
        // does not enlarge the existing 4096-byte native protocol allowance.
        if (operation !== "gateway" && new TextEncoder().encode(JSON.stringify(value)).length > 4096) {
          throw new Error("Native control response exceeds its bound");
        }
        resolve(value);
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
  for (const button of probeButtons) button.disabled = busy || !ownerReady || !canUseBridge;
}

function hideConfirmation() {
  fields["stop-confirmation"].hidden = true;
}

function clearRuntime(detail = "当前没有可验证的运行摘要。") {
  liveGateway = null;
  for (const category of ["workspace", "storage", "network", "easytier", "recovery"]) {
    fields[`${category}-summary`].textContent = "";
    fields[`${category}-summary`].hidden = true;
    setStatus(category, "暂无观察", detail);
  }
  fields["network-detail"].textContent = "当前没有已鉴权的连接样本；实际路径、外层 wire 和中继费用保持未知。";
  fields["easytier-detail"].textContent = "当前没有本机受管子进程与 RPC 属主绑定的样本。";
  fields["recovery-guide"].textContent = "没有可验证的当前历史来源。恢复须独立核对，不能使用旧观测执行。";
}

function clearExportTests(detail = "连接待测试") {
  for (const result of exportResults.values()) result.textContent = detail;
  fields["probe-result"].hidden = true;
}

function showGatewayAvailability() {
  if (!gatewayConfigured) {
    setStatus("gateway", gatewayDisabled ? "配置已关闭" : "未启用",
      gatewayDisabled ? "WebDAV 已关闭；当前页面不会测试已关闭的导出。" : "当前模块配置未启用 WebDAV。");
  } else if (!ownerReady) {
    setStatus("gateway", "配置已开 · 服务未就绪",
      activeOwner ? "后台资源尚未就绪，导出暂不能测试。" : "服务停止或状态未确认；导出配置继续保留，运行可访问性未确认。");
  } else if (!liveGateway) {
    setStatus("gateway", "配置已开 · 监听待确认", "后台资源已就绪；尚无活动监听摘要，可测试选中的导出。");
  } else {
    setStatus("gateway", "监听已登记 · 待测试", "后台登记了活动监听。每个导出的账号认证和可访问性仍需连接测试。");
  }
}

function showOwner(value) {
  if (!value || value.format_version !== 1 || value.kernel_owner_authenticated !== true ||
      typeof value.stop_requested !== "boolean" || typeof value.ready !== "boolean" ||
      !Number.isSafeInteger(value.owner_pid) || value.owner_pid < 1) {
    throw new Error("Invalid lifecycle response");
  }
  activeOwner = !value.stop_requested;
  ownerReady = activeOwner && value.ready;
  currentOwnerPid = value.owner_pid;
  if (!ownerReady) {
    clearRuntime(value.stop_requested ? "服务正在停止，旧运行摘要已清除。" : "资源尚未就绪，旧运行摘要已清除。");
    clearExportTests("服务未就绪");
    showGatewayAvailability();
  }
  if (value.stop_requested) {
    setStatus("service", "正在停止", "停止请求已接受。进程退出后可确认停止。");
  } else if (value.ready) {
    setStatus("service", "已就绪", "本机后台资源已就绪。", "ready");
  } else {
    setStatus("service", "等待资源", "已连接后台进程，当前资源尚未就绪。");
  }
}

const count = (value) => Number.isSafeInteger(value) && value >= 0;
const identifier = (value, length) => typeof value === "string" && value.length === length &&
  !/[^0-9a-f]/.test(value);
function requireCounts(value, names) {
  if (!value || typeof value !== "object" || names.some((name) => !count(value[name]))) {
    throw new Error("Invalid bounded summary count");
  }
}
function requireFlags(value, names) {
  if (names.some((name) => typeof value[name] !== "boolean")) throw new Error("Invalid bounded summary flag");
}
function showSummary(category, rows) {
  const target = fields[`${category}-summary`];
  target.textContent = "";
  for (const [name, value] of rows) {
    const label = document.createElement("dt");
    const detail = document.createElement("dd");
    label.textContent = name;
    detail.textContent = String(value);
    target.append(label, detail);
  }
  target.hidden = false;
}

function showRecovery(local, age) {
  const object = (value) => value !== null && typeof value === "object" && !Array.isArray(value);
  const optional = (value, name, valid) => {
    if (!Object.hasOwn(value, name)) return undefined;
    if (!valid(value[name])) throw new Error("Invalid recovery metadata field");
    return value[name];
  };
  const flag = (value) => typeof value === "boolean";
  const time = (value) => {
    if (value === undefined) return "未知";
    if (value === null) return "未裁剪";
    const date = new Date(value);
    return Number.isNaN(date.valueOf()) ? `${value} ms (Unix epoch)` :
      date.toISOString().replace("T", " ").replace(".000Z", " UTC");
  };
  const seen = new Set();
  function snapshotText(snapshot, pruned) {
    if (!object(snapshot) || !identifier(snapshot.snapshot_id, 64) ||
        typeof snapshot.state !== "string" || snapshot.state.length < 1 || snapshot.state.length > 64 ||
        snapshot.state.includes("\0") || !flag(snapshot.current) || seen.has(snapshot.snapshot_id)) {
      throw new Error("Invalid recovery snapshot");
    }
    seen.add(snapshot.snapshot_id);
    const created = optional(snapshot, "created_at_ms", count);
    const locked = optional(snapshot, "locked", flag);
    const retained = optional(snapshot, "content_retained", flag);
    const prunedAt = optional(snapshot, "pruned_at_ms", (value) => value === null || count(value));
    if ((retained === true && prunedAt !== undefined && prunedAt !== null) ||
        (retained === false && (snapshot.current || locked === true || prunedAt === null)) ||
        (prunedAt !== undefined && prunedAt !== null &&
          (snapshot.current || locked === true || created !== undefined && created > prunedAt)) ||
        (pruned && (snapshot.current || locked === true || retained === true)) ||
        (!pruned && retained === false)) throw new Error("Contradictory recovery snapshot");
    return `${snapshot.snapshot_id}；原状态 ${snapshot.state}；快照创建时间 ${time(created)}；` +
      `${snapshot.current ? "当前" : "历史"} / ${locked === undefined ? "锁定未知" : locked ? "锁定" : "未锁定"}；` +
      `${retained === undefined ? "保留状态未知" : retained ? "已保留；内容未验" : "内容已修剪"}；裁剪时间 ${time(prunedAt)}`;
  }
  const rows = [["采样距今", `${age} ms；不代表当前内容可恢复`]];
  if (Object.hasOwn(local, "history_metadata")) {
    const limit = optional(local, "history_metadata_limit", (value) => value === 1);
    const truncated = optional(local, "history_metadata_truncated", flag);
    if (!Array.isArray(local.history_metadata) || local.history_metadata.length > (limit ?? 1) ||
        local.history_metadata.length > local.total_snapshots ||
        truncated !== undefined && (truncated !== (local.total_snapshots > local.history_metadata.length) ||
          local.history_metadata.length !== Math.min(1, local.total_snapshots))) {
      throw new Error("Invalid retained history summary");
    }
    for (const snapshot of local.history_metadata) rows.push(["最近保留快照", snapshotText(snapshot, false)]);
    rows.push(["保留列表范围", truncated === undefined ? "摘要是否截取未知" :
      truncated ? "摘要最近 1 条；其余保留历史未展示" : "摘要最多最近 1 条"]);
  } else {
    rows.push(["保留快照元数据", "旧版本未提供；创建时间、锁定和保留状态未知"]);
  }
  const recovery = local.recovery;
  let guide = "在独立终端人工选择保留来源并再核对内容，正常停止当前资源属主后，显式执行 " +
    "syncd restore --data-dir <数据目录> --snapshot <保留快照> --path <相对文件>。占用路径保留冲突副本。" +
    "完整只读恢复预览当前尚未提供；本页不创建恢复预备状态。";
  if (recovery !== undefined && recovery !== null) {
    if (!object(recovery)) throw new Error("Invalid recovery summary");
    const retained = optional(recovery, "retained_snapshots", count);
    const pruned = optional(recovery, "pruned_snapshots", count);
    const consistent = optional(recovery, "metadata_snapshot_consistent", flag);
    for (const name of ["historical_content_hashes_verified", "restoration_performed",
      "native_authority", "cleanup_authority", "pending_resume_authority"]) {
      if (optional(recovery, name, flag) === true) throw new Error("Unsupported recovery claim or authority");
    }
    if (retained !== undefined && retained !== local.total_snapshots) throw new Error("Retained count differs");
    rows.push(["保留 / 内容已修剪快照", `${retained ?? "未知"} / ${pruned ?? "未知"}`]);
    rows.push(["元数据一致性", consistent === true ? "同一元数据快照；历史内容未验" : "未知；未确认"]);
    rows.push(["历史内容 hash", Object.hasOwn(recovery, "historical_content_hashes_verified") ?
      "未验证；保留不等于已验证可恢复" : "未知；旧载荷未提供"]);
    rows.push(["恢复 / 原生 / 清理 / pending 权限",
      ["restoration_performed", "native_authority", "cleanup_authority", "pending_resume_authority"]
        .every((name) => Object.hasOwn(recovery, name)) ? "未执行 / 无 / 无 / 无" : "未知；本页不执行恢复或清理"]);
    const limit = optional(recovery, "pruned_history_limit", (value) => value === 1);
    const truncated = optional(recovery, "pruned_history_truncated", flag);
    if (Object.hasOwn(recovery, "pruned_history")) {
      if (!Array.isArray(recovery.pruned_history) || recovery.pruned_history.length > (limit ?? 1) ||
          pruned !== undefined && (recovery.pruned_history.length > pruned ||
            truncated !== undefined && (truncated !== (pruned > recovery.pruned_history.length) ||
              recovery.pruned_history.length !== Math.min(1, pruned)))) throw new Error("Invalid pruned summary");
      for (const snapshot of recovery.pruned_history) rows.push(["最近裁剪审计", snapshotText(snapshot, true)]);
    }
    rows.push(["裁剪审计范围", !Object.hasOwn(recovery, "pruned_history") ? "未知；旧载荷未提供" :
      truncated === undefined ? "是否截取未知；内容已修剪" :
        truncated ? "摘要最近 1 条；其他裁剪审计未展示" : "摘要最多最近 1 条；内容已修剪"]);
    for (const [name, command] of [["restore_command", "restore"], ["whole_tree_restore_command", "tree-prepare"],
      ["recovered_archive_command", "recovered-local"]]) {
      if (Object.hasOwn(recovery, name) && recovery[name] !== null && recovery[name] !== command) {
        throw new Error("Invalid manual recovery command name");
      }
    }
    if (recovery.whole_tree_restore_command === "tree-prepare") {
      guide += " Windows 整树 tree-prepare 需要显式预算，会写入预备状态，不是只读预览。";
    }
    if (recovery.recovered_archive_command === "recovered-local") {
      guide += " Windows 原归档可手动使用 recovered-local --descriptor <归档描述文件> inspect 预检。";
    }
  } else rows.push(["恢复元数据", "旧版本未提供；裁剪、验证和执行权限均未知"]);
  showSummary("recovery", rows);
  fields["recovery-guide"].textContent = guide;
  setStatus("recovery", "历史元数据", "摘要只展示最近保留和裁剪各 1 条，真实总数分别列出。" +
    "后台保留列表最多 128 条、裁剪审计最多 16 条；本页不检查历史内容、不执行恢复。");
}

function validSocket(value) {
  if (typeof value !== "string" || value.length > 128) return false;
  const match = /^(\[[0-9a-fA-F:.]+\]|(?:\d{1,3}\.){3}\d{1,3}):(\d{1,5})$/.exec(value);
  if (!match || Number(match[2]) < 1 || Number(match[2]) > 65535) return false;
  try {
    const address = new URL(`http://${value}/`);
    if (!match[1].startsWith("[") && match[1].split(".").some((part) => Number(part) > 255)) return false;
    return Boolean(address.hostname) && !address.username && !address.password;
  } catch (error) { return false; }
}

function showConnection(observation) {
  if (!observation) return;
  requireCounts(observation, ["age_ms", "stale_after_ms"]);
  requireFlags(observation, ["current"]);
  const sample = observation.actual;
  requireCounts(sample, ["observation_format_version", "udp_sent_bytes", "udp_received_bytes",
    "udp_sent_datagrams", "udp_received_datagrams", "rtt_us", "path_lost_packets", "path_lost_bytes"]);
  requireFlags(sample, ["active", "initiated"]);
  if (sample.observation_format_version !== 1 || !identifier(sample.peer_device, 64) ||
      !identifier(sample.space_id, 32) || !identifier(sample.session_binding, 64) ||
      sample.sample_scope !== "latest_authenticated_connection" || sample.meter_unit !== "inner_quic_udp_payload_bytes" ||
      sample.route_attribution !== "unknown" || sample.outer_wire_bytes !== null || sample.billing_bytes !== null ||
      observation.stale_after_ms !== 30000 || observation.current !== (observation.age_ms <= observation.stale_after_ms) ||
      !["active", "finished", "failed", "dropped", "stale"].includes(sample.lifecycle) ||
      sample.active !== (sample.lifecycle === "active") || (sample.active && !observation.current) ||
      (sample.lifecycle === "stale" && observation.current) ||
      !["endpoint_bind", "connection_local_ip"].includes(sample.local_socket_scope) ||
      (sample.local_socket !== null && !validSocket(sample.local_socket)) || !validSocket(sample.remote_socket)) {
    throw new Error("Invalid authenticated connection sample");
  }
  const states = {
    active: "采样时活动", finished: "传输已结束", failed: "传输失败",
    dropped: "会话已释放", stale: "样本过旧",
  };
  showSummary("network", [
    ["样本范围", "最近一次已鉴权会话"], ["采样距今 / 过旧门槛", `${observation.age_ms} / ${observation.stale_after_ms} ms`],
    ["对端设备", sample.peer_device], ["空间", sample.space_id], ["会话绑定标识", sample.session_binding],
    ["连接方向", sample.initiated ? "本机发起" : "本机接入"],
    ["本机 UDP 端点", `${sample.local_socket ?? "未观察到"} (${sample.local_socket_scope})`],
    ["对端 UDP 端点", sample.remote_socket],
    ["内层 UDP 发送 / 接收载荷", `${sample.udp_sent_bytes} / ${sample.udp_received_bytes} B`],
    ["UDP 发送 / 接收报文", `${sample.udp_sent_datagrams} / ${sample.udp_received_datagrams}`],
    ["QUIC RTT", `${sample.rtt_us} us`],
    ["当前 QUIC 路径丢包", `${sample.path_lost_packets} 报文 / ${sample.path_lost_bytes} B`],
  ]);
  setStatus("network", states[sample.lifecycle],
    "QUINN 内层 UDP 载荷包含协议开销与重传；样本不代表所有连接，当前可达性未测试。" +
    "实际 LAN/P2P/中继路径、外层 wire 和中继费用保持未知。逻辑交付与请求预留预算分别计量。");
}

function showEasyTier(observation) {
  if (!observation) return;
  requireCounts(observation, ["age_ms", "stale_after_ms"]);
  requireFlags(observation, ["current"]);
  const sample = observation.actual;
  requireCounts(sample, ["observation_format_version", "child_pid", "peer_count"]);
  requireFlags(sample, ["owner_bound", "peers_truncated", "authenticated_sync_device"]);
  const loopback = validSocket(sample.rpc_portal) &&
    (sample.rpc_portal.startsWith("[::1]:") || /^127\.\d{1,3}\.\d{1,3}\.\d{1,3}:/.test(sample.rpc_portal));
  const reasons = ["rpc_not_observed", "configuration_pin_unavailable", "rpc_ownership_unavailable",
    "rpc_query_unavailable", "rpc_ownership_changed", "rpc_listener_changed", "configuration_pin_changed",
    "rpc_window_expired", "observation_clock_unavailable", "invalid_peer_output",
    "sampler_unavailable", "process_owner_unavailable", "sample_stale"];
  if (sample.observation_format_version !== 1 || sample.sample_scope !== "managed_easytier_peers" ||
      sample.pinned_version !== "2.6.4" || !identifier(sample.generation, 32) ||
      !identifier(sample.process_start, 16) || !["core_pin", "cli_pin", "config_pin"].every((key) => identifier(sample[key], 64)) ||
      sample.child_pid < 1 || sample.child_pid > 4294967295 || sample.peer_count > 4096 || !loopback ||
      sample.authenticated_sync_device !== false || sample.route_attribution !== "unassociated_with_sync_connection" ||
      sample.outer_wire_bytes !== null || sample.billing_bytes !== null ||
      observation.stale_after_ms !== 10000 || observation.current !== (observation.age_ms <= observation.stale_after_ms) ||
      !["available", "unavailable", "stale"].includes(sample.lifecycle) || sample.owner_bound !== (sample.lifecycle === "available") ||
      (sample.owner_bound && (!observation.current || sample.process_start === "0000000000000000")) ||
      (sample.lifecycle === "stale" && (observation.current || sample.unavailable_reason !== "sample_stale")) ||
      (sample.owner_bound ? sample.unavailable_reason !== null : !reasons.includes(sample.unavailable_reason)) ||
      !Array.isArray(sample.peers) || sample.peers.length !== Math.min(4, sample.peer_count) ||
      sample.peers_truncated !== (sample.peer_count > 4) || (!sample.owner_bound && sample.peer_count !== 0)) {
    throw new Error("Invalid managed EasyTier sample");
  }
  const rows = [
    ["样本范围", "本机受管启动代的 overlay peer；未关联到同步连接"],
    ["采样距今 / 门槛", `${observation.age_ms} / ${observation.stale_after_ms} ms`],
    ["受管启动代 / PID", `${sample.generation} / ${sample.child_pid}`],
    ["RPC 端点 / 固定版本", `${sample.rpc_portal} / ${sample.pinned_version}`],
    ["peer 显示", `${sample.peers.length} / ${sample.peer_count}${sample.peers_truncated ? "（已截取）" : ""}`],
  ];
  const ids = new Set();
  for (const peer of sample.peers) {
    requireCounts(peer, ["overlay_peer_id"]);
    if (peer.overlay_peer_id > 4294967295 || ids.has(peer.overlay_peer_id) ||
        (peer.ipv4 !== null && (typeof peer.ipv4 !== "string" || !/^(?:\d{1,3}\.){3}\d{1,3}$/.test(peer.ipv4) ||
          peer.ipv4.split(".").some((part) => Number(part) > 255)))) {
      throw new Error("Invalid EasyTier overlay peer");
    }
    ids.add(peer.overlay_peer_id);
    const names = { local: "本机 overlay", p2p: "overlay P2P", unknown: "overlay 路径未知" };
    let path = typeof peer.path === "string" && Object.hasOwn(names, peer.path) ? names[peer.path] : null;
    if (!path) {
      const relay = peer.path?.relay;
      if (typeof peer.path !== "object" || peer.path === null || Object.keys(peer.path).length !== 1 ||
          typeof relay !== "object" || relay === null || Object.keys(relay).length !== 1 ||
          !Number.isSafeInteger(relay.hops) || relay.hops < 2 || relay.hops > 64) {
        throw new Error("Invalid EasyTier overlay path");
      }
      path = `overlay 中继（${relay.hops} 跳）`;
    }
    rows.push([`overlay peer ${peer.overlay_peer_id}`, `${peer.ipv4 ?? "未观察到 IPv4"}；${path}`]);
  }
  showSummary("easytier", rows);
  const states = { available: "采样时属主已验证", unavailable: "不可用；旧 peer 已清除", stale: "样本过旧；旧 peer 已清除" };
  setStatus("easytier", states[sample.lifecycle],
    (sample.unavailable_reason ? "子进程、RPC 或采样无法验证，当前路径保持未知。" : "当前链路可达性未测试。") +
    "overlay ID 不是 SyncExtend 设备身份，未关联到同步连接；不授予 P2P 费用豁免。外层 wire 和费用未知。");
}

function showDashboard(owner) {
  clearRuntime();
  const value = owner.dashboard;
  if (!value) {
    const detail = owner.dashboard_state === "over_limit" ?
      "运行摘要超过协议上限；当前状态保持未知。" :
      owner.dashboard_state === "no_observation" ?
        "当前角色尚未提供工作区或存储样本。" :
        "当前后台版本尚未提供可用摘要；可刷新服务状态。";
    clearRuntime(detail);
    showGatewayAvailability();
    return;
  }
  if (!ownerReady || owner.dashboard_state !== "available" ||
      value.dashboard_format_version !== 1 || value.remote_backup_complete !== false ||
      new TextEncoder().encode(JSON.stringify(value)).length > 3072) {
    throw new Error("Invalid owner dashboard");
  }
  if (value.observation) {
    const observation = value.observation;
    requireCounts(observation, ["age_ms"]);
    const local = observation.local;
    requireCounts(local, ["total_entries", "total_snapshots", "outstanding_mutations",
      "outstanding_publications", "conflict_admissions_count"]);
    requireFlags(local, ["entries_truncated", "snapshots_truncated", "conflict_admissions_truncated"]);
    if (!identifier(local.space_id, 32) || !identifier(local.device_id, 64) ||
        local.remote_backup_complete !== false || local.conflict_admissions_count > 128) {
      throw new Error("Invalid workspace summary");
    }
    const chunks = local.chunks;
    requireCounts(chunks, ["checked_chunks", "checked_bytes", "total_current_chunks", "unavailable_chunks_count"]);
    requireFlags(chunks, ["all_current_chunks_checked"]);
    if (chunks.checked_chunks > 64 || chunks.checked_bytes > 16 * 1024 * 1024 ||
        chunks.checked_chunks > chunks.total_current_chunks || chunks.unavailable_chunks_count > chunks.checked_chunks ||
        chunks.all_current_chunks_checked !== (chunks.checked_chunks === chunks.total_current_chunks)) {
      throw new Error("Invalid chunk coverage");
    }
    const leases = local.read_leases;
    requireCounts(leases, ["total", "active", "expired_pending_recovery"]);
    requireFlags(leases, ["explicit_recovery_required"]);
    if (leases.active > leases.total || leases.expired_pending_recovery > leases.active ||
        leases.explicit_recovery_required !== (leases.expired_pending_recovery > 0)) {
      throw new Error("Invalid lease summary");
    }
    showSummary("workspace", [
      ["空间", local.space_id], ["设备", local.device_id], ["采样距今", `${observation.age_ms} ms`],
      ["路径 / 历史快照", `${local.total_entries} / ${local.total_snapshots}`],
      ["待处理文件 / 发布", `${local.outstanding_mutations} / ${local.outstanding_publications}`],
      ["冲突样本", `${local.conflict_admissions_count}${local.conflict_admissions_truncated ? "（已截取）" : ""}`],
      ["当前块检查", `${chunks.checked_chunks} / ${chunks.total_current_chunks}；不可读取 ${chunks.unavailable_chunks_count}`],
      ["读租约：总数 / 活跃 / 到期", `${leases.total} / ${leases.active} / ${leases.expired_pending_recovery}`],
    ]);
    setStatus("workspace", "已有样本",
      `${chunks.all_current_chunks_checked ? "已检查当前块。" : "块检查仅为部分抽样。"} ` +
      `${leases.explicit_recovery_required ? "到期租约仍受保护，需要显式回收。" : "没有到期待回收租约。"} ` +
      `${local.entries_truncated || local.snapshots_truncated ? "后台列表已有截取。 " : ""}本页展示摘要；远端备份尚未确认。`);
    showRecovery(local, observation.age_ms);
  }
  if (value.storage) {
    const observation = value.storage;
    requireCounts(observation, ["age_ms"]);
    const storage = observation.actual;
    requireCounts(storage, ["protected_chunks", "protected_bytes", "physical_cas_bytes",
      "stored_byte_limit", "request_byte_limit", "charged_logical_delivery_bytes", "traffic_byte_limit",
      "checked_chunks", "checked_bytes", "unavailable_chunks_count", "total_snapshot_reports"]);
    requireFlags(storage, ["expired", "all_protected_chunks_checked", "snapshot_reports_truncated",
      "journal_snapshot_consistent", "cross_database_snapshot_consistent"]);
    if (!identifier(storage.space_id, 32) || !identifier(storage.device_id, 64) ||
        !["full", "staging"].includes(storage.role) || storage.backup_complete !== false ||
        storage.content_complete_certified !== false || storage.checked_chunks > 64 ||
        storage.checked_bytes > 16 * 1024 * 1024 || storage.checked_chunks > storage.protected_chunks ||
        storage.unavailable_chunks_count > storage.checked_chunks ||
        storage.all_protected_chunks_checked !== (storage.checked_chunks === storage.protected_chunks)) {
      throw new Error("Invalid storage summary");
    }
    showSummary("storage", [
      ["角色", storage.role === "staging" ? "暂存" : "完整存储角色（完整性未认证）"],
      ["采样距今", `${observation.age_ms} ms`],
      ["受保护内容", `${storage.protected_bytes} B`],
      ["实际块文件 / 容量", `${storage.physical_cas_bytes} / ${storage.stored_byte_limit} B`],
      ["单次请求上限", `${storage.request_byte_limit} B`],
      ["逻辑交付累计 / 额度", `${storage.charged_logical_delivery_bytes} / ${storage.traffic_byte_limit} B`],
      ["受保护块检查", `${storage.checked_chunks} / ${storage.protected_chunks}；不可读取 ${storage.unavailable_chunks_count}`],
      ["快照报告总数", storage.total_snapshot_reports],
    ]);
    setStatus("storage", storage.expired ? "策略已到期" : "已有样本",
      `${storage.expired ? "新接收会拒绝；受保护内容不会自动清理。 " : ""}` +
      "逻辑交付按请求、内容和方向去重；不等于重试字节或中继计费。" +
      `${storage.cross_database_snapshot_consistent ? "" : "独立数据库分别采样，跨库一致性未确认。"}`,
      storage.expired ? "warn" : "neutral");
  }
  if (value.webdav) {
    const gateway = value.webdav;
    requireCounts(gateway, ["export_count"]);
    if (gateway.listening !== true || gateway.authenticated !== true ||
        !["http", "https"].includes(gateway.scheme) || typeof gateway.address !== "string" ||
        gateway.address.length > 128) throw new Error("Invalid live gateway summary");
    liveGateway = gateway;
  }
  showConnection(value.connection);
  showEasyTier(value.easytier);
  showGatewayAvailability();
}

function exportRow(item) {
  if (!item || !validExportName(item.name) ||
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
  const probe = document.createElement("button");
  const result = document.createElement("span");
  heading.className = "export-summary";
  access.className = "export-access";
  name.textContent = item.name;
  access.textContent = item.writable ? "配置允许写入（此模块仅支持读取）" : "只读";
  url.textContent = address.href;
  probe.type = "button";
  probe.className = "export-probe";
  probe.textContent = "测试连接";
  probe.setAttribute("aria-label", `测试 ${item.name} 的连接`);
  probe.addEventListener("click", () => testExport(item.name, address.href));
  probe.disabled = true;
  result.className = "export-result";
  result.textContent = ownerReady ? "连接待测试" : "服务未就绪";
  exportResults.set(item.name, result);
  heading.append(name, access);
  row.append(heading, url, probe, result);
  return { row, probe };
}

function showGateway(value) {
  if (!value || value.format_version !== 1 || !Object.prototype.hasOwnProperty.call(value, "webdav")) {
    throw new Error("Invalid gateway response");
  }
  if (!value.webdav || value.webdav.enabled === false) {
    gatewayConfigured = false;
    gatewayDisabled = value.webdav?.enabled === false;
    showGatewayAvailability();
    return;
  }
  if (value.webdav.enabled !== true || !Array.isArray(value.webdav.exports) ||
      value.webdav.exports.length < 1 || value.webdav.exports.length > 64) {
    throw new Error("Invalid gateway export list");
  }
  const rows = value.webdav.exports.map(exportRow);
  gatewayConfigured = true;
  gatewayDisabled = false;
  for (const { row, probe } of rows) {
    fields.exports.appendChild(row);
    probeButtons.push(probe);
  }
  fields.exports.hidden = false;
  showGatewayAvailability();
}

async function refresh() {
  if (busy) return;
  hideConfirmation();
  setBusy(true);
  activeOwner = false;
  ownerReady = false;
  currentOwnerPid = null;
  gatewayConfigured = false;
  gatewayDisabled = false;
  exportResults = new Map();
  probeButtons = [];
  fields.exports.textContent = "";
  fields.exports.hidden = true;
  fields["probe-result"].hidden = true;
  clearRuntime("正在读取当前后台属主的摘要。");
  try {
    await readJson("status").then((value) => {
      showOwner(value);
      if (ownerReady) {
        try { showDashboard(value); }
        catch (error) { clearRuntime("运行摘要无法验证；当前观察保持未知。"); }
      }
    }).catch(() => {
      clearRuntime("没有收到经过验证的当前后台属主状态。");
      setStatus("service", "无法读取", "未收到服务状态。若已停止，可使用“确认已停止”。", "warn");
    });
    await readJson("gateway").then(showGateway).catch(() => {
      setStatus("gateway", "无法读取", "请检查模块私有目录中的部署和网关配置。", "warn");
    });
  } finally {
    setBusy(false);
  }
}

async function testExport(name, expectedUrl) {
  if (busy || !ownerReady) return;
  hideConfirmation();
  setBusy(true);
  const result = fields["probe-result"];
  result.hidden = false;
  result.textContent = `正在测试 ${name}…`;
  const expectedOwnerPid = currentOwnerPid;
  try {
    const value = await readJson("probe", name);
    if (value.owner_pid !== expectedOwnerPid) {
      activeOwner = false;
      ownerReady = false;
      clearRuntime("后台属主已变化；请刷新当前服务状态。");
      clearExportTests("属主变化，需重新测试");
      throw new Error("Live owner changed");
    }
    showOwner(value);
    if (!ownerReady || value.webdav?.export !== name || value.webdav.export_accessible !== true ||
        value.webdav.remote_backup_complete !== false || new URL(value.webdav.url).href !== expectedUrl) {
      throw new Error("Export did not match the live gateway");
    }
    result.textContent = `${name} 可访问，已验证本机认证；远端备份需在对端确认。`;
    result.hidden = false;
    exportResults.get(name).textContent = "本机认证连接测试通过";
    setStatus("gateway", "选中导出测试通过", `${name} 可访问。其他导出需分别测试；远端备份尚未确认。`, "ready");
  } catch (error) {
    result.textContent = `${name} 无法通过连接测试。请刷新状态，并检查导出和账号配置。`;
    result.hidden = false;
    exportResults.get(name).textContent = "连接测试未通过";
    setStatus("gateway", "连接测试未通过", "当前导出可访问性未确认。请刷新属主状态并检查配置和账号。", "warn");
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
    fields["probe-result"].hidden = true;
  } catch (error) {
    activeOwner = false;
    ownerReady = false;
    clearRuntime("停止请求未确认；旧运行摘要已清除。");
    clearExportTests("状态未确认");
    showGatewayAvailability();
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
    ownerReady = false;
    currentOwnerPid = null;
    clearRuntime("当前后台服务已停止，旧运行摘要已清除。");
    clearExportTests("服务已停止");
    showGatewayAvailability();
    fields["probe-result"].hidden = true;
    setStatus("service", "已停止", "当前没有持有模块控制权的后台服务。", "ready");
  } catch (error) {
    activeOwner = false;
    ownerReady = false;
    currentOwnerPid = null;
    clearRuntime("停止状态未确认；旧运行摘要已清除。");
    clearExportTests("状态未确认");
    showGatewayAvailability();
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
  clearRuntime("请在 KernelSU 管理器中连接当前模块后读取。");
}
