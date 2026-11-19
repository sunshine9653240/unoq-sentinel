const $ = (id) => document.getElementById(id);

const ui = new WebUI();
let currentState = null;
let events = [];
let pollTimer = null;
let portsRendered = false;

const levelMeta = {
  low: { label: "系統正常，持續監看中", cls: "alert-low" },
  medium: { label: "發現可疑活動，請注意", cls: "alert-medium" },
  high: { label: "疑似攻擊，已發出警報", cls: "alert-high" },
};

function escapeHtml(value) {
  return String(value ?? "")
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;")
    .replaceAll("'", "&#039;");
}

function formatClock(date = new Date()) {
  return date.toLocaleTimeString("zh-Hant", { hour12: false });
}

function formatEventTime(iso) {
  if (!iso) return "--:--:--";
  try {
    return new Date(iso).toLocaleTimeString("zh-Hant", { hour12: false });
  } catch {
    return "--:--:--";
  }
}

function formatUptime(seconds) {
  const s = Number(seconds || 0);
  if (s < 60) return `${s}s`;
  const m = Math.floor(s / 60);
  if (m < 60) return `${m}m`;
  return `${Math.floor(m / 60)}h ${m % 60}m`;
}

function setThreat(level, score, reasons, lastEventAt) {
  const normalized = levelMeta[level] ? level : "low";
  const meta = levelMeta[normalized];
  $("threatLevel").textContent = normalized.toUpperCase();
  $("threatLabel").textContent = meta.label;
  $("score").textContent = String(score ?? 0);
  $("scoreBar").style.width = `${Math.max(0, Math.min(100, Number(score) || 0))}%`;
  $("threatPanel").className = `panel threat-panel ${meta.cls}`;
  $("shield").textContent = normalized === "high" ? "⚠️" : normalized === "medium" ? "◉" : "🛡️";
  $("lastEvent").textContent = lastEventAt ? `最近事件 ${formatEventTime(lastEventAt)}` : "尚無事件";
  const list = Array.isArray(reasons) && reasons.length ? reasons : ["目前沒有可疑事件"];
  $("reasonList").innerHTML = list.map((reason) => `<span class="reason">${escapeHtml(reason)}</span>`).join("");
}

function applyState(data) {
  if (!data) return;
  currentState = data;
  if (data.threat) {
    const t = data.threat;
    setThreat(t.level, t.score, t.reasons, t.last_event_at);
    $("eventCount").textContent = String(data.events_count ?? 0);
    $("recentCount").textContent = String(data.recent_events ?? 0);
    $("uptime").textContent = formatUptime(data.uptime_sec);
  }
  if (data.llm) {
    $("llmText").textContent = data.llm.text || "LLM 尚未分析事件。";
    const status = data.llm.running ? "分析中" : data.llm.last_at ? "完成" : "待機";
    $("llmStatus").textContent = status;
    $("llmStatus").className = `status-chip ${data.llm.running ? "warn" : data.llm.last_at ? "ok" : ""}`;
  }
  if (Array.isArray(data.honeypot_ports)) {
    $("portGrid").innerHTML = data.honeypot_ports.map((item) => `
      <div class="port-item">
        <div><div class="port-led"></div><strong>:${item.port}</strong></div>
        <span>${escapeHtml(item.service)}</span>
      </div>
    `).join("");
    if (!portsRendered) {
      $("customPorts").innerHTML = data.honeypot_ports.map((item, index) => `
        <label class="port-choice">
          <input type="checkbox" value="${item.port}" ${index === 3 ? "checked" : ""}>
          :${item.port}
        </label>
      `).join("");
      portsRendered = true;
    }
  }
  if (data.ntfy_topic) {
    $("ntfyTopic").textContent = data.ntfy_topic;
    $("ntfyLink").href = data.ntfy_url || `https://ntfy.sh/${encodeURIComponent(data.ntfy_topic)}`;
  }
  if (data.notification && data.notification.count) {
    $("notifyStatus").textContent = data.notification.ok ? `已送出 ${data.notification.count} 次` : "傳送失敗";
    $("notifyStatus").className = `status-chip ${data.notification.ok ? "ok" : "bad"}`;
  }
}

function riskClass(event) {
  const path = String(event.path || "").toLowerCase();
  if (/\.env|wp-login|passwd|\.\.|admin|phpmyadmin|cgi-bin/.test(path)) return "bad";
  if (event.service === "ssh" || event.service === "telnet") return "warn";
  return "";
}

function addEvent(event) {
  if (!event || !event.id) return;
  events = [event, ...events.filter((item) => item.id !== event.id)].slice(0, 40);
  renderEvents();
}

function renderEvents() {
  const container = $("eventList");
  if (!events.length) {
    container.innerHTML = '<div class="empty-state">等待 honeypot 或外部事件...</div>';
    return;
  }
  container.innerHTML = events.map((event) => {
    const cls = riskClass(event);
    const meta = [
      event.source || "unknown",
      event.port ? `:${event.port}` : "",
      event.path || event.detail || "",
    ].filter(Boolean).join(" · ");
    return `
      <div class="event-item ${cls}">
        <div class="event-time">${formatEventTime(event.iso_time)}</div>
        <div class="event-main">
          <div class="event-title">${escapeHtml(event.event)}</div>
          <div class="event-meta">${escapeHtml(meta)}</div>
        </div>
        <div class="event-tag">${escapeHtml(event.service || "event")}</div>
      </div>
    `;
  }).join("");
}

async function fetchJson(path, options = {}) {
  const response = await fetch(path, { cache: "no-store", ...options });
  if (!response.ok) throw new Error(`${path}: HTTP ${response.status}`);
  return response.json();
}

async function post(path, body = undefined) {
  try {
    const options = { method: "POST" };
    if (body !== undefined) {
      options.headers = { "Content-Type": "application/json" };
      options.body = JSON.stringify(body);
    }
    return await fetchJson(path, options);
  } catch (error) {
    showToast(`操作失敗：${error.message}`);
    return null;
  }
}

function refreshState() {
  fetchJson("/api/state")
    .then((data) => {
      applyState(data);
    })
    .catch(() => {});
}

function refreshEvents() {
  fetchJson("/api/events")
    .then((data) => {
      events = Array.isArray(data.events) ? data.events : [];
      renderEvents();
    })
    .catch(() => {});
}

function showToast(message) {
  const toast = $("toast");
  toast.textContent = message;
  toast.classList.add("show");
  clearTimeout(showToast.timer);
  showToast.timer = setTimeout(() => toast.classList.remove("show"), 2600);
}

function updateConnection(connected) {
  $("connectionText").textContent = connected ? "LIVE · 已連線" : "連線中斷";
  document.querySelector(".live-pill").style.opacity = connected ? "1" : ".55";
}

ui.on_connect(() => {
  updateConnection(true);
  refreshState();
  refreshEvents();
});
ui.on_disconnect(() => updateConnection(false));
ui.on_message("security_state", applyState);
ui.on_message("llm_analysis", (data) => {
  if (data) {
    $("llmText").textContent = data.text || "LLM 尚未分析事件。";
    $("llmStatus").textContent = data.running ? "分析中" : data.last_at ? "完成" : "待機";
    $("llmStatus").className = `status-chip ${data.running ? "warn" : data.last_at ? "ok" : ""}`;
  }
});
ui.on_message("new_event", addEvent);

async function runSimulation(path, button, workingText, doneText) {
  button.disabled = true;
  button.textContent = workingText;
  await post("/api/reset");
  await post(path);
  showToast("已送出測試流量，正在等待規則引擎判定");
  setTimeout(() => {
    button.disabled = false;
    button.textContent = doneText;
  }, 2600);
}

$("simulateMediumBtn").addEventListener("click", async () => {
  await runSimulation("/api/simulate-medium", $("simulateMediumBtn"), "模擬中...", "模擬中風險");
});

$("simulateBtn").addEventListener("click", async () => {
  await runSimulation("/api/simulate", $("simulateBtn"), "模擬中...", "模擬高風險");
});

$("simulateFloodBtn").addEventListener("click", async () => {
  await runSimulation("/api/simulate-flood", $("simulateFloodBtn"), "灌流量中...", "模擬單端口洪水");
});

$("runCustom").addEventListener("click", async () => {
  const ports = [...document.querySelectorAll("#customPorts input:checked")].map((input) => Number(input.value));
  if (!ports.length) {
    $("customStatus").textContent = "請至少選擇一個端口";
    return;
  }
  const payload = {
    ports,
    connections: Number($("customConnections").value) || 1,
    payload_bytes: (Number($("customPayload").value) || 0) * 1024,
    delay_ms: Number($("customDelay").value) || 0,
    malicious_http: $("customMalicious").checked,
  };
  $("runCustom").disabled = true;
  $("runCustom").textContent = "執行中...";
  $("customStatus").textContent = `執行 ${ports.length} 個端口 × ${payload.connections} 次連線`;
  await post("/api/reset");
  const result = await post("/api/simulate-custom", payload);
  if (result?.ok) {
    showToast(`已送出 ${ports.length} 個端口 × ${payload.connections} 次連線`);
    $("customStatus").textContent = "測試已送出，等待規則引擎判定";
  } else {
    $("customStatus").textContent = "測試送出失敗";
  }
  setTimeout(() => {
    $("runCustom").disabled = false;
    $("runCustom").textContent = "執行自訂測試";
  }, 2500);
});

$("testNotify").addEventListener("click", async () => {
  $("notifyStatus").textContent = "傳送中";
  $("notifyStatus").className = "status-chip warn";
  const result = await post("/api/test-notify");
  if (result?.ok) {
    $("notifyStatus").textContent = "已送出";
    $("notifyStatus").className = "status-chip ok";
    showToast("已送出 ntfy 測試通知");
  } else {
    $("notifyStatus").textContent = "失敗";
    $("notifyStatus").className = "status-chip bad";
    showToast("推播失敗，請檢查網路與 ntfy topic");
  }
});

$("analyzeBtn").addEventListener("click", async () => {
  $("analyzeBtn").disabled = true;
  $("analyzeBtn").textContent = "分析中...";
  await post("/api/analyze");
  showToast("已排入 LLM 分析");
  setTimeout(() => {
    $("analyzeBtn").disabled = false;
    $("analyzeBtn").textContent = "立即分析事件";
  }, 1800);
});

$("resetBtn").addEventListener("click", async () => {
  await post("/api/reset");
  events = [];
  renderEvents();
  refreshState();
  showToast("事件與威脅狀態已清除");
});

setInterval(() => { $("clock").textContent = formatClock(); }, 1000);
$("clock").textContent = formatClock();
refreshState();
refreshEvents();
pollTimer = setInterval(refreshState, 5000);

