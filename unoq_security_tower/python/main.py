# SPDX-License-Identifier: MPL-2.0
"""UNO Q Sentinel.

A self-contained honeypot + AI-assisted network alert node.

Architecture:
- Honeypot TCP/HTTP listeners collect connection-level attack events.
- A rule engine builds the first-stage risk assessment.
- The local Qwen3.5 0.8B LLM summarizes suspicious event batches.
- The MCU displays the current threat level on the 8x13 LED matrix.
- ntfy sends high-priority phone notifications.
"""

from __future__ import annotations

import json
import os
import re
import socket
import socketserver
import threading
import time
import urllib.parse
import urllib.request
from collections import Counter, deque
from datetime import UTC, datetime

import numpy as np
from fastapi import Request

from arduino.app_bricks.llm import LargeLanguageModel
from arduino.app_bricks.web_ui import WebUI
from arduino.app_utils import App, Bridge, Frame

# ----------------------------- configuration -----------------------------

NTFY_TOPIC = os.environ.get("NTFY_TOPIC", "unoq-sentinel-7f4c2d91")
NTFY_SERVER = os.environ.get("NTFY_SERVER", "https://ntfy.sh")
HONEYPOT_PORTS = {
    2222: "ssh",
    2323: "telnet",
    8081: "http",
    9000: "decoy",
    9001: "decoy",
    9002: "decoy",
    9003: "decoy",
    9004: "decoy",
}
EVENT_WINDOW_SEC = 30
MAX_EVENTS = 400
LLM_COOLDOWN_SEC = 60
NOTIFY_COOLDOWN_SEC = 60
HOLD_HIGH_SEC = 45
HOLD_MEDIUM_SEC = 45
DATA_FLOOD_BYTES = 8192
MALICIOUS_PATHS = (
    "/.env",
    "/wp-login.php",
    "/phpmyadmin",
    "/admin",
    "/../",
    "/etc/passwd",
    "/cgi-bin",
    "/shell",
)

# ----------------------------- runtime objects ----------------------------

ui = WebUI()
llm = LargeLanguageModel(
    system_prompt=(
        "你是 UNO Q Sentinel 的資安分析師。"
        "只根據提供的事件回答，使用繁體中文，直接輸出結論，不要思考或解釋流程。"
    ),
    temperature=0.1,
    max_tokens=90,
    timeout=120,
)

event_lock = threading.RLock()
events: deque[dict] = deque(maxlen=MAX_EVENTS)
threat_lock = threading.RLock()
threat_state = {
    "level": "low",
    "score": 0,
    "reasons": [],
    "summary": "系統待機，等待可疑連線。",
    "last_event_at": None,
}
llm_state = {
    "running": False,
    "text": "LLM 尚未分析事件。",
    "last_at": None,
}
last_llm_at = 0.0
last_notify_at = 0.0
alert_hold_until = 0.0
alert_snapshot = None
medium_hold_until = 0.0
medium_snapshot = None
llm_lock = threading.Lock()
pending_llm = False
analysis_epoch = 0
notify_state = {"count": 0, "last_at": None, "ok": None}
runtime_started_at = time.time()
matrix_failures = 0
matrix_disabled = False

# ----------------------------- LED frames --------------------------------

def _blank() -> list[list[int]]:
    return [[0 for _ in range(13)] for _ in range(8)]


def _set(frame, row, col, value=7):
    if 0 <= row < 8 and 0 <= col < 13:
        frame[row][col] = value


def idle_frame(phase: int = 0) -> list[list[int]]:
    frame = _blank()
    # a simple radar/scanning pattern
    for r in range(1, 7):
        frame[r][2] = 3
    center = 6 if phase % 2 == 0 else 7
    for r in range(2, 6):
        frame[r][center] = 7
    frame[3][center - 1] = 4
    frame[3][center + 1] = 4
    return frame


def warning_frame() -> list[list[int]]:
    frame = _blank()
    # exclamation mark
    for r in range(1, 6):
        _set(frame, r, 6, 7)
    _set(frame, 6, 6, 7)
    return frame


def critical_frame() -> list[list[int]]:
    frame = _blank()
    # X / threat symbol
    for r in range(1, 7):
        _set(frame, r, r + 2, 7)
        _set(frame, r, 10 - r, 7)
    for c in range(2, 11):
        _set(frame, 7, c, 5)
    return frame


def show_frame(frame: list[list[int]]) -> None:
    global matrix_failures, matrix_disabled
    if matrix_disabled:
        return
    try:
        Bridge.call("draw", Frame(np.array(frame, dtype=np.uint8)).to_board_bytes())
        matrix_failures = 0
    except Exception as exc:
        matrix_failures += 1
        if matrix_failures in (1, 5, 20):
            print(f"matrix bridge error ({matrix_failures}): {exc}", flush=True)
        if matrix_failures >= 20:
            matrix_disabled = True


# ----------------------------- events ------------------------------------

def _iso_now() -> str:
    return datetime.now(UTC).isoformat(timespec="milliseconds")


def record_event(
    source: str,
    service: str,
    event_type: str,
    port: int | None = None,
    path: str | None = None,
    detail: str | None = None,
    **extra,
) -> dict:
    event = {
        "id": f"{time.time_ns()}-{threading.get_ident()}",
        "ts": time.time(),
        "iso_time": _iso_now(),
        "source": str(source or "unknown")[:64],
        "service": str(service or "network")[:32],
        "event": str(event_type or "event")[:40],
        "port": int(port) if port else None,
        "path": (str(path)[:160] if path else None),
        "detail": (str(detail)[:240] if detail else None),
    }
    event.update({k: v for k, v in extra.items() if isinstance(v, (str, int, float, bool, type(None)))})
    with event_lock:
        events.append(event)
    try:
        ui.send_message("new_event", event)
    except Exception:
        pass
    return event


def snapshot_events(limit: int = 30) -> list[dict]:
    with event_lock:
        return list(events)[-limit:][::-1]


# ----------------------------- honeypot ----------------------------------

def _read_payload(sock, limit=131072, idle_timeout=0.35) -> bytes:
    """Read a bounded amount of client data without waiting forever."""
    chunks = []
    total = 0
    sock.settimeout(idle_timeout)
    while total < limit:
        try:
            chunk = sock.recv(min(8192, limit - total))
        except (socket.timeout, ConnectionResetError):
            break
        if not chunk:
            break
        chunks.append(chunk)
        total += len(chunk)
    return b"".join(chunks)


class HoneypotHandler(socketserver.BaseRequestHandler):
    def handle(self):
        port = int(self.server.server_address[1])
        service = HONEYPOT_PORTS.get(port, "decoy")
        source = self.client_address[0]
        self.request.settimeout(3)
        try:
            if service == "http":
                data = self.request.recv(4096)
                text = data.decode("utf-8", errors="replace")
                first = text.splitlines()[0] if text else "GET / HTTP/1.0"
                parts = first.split()
                path = parts[1] if len(parts) >= 2 else "/"
                payload = _read_payload(self.request, limit=DATA_FLOOD_BYTES * 2)
                total_payload = len(data) + len(payload)
                if total_payload >= DATA_FLOOD_BYTES:
                    record_event(source, service, "data_flood", port, path=path,
                                 detail=f"大量 HTTP 垃圾資料 bytes={total_payload}",
                                 payload_bytes=total_payload)
                else:
                    record_event(source, service, "http_request", port, path=path,
                                 detail=first[:200], payload_bytes=total_payload)
                body = b"HTTP/1.1 404 Not Found\r\nServer: UNO-Q-Decoy\r\nContent-Length: 15\r\n\r\nUNO Q decoy\r\n"
                self.request.sendall(body)
            elif service in ("ssh", "telnet"):
                self.request.sendall(b"SSH-2.0-OpenSSH_7.4\r\n" if service == "ssh" else b"UNO-Q login: ")
                data = _read_payload(self.request, limit=DATA_FLOOD_BYTES * 2)
                event_type = "ssh_attempt" if service == "ssh" else "telnet_attempt"
                if len(data) >= DATA_FLOOD_BYTES:
                    record_event(source, service, "data_flood", port,
                                 detail=f"大量 {service} 垃圾資料 bytes={len(data)}",
                                 payload_bytes=len(data))
                else:
                    record_event(source, service, event_type, port,
                                 detail=f"payload_bytes={len(data)}", payload_bytes=len(data))
            else:
                self.request.sendall(b"UNO-Q decoy service\r\n")
                data = _read_payload(self.request)
                if len(data) >= DATA_FLOOD_BYTES:
                    record_event(source, service, "data_flood", port,
                                 detail=f"單端口大量垃圾資料 bytes={len(data)}",
                                 payload_bytes=len(data))
                else:
                    record_event(source, service, "tcp_connect", port, payload_bytes=len(data))
        except Exception as exc:
            record_event(source, service, "connection", port, detail=type(exc).__name__)
        finally:
            try:
                self.request.close()
            except Exception:
                pass


class ThreadedHoneypot(socketserver.ThreadingTCPServer):
    allow_reuse_address = True
    daemon_threads = True


def start_honeypot() -> None:
    for port in HONEYPOT_PORTS:
        try:
            server = ThreadedHoneypot(("0.0.0.0", port), HoneypotHandler)
            threading.Thread(target=server.serve_forever, name=f"honeypot-{port}", daemon=True).start()
            print(f"honeypot listening on port {port}", flush=True)
        except Exception as exc:
            print(f"honeypot port {port} unavailable: {exc}", flush=True)


# ----------------------------- detection ---------------------------------

def _recent_events(window: int = EVENT_WINDOW_SEC) -> list[dict]:
    cutoff = time.time() - window
    with event_lock:
        return [event for event in events if event["ts"] >= cutoff]


def _assess(now: float) -> dict:
    recent = _recent_events()
    if not recent:
        return {
            "level": "low",
            "score": 0,
            "reasons": ["目前沒有可疑事件"],
            "summary": "系統待機，等待可疑連線。",
            "last_event_at": threat_state.get("last_event_at"),
        }

    by_source: dict[str, list[dict]] = {}
    for event in recent:
        by_source.setdefault(event["source"], []).append(event)

    score = 0
    reasons = []
    suspicious_source = None
    for source, source_events in by_source.items():
        ports = {event["port"] for event in source_events if event.get("port")}
        ssh_attempts = sum(1 for e in source_events if e["event"] == "ssh_attempt")
        bad_paths = [e.get("path") or "" for e in source_events if e["event"] == "http_request" and any(p in (e.get("path") or "").lower() for p in MALICIOUS_PATHS)]
        flood_events = [e for e in source_events if e["event"] in ("data_flood", "traffic_flood")]
        flood_bytes = sum(int(e.get("payload_bytes") or e.get("bytes") or 0) for e in flood_events)
        flood_pps = max([float(e.get("pps") or 0) for e in flood_events] or [0])
        port_counts = Counter(
            e["port"] for e in source_events
            if e.get("port") and e["event"] in ("tcp_connect", "ssh_attempt", "telnet_attempt", "http_request", "data_flood")
        )
        repeated_port_count = max(port_counts.values(), default=0)
        if flood_bytes >= 32768 or flood_pps >= 200:
            score = max(score, 85)
            reasons.append(f"{source} 單端口大量垃圾流量")
            suspicious_source = source
        elif flood_bytes >= DATA_FLOOD_BYTES:
            score = max(score, 65)
            reasons.append(f"{source} 單端口異常資料量")
            suspicious_source = source
        if repeated_port_count >= 10:
            score = max(score, 70)
            reasons.append(f"{source} 同一端口高頻連線 x{repeated_port_count}")
            suspicious_source = source
        elif repeated_port_count >= 5:
            score = max(score, 40)
            reasons.append(f"{source} 同一端口重複連線 x{repeated_port_count}")
            suspicious_source = suspicious_source or source
        if len(ports) >= 3:
            score = max(score, 35)
            reasons.append(f"{source} 連到 {len(ports)} 個端口")
            suspicious_source = suspicious_source or source
        if len(ports) >= 5:
            score = max(score, 65)
            reasons.append(f"{source} 疑似端口掃描")
            suspicious_source = source
        if ssh_attempts >= 3:
            score = max(score, 55)
            reasons.append(f"{source} 多次 SSH 嘗試")
            suspicious_source = suspicious_source or source
        if bad_paths:
            score = max(score, 70)
            reasons.append(f"{source} 惡意 HTTP 路徑")
            suspicious_source = source
        if len(source_events) >= 20:
            score = max(score, 60)
            reasons.append(f"{source} 短時間高頻連線")
            suspicious_source = suspicious_source or source

    level = "high" if score >= 60 else "medium" if score >= 25 else "low"
    summary = "；".join(dict.fromkeys(reasons)) or "事件已記錄，未達警報門檻。"
    return {
        "level": level,
        "score": min(score, 100),
        "reasons": list(dict.fromkeys(reasons)) or ["事件低於警報門檻"],
        "summary": summary,
        "last_event_at": datetime.fromtimestamp(recent[-1]["ts"], UTC).isoformat(timespec="milliseconds"),
        "source": suspicious_source,
    }


def detector_loop() -> None:
    global alert_hold_until, alert_snapshot, medium_hold_until, medium_snapshot
    last_state_key = None
    last_led_key = None
    phase = 0
    while True:
        try:
            now = time.time()
            assessment = _assess(now)
            if assessment["level"] == "high":
                alert_hold_until = now + HOLD_HIGH_SEC
                alert_snapshot = dict(assessment)
            elif now < alert_hold_until and alert_snapshot:
                assessment = dict(alert_snapshot)
                assessment["level"] = "high"
                assessment["score"] = max(60, int(alert_snapshot.get("score", 0)))
                assessment["reasons"] = list(alert_snapshot.get("reasons", [])) + [
                    f"警報保持中（{max(0, int(alert_hold_until - now))}s）"
                ]
            elif assessment["level"] == "medium":
                medium_hold_until = now + HOLD_MEDIUM_SEC
                medium_snapshot = dict(assessment)
            elif now < medium_hold_until and medium_snapshot and assessment["level"] == "low":
                assessment = dict(medium_snapshot)
                assessment["level"] = "medium"
                assessment["score"] = max(25, int(medium_snapshot.get("score", 0)))
                assessment["reasons"] = list(medium_snapshot.get("reasons", [])) + [
                    f"中風險保持中（{max(0, int(medium_hold_until - now))}s）"
                ]
            with threat_lock:
                old_level = threat_state["level"]
                threat_state.update(assessment)
                current_level = threat_state["level"]
            state_key = (current_level, assessment["score"], tuple(assessment["reasons"]))
            if state_key != last_state_key:
                last_state_key = state_key
                ui.send_message("security_state", public_state())
                print(f"threat state: {current_level} score={assessment['score']} reasons={assessment['reasons']}", flush=True)

            if current_level in ("medium", "high") and now - last_llm_at >= LLM_COOLDOWN_SEC:
                schedule_llm_analysis(force=False)
            if current_level == "high" and now - last_notify_at >= NOTIFY_COOLDOWN_SEC:
                # Rate-limit even when the external ntfy request fails.
                globals()["last_notify_at"] = now
                threading.Thread(
                    target=notify_high_risk,
                    args=(dict(assessment),),
                    name="ntfy-alert",
                    daemon=True,
                ).start()

            led_key = current_level
            if led_key != last_led_key:
                last_led_key = led_key
            if current_level == "low":
                show_frame(idle_frame(phase))
                phase += 1
            elif current_level == "medium":
                show_frame(warning_frame())
            else:
                show_frame(critical_frame())
        except Exception as exc:
            print(f"detector error: {exc}", flush=True)
        time.sleep(1.0)


# ----------------------------- LLM analyst --------------------------------

def _rule_summary() -> str:
    with threat_lock:
        return threat_state.get("summary", "尚未建立風險摘要。")


def schedule_llm_analysis(force: bool = False) -> None:
    global last_llm_at, pending_llm, analysis_epoch
    if not force and time.time() - last_llm_at < LLM_COOLDOWN_SEC:
        return
    if not force and not _recent_events(45):
        # Do not overwrite the last analysis while an alert hold has no new events.
        return
    analysis_epoch += 1
    epoch = analysis_epoch
    with threat_lock:
        level = threat_state.get("level", "low")
        score = threat_state.get("score", 0)
        summary = threat_state.get("summary", "")
        llm_state["running"] = True
        llm_state["text"] = f"規則初步判定：{level.upper()}（{score}/100）\n{summary}\n\nLLM 正在補充分析..."
    ui.send_message("llm_analysis", dict(llm_state))
    if not llm_lock.acquire(blocking=False):
        pending_llm = True
        return
    last_llm_at = time.time()
    threading.Thread(target=_llm_worker, args=(epoch,), daemon=True).start()


def _llm_worker(epoch: int) -> None:
    global llm_state, pending_llm
    try:
        recent = _recent_events(45)[-8:]
        if not recent:
            text = "目前沒有新的可疑事件。"
        else:
            lines = []
            for event in recent:
                line = f"{event['iso_time'][11:19]} {event['source']} {event['event']} port={event['port']}"
                if event.get("path"):
                    line += f" path={event['path']}"
                lines.append(line)
            with threat_lock:
                rule_level = threat_state.get("level", "low")
                rule_score = threat_state.get("score", 0)
                rule_summary = threat_state.get("summary", "")
            prompt = (
                f"規則引擎判定：{rule_level}（{rule_score}/100）\n"
                f"規則原因：{rule_summary}\n"
                "蜜罐事件：\n"
                + "\n".join(lines)
                + "\n請只輸出兩行：\n摘要：一句\n建議：一句"
            )
            raw = llm.chat(prompt).strip()
            raw = re.sub(r"^\s*風險[:：].*$", "", raw, flags=re.MULTILINE).strip()
            text = f"規則判定：{rule_level.upper()}（{rule_score}/100）\n{raw or _rule_summary()}"
    except Exception as exc:
        with threat_lock:
            fallback_level = threat_state.get("level", "low")
            fallback_score = threat_state.get("score", 0)
            fallback_summary = threat_state.get("summary", "")
        text = f"規則判定：{fallback_level.upper()}（{fallback_score}/100）\nLLM 無法分析：{fallback_summary} ({type(exc).__name__})"
    finally:
        with threat_lock:
            if epoch == analysis_epoch:
                llm_state["running"] = False
                llm_state["text"] = text
                llm_state["last_at"] = _iso_now()
                ui.send_message("llm_analysis", dict(llm_state))
        try:
            llm_lock.release()
        except RuntimeError:
            pass
        if pending_llm:
            pending_llm = False
            if _recent_events(45):
                threading.Timer(0.1, lambda: schedule_llm_analysis(force=True)).start()


# ----------------------------- notification -------------------------------

def notify_high_risk(assessment: dict) -> bool:
    body = (
        f"等級：{assessment.get('level', 'high').upper()}\n"
        f"風險分數：{assessment.get('score', 0)}/100\n"
        f"原因：{assessment.get('summary', '')}\n"
        f"時間：{_iso_now()}\n"
        "請開啟 UNO Q Sentinel Dashboard 查看事件。"
    )
    url = f"{NTFY_SERVER.rstrip('/')}/{urllib.parse.quote(NTFY_TOPIC, safe='')}"
    request = urllib.request.Request(
        url,
        data=body.encode("utf-8"),
        method="POST",
        headers={
            "Title": "UNO Q Sentinel Alert",
            "Priority": "5",
            "Tags": "warning,shield",
            "Content-Type": "text/plain; charset=utf-8",
        },
    )
    try:
        with urllib.request.urlopen(request, timeout=8) as response:
            ok = 200 <= response.status < 300
            print(f"ntfy notification sent: {response.status}", flush=True)
            notify_state.update({"count": notify_state["count"] + 1, "last_at": _iso_now(), "ok": ok})
            return ok
    except Exception as exc:
        print(f"ntfy notification failed: {exc}", flush=True)
        notify_state.update({"count": notify_state["count"] + 1, "last_at": _iso_now(), "ok": False})
        return False


# ----------------------------- state / API --------------------------------

def public_state() -> dict:
    with threat_lock:
        state = dict(threat_state)
        analyst = dict(llm_state)
    with event_lock:
        event_count = len(events)
        recent_count = len(_recent_events())
    return {
        "threat": state,
        "llm": analyst,
        "events_count": event_count,
        "recent_events": recent_count,
        "honeypot_ports": [{"port": p, "service": s} for p, s in HONEYPOT_PORTS.items()],
        "ntfy_topic": NTFY_TOPIC,
        "ntfy_url": f"{NTFY_SERVER.rstrip('/')}/{NTFY_TOPIC}",
        "notification": dict(notify_state),
        "uptime_sec": int(time.time() - runtime_started_at),
    }


def on_ui_connect(_sid: str) -> None:
    ui.send_message("security_state", public_state())
    ui.send_message("llm_analysis", dict(llm_state))
    for event in snapshot_events(20):
        ui.send_message("new_event", event)


def state_api():
    return public_state()


def events_api():
    return {"events": snapshot_events(50)}


async def event_api(request: Request):
    try:
        payload = await request.json()
    except Exception:
        return {"ok": False, "error": "invalid json"}
    if not isinstance(payload, dict):
        return {"ok": False, "error": "object required"}
    extra = {
        key: payload.get(key)
        for key in ("packets", "bytes", "payload_bytes", "pps", "bps", "syns", "duration")
        if payload.get(key) is not None
    }
    event = record_event(
        source=payload.get("source", "external"),
        service=payload.get("service", "external"),
        event_type=payload.get("event", "ingest"),
        port=payload.get("port"),
        path=payload.get("path"),
        detail=payload.get("detail"),
        **extra,
    )
    return {"ok": True, "event_id": event["id"]}


def reset_api():
    global last_llm_at, last_notify_at, alert_hold_until, alert_snapshot, medium_hold_until, medium_snapshot, pending_llm, analysis_epoch
    last_llm_at = 0.0
    pending_llm = False
    analysis_epoch += 1
    last_notify_at = 0.0
    alert_hold_until = 0.0
    alert_snapshot = None
    medium_hold_until = 0.0
    medium_snapshot = None
    with event_lock:
        events.clear()
    with threat_lock:
        threat_state.update({
            "level": "low",
            "score": 0,
            "reasons": ["事件已清除"],
            "summary": "系統待機，等待可疑連線。",
            "last_event_at": None,
            "source": None,
        })
        llm_state.update({"running": False, "text": "LLM 尚未分析事件。", "last_at": None})
        notify_state.update({"count": 0, "last_at": None, "ok": None})
    show_frame(idle_frame(0))
    ui.send_message("security_state", public_state())
    ui.send_message("llm_analysis", dict(llm_state))
    return {"ok": True}


def start_simulation():
    threading.Thread(target=_simulate_attack, daemon=True).start()
    return {"ok": True, "message": "simulation started"}


def _simulate_attack() -> None:
    record_event("127.0.0.1", "simulator", "simulation_started", detail="在 UNO Q 內部產生測試流量")
    for port in HONEYPOT_PORTS:
        try:
            with socket.create_connection(("127.0.0.1", port), timeout=1.0) as sock:
                if port == 8081:
                    sock.sendall(b"GET /wp-login.php HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n")
                elif port in (2222, 2323):
                    try:
                        sock.settimeout(0.5)
                        sock.recv(128)
                    except Exception:
                        pass
                    sock.sendall(b"test login attempt\r\n")
        except Exception as exc:
            record_event("127.0.0.1", "simulator", "simulation_error", port=port, detail=str(exc))
        time.sleep(0.08)
    record_event("127.0.0.1", "simulator", "simulation_finished", detail="測試流量完成")


def start_medium_simulation():
    threading.Thread(target=_simulate_medium, daemon=True).start()
    return {"ok": True, "message": "medium simulation started"}


def _simulate_medium() -> None:
    # Three distinct decoy ports = medium score, no malicious HTTP path.
    record_event("127.0.0.1", "simulator", "simulation_started", detail="中等風險測試：3 個端口")
    for port in (9000, 9001, 9002):
        try:
            with socket.create_connection(("127.0.0.1", port), timeout=1.0) as sock:
                sock.sendall(b"UNOQ sentinel medium test\r\n")
        except Exception as exc:
            record_event("127.0.0.1", "simulator", "simulation_error", port=port, detail=str(exc))
        time.sleep(0.15)
    record_event("127.0.0.1", "simulator", "simulation_finished", detail="中等風險測試完成")


def start_flood_simulation():
    threading.Thread(target=_simulate_flood, daemon=True).start()
    return {"ok": True, "message": "single-port flood simulation started"}


def _simulate_flood() -> None:
    # One port, many junk bytes: specifically tests the data_flood rule.
    record_event("127.0.0.1", "simulator", "simulation_started", detail="單端口垃圾流量測試")
    try:
        with socket.create_connection(("127.0.0.1", 9000), timeout=1.0) as sock:
            chunk = b"UNOQ-JUNK-" * 1024  # 10 KB per chunk
            for _ in range(13):
                sock.sendall(chunk)
    except Exception as exc:
        record_event("127.0.0.1", "simulator", "simulation_error", port=9000, detail=str(exc))
    record_event("127.0.0.1", "simulator", "simulation_finished", detail="單端口垃圾流量測試完成")


def _validate_custom(config: dict) -> tuple[list[int], int, int, int, bool, str]:
    ports = []
    for value in config.get("ports", []):
        try:
            port = int(value)
        except (TypeError, ValueError):
            continue
        if port in HONEYPOT_PORTS and port not in ports:
            ports.append(port)
    if not ports:
        ports = [9000]
    ports = ports[:len(HONEYPOT_PORTS)]
    connections = max(1, min(int(config.get("connections", 1) or 1), 20))
    payload_bytes = max(0, min(int(config.get("payload_bytes", 0) or 0), 131072))
    delay_ms = max(0, min(int(config.get("delay_ms", 80) or 0), 500))
    malicious_http = bool(config.get("malicious_http", False))
    http_path = str(config.get("http_path") or "/wp-login.php")[:120]
    return ports, connections, payload_bytes, delay_ms, malicious_http, http_path


async def simulate_custom_api(request: Request):
    try:
        config = await request.json()
    except Exception:
        return {"ok": False, "error": "invalid json"}
    if not isinstance(config, dict):
        return {"ok": False, "error": "object required"}
    try:
        ports, connections, payload_bytes, delay_ms, malicious_http, http_path = _validate_custom(config)
    except Exception as exc:
        return {"ok": False, "error": str(exc)}
    threading.Thread(
        target=_simulate_custom,
        args=(ports, connections, payload_bytes, delay_ms, malicious_http, http_path),
        daemon=True,
    ).start()
    return {
        "ok": True,
        "ports": ports,
        "connections": connections,
        "payload_bytes": payload_bytes,
        "delay_ms": delay_ms,
    }


def _simulate_custom(ports: list[int], connections: int, payload_bytes: int, delay_ms: int, malicious_http: bool, http_path: str) -> None:
    record_event("127.0.0.1", "simulator", "simulation_started",
                 detail=f"自訂測試 ports={ports} connections={connections} payload={payload_bytes}")
    for port in ports:
        for index in range(connections):
            try:
                with socket.create_connection(("127.0.0.1", port), timeout=1.0) as sock:
                    if port == 8081:
                        path = http_path if malicious_http else "/"
                        request = (
                            f"GET {path} HTTP/1.1\r\nHost: localhost\r\n"
                            "Connection: close\r\n\r\n"
                        ).encode()
                        sock.sendall(request)
                    elif port in (2222, 2323):
                        try:
                            sock.settimeout(0.4)
                            sock.recv(128)
                        except Exception:
                            pass
                        sock.sendall(b"admin:test-only-no-real-password\r\n")
                    if payload_bytes:
                        remaining = payload_bytes
                        chunk = b"UNOQ-CUSTOM-JUNK-" * 512
                        while remaining > 0:
                            part = chunk[:min(len(chunk), remaining)]
                            sock.sendall(part)
                            remaining -= len(part)
                if delay_ms:
                    time.sleep(delay_ms / 1000)
            except Exception as exc:
                record_event("127.0.0.1", "simulator", "simulation_error",
                             port=port, detail=f"connection={index + 1} {type(exc).__name__}")
    record_event("127.0.0.1", "simulator", "simulation_finished",
                 detail=f"自訂測試完成 ports={len(ports)} connections={connections}")


def test_notify():
    now = time.time()
    sent = notify_high_risk({
        "level": "high",
        "score": 88,
        "summary": "這是一則 UNO Q Sentinel 手機推播測試。",
    })
    return {"ok": sent, "topic": NTFY_TOPIC}


# ----------------------------- wiring -------------------------------------

ui.expose_api("GET", "/api/state", state_api)
ui.expose_api("GET", "/api/events", events_api)
ui.expose_api("POST", "/event", event_api)
ui.expose_api("POST", "/api/reset", reset_api)
ui.expose_api("POST", "/api/simulate", start_simulation)
ui.expose_api("POST", "/api/simulate-medium", start_medium_simulation)
ui.expose_api("POST", "/api/simulate-flood", start_flood_simulation)
ui.expose_api("POST", "/api/simulate-custom", simulate_custom_api)
ui.expose_api("POST", "/api/test-notify", test_notify)
ui.expose_api("POST", "/api/analyze", lambda: (schedule_llm_analysis(force=True), {"ok": True})[1])
ui.on_connect(on_ui_connect)

start_honeypot()
threading.Thread(target=detector_loop, daemon=True).start()

print("UNO Q Sentinel starting", flush=True)
print(f"phone alert topic: {NTFY_TOPIC}", flush=True)
App.run()

