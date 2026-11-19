#!/usr/bin/env python3
"""Raw IPv4/TCP capture agent for UNO Q Sentinel.

This helper runs in a privileged Docker container on the UNO Q host:

    docker run --rm --network host --user 0 --cap-add NET_RAW \
      -v /home/arduino/ArduinoApps/unoq_security_tower/capture:/capture:ro \
      --entrypoint python \
      ghcr.io/arduino/app-bricks/python-apps-base:0.13.2 \
      /capture/capture_agent.py --iface wlan0 --target-ip <BOARD_IP>

It captures IPv4/TCP packets addressed to the target board and POSTs compact
event summaries to the Sentinel /event API. It is not a full-LAN sniffer:
in managed Wi-Fi mode the interface only sees traffic to/from itself and
broadcast/multicast traffic.

No third-party Python packages are required.
"""

from __future__ import annotations

import argparse
import json
import os
import socket
import time
import urllib.request
from collections import defaultdict

ETH_P_ALL = 3
ETH_P_IP = 0x0800
IPPROTO_TCP = 6


def tcp_payload(packet: bytes):
    """Return (src, dst, sport, dport, syn, payload) for an Ethernet IPv4/TCP frame."""
    if len(packet) < 34:
        return None
    eth_type = int.from_bytes(packet[12:14], "big")
    if eth_type != ETH_P_IP:
        return None

    ip_start = 14
    version_ihl = packet[ip_start]
    if (version_ihl >> 4) != 4:
        return None
    ip_header_len = (version_ihl & 0x0F) * 4
    if len(packet) < ip_start + ip_header_len + 20:
        return None
    if packet[ip_start + 9] != IPPROTO_TCP:
        return None

    src = socket.inet_ntoa(packet[ip_start + 12:ip_start + 16])
    dst = socket.inet_ntoa(packet[ip_start + 16:ip_start + 20])
    tcp_start = ip_start + ip_header_len
    sport = int.from_bytes(packet[tcp_start:tcp_start + 2], "big")
    dport = int.from_bytes(packet[tcp_start + 2:tcp_start + 4], "big")
    tcp_header_len = (packet[tcp_start + 12] >> 4) * 4
    flags = packet[tcp_start + 13]
    syn = bool(flags & 0x02) and not bool(flags & 0x10)
    payload = packet[tcp_start + tcp_header_len:]
    return src, dst, sport, dport, syn, payload


def post_event(url: str, event: dict) -> None:
    body = json.dumps(event, ensure_ascii=False).encode("utf-8")
    request = urllib.request.Request(
        url,
        data=body,
        method="POST",
        headers={"Content-Type": "application/json; charset=utf-8"},
    )
    try:
        with urllib.request.urlopen(request, timeout=3) as response:
            if response.status >= 300:
                print(f"[!] event POST {response.status}", flush=True)
    except Exception as exc:
        print(f"[!] event POST failed: {exc}", flush=True)


def main() -> None:
    parser = argparse.ArgumentParser(description="UNO Q Sentinel raw packet capture agent")
    parser.add_argument("--iface", default=os.environ.get("CAPTURE_IFACE", "wlan0"))
    parser.add_argument("--target-ip", default=os.environ.get("UNOQ_TARGET_IP", ""))
    parser.add_argument("--event-url", default=os.environ.get("SENTINEL_EVENT_URL", "http://127.0.0.1:7000/event"))
    parser.add_argument("--interval", type=float, default=5.0, help="aggregation window in seconds")
    parser.add_argument("--duration", type=float, default=0, help="stop after N seconds; 0 means forever")
    args = parser.parse_args()
    if not args.target_ip:
        raise SystemExit("--target-ip is required (or set UNOQ_TARGET_IP)")

    sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(ETH_P_ALL))
    sock.bind((args.iface, 0))
    sock.settimeout(1.0)
    print(f"[*] capturing iface={args.iface} target={args.target_ip} -> {args.event_url}", flush=True)

    started = time.time()
    window_start = started
    aggregate = defaultdict(lambda: {"ports": set(), "syns": 0, "http_paths": set(), "ssh": 0, "packets": 0, "bytes": 0, "payload_bytes": 0})

    while True:
        now = time.time()
        if args.duration and now - started >= args.duration:
            break
        try:
            packet = sock.recv(65535)
        except socket.timeout:
            pass
        else:
            parsed = tcp_payload(packet)
            if parsed:
                src, dst, sport, dport, syn, payload = parsed
                if dst == args.target_ip:
                    item = aggregate[src]
                    item["ports"].add(dport)
                    item["packets"] += 1
                    item["bytes"] += len(packet)
                    item["payload_bytes"] += len(payload)
                    if syn:
                        item["syns"] += 1
                    if dport == 2222:
                        item["ssh"] += 1
                    if payload:
                        text = payload.decode("utf-8", errors="replace")
                        first = text.splitlines()[0] if text else ""
                        if first.startswith(("GET ", "POST ", "HEAD ")):
                            parts = first.split()
                            if len(parts) >= 2:
                                item["http_paths"].add((dport, parts[1][:160]))
        if now - window_start >= args.interval:
            for src, item in aggregate.items():
                # Single-port volume telemetry for the flood rule.
                pps = item["packets"] / max(args.interval, 1.0)
                bps = item["bytes"] * 8 / max(args.interval, 1.0)
                top_port = sorted(item["ports"])[0] if item["ports"] else None
                if item["payload_bytes"] >= 8192 or pps >= 50 or item["bytes"] >= 65536:
                    post_event(args.event_url, {
                        "source": src,
                        "service": "pcap",
                        "event": "traffic_flood",
                        "port": top_port,
                        "detail": f"packets={item['packets']} bytes={item['bytes']} ports={len(item['ports'])}",
                        "packets": item["packets"],
                        "bytes": item["bytes"],
                        "payload_bytes": item["payload_bytes"],
                        "pps": round(pps, 1),
                        "bps": round(bps, 1),
                    })
                # one event per touched port lets the app rule engine count unique ports
                for port in sorted(item["ports"])[:40]:
                    post_event(args.event_url, {
                        "source": src,
                        "service": "pcap",
                        "event": "tcp_connect",
                        "port": port,
                        "detail": "raw IPv4/TCP capture",
                    })
                if item["syns"] >= 3:
                    post_event(args.event_url, {
                        "source": src,
                        "service": "pcap",
                        "event": "tcp_port_scan",
                        "detail": f"SYN packets={item['syns']} ports={len(item['ports'])}",
                    })
                for http_port, path in sorted(item["http_paths"], key=lambda item: (item[0], item[1]))[:10]:
                    post_event(args.event_url, {
                        "source": src,
                        "service": "pcap",
                        "event": "http_request",
                        "port": http_port,
                        "path": path,
                        "detail": "raw HTTP request",
                    })
                if item["ssh"]:
                    post_event(args.event_url, {
                        "source": src,
                        "service": "pcap",
                        "event": "ssh_attempt",
                        "port": 2222,
                        "detail": f"ssh_packets={item['ssh']}",
                    })
            aggregate.clear()
            window_start = now
            print(f"[*] flushed window at {time.strftime('%H:%M:%S')}", flush=True)


if __name__ == "__main__":
    main()

