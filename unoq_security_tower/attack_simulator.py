#!/usr/bin/env python3
"""Generate real test traffic for UNO Q Sentinel.

Lab-only traffic generator. It connects to the honeypot ports exposed by the
UNO Q app. It does not exploit anything and must only be used on a network you
own or are authorized to test.

Usage:
    python attack_simulator.py --host <BOARD_IP>
"""

import argparse
import os
import socket
import time

PORTS = [2222, 2323, 8081, 9000, 9001, 9002, 9003, 9004]
HTTP_PATHS = ["/wp-login.php", "/.env", "/phpmyadmin/", "/../../etc/passwd", "/admin"]


def send_bytes(host: str, port: int, payload: bytes, timeout: float = 1.0) -> bool:
    try:
        with socket.create_connection((host, port), timeout=timeout) as sock:
            sock.settimeout(0.6)
            try:
                sock.recv(128)
            except (socket.timeout, ConnectionResetError):
                pass
            sock.sendall(payload)
        return True
    except (ConnectionAbortedError, ConnectionResetError, BrokenPipeError):
        # The honeypot may close immediately after recording the event.
        return True
    except Exception as exc:
        print(f"    {host}:{port} -> {type(exc).__name__}: {exc}")
        return False


def main() -> None:
    parser = argparse.ArgumentParser(description="UNO Q Sentinel lab traffic generator")
    parser.add_argument("--host", default=os.environ.get("UNOQ_BOARD_IP", "127.0.0.1"), help="UNO Q IP address (or set UNOQ_BOARD_IP)")
    parser.add_argument("--rounds", type=int, default=1, help="number of port-scan rounds")
    parser.add_argument("--delay", type=float, default=0.12, help="delay between connections")
    args = parser.parse_args()

    print(f"[*] target: {args.host}")
    print("[*] only use this on a network you own or are authorized to test.")
    for round_no in range(1, args.rounds + 1):
        print(f"[*] round {round_no}/{args.rounds}")
        for port in PORTS:
            if port == 8081:
                continue
            ok = send_bytes(args.host, port, b"UNOQ sentinel lab probe\r\n")
            if ok:
                print(f"    {args.host}:{port} -> sent")
            time.sleep(args.delay)

        for path in HTTP_PATHS:
            request = (
                f"GET {path} HTTP/1.1\r\n"
                f"Host: {args.host}\r\n"
                "User-Agent: UNOQ-Sentinel-Test/1.0\r\n"
                "Connection: close\r\n\r\n"
            ).encode()
            if send_bytes(args.host, 8081, request):
                print(f"    {args.host}:8081 {path} -> sent")
            time.sleep(0.08)

        for _ in range(3):
            if send_bytes(args.host, 2222, b"admin:test-only-no-real-password\r\n"):
                print(f"    {args.host}:2222 ssh attempt -> sent")
            time.sleep(0.08)
    print("[+] done; check the UNO Q Sentinel dashboard.")


if __name__ == "__main__":
    main()

