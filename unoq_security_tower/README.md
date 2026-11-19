# UNO Q Sentinel

AI-assisted honeypot and physical network alert node for **Arduino UNO Q**.

It runs a local small language model on the UNO Q, exposes a small set of
decoy services, classifies suspicious connection events with a rule engine,
shows the threat level on the 8x13 LED matrix, and sends a phone push through
**ntfy** when the risk becomes high.

> This is not a full-network IDS and not a Wireshark replacement. It is a
> honeypot/event sensor for traffic that reaches the UNO Q node, plus an
> optional event-ingest API for router/Syslog/agent events.

## Features

- On-device **Qwen3.5 0.8B** LLM analysis through the Arduino `arduino:llm` Brick
- Honeypot decoy services on ports `2222`, `2323`, `8081`, `9000`–`9004`
- Rule-based detection:
  - port scanning
  - repeated SSH/Telnet attempts
  - malicious HTTP paths
  - short-window connection floods
- LED matrix threat states:
  - green: normal
  - yellow: suspicious
  - red: high risk
- Web dashboard with live event stream, risk score, and LLM summary
- LLM analysis is triggered for both MEDIUM and HIGH risk
- Rule engine result is shown immediately; LLM adds a slower narrative summary
- `POST /event` ingestion endpoint for router/Syslog/flow agents
- Optional privileged IPv4/TCP capture sidecar (`capture/`)
- ntfy phone subscription and high-priority push notifications
- PC-side lab traffic simulator

## Architecture

```text
attacker / lab simulator
        │
        ├──► honeypot listeners (TCP / HTTP)
        └──► optional privileged capture sidecar (IPv4/TCP)
                     │
                     ▼
UNO Q Linux
  ├─ event queue + rule engine
  ├─ Qwen3.5 0.8B analyst
  ├─ WebUI / WebSocket dashboard
  ├─ ntfy push
  └─ Bridge/RPC
          │
          ▼
     STM32 MCU → 8×13 LED matrix
```

The LLM is deliberately not used as a packet parser. The rule engine does the
fast detection; the LLM only explains a batch of already-detected events.
That keeps detection predictable and keeps the phone alert path fast.

## Run on UNO Q

1. Copy this folder to the board, for example:

```bash
scp -r unoq_security_tower arduino@<board-ip>:/home/arduino/ArduinoApps/
```

2. Start the App Lab app:

```bash
arduino-app-cli app start /home/arduino/ArduinoApps/unoq_security_tower
```

The first launch downloads the small LLM model (about 507 MB). It can take a
while. The App Lab `arduino:llm` Brick chooses the UNO Q default model
(`llamacpp:Qwen3.5-0.8B-Q4_0`).

3. Forward the WebUI port when connected over USB:

```bash
adb -s <BOARD_SERIAL> forward tcp:17000 tcp:7000
```

Open:

```text
http://127.0.0.1:17000/
```

## Phone subscription with ntfy

The default topic is:

```text
unoq-sentinel-7f4c2d91
```

1. Install **ntfy** on the phone (Android / iOS).
2. Subscribe to the same topic.
3. Open the dashboard and press **測試推播**.
4. When the rule engine reaches HIGH risk, UNO Q POSTs a high-priority message
   to `https://ntfy.sh/<topic>`.

Change the topic with the `NTFY_TOPIC` environment variable before starting the
app. Use a long random topic if the board is reachable from an untrusted
network. For a private deployment, point `NTFY_SERVER` at a self-hosted ntfy
instance.

If ntfy is unavailable, the dashboard still receives live WebSocket events.
The in-page stream is not a substitute for push: it only works while the page is
open.

## Demo attack

On a PC connected to the same LAN:

```bash
python attack_simulator.py --host <BOARD_IP>
```

Or use the dashboard buttons:

- **模擬中風險**：only touches three decoy ports, producing a MEDIUM state and
  triggering the on-device LLM analysis.
- **模擬高風險**：touches all decoy ports plus malicious HTTP paths and SSH
  attempts, producing a HIGH state and a phone notification (subject to the
  one-minute notification cooldown).
- **模擬單端口洪水**：sends a large junk payload to one decoy port and should
  produce a HIGH state through the `data_flood` rule.
- **自訂測試組合**：choose any combination of ports, connections per port,
  payload size in KB, delay, and optional malicious HTTP path.

The buttons create real local TCP/HTTP connections to the honeypot listeners;
they do not inject fake dashboard data.

Custom test API:

```bash
curl -X POST http://<board-ip>:7000/api/simulate-custom \
  -H 'Content-Type: application/json' \
  -d '{
    "ports": [9000, 9001, 9002],
    "connections": 1,
    "payload_bytes": 0,
    "delay_ms": 80,
    "malicious_http": false
  }'
```

The API clamps inputs and only accepts the exposed decoy ports.

Only run the simulator against your own board or a network you are authorized to
test.

## Detect / ingest external events

A router, Syslog adapter, or capture agent can POST event summaries:

```bash
curl -X POST http://<board-ip>:7000/event \
  -H 'Content-Type: application/json' \
  -d '{"source":"192.168.0.25","service":"router","event":"port_scan","port":22,"detail":"blocked by firewall"}'
```

This is the upgrade path to a small **security event aggregator**: keep the
capture/collection where it belongs, and let UNO Q handle correlation, LLM
summary, LED state, and phone alerts.

## Optional raw IPv4/TCP capture

The normal App Lab container does not have `CAP_NET_RAW`. The helper in
`capture/capture_agent.py` runs on the UNO Q host in a small privileged Docker
container, captures IPv4/TCP packets addressed to the board, and POSTs event
summaries into the same rule engine:

```bash
sh capture/run_capture.sh <BOARD_IP>
```

Or run the container directly:

```bash
docker run --rm --network host --user 0 --cap-add NET_RAW \
  -v /home/arduino/ArduinoApps/unoq_security_tower/capture:/capture:ro \
  --entrypoint python \
  ghcr.io/arduino/app-bricks/python-apps-base:0.13.2 \
  /capture/capture_agent.py \
  --iface wlan0 --target-ip <BOARD_IP> \
  --event-url http://127.0.0.1:7000/event
```

It does **not** see every unicast packet on the subnet; in managed Wi-Fi mode it
only sees traffic to/from the board and broadcast/multicast traffic. Use the
router/Syslog ingestion path when full-network visibility is required.

## Scope and limits

- A Wi-Fi client cannot see all unicast traffic between other LAN clients.
- Raw packet capture needs `CAP_NET_RAW`/root and, for full-LAN capture, a
  mirrored switch port or a monitor-mode adapter.
- This app listens for traffic **addressed to UNO Q** and for events sent to its
  ingest API. Do not describe it as a full-network IDS.
- The LLM summary is advisory. The deterministic rule result controls the alert.
- Do not expose the honeypot or ntfy topic to an untrusted public network
  without isolating and hardening the deployment.

## Files

```text
app.yaml                 App Lab app and exposed honeypot ports
python/main.py           honeypot, rules, LLM, API, LED, ntfy
assets/                  dashboard UI
sketch/sketch.ino        Bridge/RPC LED matrix driver
attack_simulator.py      lab traffic generator
capture/                 optional privileged IPv4/TCP capture helper
```

