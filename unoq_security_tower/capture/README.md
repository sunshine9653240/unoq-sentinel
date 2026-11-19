# Raw capture helper

The normal App Lab container does not have `CAP_NET_RAW`; this directory
contains the optional privileged packet-capture helper.

It runs on the UNO Q host through Docker, captures **IPv4/TCP traffic addressed
to the UNO Q Wi-Fi address**, aggregates it, and POSTs event summaries to the
Sentinel `/event` API.

```bash
# on the UNO Q Linux host
docker run --rm --network host --user 0 --cap-add NET_RAW \
  -v /home/arduino/ArduinoApps/unoq_security_tower/capture:/capture:ro \
  --entrypoint python \
  ghcr.io/arduino/app-bricks/python-apps-base:0.13.2 \
  /capture/capture_agent.py \
  --iface wlan0 --target-ip <BOARD_IP> \
  --event-url http://127.0.0.1:7000/event
```

Stop it with `Ctrl+C`.

`--target-ip` is the board's Wi-Fi address. The capture helper does **not**
turn UNO Q into a full-LAN IDS; a managed Wi-Fi client only sees traffic
addressed to itself and broadcast/multicast frames. For full-LAN capture, use a
mirrored switch port, router flow export, or a monitor-mode adapter.

