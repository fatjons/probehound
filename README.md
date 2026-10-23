# ProbeHound (`probehound`)

> **Near-zero resource, zero-maintenance 802.11 soft perimeter monitor for homelabs and edge devices**

[![Rust](https://img.shields.io/badge/rust-2021-orange.svg)](https://www.rust-lang.org)
[![Target](https://img.shields.io/badge/arch-ARMv6%20%7C%20ARMv7%20%7C%20aarch64%20%7C%20x86__64-blue.svg)](https://github.com/fatjons/probehound)
[![License](https://img.shields.io/badge/license-MIT-green.svg)](LICENSE)

ProbeHound is a lightweight background daemon designed for homelabs and edge nodes (such as a Raspberry Pi 1 B+, Pi Zero, or thin client) equipped with a monitor-mode Wi-Fi dongle. It acts as a passive **soft perimeter monitor**, capturing 802.11 probe requests broadcast by smartphones, wearables, vehicles, and smart devices in the vicinity.

The core philosophy of ProbeHound:
1. **Near-Zero Resource & Zero Maintenance:** Runs as an ultra-lean compiled binary (~3 MB RAM, negligible CPU) that can run indefinitely in the background without attention or database administration.
2. **Zero Disk Wear (Flash Safe):** No local SQLite or write-heavy databases. All frame inspection, deduplication, and windowing occur strictly in RAM, preventing flash/SD card wear on edge hardware.
3. **Decoupled Offline Analysis:** Telemetry is periodically flushed in batches directly to a cloud webhook (such as Google Sheets). You can filter, graph, and analyze perimeter activity offline at any time without consuming homelab CPU or storage.

---

## Core Capabilities

- **Qualitative Proximity Zones:** Mitigates raw RSSI noise and device transmit power differences by categorizing signals into calibrated proximity zones:
  - `Immediate (<3m)`: Peak RSSI >= -50 dBm (same room or immediate perimeter)
  - `Near (3-8m)`: -68 dBm <= Peak RSSI < -50 dBm (adjacent room or driveway)
  - `Mid-Range (8-15m)`: -79 dBm <= Peak RSSI < -68 dBm (curbside or garden)
  - `Fringe (>15m)`: Peak RSSI < -80 dBm (passersby or distant devices)
- **Motion & Velocity Dynamics:** Compares maximum and minimum signal strength over the batch interval to detect whether a device is moving past or stationary:
  - `In Motion`: Delta RSSI >= 8 dBm (pedestrians, cyclists, vehicles)
  - `Stationary`: Delta RSSI < 8 dBm (stationary electronics, parked devices)
  - `Single Probe`: Isolated burst
- **Device Fingerprint Hash ("Wi-Fi JA3"):** Computes an invariant 8-character FNV-1a hash of the device's ordered Information Elements and vendor tags. Allows linking and tracking the same physical device over multiple days or weeks despite MAC randomization.
- **Apple & Device Screen State:** Identifies Apple Continuity / AirPort state flags inside `00:17:f2` to distinguish between `Screen On / Active` (user actively interacting with phone) versus `Screen Off / Sleep` (locked in pocket).
- **Security & Roaming Capabilities:** Dissects IE 127 (Extended Capabilities) to extract `WPA3`, `PMF` (Protected Management Frames - 802.11w), and `802.11v` (BSS Transition).
- **Deep Information Element (IE) Inspection:**
  - **WPS Device & Model Discovery:** Parses Microsoft WPS TLVs (`00:50:f2:04`) to extract plaintext device names, models, and manufacturers (e.g. *"Galaxy S21"*, *"HP DeskJet"*, *"Shelly Plus"*).
  - **Wi-Fi Generation Detection:** Identifies `Legacy 802.11b/g`, `Wi-Fi 4 (802.11n)`, `Wi-Fi 5 (802.11ac)`, and `Wi-Fi 6 (802.11ax)`.
  - **Spatial Streams (MIMO):** Detects `2x2 MIMO` vs `1x1 SISO` support via HT/VHT MCS bitmasks.
  - **Vendor Tagging:** Identifies Apple Continuity (`00:17:f2`), Microsoft (`00:50:f2`), Broadcom (`00:90:4c`), Google (`00:1a:11`), and Espressif IoT tags.
  - **MAC Type Detection:** Flags randomized/private MAC addresses versus factory hardware OUIs.
  - **Sequence Control Correlation:** Tracks hardware sequence number ranges (`seq_start -> seq_end`) to correlate probe bursts across randomized MAC addresses.
- **Built-in Channel Hopper:** Rotates across the primary 2.4 GHz channels (1, 6, 11) using low-overhead timer intervals.

---

## Architecture

```
                       +---------------------------------------+
                       |   Raw 802.11 Probe Request Frames    |
                       +---------------------------------------+
                                          |
                                          v
+------------------+         +--------------------------+
|  Channel Hopper  | ------> |  Linux AF_PACKET Socket  |
|  (Ch 1, 6, 11)   |         +--------------------------+
+------------------+                      |
                                          v
                             +--------------------------+
                             |   Radiotap / IE Parser   |
                             |   - RSSI & Channel       |
                             |   - Fingerprint Hash     |
                             |   - Apple Screen State   |
                             |   - WPA3 / PMF / 802.11v |
                             |   - WPS Device & Vendor  |
                             |   - Wi-Fi Gen & MIMO     |
                             +--------------------------+
                                          |
                                          v
                             +--------------------------+
                             | In-Memory Ring Buffer    |
                             | Deduplication & Motion   |
                             +--------------------------+
                                          | (every 60s)
                                          v
                             +--------------------------+
                             | Webhook (Google Sheets)  |
                             |   for Offline Analysis   |
                             +--------------------------+
```

---

## Telemetry Payload Schema

ProbeHound pushes batched JSON arrays to your webhook endpoint:

```json
{
  "token": "SECRET_TOKEN",
  "type": "probes",
  "items": [
    {
      "time": "1792793716",
      "mac": "da:a1:19:34:56:78",
      "mac_type": "Randomized",
      "is_random": true,
      "proximity": "Near (3-8m)",
      "motion": "In Motion",
      "rssi": -62,
      "rssi_peak": -62,
      "rssi_avg": -66,
      "rssi_min": -72,
      "ssid": "<Broadcast>",
      "vendor": "Apple iOS / macOS",
      "device_state": "Screen On / Active",
      "wifi_gen": "Wi-Fi 6 (802.11ax)",
      "mimo": "2x2 MIMO",
      "security": "WPA3/PMF/802.11v",
      "fp_hash": "a4f81c9e",
      "channel": 6,
      "count": 7,
      "seq_range": "1042 -> 1049"
    }
  ]
}
```

---

## Building and Deployment

ProbeHound has zero runtime external library dependencies. It links statically with musl libc.

### Native Build (x86_64)
```bash
cargo build --release
```

### Cross-Compilation for ARMv6 (Raspberry Pi 1 B+, Pi Zero)
Using Docker:
```bash
docker run --rm -v $(pwd):/app -w /app rust:slim bash -c '
  apt-get update -qq && apt-get install -y gcc-arm-linux-gnueabihf musl-tools
  rustup target add arm-unknown-linux-musleabihf
  RUSTFLAGS="-C target-cpu=arm1176jzf-s -C link-arg=-static" \
  cargo build --release --target arm-unknown-linux-musleabihf
'
```

### Systemd Service Setup

1. Copy the static binary:
   ```bash
   sudo cp target/arm-unknown-linux-musleabihf/release/probehound /usr/local/bin/probehound
   sudo chmod +x /usr/local/bin/probehound
   ```

2. Enable monitor mode on your adapter:
   ```bash
   sudo ip link set wlan0 down
   sudo iw dev wlan0 set type monitor
   sudo ip link set wlan0 up
   ```

3. Create `/etc/systemd/system/probehound.service`:
   ```ini
   [Unit]
   Description=ProbeHound 802.11 Soft Perimeter Monitor
   After=network.target

   [Service]
   Type=simple
   ExecStart=/usr/local/bin/probehound
   Restart=always
   RestartSec=5
   Environment=SNIFFER_IFACE=wlan0

   [Install]
   WantedBy=multi-user.target
   ```

4. Start and enable:
   ```bash
   sudo systemctl daemon-reload
   sudo systemctl enable --now probehound
   ```

---

## Offline Analysis in Google Sheets

By piping raw batches into Google Sheets via Google Apps Script, you decouple capture from analysis:
- Correlate visitors using `fp_hash` across randomized MAC addresses.
- Distinguish active smartphone use (`Screen On / Active`) from passive devices in pockets or cars.
- Filter for WPA3 / PMF capable devices versus legacy IoT devices.
- Query historical presence without querying local homelab hardware or spinning up database containers.

---

## License

MIT License. Developed by [fatjons](https://github.com/fatjons).
