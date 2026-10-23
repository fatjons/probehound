# 📡 ProbeHound (`probehound`)

> **Lightweight, Zero-Disk-Wear 802.11 Probe Request Sniffer & RF Proximity Telemetry Engine for Edge Devices**

[![Rust](https://img.shields.io/badge/rust-2021-orange.svg)](https://www.rust-lang.org)
[![Target](https://img.shields.io/badge/arch-ARMv6%20%7C%20ARMv7%20%7C%20aarch64%20%7C%20x86__64-blue.svg)]()
[![License](https://img.shields.io/badge/license-MIT-green.svg)](LICENSE)

**ProbeHound** turns any low-power Single Board Computer (such as an ultra-constrained Raspberry Pi 1 B+ or Pi Zero) equipped with a monitor-mode Wi-Fi adapter (e.g. Atheros AR9271 / TP-Link TL-WN722N v1) into an always-on, high-resolution Wi-Fi presence and proximity sensor.

It monitors 802.11 broadcast management frames (Probe Requests) emitted by smartphones, laptops, wearables, and IoT appliances, extracting deep RF and physical layer telemetry. All processing and deduplication happens strictly in **RAM** to guarantee **zero disk wear** on flash memory, flushing batched JSON payloads periodically to your cloud webhook or Google Sheets.

---

## ✨ Key Features

- **⚡ Zero Disk Wear (Flash Safe):** No SQLite or local disk logging. In-flight packets are aggregated and deduplicated in RAM and flushed to cloud webhooks in periodic batches (e.g. every 60s).
- **📶 Qualitative Proximity Zones:** Mitigates raw RSSI noise and path-loss disparity by classifying devices into calibrated proximity zones:
  - `Immediate (<3m)`: $\text{RSSI} \ge -50\text{ dBm}$
  - `Near (3-8m)`: $-68\text{ dBm} \le \text{RSSI} < -50\text{ dBm}$
  - `Mid-Range (8-15m)`: $-79\text{ dBm} \le \text{RSSI} < -68\text{ dBm}$
  - `Fringe (>15m)`: $\text{RSSI} < -80\text{ dBm}$
- **🏃 Motion & Velocity Detection:** Analyzes RSSI spread ($\Delta\text{RSSI} = \text{RSSI}_{\max} - \text{RSSI}_{\min}$) over the batch window to distinguish between:
  - `In Motion`: Fast-moving pedestrians or vehicles passing by ($\Delta\text{RSSI} \ge 8\text{ dBm}$).
  - `Stationary`: Stable devices resting on tables or stationary smart home appliances ($\Delta\text{RSSI} < 8\text{ dBm}$).
- **🔍 Deep Information Element (IE) Inspection:**
  - **WPS Device & Model Extraction:** Dissects Microsoft WPS TLVs (`00:50:f2:04`) to recover plaintext Device Names, Model Names, and Manufacturers (e.g., *"Galaxy S21"*, *"HP DeskJet"*, *"Shelly Plus"*).
  - **Wi-Fi Generation Detection:** Identifies `Legacy 802.11b/g`, `Wi-Fi 4 (802.11n)`, `Wi-Fi 5 (802.11ac)`, and `Wi-Fi 6 (802.11ax)`.
  - **MIMO Stream Capabilities:** Detects `2x2 MIMO` vs `1x1 SISO` spatial streams via HT/VHT MCS bitmasks.
  - **Vendor Tagging:** Identifies Apple Continuity (`00:17:f2`), Microsoft (`00:50:f2`), Broadcom (`00:90:4c`), Google (`00:1a:11`), and Espressif IoT tags.
  - **MAC Randomization Flag:** Detects locally administered MAC addresses vs factory OUIs.
  - **Sequence Control Correlation:** Tracks hardware sequence number ranges (`seq_start -> seq_end`) to correlate probe bursts even across randomized addresses.
- **🔄 Channel Hopping:** Built-in lightweight multi-threaded 2.4 GHz channel hopper (Channels 1, 6, 11).
- **🪶 Ultra Lean:** Consumes less than 4 MB of RAM and ~1% CPU on a 700MHz single-core ARMv6 CPU.

---

## 🏗️ Architecture

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
                             |   - WPS Device & Vendor  |
                             |   - Wi-Fi Gen & MIMO     |
                             +--------------------------+
                                          |
                                          v
                             +--------------------------+
                             | In-Memory Deduplication  |
                             | & Motion / Range Window  |
                             +--------------------------+
                                          | (every 60s)
                                          v
                             +--------------------------+
                             | HTTPS Webhook / GSheets  |
                             +--------------------------+
```

---

## 📊 Telemetry Schema

ProbeHound outputs structured JSON batches:

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
      "wifi_gen": "Wi-Fi 6 (802.11ax)",
      "mimo": "2x2 MIMO",
      "channel": 6,
      "count": 7,
      "seq_range": "1042 -> 1049"
    }
  ]
}
```

---

## 🚀 Building & Cross-Compilation

ProbeHound is self-contained with no external C library dependencies (uses pure static musl libc).

### Native Build (x86_64 / Desktop)
```bash
cargo build --release
```

### Cross-Compiling for Raspberry Pi 1 B+ / Pi Zero (ARMv6 musl)
Using Docker:
```bash
docker run --rm -v $(pwd):/app -w /app rust:slim bash -c '
  apt-get update -qq && apt-get install -y gcc-arm-linux-gnueabihf musl-tools
  rustup target add arm-unknown-linux-musleabihf
  RUSTFLAGS="-C target-cpu=arm1176jzf-s -C link-arg=-static" \
  cargo build --release --target arm-unknown-linux-musleabihf
'
```

---

## ⚙️ Deployment & Systemd Service

1. Copy the compiled binary to `/usr/local/bin/probehound`:
   ```bash
   sudo cp target/arm-unknown-linux-musleabihf/release/probehound /usr/local/bin/probehound
   sudo chmod +x /usr/local/bin/probehound
   ```

2. Put your Wi-Fi interface into monitor mode:
   ```bash
   sudo ip link set wlan0 down
   sudo iw dev wlan0 set type monitor
   sudo ip link set wlan0 up
   ```

3. Configure `/etc/systemd/system/probehound.service`:
   ```ini
   [Unit]
   Description=ProbeHound 802.11 Wi-Fi Telemetry Sniffer
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

4. Enable and start:
   ```bash
   sudo systemctl daemon-reload
   sudo systemctl enable --now probehound
   ```

---

## 📄 License
MIT License. Created by [fatjons](https://github.com/fatjons).
