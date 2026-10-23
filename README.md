# ProbeHound (`probehound`)

> **Near-zero resource, bounded-memory 802.11 soft perimeter monitor for homelabs and edge devices**

[![Rust](https://img.shields.io/badge/rust-2021-orange.svg)](https://www.rust-lang.org)
[![Target](https://img.shields.io/badge/arch-ARMv6%20%7C%20ARMv7%20%7C%20aarch64%20%7C%20x86__64-blue.svg)](https://github.com/fatjons/probehound)
[![License](https://img.shields.io/badge/license-MIT-green.svg)](LICENSE)

ProbeHound is a lightweight background daemon designed for homelabs and edge nodes (such as a Raspberry Pi 1 B+, Pi Zero, or thin client) equipped with a monitor-mode Wi-Fi dongle. It acts as a passive **soft perimeter monitor**, capturing 802.11 probe requests broadcast by smartphones, wearables, vehicles, and smart devices in the vicinity.

### Core Design Principles
1. **Near-Zero Resource & Zero Maintenance:** Runs as a small statically linked binary (~3 MB RAM, negligible CPU) with quiet default logging (`DEBUG_PROBES=0`) to avoid journald write amplification.
2. **Bounded In-Memory Operation:** No local SQLite or write-heavy disk databases. Frame inspection, per-channel aggregation (`MAC + SSID + Channel`), and retry queueing occur strictly in bounded RAM (`MAX_ACTIVE_RECORDS = 1024`, `MAX_QUEUED_BATCHES = 15`).
3. **Decoupled Offline Analysis:** Telemetry is periodically flushed in bounded batches to a cloud webhook (such as Google Sheets) with HTTP timeouts and automatic retry queueing on transient network failures.

---

## Core Capabilities

- **Strict Radiotap & FCS Validation:**
  - Parses Radiotap headers strictly according to field alignment rules without guessing bytes; reports `None` (`Unknown RSSI`) if the antenna signal bit is absent.
  - Rejects frames marked with `BADFCS` (`0x40`) and strips trailing 4-byte `FCS` (`0x10`) prior to Information Element parsing so frame checksums never pollute IE tags.
- **Per-Channel Signal Bands & Spread:**
  - Aggregates observations per `(MAC, SSID, Channel)` tuple so cross-channel antenna variations do not distort signal metrics:
    - `Strong (>= -50 dBm)`
    - `Moderate (-51..-68 dBm)`
    - `Weak (-69..-79 dBm)`
    - `Very Weak (<= -80 dBm)`
  - Computes intra-window **RSSI Spread** ($\text{RSSI}_{\max} - \text{RSSI}_{\min}$):
    - `High Spread (>=8 dB)`: Significant signal variation during the window.
    - `Low Spread (<8 dB)`: Stable signal level.
    - `Single Probe`: Single observation in the window.
- **Capability Pattern Fingerprint (`fp_hash`):**
  - Computes an 8-character FNV-1a hash over the ordered IE tag sequence, Supported/Extended Rates (Tags 1, 50), HT/VHT capability headers (Tags 45, 191), Extended Capabilities (Tag 127), Extension IDs (Tag 255), and Vendor OUIs (Tag 221).
  - Represents a device's driver/OS capability profile, helping correlate recurring capability classes across randomized MAC addresses.
- **Deep Information Element (IE) Inspection:**
  - **Probe Type:** Distinguishes `Directed` (explicit target SSID) vs `Broadcast` (wildcard scan).
  - **Protocol & Roaming Capabilities:** Detects `802.11k` (RM, Tag 70), `802.11u` (Interworking, Tag 107), `802.11v` (BSS Transition, Tag 127), `UTF8-SSID`, and `WPS`.
  - **WPS Device & Model Discovery:** Parses Microsoft WPS TLVs (`00:50:f2:04`) to extract plaintext device names, models, and manufacturers.
  - **Wi-Fi Generation & Spatial Streams:** Identifies `Legacy 802.11b/g`, `Wi-Fi 4 (802.11n)`, `Wi-Fi 5 (802.11ac)`, and `Wi-Fi 6 (802.11ax)`, and decodes both HT RX MCS bitmasks and VHT RX MCS maps for `2x2 MIMO` vs `1x1 SISO`.

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
                             |   - Strict RSSI & FCS    |
                             |   - Capability Hash      |
                             |   - 802.11k/u/v & WPS    |
                             |   - HT/VHT MIMO Decode   |
                             +--------------------------+
                                          |
                                          v
                             +--------------------------+
                             | Bounded In-Memory Map    |
                             | & Retry Batch Queue      |
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
      "proximity": "Moderate (-51..-68 dBm)",
      "motion": "High Spread (>=8 dB)",
      "rssi": -60,
      "rssi_peak": -60,
      "rssi_avg": -66,
      "rssi_min": -72,
      "ssid": "<Broadcast>",
      "vendor": "Apple",
      "device_state": "Broadcast",
      "wifi_gen": "Wi-Fi 6 (802.11ax)",
      "mimo": "2x2 MIMO",
      "security": "802.11k/802.11v",
      "fp_hash": "a4f81c9e",
      "channel": 6,
      "count": 7,
      "seq_range": "1042 -> 1049"
    }
  ]
}
```

---

## Building, Testing, and Deployment

### Run Unit Tests
```bash
cargo test
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

---

## License

MIT License. Developed by [fatjons](https://github.com/fatjons).
