use std::collections::HashMap;
use std::env;
use std::fs;
use std::process::Command;
use std::sync::atomic::{AtomicU8, Ordering};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use serde::Serialize;

static CURRENT_CHANNEL: AtomicU8 = AtomicU8::new(1);

#[derive(Clone, Debug)]
struct RawProbeRecord {
    time: String,
    mac: String,
    mac_type: String,
    is_random: bool,
    ssid: String,
    vendor: String,
    wifi_gen: String,
    mimo: String,
    channel: u8,
    peak_rssi: i8,
    min_rssi: i8,
    rssi_sum: i32,
    count: u32,
    seq_start: u16,
    seq_end: u16,
}

#[derive(Serialize, Clone, Debug)]
struct EnrichedProbe {
    time: String,
    mac: String,
    mac_type: String,
    is_random: bool,
    proximity: String,
    motion: String,
    rssi: i8,
    rssi_peak: i8,
    rssi_avg: i8,
    rssi_min: i8,
    ssid: String,
    vendor: String,
    wifi_gen: String,
    mimo: String,
    channel: u8,
    count: u32,
    seq_range: String,
}

#[derive(Serialize)]
struct BatchPayload {
    token: String,
    #[serde(rename = "type")]
    msg_type: String,
    items: Vec<EnrichedProbe>,
}

fn format_mac(mac: &[u8; 6]) -> String {
    format!(
        "{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
        mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]
    )
}

fn get_timestamp() -> String {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    format!("{}", now)
}

/// Parses Radiotap header to extract (RSSI dBm, Channel/Frequency, header_len)
fn parse_radiotap(buf: &[u8]) -> Option<(i8, u8, usize)> {
    if buf.len() < 8 || buf[0] != 0 {
        return None;
    }
    let header_len = u16::from_le_bytes([buf[2], buf[3]]) as usize;
    if buf.len() < header_len {
        return None;
    }

    let mut present_words = Vec::new();
    let mut offset = 4;
    while offset + 4 <= header_len {
        let flags = u32::from_le_bytes([buf[offset], buf[offset + 1], buf[offset + 2], buf[offset + 3]]);
        present_words.push(flags);
        offset += 4;
        if (flags & (1 << 31)) == 0 {
            break;
        }
    }

    if present_words.is_empty() {
        return None;
    }

    let flags = present_words[0];
    let mut data_offset = offset;

    // Follow Radiotap fields order according to spec:
    // Bit 0: TSFT (8 bytes, 8-align)
    if (flags & (1 << 0)) != 0 {
        data_offset = (data_offset + 7) & !7;
        data_offset += 8;
    }
    // Bit 1: Flags (1 byte)
    if (flags & (1 << 1)) != 0 {
        data_offset += 1;
    }
    // Bit 2: Rate (1 byte)
    if (flags & (1 << 2)) != 0 {
        data_offset += 1;
    }

    // Bit 3: Channel (4 bytes, 2-align: u16 freq_mhz, u16 flags)
    let mut channel: u8 = 0;
    if (flags & (1 << 3)) != 0 {
        data_offset = (data_offset + 1) & !1;
        if data_offset + 2 <= header_len {
            let freq = u16::from_le_bytes([buf[data_offset], buf[data_offset + 1]]);
            channel = if freq >= 2412 && freq <= 2472 {
                ((freq - 2407) / 5) as u8
            } else if freq == 2484 {
                14
            } else if freq >= 5180 && freq <= 5825 {
                ((freq - 5000) / 5) as u8
            } else {
                0
            };
        }
        data_offset += 4;
    }

    // Bit 4: FHSS (2 bytes)
    if (flags & (1 << 4)) != 0 {
        data_offset += 2;
    }

    // Bit 5: dBm Antenna Signal (1 byte signed int)
    let mut rssi = -100i8;
    if (flags & (1 << 5)) != 0 {
        if data_offset < header_len {
            rssi = buf[data_offset] as i8;
        }
    }

    // Fallback search if radiotap alignment differed
    if rssi == -100 || rssi >= 0 {
        for b in &buf[8..header_len] {
            let val = *b as i8;
            if val <= -20 && val >= -95 {
                rssi = val;
                break;
            }
        }
    }

    if channel == 0 {
        channel = CURRENT_CHANNEL.load(Ordering::Relaxed);
    }

    Some((rssi, channel, header_len))
}

/// Parses WPS (Wi-Fi Protected Setup) sub-TLVs inside Vendor IE (00:50:f2:04)
fn parse_wps_vendor(tag_data: &[u8]) -> Option<String> {
    if tag_data.len() < 4 {
        return None;
    }
    let mut sub_offset = 4; // Skip OUI (3 bytes) and OUI Type (1 byte)
    let mut dev_name: Option<String> = None;
    let mut model_name: Option<String> = None;
    let mut manufacturer: Option<String> = None;

    while sub_offset + 4 <= tag_data.len() {
        let attr_type = u16::from_be_bytes([tag_data[sub_offset], tag_data[sub_offset + 1]]);
        let attr_len = u16::from_be_bytes([tag_data[sub_offset + 2], tag_data[sub_offset + 3]]) as usize;
        sub_offset += 4;

        if sub_offset + attr_len > tag_data.len() {
            break;
        }

        let val_bytes = &tag_data[sub_offset..sub_offset + attr_len];
        match attr_type {
            0x1011 => {
                // Device Name
                if let Ok(s) = std::str::from_utf8(val_bytes) {
                    let trimmed = s.trim().trim_matches('\0');
                    if !trimmed.is_empty() {
                        dev_name = Some(trimmed.to_string());
                    }
                }
            }
            0x1021 => {
                // Manufacturer
                if let Ok(s) = std::str::from_utf8(val_bytes) {
                    let trimmed = s.trim().trim_matches('\0');
                    if !trimmed.is_empty() {
                        manufacturer = Some(trimmed.to_string());
                    }
                }
            }
            0x1023 => {
                // Model Name
                if let Ok(s) = std::str::from_utf8(val_bytes) {
                    let trimmed = s.trim().trim_matches('\0');
                    if !trimmed.is_empty() {
                        model_name = Some(trimmed.to_string());
                    }
                }
            }
            _ => {}
        }

        sub_offset += attr_len;
    }

    if let Some(dev) = dev_name {
        if let Some(mfg) = manufacturer {
            Some(format!("{} ({})", dev, mfg))
        } else {
            Some(dev)
        }
    } else if let Some(model) = model_name {
        if let Some(mfg) = manufacturer {
            Some(format!("{} ({})", model, mfg))
        } else {
            Some(model)
        }
    } else {
        manufacturer
    }
}

/// Parses 802.11 Probe Request Frame & Information Elements
fn parse_probe_frame(buf: &[u8], radiotap_len: usize, rssi: i8, channel: u8) -> Option<(RawProbeRecord, String)> {
    let frame = &buf[radiotap_len..];
    if frame.len() < 24 {
        return None;
    }

    // Byte 0: Frame Control. Management = 0, Subtype = 4 -> 0x40
    if frame[0] != 0x40 {
        return None;
    }

    // Sequence control: bytes 22..24 (12-bit sequence number)
    let seq_ctrl = u16::from_le_bytes([frame[22], frame[23]]);
    let seq_num = seq_ctrl >> 4;

    // Address 2 (Transmitter MAC): bytes 10..16
    let mut mac = [0u8; 6];
    mac.copy_from_slice(&frame[10..16]);
    let mac_str = format_mac(&mac);

    let is_random = (mac[0] & 0x02) != 0;
    let mac_type = if is_random {
        "Randomized".to_string()
    } else {
        "Factory OUI".to_string()
    };

    // Tagged Parameters (IEs) start at offset 24
    let mut offset = 24;
    let mut ssid = "<Broadcast>".to_string();
    let mut has_ht = false;
    let mut has_vht = false;
    let mut has_he = false;
    let mut vendor = "Generic / Hidden".to_string();
    let mut mimo = "1x1 SISO".to_string();

    while offset + 2 <= frame.len() {
        let tag_num = frame[offset];
        let tag_len = frame[offset + 1] as usize;
        offset += 2;

        if offset + tag_len > frame.len() {
            break;
        }

        let tag_data = &frame[offset..offset + tag_len];

        match tag_num {
            0 => {
                // SSID
                if tag_len > 0 {
                    if let Ok(s) = std::str::from_utf8(tag_data) {
                        let clean: String = s.chars().filter(|c| !c.is_control() && *c != '\0').collect();
                        if !clean.is_empty() {
                            ssid = clean;
                        }
                    }
                }
            }
            45 => {
                // HT Capabilities (Wi-Fi 4)
                has_ht = true;
                if tag_data.len() >= 5 {
                    // RX MCS bitmask (bytes 3..4): MCS 8-15 indicates 2 spatial streams
                    if tag_data[3] != 0 && tag_data[4] != 0 {
                        mimo = "2x2 MIMO".to_string();
                    }
                }
            }
            191 => {
                // VHT Capabilities (Wi-Fi 5)
                has_vht = true;
            }
            255 => {
                // Extension elements (Wi-Fi 6 / HE is under Ext ID 35)
                if tag_len > 0 && tag_data[0] == 35 {
                    has_he = true;
                }
            }
            221 => {
                // Vendor Specific IE
                if tag_data.len() >= 4 && tag_data[0..4] == [0x00, 0x50, 0xf2, 0x04] {
                    // Microsoft WPS Element
                    if let Some(wps_name) = parse_wps_vendor(tag_data) {
                        vendor = wps_name;
                    } else if vendor == "Generic / Hidden" {
                        vendor = "Microsoft WPS".to_string();
                    }
                } else if tag_data.len() >= 3 {
                    let oui = &tag_data[0..3];
                    if oui == [0x00, 0x17, 0xf2] {
                        if vendor == "Generic / Hidden" {
                            vendor = "Apple iOS / macOS".to_string();
                        }
                    } else if oui == [0x00, 0x50, 0xf2] {
                        if vendor == "Generic / Hidden" {
                            vendor = "Microsoft".to_string();
                        }
                    } else if oui == [0x00, 0x90, 0x4c] {
                        if vendor == "Generic / Hidden" {
                            vendor = "Broadcom".to_string();
                        }
                    } else if oui == [0x00, 0x1a, 0x11] {
                        if vendor == "Generic / Hidden" {
                            vendor = "Google".to_string();
                        }
                    } else if oui == [0x08, 0x00, 0x27] {
                        if vendor == "Generic / Hidden" {
                            vendor = "Espressif / IoT".to_string();
                        }
                    }
                }
            }
            _ => {}
        }

        offset += tag_len;
    }

    let wifi_gen = if has_he {
        "Wi-Fi 6 (802.11ax)"
    } else if has_vht {
        "Wi-Fi 5 (802.11ac)"
    } else if has_ht {
        "Wi-Fi 4 (802.11n)"
    } else {
        "Legacy 802.11b/g"
    }
    .to_string();

    let dedup_key = format!("{}-{}", mac_str, ssid);
    let record = RawProbeRecord {
        time: get_timestamp(),
        mac: mac_str,
        mac_type,
        is_random,
        ssid,
        vendor,
        wifi_gen,
        mimo,
        channel,
        peak_rssi: rssi,
        min_rssi: rssi,
        rssi_sum: rssi as i32,
        count: 1,
        seq_start: seq_num,
        seq_end: seq_num,
    };

    Some((record, dedup_key))
}

fn finalize_record(raw: RawProbeRecord) -> EnrichedProbe {
    let avg_rssi = (raw.rssi_sum / raw.count as i32) as i8;

    // Proximity Zone classification based on Peak RSSI
    let proximity = if raw.peak_rssi >= -50 {
        "Immediate (<3m)".to_string()
    } else if raw.peak_rssi >= -68 {
        "Near (3-8m)".to_string()
    } else if raw.peak_rssi >= -79 {
        "Mid-Range (8-15m)".to_string()
    } else {
        "Fringe (>15m)".to_string()
    };

    // Motion State based on RSSI spread during window
    let rssi_delta = (raw.peak_rssi - raw.min_rssi).abs();
    let motion = if raw.count == 1 {
        "Single Probe".to_string()
    } else if rssi_delta >= 8 {
        "In Motion".to_string()
    } else {
        "Stationary".to_string()
    };

    let seq_range = if raw.count == 1 {
        format!("{}", raw.seq_start)
    } else {
        format!("{} -> {}", raw.seq_start, raw.seq_end)
    };

    EnrichedProbe {
        time: raw.time,
        mac: raw.mac,
        mac_type: raw.mac_type,
        is_random: raw.is_random,
        proximity,
        motion,
        rssi: raw.peak_rssi,
        rssi_peak: raw.peak_rssi,
        rssi_avg: avg_rssi,
        rssi_min: raw.min_rssi,
        ssid: raw.ssid,
        vendor: raw.vendor,
        wifi_gen: raw.wifi_gen,
        mimo: raw.mimo,
        channel: raw.channel,
        count: raw.count,
        seq_range,
    }
}

fn main() {
    println!("========================================================");
    println!("     ProbeHound v0.2.0 - 802.11 Probe Telemetry Engine   ");
    println!("========================================================");

    // Read config
    let mut webapp_url = env::var("WEBAPP_URL").unwrap_or_default();
    let mut secret_token = env::var("SECRET_TOKEN").unwrap_or_default();

    if let Ok(content) = fs::read_to_string("/etc/speedtest-tracker.conf") {
        for line in content.lines() {
            let line = line.trim();
            if let Some(val) = line.strip_prefix("export WEBAPP_URL=") {
                webapp_url = val.trim_matches('"').to_string();
            } else if let Some(val) = line.strip_prefix("export SECRET_TOKEN=") {
                secret_token = val.trim_matches('"').to_string();
            }
        }
    }

    let iface = env::var("SNIFFER_IFACE").unwrap_or_else(|_| "wlan0".to_string());
    println!("[*] Interface:       {}", iface);
    println!("[*] Hopper Channels: 1, 6, 11 (250ms interval)");
    println!("[*] Batch Window:    60 seconds");

    let cache: Arc<Mutex<HashMap<String, RawProbeRecord>>> = Arc::new(Mutex::new(HashMap::new()));

    // 1. Channel Hopper Thread (hops channels 1, 6, 11)
    let hopper_iface = iface.clone();
    thread::spawn(move || {
        let channels: [u8; 3] = [1, 6, 11];
        let mut idx = 0;
        loop {
            let ch = channels[idx % channels.len()];
            idx += 1;
            CURRENT_CHANNEL.store(ch, Ordering::Relaxed);
            let _ = Command::new("iw")
                .args(["dev", &hopper_iface, "set", "channel", &ch.to_string()])
                .status();
            thread::sleep(Duration::from_millis(250));
        }
    });

    // 2. Batch Sender Thread (flushes unique aggregated probes every 60s)
    let flush_cache = Arc::clone(&cache);
    let flush_url = webapp_url.clone();
    let flush_token = secret_token.clone();
    thread::spawn(move || loop {
        thread::sleep(Duration::from_secs(60));
        let raw_items: Vec<RawProbeRecord> = {
            let mut lock = flush_cache.lock().unwrap();
            if lock.is_empty() {
                continue;
            }
            lock.drain().map(|(_, v)| v).collect()
        };

        if raw_items.is_empty() || flush_url.is_empty() {
            continue;
        }

        let items_to_send: Vec<EnrichedProbe> = raw_items.into_iter().map(finalize_record).collect();

        println!(
            "[{}] Flushing {} unique probes to Webhook...",
            get_timestamp(),
            items_to_send.len()
        );

        let payload = BatchPayload {
            token: flush_token.clone(),
            msg_type: "probes".to_string(),
            items: items_to_send,
        };

        match ureq::post(&flush_url)
            .set("Content-Type", "application/json")
            .send_json(&payload)
        {
            Ok(resp) => {
                println!("[*] Cloud Push Status: {}", resp.status());
            }
            Err(e) => {
                eprintln!("[!] Cloud Push Failed: {}", e);
            }
        }
    });

    // 3. Raw Socket Packet Sniffer
    unsafe {
        let proto = (libc::ETH_P_ALL as u16).to_be() as i32;
        let fd = libc::socket(libc::AF_PACKET, libc::SOCK_RAW, proto);
        if fd < 0 {
            eprintln!("[!] Failed to open raw socket! Must run as root.");
            return;
        }

        let if_name = std::ffi::CString::new(iface.as_str()).unwrap();
        let ifindex = libc::if_nametoindex(if_name.as_ptr());
        if ifindex == 0 {
            eprintln!("[!] Invalid interface name: {}", iface);
            return;
        }

        let mut addr: libc::sockaddr_ll = std::mem::zeroed();
        addr.sll_family = libc::AF_PACKET as u16;
        addr.sll_protocol = (libc::ETH_P_ALL as u16).to_be();
        addr.sll_ifindex = ifindex as i32;

        if libc::bind(
            fd,
            &addr as *const _ as *const libc::sockaddr,
            std::mem::size_of::<libc::sockaddr_ll>() as u32,
        ) < 0
        {
            eprintln!("[!] Failed to bind raw socket to {}", iface);
            return;
        }

        println!("[*] ProbeHound listening in monitor mode...");

        let mut buf = [0u8; 2048];
        loop {
            let n = libc::recv(fd, buf.as_mut_ptr() as *mut libc::c_void, buf.len(), 0);
            if n <= 0 {
                continue;
            }

            let len = n as usize;
            if let Some((rssi, ch, radiotap_len)) = parse_radiotap(&buf[..len]) {
                if let Some((record, dedup_key)) = parse_probe_frame(&buf[..len], radiotap_len, rssi, ch) {
                    println!(
                        "Probe: {} | Ch: {:2} | {:4} dBm | SSID: {:18} | Vendor: {:16} | {}",
                        record.mac, record.channel, record.peak_rssi, record.ssid, record.vendor, record.wifi_gen
                    );

                    let mut lock = cache.lock().unwrap();
                    let e = lock.entry(dedup_key).or_insert(record.clone());
                    e.count += 1;
                    e.rssi_sum += rssi as i32;
                    if rssi > e.peak_rssi {
                        e.peak_rssi = rssi;
                    }
                    if rssi < e.min_rssi {
                        e.min_rssi = rssi;
                    }
                    e.channel = ch;
                    e.seq_end = record.seq_start;
                    e.time = get_timestamp();
                }
            }
        }
    }
}
