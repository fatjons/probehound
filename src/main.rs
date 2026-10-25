use std::collections::hash_map::Entry;
use std::collections::{HashMap, VecDeque};
use std::env;
use std::fs;
use std::process::Command;
use std::sync::atomic::{AtomicU8, Ordering};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use serde::Serialize;

static CURRENT_CHANNEL: AtomicU8 = AtomicU8::new(1);

const MAX_ACTIVE_RECORDS: usize = 1024;
const MAX_QUEUED_BATCHES: usize = 15;
const MAX_ITEMS_PER_POST: usize = 250;

#[derive(Clone, Debug, PartialEq, Eq, Hash)]
struct AggregationKey {
    mac: [u8; 6],
    ssid: String,
    channel: u8,
}

#[derive(Clone, Debug)]
struct RawProbeRecord {
    first_seen: u64,
    last_seen: u64,
    mac: [u8; 6],
    is_random: bool,
    ssid: String,
    vendor: String,
    probe_type: &'static str,
    wifi_gen: &'static str,
    mimo: &'static str,
    capabilities: String,
    fp_hash: String,
    channel: u8,
    peak_rssi: Option<i8>,
    min_rssi: Option<i8>,
    rssi_sum: i32,
    rssi_count: u32,
    count: u32,
    seq_start: u16,
    seq_end: u16,
}

#[derive(Serialize, Clone, Debug)]
struct EnrichedProbe {
    time: String,
    mac: String,
    mac_type: &'static str,
    is_random: bool,
    proximity: &'static str,
    motion: &'static str,
    rssi: i8,
    rssi_peak: Option<i8>,
    rssi_avg: Option<i8>,
    rssi_min: Option<i8>,
    ssid: String,
    vendor: String,
    device_state: &'static str,
    wifi_gen: &'static str,
    mimo: &'static str,
    security: String,
    fp_hash: String,
    channel: u8,
    count: u32,
    seq_range: String,
}

#[derive(Serialize)]
struct BatchPayload<'a> {
    token: String,
    #[serde(rename = "type")]
    msg_type: &'static str,
    items: &'a [EnrichedProbe],
}

fn push_accepted(body: &str) -> bool {
    serde_json::from_str::<serde_json::Value>(body)
        .map(|v| v["status"] == "probes_saved")
        .unwrap_or(false)
}

#[derive(Debug, PartialEq, Eq)]
struct RadiotapInfo {
    rssi: Option<i8>,
    channel: u8,
    header_len: usize,
    has_fcs: bool,
    bad_fcs: bool,
}

fn format_mac(mac: &[u8; 6]) -> String {
    format!(
        "{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
        mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]
    )
}

fn get_epoch_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

/// Computes a compact 64-bit FNV-1a hash formatted as 8 hex characters
fn fnv1a_hash(data: &[u8]) -> String {
    let mut h: u64 = 0xcbf29ce484222325;
    for &b in data {
        h ^= b as u64;
        h = h.wrapping_mul(0x100000001b3);
    }
    format!("{:08x}", (h ^ (h >> 32)) as u32)
}

/// Strictly parses Radiotap header according to specification without guessing bytes
fn parse_radiotap(buf: &[u8]) -> Option<RadiotapInfo> {
    if buf.len() < 8 || buf[0] != 0 {
        return None;
    }
    let header_len = u16::from_le_bytes([buf[2], buf[3]]) as usize;
    if header_len < 8 || buf.len() < header_len {
        return None;
    }

    let mut present_words = Vec::new();
    let mut offset = 4;
    loop {
        if offset + 4 > header_len {
            return None;
        }
        let word = u32::from_le_bytes([
            buf[offset],
            buf[offset + 1],
            buf[offset + 2],
            buf[offset + 3],
        ]);
        present_words.push(word);
        offset += 4;
        if (word & (1 << 31)) == 0 {
            break;
        }
    }

    let flags_word = present_words[0];
    // Reject frames with vendor namespace or unknown extended bitmap layouts in word 0
    let mut cursor = offset;

    // Bit 0: TSFT (8 bytes, 8-byte aligned)
    if (flags_word & (1 << 0)) != 0 {
        cursor = (cursor + 7) & !7;
        if cursor + 8 > header_len {
            return None;
        }
        cursor += 8;
    }

    // Bit 1: Flags (1 byte)
    let mut has_fcs = false;
    let mut bad_fcs = false;
    if (flags_word & (1 << 1)) != 0 {
        if cursor + 1 > header_len {
            return None;
        }
        let rtap_flags = buf[cursor];
        has_fcs = (rtap_flags & 0x10) != 0;
        bad_fcs = (rtap_flags & 0x40) != 0;
        cursor += 1;
    }

    // Bit 2: Rate (1 byte)
    if (flags_word & (1 << 2)) != 0 {
        if cursor + 1 > header_len {
            return None;
        }
        cursor += 1;
    }

    // Bit 3: Channel (4 bytes: u16 freq, u16 flags, 2-byte aligned)
    let mut channel: u8 = 0;
    if (flags_word & (1 << 3)) != 0 {
        cursor = (cursor + 1) & !1;
        if cursor + 4 > header_len {
            return None;
        }
        let freq = u16::from_le_bytes([buf[cursor], buf[cursor + 1]]);
        channel = if (2412..=2472).contains(&freq) {
            ((freq - 2407) / 5) as u8
        } else if freq == 2484 {
            14
        } else if (5180..=5825).contains(&freq) {
            ((freq - 5000) / 5) as u8
        } else {
            0
        };
        cursor += 4;
    }

    // Bit 4: FHSS (2 bytes, 2-byte aligned)
    if (flags_word & (1 << 4)) != 0 {
        cursor = (cursor + 1) & !1;
        if cursor + 2 > header_len {
            return None;
        }
        cursor += 2;
    }

    // Bit 5: dBm Antenna Signal (1 byte signed)
    let mut rssi: Option<i8> = None;
    if (flags_word & (1 << 5)) != 0 {
        if cursor + 1 > header_len {
            return None;
        }
        let sig = buf[cursor] as i8;
        if (-110..=-10).contains(&sig) {
            rssi = Some(sig);
        }
    }

    if channel == 0 {
        channel = CURRENT_CHANNEL.load(Ordering::Relaxed);
    }

    Some(RadiotapInfo {
        rssi,
        channel,
        header_len,
        has_fcs,
        bad_fcs,
    })
}

/// Parses WPS sub-TLVs inside Vendor IE (00:50:f2:04)
fn parse_wps_vendor(tag_data: &[u8]) -> Option<String> {
    if tag_data.len() < 4 {
        return None;
    }
    let mut sub_offset = 4;
    let mut dev_name: Option<String> = None;
    let mut model_name: Option<String> = None;
    let mut manufacturer: Option<String> = None;

    while sub_offset + 4 <= tag_data.len() {
        let attr_type = u16::from_be_bytes([tag_data[sub_offset], tag_data[sub_offset + 1]]);
        let attr_len =
            u16::from_be_bytes([tag_data[sub_offset + 2], tag_data[sub_offset + 3]]) as usize;
        sub_offset += 4;

        if sub_offset + attr_len > tag_data.len() {
            break;
        }

        let val_bytes = &tag_data[sub_offset..sub_offset + attr_len];
        match attr_type {
            0x1011 => {
                if let Ok(s) = std::str::from_utf8(val_bytes) {
                    let trimmed = s.trim().trim_matches('\0');
                    if !trimmed.is_empty() {
                        dev_name = Some(trimmed.to_string());
                    }
                }
            }
            0x1021 => {
                if let Ok(s) = std::str::from_utf8(val_bytes) {
                    let trimmed = s.trim().trim_matches('\0');
                    if !trimmed.is_empty() {
                        manufacturer = Some(trimmed.to_string());
                    }
                }
            }
            0x1023 => {
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
fn parse_probe_frame(
    buf: &[u8],
    rtap: &RadiotapInfo,
    now_secs: u64,
) -> Option<(RawProbeRecord, AggregationKey)> {
    if rtap.bad_fcs || buf.len() <= rtap.header_len {
        return None;
    }

    let end_idx = if rtap.has_fcs {
        buf.len().checked_sub(4)?
    } else {
        buf.len()
    };

    if end_idx <= rtap.header_len {
        return None;
    }

    let frame = &buf[rtap.header_len..end_idx];
    if frame.len() < 24 {
        return None;
    }

    // Byte 0: Frame Control (Type = 0 Management, Subtype = 4 Probe Request -> 0x40)
    if (frame[0] & 0xfc) != 0x40 {
        return None;
    }

    // Sequence control: bytes 22..24 (12-bit sequence number)
    let seq_ctrl = u16::from_le_bytes([frame[22], frame[23]]);
    let seq_num = seq_ctrl >> 4;

    // Address 2 (Transmitter MAC): bytes 10..16
    let mut mac = [0u8; 6];
    mac.copy_from_slice(&frame[10..16]);
    let is_random = (mac[0] & 0x02) != 0;

    let mut offset = 24;
    let mut ssid = "<Broadcast>".to_string();
    let mut probe_type: &'static str = "Broadcast";
    let mut has_ht = false;
    let mut has_vht = false;
    let mut has_he = false;
    let mut vendor = "Generic / Unspecified".to_string();
    let mut mimo: &'static str = "1x1 SISO";

    let mut cap_flags: Vec<&'static str> = Vec::new();
    let mut fp_raw_bytes = Vec::with_capacity(64);

    while offset + 2 <= frame.len() {
        let tag_num = frame[offset];
        let tag_len = frame[offset + 1] as usize;
        offset += 2;

        if offset + tag_len > frame.len() {
            break;
        }

        let tag_data = &frame[offset..offset + tag_len];
        fp_raw_bytes.push(tag_num);

        match tag_num {
            0 => {
                // SSID
                if tag_len > 0 {
                    if let Ok(s) = std::str::from_utf8(tag_data) {
                        let clean: String = s
                            .chars()
                            .filter(|c| !c.is_control() && *c != '\0')
                            .collect();
                        if !clean.is_empty() {
                            ssid = clean;
                            probe_type = "Directed";
                        }
                    }
                }
            }
            1 | 50 => {
                // Supported Rates / Extended Supported Rates contribute to capability fingerprint
                fp_raw_bytes.extend_from_slice(tag_data);
            }
            45 => {
                // HT Capabilities (802.11n)
                has_ht = true;
                if tag_data.len() >= 2 {
                    fp_raw_bytes.extend_from_slice(&tag_data[0..2]);
                }
                if tag_data.len() >= 5 {
                    // RX MCS bitmask: byte 3 = stream 1, byte 4 = stream 2
                    if tag_data[3] != 0 && tag_data[4] != 0 {
                        mimo = "2x2 MIMO";
                    }
                }
            }
            70 => {
                // RM Enabled Capabilities (802.11k)
                if !cap_flags.contains(&"802.11k") {
                    cap_flags.push("802.11k");
                }
            }
            107 => {
                // Interworking (802.11u / Hotspot 2.0)
                if !cap_flags.contains(&"802.11u") {
                    cap_flags.push("802.11u");
                }
            }
            127 => {
                // Extended Capabilities
                fp_raw_bytes.extend_from_slice(tag_data);
                if tag_data.len() > 2 && (tag_data[2] & (1 << 3)) != 0 && !cap_flags.contains(&"802.11v") {
                    cap_flags.push("802.11v");
                }
                if tag_data.len() > 6 && (tag_data[6] & 0x01) != 0 && !cap_flags.contains(&"UTF8-SSID") {
                    cap_flags.push("UTF8-SSID");
                }
            }
            191 => {
                // VHT Capabilities (802.11ac)
                has_vht = true;
                if tag_data.len() >= 4 {
                    fp_raw_bytes.extend_from_slice(&tag_data[0..4]);
                }
                // Decode VHT RX MCS Map (bytes 4..6): 2 bits per spatial stream (3 != 0b11 means supported)
                if tag_data.len() >= 6 {
                    let rx_mcs_map = u16::from_le_bytes([tag_data[4], tag_data[5]]);
                    let ss1 = rx_mcs_map & 0x03;
                    let ss2 = (rx_mcs_map >> 2) & 0x03;
                    if ss1 != 0x03 && ss2 != 0x03 {
                        mimo = "2x2 MIMO";
                    }
                }
            }
            255 => {
                // Extension elements (Wi-Fi 6 / HE is Ext ID 35)
                if tag_len > 0 {
                    fp_raw_bytes.push(tag_data[0]);
                    if tag_data[0] == 35 {
                        has_he = true;
                    }
                }
            }
            221 => {
                // Vendor Specific IE
                if tag_data.len() >= 4 && tag_data[0..4] == [0x00, 0x50, 0xf2, 0x04] {
                    fp_raw_bytes.extend_from_slice(&[0x00, 0x50, 0xf2, 0x04]);
                    if !cap_flags.contains(&"WPS") {
                        cap_flags.push("WPS");
                    }
                    if let Some(wps_name) = parse_wps_vendor(tag_data) {
                        vendor = wps_name;
                    } else if vendor == "Generic / Unspecified" {
                        vendor = "Microsoft WPS".to_string();
                    }
                } else if tag_data.len() >= 3 {
                    let oui = &tag_data[0..3];
                    fp_raw_bytes.extend_from_slice(oui);
                    if oui == [0x00, 0x17, 0xf2] || oui == [0x00, 0x03, 0x7f] {
                        if oui == [0x00, 0x17, 0xf2] && vendor == "Generic / Unspecified" {
                            vendor = "Apple".to_string();
                        }
                    } else if oui == [0x00, 0x50, 0xf2] {
                        if vendor == "Generic / Unspecified" {
                            vendor = "Microsoft".to_string();
                        }
                    } else if oui == [0x00, 0x90, 0x4c] {
                        if vendor == "Generic / Unspecified" {
                            vendor = "Broadcom".to_string();
                        }
                    } else if oui == [0x00, 0x1a, 0x11] {
                        if vendor == "Generic / Unspecified" {
                            vendor = "Google".to_string();
                        }
                    } else if oui == [0x08, 0x00, 0x27] {
                        if vendor == "Generic / Unspecified" {
                            vendor = "Espressif".to_string();
                        }
                    }
                }
            }
            _ => {}
        }

        offset += tag_len;
    }

    let capabilities = if cap_flags.is_empty() {
        "Basic".to_string()
    } else {
        cap_flags.join("/")
    };

    let fp_hash = fnv1a_hash(&fp_raw_bytes);

    let wifi_gen = if has_he {
        "Wi-Fi 6 (802.11ax)"
    } else if has_vht {
        "Wi-Fi 5 (802.11ac)"
    } else if has_ht {
        "Wi-Fi 4 (802.11n)"
    } else {
        "Legacy 802.11b/g"
    };

    let key = AggregationKey {
        mac,
        ssid: ssid.clone(),
        channel: rtap.channel,
    };

    let (rssi_sum, rssi_count) = match rtap.rssi {
        Some(v) => (v as i32, 1),
        None => (0, 0),
    };

    let record = RawProbeRecord {
        first_seen: now_secs,
        last_seen: now_secs,
        mac,
        is_random,
        ssid,
        vendor,
        probe_type,
        wifi_gen,
        mimo,
        capabilities,
        fp_hash,
        channel: rtap.channel,
        peak_rssi: rtap.rssi,
        min_rssi: rtap.rssi,
        rssi_sum,
        rssi_count,
        count: 1,
        seq_start: seq_num,
        seq_end: seq_num,
    };

    Some((record, key))
}

/// Inserts or updates a probe observation in the bounded aggregation map without double-counting
fn ingest_probe(
    map: &mut HashMap<AggregationKey, RawProbeRecord>,
    key: AggregationKey,
    record: RawProbeRecord,
) -> bool {
    let is_full = map.len() >= MAX_ACTIVE_RECORDS;
    match map.entry(key) {
        Entry::Occupied(mut occ) => {
            let e = occ.get_mut();
            e.count += 1;
            e.last_seen = record.last_seen;
            e.seq_end = record.seq_start;
            if let Some(r) = record.peak_rssi {
                e.rssi_sum += r as i32;
                e.rssi_count += 1;
                e.peak_rssi = Some(e.peak_rssi.map_or(r, |cur| cur.max(r)));
                e.min_rssi = Some(e.min_rssi.map_or(r, |cur| cur.min(r)));
            }
            if e.vendor == "Generic / Unspecified" && record.vendor != "Generic / Unspecified" {
                e.vendor = record.vendor;
            }
            if e.mimo == "1x1 SISO" && record.mimo == "2x2 MIMO" {
                e.mimo = record.mimo;
            }
            true
        }
        Entry::Vacant(vac) => {
            if is_full {
                false
            } else {
                vac.insert(record);
                true
            }
        }
    }
}

fn finalize_record(raw: RawProbeRecord) -> EnrichedProbe {
    let avg_rssi = if raw.rssi_count > 0 {
        Some((raw.rssi_sum as f32 / raw.rssi_count as f32).round() as i8)
    } else {
        None
    };

    let proximity = match raw.peak_rssi {
        Some(p) if p >= -50 => "Strong (>= -50 dBm)",
        Some(p) if p >= -68 => "Moderate (-51..-68 dBm)",
        Some(p) if p >= -79 => "Weak (-69..-79 dBm)",
        Some(_) => "Very Weak (<= -80 dBm)",
        None => "Unknown RSSI",
    };

    let motion = match (raw.peak_rssi, raw.min_rssi) {
        _ if raw.count == 1 => "Single Probe",
        (Some(peak), Some(min)) if (peak - min).abs() >= 8 => "High Spread (>=8 dB)",
        (Some(_), Some(_)) => "Low Spread (<8 dB)",
        _ => "Unknown",
    };

    let seq_range = if raw.count == 1 {
        format!("{}", raw.seq_start)
    } else {
        format!("{} -> {}", raw.seq_start, raw.seq_end)
    };

    let mac_type = if raw.is_random {
        "Randomized"
    } else {
        "Factory OUI"
    };

    EnrichedProbe {
        time: format!("{}", raw.last_seen),
        mac: format_mac(&raw.mac),
        mac_type,
        is_random: raw.is_random,
        proximity,
        motion,
        rssi: raw.peak_rssi.unwrap_or(-127),
        rssi_peak: raw.peak_rssi,
        rssi_avg: avg_rssi,
        rssi_min: raw.min_rssi,
        ssid: raw.ssid,
        vendor: raw.vendor,
        device_state: raw.probe_type,
        wifi_gen: raw.wifi_gen,
        mimo: raw.mimo,
        security: raw.capabilities,
        fp_hash: raw.fp_hash,
        channel: raw.channel,
        count: raw.count,
        seq_range,
    }
}

fn main() {
    println!("========================================================");
    println!("     ProbeHound v0.4.1 - 802.11 Probe Telemetry Engine   ");
    println!("========================================================");

    let mut webapp_url = env::var("WEBAPP_URL").unwrap_or_default();
    let mut secret_token = env::var("SECRET_TOKEN").unwrap_or_default();
    let debug_probes = env::var("DEBUG_PROBES")
        .map(|v| v == "1" || v.eq_ignore_ascii_case("true"))
        .unwrap_or(false);

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
    println!(
        "[*] Bounds:          {} max records / {} retry batches",
        MAX_ACTIVE_RECORDS, MAX_QUEUED_BATCHES
    );
    println!("[*] Debug Logging:   {}", debug_probes);

    let cache: Arc<Mutex<HashMap<AggregationKey, RawProbeRecord>>> =
        Arc::new(Mutex::new(HashMap::with_capacity(256)));

    // 1. Channel Hopper Thread (only updates fallback channel on successful iw execution)
    let hopper_iface = iface.clone();
    thread::spawn(move || {
        let channels: [u8; 3] = [1, 6, 11];
        let mut idx = 0;
        loop {
            let ch = channels[idx % channels.len()];
            idx += 1;
            match Command::new("iw")
                .args(["dev", &hopper_iface, "set", "channel", &ch.to_string()])
                .status()
            {
                Ok(status) if status.success() => {
                    CURRENT_CHANNEL.store(ch, Ordering::Relaxed);
                }
                _ => {
                    thread::sleep(Duration::from_secs(1));
                }
            }
            thread::sleep(Duration::from_millis(250));
        }
    });

    // 2. Bounded Batch Sender Thread with Retry Queue & Timeouts
    let flush_cache = Arc::clone(&cache);
    let flush_url = webapp_url.clone();
    let flush_token = secret_token.clone();
    thread::spawn(move || {
        let agent = ureq::AgentBuilder::new()
            .timeout_connect(Duration::from_secs(10))
            .timeout_read(Duration::from_secs(15))
            .timeout_write(Duration::from_secs(15))
            .build();

        let mut retry_queue: VecDeque<Vec<EnrichedProbe>> = VecDeque::new();
        let mut dropped_batches: u64 = 0;

        loop {
            thread::sleep(Duration::from_secs(60));

            // Fast pointer swap under mutex to minimize capture lock contention
            let drained_map = {
                let mut lock = flush_cache.lock().unwrap();
                if lock.is_empty() {
                    HashMap::new()
                } else {
                    std::mem::take(&mut *lock)
                }
            };

            if !drained_map.is_empty() {
                let mut batch = Vec::with_capacity(drained_map.len().min(MAX_ITEMS_PER_POST));
                for (_, raw) in drained_map {
                    batch.push(finalize_record(raw));
                    if batch.len() >= MAX_ITEMS_PER_POST {
                        if retry_queue.len() >= MAX_QUEUED_BATCHES {
                            retry_queue.pop_front();
                            dropped_batches += 1;
                        }
                        retry_queue.push_back(std::mem::take(&mut batch));
                    }
                }
                if !batch.is_empty() {
                    if retry_queue.len() >= MAX_QUEUED_BATCHES {
                        retry_queue.pop_front();
                        dropped_batches += 1;
                    }
                    retry_queue.push_back(batch);
                }
            }

            if retry_queue.is_empty() || flush_url.is_empty() {
                continue;
            }

            while let Some(items_to_send) = retry_queue.pop_front() {
                println!(
                    "[{}] Pushing batch ({} groups, {} queued, {} dropped_total)...",
                    get_epoch_secs(),
                    items_to_send.len(),
                    retry_queue.len(),
                    dropped_batches
                );

                let payload = BatchPayload {
                    token: flush_token.clone(),
                    msg_type: "probes",
                    items: &items_to_send,
                };

                match agent
                    .post(&flush_url)
                    .set("Content-Type", "application/json")
                    .send_json(&payload)
                {
                    Ok(resp) => {
                        let status = resp.status();
                        let body = resp.into_string().unwrap_or_default();
                        if !push_accepted(&body) {
                            eprintln!(
                                "[!] Webhook Push Rejected (re-queueing batch): {}",
                                body.chars().take(200).collect::<String>()
                            );
                            retry_queue.push_front(items_to_send);
                            break;
                        }
                        println!("[*] Webhook Push Status: {}", status);
                    }
                    Err(e) => {
                        eprintln!("[!] Webhook Push Failed (re-queueing batch): {}", e);
                        retry_queue.push_front(items_to_send);
                        break;
                    }
                }
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

        println!("[*] ProbeHound v0.4.1 active in monitor mode...");

        let mut buf = [0u8; 2048];
        let mut consecutive_errors = 0u32;

        loop {
            let n = libc::recv(fd, buf.as_mut_ptr() as *mut libc::c_void, buf.len(), 0);
            if n < 0 {
                let err = *libc::__errno_location();
                if err == libc::EINTR || err == libc::EAGAIN {
                    continue;
                }
                consecutive_errors += 1;
                if consecutive_errors % 10 == 1 {
                    eprintln!("[!] Socket recv error (errno {}), backing off...", err);
                }
                thread::sleep(Duration::from_millis(250));
                continue;
            }
            if n == 0 {
                thread::sleep(Duration::from_millis(100));
                continue;
            }
            consecutive_errors = 0;

            let len = n as usize;
            if let Some(rtap) = parse_radiotap(&buf[..len]) {
                let now_secs = get_epoch_secs();
                if let Some((record, key)) = parse_probe_frame(&buf[..len], &rtap, now_secs) {
                    if debug_probes {
                        println!(
                            "Probe: {} [FP:{}] | Ch:{:2} | {:?} dBm | Type: {:9} | Caps: {:12} | SSID: {:14} | {}",
                            format_mac(&record.mac),
                            record.fp_hash,
                            record.channel,
                            record.peak_rssi,
                            record.probe_type,
                            record.capabilities,
                            record.ssid,
                            record.vendor
                        );
                    }

                    let mut lock = cache.lock().unwrap();
                    let _ = ingest_probe(&mut lock, key, record);
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Helper to build a synthetic Radiotap + 802.11 Probe Request packet
    fn build_test_packet(
        rtap_flags: u8,
        rssi: Option<i8>,
        mac: [u8; 6],
        seq_num: u16,
        ies: &[u8],
        fcs: Option<[u8; 4]>,
    ) -> Vec<u8> {
        let mut pkt = Vec::new();
        // Radiotap version (0), pad (0)
        pkt.push(0);
        pkt.push(0);

        let mut present: u32 = (1 << 1) | (1 << 3); // Flags (bit 1) + Channel (bit 3)
        if rssi.is_some() {
            present |= 1 << 5; // dBm Antenna Signal (bit 5)
        }

        let header_len: u16 = if rssi.is_some() { 15 } else { 14 };
        pkt.extend_from_slice(&header_len.to_le_bytes());
        pkt.extend_from_slice(&present.to_le_bytes());

        // Bit 1: Flags (offset 8)
        pkt.push(rtap_flags);
        // Padding for 2-byte alignment of Channel (offset 9)
        pkt.push(0);
        // Bit 3: Channel 2437 MHz (Ch 6) + flags (offsets 10..14)
        pkt.extend_from_slice(&2437u16.to_le_bytes());
        pkt.extend_from_slice(&0x00a0u16.to_le_bytes());

        // Bit 5: RSSI (offset 14)
        if let Some(sig) = rssi {
            pkt.push(sig as u8);
        }

        // 802.11 Probe Request Header (24 bytes)
        pkt.push(0x40); // Frame Control: Probe Request
        pkt.push(0x00);
        pkt.extend_from_slice(&[0x00, 0x00]); // Duration
        pkt.extend_from_slice(&[0xff; 6]); // DA: Broadcast
        pkt.extend_from_slice(&mac); // SA: Transmitter
        pkt.extend_from_slice(&[0xff; 6]); // BSSID: Broadcast
        let seq_ctrl = seq_num << 4;
        pkt.extend_from_slice(&seq_ctrl.to_le_bytes());

        // Information Elements
        pkt.extend_from_slice(ies);

        // Optional trailing 4-byte FCS
        if let Some(crc) = fcs {
            pkt.extend_from_slice(&crc);
        }

        pkt
    }

    #[test]
    fn test_single_probe_not_double_counted() {
        let mac = [0xda, 0xa1, 0x19, 0x01, 0x02, 0x03];
        let ies = [0x00, 0x04, b'H', b'o', b'm', b'e']; // SSID "Home"
        let pkt = build_test_packet(0x00, Some(-58), mac, 100, &ies, None);

        let rtap = parse_radiotap(&pkt).expect("valid radiotap");
        assert_eq!(rtap.rssi, Some(-58));
        assert_eq!(rtap.channel, 6);

        let (rec, key) = parse_probe_frame(&pkt, &rtap, 1700000000).expect("valid probe");
        let mut map = HashMap::new();
        assert!(ingest_probe(&mut map, key.clone(), rec));

        let stored = map.get(&key).unwrap();
        assert_eq!(stored.count, 1, "First probe must have count == 1");
        assert_eq!(stored.rssi_sum, -58);

        let finalized = finalize_record(stored.clone());
        assert_eq!(finalized.count, 1);
        assert_eq!(finalized.motion, "Single Probe");
        assert_eq!(finalized.device_state, "Directed");
    }

    #[test]
    fn test_two_probes_aggregated_correctly() {
        let mac = [0xda, 0xa1, 0x19, 0x01, 0x02, 0x03];
        let ies = [0x00, 0x00]; // Broadcast SSID
        let pkt1 = build_test_packet(0x00, Some(-72), mac, 10, &ies, None);
        let pkt2 = build_test_packet(0x00, Some(-60), mac, 11, &ies, None);

        let mut map = HashMap::new();
        for pkt in [&pkt1, &pkt2] {
            let rtap = parse_radiotap(pkt).unwrap();
            let (rec, key) = parse_probe_frame(pkt, &rtap, 1700000005).unwrap();
            ingest_probe(&mut map, key, rec);
        }

        assert_eq!(map.len(), 1);
        let rec = map.into_values().next().unwrap();
        assert_eq!(rec.count, 2);
        let fin = finalize_record(rec);
        assert_eq!(fin.count, 2);
        assert_eq!(fin.rssi_peak, Some(-60));
        assert_eq!(fin.rssi_min, Some(-72));
        assert_eq!(fin.rssi_avg, Some(-66));
        assert_eq!(fin.motion, "High Spread (>=8 dB)");
        assert_eq!(fin.seq_range, "10 -> 11");
    }

    #[test]
    fn test_fcs_stripped_and_bad_fcs_rejected() {
        let mac = [0x00, 0x11, 0x22, 0x33, 0x44, 0x55];
        let ies = [0x00, 0x00, 0x01, 0x02, 0x82, 0x84];

        // Packet without FCS vs Packet with FCS flag (0x10) and 4 trailing FCS bytes
        let pkt_no_fcs = build_test_packet(0x00, Some(-65), mac, 1, &ies, None);
        let pkt_with_fcs =
            build_test_packet(0x10, Some(-65), mac, 1, &ies, Some([0xde, 0xad, 0xbe, 0xef]));

        let rtap1 = parse_radiotap(&pkt_no_fcs).unwrap();
        let (rec1, _) = parse_probe_frame(&pkt_no_fcs, &rtap1, 100).unwrap();

        let rtap2 = parse_radiotap(&pkt_with_fcs).unwrap();
        assert!(rtap2.has_fcs);
        let (rec2, _) = parse_probe_frame(&pkt_with_fcs, &rtap2, 100).unwrap();

        assert_eq!(
            rec1.fp_hash, rec2.fp_hash,
            "Trailing FCS must be stripped and not alter the fingerprint"
        );

        // Bad FCS (0x40) must be rejected
        let pkt_bad_fcs =
            build_test_packet(0x40, Some(-65), mac, 1, &ies, Some([0x00, 0x00, 0x00, 0x00]));
        let rtap_bad = parse_radiotap(&pkt_bad_fcs).unwrap();
        assert!(rtap_bad.bad_fcs);
        assert!(parse_probe_frame(&pkt_bad_fcs, &rtap_bad, 100).is_none());
    }

    #[test]
    fn test_missing_rssi_is_not_fabricated() {
        let mac = [0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff];
        let ies = [0x00, 0x00];
        let pkt = build_test_packet(0x00, None, mac, 42, &ies, None);

        let rtap = parse_radiotap(&pkt).unwrap();
        assert_eq!(rtap.rssi, None, "Missing RSSI must remain None");

        let (rec, _) = parse_probe_frame(&pkt, &rtap, 100).unwrap();
        let fin = finalize_record(rec);
        assert_eq!(fin.rssi_peak, None);
        assert_eq!(fin.proximity, "Unknown RSSI");
    }

    #[test]
    fn test_push_accepted() {
        assert!(push_accepted(r#"{"status":"probes_saved","count":3}"#));
        assert!(!push_accepted(r#"{"status":"forbidden"}"#));
        assert!(!push_accepted(r#"{"error":"x"}"#));
        assert!(!push_accepted("<html>"));
        assert!(!push_accepted(""));
    }
}
