use std::collections::hash_map::Entry;
use std::collections::{HashMap, HashSet, VecDeque};
use std::env;
use std::fs;
use std::net::{Ipv4Addr, UdpSocket};
use std::process::Command;
use std::sync::atomic::{AtomicBool, AtomicU32, AtomicU8, Ordering};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use serde::Serialize;

static CURRENT_CHANNEL: AtomicU8 = AtomicU8::new(1);

// Status counters, swapped to 0 each time a status batch is built (Relaxed: they are statistics only)
static HOP_OK: AtomicU32 = AtomicU32::new(0);
static HOP_FAIL: AtomicU32 = AtomicU32::new(0);
static FRAMES: AtomicU32 = AtomicU32::new(0); // frames with a valid radiotap header
static PROBES: AtomicU32 = AtomicU32::new(0);
static BEACONS: AtomicU32 = AtomicU32::new(0);
static STATIONS_SEEN: AtomicU32 = AtomicU32::new(0); // data frames counted into station stats
static STATIONS_OVERFLOW: AtomicU32 = AtomicU32::new(0); // new stations skipped at the cap
static BAD_FCS: AtomicU32 = AtomicU32::new(0);
static DROPPED_FRAMES: AtomicU32 = AtomicU32::new(0); // radiotap header unparseable
static NL_ACTIVE: AtomicBool = AtomicBool::new(false);
static LAN_DEVICES: AtomicU32 = AtomicU32::new(u32::MAX); // u32::MAX = no scan yet
static ROTATION: Mutex<Vec<u8>> = Mutex::new(Vec::new()); // hopper's current channel list

const MAX_ACTIVE_RECORDS: usize = 1024;
const MAX_QUEUED_BATCHES: usize = 15;
const MAX_ITEMS_PER_POST: usize = 250;
const MAX_BEACON_BSSIDS: usize = 64;
const MAX_STATIONS: usize = 128;
const MAX_LAN_HOSTS: usize = 1024;

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

struct BeaconStat {
    ssid: String,
    channel: u8,
    rssi_sum: i32,
    rssi_sq_sum: i64,
    n: u32,
    min: i8,
    max: i8,
}

/// [bssid, ssid, channel, mean, min, max, n, std] serialized as a JSON array
type BeaconItem = (String, String, u8, f32, i8, i8, u32, Option<f32>);

/// Population std dev of beacon RSSI, 1 decimal; None for a single sample
fn beacon_std(b: &BeaconStat) -> Option<f32> {
    rssi_std(b.n, b.rssi_sum, b.rssi_sq_sum)
}

fn rssi_std(n: u32, sum: i32, sq_sum: i64) -> Option<f32> {
    if n < 2 {
        return None;
    }
    let n = n as f64;
    let mean = sum as f64 / n;
    let sd = (sq_sum as f64 / n - mean * mean).max(0.0).sqrt();
    Some(((sd * 10.0).round() / 10.0) as f32)
}

/// Per-minute RSSI of one client station, from the headers of its data frames
struct StationStat {
    bssid: [u8; 6], // last seen
    channel: u8,
    rssi_sum: i32,
    rssi_sq_sum: i64,
    n: u32,
    min: i8,
    max: i8,
}

/// [sta, bssid, channel, mean, min, max, n, std] serialized as a JSON array
type StationItem = (String, String, u8, f32, i8, i8, u32, Option<f32>);

struct StationBatch {
    time: String,
    items: Vec<StationItem>,
}

struct BeaconBatch {
    time: String,
    items: Vec<BeaconItem>,
}

struct LanBatch {
    time: String,
    items: Vec<(String, String)>, // (mac, ip)
}

#[derive(Serialize)]
struct StatusReport {
    version: &'static str,
    uptime_s: u64,
    iface: String,
    channels: Vec<u8>,
    dwell_ms: u64,
    nl80211: bool,
    hop_ok: u32,
    hop_fail: u32,
    frames: u32,
    probes: u32,
    beacons: u32,
    stations: u32,
    stations_overflow: u32,
    bad_fcs: u32,
    dropped_frames: u32,
    queued: usize,
    dropped_total: u64,
    lan_devices: Option<u32>,
    load1: Option<f32>,
    rss_kb: Option<u64>,
    throttled: Option<u32>,
    temp_c: Option<f32>,
}

struct StatusBatch {
    time: String,
    item: StatusReport,
}

enum Batch {
    Probes(Vec<EnrichedProbe>),
    Beacons(BeaconBatch),
    Stations(StationBatch),
    Lan(LanBatch),
    Status(StatusBatch),
}

/// First field of /proc/loadavg
fn parse_loadavg(s: &str) -> Option<f32> {
    s.split_whitespace().next()?.parse().ok()
}

/// VmRSS (kB) from /proc/self/status text
fn parse_vmrss(s: &str) -> Option<u64> {
    s.lines().find_map(|l| l.strip_prefix("VmRSS:"))?.split_whitespace().next()?.parse().ok()
}

/// First /sys/class/hwmon/hwmonN/<file> whose `name` is `want` (e.g. rpi_volt, cpu_thermal)
fn hwmon_read(want: &str, file: &str) -> Option<String> {
    for e in fs::read_dir("/sys/class/hwmon").ok()?.flatten() {
        if fs::read_to_string(e.path().join("name")).ok()?.trim() == want {
            return fs::read_to_string(e.path().join(file)).ok();
        }
    }
    None
}

/// "0x50005" or "throttled=0x0"
fn parse_throttled(s: &str) -> Option<u32> {
    let v = s.trim().rsplit('=').next()?;
    u32::from_str_radix(v.trim_start_matches("0x"), 16).ok()
}

/// Builds a status report, resetting the since-last-status counters
fn collect_status(started: Instant, iface: &str, dwell_ms: u64, queued: usize, dropped_total: u64) -> StatusReport {
    let take = |a: &AtomicU32| a.swap(0, Ordering::Relaxed);
    let lan = LAN_DEVICES.load(Ordering::Relaxed);
    StatusReport {
        version: env!("CARGO_PKG_VERSION"),
        uptime_s: started.elapsed().as_secs(),
        iface: iface.to_string(),
        channels: ROTATION.lock().unwrap().clone(),
        dwell_ms,
        nl80211: NL_ACTIVE.load(Ordering::Relaxed),
        hop_ok: take(&HOP_OK),
        hop_fail: take(&HOP_FAIL),
        frames: take(&FRAMES),
        probes: take(&PROBES),
        beacons: take(&BEACONS),
        stations: take(&STATIONS_SEEN),
        stations_overflow: take(&STATIONS_OVERFLOW),
        bad_fcs: take(&BAD_FCS),
        dropped_frames: take(&DROPPED_FRAMES),
        queued,
        dropped_total,
        lan_devices: (lan != u32::MAX).then_some(lan),
        load1: fs::read_to_string("/proc/loadavg").ok().and_then(|s| parse_loadavg(&s)),
        rss_kb: fs::read_to_string("/proc/self/status").ok().and_then(|s| parse_vmrss(&s)),
        // firmware flags if exposed, else the Pi kernel's undervoltage alarm (0/1, current state)
        throttled: fs::read_to_string("/sys/devices/platform/soc/soc:firmware/get_throttled")
            .ok()
            .or_else(|| hwmon_read("rpi_volt", "in0_lcrit_alarm"))
            .and_then(|s| parse_throttled(&s).or_else(|| s.trim().parse().ok())),
        temp_c: hwmon_read("cpu_thermal", "temp1_input")
            .and_then(|s| s.trim().parse::<f32>().ok())
            .map(|m| (m / 100.0).round() / 10.0),
    }
}

#[derive(Serialize)]
struct BatchPayload<'a, T> {
    token: String,
    #[serde(rename = "type")]
    msg_type: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    time: Option<&'a str>,
    items: &'a [T],
}

/// The webhook answers "ignored" for a type it does not know: retrying can never succeed,
/// and a re-queued batch at the head of the queue would hold back every probe batch behind it.
fn push_ignored(body: &str) -> bool {
    push_accepted(body, "ignored")
}

fn push_accepted(body: &str, expected_status: &str) -> bool {
    serde_json::from_str::<serde_json::Value>(body)
        .map(|v| v["status"] == expected_status)
        .unwrap_or(false)
}

/// Subnet being scanned: interface, network address, prefix length, own address
#[derive(Clone)]
struct LanNet {
    dev: String,
    net: u32,
    prefix: u8,
    own: u32,
}

fn prefix_mask(prefix: u8) -> u32 {
    u32::MAX.checked_shl(32 - prefix as u32).unwrap_or(0)
}

/// Host addresses of the subnet: no network, broadcast or `own` address
fn hosts(net: u32, prefix: u8, own: u32) -> impl Iterator<Item = Ipv4Addr> {
    let base = net & prefix_mask(prefix);
    let size = 1u32 << (32 - prefix as u32);
    (1..size - 1).map(move |i| base + i).filter(move |&a| a != own).map(Ipv4Addr::from)
}

/// Resolved ARP entries (mac, ip) of `dev` inside net/mask from /proc/net/arp text
fn parse_arp(text: &str, dev: &str, net: u32, mask: u32) -> Vec<(String, String)> {
    let mut seen = HashSet::new();
    let mut out = Vec::new();
    for line in text.lines().skip(1) {
        let c: Vec<&str> = line.split_whitespace().collect();
        if c.len() < 6 || c[5] != dev {
            continue;
        }
        let flags = u32::from_str_radix(c[2].trim_start_matches("0x"), 16).unwrap_or(0);
        let mac = c[3].to_ascii_lowercase();
        if flags & 0x2 == 0 || mac == "00:00:00:00:00:00" {
            continue;
        }
        let Ok(ip) = c[0].parse::<Ipv4Addr>() else { continue };
        if u32::from(ip) & mask != net & mask || !seen.insert(mac.clone()) {
            continue;
        }
        out.push((mac, ip.to_string()));
        if out.len() >= MAX_LAN_HOSTS {
            break;
        }
    }
    out
}

/// Up, non-loopback IPv4 interfaces except `skip`: (name, addr, netmask)
fn ipv4_ifaces(skip: &str) -> Vec<(String, u32, u32)> {
    let mut out = Vec::new();
    let mut ifap: *mut libc::ifaddrs = std::ptr::null_mut();
    // SAFETY: getifaddrs fills ifap with a list we only read and then free
    unsafe {
        if libc::getifaddrs(&mut ifap) != 0 {
            return out;
        }
        let mut p = ifap;
        while !p.is_null() {
            let a = &*p;
            p = a.ifa_next;
            let up = a.ifa_flags & libc::IFF_UP as u32 != 0 && a.ifa_flags & libc::IFF_LOOPBACK as u32 == 0;
            if !up || a.ifa_addr.is_null() || a.ifa_netmask.is_null() || (*a.ifa_addr).sa_family as i32 != libc::AF_INET {
                continue;
            }
            let name = std::ffi::CStr::from_ptr(a.ifa_name).to_string_lossy().into_owned();
            if name == skip {
                continue;
            }
            let ip = u32::from_be((*(a.ifa_addr as *const libc::sockaddr_in)).sin_addr.s_addr);
            let mask = u32::from_be((*(a.ifa_netmask as *const libc::sockaddr_in)).sin_addr.s_addr);
            out.push((name, ip, mask));
        }
        libc::freeifaddrs(ifap);
    }
    out
}

/// LAN to scan: from LAN_CIDR (interface owning an address in it) or the first usable non-sniffer interface
fn detect_lan(sniffer: &str, cidr: Option<&str>) -> Result<LanNet, String> {
    let forced = match cidr {
        Some(c) => {
            let (ip, p) = c.split_once('/').ok_or("LAN_CIDR needs a.b.c.d/n")?;
            let ip: Ipv4Addr = ip.trim().parse().map_err(|_| "LAN_CIDR bad address")?;
            let p: u8 = p.trim().parse().map_err(|_| "LAN_CIDR bad prefix")?;
            if !(22..=30).contains(&p) {
                return Err(format!("prefix /{} outside /22../30", p));
            }
            Some((u32::from(ip), p))
        }
        None => None,
    };
    for (dev, own, mask) in ipv4_ifaces(sniffer) {
        let prefix = mask.count_ones() as u8;
        if let Some((fnet, fp)) = forced {
            if own & prefix_mask(fp) != fnet & prefix_mask(fp) {
                continue;
            }
            return Ok(LanNet { dev, net: fnet & prefix_mask(fp), prefix: fp, own });
        }
        // skip VPN /32 (tailscale0), docker /16 and the like; take the first home-sized subnet
        if !(22..=30).contains(&prefix) {
            continue;
        }
        return Ok(LanNet { dev, net: own & mask, prefix, own });
    }
    Err("no interface with a /22../30 IPv4 subnet".to_string())
}

/// ARPs every host of the subnet via UDP discard, then reads the kernel neighbour table
fn scan_lan(lan: &LanNet) -> Vec<(String, String)> {
    let Ok(sock) = UdpSocket::bind("0.0.0.0:0") else { return Vec::new() };
    let _ = sock.set_nonblocking(true);
    for ip in hosts(lan.net, lan.prefix, lan.own) {
        let _ = sock.send_to(&[0u8], (ip, 9)); // EAGAIN/EHOSTUNREACH are normal
        thread::sleep(Duration::from_millis(2));
    }
    thread::sleep(Duration::from_secs(3));
    let text = fs::read_to_string("/proc/net/arp").unwrap_or_default();
    parse_arp(&text, &lan.dev, lan.net, prefix_mask(lan.prefix))
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

/// Radiotap frequency (MHz) to channel number: 2.4 GHz 1..14, 5 GHz 32..177; None otherwise
fn freq_to_channel(mhz: u16) -> Option<u8> {
    match mhz {
        2412..=2472 if mhz % 5 == 2 => Some(((mhz - 2407) / 5) as u8),
        2484 => Some(14),
        5160..=5885 if mhz % 5 == 0 => Some(((mhz - 5000) / 5) as u8),
        _ => None,
    }
}

/// Channel number to centre frequency (MHz), inverse of `freq_to_channel`
fn channel_to_freq(ch: u8) -> Option<u32> {
    match ch {
        1..=13 => Some(2407 + 5 * ch as u32),
        14 => Some(2484),
        32..=177 => Some(5000 + 5 * ch as u32),
        _ => None,
    }
}

const DEFAULT_CHANNELS: [u8; 3] = [1, 6, 11];
const MAX_CHANNELS: usize = 32;

/// Comma list of channel numbers: invalid/unknown skipped, deduped in order; falls back to 1,6,11
fn parse_channels(s: &str) -> Vec<u8> {
    let mut out: Vec<u8> = Vec::new();
    for t in s.split(',') {
        if let Ok(c) = t.trim().parse::<u8>() {
            if channel_to_freq(c).is_some() && !out.contains(&c) && out.len() < MAX_CHANNELS {
                out.push(c);
            }
        }
    }
    if out.is_empty() {
        eprintln!("[!] CHANNELS has no valid channel, using 1, 6, 11");
        out = DEFAULT_CHANNELS.to_vec();
    }
    out
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
        channel = freq_to_channel(freq).unwrap_or(0);
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

/// Returns the 802.11 frame (radiotap and FCS stripped), rejecting bad-FCS or short frames
fn extract_frame<'a>(buf: &'a [u8], rtap: &RadiotapInfo) -> Option<&'a [u8]> {
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
    Some(frame)
}

/// Parses 802.11 Probe Request Frame & Information Elements
fn parse_probe_frame(
    buf: &[u8],
    rtap: &RadiotapInfo,
    now_secs: u64,
) -> Option<(RawProbeRecord, AggregationKey)> {
    let frame = extract_frame(buf, rtap)?;

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

/// Parses a Beacon into (bssid, ssid, ap channel, rssi); None if not a usable beacon
fn parse_beacon_frame(buf: &[u8], rtap: &RadiotapInfo) -> Option<([u8; 6], String, u8, i8)> {
    let frame = extract_frame(buf, rtap)?;
    // Type 0 Management, Subtype 8 Beacon -> 0x80; fixed fields end at offset 36
    if (frame[0] & 0xfc) != 0x80 || frame.len() < 36 {
        return None;
    }
    let rssi = rtap.rssi?;
    let mut bssid = [0u8; 6];
    bssid.copy_from_slice(&frame[16..22]);

    let mut ssid = String::new();
    let mut ds_channel: Option<u8> = None;
    let mut offset = 36;
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
                if let Ok(s) = std::str::from_utf8(tag_data) {
                    ssid = s.chars().filter(|c| !c.is_control()).collect();
                }
            }
            3 if tag_len == 1 => ds_channel = Some(tag_data[0]),
            _ => {}
        }
        offset += tag_len;
    }

    // Adjacent-channel leakage gives attenuated, misleading RSSI
    if ds_channel.map_or(false, |c| c != rtap.channel) {
        return None;
    }
    if ssid.is_empty() {
        ssid = "<Hidden>".to_string();
    }
    Some((bssid, ssid, rtap.channel, rssi))
}

/// Aggregates a beacon observation into the bounded per-BSSID map
fn ingest_beacon(
    map: &mut HashMap<[u8; 6], BeaconStat>,
    bssid: [u8; 6],
    ssid: String,
    channel: u8,
    rssi: i8,
) -> bool {
    let is_full = map.len() >= MAX_BEACON_BSSIDS;
    match map.entry(bssid) {
        Entry::Occupied(mut occ) => {
            let e = occ.get_mut();
            e.rssi_sum += rssi as i32;
            e.rssi_sq_sum += (rssi as i64) * (rssi as i64);
            e.n += 1;
            e.min = e.min.min(rssi);
            e.max = e.max.max(rssi);
            true
        }
        Entry::Vacant(vac) => {
            if is_full {
                false
            } else {
                vac.insert(BeaconStat {
                    ssid,
                    channel,
                    rssi_sum: rssi as i32,
                    rssi_sq_sum: (rssi as i64) * (rssi as i64),
                    n: 1,
                    min: rssi,
                    max: rssi,
                });
                true
            }
        }
    }
}

/// Parses a ToDS data frame (station -> AP) into (station, bssid, channel, rssi) from the 802.11 header only
fn parse_station_frame(buf: &[u8], rtap: &RadiotapInfo) -> Option<([u8; 6], [u8; 6], u8, i8)> {
    let frame = extract_frame(buf, rtap)?;
    // Type 2 Data (incl. null/QoS-null); ToDS=1, FromDS=0 only
    if (frame[0] >> 2) & 3 != 2 || frame[1] & 3 != 1 {
        return None;
    }
    let rssi = rtap.rssi?;
    let mut bssid = [0u8; 6];
    bssid.copy_from_slice(&frame[4..10]);
    let mut sta = [0u8; 6];
    sta.copy_from_slice(&frame[10..16]);
    if sta[0] & 1 == 1 {
        return None;
    }
    Some((sta, bssid, rtap.channel, rssi))
}

/// Aggregates a station observation into the bounded per-station map; false if skipped at the cap
fn ingest_station(
    map: &mut HashMap<[u8; 6], StationStat>,
    sta: [u8; 6],
    bssid: [u8; 6],
    channel: u8,
    rssi: i8,
) -> bool {
    let is_full = map.len() >= MAX_STATIONS;
    match map.entry(sta) {
        Entry::Occupied(mut occ) => {
            let e = occ.get_mut();
            e.bssid = bssid;
            e.rssi_sum += rssi as i32;
            e.rssi_sq_sum += (rssi as i64) * (rssi as i64);
            e.n += 1;
            e.min = e.min.min(rssi);
            e.max = e.max.max(rssi);
            true
        }
        Entry::Vacant(vac) => {
            if is_full {
                false
            } else {
                vac.insert(StationStat {
                    bssid,
                    channel,
                    rssi_sum: rssi as i32,
                    rssi_sq_sum: (rssi as i64) * (rssi as i64),
                    n: 1,
                    min: rssi,
                    max: rssi,
                });
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

/// Minimal nl80211 channel setter over a raw generic-netlink socket (no iw spawn)
mod nl80211 {
    use std::io;

    const GENL_ID_CTRL: u16 = 0x10;
    const CTRL_CMD_GETFAMILY: u8 = 3;
    const CTRL_ATTR_FAMILY_ID: u16 = 1;
    const CTRL_ATTR_FAMILY_NAME: u16 = 2;
    const NLMSG_ERROR: u16 = 2;
    const NLM_F_REQUEST: u16 = 1;
    const NLM_F_ACK: u16 = 4;
    const NL80211_CMD_SET_WIPHY: u8 = 2;
    const NL80211_ATTR_IFINDEX: u16 = 3;
    const NL80211_ATTR_WIPHY_FREQ: u16 = 38;
    const NL80211_ATTR_WIPHY_CHANNEL_TYPE: u16 = 39;

    /// nlmsghdr + genlmsghdr + 4-byte aligned attributes (native endian)
    fn build_msg(typ: u16, flags: u16, seq: u32, cmd: u8, version: u8, attrs: &[(u16, &[u8])]) -> Vec<u8> {
        let mut m = Vec::with_capacity(64);
        m.extend_from_slice(&[0; 4]); // length, patched below
        m.extend_from_slice(&typ.to_ne_bytes());
        m.extend_from_slice(&flags.to_ne_bytes());
        m.extend_from_slice(&seq.to_ne_bytes());
        m.extend_from_slice(&0u32.to_ne_bytes()); // pid: kernel assigns
        m.extend_from_slice(&[cmd, version, 0, 0]);
        for (t, payload) in attrs {
            m.extend_from_slice(&((4 + payload.len()) as u16).to_ne_bytes());
            m.extend_from_slice(&t.to_ne_bytes());
            m.extend_from_slice(payload);
            while m.len() % 4 != 0 {
                m.push(0);
            }
        }
        let len = m.len() as u32;
        m[0..4].copy_from_slice(&len.to_ne_bytes());
        m
    }

    fn build_getfamily(seq: u32) -> Vec<u8> {
        build_msg(GENL_ID_CTRL, NLM_F_REQUEST, seq, CTRL_CMD_GETFAMILY, 1, &[(CTRL_ATTR_FAMILY_NAME, b"nl80211\0")])
    }

    fn build_set_channel(family: u16, seq: u32, ifindex: u32, ch: u8) -> Vec<u8> {
        let freq = super::channel_to_freq(ch).unwrap_or(0);
        build_msg(
            family,
            NLM_F_REQUEST | NLM_F_ACK,
            seq,
            NL80211_CMD_SET_WIPHY,
            0,
            &[
                (NL80211_ATTR_IFINDEX, &ifindex.to_ne_bytes()),
                (NL80211_ATTR_WIPHY_FREQ, &freq.to_ne_bytes()),
                (NL80211_ATTR_WIPHY_CHANNEL_TYPE, &0u32.to_ne_bytes()), // NL80211_CHAN_NO_HT
            ],
        )
    }

    /// Iterates netlink messages in `buf` as (type, seq, payload after nlmsghdr)
    fn messages(buf: &[u8]) -> impl Iterator<Item = (u16, u32, &[u8])> {
        let mut off = 0;
        std::iter::from_fn(move || {
            let h = buf.get(off..off + 16)?;
            let len = u32::from_ne_bytes(h[0..4].try_into().unwrap()) as usize;
            if len < 16 || off + len > buf.len() {
                return None;
            }
            let item = (
                u16::from_ne_bytes([h[4], h[5]]),
                u32::from_ne_bytes(h[8..12].try_into().unwrap()),
                &buf[off + 16..off + len],
            );
            off += (len + 3) & !3;
            Some(item)
        })
    }

    /// Error code of the NLMSG_ERROR reply for `seq` (0 = ack); None if absent
    fn parse_ack(buf: &[u8], seq: u32) -> Option<i32> {
        messages(buf)
            .find(|&(t, s, p)| t == NLMSG_ERROR && s == seq && p.len() >= 4)
            .map(|(_, _, p)| i32::from_ne_bytes(p[0..4].try_into().unwrap()))
    }

    /// Family id from a CTRL_CMD_GETFAMILY reply for `seq`
    fn parse_family(buf: &[u8], seq: u32) -> Option<u16> {
        let (_, _, p) = messages(buf).find(|&(t, s, _)| t == GENL_ID_CTRL && s == seq)?;
        let mut a = p.get(4..)?; // skip genlmsghdr
        while a.len() >= 4 {
            let len = u16::from_ne_bytes([a[0], a[1]]) as usize;
            if len < 4 || len > a.len() {
                return None;
            }
            if u16::from_ne_bytes([a[2], a[3]]) == CTRL_ATTR_FAMILY_ID && len >= 6 {
                return Some(u16::from_ne_bytes([a[4], a[5]]));
            }
            a = &a[((len + 3) & !3).min(a.len())..];
        }
        None
    }

    pub struct Hopper {
        fd: i32,
        family: u16,
        ifindex: u32,
        seq: u32,
        buf: Vec<u8>, // the nl80211 GETFAMILY reply lists every command: several KB
    }

    impl Drop for Hopper {
        fn drop(&mut self) {
            // SAFETY: fd is owned by this struct and closed exactly once
            unsafe { libc::close(self.fd) };
        }
    }

    impl Hopper {
        pub fn open(iface: &str) -> io::Result<Hopper> {
            let name = std::ffi::CString::new(iface).map_err(|_| io::ErrorKind::InvalidInput)?;
            // SAFETY: name is a valid NUL-terminated string
            let ifindex = unsafe { libc::if_nametoindex(name.as_ptr()) };
            if ifindex == 0 {
                return Err(io::Error::last_os_error());
            }
            // SAFETY: plain socket(2) call; result checked
            let fd = unsafe { libc::socket(libc::AF_NETLINK, libc::SOCK_RAW | libc::SOCK_CLOEXEC, libc::NETLINK_GENERIC) };
            if fd < 0 {
                return Err(io::Error::last_os_error());
            }
            // From here Drop closes fd on every error path
            let mut h = Hopper { fd, family: 0, ifindex, seq: 0, buf: vec![0u8; 32768] };
            // SAFETY: zeroed sockaddr_nl is valid; pointers/lengths match the objects passed
            let rc = unsafe {
                let mut addr: libc::sockaddr_nl = std::mem::zeroed();
                addr.nl_family = libc::AF_NETLINK as u16;
                let tv = libc::timeval { tv_sec: 2 as _, tv_usec: 0 as _ };
                if libc::setsockopt(
                    fd,
                    libc::SOL_SOCKET,
                    libc::SO_RCVTIMEO,
                    &tv as *const _ as *const libc::c_void,
                    std::mem::size_of::<libc::timeval>() as u32,
                ) < 0
                {
                    -1
                } else {
                    libc::bind(
                        fd,
                        &addr as *const _ as *const libc::sockaddr,
                        std::mem::size_of::<libc::sockaddr_nl>() as u32,
                    )
                }
            };
            if rc < 0 {
                return Err(io::Error::last_os_error());
            }
            let seq = h.next_seq();
            let msg = build_getfamily(seq);
            h.family = h
                .request(&msg, seq, parse_family)?
                .ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, "nl80211 family not found"))?;
            Ok(h)
        }

        fn next_seq(&mut self) -> u32 {
            self.seq = self.seq.wrapping_add(1);
            self.seq
        }

        /// Sends `msg`, then reads replies until `parse` yields a value (replies with other seqs are skipped)
        fn request<T>(&mut self, msg: &[u8], seq: u32, parse: fn(&[u8], u32) -> Option<T>) -> io::Result<Option<T>> {
            // SAFETY: msg points to msg.len() valid bytes
            if unsafe { libc::send(self.fd, msg.as_ptr() as *const libc::c_void, msg.len(), 0) } < 0 {
                return Err(io::Error::last_os_error());
            }
            let buf = &mut self.buf;
            loop {
                // SAFETY: buf is a valid writable buffer of buf.len() bytes
                let n = unsafe { libc::recv(self.fd, buf.as_mut_ptr() as *mut libc::c_void, buf.len(), 0) };
                if n < 0 {
                    return Err(io::Error::last_os_error());
                }
                if let Some(v) = parse(&buf[..n as usize], seq) {
                    return Ok(Some(v));
                }
            }
        }

        pub fn set_channel(&mut self, ch: u8) -> io::Result<()> {
            if super::channel_to_freq(ch).is_none() {
                return Err(io::ErrorKind::InvalidInput.into());
            }
            let seq = self.next_seq();
            let msg = build_set_channel(self.family, seq, self.ifindex, ch);
            match self.request(&msg, seq, parse_ack)? {
                Some(0) | None => Ok(()),
                Some(code) => Err(io::Error::from_raw_os_error(-code)),
            }
        }
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        fn ne16(v: u16) -> [u8; 2] {
            v.to_ne_bytes()
        }
        fn ne32(v: u32) -> [u8; 4] {
            v.to_ne_bytes()
        }

        #[test]
        fn test_set_channel_bytes() {
            let mut e = Vec::new();
            e.extend(ne32(44)); // 16 + 4 + 3*8
            e.extend(ne16(0x1c)); // family
            e.extend(ne16(5)); // REQUEST|ACK
            e.extend(ne32(7)); // seq
            e.extend(ne32(0)); // pid
            e.extend([2, 0, 0, 0]); // SET_WIPHY
            for (t, v) in [(3u16, 3u32), (38, 2437), (39, 0)] {
                e.extend(ne16(8));
                e.extend(ne16(t));
                e.extend(ne32(v));
            }
            assert_eq!(build_set_channel(0x1c, 7, 3, 6), e);
        }

        #[test]
        fn test_set_channel_bytes_5ghz() {
            let m = build_set_channel(0x1c, 7, 3, 36);
            assert!(m.windows(4).any(|w| w == ne32(5180)));
        }

        #[test]
        fn test_getfamily_bytes() {
            let mut e = Vec::new();
            e.extend(ne32(32)); // 16 + 4 + 12
            e.extend(ne16(0x10));
            e.extend(ne16(1));
            e.extend(ne32(1));
            e.extend(ne32(0));
            e.extend([3, 1, 0, 0]);
            e.extend(ne16(12));
            e.extend(ne16(2));
            e.extend(b"nl80211\0");
            assert_eq!(build_getfamily(1), e);
        }

        #[test]
        fn test_parse_ack() {
            let ack = |seq: u32, code: i32| {
                let mut m = Vec::new();
                m.extend(ne32(20));
                m.extend(ne16(NLMSG_ERROR));
                m.extend(ne16(0));
                m.extend(ne32(seq));
                m.extend(ne32(0));
                m.extend(code.to_ne_bytes());
                m
            };
            assert_eq!(parse_ack(&ack(5, 0), 5), Some(0));
            assert_eq!(parse_ack(&ack(5, -16), 5), Some(-16));
            assert_eq!(parse_ack(&ack(4, 0), 5), None); // stale seq ignored
        }

        #[test]
        fn test_parse_family() {
            let mut m = build_msg(GENL_ID_CTRL, 0, 9, 1, 1, &[(CTRL_ATTR_FAMILY_NAME, b"nl80211\0"), (CTRL_ATTR_FAMILY_ID, &ne16(0x1c))]);
            assert_eq!(parse_family(&m, 9), Some(0x1c));
            assert_eq!(parse_family(&m, 8), None);
            m.truncate(10);
            assert_eq!(parse_family(&m, 9), None);
        }
    }
}

fn main() {
    println!("========================================================");
    println!("     ProbeHound v0.6.7 - 802.11 Probe Telemetry Engine   ");
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
    let dwell_ms: u64 = env::var("DWELL_MS")
        .ok()
        .and_then(|v| v.trim().parse().ok())
        .unwrap_or(3000) // A/B 2026-10-26: 1000 ms = 2.7x beacons of 250 ms; 3000 ms = +70% beacons, capture 65% -> 74% vs 1000 (a hop costs 0.6-1.1 s on ath9k_htc)
        .clamp(100, 5000);
    let channels = parse_channels(&env::var("CHANNELS").unwrap_or_else(|_| "1,6,11".to_string()));
    println!(
        "[*] Hopper Channels: {} ({}ms dwell)",
        channels.iter().map(|c| c.to_string()).collect::<Vec<_>>().join(", "),
        dwell_ms
    );
    println!(
        "[*] Bounds:          {} max records / {} retry batches",
        MAX_ACTIVE_RECORDS, MAX_QUEUED_BATCHES
    );
    println!("[*] Debug Logging:   {}", debug_probes);
    let stations_on = env::var("STATIONS").map(|v| v.trim() != "0").unwrap_or(true);
    if stations_on {
        println!("[*] Stations:        data-frame RSSI (max {}/min)", MAX_STATIONS);
    } else {
        println!("[*] Stations:        disabled");
    }
    let status_min: u64 = match env::var("STATUS_MIN").ok().and_then(|v| v.trim().parse().ok()).unwrap_or(5) {
        0 => 0,
        m => m.clamp(1, 60),
    };
    if status_min == 0 {
        println!("[*] Status:          disabled");
    } else {
        println!("[*] Status:          every {} min", status_min);
    }

    let lan_min: u64 = match env::var("LAN_SCAN_MIN").ok().and_then(|v| v.trim().parse().ok()).unwrap_or(60) {
        0 => 0,
        m => m.clamp(10, 1440),
    };
    let lan_cidr = env::var("LAN_CIDR").ok().filter(|v| !v.trim().is_empty());
    let lan = if lan_min == 0 {
        println!("[*] LAN scan:        disabled");
        None
    } else {
        match detect_lan(&iface, lan_cidr.as_deref()) {
            Ok(l) => {
                println!(
                    "[*] LAN scan:        {}/{} on {} every {} min",
                    Ipv4Addr::from(l.net),
                    l.prefix,
                    l.dev,
                    lan_min
                );
                Some(l)
            }
            Err(e) => {
                println!("[*] LAN scan:        disabled ({})", e);
                None
            }
        }
    };
    let lan_slot: Arc<Mutex<Option<LanBatch>>> = Arc::new(Mutex::new(None));
    if let Some(l) = lan {
        let slot = Arc::clone(&lan_slot);
        thread::spawn(move || {
            thread::sleep(Duration::from_secs(120));
            loop {
                let items = scan_lan(&l);
                println!("[*] LAN scan {}/{}: {} devices", Ipv4Addr::from(l.net), l.prefix, items.len());
                LAN_DEVICES.store(items.len() as u32, Ordering::Relaxed);
                *slot.lock().unwrap() = Some(LanBatch { time: get_epoch_secs().to_string(), items });
                thread::sleep(Duration::from_secs(lan_min * 60));
            }
        });
    }

    let cache: Arc<Mutex<HashMap<AggregationKey, RawProbeRecord>>> =
        Arc::new(Mutex::new(HashMap::with_capacity(256)));
    let beacon_cache: Arc<Mutex<HashMap<[u8; 6], BeaconStat>>> =
        Arc::new(Mutex::new(HashMap::new()));
    let station_cache: Arc<Mutex<HashMap<[u8; 6], StationStat>>> =
        Arc::new(Mutex::new(HashMap::new()));

    // 1. Channel Hopper Thread (nl80211 with `iw` fallback; channel updated only on success)
    let hopper_iface = iface.clone();
    thread::spawn(move || {
        let mut channels = channels;
        let mut fails = vec![0u8; channels.len()]; // consecutive failed hops per channel
        let mut fell_back = false;
        // A failure only counts against a channel when the hop before it worked: then the adapter is fine
        // and this channel is the problem. A USB hiccup fails every channel and must not strip valid ones.
        let mut prev_ok = false;
        let mut settled = false; // single channel already set
        let mut nl = nl80211::Hopper::open(&hopper_iface)
            .map_err(|e| eprintln!("[!] nl80211 unavailable ({}), using iw", e))
            .ok();
        let mut last_err: Option<Instant> = None;
        let mut idx = 0;
        *ROTATION.lock().unwrap() = channels.clone();
        loop {
            if settled {
                thread::sleep(Duration::from_millis(dwell_ms));
                continue;
            }
            let pos = idx % channels.len();
            let ch = channels[pos];
            idx += 1;
            let mut ok = false;
            if let Some(h) = nl.as_mut() {
                match h.set_channel(ch) {
                    Ok(()) => {
                        ok = true;
                        NL_ACTIVE.store(true, Ordering::Relaxed);
                    }
                    Err(e) => {
                        if last_err.map_or(true, |t| t.elapsed() >= Duration::from_secs(600)) {
                            eprintln!("[!] nl80211 set_channel failed ({}), falling back to iw", e);
                            last_err = Some(Instant::now());
                        }
                    }
                }
            }
            if !ok {
                NL_ACTIVE.store(false, Ordering::Relaxed);
                ok = matches!(
                    Command::new("iw")
                        .args(["dev", &hopper_iface, "set", "channel", &ch.to_string()])
                        .status(),
                    Ok(status) if status.success()
                );
            }
            let counts = prev_ok || channels.len() == 1;
            prev_ok = ok;
            if ok {
                HOP_OK.fetch_add(1, Ordering::Relaxed);
                fails[pos] = 0;
                CURRENT_CHANNEL.store(ch, Ordering::Relaxed);
                settled = channels.len() == 1;
            } else {
                HOP_FAIL.fetch_add(1, Ordering::Relaxed);
                if counts {
                    fails[pos] += 1;
                }
                if fails[pos] >= 3 && !fell_back {
                    eprintln!("[!] channel {} not supported by {}, removed from rotation", ch, hopper_iface);
                    channels.remove(pos);
                    fails.remove(pos);
                    idx = pos;
                    if channels.is_empty() {
                        eprintln!("[!] no usable channel left, falling back to 1, 6, 11");
                        channels = DEFAULT_CHANNELS.to_vec();
                        fails = vec![0; channels.len()];
                        fell_back = true;
                        idx = 0;
                    }
                    *ROTATION.lock().unwrap() = channels.clone();
                }
                thread::sleep(Duration::from_secs(1));
            }
            thread::sleep(Duration::from_millis(dwell_ms));
        }
    });

    // 2. Bounded Batch Sender Thread with Retry Queue & Timeouts
    let flush_cache = Arc::clone(&cache);
    let flush_beacons = Arc::clone(&beacon_cache);
    let flush_stations = Arc::clone(&station_cache);
    let flush_lan = Arc::clone(&lan_slot);
    let flush_url = webapp_url.clone();
    let flush_token = secret_token.clone();
    let status_iface = iface.clone();
    let started = Instant::now();
    thread::spawn(move || {
        let agent = ureq::AgentBuilder::new()
            .timeout_connect(Duration::from_secs(10))
            .timeout_read(Duration::from_secs(15))
            .timeout_write(Duration::from_secs(15))
            // Overall deadline: timeout_read is not re-applied to pooled keep-alive sockets,
            // a reused connection hung in recv for 37 h (2026-10-28).
            .timeout(Duration::from_secs(60))
            .build();

        let mut retry_queue: VecDeque<Batch> = VecDeque::new();
        let mut dropped_batches: u64 = 0;
        let mut next_status = Instant::now() + Duration::from_secs(status_min * 60);

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
                        retry_queue.push_back(Batch::Probes(std::mem::take(&mut batch)));
                    }
                }
                if !batch.is_empty() {
                    if retry_queue.len() >= MAX_QUEUED_BATCHES {
                        retry_queue.pop_front();
                        dropped_batches += 1;
                    }
                    retry_queue.push_back(Batch::Probes(batch));
                }
            }

            let drained_beacons = std::mem::take(&mut *flush_beacons.lock().unwrap());
            if !drained_beacons.is_empty() {
                let items = drained_beacons
                    .into_iter()
                    .map(|(bssid, b)| {
                        let mean = (b.rssi_sum as f32 / b.n as f32 * 10.0).round() / 10.0;
                        let std = beacon_std(&b);
                        (format_mac(&bssid), b.ssid, b.channel, mean, b.min, b.max, b.n, std)
                    })
                    .collect();
                if retry_queue.len() >= MAX_QUEUED_BATCHES {
                    retry_queue.pop_front();
                    dropped_batches += 1;
                }
                retry_queue.push_back(Batch::Beacons(BeaconBatch {
                    time: get_epoch_secs().to_string(),
                    items,
                }));
            }

            let drained_stations = std::mem::take(&mut *flush_stations.lock().unwrap());
            if !drained_stations.is_empty() {
                let items = drained_stations
                    .into_iter()
                    .map(|(sta, s)| {
                        let mean = (s.rssi_sum as f32 / s.n as f32 * 10.0).round() / 10.0;
                        let std = rssi_std(s.n, s.rssi_sum, s.rssi_sq_sum);
                        (format_mac(&sta), format_mac(&s.bssid), s.channel, mean, s.min, s.max, s.n, std)
                    })
                    .collect();
                if retry_queue.len() >= MAX_QUEUED_BATCHES {
                    retry_queue.pop_front();
                    dropped_batches += 1;
                }
                retry_queue.push_back(Batch::Stations(StationBatch {
                    time: get_epoch_secs().to_string(),
                    items,
                }));
            }

            if let Some(b) = flush_lan.lock().unwrap().take() {
                if retry_queue.len() >= MAX_QUEUED_BATCHES {
                    retry_queue.pop_front();
                    dropped_batches += 1;
                }
                retry_queue.push_back(Batch::Lan(b));
            }

            if status_min > 0 && Instant::now() >= next_status {
                next_status = Instant::now() + Duration::from_secs(status_min * 60);
                let item = collect_status(started, &status_iface, dwell_ms, retry_queue.len(), dropped_batches);
                if retry_queue.len() >= MAX_QUEUED_BATCHES {
                    retry_queue.pop_front();
                    dropped_batches += 1;
                }
                retry_queue.push_back(Batch::Status(StatusBatch { time: get_epoch_secs().to_string(), item }));
            }

            if retry_queue.is_empty() || flush_url.is_empty() {
                continue;
            }

            while let Some(items_to_send) = retry_queue.pop_front() {
                println!(
                    "[{}] Pushing batch ({} groups, {} queued, {} dropped_total)...",
                    get_epoch_secs(),
                    match &items_to_send {
                        Batch::Probes(v) => v.len(),
                        Batch::Beacons(b) => b.items.len(),
                        Batch::Stations(b) => b.items.len(),
                        Batch::Lan(b) => b.items.len(),
                        Batch::Status(_) => 1,
                    },
                    retry_queue.len(),
                    dropped_batches
                );

                let req = agent
                    .post(&flush_url)
                    .set("Content-Type", "application/json");
                let (expected, result) = match &items_to_send {
                    Batch::Probes(v) => (
                        "probes_saved",
                        req.send_json(&BatchPayload {
                            token: flush_token.clone(),
                            msg_type: "probes",
                            time: None,
                            items: v,
                        }),
                    ),
                    Batch::Beacons(b) => (
                        "beacons_saved",
                        req.send_json(&BatchPayload {
                            token: flush_token.clone(),
                            msg_type: "beacons",
                            time: Some(&b.time),
                            items: &b.items,
                        }),
                    ),
                    Batch::Stations(b) => (
                        "stations_saved",
                        req.send_json(&BatchPayload {
                            token: flush_token.clone(),
                            msg_type: "stations",
                            time: Some(&b.time),
                            items: &b.items,
                        }),
                    ),
                    Batch::Lan(b) => (
                        "lan_saved",
                        req.send_json(&BatchPayload {
                            token: flush_token.clone(),
                            msg_type: "lan",
                            time: Some(&b.time),
                            items: &b.items,
                        }),
                    ),
                    Batch::Status(b) => (
                        "status_saved",
                        req.send_json(&BatchPayload {
                            token: flush_token.clone(),
                            msg_type: "status",
                            time: Some(&b.time),
                            items: std::slice::from_ref(&b.item),
                        }),
                    ),
                };

                match result {
                    Ok(resp) => {
                        let status = resp.status();
                        let body = resp.into_string().unwrap_or_default();
                        if push_ignored(&body) {
                            eprintln!("[!] Webhook does not know this batch type ({}): dropped", expected);
                            dropped_batches += 1;
                            continue;
                        }
                        if !push_accepted(&body, expected) {
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

        println!("[*] ProbeHound v0.6.7 active in monitor mode...");

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
                FRAMES.fetch_add(1, Ordering::Relaxed);
                if rtap.bad_fcs {
                    BAD_FCS.fetch_add(1, Ordering::Relaxed);
                }
                let now_secs = get_epoch_secs();
                if let Some((record, key)) = parse_probe_frame(&buf[..len], &rtap, now_secs) {
                    PROBES.fetch_add(1, Ordering::Relaxed);
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
                } else if let Some((bssid, ssid, channel, rssi)) =
                    parse_beacon_frame(&buf[..len], &rtap)
                {
                    BEACONS.fetch_add(1, Ordering::Relaxed);
                    if debug_probes {
                        println!(
                            "Beacon: {} | Ch:{:2} | {} dBm | SSID: {}",
                            format_mac(&bssid),
                            channel,
                            rssi,
                            ssid
                        );
                    }
                    let mut lock = beacon_cache.lock().unwrap();
                    let _ = ingest_beacon(&mut lock, bssid, ssid, channel, rssi);
                } else if stations_on {
                    if let Some((sta, bssid, channel, rssi)) = parse_station_frame(&buf[..len], &rtap) {
                        let mut lock = station_cache.lock().unwrap();
                        if ingest_station(&mut lock, sta, bssid, channel, rssi) {
                            STATIONS_SEEN.fetch_add(1, Ordering::Relaxed);
                        } else {
                            STATIONS_OVERFLOW.fetch_add(1, Ordering::Relaxed);
                        }
                    }
                }
            } else {
                DROPPED_FRAMES.fetch_add(1, Ordering::Relaxed);
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
        assert!(push_accepted(r#"{"status":"probes_saved","count":3}"#, "probes_saved"));
        assert!(!push_accepted(r#"{"status":"forbidden"}"#, "probes_saved"));
        assert!(!push_accepted(r#"{"error":"x"}"#, "probes_saved"));
        assert!(!push_accepted("<html>", "probes_saved"));
        assert!(!push_accepted("", "probes_saved"));
    }

    /// Builds a beacon from the probe packet builder: swaps the frame type, BSSID and fixed fields
    fn build_beacon(bssid: [u8; 6], ies: &[u8], rssi: Option<i8>) -> Vec<u8> {
        let mut pkt = build_test_packet(0x00, rssi, [0; 6], 0, &[], None);
        let h = pkt.len() - 24;
        pkt[h] = 0x80;
        pkt[h + 16..h + 22].copy_from_slice(&bssid);
        pkt.extend_from_slice(&[0; 12]); // timestamp + interval + capability
        pkt.extend_from_slice(ies);
        pkt
    }

    #[test]
    fn test_beacon_parsed_and_ds_channel_checked() {
        let bssid = [0x02, 0x11, 0x22, 0x33, 0x44, 0x55];
        let ies = [0x00, 0x02, b'A', b'P', 0x03, 0x01, 6];
        let pkt = build_beacon(bssid, &ies, Some(-61));
        let rtap = parse_radiotap(&pkt).unwrap();
        assert_eq!(
            parse_beacon_frame(&pkt, &rtap),
            Some((bssid, "AP".to_string(), 6, -61))
        );
        // Not a probe
        assert!(parse_probe_frame(&pkt, &rtap, 0).is_none());

        // DS channel 7 while received on 6 -> leakage, dropped
        let pkt = build_beacon(bssid, &[0x00, 0x00, 0x03, 0x01, 7], Some(-61));
        assert!(parse_beacon_frame(&pkt, &parse_radiotap(&pkt).unwrap()).is_none());

        // Hidden SSID without DS element is accepted; missing RSSI is dropped
        let pkt = build_beacon(bssid, &[0x00, 0x00], Some(-70));
        let b = parse_beacon_frame(&pkt, &parse_radiotap(&pkt).unwrap()).unwrap();
        assert_eq!(b.1, "<Hidden>");
        let pkt = build_beacon(bssid, &[0x00, 0x00], None);
        assert!(parse_beacon_frame(&pkt, &parse_radiotap(&pkt).unwrap()).is_none());
    }

    #[test]
    fn test_beacon_5ghz_without_ds_tag() {
        let bssid = [0x02, 0x11, 0x22, 0x33, 0x44, 0x55];
        let mut pkt = build_beacon(bssid, &[0x00, 0x02, b'A', b'P'], Some(-55));
        pkt[10..12].copy_from_slice(&5180u16.to_le_bytes());
        let rtap = parse_radiotap(&pkt).unwrap();
        assert_eq!(rtap.channel, 36);
        assert_eq!(parse_beacon_frame(&pkt, &rtap), Some((bssid, "AP".to_string(), 36, -55)));
    }

    #[test]
    fn test_channel_freq_mapping() {
        for (ch, f) in [(1u8, 2412u16), (6, 2437), (13, 2472), (14, 2484), (36, 5180), (165, 5825), (177, 5885)] {
            assert_eq!(freq_to_channel(f), Some(ch));
            assert_eq!(channel_to_freq(ch), Some(f as u32));
        }
        for f in [0u16, 2411, 2417 + 1, 4900, 5955, 6000] {
            assert_eq!(freq_to_channel(f), None);
        }
        for c in [0u8, 15, 31, 178, 255] {
            assert_eq!(channel_to_freq(c), None);
        }
    }

    #[test]
    fn test_parse_channels() {
        assert_eq!(parse_channels("1, 6,11,36,abc,6,200"), vec![1, 6, 11, 36]);
        assert_eq!(parse_channels(""), vec![1, 6, 11]);
        assert_eq!(parse_channels("0,15,x"), vec![1, 6, 11]);
        assert_eq!(parse_channels("36"), vec![36]);
    }

    #[test]
    fn test_ingest_beacon_aggregates_and_is_bounded() {
        let mut map = HashMap::new();
        let a = [1u8; 6];
        for r in [-60, -70, -65] {
            assert!(ingest_beacon(&mut map, a, "x".into(), 6, r));
        }
        let s = &map[&a];
        assert_eq!((s.rssi_sum, s.n, s.min, s.max), (-195, 3, -70, -60));
        assert_eq!(s.rssi_sq_sum, 3600 + 4900 + 4225);

        for i in 0..MAX_BEACON_BSSIDS {
            ingest_beacon(&mut map, [2, i as u8, 0, 0, 0, 0], "y".into(), 1, -50);
        }
        assert_eq!(map.len(), MAX_BEACON_BSSIDS);
        assert!(!ingest_beacon(&mut map, [9u8; 6], "z".into(), 1, -50));
        assert!(ingest_beacon(&mut map, a, "x".into(), 6, -60));
    }

    #[test]
    fn test_push_accepted_status_mismatch() {
        assert!(push_accepted(r#"{"status":"beacons_saved"}"#, "beacons_saved"));
        assert!(!push_accepted(r#"{"status":"probes_saved"}"#, "beacons_saved"));
        assert!(!push_accepted(r#"{"status":"beacons_saved"}"#, "probes_saved"));
    }

    #[test]
    fn test_parse_arp() {
        let arp = "IP address       HW type     Flags       HW address            Mask     Device\n\
192.168.1.5      0x1         0x2         AA:BB:CC:DD:EE:01     *        eth0\n\
192.168.1.6      0x1         0x0         aa:bb:cc:dd:ee:02     *        eth0\n\
192.168.1.7      0x1         0x2         aa:bb:cc:dd:ee:03     *        wlan1\n\
192.168.1.8      0x1         0x2         00:00:00:00:00:00     *        eth0\n\
10.0.0.9         0x1         0x2         aa:bb:cc:dd:ee:04     *        eth0\n\
192.168.1.10     0x1         0x2         aa:bb:cc:dd:ee:01     *        eth0\n";
        let net = u32::from(Ipv4Addr::new(192, 168, 1, 0));
        let got = parse_arp(arp, "eth0", net, prefix_mask(24));
        assert_eq!(got, vec![("aa:bb:cc:dd:ee:01".to_string(), "192.168.1.5".to_string())]);
    }

    #[test]
    fn test_hosts() {
        assert_eq!(hosts(u32::from(Ipv4Addr::new(10, 0, 0, 4)), 30, 0).count(), 2);
        let net = u32::from(Ipv4Addr::new(192, 168, 1, 0));
        let own = net + 7;
        let v: Vec<_> = hosts(net, 24, own).collect();
        assert_eq!(v.len(), 253);
        assert!(!v.contains(&Ipv4Addr::from(own)) && !v.contains(&Ipv4Addr::from(net)));
        assert!(!v.contains(&Ipv4Addr::new(192, 168, 1, 255)));
    }

    #[test]
    fn test_lan_payload() {
        assert!(push_accepted(r#"{"status":"lan_saved"}"#, "lan_saved"));
        let items = vec![("aa:bb".to_string(), "192.168.1.5".to_string())];
        let p = BatchPayload { token: "t".into(), msg_type: "lan", time: Some("1"), items: &items };
        let j = serde_json::to_string(&p).unwrap();
        assert!(j.contains(r#""type":"lan""#) && j.contains(r#""items":[["aa:bb","192.168.1.5"]]"#));
    }

    #[test]
    fn test_push_ignored() {
        assert!(push_ignored(r#"{"status":"ignored"}"#));
        assert!(!push_ignored(r#"{"status":"forbidden"}"#));
        assert!(!push_ignored("<html>quota</html>"));
    }

    #[test]
    fn test_status_helpers_and_payload() {
        assert_eq!(parse_loadavg("0.42 0.30 0.20 1/80 1234\n"), Some(0.42));
        assert_eq!(parse_loadavg(""), None);
        assert_eq!(parse_vmrss("Name:\tx\nVmRSS:\t    1234 kB\nThreads: 3\n"), Some(1234));
        assert_eq!(parse_vmrss("Name:\tx\n"), None);
        assert_eq!(parse_throttled("0x50005\n"), Some(0x50005));
        assert_eq!(parse_throttled("throttled=0x0"), Some(0));
        assert_eq!(parse_throttled("junk"), None);

        let r = collect_status(Instant::now(), "wlan0", 1000, 2, 3);
        let p = BatchPayload { token: "t".into(), msg_type: "status", time: Some("1"), items: std::slice::from_ref(&r) };
        let j = serde_json::to_string(&p).unwrap();
        assert!(j.contains(r#""type":"status""#));
        for f in [
            "version", "uptime_s", "iface", "channels", "dwell_ms", "nl80211", "hop_ok", "hop_fail", "frames",
            "probes", "beacons", "stations", "stations_overflow", "bad_fcs", "dropped_frames", "queued", "dropped_total", "lan_devices", "load1",
            "rss_kb", "throttled", "temp_c",
        ] {
            assert!(j.contains(&format!("\"{}\":", f)), "missing {}", f);
        }
        assert!(push_accepted(r#"{"status":"status_saved"}"#, "status_saved"));
    }

    #[test]
    fn test_beacon_std() {
        let mut map = HashMap::new();
        let a = [1u8; 6];
        ingest_beacon(&mut map, a, "x".into(), 6, -60);
        let single = beacon_std(&map[&a]);
        assert_eq!(single, None);
        for r in [-60, -62, -58] {
            ingest_beacon(&mut map, a, "x".into(), 6, r);
        }
        let sd = beacon_std(&map[&a]);
        assert_eq!(sd, Some(1.4));

        let item = |std| ("aa".to_string(), "s".to_string(), 6u8, -60.0f32, -62i8, -58i8, 4u32, std);
        assert!(serde_json::to_string(&item(sd)).unwrap().ends_with(",1.4]"));
        assert!(serde_json::to_string(&item(single)).unwrap().ends_with(",null]"));
    }

    /// Builds a data frame from the probe packet builder: FC, flags, addr1 (bssid) and addr2 (sta)
    fn build_data(fc0: u8, flags: u8, bssid: [u8; 6], sta: [u8; 6], rssi: Option<i8>) -> Vec<u8> {
        let mut pkt = build_test_packet(0x00, rssi, [0; 6], 0, &[], None);
        let h = pkt.len() - 24;
        pkt[h] = fc0;
        pkt[h + 1] = flags;
        pkt[h + 4..h + 10].copy_from_slice(&bssid);
        pkt[h + 10..h + 16].copy_from_slice(&sta);
        pkt
    }

    #[test]
    fn test_parse_station_frame() {
        let (bssid, sta) = ([2u8, 1, 1, 1, 1, 1], [2u8, 2, 2, 2, 2, 2]);
        let parse = |p: &Vec<u8>| parse_station_frame(p, &parse_radiotap(p).unwrap());
        // QoS data (0x88) and null data (0x48), ToDS
        assert_eq!(parse(&build_data(0x88, 0x01, bssid, sta, Some(-47))), Some((sta, bssid, 6, -47)));
        assert!(parse(&build_data(0x48, 0x01, bssid, sta, Some(-47))).is_some());
        assert!(parse(&build_data(0x88, 0x02, bssid, sta, Some(-47))).is_none()); // FromDS
        assert!(parse(&build_data(0x88, 0x03, bssid, sta, Some(-47))).is_none()); // WDS
        assert!(parse(&build_data(0x88, 0x00, bssid, sta, Some(-47))).is_none()); // IBSS
        assert!(parse(&build_data(0x40, 0x01, bssid, sta, Some(-47))).is_none()); // mgmt
        assert!(parse(&build_data(0x88, 0x01, bssid, [0x03, 2, 2, 2, 2, 2], Some(-47))).is_none()); // multicast sta
        assert!(parse(&build_data(0x88, 0x01, bssid, sta, None)).is_none());
        let short = build_data(0x88, 0x01, bssid, sta, Some(-47));
        assert!(parse_station_frame(&short[..short.len() - 1], &parse_radiotap(&short[..short.len() - 1]).unwrap()).is_none());
    }

    #[test]
    fn test_station_cap_and_json() {
        let mut map = HashMap::new();
        for i in 0..MAX_STATIONS {
            assert!(ingest_station(&mut map, [2, i as u8, 0, 0, 0, 0], [2; 6], 6, -50));
        }
        assert!(!ingest_station(&mut map, [4u8; 6], [2; 6], 6, -50)); // 129th distinct
        assert!(ingest_station(&mut map, [2, 0, 0, 0, 0, 0], [3; 6], 6, -60));
        let s = &map[&[2, 0, 0, 0, 0, 0]];
        assert_eq!((s.n, s.min, s.max, s.bssid), (2, -60, -50, [3; 6]));
        let sd = rssi_std(s.n, s.rssi_sum, s.rssi_sq_sum);
        assert_eq!(sd, Some(5.0));
        let item = |std| ("a".to_string(), "b".to_string(), 6u8, -55.0f32, -60i8, -50i8, 2u32, std);
        let p = BatchPayload { token: "t".into(), msg_type: "stations", time: Some("1"), items: &[item(sd)] };
        let j = serde_json::to_string(&p).unwrap();
        assert!(j.contains(r#""type":"stations""#) && j.contains(",5.0]]"));
        assert!(serde_json::to_string(&item(None)).unwrap().ends_with(",null]"));
    }
}
