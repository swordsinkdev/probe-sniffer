//! 802.11 frame and Radiotap header parsing.
//!
//! Extracts probe request frames, their SSID, source MAC, and signal strength
//! from raw pcap packets captured in monitor mode.

/// Parsed probe request information.
#[derive(Debug, Clone)]
pub struct ProbeRequest {
    /// Source MAC address (may be randomized).
    pub source_mac: [u8; 6],
    /// Requested SSID (empty string for broadcast probes).
    pub ssid: String,
    /// Signal strength in dBm (from Radiotap header), if available.
    pub signal_dbm: Option<i8>,
    /// Channel frequency in MHz (from Radiotap header), if available.
    pub channel_freq: Option<u16>,
}

// ---------------------------------------------------------------------------
// Radiotap header parsing
// ---------------------------------------------------------------------------

/// Field metadata: (bit index, size in bytes, alignment).
const RADIOTAP_FIELDS: &[(u8, usize, usize)] = &[
    (0, 8, 8),  // TSFT
    (1, 1, 1),  // Flags
    (2, 1, 1),  // Rate
    (3, 4, 2),  // Channel (freq u16 + flags u16)
    (4, 2, 1),  // FHSS
    (5, 1, 1),  // Antenna Signal dBm
    (6, 1, 1),  // Antenna Noise dBm
    (7, 2, 2),  // Lock Quality
    (8, 2, 2),  // TX Attenuation
    (9, 2, 2),  // dB TX Attenuation
    (10, 1, 1), // dBm TX Power
    (11, 1, 1), // Antenna index
    (12, 1, 1), // dB Antenna Signal
    (13, 1, 1), // dB Antenna Noise
];

fn align_up(offset: usize, align: usize) -> usize {
    (offset + align - 1) & !(align - 1)
}

/// Result of radiotap header parsing.
struct RadiotapInfo {
    /// Total header length (offset where the 802.11 frame begins).
    header_len: usize,
    /// Signal strength in dBm, if present.
    signal_dbm: Option<i8>,
    /// Channel frequency in MHz, if present.
    channel_freq: Option<u16>,
}

/// Parse the Radiotap header and extract signal strength + channel frequency.
fn parse_radiotap(data: &[u8]) -> Option<RadiotapInfo> {
    if data.len() < 8 {
        return None;
    }
    let version = data[0];
    if version != 0 {
        log::warn!("Unsupported radiotap version {version}");
        return None;
    }
    let header_len = u16::from_le_bytes([data[2], data[3]]) as usize;
    if data.len() < header_len {
        return None;
    }
    let present = u32::from_le_bytes([data[4], data[5], data[6], data[7]]);

    // Walk through present fields to find signal strength.
    // Account for possible extended present bitmasks (bit 31 set).
    let mut bitmask_count = 1u32;
    {
        let mut p = present;
        while p & (1 << 31) != 0 {
            bitmask_count += 1;
            let base = 4 + (bitmask_count as usize) * 4;
            if data.len() < base + 4 {
                break;
            }
            p = u32::from_le_bytes([data[base], data[base + 1], data[base + 2], data[base + 3]]);
        }
    }

    let fields_start = 4 + (bitmask_count as usize) * 4;
    let mut offset = fields_start;
    let mut signal_dbm: Option<i8> = None;
    let mut channel_freq: Option<u16> = None;

    for &(bit, size, align) in RADIOTAP_FIELDS {
        if present & (1 << bit) == 0 {
            continue; // field not present
        }
        offset = align_up(offset, align);
        if offset + size > header_len {
            break;
        }
        match bit {
            3 => {
                // Channel: u16 frequency + u16 flags
                channel_freq =
                    Some(u16::from_le_bytes([data[offset], data[offset + 1]]));
            }
            5 => {
                signal_dbm = Some(data[offset] as i8);
            }
            _ => {}
        }
        offset += size;
    }

    Some(RadiotapInfo {
        header_len,
        signal_dbm,
        channel_freq,
    })
}

// ---------------------------------------------------------------------------
// 802.11 Management frame parsing
// ---------------------------------------------------------------------------

const IEEE80211_FC_TYPE_MGMT: u8 = 0;
const IEEE80211_FC_SUBTYPE_PROBE_REQ: u8 = 4;

/// Minimum management frame header size (FC + Dur + Addr1 + Addr2 + Addr3 + SeqCtl).
const MGMT_HEADER_LEN: usize = 24;

/// Try to parse a raw pcap packet as a probe request.
///
/// `dlt` is the pcap datalink type:
/// - 127 = DLT_IEEE802_11_RADIO (Radiotap + 802.11)
/// - 105 = DLT_IEEE802_11       (raw 802.11)
pub fn parse_probe_request(data: &[u8], dlt: i32) -> Option<ProbeRequest> {
    let (dot11_data, signal_dbm, channel_freq) = match dlt {
        127 => {
            // Radiotap + 802.11
            let rt = parse_radiotap(data)?;
            if data.len() < rt.header_len {
                return None;
            }
            (&data[rt.header_len..], rt.signal_dbm, rt.channel_freq)
        }
        105 => {
            // Raw 802.11 — no radiotap, no signal info
            (data, None, None)
        }
        _ => {
            log::debug!("Unsupported datalink type {dlt}");
            return None;
        }
    };

    if dot11_data.len() < MGMT_HEADER_LEN {
        return None;
    }

    // Frame Control field (2 bytes, little-endian).
    let fc0 = dot11_data[0];
    let frame_type = (fc0 >> 2) & 0x03;
    let frame_subtype = (fc0 >> 4) & 0x0F;

    if frame_type != IEEE80211_FC_TYPE_MGMT || frame_subtype != IEEE80211_FC_SUBTYPE_PROBE_REQ {
        return None;
    }

    // Address 2 (Source Address) starts at offset 10.
    let mut source_mac = [0u8; 6];
    source_mac.copy_from_slice(&dot11_data[10..16]);

    // Tagged parameters start at offset 24.
    let body = &dot11_data[MGMT_HEADER_LEN..];
    let ssid = parse_ssid_tag(body).unwrap_or_default();

    Some(ProbeRequest {
        source_mac,
        ssid,
        signal_dbm,
        channel_freq,
    })
}

/// Walk the tagged parameters and extract the SSID (tag 0).
fn parse_ssid_tag(body: &[u8]) -> Option<String> {
    let mut offset = 0;
    while offset + 2 <= body.len() {
        let tag = body[offset];
        let len = body[offset + 1] as usize;
        offset += 2;
        if offset + len > body.len() {
            break;
        }
        if tag == 0 {
            // SSID tag
            return Some(String::from_utf8_lossy(&body[offset..offset + len]).into_owned());
        }
        offset += len;
    }
    None
}

/// Format a MAC address as a colon-separated hex string.
pub fn format_mac(mac: &[u8; 6]) -> String {
    format!(
        "{:02X}:{:02X}:{:02X}:{:02X}:{:02X}:{:02X}",
        mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]
    )
}

/// Check whether a MAC address looks like a locally-administered (randomized) address.
/// Bit 1 of the first octet is the U/L bit (1 = locally administered).
pub fn is_randomized_mac(mac: &[u8; 6]) -> bool {
    mac[0] & 0x02 != 0
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_format_mac() {
        let mac = [0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF];
        assert_eq!(format_mac(&mac), "AA:BB:CC:DD:EE:FF");
    }

    #[test]
    fn test_randomized_mac() {
        assert!(is_randomized_mac(&[0xDA, 0x00, 0x00, 0x00, 0x00, 0x00])); // bit 1 set
        assert!(!is_randomized_mac(&[0x00, 0x11, 0x22, 0x33, 0x44, 0x55]));
    }

    #[test]
    fn test_parse_ssid_tag() {
        // Tag 0, length 4, "Test"
        let body = [0x00, 0x04, b'T', b'e', b's', b't'];
        assert_eq!(parse_ssid_tag(&body), Some("Test".to_string()));
    }
}
