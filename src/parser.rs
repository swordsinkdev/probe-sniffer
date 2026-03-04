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
    /// Information-element (IE) fingerprint for device identification
    /// despite MAC randomization.  See [`IeFingerprint`].
    pub ie_fingerprint: Option<IeFingerprint>,
}

/// A fingerprint derived from the Information Elements (IEs) embedded
/// in a probe request frame body.
///
/// Research shows that the order and contents of IEs are highly
/// device-specific and persist across MAC address changes, making them
/// effective for tracking and de-randomization:
///
/// - Martin et al., *"Defeating MAC Address Randomization Through
///   Timing Attacks"*, WiSec 2016, demonstrated that IE order +
///   supported-rate sets uniquely identify device models and often
///   individual devices.
/// - Matte et al., *"Decomposition of MAC address structure for
///   granular device inference"*, 2017, showed that the combination
///   of tag ordering, HT capabilities, and vendor-specific IEs
///   creates a near-unique per-model signature.
///
/// The fingerprint is a compact hash of:
/// 1. Ordered list of IE tag numbers (e.g. `[0, 1, 50, 45, 127, 221]`).
/// 2. Supported rates (tag 1) content.
/// 3. Extended supported rates (tag 50) content.
/// 4. HT capabilities (tag 45) raw bytes.
/// 5. Count of vendor-specific (tag 221) IEs.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct IeFingerprint {
    /// The ordered sequence of IE tag IDs as they appear in the frame.
    pub tag_order: Vec<u8>,
    /// Supported rates IE content (tag 1), if present.
    pub supported_rates: Option<Vec<u8>>,
    /// Extended supported rates IE content (tag 50), if present.
    pub extended_rates: Option<Vec<u8>>,
    /// HT capabilities IE (tag 45) raw bytes, if present.
    pub ht_capabilities: Option<Vec<u8>>,
    /// Number of vendor-specific IEs (tag 221).
    pub vendor_ie_count: u8,
    /// A compact 64-bit hash of all the above for fast comparison.
    pub hash: u64,
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
    let ie_fingerprint = extract_ie_fingerprint(body);

    Some(ProbeRequest {
        source_mac,
        ssid,
        signal_dbm,
        channel_freq,
        ie_fingerprint,
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

// ---------------------------------------------------------------------------
// IE fingerprinting for device identification despite MAC randomization
// ---------------------------------------------------------------------------

/// Extract an [`IeFingerprint`] from the tagged-parameter body of a
/// probe request frame.
///
/// This walks every IE in order and collects:
/// - The tag-ID sequence (critical for fingerprinting — see Martin
///   et al. WiSec 2016).
/// - Supported rates (tag 1), extended supported rates (tag 50), and
///   HT capabilities (tag 45).
/// - A count of vendor-specific IEs (tag 221).
///
/// All of these are hashed into a compact 64-bit value via FNV-1a for
/// fast lookup and comparison.
fn extract_ie_fingerprint(body: &[u8]) -> Option<IeFingerprint> {
    let mut tag_order: Vec<u8> = Vec::new();
    let mut supported_rates: Option<Vec<u8>> = None;
    let mut extended_rates: Option<Vec<u8>> = None;
    let mut ht_capabilities: Option<Vec<u8>> = None;
    let mut vendor_ie_count: u8 = 0;

    let mut offset = 0;
    while offset + 2 <= body.len() {
        let tag = body[offset];
        let len = body[offset + 1] as usize;
        offset += 2;
        if offset + len > body.len() {
            break;
        }

        tag_order.push(tag);

        match tag {
            1 => {
                supported_rates = Some(body[offset..offset + len].to_vec());
            }
            45 => {
                ht_capabilities = Some(body[offset..offset + len].to_vec());
            }
            50 => {
                extended_rates = Some(body[offset..offset + len].to_vec());
            }
            221 => {
                vendor_ie_count = vendor_ie_count.saturating_add(1);
            }
            _ => {}
        }

        offset += len;
    }

    if tag_order.is_empty() {
        return None;
    }

    // Compute FNV-1a hash over all fingerprint components.
    let mut hash = fnv1a_hash(&tag_order);
    if let Some(ref rates) = supported_rates {
        hash ^= fnv1a_hash(rates);
    }
    if let Some(ref ext) = extended_rates {
        hash ^= fnv1a_hash(ext);
    }
    if let Some(ref ht) = ht_capabilities {
        hash ^= fnv1a_hash(ht);
    }
    hash ^= vendor_ie_count as u64;

    Some(IeFingerprint {
        tag_order,
        supported_rates,
        extended_rates,
        ht_capabilities,
        vendor_ie_count,
        hash,
    })
}

/// FNV-1a 64-bit hash.  Fast, non-cryptographic, good distribution.
fn fnv1a_hash(data: &[u8]) -> u64 {
    const FNV_OFFSET: u64 = 0xcbf29ce484222325;
    const FNV_PRIME: u64 = 0x100000001b3;
    let mut hash = FNV_OFFSET;
    for &byte in data {
        hash ^= byte as u64;
        hash = hash.wrapping_mul(FNV_PRIME);
    }
    hash
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

    #[test]
    fn test_ie_fingerprint_basic() {
        // SSID tag (0), then Supported Rates tag (1), then HT Caps (45)
        let body = [
            0x00, 0x04, b'T', b'e', b's', b't', // Tag 0: SSID "Test"
            0x01, 0x02, 0x82, 0x84,              // Tag 1: Supported rates
            0x2D, 0x02, 0xEF, 0x01,              // Tag 45 (0x2D): HT caps
        ];
        let fp = extract_ie_fingerprint(&body).unwrap();
        assert_eq!(fp.tag_order, vec![0, 1, 45]);
        assert_eq!(fp.supported_rates, Some(vec![0x82, 0x84]));
        assert_eq!(fp.ht_capabilities, Some(vec![0xEF, 0x01]));
        assert_eq!(fp.extended_rates, None);
        assert_eq!(fp.vendor_ie_count, 0);
    }

    #[test]
    fn test_ie_fingerprint_same_device_different_ssid() {
        // Same IEs except SSID content → should have same tag_order
        let body_a = [
            0x00, 0x03, b'F', b'o', b'o',
            0x01, 0x02, 0x82, 0x84,
        ];
        let body_b = [
            0x00, 0x03, b'B', b'a', b'r',
            0x01, 0x02, 0x82, 0x84,
        ];
        let fp_a = extract_ie_fingerprint(&body_a).unwrap();
        let fp_b = extract_ie_fingerprint(&body_b).unwrap();
        assert_eq!(fp_a.tag_order, fp_b.tag_order);
        assert_eq!(fp_a.supported_rates, fp_b.supported_rates);
    }

    #[test]
    fn test_ie_fingerprint_vendor_count() {
        let body = [
            0x00, 0x01, b'X',                    // SSID
            0xDD, 0x03, 0x00, 0x50, 0xF2,       // Vendor-specific (221)
            0xDD, 0x02, 0xAA, 0xBB,             // Another vendor-specific
        ];
        let fp = extract_ie_fingerprint(&body).unwrap();
        assert_eq!(fp.vendor_ie_count, 2);
        assert_eq!(fp.tag_order, vec![0, 221, 221]);
    }
}
