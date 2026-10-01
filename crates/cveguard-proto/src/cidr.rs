//! IPv4 allow-list parsing for isolate plans.
//!
//! Threats: a world route or a silently widened prefix would isolate the
//! operator out, or would leave the fleet routable. Parsing fails closed.
//! Host bits are masked only after the prefix is accepted, so the plan shows
//! the network that would actually be allowed.

use crate::error::{Error, invalid};

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct Net {
    pub network: u32,
    pub prefix: u8,
}

impl Net {
    #[must_use]
    pub fn loopback() -> Self {
        Self {
            network: 127 << 24,
            prefix: 8,
        }
    }

    #[must_use]
    pub fn format(self) -> String {
        let n = self.network;
        format!(
            "{}.{}.{}.{}/{}",
            n >> 24,
            (n >> 16) & 0xff,
            (n >> 8) & 0xff,
            n & 0xff,
            self.prefix
        )
    }
}

pub fn parse_ipv4(s: &str) -> Result<[u8; 4], Error> {
    let mut out = [0u8; 4];
    let mut parts = s.split('.');
    for slot in &mut out {
        let Some(part) = parts.next() else {
            return Err(invalid("cidr rejected"));
        };
        if part.is_empty() || (part.len() > 1 && part.starts_with('0')) {
            return Err(invalid("cidr rejected"));
        }
        if !part.bytes().all(|b| b.is_ascii_digit()) {
            return Err(invalid("cidr rejected"));
        }
        let value: u16 = part.parse().map_err(|_| invalid("cidr rejected"))?;
        if value > 255 {
            return Err(invalid("cidr rejected"));
        }
        *slot = u8::try_from(value).map_err(|_| invalid("cidr rejected"))?;
    }
    if parts.next().is_some() {
        return Err(invalid("cidr rejected"));
    }
    Ok(out)
}

pub fn format_ipv4(octets: [u8; 4]) -> String {
    format!("{}.{}.{}.{}", octets[0], octets[1], octets[2], octets[3])
}

/// Accept a host (`a.b.c.d` → /32) or a CIDR with prefix 16..=32.
/// `0.0.0.0/0` and `::/0` are world routes. `0.0.0.0` with any prefix is rejected.
pub fn parse_allow(s: &str) -> Result<Net, Error> {
    if s == "0.0.0.0/0" || s == "::/0" {
        return Err(invalid("world cidr rejected"));
    }
    if s.is_empty() || s.contains(':') || s.contains(char::is_whitespace) {
        return Err(invalid("cidr rejected"));
    }
    let (addr_s, prefix) = if let Some((addr, prefix_s)) = s.split_once('/') {
        if prefix_s.is_empty()
            || (prefix_s.len() > 1 && prefix_s.starts_with('0'))
            || !prefix_s.bytes().all(|b| b.is_ascii_digit())
        {
            return Err(invalid("cidr rejected"));
        }
        let prefix: u8 = prefix_s.parse().map_err(|_| invalid("cidr rejected"))?;
        (addr, prefix)
    } else {
        (s, 32)
    };
    if !(16..=32).contains(&prefix) {
        return Err(invalid("cidr rejected"));
    }
    let octets = parse_ipv4(addr_s)?;
    let addr = u32::from_be_bytes(octets);
    if addr == 0 {
        return Err(invalid("cidr rejected"));
    }
    let shift = 32 - u32::from(prefix);
    let mask = u32::MAX
        .checked_shl(shift)
        .ok_or_else(|| invalid("cidr rejected"))?;
    let network = addr & mask;
    if network == 0 {
        return Err(invalid("cidr rejected"));
    }
    Ok(Net { network, prefix })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_world_leading_zero_short_prefix_and_zero_address() {
        assert!(
            parse_allow("0.0.0.0/0")
                .unwrap_err()
                .to_string()
                .contains("world")
        );
        assert!(
            parse_allow("::/0")
                .unwrap_err()
                .to_string()
                .contains("world")
        );
        assert!(parse_allow("01.2.3.4/32").is_err());
        assert!(parse_allow("10.0.0.0/8").is_err());
        assert!(parse_allow("0.0.0.0/32").is_err());
        assert!(parse_allow("10.1.2.0/15").is_err());
    }

    #[test]
    fn masks_host_bits_on_display() {
        let net = parse_allow("10.1.2.3/16").unwrap();
        assert_eq!(net.format(), "10.1.0.0/16");
        assert_eq!(parse_allow("192.0.2.10").unwrap().format(), "192.0.2.10/32");
        assert_eq!(format_ipv4([192, 0, 2, 10]), "192.0.2.10");
    }
}
