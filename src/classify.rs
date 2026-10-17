//! Address classification against the IANA IPv4 and IPv6 Special-Purpose
//! Address Registries.
//!
//! The classifier is deliberately stricter than "globally reachable":
//!
//! - Every block of both registries is refused, including the few anycast
//!   service blocks the registry marks globally reachable (AS112, AMT, PCP,
//!   TURN, ORCHIDv2, DRIP). No webhook receiver lives there.
//! - IPv4 multicast (224.0.0.0/4) and IPv6 multicast and site-local are
//!   refused although the special-purpose registries do not list them.
//! - Any IPv6 address outside 2000::/3, the only space IANA allocates as
//!   global unicast, is refused.
//! - IPv6 forms that embed an IPv4 address (IPv4-mapped, IPv4-compatible,
//!   NAT64, 6to4, Teredo) are refused outright instead of being judged by the
//!   embedded address: a dual-stack or translating network routes them to an
//!   IPv4 destination this classifier would otherwise never see.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

/// One refused address block.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SpecialBlock {
    /// The block in CIDR notation.
    pub cidr: &'static str,
    /// What the registry calls it.
    pub name: &'static str,
    net: Net,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Net {
    V4 { bits: u32, len: u8 },
    V6 { bits: u128, len: u8 },
}

impl SpecialBlock {
    const fn v4(cidr: &'static str, name: &'static str, addr: Ipv4Addr, len: u8) -> Self {
        Self {
            cidr,
            name,
            net: Net::V4 {
                bits: addr.to_bits(),
                len,
            },
        }
    }

    const fn v6(cidr: &'static str, name: &'static str, addr: Ipv6Addr, len: u8) -> Self {
        Self {
            cidr,
            name,
            net: Net::V6 {
                bits: addr.to_bits(),
                len,
            },
        }
    }

    /// Whether `ip` lies in this block.
    pub fn contains(&self, ip: IpAddr) -> bool {
        match (self.net, ip) {
            (Net::V4 { bits, len }, IpAddr::V4(v4)) => {
                let mask = u32::MAX.checked_shl(32 - u32::from(len)).unwrap_or(0);
                v4.to_bits() & mask == bits & mask
            }
            (Net::V6 { bits, len }, IpAddr::V6(v6)) => {
                let mask = u128::MAX.checked_shl(128 - u32::from(len)).unwrap_or(0);
                v6.to_bits() & mask == bits & mask
            }
            _ => false,
        }
    }

    /// The first and the last address of the block.
    pub fn bounds(&self) -> (IpAddr, IpAddr) {
        match self.net {
            Net::V4 { bits, len } => {
                let mask = u32::MAX.checked_shl(32 - u32::from(len)).unwrap_or(0);
                (
                    IpAddr::V4(Ipv4Addr::from_bits(bits & mask)),
                    IpAddr::V4(Ipv4Addr::from_bits((bits & mask) | !mask)),
                )
            }
            Net::V6 { bits, len } => {
                let mask = u128::MAX.checked_shl(128 - u32::from(len)).unwrap_or(0);
                (
                    IpAddr::V6(Ipv6Addr::from_bits(bits & mask)),
                    IpAddr::V6(Ipv6Addr::from_bits((bits & mask) | !mask)),
                )
            }
        }
    }
}

/// Refused IPv4 blocks: the IPv4 Special-Purpose Address Registry plus
/// multicast.
pub const IPV4_BLOCKS: &[SpecialBlock] = &[
    SpecialBlock::v4("0.0.0.0/8", "this network", Ipv4Addr::new(0, 0, 0, 0), 8),
    SpecialBlock::v4("10.0.0.0/8", "private use", Ipv4Addr::new(10, 0, 0, 0), 8),
    SpecialBlock::v4(
        "100.64.0.0/10",
        "shared address space",
        Ipv4Addr::new(100, 64, 0, 0),
        10,
    ),
    SpecialBlock::v4("127.0.0.0/8", "loopback", Ipv4Addr::new(127, 0, 0, 0), 8),
    SpecialBlock::v4(
        "169.254.0.0/16",
        "link local",
        Ipv4Addr::new(169, 254, 0, 0),
        16,
    ),
    SpecialBlock::v4(
        "172.16.0.0/12",
        "private use",
        Ipv4Addr::new(172, 16, 0, 0),
        12,
    ),
    SpecialBlock::v4(
        "192.0.0.0/24",
        "IETF protocol assignments",
        Ipv4Addr::new(192, 0, 0, 0),
        24,
    ),
    SpecialBlock::v4(
        "192.0.2.0/24",
        "documentation (TEST-NET-1)",
        Ipv4Addr::new(192, 0, 2, 0),
        24,
    ),
    SpecialBlock::v4(
        "192.31.196.0/24",
        "AS112-v4",
        Ipv4Addr::new(192, 31, 196, 0),
        24,
    ),
    SpecialBlock::v4("192.52.193.0/24", "AMT", Ipv4Addr::new(192, 52, 193, 0), 24),
    SpecialBlock::v4(
        "192.88.99.0/24",
        "deprecated 6to4 relay anycast",
        Ipv4Addr::new(192, 88, 99, 0),
        24,
    ),
    SpecialBlock::v4(
        "192.168.0.0/16",
        "private use",
        Ipv4Addr::new(192, 168, 0, 0),
        16,
    ),
    SpecialBlock::v4(
        "192.175.48.0/24",
        "direct delegation AS112 service",
        Ipv4Addr::new(192, 175, 48, 0),
        24,
    ),
    SpecialBlock::v4(
        "198.18.0.0/15",
        "benchmarking",
        Ipv4Addr::new(198, 18, 0, 0),
        15,
    ),
    SpecialBlock::v4(
        "198.51.100.0/24",
        "documentation (TEST-NET-2)",
        Ipv4Addr::new(198, 51, 100, 0),
        24,
    ),
    SpecialBlock::v4(
        "203.0.113.0/24",
        "documentation (TEST-NET-3)",
        Ipv4Addr::new(203, 0, 113, 0),
        24,
    ),
    SpecialBlock::v4("224.0.0.0/4", "multicast", Ipv4Addr::new(224, 0, 0, 0), 4),
    SpecialBlock::v4(
        "240.0.0.0/4",
        "reserved, including limited broadcast",
        Ipv4Addr::new(240, 0, 0, 0),
        4,
    ),
];

/// Refused IPv6 blocks: the IPv6 Special-Purpose Address Registry plus
/// site-local and multicast. More specific blocks come first so that a lookup
/// names the most precise block.
pub const IPV6_BLOCKS: &[SpecialBlock] = &[
    SpecialBlock::v6("::/128", "unspecified", Ipv6Addr::UNSPECIFIED, 128),
    SpecialBlock::v6("::1/128", "loopback", Ipv6Addr::LOCALHOST, 128),
    SpecialBlock::v6(
        "::ffff:0:0/96",
        "IPv4-mapped",
        Ipv6Addr::new(0, 0, 0, 0, 0, 0xffff, 0, 0),
        96,
    ),
    SpecialBlock::v6(
        "::/96",
        "IPv4-compatible (deprecated)",
        Ipv6Addr::UNSPECIFIED,
        96,
    ),
    SpecialBlock::v6(
        "64:ff9b::/32",
        "IPv4-IPv6 translation, well-known and local-use",
        Ipv6Addr::new(0x64, 0xff9b, 0, 0, 0, 0, 0, 0),
        32,
    ),
    SpecialBlock::v6(
        "100::/64",
        "discard-only",
        Ipv6Addr::new(0x100, 0, 0, 0, 0, 0, 0, 0),
        64,
    ),
    SpecialBlock::v6(
        "100:0:0:1::/64",
        "dummy prefix",
        Ipv6Addr::new(0x100, 0, 0, 1, 0, 0, 0, 0),
        64,
    ),
    SpecialBlock::v6(
        "2001::/32",
        "Teredo",
        Ipv6Addr::new(0x2001, 0, 0, 0, 0, 0, 0, 0),
        32,
    ),
    SpecialBlock::v6(
        "2001:2::/48",
        "benchmarking",
        Ipv6Addr::new(0x2001, 2, 0, 0, 0, 0, 0, 0),
        48,
    ),
    SpecialBlock::v6(
        "2001::/23",
        "IETF protocol assignments",
        Ipv6Addr::new(0x2001, 0, 0, 0, 0, 0, 0, 0),
        23,
    ),
    SpecialBlock::v6(
        "2001:db8::/32",
        "documentation",
        Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 0),
        32,
    ),
    SpecialBlock::v6(
        "2002::/16",
        "6to4",
        Ipv6Addr::new(0x2002, 0, 0, 0, 0, 0, 0, 0),
        16,
    ),
    SpecialBlock::v6(
        "2620:4f:8000::/48",
        "direct delegation AS112 service",
        Ipv6Addr::new(0x2620, 0x4f, 0x8000, 0, 0, 0, 0, 0),
        48,
    ),
    SpecialBlock::v6(
        "3fff::/20",
        "documentation",
        Ipv6Addr::new(0x3fff, 0, 0, 0, 0, 0, 0, 0),
        20,
    ),
    SpecialBlock::v6(
        "5f00::/16",
        "segment routing SIDs",
        Ipv6Addr::new(0x5f00, 0, 0, 0, 0, 0, 0, 0),
        16,
    ),
    SpecialBlock::v6(
        "fc00::/7",
        "unique local",
        Ipv6Addr::new(0xfc00, 0, 0, 0, 0, 0, 0, 0),
        7,
    ),
    SpecialBlock::v6(
        "fe80::/10",
        "link-local unicast",
        Ipv6Addr::new(0xfe80, 0, 0, 0, 0, 0, 0, 0),
        10,
    ),
    SpecialBlock::v6(
        "fec0::/10",
        "site-local (deprecated)",
        Ipv6Addr::new(0xfec0, 0, 0, 0, 0, 0, 0, 0),
        10,
    ),
    SpecialBlock::v6(
        "ff00::/8",
        "multicast",
        Ipv6Addr::new(0xff00, 0, 0, 0, 0, 0, 0, 0),
        8,
    ),
];

/// IPv6 global unicast, 2000::/3.
const GLOBAL_UNICAST_V6: SpecialBlock = SpecialBlock::v6(
    "2000::/3",
    "global unicast",
    Ipv6Addr::new(0x2000, 0, 0, 0, 0, 0, 0, 0),
    3,
);

/// How the classifier sees one address.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AddressClass {
    /// A destination an egress may connect to.
    Global,
    /// In a refused special-purpose block.
    SpecialPurpose(&'static SpecialBlock),
    /// An IPv6 address outside 2000::/3 and outside every listed block.
    OutsideGlobalUnicast,
}

/// Classify one address.
pub fn classify(ip: IpAddr) -> AddressClass {
    let table = match ip {
        IpAddr::V4(_) => IPV4_BLOCKS,
        IpAddr::V6(_) => IPV6_BLOCKS,
    };
    if let Some(block) = table.iter().find(|b| b.contains(ip)) {
        return AddressClass::SpecialPurpose(block);
    }
    if ip.is_ipv6() && !GLOBAL_UNICAST_V6.contains(ip) {
        return AddressClass::OutsideGlobalUnicast;
    }
    AddressClass::Global
}

/// Whether an egress may connect to `ip`.
pub fn is_globally_reachable(ip: IpAddr) -> bool {
    classify(ip) == AddressClass::Global
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ip(s: &str) -> IpAddr {
        s.parse().unwrap()
    }

    #[test]
    fn every_block_refuses_its_first_and_last_address() {
        for block in IPV4_BLOCKS.iter().chain(IPV6_BLOCKS) {
            let (first, last) = block.bounds();
            assert!(
                block.contains(first) && block.contains(last),
                "{}",
                block.cidr
            );
            assert!(
                !is_globally_reachable(first),
                "{} first {first}",
                block.cidr
            );
            assert!(!is_globally_reachable(last), "{} last {last}", block.cidr);
        }
    }

    #[test]
    fn bounds_match_the_written_cidr() {
        for block in IPV4_BLOCKS.iter().chain(IPV6_BLOCKS) {
            let (first, _) = block.bounds();
            let (net, len) = block.cidr.split_once('/').unwrap();
            assert_eq!(first, ip(net), "{}", block.cidr);
            let len: u8 = len.parse().unwrap();
            let written = match block.net {
                Net::V4 { len, .. } | Net::V6 { len, .. } => len,
            };
            assert_eq!(written, len, "{}", block.cidr);
        }
    }

    #[test]
    fn the_registry_table_is_refused() {
        // (address, block the classifier must name)
        let cases = [
            ("0.0.0.0", "0.0.0.0/8"),
            ("0.255.255.255", "0.0.0.0/8"),
            ("10.1.2.3", "10.0.0.0/8"),
            ("100.64.0.1", "100.64.0.0/10"),
            ("100.127.255.254", "100.64.0.0/10"),
            ("127.0.0.1", "127.0.0.0/8"),
            ("169.254.169.254", "169.254.0.0/16"),
            ("172.16.0.1", "172.16.0.0/12"),
            ("172.31.255.255", "172.16.0.0/12"),
            ("192.0.0.8", "192.0.0.0/24"),
            ("192.0.0.9", "192.0.0.0/24"),
            ("192.0.0.170", "192.0.0.0/24"),
            ("192.0.2.1", "192.0.2.0/24"),
            ("192.31.196.1", "192.31.196.0/24"),
            ("192.52.193.1", "192.52.193.0/24"),
            ("192.88.99.1", "192.88.99.0/24"),
            ("192.168.1.1", "192.168.0.0/16"),
            ("192.175.48.6", "192.175.48.0/24"),
            ("198.18.0.1", "198.18.0.0/15"),
            ("198.19.255.255", "198.18.0.0/15"),
            ("198.51.100.7", "198.51.100.0/24"),
            ("203.0.113.7", "203.0.113.0/24"),
            ("224.0.0.251", "224.0.0.0/4"),
            ("239.255.255.250", "224.0.0.0/4"),
            ("240.0.0.1", "240.0.0.0/4"),
            ("255.255.255.255", "240.0.0.0/4"),
            ("::", "::/128"),
            ("::1", "::1/128"),
            ("::ffff:0:0", "::ffff:0:0/96"),
            ("64:ff9b::1", "64:ff9b::/32"),
            ("64:ff9b:1::1", "64:ff9b::/32"),
            ("100::1", "100::/64"),
            ("100:0:0:1::1", "100:0:0:1::/64"),
            ("2001::1", "2001::/32"),
            ("2001:1::1", "2001::/23"),
            ("2001:1::2", "2001::/23"),
            ("2001:2::1", "2001:2::/48"),
            ("2001:3::1", "2001::/23"),
            ("2001:4:112::1", "2001::/23"),
            ("2001:20::1", "2001::/23"),
            ("2001:30::1", "2001::/23"),
            ("2001:1ff:ffff::1", "2001::/23"),
            ("2001:db8::1", "2001:db8::/32"),
            ("2002::1", "2002::/16"),
            ("2620:4f:8000::42", "2620:4f:8000::/48"),
            ("3fff::1", "3fff::/20"),
            ("3fff:fff:ffff::1", "3fff::/20"),
            ("5f00::1", "5f00::/16"),
            ("fc00::1", "fc00::/7"),
            ("fd12:3456::1", "fc00::/7"),
            ("fe80::1", "fe80::/10"),
            ("fec0::1", "fec0::/10"),
            ("ff02::1", "ff00::/8"),
        ];
        for (addr, cidr) in cases {
            match classify(ip(addr)) {
                AddressClass::SpecialPurpose(block) => assert_eq!(block.cidr, cidr, "{addr}"),
                other => panic!("{addr} classified as {other:?}"),
            }
        }
    }

    #[test]
    fn embedded_ipv4_forms_are_refused_whatever_they_embed() {
        for addr in [
            "::ffff:127.0.0.1",
            "::ffff:169.254.169.254",
            "::ffff:8.8.8.8",
            "::127.0.0.1",
            "::8.8.8.8",
            "64:ff9b::a9fe:a9fe",
            "64:ff9b::808:808",
            "2002:7f00:1::1",
            "2002:808:808::1",
            "2001:0:4136:e378:8000:63bf:3fff:fdd2",
        ] {
            assert!(!is_globally_reachable(ip(addr)), "{addr}");
        }
    }

    #[test]
    fn ipv6_outside_global_unicast_is_refused() {
        for addr in ["1::1", "4000::1", "8000::1", "e000::1", "fe00::1"] {
            assert_eq!(
                classify(ip(addr)),
                AddressClass::OutsideGlobalUnicast,
                "{addr}"
            );
        }
    }

    #[test]
    fn public_addresses_next_to_refused_blocks_are_allowed() {
        for addr in [
            "1.1.1.1",
            "8.8.8.8",
            "9.255.255.255",
            "11.0.0.0",
            "100.63.255.255",
            "100.128.0.0",
            "126.255.255.255",
            "128.0.0.0",
            "169.253.255.255",
            "172.15.255.255",
            "172.32.0.0",
            "192.0.1.1",
            "192.0.3.0",
            "192.167.255.255",
            "192.169.0.0",
            "198.17.255.255",
            "198.20.0.0",
            "203.0.112.255",
            "223.255.255.255",
            "2001:200::1",
            "2001:4860:4860::8888",
            "2003::1",
            "2606:4700:4700::1111",
            "2620:4f:7fff::1",
            "2620:4f:8001::1",
            "3fff:1000::1",
        ] {
            assert_eq!(classify(ip(addr)), AddressClass::Global, "{addr}");
        }
    }
}
