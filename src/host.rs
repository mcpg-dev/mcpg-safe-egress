use std::net::IpAddr;

/// Names that only ever lead into a private network or nowhere: the internal
/// suffixes of Kubernetes and enterprise DNS, and the special-use names of
/// RFC 6761, RFC 6762, RFC 7686, RFC 8375 and RFC 9476. A host equal to one of
/// these or under one of them is refused.
pub(crate) const INTERNAL_SUFFIXES: &[&str] = &[
    "local",
    "cluster.local",
    "internal",
    "svc",
    "localhost",
    "localdomain",
    "home.arpa",
    "arpa",
    "test",
    "invalid",
    "example",
    "onion",
    "alt",
];

/// An operator `deny_hosts` entry.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum DenyEntry {
    /// A domain and every name under it.
    Domain(String),
    /// One address, matched against literal hosts and resolved answers.
    Ip(IpAddr),
}

impl DenyEntry {
    /// Parse one entry: a domain (`mcpg.cloud`, `.mcpg.cloud` and
    /// `*.mcpg.cloud` all mean the domain and everything under it), an IPv4
    /// address, or an IPv6 address with or without brackets. `None` when the
    /// entry is none of these.
    pub(crate) fn parse(entry: &str) -> Option<Self> {
        let trimmed = entry.trim();
        let bare = trimmed
            .strip_prefix("*.")
            .or_else(|| trimmed.strip_prefix('.'))
            .unwrap_or(trimmed);
        let bare = bare
            .strip_prefix('[')
            .and_then(|s| s.strip_suffix(']'))
            .unwrap_or(bare);
        if let Ok(ip) = bare.parse::<IpAddr>() {
            return Some(Self::Ip(ip));
        }
        match url::Host::parse(bare).ok()? {
            url::Host::Domain(d) => {
                let d = normalize_domain(&d);
                (!d.is_empty() && !d.contains('/')).then(|| Self::Domain(d.to_owned()))
            }
            url::Host::Ipv4(v4) => Some(Self::Ip(IpAddr::V4(v4))),
            url::Host::Ipv6(v6) => Some(Self::Ip(IpAddr::V6(v6))),
        }
    }
}

/// A domain without its one optional trailing root dot.
pub(crate) fn normalize_domain(host: &str) -> &str {
    host.strip_suffix('.').unwrap_or(host)
}

/// Whether `host` is `suffix` or a name under it.
pub(crate) fn under(host: &str, suffix: &str) -> bool {
    host == suffix
        || (host.len() > suffix.len()
            && host.ends_with(suffix)
            && host.as_bytes()[host.len() - suffix.len() - 1] == b'.')
}

/// Whether a (lower-case, ASCII) domain is an internal name: a single label,
/// or a name under one of [`INTERNAL_SUFFIXES`].
pub(crate) fn is_internal_name(host: &str) -> bool {
    let host = normalize_domain(host);
    !host.contains('.') || INTERNAL_SUFFIXES.iter().any(|s| under(host, s))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn single_labels_and_internal_suffixes_are_internal() {
        for host in [
            "localhost",
            "localhost.",
            "intranet",
            "metadata",
            "printer.local",
            "api.default.svc",
            "api.default.svc.cluster.local",
            "db.internal",
            "metadata.google.internal",
            "router.home.arpa",
            "1.0.0.127.in-addr.arpa",
            "app.localhost",
            "box.localdomain",
            "x.test",
            "x.invalid",
            "x.example",
            "hidden.onion",
            "x.alt",
        ] {
            assert!(is_internal_name(host), "{host}");
        }
    }

    #[test]
    fn public_names_are_not_internal() {
        for host in [
            "hooks.example.com",
            "chatgpt.com",
            "api.openai.com",
            "local.example.com",
            "svc.example.com",
            "internal-tools.example.com",
            "localhost.example.com",
        ] {
            assert!(!is_internal_name(host), "{host}");
        }
    }

    #[test]
    fn under_respects_label_boundaries() {
        assert!(under("mcpg.cloud", "mcpg.cloud"));
        assert!(under("cp.mcpg.cloud", "mcpg.cloud"));
        assert!(!under("evilmcpg.cloud", "mcpg.cloud"));
        assert!(!under("mcpg.cloud.example.com", "mcpg.cloud"));
        assert!(!under("cloud", "mcpg.cloud"));
    }

    #[test]
    fn deny_entries_parse_domains_wildcards_and_addresses() {
        assert_eq!(
            DenyEntry::parse("MCPG.Cloud"),
            Some(DenyEntry::Domain("mcpg.cloud".into()))
        );
        assert_eq!(
            DenyEntry::parse("*.mcpg.cloud"),
            Some(DenyEntry::Domain("mcpg.cloud".into()))
        );
        assert_eq!(
            DenyEntry::parse(".mcpg.cloud."),
            Some(DenyEntry::Domain("mcpg.cloud".into()))
        );
        assert_eq!(
            DenyEntry::parse("b\u{fc}cher.example.com"),
            Some(DenyEntry::Domain("xn--bcher-kva.example.com".into()))
        );
        assert_eq!(
            DenyEntry::parse("203.0.113.9"),
            Some(DenyEntry::Ip("203.0.113.9".parse().unwrap()))
        );
        assert_eq!(
            DenyEntry::parse("[2606:4700::1]"),
            Some(DenyEntry::Ip("2606:4700::1".parse().unwrap()))
        );
        assert_eq!(
            DenyEntry::parse("2606:4700::1"),
            Some(DenyEntry::Ip("2606:4700::1".parse().unwrap()))
        );
        for bad in ["", "  ", "*.", "a b.example", "exa mple.com"] {
            assert_eq!(DenyEntry::parse(bad), None, "{bad:?}");
        }
    }
}
