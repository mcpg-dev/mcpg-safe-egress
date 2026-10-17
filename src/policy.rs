use std::fmt;
use std::net::IpAddr;
use std::time::Duration;

use url::{Host, Position, Url};

use crate::classify::is_globally_reachable;
use crate::host::{DenyEntry, is_internal_name, normalize_domain, under};

/// Operator settings of a [`crate::SafeEgress`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EgressPolicy {
    /// Ports a URL may name. Empty allows every port except 0.
    pub allowed_ports: Vec<u16>,
    /// Hosts never contacted, whatever they resolve to: a domain (with every
    /// name under it) or an address. For the platform's own domains, so that
    /// the egress cannot be aimed at them.
    pub deny_hosts: Vec<String>,
    /// Time allowed to open the TCP connection.
    pub connect_timeout: Duration,
    /// Time allowed for one whole attempt: resolution, connection, TLS,
    /// request and the capped response body.
    pub attempt_timeout: Duration,
    /// Longest URL accepted, in bytes.
    pub max_url_bytes: usize,
    /// Most response-body bytes read; the rest is discarded.
    pub max_response_bytes: usize,
    /// Admit destinations outside the global unicast space and internal host
    /// names. For self-hosted operators delivering inside their own network.
    pub allow_private_backends: bool,
    /// Admit `http` URLs. Honoured only with `allow_private_backends`.
    pub allow_http: bool,
    /// The `User-Agent` header sent with every request.
    pub user_agent: String,
}

impl Default for EgressPolicy {
    fn default() -> Self {
        Self {
            allowed_ports: Vec::new(),
            deny_hosts: Vec::new(),
            connect_timeout: Duration::from_secs(3),
            attempt_timeout: Duration::from_secs(10),
            max_url_bytes: 2048,
            max_response_bytes: 4096,
            allow_private_backends: false,
            allow_http: false,
            user_agent: "mcpg".to_owned(),
        }
    }
}

/// Why a [`crate::SafeEgress`] cannot be built over an [`EgressPolicy`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PolicyError {
    /// `deny_hosts[index]` is neither a domain nor an address.
    InvalidDenyHost { index: usize },
    /// A timeout is zero.
    ZeroTimeout,
    /// `max_url_bytes` is zero.
    ZeroUrlLimit,
    /// `allowed_ports` lists port 0.
    PortZero,
    /// `user_agent` is not a valid header value.
    InvalidUserAgent,
    /// The platform's TLS trust roots could not be loaded, so no `https`
    /// destination could be verified.
    NoTrustRoots,
}

impl fmt::Display for PolicyError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidDenyHost { index } => {
                write!(
                    f,
                    "deny_hosts[{index}] is neither a domain nor an IP address"
                )
            }
            Self::ZeroTimeout => f.write_str("egress timeouts must be greater than zero"),
            Self::ZeroUrlLimit => f.write_str("max_url_bytes must be greater than zero"),
            Self::PortZero => f.write_str("allowed_ports must not contain 0"),
            Self::InvalidUserAgent => f.write_str("user_agent is not a valid header value"),
            Self::NoTrustRoots => f.write_str("no TLS trust roots could be loaded from the system"),
        }
    }
}

impl std::error::Error for PolicyError {}

/// The policy with its deny list parsed, as the client applies it.
#[derive(Debug, Clone)]
pub(crate) struct CompiledPolicy {
    pub(crate) raw: EgressPolicy,
    deny_domains: Vec<String>,
    deny_ips: Vec<IpAddr>,
}

impl CompiledPolicy {
    pub(crate) fn compile(raw: EgressPolicy) -> Result<Self, PolicyError> {
        if raw.connect_timeout.is_zero() || raw.attempt_timeout.is_zero() {
            return Err(PolicyError::ZeroTimeout);
        }
        if raw.max_url_bytes == 0 {
            return Err(PolicyError::ZeroUrlLimit);
        }
        if raw.allowed_ports.contains(&0) {
            return Err(PolicyError::PortZero);
        }
        if http::HeaderValue::from_str(&raw.user_agent).is_err() {
            return Err(PolicyError::InvalidUserAgent);
        }
        let mut deny_domains = Vec::new();
        let mut deny_ips = Vec::new();
        for (index, entry) in raw.deny_hosts.iter().enumerate() {
            match DenyEntry::parse(entry) {
                Some(DenyEntry::Domain(d)) => deny_domains.push(d),
                Some(DenyEntry::Ip(ip)) => deny_ips.push(ip),
                None => return Err(PolicyError::InvalidDenyHost { index }),
            }
        }
        Ok(Self {
            raw,
            deny_domains,
            deny_ips,
        })
    }

    pub(crate) fn http_allowed(&self) -> bool {
        self.raw.allow_private_backends && self.raw.allow_http
    }

    /// Whether a resolved or literal address may be contacted.
    pub(crate) fn admits_ip(&self, ip: IpAddr) -> bool {
        !self.is_denied_ip(ip) && (self.raw.allow_private_backends || is_globally_reachable(ip))
    }

    fn is_denied_ip(&self, ip: IpAddr) -> bool {
        let ip = ip.to_canonical();
        self.deny_ips.iter().any(|d| d.to_canonical() == ip)
    }

    /// The static checks a URL must pass before anything is resolved.
    pub(crate) fn check(&self, raw: &str) -> Result<Url, UrlRefusal> {
        if raw.len() > self.raw.max_url_bytes {
            return Err(UrlRefusal::TooLong);
        }
        let url = Url::parse(raw).map_err(|_| UrlRefusal::Malformed)?;
        self.check_parsed(&url)?;
        Ok(url)
    }

    pub(crate) fn check_parsed(&self, url: &Url) -> Result<(), UrlRefusal> {
        if url.as_str().len() > self.raw.max_url_bytes {
            return Err(UrlRefusal::TooLong);
        }
        match url.scheme() {
            "https" => {}
            "http" if self.http_allowed() => {}
            _ => return Err(UrlRefusal::SchemeNotAllowed),
        }
        if !url.username().is_empty() || url.password().is_some() {
            return Err(UrlRefusal::Userinfo);
        }
        if url.fragment().is_some() {
            return Err(UrlRefusal::Fragment);
        }
        let port = url.port_or_known_default().ok_or(UrlRefusal::Malformed)?;
        if port == 0
            || (!self.raw.allowed_ports.is_empty() && !self.raw.allowed_ports.contains(&port))
        {
            return Err(UrlRefusal::PortNotAllowed);
        }
        match url.host().ok_or(UrlRefusal::Malformed)? {
            Host::Domain(d) => {
                let d = normalize_domain(d);
                if d.is_empty() {
                    return Err(UrlRefusal::Malformed);
                }
                if self.deny_domains.iter().any(|s| under(d, s)) {
                    return Err(UrlRefusal::DeniedHost);
                }
                if !self.raw.allow_private_backends && is_internal_name(d) {
                    return Err(UrlRefusal::DeniedHost);
                }
            }
            Host::Ipv4(v4) => self.check_literal(IpAddr::V4(v4))?,
            Host::Ipv6(v6) => self.check_literal(IpAddr::V6(v6))?,
        }
        Ok(())
    }

    fn check_literal(&self, ip: IpAddr) -> Result<(), UrlRefusal> {
        if self.is_denied_ip(ip) {
            return Err(UrlRefusal::DeniedHost);
        }
        if !self.raw.allow_private_backends && !is_globally_reachable(ip) {
            return Err(UrlRefusal::NonPublicAddress);
        }
        Ok(())
    }
}

/// Why a URL fails the static policy. The variants name the rule, never the
/// URL or an address.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum UrlRefusal {
    /// Longer than `max_url_bytes`.
    TooLong,
    /// Not an absolute URL with a host.
    Malformed,
    /// Not `https` (or `http` where allowed).
    SchemeNotAllowed,
    /// Carries a user name or password.
    Userinfo,
    /// Carries a `#fragment`.
    Fragment,
    /// Port 0, or a port outside `allowed_ports`.
    PortNotAllowed,
    /// An internal name or a host in `deny_hosts`.
    DeniedHost,
    /// A literal address outside the global unicast space.
    NonPublicAddress,
}

impl UrlRefusal {
    /// A stable snake_case name for logs and metrics.
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::TooLong => "too_long",
            Self::Malformed => "malformed",
            Self::SchemeNotAllowed => "scheme_not_allowed",
            Self::Userinfo => "userinfo",
            Self::Fragment => "fragment",
            Self::PortNotAllowed => "port_not_allowed",
            Self::DeniedHost => "denied_host",
            Self::NonPublicAddress => "non_public_address",
        }
    }
}

impl fmt::Display for UrlRefusal {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "callback URL refused: {}", self.as_str())
    }
}

impl std::error::Error for UrlRefusal {}

/// A URL that passed the static policy, in WHATWG-normalized form: lower-case
/// host, IDNA in ASCII, default port elided, empty path as `/`.
///
/// The policy is checked again on every attempt, so a host denied after the
/// URL was accepted is refused from then on.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct CallbackUrl {
    url: Url,
}

impl CallbackUrl {
    pub(crate) fn new(url: Url) -> Self {
        Self { url }
    }

    pub(crate) fn url(&self) -> &Url {
        &self.url
    }

    /// The normalized URL.
    pub fn as_str(&self) -> &str {
        self.url.as_str()
    }

    /// The host as it appears in the URL (an IPv6 literal keeps its
    /// brackets), without a trailing root dot. The unit for per-destination
    /// limits.
    pub fn host(&self) -> &str {
        // `example.com.` and `example.com` are one destination; they must not
        // count as two against a per-host limit.
        normalize_domain(self.url.host_str().unwrap_or_default())
    }

    /// The port, the scheme's default when the URL names none.
    pub fn port(&self) -> u16 {
        self.url.port_or_known_default().unwrap_or(443)
    }

    /// `scheme://host[:port]`, the part of the URL that is safe to log.
    pub fn origin(&self) -> String {
        self.url.origin().ascii_serialization()
    }

    /// The path and query, the part to log only as a keyed hash.
    pub fn path_and_query(&self) -> &str {
        &self.url[Position::BeforePath..Position::AfterQuery]
    }
}

impl fmt::Display for CallbackUrl {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.url.as_str())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn compiled(f: impl FnOnce(&mut EgressPolicy)) -> CompiledPolicy {
        let mut p = EgressPolicy::default();
        f(&mut p);
        CompiledPolicy::compile(p).unwrap()
    }

    fn check(p: &CompiledPolicy, raw: &str) -> Result<String, UrlRefusal> {
        p.check(raw).map(|u| u.to_string())
    }

    #[test]
    fn normalizes_host_case_default_port_and_empty_path() {
        let p = compiled(|_| {});
        assert_eq!(
            check(&p, "HTTPS://Hooks.Example.COM:443").unwrap(),
            "https://hooks.example.com/"
        );
        assert_eq!(
            check(&p, "https://hooks.example.com:8443/cb?x=1").unwrap(),
            "https://hooks.example.com:8443/cb?x=1"
        );
        assert_eq!(
            check(&p, "https://b\u{fc}cher.example.com/").unwrap(),
            "https://xn--bcher-kva.example.com/"
        );
    }

    #[test]
    fn refuses_plain_http_unless_private_backends_and_http_are_both_allowed() {
        let raw = "http://hooks.example.com/";
        assert_eq!(
            check(&compiled(|_| {}), raw),
            Err(UrlRefusal::SchemeNotAllowed)
        );
        assert_eq!(
            check(&compiled(|p| p.allow_http = true), raw),
            Err(UrlRefusal::SchemeNotAllowed)
        );
        assert_eq!(
            check(&compiled(|p| p.allow_private_backends = true), raw),
            Err(UrlRefusal::SchemeNotAllowed)
        );
        assert!(
            check(
                &compiled(|p| {
                    p.allow_private_backends = true;
                    p.allow_http = true;
                }),
                raw
            )
            .is_ok()
        );
        for other in [
            "ftp://hooks.example.com/",
            "file:///etc/passwd",
            "data:text/plain,x",
            "javascript:alert(1)",
        ] {
            assert!(check(&compiled(|_| {}), other).is_err(), "{other}");
        }
    }

    #[test]
    fn refuses_userinfo_fragments_and_overlong_urls() {
        let p = compiled(|_| {});
        assert_eq!(
            check(&p, "https://u:p@hooks.example.com/"),
            Err(UrlRefusal::Userinfo)
        );
        assert_eq!(
            check(&p, "https://u@hooks.example.com/"),
            Err(UrlRefusal::Userinfo)
        );
        assert_eq!(
            check(&p, "https://hooks.example.com/#x"),
            Err(UrlRefusal::Fragment)
        );
        let long = format!("https://hooks.example.com/{}", "a".repeat(2048));
        assert_eq!(check(&p, &long), Err(UrlRefusal::TooLong));
        let exact = format!("https://hooks.example.com/{}", "a".repeat(2048 - 26));
        assert_eq!(exact.len(), 2048);
        assert!(check(&p, &exact).is_ok());
        assert_eq!(check(&p, "not a url"), Err(UrlRefusal::Malformed));
        assert_eq!(check(&p, "/relative/path"), Err(UrlRefusal::Malformed));
    }

    #[test]
    fn port_allowlist_and_port_zero() {
        let any = compiled(|_| {});
        assert!(check(&any, "https://hooks.example.com:8443/").is_ok());
        assert_eq!(
            check(&any, "https://hooks.example.com:0/"),
            Err(UrlRefusal::PortNotAllowed)
        );
        let only_443 = compiled(|p| p.allowed_ports = vec![443]);
        assert!(check(&only_443, "https://hooks.example.com/").is_ok());
        assert!(check(&only_443, "https://hooks.example.com:443/").is_ok());
        assert_eq!(
            check(&only_443, "https://hooks.example.com:8443/"),
            Err(UrlRefusal::PortNotAllowed)
        );
    }

    #[test]
    fn refuses_internal_names() {
        let p = compiled(|_| {});
        for raw in [
            "https://localhost/",
            "https://LOCALHOST./",
            "https://metadata/",
            "https://printer.local/",
            "https://api.default.svc/",
            "https://api.default.svc.cluster.local/",
            "https://metadata.google.internal/",
            "https://router.home.arpa/",
            "https://app.localhost/",
        ] {
            assert_eq!(check(&p, raw), Err(UrlRefusal::DeniedHost), "{raw}");
        }
        let private = compiled(|p| p.allow_private_backends = true);
        assert!(check(&private, "https://api.default.svc.cluster.local/").is_ok());
    }

    #[test]
    fn deny_hosts_cover_the_domain_and_its_subdomains_even_with_private_backends() {
        for allow_private in [false, true] {
            let p = compiled(|p| {
                p.deny_hosts = vec![
                    "mcpg.cloud".into(),
                    "*.relay.example.net".into(),
                    "8.8.4.4".into(),
                ];
                p.allow_private_backends = allow_private;
            });
            for raw in [
                "https://mcpg.cloud/",
                "https://cp.mcpg.cloud/",
                "https://CP.MCPG.CLOUD./x",
                "https://relay.example.net/",
                "https://a.relay.example.net/",
                "https://8.8.4.4/",
            ] {
                assert_eq!(check(&p, raw), Err(UrlRefusal::DeniedHost), "{raw}");
            }
            assert!(check(&p, "https://evilmcpg.cloud/").is_ok());
            assert!(check(&p, "https://8.8.8.8/").is_ok());
        }
    }

    #[test]
    fn refuses_non_public_literals_in_every_spelling() {
        let p = compiled(|_| {});
        for raw in [
            "https://127.0.0.1/",
            "https://2130706433/",
            "https://0x7f.1/",
            "https://0177.0.0.1/",
            "https://10.0.0.1/",
            "https://169.254.169.254/latest/meta-data/",
            "https://[::1]/",
            "https://[::ffff:127.0.0.1]/",
            "https://[::ffff:8.8.8.8]/",
            "https://[64:ff9b::a9fe:a9fe]/",
            "https://[fd00::1]/",
            "https://0.0.0.0/",
        ] {
            assert_eq!(check(&p, raw), Err(UrlRefusal::NonPublicAddress), "{raw}");
        }
        assert!(check(&p, "https://8.8.8.8/").is_ok());
        assert!(check(&p, "https://[2606:4700:4700::1111]/").is_ok());
        let private = compiled(|p| p.allow_private_backends = true);
        assert!(check(&private, "https://10.0.0.1/").is_ok());
    }

    #[test]
    fn invalid_policies_are_refused() {
        let bad = |f: fn(&mut EgressPolicy)| {
            let mut p = EgressPolicy::default();
            f(&mut p);
            CompiledPolicy::compile(p).unwrap_err()
        };
        assert_eq!(
            bad(|p| p.deny_hosts = vec!["ok.example.com".into(), "not a host".into()]),
            PolicyError::InvalidDenyHost { index: 1 }
        );
        assert_eq!(
            bad(|p| p.connect_timeout = Duration::ZERO),
            PolicyError::ZeroTimeout
        );
        assert_eq!(
            bad(|p| p.attempt_timeout = Duration::ZERO),
            PolicyError::ZeroTimeout
        );
        assert_eq!(bad(|p| p.max_url_bytes = 0), PolicyError::ZeroUrlLimit);
        assert_eq!(
            bad(|p| p.allowed_ports = vec![443, 0]),
            PolicyError::PortZero
        );
        assert_eq!(
            bad(|p| p.user_agent = "a\nb".into()),
            PolicyError::InvalidUserAgent
        );
    }

    #[test]
    fn callback_url_accessors() {
        let p = compiled(|_| {});
        let url = CallbackUrl::new(
            p.check("https://Hooks.Example.com:8443/cb/1?token=abc")
                .unwrap(),
        );
        assert_eq!(
            url.as_str(),
            "https://hooks.example.com:8443/cb/1?token=abc"
        );
        assert_eq!(url.host(), "hooks.example.com");
        assert_eq!(url.port(), 8443);
        assert_eq!(url.origin(), "https://hooks.example.com:8443");
        assert_eq!(url.path_and_query(), "/cb/1?token=abc");
        let v6 = CallbackUrl::new(p.check("https://[2606:4700:4700::1111]/").unwrap());
        assert_eq!(v6.host(), "[2606:4700:4700::1111]");
        assert_eq!(v6.port(), 443);
        assert_eq!(v6.path_and_query(), "/");
    }

    #[test]
    fn a_trailing_root_dot_names_the_same_host() {
        let p = compiled(|_| {});
        let dotted = CallbackUrl::new(p.check("https://Hooks.Example.com./a").unwrap());
        let plain = CallbackUrl::new(p.check("https://hooks.example.com/b").unwrap());
        assert_eq!(dotted.host(), "hooks.example.com");
        assert_eq!(dotted.host(), plain.host());
        assert_eq!(dotted.as_str(), "https://hooks.example.com./a");
    }

    #[test]
    fn refusal_names_are_stable() {
        assert_eq!(UrlRefusal::NonPublicAddress.as_str(), "non_public_address");
        assert_eq!(
            UrlRefusal::DeniedHost.to_string(),
            "callback URL refused: denied_host"
        );
    }
}
