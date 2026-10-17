use std::error::Error as _;
use std::fmt;
use std::future::Future;
use std::io;
use std::net::{IpAddr, SocketAddr};
use std::pin::Pin;
use std::sync::Arc;

use bytes::{Bytes, BytesMut};
use http::{HeaderMap, Method, StatusCode};
use url::Host;

use crate::policy::{CallbackUrl, CompiledPolicy, EgressPolicy, PolicyError, UrlRefusal};

/// The future a [`Resolve`] returns.
pub type ResolveFuture<'a> = Pin<Box<dyn Future<Output = io::Result<Vec<IpAddr>>> + Send + 'a>>;

/// Name resolution for [`SafeEgress`]. Every answer is classified, so a
/// resolver only has to answer; it never decides what is safe.
pub trait Resolve: Send + Sync {
    /// Every address `host` resolves to.
    fn resolve<'a>(&'a self, host: &'a str) -> ResolveFuture<'a>;
}

/// The operating system's resolver.
#[derive(Debug, Clone, Copy, Default)]
pub struct SystemResolver;

impl Resolve for SystemResolver {
    fn resolve<'a>(&'a self, host: &'a str) -> ResolveFuture<'a> {
        Box::pin(async move {
            Ok(tokio::net::lookup_host((host, 0))
                .await?
                .map(|a| a.ip())
                .collect())
        })
    }
}

/// The strict outbound client. Hold one per policy, share it by cloning, and
/// build a new one when the policy changes.
#[derive(Clone)]
pub struct SafeEgress {
    policy: CompiledPolicy,
    resolver: Arc<dyn Resolve>,
    /// Built once: loading the platform's roots reads and parses every system
    /// CA certificate, which is too slow to repeat on each attempt.
    tls: Arc<rustls::ClientConfig>,
}

impl fmt::Debug for SafeEgress {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SafeEgress")
            .field("policy", &self.policy.raw)
            .finish_non_exhaustive()
    }
}

/// A response that passed every check.
#[derive(Debug, Clone)]
pub struct EgressResponse {
    /// The status; never a 3xx.
    pub status: StatusCode,
    /// The response headers.
    pub headers: HeaderMap,
    /// At most `max_response_bytes` of the body.
    pub body: Bytes,
    /// Whether the body was longer than the cap and was cut.
    pub body_truncated: bool,
}

/// The outward category of a failure: the only part of an [`EgressError`]
/// that may reach the party that supplied the URL.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ErrorCategory {
    /// Nothing usable answered: the host is refused, does not resolve,
    /// resolves to a refused address, refused the connection, redirected, or
    /// answered from an unexpected address.
    ConnectionRefused,
    /// The connection or the attempt ran out of time.
    Timeout,
    /// The TLS handshake failed.
    TlsError,
}

impl ErrorCategory {
    /// `connection_refused`, `timeout` or `tls_error`.
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::ConnectionRefused => "connection_refused",
            Self::Timeout => "timeout",
            Self::TlsError => "tls_error",
        }
    }
}

impl fmt::Display for ErrorCategory {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// What went wrong, for the operator's logs and metrics. Never shown to the
/// party that supplied the URL; use [`EgressError::category`] for that.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum EgressErrorKind {
    /// The URL fails the current static policy.
    UrlRefused(UrlRefusal),
    /// The host did not resolve, or resolved to nothing.
    DnsFailed,
    /// An answer is outside the global unicast space or denied.
    AddressBlocked,
    /// The TCP connection failed.
    Connect,
    /// A timeout elapsed.
    Timeout,
    /// The TLS handshake failed.
    Tls,
    /// The response was a 3xx.
    Redirect,
    /// The response came from an address that was not vetted, or from an
    /// unknown one.
    RemoteAddrMismatch,
    /// Another failure while sending the request or reading the response.
    Transport,
}

impl EgressErrorKind {
    /// A stable snake_case name for logs and metrics.
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::UrlRefused(_) => "url_refused",
            Self::DnsFailed => "dns_failed",
            Self::AddressBlocked => "address_blocked",
            Self::Connect => "connect",
            Self::Timeout => "timeout",
            Self::Tls => "tls",
            Self::Redirect => "redirect",
            Self::RemoteAddrMismatch => "remote_addr_mismatch",
            Self::Transport => "transport",
        }
    }
}

/// A failed attempt. Holds no URL, address, header or body; `Display` prints
/// the outward category only.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EgressError {
    kind: EgressErrorKind,
}

impl EgressError {
    fn new(kind: EgressErrorKind) -> Self {
        Self { kind }
    }

    /// The precise reason, for the operator.
    pub fn kind(&self) -> EgressErrorKind {
        self.kind
    }

    /// The outward category.
    pub fn category(&self) -> ErrorCategory {
        match self.kind {
            EgressErrorKind::Timeout => ErrorCategory::Timeout,
            EgressErrorKind::Tls => ErrorCategory::TlsError,
            EgressErrorKind::UrlRefused(_)
            | EgressErrorKind::DnsFailed
            | EgressErrorKind::AddressBlocked
            | EgressErrorKind::Connect
            | EgressErrorKind::Redirect
            | EgressErrorKind::RemoteAddrMismatch
            | EgressErrorKind::Transport => ErrorCategory::ConnectionRefused,
        }
    }

    /// Whether the egress policy itself refused the destination, as opposed
    /// to the network failing. A rising count suggests probing.
    pub fn is_blocked(&self) -> bool {
        matches!(
            self.kind,
            EgressErrorKind::UrlRefused(_)
                | EgressErrorKind::AddressBlocked
                | EgressErrorKind::RemoteAddrMismatch
                | EgressErrorKind::Redirect
        )
    }
}

impl fmt::Display for EgressError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "egress failed: {}", self.category())
    }
}

impl std::error::Error for EgressError {}

impl SafeEgress {
    /// A client over `policy` with the system resolver.
    ///
    /// Loads the platform's TLS trust roots, once for this client and its
    /// clones; build a new client to pick up changed roots.
    pub fn new(policy: EgressPolicy) -> Result<Self, PolicyError> {
        Self::with_resolver(policy, Arc::new(SystemResolver))
    }

    /// A client over `policy` with another resolver. Loads the platform's TLS
    /// trust roots as [`Self::new`] does.
    pub fn with_resolver(
        policy: EgressPolicy,
        resolver: Arc<dyn Resolve>,
    ) -> Result<Self, PolicyError> {
        let policy = CompiledPolicy::compile(policy)?;
        let tls = platform_tls_config().map_err(|_| PolicyError::NoTrustRoots)?;
        Ok(Self::assemble(policy, resolver, tls))
    }

    /// A client that trusts the roots of `tls` instead of the platform's.
    #[cfg(test)]
    pub(crate) fn with_tls_config(
        policy: EgressPolicy,
        resolver: Arc<dyn Resolve>,
        tls: rustls::ClientConfig,
    ) -> Result<Self, PolicyError> {
        Ok(Self::assemble(
            CompiledPolicy::compile(policy)?,
            resolver,
            tls,
        ))
    }

    fn assemble(
        policy: CompiledPolicy,
        resolver: Arc<dyn Resolve>,
        mut tls: rustls::ClientConfig,
    ) -> Self {
        tls.alpn_protocols = vec![b"http/1.1".to_vec()];
        // Attempts share the trust roots and nothing else: no TLS session
        // outlives the attempt that made it.
        tls.resumption = rustls::client::Resumption::disabled();
        Self {
            policy,
            resolver,
            tls: Arc::new(tls),
        }
    }

    /// The policy this client applies.
    pub fn policy(&self) -> &EgressPolicy {
        &self.policy.raw
    }

    /// Apply the static URL policy without any network access.
    pub fn check_url(&self, raw: &str) -> Result<CallbackUrl, UrlRefusal> {
        self.policy.check(raw).map(CallbackUrl::new)
    }

    /// `POST` `body` to `url`.
    pub async fn post(
        &self,
        url: &CallbackUrl,
        headers: HeaderMap,
        body: Bytes,
    ) -> Result<EgressResponse, EgressError> {
        self.execute(Method::POST, url, headers, Some(body)).await
    }

    /// `GET` `url`.
    pub async fn get(
        &self,
        url: &CallbackUrl,
        headers: HeaderMap,
    ) -> Result<EgressResponse, EgressError> {
        self.execute(Method::GET, url, headers, None).await
    }

    async fn execute(
        &self,
        method: Method,
        url: &CallbackUrl,
        headers: HeaderMap,
        body: Option<Bytes>,
    ) -> Result<EgressResponse, EgressError> {
        let attempt = self.attempt(method, url, headers, body);
        match tokio::time::timeout(self.policy.raw.attempt_timeout, attempt).await {
            Ok(result) => result,
            Err(_) => Err(EgressError::new(EgressErrorKind::Timeout)),
        }
    }

    async fn attempt(
        &self,
        method: Method,
        url: &CallbackUrl,
        headers: HeaderMap,
        body: Option<Bytes>,
    ) -> Result<EgressResponse, EgressError> {
        let url = url.url();
        self.policy
            .check_parsed(url)
            .map_err(|r| EgressError::new(EgressErrorKind::UrlRefused(r)))?;
        let port =
            url.port_or_known_default()
                .ok_or(EgressError::new(EgressErrorKind::UrlRefused(
                    UrlRefusal::Malformed,
                )))?;

        let (domain, ips) = match url.host() {
            Some(Host::Domain(d)) => {
                let ips = self
                    .resolver
                    .resolve(d)
                    .await
                    .map_err(|_| EgressError::new(EgressErrorKind::DnsFailed))?;
                (Some(d.to_owned()), ips)
            }
            Some(Host::Ipv4(v4)) => (None, vec![IpAddr::V4(v4)]),
            Some(Host::Ipv6(v6)) => (None, vec![IpAddr::V6(v6)]),
            None => {
                return Err(EgressError::new(EgressErrorKind::UrlRefused(
                    UrlRefusal::Malformed,
                )));
            }
        };
        let mut vetted: Vec<SocketAddr> = Vec::with_capacity(ips.len());
        for ip in ips {
            let addr = SocketAddr::new(ip, port);
            if !vetted.contains(&addr) {
                vetted.push(addr);
            }
        }
        if vetted.is_empty() {
            return Err(EgressError::new(EgressErrorKind::DnsFailed));
        }
        // One refused answer refuses the host: a name that mixes public and
        // private answers is a rebinding setup, not a choice to make here.
        if vetted.iter().any(|a| !self.policy.admits_ip(a.ip())) {
            return Err(EgressError::new(EgressErrorKind::AddressBlocked));
        }

        let client = self.pinned_client(domain.as_deref(), &vetted)?;
        let mut request = client.request(method, url.clone()).headers(headers);
        if let Some(body) = body {
            request = request.body(body);
        }
        let mut response = request
            .send()
            .await
            .map_err(|e| EgressError::new(classify_reqwest(&e)))?;

        check_remote_addr(response.remote_addr(), &vetted)?;
        if response.status().is_redirection() {
            return Err(EgressError::new(EgressErrorKind::Redirect));
        }

        let status = response.status();
        let headers = std::mem::take(response.headers_mut());
        let cap = self.policy.raw.max_response_bytes;
        let mut body = BytesMut::with_capacity(cap.min(8192));
        let mut body_truncated = false;
        while let Some(chunk) = response
            .chunk()
            .await
            .map_err(|e| EgressError::new(classify_reqwest(&e)))?
        {
            let room = cap - body.len();
            if chunk.len() > room {
                body.extend_from_slice(&chunk[..room]);
                body_truncated = true;
                break;
            }
            body.extend_from_slice(&chunk);
        }
        Ok(EgressResponse {
            status,
            headers,
            body: body.freeze(),
            body_truncated,
        })
    }

    /// A client for one attempt that reaches `domain` only at `vetted`.
    fn pinned_client(
        &self,
        domain: Option<&str>,
        vetted: &[SocketAddr],
    ) -> Result<reqwest::Client, EgressError> {
        let mut builder = reqwest::Client::builder()
            .no_proxy()
            // A name the pin does not cover fails instead of reaching the
            // system resolver, whose answer nothing has vetted.
            .dns_resolver(Arc::new(NoResolver))
            .redirect(reqwest::redirect::Policy::none())
            .https_only(!self.policy.http_allowed())
            .connect_timeout(self.policy.raw.connect_timeout)
            .timeout(self.policy.raw.attempt_timeout)
            .pool_max_idle_per_host(0)
            .user_agent(self.policy.raw.user_agent.as_str())
            .tls_backend_preconfigured(self.tls.as_ref().clone());
        if let Some(domain) = domain {
            builder = builder.resolve_to_addrs(domain, vetted);
        }
        builder
            .build()
            .map_err(|_| EgressError::new(EgressErrorKind::Transport))
    }
}

/// A TLS configuration that verifies servers against the platform's trust
/// roots, under the process's default crypto provider or aws-lc-rs.
fn platform_tls_config() -> Result<rustls::ClientConfig, rustls::Error> {
    use rustls_platform_verifier::BuilderVerifierExt as _;

    let provider = rustls::crypto::CryptoProvider::get_default()
        .cloned()
        .unwrap_or_else(|| Arc::new(rustls::crypto::aws_lc_rs::default_provider()));
    Ok(rustls::ClientConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()?
        .with_platform_verifier()?
        .with_no_client_auth())
}

/// The resolver behind the pin: it answers no name.
struct NoResolver;

impl reqwest::dns::Resolve for NoResolver {
    fn resolve(&self, _name: reqwest::dns::Name) -> reqwest::dns::Resolving {
        Box::pin(std::future::ready(Err(Box::new(io::Error::new(
            io::ErrorKind::NotFound,
            "name is not pinned",
        ))
            as Box<dyn std::error::Error + Send + Sync>)))
    }
}

/// The peer must be one of the vetted addresses; an unknown peer is refused.
fn check_remote_addr(remote: Option<SocketAddr>, vetted: &[SocketAddr]) -> Result<(), EgressError> {
    let ok = remote.is_some_and(|r| {
        let ip = r.ip().to_canonical();
        vetted.iter().any(|v| v.ip().to_canonical() == ip)
    });
    if ok {
        Ok(())
    } else {
        Err(EgressError::new(EgressErrorKind::RemoteAddrMismatch))
    }
}

fn classify_reqwest(err: &reqwest::Error) -> EgressErrorKind {
    if err.is_timeout() {
        return EgressErrorKind::Timeout;
    }
    if is_tls_failure(err) {
        return EgressErrorKind::Tls;
    }
    if err.is_connect() {
        return EgressErrorKind::Connect;
    }
    EgressErrorKind::Transport
}

/// rustls reports handshake and certificate failures through tokio-rustls as
/// an `io::Error` of kind `InvalidData`; a TCP failure never has that kind.
fn is_tls_failure(err: &reqwest::Error) -> bool {
    let mut current: Option<&(dyn std::error::Error + 'static)> = err.source();
    while let Some(e) = current {
        if let Some(io) = e.downcast_ref::<io::Error>()
            && io_chain_has_tls_failure(io)
        {
            return true;
        }
        current = e.source();
    }
    false
}

/// The connector wraps the TLS `io::Error` in another one, and
/// `io::Error::source` skips the wrapped error itself, so the nesting is
/// walked through `get_ref`.
fn io_chain_has_tls_failure(io: &io::Error) -> bool {
    let mut current = Some(io);
    while let Some(e) = current {
        if e.kind() == io::ErrorKind::InvalidData {
            return true;
        }
        current = e
            .get_ref()
            .and_then(|inner| inner.downcast_ref::<io::Error>());
    }
    false
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;
    use std::sync::Mutex;
    use std::time::Duration;

    use super::*;
    use crate::test_server::{Reply, TestServer};

    /// Answers from a fixed table; `None` answers with a resolver error.
    struct FakeResolver {
        answers: HashMap<String, Option<Vec<IpAddr>>>,
        asked: Mutex<Vec<String>>,
    }

    impl FakeResolver {
        fn new(answers: &[(&str, Option<&[&str]>)]) -> Arc<Self> {
            Arc::new(Self {
                answers: answers
                    .iter()
                    .map(|(h, ips)| {
                        (
                            (*h).to_owned(),
                            ips.map(|ips| ips.iter().map(|ip| ip.parse().unwrap()).collect()),
                        )
                    })
                    .collect(),
                asked: Mutex::new(Vec::new()),
            })
        }
    }

    impl Resolve for FakeResolver {
        fn resolve<'a>(&'a self, host: &'a str) -> ResolveFuture<'a> {
            self.asked.lock().unwrap().push(host.to_owned());
            let answer = self.answers.get(host).cloned().flatten();
            Box::pin(async move {
                answer.ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, "no such host"))
            })
        }
    }

    fn private_http_policy() -> EgressPolicy {
        EgressPolicy {
            allow_private_backends: true,
            allow_http: true,
            connect_timeout: Duration::from_secs(2),
            attempt_timeout: Duration::from_secs(5),
            ..EgressPolicy::default()
        }
    }

    fn egress(policy: EgressPolicy, resolver: Arc<FakeResolver>) -> SafeEgress {
        SafeEgress::with_resolver(policy, resolver).unwrap()
    }

    fn json_headers() -> HeaderMap {
        let mut h = HeaderMap::new();
        h.insert(
            http::header::CONTENT_TYPE,
            "application/json".parse().unwrap(),
        );
        h
    }

    #[tokio::test]
    async fn connects_to_the_vetted_address_and_keeps_the_hostname() {
        let server = TestServer::start(Reply::status(204)).await;
        let resolver = FakeResolver::new(&[("hooks.example.com", Some(&["127.0.0.1"]))]);
        let e = egress(private_http_policy(), resolver.clone());
        let url = e
            .check_url(&format!(
                "http://hooks.example.com:{}/cb?x=1",
                server.port()
            ))
            .unwrap();
        let resp = e
            .post(&url, json_headers(), Bytes::from_static(b"{\"a\":1}"))
            .await
            .unwrap();
        assert_eq!(resp.status, StatusCode::NO_CONTENT);

        let seen = server.requests().await;
        assert_eq!(seen.len(), 1);
        assert_eq!(seen[0].method, "POST");
        assert_eq!(seen[0].target, "/cb?x=1");
        assert_eq!(
            seen[0].header("host").unwrap(),
            format!("hooks.example.com:{}", server.port())
        );
        assert_eq!(seen[0].header("content-type").unwrap(), "application/json");
        assert_eq!(seen[0].header("user-agent").unwrap(), "mcpg");
        assert_eq!(seen[0].body, b"{\"a\":1}");
        assert_eq!(
            resolver.asked.lock().unwrap().as_slice(),
            ["hooks.example.com"]
        );
    }

    #[tokio::test]
    async fn resolves_again_on_every_attempt() {
        let server = TestServer::start(Reply::status(200)).await;
        let resolver = FakeResolver::new(&[("hooks.example.com", Some(&["127.0.0.1"]))]);
        let e = egress(private_http_policy(), resolver.clone());
        let url = e
            .check_url(&format!("http://hooks.example.com:{}/", server.port()))
            .unwrap();
        for _ in 0..3 {
            e.post(&url, HeaderMap::new(), Bytes::new()).await.unwrap();
        }
        assert_eq!(resolver.asked.lock().unwrap().len(), 3);
        assert_eq!(server.requests().await.len(), 3);
    }

    #[tokio::test]
    async fn a_private_answer_is_refused_before_any_connection() {
        let resolver = FakeResolver::new(&[
            ("private.example.com", Some(&["10.0.0.7"])),
            ("metadata.example.com", Some(&["169.254.169.254"])),
            ("mapped.example.com", Some(&["::ffff:127.0.0.1"])),
            ("mixed.example.com", Some(&["93.184.215.14", "127.0.0.1"])),
        ]);
        let e = egress(EgressPolicy::default(), resolver);
        for host in ["private", "metadata", "mapped", "mixed"] {
            let url = e
                .check_url(&format!("https://{host}.example.com/"))
                .unwrap();
            let err = e
                .post(&url, HeaderMap::new(), Bytes::new())
                .await
                .unwrap_err();
            assert_eq!(err.kind(), EgressErrorKind::AddressBlocked, "{host}");
            assert_eq!(err.category(), ErrorCategory::ConnectionRefused);
            assert!(err.is_blocked());
        }
    }

    #[tokio::test]
    async fn blocked_and_unresolvable_hosts_look_the_same_outward() {
        let resolver = FakeResolver::new(&[
            ("private.example.com", Some(&["10.0.0.7"])),
            ("empty.example.com", Some(&[])),
            ("missing.example.com", None),
        ]);
        let e = egress(EgressPolicy::default(), resolver);
        let mut outward = Vec::new();
        for host in ["private", "empty", "missing"] {
            let url = e
                .check_url(&format!("https://{host}.example.com/"))
                .unwrap();
            let err = e
                .post(&url, HeaderMap::new(), Bytes::new())
                .await
                .unwrap_err();
            outward.push((err.category(), err.to_string()));
            let shown = format!("{err} {err:?}");
            assert!(!shown.contains("10.0.0.7"), "{shown}");
            assert!(!shown.contains("example.com"), "{shown}");
        }
        assert!(outward.windows(2).all(|w| w[0] == w[1]), "{outward:?}");
        assert_eq!(outward[0].1, "egress failed: connection_refused");
    }

    #[tokio::test]
    async fn redirects_are_refused_and_never_followed() {
        let target = TestServer::start(Reply::status(200)).await;
        let location = format!("http://127.0.0.1:{}/stolen", target.port());
        let server = TestServer::start(Reply::status(302).with_header("location", &location)).await;
        let resolver = FakeResolver::new(&[("hooks.example.com", Some(&["127.0.0.1"]))]);
        let e = egress(private_http_policy(), resolver);
        let url = e
            .check_url(&format!("http://hooks.example.com:{}/", server.port()))
            .unwrap();
        let err = e
            .post(&url, HeaderMap::new(), Bytes::new())
            .await
            .unwrap_err();
        assert_eq!(err.kind(), EgressErrorKind::Redirect);
        assert_eq!(err.category(), ErrorCategory::ConnectionRefused);
        assert_eq!(server.requests().await.len(), 1);
        assert!(target.requests().await.is_empty());
    }

    #[tokio::test]
    async fn a_silent_server_times_out() {
        let server = TestServer::start(Reply::Hang).await;
        let resolver = FakeResolver::new(&[("hooks.example.com", Some(&["127.0.0.1"]))]);
        let policy = EgressPolicy {
            attempt_timeout: Duration::from_millis(300),
            ..private_http_policy()
        };
        let e = egress(policy, resolver);
        let url = e
            .check_url(&format!("http://hooks.example.com:{}/", server.port()))
            .unwrap();
        let err = e
            .post(&url, HeaderMap::new(), Bytes::new())
            .await
            .unwrap_err();
        assert_eq!(err.kind(), EgressErrorKind::Timeout);
        assert_eq!(err.category(), ErrorCategory::Timeout);
    }

    #[tokio::test]
    async fn a_closed_port_is_connection_refused() {
        let port = TestServer::unused_port().await;
        let resolver = FakeResolver::new(&[("hooks.example.com", Some(&["127.0.0.1"]))]);
        let e = egress(private_http_policy(), resolver);
        let url = e
            .check_url(&format!("http://hooks.example.com:{port}/"))
            .unwrap();
        let err = e
            .post(&url, HeaderMap::new(), Bytes::new())
            .await
            .unwrap_err();
        assert_eq!(err.kind(), EgressErrorKind::Connect);
        assert_eq!(err.category(), ErrorCategory::ConnectionRefused);
        assert!(!err.is_blocked());
    }

    #[tokio::test]
    async fn tls_keeps_the_hostname_for_sni_and_a_failed_handshake_is_tls_error() {
        let server = TestServer::start(Reply::GarbageAfterClientHello).await;
        let resolver = FakeResolver::new(&[("hooks.example.com", Some(&["127.0.0.1"]))]);
        let policy = EgressPolicy {
            allow_private_backends: true,
            ..EgressPolicy::default()
        };
        let e = egress(policy, resolver);
        let url = e
            .check_url(&format!("https://hooks.example.com:{}/", server.port()))
            .unwrap();
        let err = e
            .post(&url, HeaderMap::new(), Bytes::new())
            .await
            .unwrap_err();
        assert_eq!(err.kind(), EgressErrorKind::Tls);
        assert_eq!(err.category(), ErrorCategory::TlsError);
        let hello = server.raw_reads().await;
        assert_eq!(hello.len(), 1);
        assert!(
            hello[0]
                .windows(b"hooks.example.com".len())
                .any(|w| w == b"hooks.example.com"),
            "the ClientHello names the host"
        );
    }

    #[tokio::test]
    async fn the_response_body_is_capped() {
        let server = TestServer::start(Reply::status(200).with_body(vec![b'x'; 10_000])).await;
        let resolver = FakeResolver::new(&[("hooks.example.com", Some(&["127.0.0.1"]))]);
        let e = egress(private_http_policy(), resolver);
        let url = e
            .check_url(&format!("http://hooks.example.com:{}/", server.port()))
            .unwrap();
        let resp = e.get(&url, HeaderMap::new()).await.unwrap();
        assert_eq!(resp.body.len(), 4096);
        assert!(resp.body_truncated);

        let small =
            TestServer::start(Reply::status(200).with_body(b"{\"challenge\":\"n\"}".to_vec()))
                .await;
        let url = e
            .check_url(&format!("http://hooks.example.com:{}/", small.port()))
            .unwrap();
        let resp = e.get(&url, HeaderMap::new()).await.unwrap();
        assert_eq!(&resp.body[..], b"{\"challenge\":\"n\"}");
        assert!(!resp.body_truncated);
    }

    #[tokio::test]
    async fn a_policy_change_applies_to_urls_accepted_earlier() {
        let server = TestServer::start(Reply::status(200)).await;
        let resolver = FakeResolver::new(&[("hooks.example.com", Some(&["127.0.0.1"]))]);
        let before = egress(private_http_policy(), resolver.clone());
        let url = before
            .check_url(&format!("http://hooks.example.com:{}/", server.port()))
            .unwrap();
        before
            .post(&url, HeaderMap::new(), Bytes::new())
            .await
            .unwrap();

        let after = egress(
            EgressPolicy {
                deny_hosts: vec!["example.com".into()],
                ..private_http_policy()
            },
            resolver.clone(),
        );
        let err = after
            .post(&url, HeaderMap::new(), Bytes::new())
            .await
            .unwrap_err();
        assert_eq!(
            err.kind(),
            EgressErrorKind::UrlRefused(UrlRefusal::DeniedHost)
        );
        assert_eq!(err.category(), ErrorCategory::ConnectionRefused);
        assert_eq!(server.requests().await.len(), 1);
        assert_eq!(
            resolver.asked.lock().unwrap().len(),
            1,
            "a denied host is never resolved"
        );

        let deny_ip = egress(
            EgressPolicy {
                deny_hosts: vec!["127.0.0.1".into()],
                ..private_http_policy()
            },
            resolver,
        );
        let err = deny_ip
            .post(&url, HeaderMap::new(), Bytes::new())
            .await
            .unwrap_err();
        assert_eq!(err.kind(), EgressErrorKind::AddressBlocked);
    }

    /// A server configuration presenting a certificate for `names`, issued by
    /// a fresh CA, and a client configuration that trusts only that CA.
    fn test_pki(names: &[&str]) -> (Arc<rustls::ServerConfig>, rustls::ClientConfig) {
        let provider = Arc::new(rustls::crypto::aws_lc_rs::default_provider());
        let mut ca_params = rcgen::CertificateParams::new(Vec::<String>::new()).unwrap();
        ca_params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
        let ca =
            rcgen::CertifiedIssuer::self_signed(ca_params, rcgen::KeyPair::generate().unwrap())
                .unwrap();
        let leaf_key = rcgen::KeyPair::generate().unwrap();
        let names: Vec<String> = names.iter().map(|n| (*n).to_owned()).collect();
        let leaf = rcgen::CertificateParams::new(names)
            .unwrap()
            .signed_by(&leaf_key, &*ca)
            .unwrap();
        let key = rustls::pki_types::PrivatePkcs8KeyDer::from(leaf_key.serialize_der());
        let server = rustls::ServerConfig::builder_with_provider(provider.clone())
            .with_safe_default_protocol_versions()
            .unwrap()
            .with_no_client_auth()
            .with_single_cert(vec![leaf.der().clone()], key.into())
            .unwrap();
        let mut roots = rustls::RootCertStore::empty();
        roots.add(ca.der().clone()).unwrap();
        let client = rustls::ClientConfig::builder_with_provider(provider)
            .with_safe_default_protocol_versions()
            .unwrap()
            .with_root_certificates(roots)
            .with_no_client_auth();
        (Arc::new(server), client)
    }

    #[tokio::test]
    async fn https_reaches_the_vetted_address_under_the_hostname_on_every_attempt() {
        let (server_tls, client_tls) = test_pki(&["hooks.example.com"]);
        let server = TestServer::start_tls(Reply::status(204), server_tls).await;
        let resolver = FakeResolver::new(&[
            ("hooks.example.com", Some(&["127.0.0.1"])),
            ("other.example.com", Some(&["127.0.0.1"])),
        ]);
        let policy = EgressPolicy {
            allow_private_backends: true,
            ..EgressPolicy::default()
        };
        let e = SafeEgress::with_tls_config(policy, resolver, client_tls).unwrap();

        let url = e
            .check_url(&format!("https://hooks.example.com:{}/cb", server.port()))
            .unwrap();
        for _ in 0..2 {
            let resp = e
                .post(&url, json_headers(), Bytes::from_static(b"{}"))
                .await
                .unwrap();
            assert_eq!(resp.status, StatusCode::NO_CONTENT);
        }
        let seen = server.requests().await;
        assert_eq!(seen.len(), 2);
        assert_eq!(
            seen[0].header("host").unwrap(),
            format!("hooks.example.com:{}", server.port())
        );
        assert_eq!(
            server.server_names().await,
            vec![Some("hooks.example.com".to_owned()); 2]
        );

        // The same address under a name the certificate does not cover fails
        // the handshake: the pin changes where the client connects, never
        // which name it verifies.
        let other = e
            .check_url(&format!("https://other.example.com:{}/cb", server.port()))
            .unwrap();
        let err = e
            .post(&other, HeaderMap::new(), Bytes::new())
            .await
            .unwrap_err();
        assert_eq!(err.kind(), EgressErrorKind::Tls);
        assert_eq!(err.category(), ErrorCategory::TlsError);
        assert_eq!(server.requests().await.len(), 2);
    }

    #[tokio::test]
    async fn a_pinned_client_never_asks_the_system_resolver() {
        let server = TestServer::start(Reply::status(200)).await;
        let e = egress(private_http_policy(), FakeResolver::new(&[]));
        let vetted: Vec<SocketAddr> = vec![SocketAddr::from(([127, 0, 0, 1], server.port()))];
        let client = e.pinned_client(Some("hooks.example.com"), &vetted).unwrap();

        let pinned = client
            .get(format!("http://hooks.example.com:{}/", server.port()))
            .send()
            .await
            .unwrap();
        assert_eq!(pinned.status(), StatusCode::OK);

        // The system resolver answers `localhost` with a loopback address, so
        // only a client that never consults it keeps this request off the wire.
        let unpinned = client
            .get(format!("http://localhost:{}/", server.port()))
            .send()
            .await;
        assert!(unpinned.is_err());
        assert_eq!(server.requests().await.len(), 1);
    }

    #[test]
    fn the_peer_must_be_a_vetted_address() {
        let vetted: Vec<SocketAddr> = vec!["93.184.215.14:443".parse().unwrap()];
        assert!(check_remote_addr(Some("93.184.215.14:443".parse().unwrap()), &vetted).is_ok());
        assert!(
            check_remote_addr(Some("[::ffff:93.184.215.14]:443".parse().unwrap()), &vetted).is_ok()
        );
        for remote in [
            None,
            Some("10.0.0.1:443".parse().unwrap()),
            Some("93.184.215.15:443".parse().unwrap()),
        ] {
            let err = check_remote_addr(remote, &vetted).unwrap_err();
            assert_eq!(err.kind(), EgressErrorKind::RemoteAddrMismatch);
            assert_eq!(err.category(), ErrorCategory::ConnectionRefused);
        }
    }

    #[test]
    fn categories_and_kinds_have_stable_names() {
        assert_eq!(
            ErrorCategory::ConnectionRefused.as_str(),
            "connection_refused"
        );
        assert_eq!(ErrorCategory::Timeout.as_str(), "timeout");
        assert_eq!(ErrorCategory::TlsError.as_str(), "tls_error");
        assert_eq!(EgressErrorKind::AddressBlocked.as_str(), "address_blocked");
        assert_eq!(
            EgressErrorKind::UrlRefused(UrlRefusal::Fragment).as_str(),
            "url_refused"
        );
    }

    #[test]
    fn requests_can_run_on_a_spawned_task() {
        fn assert_send<T: Send>(_: &T) {}
        let e = SafeEgress::new(EgressPolicy::default()).unwrap();
        let url = e.check_url("https://hooks.example.com/").unwrap();
        let post = e.post(&url, HeaderMap::new(), Bytes::new());
        assert_send(&post);
        let get = e.get(&url, HeaderMap::new());
        assert_send(&get);
        fn assert_shareable<T: Send + Sync + Clone>() {}
        assert_shareable::<SafeEgress>();
    }

    #[tokio::test]
    async fn the_system_resolver_answers_literals() {
        let ips = SystemResolver.resolve("127.0.0.1").await.unwrap();
        assert_eq!(ips, vec!["127.0.0.1".parse::<IpAddr>().unwrap()]);
    }

    #[test]
    fn an_invalid_data_io_error_nested_in_another_is_a_tls_failure() {
        let tls = io::Error::new(io::ErrorKind::InvalidData, "bad record");
        let wrapped = io::Error::other(tls);
        assert!(io_chain_has_tls_failure(&wrapped));
        let refused = io::Error::other(io::Error::from(io::ErrorKind::ConnectionRefused));
        assert!(!io_chain_has_tls_failure(&refused));
        assert!(!io_chain_has_tls_failure(&io::Error::other("plain")));
    }
}
