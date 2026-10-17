//! A raw TCP server, optionally behind TLS, for the client tests: records
//! what arrives and answers with a canned reply, so the tests see exactly the
//! bytes the client sent.

use std::sync::Arc;

use tokio::io::{AsyncRead, AsyncReadExt as _, AsyncWrite, AsyncWriteExt as _};
use tokio::net::TcpListener;
use tokio::sync::Mutex;
use tokio::task::JoinHandle;
use tokio_rustls::TlsAcceptor;

#[derive(Clone)]
pub(crate) enum Reply {
    Http {
        status: u16,
        headers: Vec<(String, String)>,
        body: Vec<u8>,
    },
    /// Read the request and never answer.
    Hang,
    /// Read the first flight (a TLS ClientHello) and answer with bytes that
    /// are not TLS.
    GarbageAfterClientHello,
}

impl Reply {
    pub(crate) fn status(status: u16) -> Self {
        Self::Http {
            status,
            headers: Vec::new(),
            body: Vec::new(),
        }
    }

    pub(crate) fn with_header(mut self, name: &str, value: &str) -> Self {
        if let Self::Http { headers, .. } = &mut self {
            headers.push((name.to_owned(), value.to_owned()));
        }
        self
    }

    pub(crate) fn with_body(mut self, bytes: Vec<u8>) -> Self {
        if let Self::Http { body, .. } = &mut self {
            *body = bytes;
        }
        self
    }
}

#[derive(Debug, Clone)]
pub(crate) struct Request {
    pub(crate) method: String,
    pub(crate) target: String,
    pub(crate) headers: Vec<(String, String)>,
    pub(crate) body: Vec<u8>,
}

impl Request {
    pub(crate) fn header(&self, name: &str) -> Option<&str> {
        self.headers
            .iter()
            .find(|(k, _)| k.eq_ignore_ascii_case(name))
            .map(|(_, v)| v.as_str())
    }
}

pub(crate) struct TestServer {
    port: u16,
    requests: Arc<Mutex<Vec<Request>>>,
    raw: Arc<Mutex<Vec<Vec<u8>>>>,
    server_names: Arc<Mutex<Vec<Option<String>>>>,
    task: JoinHandle<()>,
}

impl Drop for TestServer {
    fn drop(&mut self) {
        self.task.abort();
    }
}

impl TestServer {
    pub(crate) async fn start(reply: Reply) -> Self {
        Self::start_with(reply, None).await
    }

    /// The same server behind TLS with `config`; [`Self::server_names`]
    /// records the SNI of every completed handshake.
    pub(crate) async fn start_tls(reply: Reply, config: Arc<rustls::ServerConfig>) -> Self {
        Self::start_with(reply, Some(TlsAcceptor::from(config))).await
    }

    async fn start_with(reply: Reply, tls: Option<TlsAcceptor>) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let requests = Arc::new(Mutex::new(Vec::new()));
        let raw = Arc::new(Mutex::new(Vec::new()));
        let server_names = Arc::new(Mutex::new(Vec::new()));
        let (req_log, raw_log, sni_log) = (requests.clone(), raw.clone(), server_names.clone());
        let task = tokio::spawn(async move {
            while let Ok((stream, _)) = listener.accept().await {
                let (reply, req_log, raw_log, sni_log, tls) = (
                    reply.clone(),
                    req_log.clone(),
                    raw_log.clone(),
                    sni_log.clone(),
                    tls.clone(),
                );
                tokio::spawn(async move {
                    match tls {
                        None => serve(stream, reply, req_log, raw_log).await,
                        Some(acceptor) => {
                            let Ok(stream) = acceptor.accept(stream).await else {
                                return;
                            };
                            let sni = stream.get_ref().1.server_name().map(str::to_owned);
                            sni_log.lock().await.push(sni);
                            serve(stream, reply, req_log, raw_log).await;
                        }
                    }
                });
            }
        });
        Self {
            port,
            requests,
            raw,
            server_names,
            task,
        }
    }

    pub(crate) async fn server_names(&self) -> Vec<Option<String>> {
        self.server_names.lock().await.clone()
    }

    /// A port nothing listens on.
    pub(crate) async fn unused_port() -> u16 {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        listener.local_addr().unwrap().port()
    }

    pub(crate) fn port(&self) -> u16 {
        self.port
    }

    pub(crate) async fn requests(&self) -> Vec<Request> {
        self.requests.lock().await.clone()
    }

    pub(crate) async fn raw_reads(&self) -> Vec<Vec<u8>> {
        self.raw.lock().await.clone()
    }
}

async fn serve<S: AsyncRead + AsyncWrite + Unpin>(
    mut stream: S,
    reply: Reply,
    req_log: Arc<Mutex<Vec<Request>>>,
    raw_log: Arc<Mutex<Vec<Vec<u8>>>>,
) {
    match reply {
        Reply::GarbageAfterClientHello => {
            let mut buf = vec![0u8; 8192];
            let n = stream.read(&mut buf).await.unwrap_or(0);
            raw_log.lock().await.push(buf[..n].to_vec());
            let _ = stream
                .write_all(b"HTTP/1.1 400 Bad Request\r\ncontent-length: 0\r\n\r\n")
                .await;
            let _ = stream.shutdown().await;
        }
        Reply::Hang => {
            let mut buf = vec![0u8; 8192];
            let _ = stream.read(&mut buf).await;
            std::future::pending::<()>().await;
        }
        Reply::Http {
            status,
            headers,
            body,
        } => {
            let Some(request) = read_request(&mut stream).await else {
                return;
            };
            req_log.lock().await.push(request);
            let mut head = format!(
                "HTTP/1.1 {status} X\r\ncontent-length: {}\r\nconnection: close\r\n",
                body.len()
            );
            for (k, v) in &headers {
                head.push_str(&format!("{k}: {v}\r\n"));
            }
            head.push_str("\r\n");
            let _ = stream.write_all(head.as_bytes()).await;
            let _ = stream.write_all(&body).await;
            let _ = stream.shutdown().await;
        }
    }
}

async fn read_request<S: AsyncRead + Unpin>(stream: &mut S) -> Option<Request> {
    let mut buf = Vec::new();
    let mut chunk = [0u8; 4096];
    let head_end = loop {
        let n = stream.read(&mut chunk).await.ok()?;
        if n == 0 {
            return None;
        }
        buf.extend_from_slice(&chunk[..n]);
        if let Some(pos) = buf.windows(4).position(|w| w == b"\r\n\r\n") {
            break pos + 4;
        }
    };
    let head = String::from_utf8_lossy(&buf[..head_end]).into_owned();
    let mut lines = head.split("\r\n");
    let mut start = lines.next()?.split(' ');
    let method = start.next()?.to_owned();
    let target = start.next()?.to_owned();
    let headers: Vec<(String, String)> = lines
        .filter_map(|l| l.split_once(':'))
        .map(|(k, v)| (k.trim().to_ascii_lowercase(), v.trim().to_owned()))
        .collect();
    let len: usize = headers
        .iter()
        .find(|(k, _)| k == "content-length")
        .and_then(|(_, v)| v.parse().ok())
        .unwrap_or(0);
    let mut body = buf[head_end..].to_vec();
    while body.len() < len {
        let n = stream.read(&mut chunk).await.ok()?;
        if n == 0 {
            break;
        }
        body.extend_from_slice(&chunk[..n]);
    }
    Some(Request {
        method,
        target,
        headers,
        body,
    })
}
