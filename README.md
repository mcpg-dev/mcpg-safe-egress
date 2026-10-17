# mcpg-safe-egress

> An outbound HTTP client for URLs you do not trust.

`mcpg-safe-egress` sends requests to URLs that another party supplied, such as
webhook callback URLs, without letting that party aim the sender at a private
network. MCPG uses it for MCP Events webhook deliveries and callback
verification.

## What it checks

Every attempt runs the whole sequence again, so a URL that was safe when it was
registered is judged afresh each time:

1. **Static URL policy** (`SafeEgress::check_url`): `https` only, no userinfo,
   no fragment, at most 2,048 bytes, an allowed port, no internal host name
   (a single label, `.local`, `.internal`, `.svc`, `.cluster.local`,
   `.localhost`, `.home.arpa` and the other special-use names), no host from
   the operator's `deny_hosts`, and no literal address outside the global
   unicast space. Hex, octal and integer IPv4 spellings are normalized before
   the check.
2. **Resolve and classify.** The host is resolved on every attempt. If **any**
   answer falls in a block of the IANA IPv4 or IPv6 Special-Purpose Address
   Registries (plus multicast, site-local, and IPv6 outside 2000::/3), the
   host is refused. IPv6 forms that embed an IPv4 address (mapped,
   compatible, NAT64, 6to4, Teredo) are refused outright.
3. **Pin.** A fresh client connects only to the vetted addresses; the URL
   keeps the hostname, so the `Host` header and TLS SNI name the host, and
   the certificate is verified for that name. A name the pin does not cover
   is never resolved. No client, connection or TLS session is reused across
   attempts, and no proxy is used; only the platform's TLS trust roots, loaded
   once when the `SafeEgress` is built, are shared.
4. **No redirects.** A 3xx response is a failure.
5. **Re-check.** The address the response came from must be a vetted one.
6. **Bounded.** Connect timeout (3 s) and attempt timeout (10 s); at most
   `max_response_bytes` (4 KiB) of the body are read.

## Errors that do not leak

`EgressError::category()` is the only part meant for the party that supplied
the URL: `connection_refused`, `timeout` or `tls_error`. A host that does not
resolve and a host that resolves to a private address give the same category,
so the client cannot be used to map internal DNS. `EgressError::kind()` holds
the precise reason for the operator's logs and metrics. No error holds a URL,
an address, a header or a body.

```rust
use bytes::Bytes;
use http::HeaderMap;
use mcpg_safe_egress::{EgressPolicy, SafeEgress};

let egress = SafeEgress::new(EgressPolicy {
    deny_hosts: vec!["platform.example.net".into()],
    ..EgressPolicy::default()
})?;
let url = egress.check_url("https://hooks.example.com/mcp/events")?;
match egress.post(&url, HeaderMap::new(), Bytes::from_static(b"{}")).await {
    Ok(resp) => println!("{}", resp.status),
    Err(err) => println!("{}", err.category()),
}
```

`allow_private_backends: true` turns off the address classification and the
internal-name list for an operator delivering inside their own network;
`allow_http` is honoured only together with it. `deny_hosts` always applies.
Build a new `SafeEgress` when the policy changes; URLs accepted earlier are
checked against the new policy at their next attempt. Building one fails with
`PolicyError::NoTrustRoots` when the system has no usable CA certificates.

## Build / test

```bash
cargo build -p mcpg-safe-egress
cargo test  -p mcpg-safe-egress
```

## Licence

Apache-2.0.

## See also

- [IANA IPv4 Special-Purpose Address Registry](https://www.iana.org/assignments/iana-ipv4-special-registry/)
- [IANA IPv6 Special-Purpose Address Registry](https://www.iana.org/assignments/iana-ipv6-special-registry/)
- [`mcpg-standard-webhooks`](https://github.com/mcpg-dev/mcpg-standard-webhooks) — signs the requests this client sends.
