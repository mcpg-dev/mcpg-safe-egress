//! A strict outbound HTTP client for URLs that untrusted parties supply, such
//! as webhook callback URLs.
//!
//! Every attempt runs the same sequence, so a destination that was safe when
//! it was registered is checked again each time it is used:
//!
//! 1. **Static URL policy** ([`SafeEgress::check_url`]): `https` only, no
//!    userinfo, no fragment, bounded length, an allowed port, a host that is
//!    not an internal name (single label, `.local`, `.internal`, `.svc`,
//!    `.cluster.local`, other special-use names) or an operator-denied
//!    domain, and no literal address outside the global unicast space.
//! 2. **Resolve and classify.** The host is resolved on every attempt. If
//!    **any** answer is not globally reachable per the IANA special-purpose
//!    registries ([`classify`]), the host is refused.
//! 3. **Pin.** A fresh client connects only to the vetted addresses while the
//!    URL keeps the hostname, so `Host` and TLS SNI name the host and the
//!    certificate is verified for it. Clients, connections and TLS sessions
//!    are never kept across attempts; only the platform's trust roots, loaded
//!    when the [`SafeEgress`] is built, are shared.
//! 4. **No redirects.** A 3xx response is a failure.
//! 5. **Re-check.** The address the response came from must be one of the
//!    vetted addresses.
//! 6. **Bounded.** Connect and attempt timeouts; the response body is read
//!    up to a cap.
//!
//! Failures are [`EgressError`]s. Outward they collapse into three
//! categories, `connection_refused`, `timeout` and `tls_error`
//! ([`ErrorCategory`]); a host that does not resolve and a host that resolves
//! to a refused address give the same category, so the client is not an
//! oracle for internal DNS. No error carries a resolved address, a URL or a
//! response body.
//!
//! `allow_private_backends` turns off the address classification and the
//! internal-name list for operators that deliver to their own network;
//! `allow_http` is honoured only together with it.

pub mod classify;
mod client;
mod host;
mod policy;

#[cfg(test)]
mod test_server;

pub use client::{
    EgressError, EgressErrorKind, EgressResponse, ErrorCategory, Resolve, ResolveFuture,
    SafeEgress, SystemResolver,
};
pub use policy::{CallbackUrl, EgressPolicy, PolicyError, UrlRefusal};
