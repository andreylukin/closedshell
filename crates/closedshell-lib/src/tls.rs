//! Session-scoped CA and dynamic certificate generation.
//!
//! Each session gets a unique CA. The proxy generates leaf certs on-the-fly
//! per SNI hostname, signed by the session CA.

// TODO: implement session CA generation and per-SNI leaf cert generation
// using rcgen. This is a core component of the MITM proxy.
