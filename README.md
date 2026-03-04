# Appattest
[![CI](https://img.shields.io/github/actions/workflow/status/PrismaPhonic/appattest/ci.yml?branch=main)](https://github.com/PrismaPhonic/appattest/actions)
[![Crates.io](https://img.shields.io/crates/v/appattest.svg)](https://crates.io/crates/appattest)
[![Docs](https://docs.rs/appattest/badge.svg)](https://docs.rs/appattest)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![maintenance](https://img.shields.io/badge/maintenance-actively--developed-brightgreen)](https://github.com/PrismaPhonic/appattest)


Verification of Apple App Attestations and Assertions for iOS apps that use
[DeviceCheck App Attest](https://developer.apple.com/documentation/devicecheck). All
verification is performed locally - no calls to Apple's servers are made during
verification.

This is a fork of [appattest-rs](https://github.com/TheDhejavu/appattest-rs) by Ayodeji
Akinola, with the full original commit history preserved.

## Why this fork?

The original crate is correct and useful, but its hot path allocates heavily, pulls in
`openssl` and `x509-parser` as dependencies, and fetches Apple's root CA certificate from
the network on every single attestation verification call - one blocking HTTPS request per
device registration. This fork rewrites the verification path with different goals and a
different API: the caller is expected to fetch and cache the root cert once (using
`fetch_apple_root_cert_pem()` or their own HTTP client), then pass it by reference to every
`verify` call.

- **Minimal allocations on the hot path.** CBOR parsing uses
  [minicbor](https://crates.io/crates/minicbor), which borrows directly from the input slice
  rather than deserializing into owned structures. Intermediate certificate arrays use
  [arrayvec](https://crates.io/crates/arrayvec) to stay on the stack. The root CA PEM is
  decoded to DER on a stack buffer. The only unavoidable allocation on the attestation path is
  the Vec returned by the base64 decode of the attestation object itself.

- **Custom DER walkers instead of x509-parser.** Rather than parsing a full X.509 certificate
  into an owned AST, extension extraction and public key extraction are done by walking the raw
  DER TLV structure directly. This eliminates the `x509-parser` dependency entirely and avoids
  the allocations that come with it.

- **aws-lc-rs as the crypto backend.** The crate uses
  [aws-lc-rs](https://crates.io/crates/aws-lc-rs) for all cryptographic operations - SHA-256
  hashing and ECDSA signature verification. `openssl` no longer appears on the hot path (it
  remains available as a dev-dependency behind the `testing` feature for generating synthetic
  test data).

- **rustls-webpki for certificate chain verification.** The certificate chain is verified with
  [rustls-webpki](https://crates.io/crates/rustls-webpki), which pairs naturally with
  aws-lc-rs and avoids a separate OpenSSL dependency for that step.

The net effect is a verification path that is lighter on both dependencies and runtime
allocations, making it more suitable for embedding in high-throughput servers.

## Overview

Apple's App Attest service lets an iOS app prove to your server that it is genuine and
unmodified. The protocol has two parts:

- **Attestation** - a one-time device registration step. The device generates a key pair and
  produces an attestation object containing a certificate chain, receipt, and authenticator
  data. Your server verifies the certificate chain back to a supplied root cert (Apple's root
  CA, or a fabricated one for testing), checks the integrity of the authenticator data, and
  stores the device's public key.

- **Assertion** - a per-request signing step. For each request the app produces an assertion
  containing a signature over a nonce derived from the request data. Your server verifies the
  signature against the stored public key and checks that the counter has advanced.

## Features

| Feature   | Default | Description                                                                   |
|-----------|---------|-------------------------------------------------------------------------------|
| `reqwest` | yes     | Enables `fetch_apple_root_cert_pem()` for fetching Apple's root CA over HTTPS |
| `testing` | no      | Enables helpers for generating synthetic attestations and assertions in tests |

## Installation

```toml
[dependencies]
appattest = "0.1"
```

To disable the network-fetch helper and avoid the reqwest dependency:

```toml
[dependencies]
appattest = { version = "0.1", default-features = false }
```

## Usage

### Verifying an Attestation

Fetch the Apple root cert once at startup and cache it. Pass the same bytes to every
`verify` call - there is no implicit network access.

```rust
use appattest::attestation::{fetch_apple_root_cert_pem, Attestation};

fn verify_attestation(
    base64_cbor: &str,
    challenge: &str,
    app_id: &str,
    key_id: &str,
    root_cert_pem: &[u8],
) -> Result<(), appattest::error::AppAttestError> {
    let cbor = Attestation::decode_base64(base64_cbor)?;
    let attestation = Attestation::from_cbor_bytes(&cbor)?;

    let (public_key_bytes, receipt) = attestation.verify(challenge, app_id, key_id, root_cert_pem)?;

    // Store public_key_bytes (65-byte uncompressed P-256 point) for assertion verification.
    // Store receipt if you use the DeviceCheck receipt service.
    Ok(())
}

fn main() {
    // Fetch once at startup and cache.
    let root_cert_pem = fetch_apple_root_cert_pem().expect("failed to fetch Apple root cert");

    let app_id = "TEAMID.com.example.app";
    let key_id = "ZSSh9dOqo0iEvnNOtTGIHaue8n4RN/Dd8FiYFphsKTI=";
    let challenge = "5b3b2303-e650-4a56-a9ec-33e3e2a90d14";
    let base64_cbor_data = "o2NmbXRv...";

    match verify_attestation(base64_cbor_data, challenge, app_id, key_id, &root_cert_pem) {
        Ok(_) => println!("attestation verified"),
        Err(e) => println!("attestation failed: {}", e),
    }
}
```

If you support multiple bundle IDs or environments, use `app_id_verifies` instead. It
accepts a slice of app IDs and returns the one that matched along with the public key and
receipt:

```rust
let app_ids: &[&'static str] = &[
    "TEAMID.com.example.app",
    "TEAMID.com.example.app.dev",
];
let (matched_app_id, public_key_bytes, receipt) =
    attestation.app_id_verifies(challenge, app_ids, key_id, &root_cert_pem)?;
```

### Verifying an Assertion

```rust
use appattest::assertion::Assertion;
use aws_lc_rs::digest::{digest, SHA256};

fn verify_assertion(
    base64_cbor: &str,
    client_data_json: &[u8],
    challenge: &str,
    app_id: &str,
    public_key_bytes: &[u8],
    previous_counter: u32,
    stored_challenge: &str,
) -> Result<(), appattest::error::AppAttestError> {
    let client_data_hash = digest(&SHA256, client_data_json);

    let mut buf = [0u8; 192];
    let assertion = Assertion::from_base64(base64_cbor, &mut buf)?;

    assertion.verify(
        client_data_hash.as_ref(),
        challenge,
        app_id,
        public_key_bytes,
        previous_counter,
        stored_challenge,
    )
}
```

If you support multiple app IDs, use `app_id_verifies` instead. It does not accept a
challenge and stored challenge - the check (`challenge == stored_challenge`) is trivial
enough that it is left to the caller. Check it yourself before calling `app_id_verifies`:

```rust
if challenge != stored_challenge {
    return Err(...);
}
let matched_app_id = assertion.app_id_verifies(
    client_data_hash.as_ref(),
    &["TEAMID.com.example.app", "TEAMID.com.example.app.dev"],
    public_key_bytes,
    previous_counter,
)?;
```

### Root cert constant

If you fetch the cert yourself (for example with your own HTTP client), the URL is exposed
as a constant:

```rust
use appattest::attestation::APPLE_ROOT_CERT_URL;
```

## References

- [Apple Developer: Validating apps that connect to your server](https://developer.apple.com/documentation/devicecheck/validating-apps-that-connect-to-your-server)
- [WWDC 2021 - Session 10244](https://developer.apple.com/videos/play/wwdc2021/10244/)
- [Original appattest-rs by Ayodeji Akinola](https://github.com/TheDhejavu/appattest-rs)
