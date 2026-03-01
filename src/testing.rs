//! Test helpers for constructing synthetic Apple App Attestation objects.
//!
//! Only available under `feature = "testing"`. Allows tests to build fully
//! valid attestation and assertion blobs signed by an in-process test CA, so
//! the complete verification path can be exercised without a real iOS device.
//!
//! A static two-level CA is embedded here:
//! - Root CA (P-384, self-signed) - pass [`TEST_ROOT_CA_CERT_PEM`] to
//!   `verify_with_cert` / `app_id_verifies_with_cert` in place of the real
//!   Apple root.
//! - Intermediate CA (P-256, signed by root) - used to sign per-call credential
//!   certs, mirroring Apple's "App Attestation CA 1".
//!
//! Both were generated once with openssl and are embedded as constants along
//! with the intermediate private key so fresh credential certs can be signed at
//! test time.
//!
//! The nonce extension at OID 1.2.840.113635.100.8.2 is encoded exactly as
//! Apple produces it:
//!
//! ```text
//! SEQUENCE {
//!   [1] EXPLICIT {
//!     OCTET STRING (32 bytes)
//!   }
//! }
//! ```
//!
//! `extract_nonce_from_cert` in `attestation.rs` walks this structure directly
//! via `der_unwrap_tag`, stripping the `04 20` OCTET STRING tag+length to yield
//! the raw 32-byte nonce.

use base64::{engine::general_purpose, Engine};
use byteorder::{BigEndian, ByteOrder};
use ciborium::{cbor, Value};
use openssl::{
    asn1::{Asn1Integer, Asn1Object, Asn1OctetString, Asn1Time},
    bn::BigNum,
    ec::{EcGroup, EcKey, PointConversionForm},
    hash::{hash, MessageDigest},
    nid::Nid,
    pkey::PKey,
    rand::rand_bytes,
    x509::{extension::BasicConstraints, X509Builder, X509NameBuilder, X509},
};
use p256::ecdsa::{signature::Signer, DerSignature, SigningKey};
use sha2::{Digest, Sha256 as Sha256Digest};

/// PEM bytes of the test root CA certificate (P-384).
/// Pass this to `verify_with_cert` / `app_id_verifies_with_cert` in tests.
pub const TEST_ROOT_CA_CERT_PEM: &[u8] = b"-----BEGIN CERTIFICATE-----\n\
MIICNzCCAb6gAwIBAgIUFeZt+1JiuWUm7RJtzNA3etiyaTgwCgYIKoZIzj0EAwIw\n\
SzElMCMGA1UEAwwcVGVzdCBBcHAgQXR0ZXN0YXRpb24gUm9vdCBDQTENMAsGA1UE\n\
CgwEVGVzdDETMBEGA1UECAwKQ2FsaWZvcm5pYTAeFw0yNjAyMjcxODU2MTBaFw00\n\
NjAyMjIxODU2MTBaMEsxJTAjBgNVBAMMHFRlc3QgQXBwIEF0dGVzdGF0aW9uIFJv\n\
b3QgQ0ExDTALBgNVBAoMBFRlc3QxEzARBgNVBAgMCkNhbGlmb3JuaWEwdjAQBgcq\n\
hkjOPQIBBgUrgQQAIgNiAAT2cBxT0pWtGUECFzUn+Hdx6MaDyVoOHFcjsd+wqlKZ\n\
IKNg+bopRItVz79g5Rn3F7126h7Q6ZEosNMCMiV2u1t47NBVGAvs0FtM/gqN2hZv\n\
4vy3F2l3Vwd2TatWzpRC0iKjYzBhMB0GA1UdDgQWBBR9vyJAdCH/3azKhgGa9JSh\n\
5LVM+DAfBgNVHSMEGDAWgBR9vyJAdCH/3azKhgGa9JSh5LVM+DAPBgNVHRMBAf8E\n\
BTADAQH/MA4GA1UdDwEB/wQEAwIBBjAKBggqhkjOPQQDAgNnADBkAjBi8yL62XLW\n\
g604KgEaEn9IFxR2c4vx+K0ZhYjPq6OU8X4pq9757JityNdJW1THgxgCMAo9bL44\n\
UUoFJPTgvmKobdPOIUQ1oRNRYnGmtfovWa31WM2IK0mOs+lpWYncFZOr3Q==\n\
-----END CERTIFICATE-----\n";

const TEST_INT_CA_CERT_PEM: &[u8] = b"-----BEGIN CERTIFICATE-----\n\
MIICHDCCAaGgAwIBAgIUYM1hx4yf7fLmLiIQ57Ov3d5h27cwCgYIKoZIzj0EAwIw\n\
SzElMCMGA1UEAwwcVGVzdCBBcHAgQXR0ZXN0YXRpb24gUm9vdCBDQTENMAsGA1UE\n\
CgwEVGVzdDETMBEGA1UECAwKQ2FsaWZvcm5pYTAeFw0yNjAyMjcxODU2MTBaFw00\n\
NjAyMjIxODU2MTBaMEgxIjAgBgNVBAMMGVRlc3QgQXBwIEF0dGVzdGF0aW9uIENB\n\
IDExDTALBgNVBAoMBFRlc3QxEzARBgNVBAgMCkNhbGlmb3JuaWEwWTATBgcqhkjO\n\
PQIBBggqhkjOPQMBBwNCAARXQJU3qZo9zCz2xZpq0ZyFfYN+WpG6uEdt++GKRcaj\n\
jmJiMYBpxOBtrecCgvPlrZdS7UlHhmUg2Zdfnvu7+DEIo2YwZDASBgNVHRMBAf8E\n\
CDAGAQH/AgEAMB0GA1UdDgQWBBQzJ5DNIxBnjG4jq4wZ0ZgB+4SYsDAfBgNVHSME\n\
GDAWgBR9vyJAdCH/3azKhgGa9JSh5LVM+DAOBgNVHQ8BAf8EBAMCAQYwCgYIKoZI\n\
zj0EAwIDaQAwZgIxAJ2KT9ZsXtEtvemPNnp5FsyM1WEli1qztnjhjDV5qHcCFydq\n\
g8rl2BjX1qwXyl9odQIxAMXiN2QWgtbC7VqNUjZFevnwVPwXgkRr+g6mqKjWVTTf\n\
rGDANtkIDXqrnt8GyCZQWw==\n\
-----END CERTIFICATE-----\n";

const TEST_INT_CA_KEY_PEM: &[u8] = b"-----BEGIN EC PRIVATE KEY-----\n\
MHcCAQEEIFM/DSPwekMvsqNpx/wpynoxNHL6driuUlXKdzaxVuIEoAoGCCqGSM49\n\
AwEHoUQDQgAEV0CVN6maPcws9sWaatGchX2DflqRurhHbfvhikXGo45iYjGAacTg\n\
ba3nAoLz5a2XUu1JR4ZlINmXX577u/gxCA==\n\
-----END EC PRIVATE KEY-----\n";

/// Output of [`build_test_attestation`].
pub struct TestAttestation {
    /// CBOR-encoded attestation bytes. Base64-encode and pass to
    /// `Attestation::from_base64`, or decode directly via
    /// `Attestation::from_cbor` if exposed.
    pub cbor: Vec<u8>,
    /// Base64-encoded key ID (standard encoding). Pass to `verify_with_cert` /
    /// `app_id_verifies_with_cert`.
    pub key_id: String,
    /// The device's P-256 private key. Keep this to sign assertions in
    /// subsequent calls.
    pub device_key: SigningKey,
}

/// Build a fully valid synthetic attestation signed by the embedded test CA.
///
/// The returned [`TestAttestation`] will pass
/// `Attestation::app_id_verifies_with_cert(challenge, &[app_id], &key_id,
/// TEST_ROOT_CA_CERT_PEM)`.
pub fn build_test_attestation(challenge: &str, app_id: &str) -> TestAttestation {
    // Generate a P-256 device keypair via openssl, then import the scalar into
    // p256 for signing.
    let group = EcGroup::from_curve_name(Nid::X9_62_PRIME256V1).unwrap();
    let openssl_key = EcKey::generate(&group).unwrap();

    let scalar_bytes = openssl_key.private_key().to_vec();
    // p256 expects a 32-byte scalar; left-pad if shorter.
    let mut scalar32 = [0u8; 32];
    let off = 32 - scalar_bytes.len();
    scalar32[off..].copy_from_slice(&scalar_bytes);
    let signing_key = SigningKey::from_bytes(&scalar32.into()).unwrap();

    let device_pkey = PKey::from_ec_key(openssl_key.clone()).unwrap();

    // key_id = base64(SHA256(uncompressed public key bytes))
    let mut ctx = openssl::bn::BigNumContext::new().unwrap();
    let pub_key_bytes = openssl_key
        .public_key()
        .to_bytes(&group, PointConversionForm::UNCOMPRESSED, &mut ctx)
        .unwrap();
    let pub_key_hash = hash(MessageDigest::sha256(), &pub_key_bytes).unwrap();
    let key_id = general_purpose::STANDARD.encode(pub_key_hash.as_ref());
    let key_id_bytes = pub_key_hash.to_vec();

    // authenticator data layout:
    //   [0..32]  rp_id_hash  = SHA256(app_id)
    //   [32]     flags       = 0x41 (attested credential data included)
    //   [33..37] counter     = 0u32 big-endian
    //   [37..53] aaguid      = b"appattest\0\0\0\0\0\0\0" (16 bytes)
    //   [53..55] cred_id_len = 32u16 big-endian
    //   [55..87] cred_id     = key_id raw bytes
    let rp_id_hash: [u8; 32] = Sha256Digest::digest(app_id.as_bytes()).into();
    let mut aaguid = [0u8; 16];
    aaguid[..9].copy_from_slice(b"appattest");

    let mut auth_data = Vec::with_capacity(87);
    auth_data.extend_from_slice(&rp_id_hash);
    auth_data.push(0x41);
    auth_data.extend_from_slice(&[0u8; 4]);
    auth_data.extend_from_slice(&aaguid);
    let mut len_bytes = [0u8; 2];
    BigEndian::write_u16(&mut len_bytes, key_id_bytes.len() as u16);
    auth_data.extend_from_slice(&len_bytes);
    auth_data.extend_from_slice(&key_id_bytes);

    // nonce = SHA256(authData || SHA256(challenge))
    let client_data_hash: [u8; 32] = Sha256Digest::digest(challenge.as_bytes()).into();
    let nonce: [u8; 32] = {
        let mut h = sha2::Sha256::new();
        sha2::Digest::update(&mut h, &auth_data);
        sha2::Digest::update(&mut h, client_data_hash);
        sha2::Digest::finalize(h).into()
    };

    let cred_cert_der = build_cred_cert(&device_pkey, nonce.as_slice(), &key_id);
    let int_cert_der = X509::from_pem(TEST_INT_CA_CERT_PEM)
        .unwrap()
        .to_der()
        .unwrap();

    let cbor = encode_attestation_cbor(&cred_cert_der, &int_cert_der, &auth_data);

    TestAttestation {
        cbor,
        key_id,
        device_key: signing_key,
    }
}

/// Build a synthetic assertion signed by the given device private key.
///
/// Returns raw CBOR bytes ready for `Assertion::from_assertion`.
///
/// `previous_counter` should be the counter value stored server-side;
/// the assertion will use `previous_counter + 1`.
pub fn build_test_assertion(
    app_id: &str,
    client_data_hash: impl AsRef<[u8]>,
    previous_counter: u32,
    device_key: &SigningKey,
) -> Vec<u8> {
    let rp_id_hash: [u8; 32] = Sha256Digest::digest(app_id.as_bytes()).into();
    let counter = previous_counter + 1;

    let mut auth_data = Vec::with_capacity(37);
    auth_data.extend_from_slice(&rp_id_hash);
    auth_data.push(0x01);
    let mut counter_bytes = [0u8; 4];
    BigEndian::write_u32(&mut counter_bytes, counter);
    auth_data.extend_from_slice(&counter_bytes);

    let nonce: Vec<u8> = {
        let mut h = sha2::Sha256::new();
        sha2::Digest::update(&mut h, &auth_data);
        sha2::Digest::update(&mut h, client_data_hash.as_ref());
        sha2::Digest::finalize(h).to_vec()
    };

    let sig: DerSignature = device_key.sign(&nonce);
    encode_assertion_cbor(&auth_data, sig.as_bytes())
}

fn build_cred_cert(
    device_pkey: &PKey<openssl::pkey::Private>,
    nonce: &[u8],
    key_id: &str,
) -> Vec<u8> {
    assert_eq!(nonce.len(), 32);

    let int_cert = X509::from_pem(TEST_INT_CA_CERT_PEM).unwrap();
    let int_key = PKey::private_key_from_pem(TEST_INT_CA_KEY_PEM).unwrap();

    let mut name_builder = X509NameBuilder::new().unwrap();
    name_builder.append_entry_by_text("CN", key_id).unwrap();
    name_builder
        .append_entry_by_text("OU", "AAA Certification")
        .unwrap();
    name_builder.append_entry_by_text("O", "Test").unwrap();
    name_builder
        .append_entry_by_text("ST", "California")
        .unwrap();
    let subject_name = name_builder.build();

    let mut builder = X509Builder::new().unwrap();
    builder.set_version(2).unwrap();
    builder.set_subject_name(&subject_name).unwrap();
    builder.set_issuer_name(int_cert.subject_name()).unwrap();
    builder.set_pubkey(device_pkey).unwrap();
    builder
        .set_not_before(&Asn1Time::days_from_now(0).unwrap())
        .unwrap();
    builder
        .set_not_after(&Asn1Time::days_from_now(365).unwrap())
        .unwrap();

    let mut serial_bytes = [0u8; 8];
    rand_bytes(&mut serial_bytes).unwrap();
    let serial_asn1 = Asn1Integer::from_bn(&BigNum::from_slice(&serial_bytes).unwrap()).unwrap();
    builder.set_serial_number(&serial_asn1).unwrap();

    builder
        .append_extension(BasicConstraints::new().build().unwrap())
        .unwrap();

    // Nonce extension OID 1.2.840.113635.100.8.2, encoding:
    //   30 24        SEQUENCE, length 36
    //     a1 22      [1] EXPLICIT, length 34
    //       04 20    OCTET STRING, length 32
    //         <nonce bytes>
    //
    // The verifier calls parse_ber on this, finds the [1] item as Unknown, and
    // returns data[2..] which strips the 04 20 header to yield the raw 32-byte
    // nonce.
    let mut ext_value = Vec::with_capacity(38);
    ext_value.extend_from_slice(&[0x30, 0x24, 0xa1, 0x22, 0x04, 0x20]);
    ext_value.extend_from_slice(nonce);

    let oid = Asn1Object::from_str("1.2.840.113635.100.8.2").unwrap();
    let octet_val = Asn1OctetString::new_from_bytes(&ext_value).unwrap();
    builder
        .append_extension(
            openssl::x509::X509Extension::new_from_der(&oid, false, &octet_val).unwrap(),
        )
        .unwrap();

    builder.sign(&int_key, MessageDigest::sha256()).unwrap();
    builder.build().to_der().unwrap()
}

fn encode_attestation_cbor(cred_cert_der: &[u8], int_cert_der: &[u8], auth_data: &[u8]) -> Vec<u8> {
    let val = cbor!({
        "fmt" => "apple-appattest",
        "attStmt" => {
            "x5c" => [
                Value::Bytes(cred_cert_der.to_vec()),
                Value::Bytes(int_cert_der.to_vec())
            ],
            "receipt" => Value::Bytes(vec![])
        },
        "authData" => Value::Bytes(auth_data.to_vec())
    })
    .unwrap();

    let mut buf = Vec::new();
    ciborium::into_writer(&val, &mut buf).unwrap();
    buf
}

fn encode_assertion_cbor(auth_data: &[u8], signature: &[u8]) -> Vec<u8> {
    let val = cbor!({
        "authenticatorData" => Value::Bytes(auth_data.to_vec()),
        "signature" => Value::Bytes(signature.to_vec())
    })
    .unwrap();

    let mut buf = Vec::new();
    ciborium::into_writer(&val, &mut buf).unwrap();
    buf
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::assertion::Assertion;
    use crate::attestation::Attestation;

    const TEST_APP_ID: &str = "GBJ682NHC4.com.rumble.PassKeyDemoApp";

    #[test]
    fn round_trip_attestation() {
        let challenge = "test_challenge_12345";
        let ta = build_test_attestation(challenge, TEST_APP_ID);
        let b64 = general_purpose::STANDARD.encode(&ta.cbor);
        let cbor = Attestation::decode_base64(&b64).expect("decode_base64 failed");
        Attestation::from_cbor_bytes(&cbor)
            .expect("from_cbor_bytes failed")
            .app_id_verifies_with_cert(challenge, &[TEST_APP_ID], &ta.key_id, TEST_ROOT_CA_CERT_PEM)
            .expect("app_id_verifies_with_cert failed");
    }

    #[test]
    fn round_trip_assertion() {
        let challenge = "test_challenge_12345";
        let client_data_hash = Sha256Digest::digest(b"some payload").to_vec();

        let ta = build_test_attestation(challenge, TEST_APP_ID);
        let b64 = general_purpose::STANDARD.encode(&ta.cbor);
        let cbor = Attestation::decode_base64(&b64).unwrap();
        let pub_key_bytes = Attestation::from_cbor_bytes(&cbor)
            .unwrap()
            .extract_client_pub_key_bytes()
            .unwrap();

        let assertion_cbor =
            build_test_assertion(TEST_APP_ID, &client_data_hash, 0, &ta.device_key);

        Assertion::from_assertion(&assertion_cbor)
            .unwrap()
            .app_id_verifies(&client_data_hash, &[TEST_APP_ID], pub_key_bytes, 0)
            .expect("assertion app_id_verifies failed");
    }
}
