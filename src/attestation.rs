use crate::{authenticator::AuthenticatorData, error::AppAttestError};
use base64::{engine::general_purpose::STANDARD as BASE64_STANDARD, Engine};

use arrayvec::ArrayVec;
use aws_lc_rs::digest::{digest, Context as DigestContext, SHA256};

use rustls_pki_types::{CertificateDer, UnixTime};
use webpki::{
    anchor_from_trusted_cert, EndEntityCert, KeyUsage as WebpkiKeyUsage, ALL_VERIFICATION_ALGS,
};

const PEM_BEGIN: &str = "-----BEGIN CERTIFICATE-----";
const PEM_END: &str = "-----END CERTIFICATE-----";

/// The URL of Apple's App Attestation Root CA certificate PEM.
pub const APPLE_ROOT_CERT_URL: &str =
    "https://www.apple.com/certificateauthority/Apple_App_Attestation_Root_CA.pem";

/// Fetches the Apple App Attestation Root CA certificate PEM bytes from Apple's servers.
///
/// The returned bytes can be passed directly to [`Attestation::verify`] or
/// [`Attestation::app_id_verifies`]. Cache the result to avoid a network
/// round-trip on every verification.
#[cfg(feature = "reqwest")]
pub fn fetch_apple_root_cert_pem() -> Result<Vec<u8>, AppAttestError> {
    use reqwest::blocking::Client;
    use std::time::Duration;
    let client = Client::builder()
        .timeout(Duration::from_secs(30))
        .build()
        .map_err(|e| AppAttestError::Message(format!("Failed to build HTTP client: {}", e)))?;
    let response = client
        .get(APPLE_ROOT_CERT_URL)
        .send()
        .map_err(|e| AppAttestError::Message(format!("Network request failed: {}", e)))?;
    if !response.status().is_success() {
        return Err(AppAttestError::Message(format!(
            "Failed to fetch root cert: HTTP {}",
            response.status()
        )));
    }
    response
        .bytes()
        .map(|b| b.to_vec())
        .map_err(|e| AppAttestError::Message(format!("Failed to read response body: {}", e)))
}

/// Read a DER TLV length field starting at `buf[pos]`.
/// Returns `(length, bytes_consumed)` or `None` if the buffer is too short.
fn der_read_len(buf: &[u8], pos: usize) -> Option<(usize, usize)> {
    let b = *buf.get(pos)?;
    if b < 0x80 {
        Some((b as usize, 1))
    } else {
        let n = (b & 0x7f) as usize;
        if n == 0 || n > 4 || pos + n >= buf.len() {
            return None;
        }
        let mut len = 0usize;
        for i in 0..n {
            len = (len << 8) | (*buf.get(pos + 1 + i)? as usize);
        }
        Some((len, 1 + n))
    }
}

/// If `buf` starts with a DER TLV whose tag matches `expected_tag`,
/// return a slice of its value bytes. Otherwise return `None`.
fn der_unwrap_tag(buf: &[u8], expected_tag: u8) -> Option<&[u8]> {
    if buf.first()? != &expected_tag {
        return None;
    }
    let (len, consumed) = der_read_len(buf, 1)?;
    let start = 1 + consumed;
    buf.get(start..start + len)
}

/// Walk the DER Extensions in `cert_der` and return the raw value bytes
/// (contents of the extnValue OCTET STRING) for the first extension whose
/// OID matches `target_oid_bytes` (the raw DER OID value bytes, without tag/length).
///
/// Returns `None` if the extension is not present or the certificate cannot be parsed.
fn der_find_extension<'a>(cert_der: &'a [u8], target_oid_bytes: &[u8]) -> Option<&'a [u8]> {
    // Certificate ::= SEQUENCE { tbsCertificate SEQUENCE { ... } ... }
    let cert_seq = der_unwrap_tag(cert_der, 0x30)?;
    // TBSCertificate is the first item inside the outer SEQUENCE.
    let tbs_seq = der_unwrap_tag(cert_seq, 0x30)?;

    // Walk TBSCertificate fields until we find the [3] EXPLICIT extensions tag (0xa3).
    let mut pos = 0;
    while pos < tbs_seq.len() {
        let tag = *tbs_seq.get(pos)?;
        let (len, consumed) = der_read_len(tbs_seq, pos + 1)?;
        let value_start = pos + 1 + consumed;
        let value_end = value_start + len;
        if value_end > tbs_seq.len() {
            return None;
        }
        if tag == 0xa3 {
            // Found [3] EXPLICIT - its contents are a SEQUENCE OF Extension.
            let exts_seq = der_unwrap_tag(&tbs_seq[value_start..value_end], 0x30)?;
            return der_scan_extensions(exts_seq, target_oid_bytes);
        }
        pos = value_end;
    }
    None
}

/// Scan a DER SEQUENCE OF Extension bodies for a matching OID.
/// Returns the raw bytes of the matching extension's extnValue OCTET STRING contents.
fn der_scan_extensions<'a>(exts: &'a [u8], target_oid_bytes: &[u8]) -> Option<&'a [u8]> {
    let mut pos = 0;
    while pos < exts.len() {
        // Each Extension is a SEQUENCE.
        let ext_seq = der_unwrap_tag(&exts[pos..], 0x30)?;
        let (len, consumed) = der_read_len(exts, pos + 1)?;
        let ext_end = pos + 1 + consumed + len;

        // First field in Extension SEQUENCE is the OID.
        if ext_seq.first()? == &0x06 {
            let (oid_len, oid_consumed) = der_read_len(ext_seq, 1)?;
            let oid_bytes = ext_seq.get(1 + oid_consumed..1 + oid_consumed + oid_len)?;
            if oid_bytes == target_oid_bytes {
                // Found it. The last field in the Extension SEQUENCE is the
                // extnValue OCTET STRING. Unwrap it to get the raw value bytes.
                let rest = &ext_seq[1 + oid_consumed + oid_len..];
                // Skip optional critical BOOLEAN if present (tag 0x01).
                let value_start = if rest.first() == Some(&0x01) {
                    let (bl, bc) = der_read_len(rest, 1)?;
                    1 + bc + bl
                } else {
                    0
                };
                let octet_str_contents = der_unwrap_tag(&rest[value_start..], 0x04)?;
                return Some(octet_str_contents);
            }
        }
        pos = ext_end;
    }
    None
}

/// Maximum DER size for a root CA certificate. The real Apple App Attestation
/// Root CA is 549 bytes; the test CA is 571 bytes. 640 gives comfortable margin.
const MAX_ROOT_DER_SIZE: usize = 640;

pub struct Attestation<'a> {
    /// DER-encoded certificate slices, borrowed from the decoded buffer.
    /// certificates[0] is the credential cert; certificates[1..] are
    /// intermediates. Apple's chain has at most 3 certs (leaf + 2 intermediates).
    certificates: ArrayVec<&'a [u8], 3>,
    /// Receipt bytes, borrowed from the decoded buffer.
    receipt: &'a [u8],
    /// Authenticator data bytes, borrowed from the decoded buffer.
    auth_data: &'a [u8],
}

impl<'a> Attestation<'a> {
    /// Parse an `Attestation` from raw CBOR bytes,
    /// borrowing directly from the input.
    fn from_cbor(cbor: &'a [u8]) -> Result<Self, AppAttestError> {
        let mut decoder = minicbor::Decoder::new(cbor);
        let map_len = decoder
            .map()
            .map_err(|_| AppAttestError::Message("expected CBOR map".to_string()))?;

        let mut certificates: Option<ArrayVec<&'a [u8], 3>> = None;
        let mut receipt: Option<&'a [u8]> = None;
        let mut auth_data: Option<&'a [u8]> = None;

        let entries = map_len.unwrap_or(0);
        for _ in 0..entries {
            let key = decoder.str().map_err(|_| {
                AppAttestError::Message("expected string key in root map".to_string())
            })?;
            match key {
                "attStmt" => {
                    let stmt_len = decoder.map().map_err(|_| {
                        AppAttestError::Message("expected CBOR map for attStmt".to_string())
                    })?;
                    let stmt_entries = stmt_len.unwrap_or(0);
                    for _ in 0..stmt_entries {
                        let stmt_key = decoder.str().map_err(|_| {
                            AppAttestError::Message("expected string key in attStmt".to_string())
                        })?;
                        match stmt_key {
                            "x5c" => {
                                let arr_len = decoder.array().map_err(|_| {
                                    AppAttestError::Message("expected array for x5c".to_string())
                                })?;
                                let cert_count = arr_len.unwrap_or(0) as usize;
                                if cert_count > 3 {
                                    return Err(AppAttestError::Message(format!(
                                        "x5c contains {} certificates; Apple's chain has at most 3",
                                        cert_count
                                    )));
                                }
                                let mut certs: ArrayVec<&'a [u8], 3> = ArrayVec::new();
                                for _ in 0..cert_count {
                                    let cert_bytes = decoder.bytes().map_err(|_| {
                                        AppAttestError::Message(
                                            "expected bytes for certificate".to_string(),
                                        )
                                    })?;
                                    // Safety: cert_count <= 3, so push cannot overflow.
                                    unsafe { certs.push_unchecked(cert_bytes) };
                                }
                                certificates = Some(certs);
                            }
                            "receipt" => {
                                receipt = Some(decoder.bytes().map_err(|_| {
                                    AppAttestError::Message(
                                        "expected bytes for receipt".to_string(),
                                    )
                                })?);
                            }
                            _ => {
                                decoder.skip().map_err(|_| {
                                    AppAttestError::Message(
                                        "failed to skip unknown attStmt field".to_string(),
                                    )
                                })?;
                            }
                        }
                    }
                }
                "authData" => {
                    auth_data = Some(decoder.bytes().map_err(|_| {
                        AppAttestError::Message("expected bytes for authData".to_string())
                    })?);
                }
                _ => {
                    decoder.skip().map_err(|_| {
                        AppAttestError::Message("failed to skip unknown root field".to_string())
                    })?;
                }
            }
        }

        let certificates = certificates
            .ok_or_else(|| AppAttestError::Message("missing x5c certificates".to_string()))?;
        if certificates.is_empty() {
            return Err(AppAttestError::Message(
                "x5c certificates array is empty".to_string(),
            ));
        }
        let receipt =
            receipt.ok_or_else(|| AppAttestError::Message("missing receipt".to_string()))?;
        let auth_data =
            auth_data.ok_or_else(|| AppAttestError::Message("missing authData".to_string()))?;

        Ok(Attestation {
            certificates,
            receipt,
            auth_data,
        })
    }

    /// Decodes a Base64-encoded CBOR attestation string into raw CBOR bytes.
    ///
    /// Call [`from_cbor_bytes`](Self::from_cbor_bytes) on the returned buffer
    /// to parse it. Splitting decode and parse into two steps lets the caller
    /// own the buffer and pass a borrow, keeping lifetimes explicit:
    ///
    /// ```no_run
    /// # use appattest::attestation::Attestation;
    /// # let b64 = "";
    /// let cbor = Attestation::decode_base64(b64)?;
    /// let attestation = Attestation::from_cbor_bytes(&cbor)?;
    /// # Ok::<(), appattest::error::AppAttestError>(())
    /// ```
    ///
    /// # Errors
    /// Returns `AppAttestError` if Base64 decoding fails.
    pub fn decode_base64(base64_attestation: &str) -> Result<Vec<u8>, AppAttestError> {
        BASE64_STANDARD
            .decode(base64_attestation)
            .map_err(|e| AppAttestError::Message(format!("Failed to decode Base64: {}", e)))
    }

    /// Creates a new `Attestation` from raw CBOR bytes.
    /// The returned `Attestation` borrows from the input slice.
    ///
    /// # Errors
    /// Returns `AppAttestError` if deserialization fails.
    pub fn from_cbor_bytes(cbor: &'a [u8]) -> Result<Self, AppAttestError> {
        Self::from_cbor(cbor)
    }

    /// Decode a single PEM certificate into DER bytes on the stack.
    ///
    /// Returns a `([u8; MAX_ROOT_DER_SIZE], usize)` pair; use `&buf[..len]`
    /// to get the actual DER slice. No heap allocation occurs.
    fn pem_to_der(pem: &[u8]) -> Result<([u8; MAX_ROOT_DER_SIZE], usize), AppAttestError> {
        let pem_str = std::str::from_utf8(pem)
            .map_err(|_| AppAttestError::Message("root cert PEM is not valid UTF-8".to_string()))?;
        let start = pem_str
            .find(PEM_BEGIN)
            .ok_or_else(|| AppAttestError::Message("no BEGIN CERTIFICATE in PEM".to_string()))?
            + PEM_BEGIN.len();
        let stop = pem_str
            .find(PEM_END)
            .ok_or_else(|| AppAttestError::Message("no END CERTIFICATE in PEM".to_string()))?;
        let b64_with_whitespace = &pem_str[start..stop];

        // Strip whitespace into a temporary stack buffer before decoding.
        // Max base64 length for MAX_ROOT_DER_SIZE bytes of DER is ceil(640*4/3) = 854.
        let mut b64_buf = [0u8; 854];
        let mut b64_len = 0usize;
        for b in b64_with_whitespace.bytes() {
            if !b.is_ascii_whitespace() {
                if b64_len >= b64_buf.len() {
                    return Err(AppAttestError::Message(
                        "PEM base64 body too large for root CA buffer".to_string(),
                    ));
                }
                b64_buf[b64_len] = b;
                b64_len += 1;
            }
        }

        let mut der_buf = [0u8; MAX_ROOT_DER_SIZE];
        let written = BASE64_STANDARD
            .decode_slice(&b64_buf[..b64_len], &mut der_buf)
            .map_err(|e| AppAttestError::Message(format!("PEM base64 decode failed: {}", e)))?;
        Ok((der_buf, written))
    }

    /// Verifies the certificate chain in the attestation statement using rustls-webpki.
    fn verify_certificates(
        certificates: &[&[u8]],
        apple_root_cert_pem: &[u8],
    ) -> Result<(), AppAttestError> {
        if certificates.is_empty() {
            return Err(AppAttestError::Message("certificates is empty".to_string()));
        }

        let (root_der_buf, root_der_len) = Self::pem_to_der(apple_root_cert_pem)?;
        let root_cert_der = CertificateDer::from(&root_der_buf[..root_der_len]);
        let trust_anchor = anchor_from_trusted_cert(&root_cert_der)
            .map_err(|e| AppAttestError::Message(format!("invalid root cert: {}", e)))?;

        let leaf_der = CertificateDer::from(certificates[0]);
        // At most 2 intermediates (Apple's chain: leaf + intermediate + root, root is the trust anchor).
        let mut intermediates: ArrayVec<CertificateDer<'_>, 2> = ArrayVec::new();
        for c in &certificates[1..] {
            intermediates
                .try_push(CertificateDer::from(*c))
                .map_err(|_| AppAttestError::Message("too many intermediate certs".to_string()))?;
        }

        let leaf = EndEntityCert::try_from(&leaf_der)
            .map_err(|e| AppAttestError::Message(format!("invalid leaf cert: {}", e)))?;

        leaf.verify_for_usage(
            ALL_VERIFICATION_ALGS,
            &[trust_anchor],
            &intermediates,
            UnixTime::now(),
            WebpkiKeyUsage::client_auth(),
            None,
            None,
        )
        .map_err(|e| AppAttestError::Message(format!("cert chain verification failed: {}", e)))?;

        Ok(())
    }

    /// Extracts the nonce from the credential certificate's extension.
    ///
    /// Walks the DER TLV structure directly - no heap allocation. The nonce
    /// lives at OID 1.2.840.113635.100.8.2 inside a SEQUENCE > [1] EXPLICIT
    /// > OCTET STRING (32 bytes).
    fn extract_nonce_from_cert(cert_der: &[u8]) -> Result<[u8; 32], AppAttestError> {
        // DER OID bytes for 1.2.840.113635.100.8.2
        const CRED_CERT_OID: &[u8] = &[0x2a, 0x86, 0x48, 0x86, 0xf7, 0x63, 0x64, 0x08, 0x02];

        let ext_value = der_find_extension(cert_der, CRED_CERT_OID).ok_or(
            AppAttestError::Message("Certificate did not contain credCert extension".to_string()),
        )?;

        // ext_value is the raw bytes of the extension's extnValue OCTET STRING contents.
        // Structure: SEQUENCE { [1] EXPLICIT { OCTET STRING (32 bytes) } }
        let seq = der_unwrap_tag(ext_value, 0x30).ok_or(AppAttestError::ExpectedASN1Node)?;
        // [1] EXPLICIT context tag = 0xa1
        let ctx = der_unwrap_tag(seq, 0xa1).ok_or(AppAttestError::ExpectedASN1Node)?;
        // OCTET STRING tag = 0x04, length = 0x20 (32)
        let nonce_bytes =
            der_unwrap_tag(ctx, 0x04).ok_or(AppAttestError::ExpectedOctetStringInsideASN1Node)?;

        nonce_bytes.try_into().map_err(|_| {
            AppAttestError::Message(format!(
                "expected 32-byte nonce in credCert extension, got {}",
                nonce_bytes.len()
            ))
        })
    }

    /// Creates a SHA-256 hash of the challenge string.
    fn client_data_hash(challenge: &str) -> [u8; 32] {
        digest(&SHA256, challenge.as_bytes())
            .as_ref()
            .try_into()
            .unwrap()
    }

    /// Creates a SHA-256 hash of authData concatenated with clientDataHash.
    fn nonce_hash(auth_data: &[u8], client_data_hash: [u8; 32]) -> [u8; 32] {
        let mut ctx = DigestContext::new(&SHA256);
        ctx.update(auth_data);
        ctx.update(&client_data_hash);
        ctx.finish().as_ref().try_into().unwrap()
    }

    fn verify_public_key_hash(
        cert_der: &[u8],
        key_identifier: &[u8],
    ) -> Result<([u8; 65], bool), AppAttestError> {
        let pub_key_bytes = Self::extract_pub_key_from_cert_der(cert_der)?;
        let pub_key_hash: [u8; 32] = digest(&SHA256, &pub_key_bytes).as_ref().try_into().unwrap();
        Ok((pub_key_bytes, pub_key_hash.as_ref() == key_identifier))
    }

    /// Walk the DER TBSCertificate and return the raw EC public key bytes from
    /// the SubjectPublicKeyInfo (the 5th SEQUENCE field, after signature,
    /// issuer, validity, and subject). Returns the BIT STRING contents minus
    /// the leading unused-bits byte - i.e., the 65-byte uncompressed EC point
    /// for P-256 keys.
    ///
    /// all returned bytes are borrowed from `cert_der`.
    fn der_extract_spki_key_bytes(cert_der: &[u8]) -> Option<&[u8]> {
        // Certificate ::= SEQUENCE { tbsCertificate SEQUENCE { ... } ... }
        let cert_seq = der_unwrap_tag(cert_der, 0x30)?;
        let tbs_seq = der_unwrap_tag(cert_seq, 0x30)?;

        let mut pos = 0;
        let mut seq_count = 0u8;

        while pos < tbs_seq.len() {
            let tag = *tbs_seq.get(pos)?;
            let (len, consumed) = der_read_len(tbs_seq, pos + 1)?;
            let value_start = pos + 1 + consumed;
            let value_end = value_start + len;
            if value_end > tbs_seq.len() {
                return None;
            }
            if tag == 0x30 {
                seq_count += 1;
                if seq_count == 5 {
                    // SubjectPublicKeyInfo ::= SEQUENCE { AlgorithmIdentifier,
                    // BIT STRING }
                    let spki = &tbs_seq[value_start..value_end];
                    // Skip the AlgorithmIdentifier SEQUENCE.
                    if spki.first()? != &0x30 {
                        return None;
                    }
                    let (ai_len, ai_consumed) = der_read_len(spki, 1)?;
                    let ai_end = 1 + ai_consumed + ai_len;
                    // Read the BIT STRING that follows.
                    let rest = spki.get(ai_end..)?;
                    let bit_str = der_unwrap_tag(rest, 0x03)?;
                    // Drop the leading unused-bits byte (always 0x00 for EC keys).
                    return bit_str.get(1..);
                }
            }
            pos = value_end;
        }
        None
    }

    fn extract_pub_key_from_cert_der(cert_der: &[u8]) -> Result<[u8; 65], AppAttestError> {
        let key_data = Self::der_extract_spki_key_bytes(cert_der).ok_or(
            AppAttestError::Message("Failed to extract public key from certificate".to_string()),
        )?;
        key_data.try_into().map_err(|_| {
            AppAttestError::Message(format!("expected 65-byte EC point, got {}", key_data.len()))
        })
    }

    /// Extracts the credential public key bytes from the first certificate.
    pub fn extract_client_pub_key_bytes(&self) -> Result<[u8; 65], AppAttestError> {
        Self::extract_pub_key_from_cert_der(self.certificates[0])
    }

    /// Verifies the attestation using caller-supplied root certificate PEM bytes.
    ///
    /// Fetch the root cert once with [`fetch_apple_root_cert_pem`] (requires the
    /// `reqwest` feature) and cache it; pass the same bytes on every call.
    /// Returns the device's public key bytes and the receipt on success.
    pub fn verify(
        self,
        challenge: &str,
        app_id: &str,
        key_id: &str,
        apple_root_cert_pem: &[u8],
    ) -> Result<([u8; 65], &'a [u8]), AppAttestError> {
        // Step 1: Verify Certificates
        Attestation::verify_certificates(&self.certificates, apple_root_cert_pem)?;

        // Step 2: Parse Authenticator Data
        let auth_data = AuthenticatorData::new(self.auth_data)?;

        // Step 3: Create and Verify Nonce
        let client_data_hash = Attestation::client_data_hash(challenge);
        let nonce = Attestation::nonce_hash(self.auth_data, client_data_hash);

        // key_id is always SHA-256 of the public key - exactly 32 decoded bytes.
        let mut key_id_buf = [0u8; 32];
        let key_id_len = BASE64_STANDARD
            .decode_slice(key_id, &mut key_id_buf)
            .map_err(|_| AppAttestError::Message("key_id base64 decode failed".to_string()))?;
        if key_id_len != 32 {
            return Err(AppAttestError::InvalidPublicKey);
        }

        // Step 4: Verify Public Key Hash
        let (public_key_bytes, hash_matches) =
            Attestation::verify_public_key_hash(self.certificates[0], &key_id_buf)?;
        if !hash_matches {
            return Err(AppAttestError::InvalidPublicKey);
        }

        let extracted_nonce = Attestation::extract_nonce_from_cert(self.certificates[0])?;
        if extracted_nonce != nonce {
            return Err(AppAttestError::InvalidNonce);
        }

        // Step 5: Verify App ID Hash
        auth_data.verify_app_id(app_id)?;

        // Step 6: Verify Counter
        auth_data.verify_counter()?;

        // Step 7: Verify AAGUID
        if !auth_data.is_valid_aaguid() {
            return Err(AppAttestError::InvalidAAGUID);
        }

        // Step 8: Verify Credential ID
        auth_data.verify_key_id(&key_id_buf)?;

        Ok((public_key_bytes, self.receipt))
    }

    /// If any of the supplied app IDs verifies, returns `(app_id, public_key_bytes, receipt)`.
    ///
    /// Useful when supporting multiple bundle IDs or environments. Pass the root
    /// cert PEM bytes obtained from [`fetch_apple_root_cert_pem`].
    pub fn app_id_verifies(
        self,
        challenge: &str,
        app_ids: &[&'static str],
        key_id: &str,
        apple_root_cert_pem: &[u8],
    ) -> Result<(&'static str, [u8; 65], &'a [u8]), AppAttestError> {
        // Step 1: Verify Certificates
        Attestation::verify_certificates(&self.certificates, apple_root_cert_pem)?;

        // Step 2: Parse Authenticator Data
        let auth_data = AuthenticatorData::new(self.auth_data)?;

        // Step 3: Create and Verify Nonce
        let client_data_hash = Attestation::client_data_hash(challenge);
        let nonce = Attestation::nonce_hash(self.auth_data, client_data_hash);

        // key_id is always SHA-256 of the public key - exactly 32 decoded bytes.
        let mut key_id_buf = [0u8; 32];
        let key_id_len = BASE64_STANDARD
            .decode_slice(key_id, &mut key_id_buf)
            .map_err(|_| AppAttestError::Message("key_id base64 decode failed".to_string()))?;
        if key_id_len != 32 {
            return Err(AppAttestError::InvalidPublicKey);
        }

        // Step 4: Verify Public Key Hash
        let (public_key_bytes, hash_matches) =
            Attestation::verify_public_key_hash(self.certificates[0], &key_id_buf)?;
        if !hash_matches {
            return Err(AppAttestError::InvalidPublicKey);
        }

        let extracted_nonce = Attestation::extract_nonce_from_cert(self.certificates[0])?;
        if extracted_nonce != nonce {
            return Err(AppAttestError::InvalidNonce);
        }

        // Step 5: Verify App ID Hash
        let mut res = Err(AppAttestError::InvalidAppID);
        for app_id in app_ids {
            if auth_data.verify_app_id(app_id).is_ok() {
                res = Ok(app_id);
                break;
            }
        }

        let verified_app_id = res?;

        // Step 6: Verify Counter
        auth_data.verify_counter()?;

        // Step 7: Verify AAGUID
        if !auth_data.is_valid_aaguid() {
            return Err(AppAttestError::InvalidAAGUID);
        }

        // Step 8: Verify Credential ID
        auth_data.verify_key_id(&key_id_buf)?;

        Ok((verified_app_id, public_key_bytes, self.receipt))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_from_base64_valid() {
        let valid_cbor_base64 = "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";
        let cbor = Attestation::decode_base64(valid_cbor_base64).unwrap();
        let attestation = Attestation::from_cbor_bytes(&cbor).unwrap();
        assert!(!attestation.certificates.is_empty());
        assert!(!attestation.auth_data.is_empty());
    }

    #[cfg(feature = "testing")]
    #[test]
    fn test_verify_certificates_empty() {
        let root_cert_pem = crate::testing::TEST_ROOT_CA_CERT_PEM;
        let result = Attestation::verify_certificates(&[], root_cert_pem);
        assert!(result.is_err());
    }
}
