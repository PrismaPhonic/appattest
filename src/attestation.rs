use crate::{authenticator::AuthenticatorData, error::AppAttestError};
use base64::{engine::general_purpose, Engine};
use openssl::{
    bn::BigNumContext,
    ec::PointConversionForm,
    hash::{hash, MessageDigest},
    sha::Sha256,
    stack::Stack,
    x509::{store::X509StoreBuilder, X509StoreContext, X509},
};
#[cfg(feature = "reqwest")]
use reqwest::blocking::Client;
#[cfg(feature = "reqwest")]
use std::time::Duration;

use der_parser::{ber::BerObjectContent, oid::Oid, parse_ber};
use x509_parser::prelude::*;

pub struct Attestation<'a> {
    /// DER-encoded certificate slices, borrowed from the decoded buffer.
    /// certificates[0] is the credential cert; certificates[1..] are
    /// intermediates.
    certificates: Vec<&'a [u8]>,
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

        let mut certificates: Option<Vec<&'a [u8]>> = None;
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
                                let mut certs: Vec<&'a [u8]> = Vec::with_capacity(cert_count);
                                for _ in 0..cert_count {
                                    let cert_bytes = decoder.bytes().map_err(|_| {
                                        AppAttestError::Message(
                                            "expected bytes for certificate".to_string(),
                                        )
                                    })?;
                                    certs.push(cert_bytes);
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
        general_purpose::STANDARD
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

    /// Fetches the Apple root certificate from the specified URL.
    #[cfg(feature = "reqwest")]
    fn fetch_apple_root_cert(url: &str) -> Result<X509, AppAttestError> {
        let client = Client::builder()
            .timeout(Duration::from_secs(30))
            .build()
            .map_err(|e| AppAttestError::Message(format!("Failed to build HTTP client: {}", e)))?;

        let response = client
            .get(url)
            .send()
            .map_err(|e| AppAttestError::Message(format!("Network request failed: {}", e)))?;

        if !response.status().is_success() {
            return Err(AppAttestError::Message(format!(
                "Failed to fetch: HTTP Status: {}",
                response.status()
            )));
        }

        let cert_data = response
            .text()
            .map_err(|e| AppAttestError::Message(format!("Failed to read response text: {}", e)))?;

        let cert = X509::from_pem(cert_data.as_bytes())
            .map_err(|e| AppAttestError::Message(format!("Failed to parse certificate: {}", e)))?;

        Ok(cert)
    }

    /// Verifies the certificate chain in the attestation statement.
    fn verify_certificates(
        certificates: &[&[u8]],
        apple_root_cert: &X509,
    ) -> Result<(), AppAttestError> {
        if certificates.is_empty() {
            return Err(AppAttestError::Message("certificates is empty".to_string()));
        }
        let mut certs: Vec<X509> = Vec::with_capacity(certificates.len());
        for cert_der in certificates {
            let cert = X509::from_der(cert_der).map_err(|e| {
                AppAttestError::Message(format!("Failed to parse certificate DER: {}", e))
            })?;
            certs.push(cert);
        }

        let mut store_builder = X509StoreBuilder::new()
            .map_err(|e| AppAttestError::Message(format!("Failed to create X509 store: {}", e)))?;
        store_builder
            .add_cert(apple_root_cert.clone())
            .map_err(|e| {
                AppAttestError::Message(format!("Failed to add root cert to store: {}", e))
            })?;
        let store = store_builder.build();

        let mut cert_chain = Stack::new()
            .map_err(|e| AppAttestError::Message(format!("Failed to create cert stack: {}", e)))?;
        for cert in certs.iter().skip(1) {
            cert_chain.push(cert.to_owned()).map_err(|e| {
                AppAttestError::Message(format!("Failed to push cert to stack: {}", e))
            })?;
        }

        let mut context = X509StoreContext::new().map_err(|e| {
            AppAttestError::Message(format!("Failed to create X509 store context: {}", e))
        })?;
        context
            .init(&store, &certs[0], &cert_chain, |ctx| {
                ctx.verify_cert()?;
                Ok(())
            })
            .map_err(|e| {
                AppAttestError::Message(format!("Certificate chain verification failed: {}", e))
            })?;

        Ok(())
    }

    /// Extracts the nonce from the credential certificate's extension.
    fn extract_nonce_from_cert(cert_der: &[u8]) -> Result<[u8; 32], AppAttestError> {
        let (_, cert) = parse_x509_certificate(cert_der)
            .map_err(|_| AppAttestError::Message("Failed to parse certificate".to_string()))?;

        let cred_cert_oid = Oid::from(&[1, 2, 840, 113635, 100, 8, 2])
            .map_err(|_| AppAttestError::Message("Failed to parse OID".to_string()))?;

        let extensions: &[X509Extension] = cert.extensions();
        let extension_value = extensions
            .iter()
            .find(|ext| ext.oid == cred_cert_oid)
            .ok_or(AppAttestError::Message(
                "Certificate did not contain credCert extension".to_string(),
            ))?
            .value;

        let (_, raw_value) =
            parse_ber(extension_value).map_err(|_| AppAttestError::ExpectedASN1Node)?;

        if let BerObjectContent::Sequence(seq) = &raw_value.content {
            for obj in seq {
                match &obj.content {
                    BerObjectContent::Unknown(unknown_obj) => {
                        // Ref: https://cs.opensource.google/go/go/+/refs/tags/go1.22.4:src/encoding/asn1/asn1.go;l=530
                        let offset: usize = 2;
                        let nonce_bytes = &unknown_obj.data[offset..];
                        return nonce_bytes.try_into().map_err(|_| {
                            AppAttestError::Message(format!(
                                "expected 32-byte nonce in credCert extension, got {}",
                                nonce_bytes.len()
                            ))
                        });
                    }
                    _ => continue,
                }
            }
            Err(AppAttestError::FailedToExtractValueFromASN1Node)
        } else {
            Err(AppAttestError::ExpectedASN1Node)
        }
    }

    /// Creates a SHA-256 hash of the challenge string.
    fn client_data_hash(challenge: &str) -> [u8; 32] {
        let mut hasher = Sha256::new();
        hasher.update(challenge.as_bytes());
        hasher.finish().into()
    }

    /// Creates a SHA-256 hash of authData concatenated with clientDataHash.
    fn nonce_hash(auth_data: &[u8], client_data_hash: [u8; 32]) -> [u8; 32] {
        let mut hasher = Sha256::new();
        hasher.update(auth_data);
        hasher.update(&client_data_hash);
        hasher.finish().into()
    }

    fn verify_public_key_hash(
        cert: &X509,
        key_identifier: &[u8],
    ) -> Result<([u8; 65], bool), AppAttestError> {
        let pub_key_bytes = Self::_extract_client_pub_key_bytes(cert)?;
        let pub_key_hash = hash(MessageDigest::sha256(), &pub_key_bytes)
            .map_err(|e| AppAttestError::Message(format!("SHA-256 hash failed: {}", e)))?;
        Ok((pub_key_bytes, pub_key_hash.as_ref() == key_identifier))
    }

    fn _extract_client_pub_key_bytes(cert: &X509) -> Result<[u8; 65], AppAttestError> {
        let public_key = cert
            .public_key()
            .map_err(|e| AppAttestError::Message(format!("Failed to get public key: {}", e)))?;
        let ecdsa_key = public_key
            .ec_key()
            .map_err(|e| AppAttestError::Message(format!("Failed to get EC key: {}", e)))?;
        let ec_point = ecdsa_key.public_key();
        let group = ecdsa_key.group();

        let mut ctx = BigNumContext::new().map_err(|e| {
            AppAttestError::Message(format!("Failed to create BigNumContext: {}", e))
        })?;
        let pub_key_vec = ec_point
            .to_bytes(group, PointConversionForm::UNCOMPRESSED, &mut ctx)
            .map_err(|e| AppAttestError::Message(format!("Failed to export EC point: {}", e)))?;

        pub_key_vec.as_slice().try_into().map_err(|_| {
            AppAttestError::Message(format!(
                "expected 65-byte EC point, got {}",
                pub_key_vec.len()
            ))
        })
    }

    /// Extracts the credential public key bytes from the first certificate.
    pub fn extract_client_pub_key_bytes(&self) -> Result<[u8; 65], AppAttestError> {
        let cred_cert = X509::from_der(self.certificates[0]).map_err(|e| {
            AppAttestError::Message(format!("Failed to parse credential certificate: {}", e))
        })?;
        Self::_extract_client_pub_key_bytes(&cred_cert)
    }

    /// Verify performs the complete attestation verification, fetching the
    /// Apple root certificate automatically on each call.
    ///
    /// If you want to avoid the network round-trip on every verification, use
    /// [`verify_with_cert`](Self::verify_with_cert) and supply the cached PEM
    /// bytes yourself.
    #[cfg(feature = "reqwest")]
    pub fn verify(
        self,
        challenge: &str,
        app_id: &str,
        key_id: &str,
    ) -> Result<([u8; 65], Vec<u8>), AppAttestError> {
        let apple_root_cert = Attestation::fetch_apple_root_cert(
            "https://www.apple.com/certificateauthority/Apple_App_Attestation_Root_CA.pem",
        )?;
        let cert_pem = apple_root_cert.to_pem().map_err(|e| {
            AppAttestError::Message(format!("Failed to encode root cert as PEM: {}", e))
        })?;
        self.verify_with_cert(challenge, app_id, key_id, &cert_pem)
    }

    /// Verify performs the complete attestation verification using caller-supplied Apple root
    /// certificate PEM bytes.
    ///
    /// This is the preferred entry point for production use: fetch (and cache) the Apple root
    /// certificate once, then pass the raw PEM bytes here on every call to avoid a network
    /// round-trip per verification.
    ///
    /// The current Apple App Attestation Root CA PEM can be obtained from:
    /// `https://www.apple.com/certificateauthority/Apple_App_Attestation_Root_CA.pem`
    pub fn verify_with_cert(
        self,
        challenge: &str,
        app_id: &str,
        key_id: &str,
        apple_root_cert_pem: &[u8],
    ) -> Result<([u8; 65], Vec<u8>), AppAttestError> {
        let apple_root_cert = X509::from_pem(apple_root_cert_pem)
            .map_err(|e| AppAttestError::Message(format!("Failed to parse certificate: {}", e)))?;

        // Step 1: Verify Certificates
        Attestation::verify_certificates(&self.certificates, &apple_root_cert)?;

        // Step 2: Parse Authenticator Data
        let auth_data = AuthenticatorData::new(self.auth_data)?;

        // Step 3: Create and Verify Nonce
        let client_data_hash = Attestation::client_data_hash(challenge);
        let nonce = Attestation::nonce_hash(self.auth_data, client_data_hash);

        let cred_cert = X509::from_der(self.certificates[0]).map_err(|e| {
            AppAttestError::Message(format!("Failed to parse credential certificate: {}", e))
        })?;

        let key_id_decoded_bytes = general_purpose::STANDARD
            .decode(key_id)
            .map_err(|e| AppAttestError::Message(e.to_string()))?;

        // Step 4: Verify Public Key Hash
        let (public_key_bytes, hash_matches) =
            Attestation::verify_public_key_hash(&cred_cert, &key_id_decoded_bytes)?;
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
        auth_data.verify_key_id(&key_id_decoded_bytes)?;

        Ok((public_key_bytes, self.receipt.to_vec()))
    }

    /// If any of the supplied app IDs verifies, returns `(app_id, public_key_bytes, receipt)`.
    ///
    /// Fetches the Apple root certificate automatically on each call. See
    /// [`app_id_verifies_with_cert`](Self::app_id_verifies_with_cert) to supply the cert yourself
    /// and avoid a network round-trip per call.
    #[cfg(feature = "reqwest")]
    pub fn app_id_verifies(
        self,
        challenge: &str,
        app_ids: &[&'static str],
        key_id: &str,
    ) -> Result<(&'static str, [u8; 65], Vec<u8>), AppAttestError> {
        let apple_root_cert = Attestation::fetch_apple_root_cert(
            "https://www.apple.com/certificateauthority/Apple_App_Attestation_Root_CA.pem",
        )?;
        let cert_pem = apple_root_cert.to_pem().map_err(|e| {
            AppAttestError::Message(format!("Failed to encode root cert as PEM: {}", e))
        })?;
        self.app_id_verifies_with_cert(challenge, app_ids, key_id, &cert_pem)
    }

    /// If any of the supplied app IDs verifies, returns `(app_id, public_key_bytes, receipt)`.
    ///
    /// Uses caller-supplied Apple root certificate PEM bytes so the caller can cache the cert and
    /// avoid a network round-trip on every verification.
    pub fn app_id_verifies_with_cert(
        self,
        challenge: &str,
        app_ids: &[&'static str],
        key_id: &str,
        apple_root_cert_pem: &[u8],
    ) -> Result<(&'static str, [u8; 65], Vec<u8>), AppAttestError> {
        let apple_root_cert = X509::from_pem(apple_root_cert_pem)
            .map_err(|e| AppAttestError::Message(format!("Failed to parse certificate: {}", e)))?;

        // Step 1: Verify Certificates
        Attestation::verify_certificates(&self.certificates, &apple_root_cert)?;

        // Step 2: Parse Authenticator Data
        let auth_data = AuthenticatorData::new(self.auth_data)?;

        // Step 3: Create and Verify Nonce
        let client_data_hash = Attestation::client_data_hash(challenge);
        let nonce = Attestation::nonce_hash(self.auth_data, client_data_hash);

        let cred_cert = X509::from_der(self.certificates[0]).map_err(|e| {
            AppAttestError::Message(format!("Failed to parse credential certificate: {}", e))
        })?;

        let key_id_decoded_bytes = general_purpose::STANDARD
            .decode(key_id)
            .map_err(|e| AppAttestError::Message(e.to_string()))?;

        // Step 4: Verify Public Key Hash
        let (public_key_bytes, hash_matches) =
            Attestation::verify_public_key_hash(&cred_cert, &key_id_decoded_bytes)?;
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
        auth_data.verify_key_id(&key_id_decoded_bytes)?;

        Ok((verified_app_id, public_key_bytes, self.receipt.to_vec()))
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

    #[test]
    fn test_verify_certificates_empty() {
        let root_cert_pem = b"-----BEGIN CERTIFICATE-----\n\
        MIICITCCAaegAwIBAgIQC/O+DvHN0uD7jG5yH2IXmDAKBggqhkjOPQQDAzBSMSYw\n\
        JAYDVQQDDB1BcHBsZSBBcHAgQXR0ZXN0YXRpb24gUm9vdCBDQTETMBEGA1UECgwK\n\
        QXBwbGUgSW5jLjETMBEGA1UECAwKQ2FsaWZvcm5pYTAeFw0yMDAzMTgxODMyNTNa\n\
        Fw00NTAzMTUwMDAwMDBaMFIxJjAkBgNVBAMMHUFwcGxlIEFwcCBBdHRlc3RhdGlv\n\
        biBSb290IENBMRMwEQYDVQQKDApBcHBsZSBJbmMuMRMwEQYDVQQIDApDYWxpZm9y\n\
        bmlhMHYwEAYHKoZIzj0CAQYFK4EEACIDYgAERTHhmLW07ATaFQIEVwTtT4dyctdh\n\
        NbJhFs/Ii2FdCgAHGbpphY3+d8qjuDngIN3WVhQUBHAoMeQ/cLiP1sOUtgjqK9au\n\
        Yen1mMEvRq9Sk3Jm5X8U62H+xTD3FE9TgS41o0IwQDAPBgNVHRMBAf8EBTADAQH/\n\
        MB0GA1UdDgQWBBSskRBTM72+aEH/pwyp5frq5eWKoTAOBgNVHQ8BAf8EBAMCAQYw\n\
        CgYIKoZIzj0EAwMDaAAwZQIwQgFGnByvsiVbpTKwSga0kP0e8EeDS4+sQmTvb7vn\n\
        53O5+FRXgeLhpJ06ysC5PrOyAjEAp5U4xDgEgllF7En3VcE3iexZZtKeYnpqtijV\n\
        oyFraWVIyd/dganmrduC1bmTBGwD\n\
        -----END CERTIFICATE-----";

        let root_cert = openssl::x509::X509::from_pem(root_cert_pem).unwrap();
        let result = Attestation::verify_certificates(&[], &root_cert);
        assert!(result.is_err());
    }
}
