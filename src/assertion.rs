use crate::{authenticator::AuthenticatorData, error::AppAttestError};
use aws_lc_rs::{
    digest::{Context as DigestContext, SHA256},
    signature::{UnparsedPublicKey, ECDSA_P256_SHA256_ASN1},
};
use base64::{engine::general_purpose, Engine};

const AUTHENTICATOR_DATA_LEN: usize = 37;

#[derive(Debug, Clone)]
pub struct Assertion<'a> {
    raw_authenticator_data: &'a [u8],
    signature: &'a [u8],
}

impl<'a> Assertion<'a> {
    /// Parse an `Assertion` from raw CBOR bytes, borrowing directly from the input.
    fn from_cbor(cbor: &'a [u8]) -> Result<Self, AppAttestError> {
        let mut decoder = minicbor::Decoder::new(cbor);
        let map_len = decoder
            .map()
            .map_err(|_| AppAttestError::Message("expected CBOR map".to_string()))?;

        let mut authenticator_data: Option<&'a [u8]> = None;
        let mut signature: Option<&'a [u8]> = None;

        let entries = map_len.unwrap_or(0);
        for _ in 0..entries {
            let key = decoder
                .str()
                .map_err(|_| AppAttestError::Message("expected string key".to_string()))?;
            match key {
                "authenticatorData" => {
                    let bytes = decoder.bytes().map_err(|_| {
                        AppAttestError::Message("expected bytes for authenticatorData".to_string())
                    })?;
                    if bytes.len() != AUTHENTICATOR_DATA_LEN {
                        return Err(AppAttestError::Message(format!(
                            "authenticatorData must be {} bytes, got {}",
                            AUTHENTICATOR_DATA_LEN,
                            bytes.len()
                        )));
                    }
                    authenticator_data = Some(bytes);
                }
                "signature" => {
                    signature = Some(decoder.bytes().map_err(|_| {
                        AppAttestError::Message("expected bytes for signature".to_string())
                    })?);
                }
                _ => {
                    decoder.skip().map_err(|_| {
                        AppAttestError::Message("failed to skip unknown field".to_string())
                    })?;
                }
            }
        }

        let raw_authenticator_data = authenticator_data
            .ok_or_else(|| AppAttestError::Message("missing authenticatorData".to_string()))?;
        let signature =
            signature.ok_or_else(|| AppAttestError::Message("missing signature".to_string()))?;

        Ok(Assertion {
            raw_authenticator_data,
            signature,
        })
    }

    /// Creates a new `Assertion` from a Base64-encoded CBOR string.
    ///
    /// The decoded bytes are written into `buf` to avoid heap allocation.
    /// The returned `Assertion` borrows from `buf`.
    ///
    /// # Errors
    /// Returns `AppAttestError` if decoding or deserialization fails.
    pub fn from_base64(
        base64_assertion: &str,
        buf: &'a mut [u8; 192],
    ) -> Result<Self, AppAttestError> {
        let len = general_purpose::STANDARD
            .decode_slice(base64_assertion, buf.as_mut_slice())
            .map_err(|e| AppAttestError::Message(format!("Failed to decode Base64: {}", e)))?;

        Self::from_cbor(&buf[..len])
    }

    /// Creates a new `Assertion` from raw CBOR bytes.
    /// The returned `Assertion` borrows from the input slice.
    ///
    /// # Errors
    /// Returns `AppAttestError` if deserialization fails.
    pub fn from_assertion(assertion: &'a [u8]) -> Result<Self, AppAttestError> {
        Self::from_cbor(assertion)
    }

    /// Verifies the authenticity of an assertion using provided data and cryptographic checks.
    pub fn verify(
        self,
        client_data_hash: impl AsRef<[u8]>,
        challenge: &str,
        app_id: &str,
        public_key_byte: impl AsRef<[u8]>,
        previous_counter: u32,
        stored_challenge: &str,
    ) -> Result<(), AppAttestError> {
        let auth_data = AuthenticatorData::new(self.raw_authenticator_data)?;

        // 2. Compute nonce = SHA256(authenticatorData || clientDataHash).
        // The device signs nonce via p256::Signer which hashes its input again (SHA256(nonce)),
        // so we pass nonce to aws-lc-rs ECDSA_P256_SHA256_ASN1 which also applies SHA256 once.
        let mut ctx = DigestContext::new(&SHA256);
        ctx.update(self.raw_authenticator_data);
        ctx.update(client_data_hash.as_ref());
        let nonce = ctx.finish();

        // 3. Verify that the assertion's signature is valid for nonce.
        let public_key = UnparsedPublicKey::new(&ECDSA_P256_SHA256_ASN1, public_key_byte.as_ref());
        if public_key.verify(nonce.as_ref(), self.signature).is_err() {
            return Err(AppAttestError::InvalidSignature);
        }

        // 4. Verify that the RP ID matches the app ID.
        auth_data.verify_app_id(app_id)?;

        // 5. Verify counter is greater than previous.
        if auth_data.counter <= previous_counter {
            return Err(AppAttestError::InvalidCounter);
        }

        // 6. Verify challenge matches.
        if stored_challenge != challenge {
            return Err(AppAttestError::Message("challenge mismatch".to_string()));
        }

        Ok(())
    }

    /// Returns the app id that verifies, if any do. Otherwise, returns an error
    /// if none verify.
    ///
    /// Does not check the challenge matches the stored challenge.
    pub fn app_id_verifies(
        self,
        client_data_hash: impl AsRef<[u8]>,
        app_ids: &[&'static str],
        public_key_byte: impl AsRef<[u8]>,
        previous_counter: u32,
    ) -> Result<&'static str, AppAttestError> {
        let auth_data = AuthenticatorData::new(self.raw_authenticator_data)?;

        // 2. Compute nonce = SHA256(authenticatorData || clientDataHash).
        // The device signs nonce via p256::Signer which hashes its input again (SHA256(nonce)),
        // so we pass nonce to aws-lc-rs ECDSA_P256_SHA256_ASN1 which also applies SHA256 once.
        let mut ctx = DigestContext::new(&SHA256);
        ctx.update(self.raw_authenticator_data);
        ctx.update(client_data_hash.as_ref());
        let nonce = ctx.finish();

        // 3. Verify that the assertion's signature is valid for nonce.
        let public_key = UnparsedPublicKey::new(&ECDSA_P256_SHA256_ASN1, public_key_byte.as_ref());
        if public_key.verify(nonce.as_ref(), self.signature).is_err() {
            return Err(AppAttestError::InvalidSignature);
        }

        // 4. Verify that the RP ID matches one of the app IDs.
        let mut res = Err(AppAttestError::InvalidAppID);
        for app_id in app_ids {
            if auth_data.verify_app_id(app_id).is_ok() {
                res = Ok(app_id);
                break;
            }
        }

        let verified_app_id = res?;

        // 5. Verify counter is greater than previous.
        if auth_data.counter <= previous_counter {
            return Err(AppAttestError::InvalidCounter);
        }

        Ok(verified_app_id)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_from_base64_valid() {
        let valid_cbor_base64 = "omlzaWduYXR1cmVYRjBEAiAImFuY4+UbGZ5/ZbjAJpjQ3bd8GxaKFpMEo58WMEUGbwIgaqdDJnVS8/3oJCz16O5Zp4Qga5g6zrFF7eoiYEWkdtNxYXV0aGVudGljYXRvckRhdGFYJaRc2WwGuoniZEqtF+kolObjxcczFdDxbrhJR/nT8ehTQAAAAAI=";
        let mut buf = [0u8; 192];
        let result = Assertion::from_base64(valid_cbor_base64, &mut buf);
        assert!(result.is_ok());
    }

    #[test]
    fn test_from_assertion_valid() {
        let cbor_bytes = general_purpose::STANDARD
            .decode("omlzaWduYXR1cmVYRjBEAiAImFuY4+UbGZ5/ZbjAJpjQ3bd8GxaKFpMEo58WMEUGbwIgaqdDJnVS8/3oJCz16O5Zp4Qga5g6zrFF7eoiYEWkdtNxYXV0aGVudGljYXRvckRhdGFYJaRc2WwGuoniZEqtF+kolObjxcczFdDxbrhJR/nT8ehTQAAAAAI=")
            .unwrap();
        let assertion = Assertion::from_assertion(&cbor_bytes).unwrap();
        assert_eq!(assertion.raw_authenticator_data.len(), 37);
        assert_eq!(assertion.signature.len(), 70);
    }
}
