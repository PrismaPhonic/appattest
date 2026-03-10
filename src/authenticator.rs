use crate::error::AppAttestError;
use aws_lc_rs::digest::{digest, SHA256};
use byteorder::{BigEndian, ByteOrder};

const APP_ATTEST: &[u8] = b"appattest";
const APP_ATTEST_DEVELOP: &[u8] = b"appattestdevelop";

pub(crate) struct AuthenticatorData<'a> {
    pub(crate) rp_id_hash: [u8; 32],
    #[allow(dead_code)]
    pub(crate) flags: u8,
    pub(crate) counter: u32,
    aaguid: Option<Aaguid<'a>>,
    credential_id: Option<&'a [u8]>,
}

impl<'a> AuthenticatorData<'a> {
    pub(crate) fn new(auth_data_byte: &'a [u8]) -> Result<Self, AppAttestError> {
        if auth_data_byte.len() < 37 {
            return Err(AppAttestError::AuthenticatorDataTooShort);
        }

        let rp_id_hash: [u8; 32] = auth_data_byte[0..32]
            .try_into()
            .expect("slice is exactly 32 bytes");

        let mut auth_data = AuthenticatorData {
            rp_id_hash,
            flags: auth_data_byte[32],
            counter: BigEndian::read_u32(&auth_data_byte[33..37]),
            aaguid: None,
            credential_id: None,
        };

        auth_data.populate_optional_data(auth_data_byte)?;

        Ok(auth_data)
    }

    fn populate_optional_data(&mut self, bytes: &'a [u8]) -> Result<(), AppAttestError> {
        if bytes.len() < 55 {
            return Ok(());
        }

        // Apple App Attest credential IDs are always 32 bytes (SHA-256 of the
        // public key). We intentionally ignore the credentialIdLength field at
        // bytes [53..55] because some iOS versions (notably 26.x) write a
        // non-standard value there while the actual credential ID remains 32
        // bytes followed by a valid COSE key.
        const CREDENTIAL_ID_LEN: usize = 32;
        let end = 55 + CREDENTIAL_ID_LEN;
        if bytes.len() < end {
            return Err(AppAttestError::AuthenticatorDataTooShort);
        }
        self.credential_id = Some(&bytes[55..end]);
        self.aaguid = Some(Aaguid::new(&bytes[37..53])?);

        Ok(())
    }

    pub(crate) fn is_valid_aaguid(&self) -> bool {
        let Some(aaguid) = &self.aaguid else {
            return false;
        };

        if aaguid.matches(APP_ATTEST) {
            return true;
        }

        if cfg!(feature = "testing") {
            return aaguid.matches(APP_ATTEST_DEVELOP);
        }

        false
    }

    pub(crate) fn verify_counter(&self) -> Result<(), AppAttestError> {
        if self.counter != 0 {
            return Err(AppAttestError::InvalidCounter);
        }
        Ok(())
    }

    pub(crate) fn verify_app_id(&self, app_id: &str) -> Result<(), AppAttestError> {
        let hash = digest(&SHA256, app_id.as_bytes());
        if self.rp_id_hash != hash.as_ref() {
            Err(AppAttestError::InvalidAppID)
        } else {
            Ok(())
        }
    }

    pub(crate) fn verify_key_id(&self, key_id: &[u8]) -> Result<(), AppAttestError> {
        if let Some(credential_id) = self.credential_id {
            if credential_id == key_id {
                return Ok(());
            }
        }
        Err(AppAttestError::InvalidCredentialID)
    }
}

/// A 16-byte AAGUID that borrows from authenticator data.
struct Aaguid<'a> {
    bytes: &'a [u8],
}

impl<'a> Aaguid<'a> {
    fn new(bytes: &'a [u8]) -> Result<Self, AppAttestError> {
        let trimmed = trim_trailing_zeros(bytes);
        if trimmed == APP_ATTEST || trimmed == APP_ATTEST_DEVELOP {
            Ok(Aaguid { bytes })
        } else {
            Err(AppAttestError::InvalidAAGUID)
        }
    }

    /// Check whether this AAGUID matches the given identifier, ignoring trailing zeros.
    fn matches(&self, expected: &[u8]) -> bool {
        trim_trailing_zeros(self.bytes) == expected
    }
}

fn trim_trailing_zeros(bytes: &[u8]) -> &[u8] {
    let len = bytes.iter().rposition(|&b| b != 0).map_or(0, |pos| pos + 1);
    &bytes[..len]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_auth_data_new_valid() {
        let mut bytes = vec![0u8; 37];
        // use random flags
        bytes[32] = 0b00000001;
        // set counter to 1
        BigEndian::write_u32(&mut bytes[33..37], 1);

        let result = AuthenticatorData::new(&bytes);
        assert!(result.is_ok());

        let auth_data = result.unwrap();
        assert_eq!(auth_data.counter, 1);
    }

    #[test]
    fn test_auth_data_new_too_short() {
        // here, we create bytes less than required 37 bytes
        let bytes = vec![0u8; 36];
        let result = AuthenticatorData::new(&bytes);
        assert!(result.is_err());
    }

    #[test]
    fn test_aaguid_new_valid() {
        let mut bytes = [0u8; 16];
        bytes[..APP_ATTEST.len()].copy_from_slice(APP_ATTEST);
        let result = Aaguid::new(&bytes);
        assert!(result.is_ok());
    }

    #[test]
    fn test_aaguid_new_invalid() {
        let invalid_bytes = [0u8; 16];
        let result = Aaguid::new(&invalid_bytes);
        assert!(result.is_err());
    }

    #[test]
    fn test_verify_app_id() {
        let app_id = "app.apple.connect";
        let hash: [u8; 32] = digest(&SHA256, app_id.as_bytes())
            .as_ref()
            .try_into()
            .unwrap();

        let auth_data = AuthenticatorData {
            rp_id_hash: hash,
            flags: 0,
            counter: 0,
            aaguid: None,
            credential_id: None,
        };

        assert!(auth_data.verify_app_id("app.apple.connect").is_ok());
        assert!(auth_data.verify_app_id("invalid.apple.connect").is_err());
    }

    #[test]
    fn test_verify_key_id() {
        let key_id = [1u8, 2, 3, 4];
        let _data = [0u8; 60];
        // We need to construct AuthenticatorData with a credential_id
        let auth_data = AuthenticatorData {
            rp_id_hash: [0u8; 32],
            flags: 0,
            counter: 0,
            aaguid: None,
            credential_id: Some(&key_id),
        };

        assert!(auth_data.verify_key_id(&key_id).is_ok());
        assert!(auth_data.verify_key_id(&[4, 3, 2, 1]).is_err());
    }
}
