use std::{error::Error, fmt};

#[derive(Debug, PartialEq)]
pub enum AppAttestError {
    InvalidNonce,
    InvalidPublicKey,
    InvalidCounter,
    InvalidCredentialID,
    InvalidAAGUID,
    InvalidSignature,
    InvalidAppID,
    InvalidFormat,
    ExpectedASN1Node,
    ExpectedOctetStringInsideASN1Node,
    AuthenticatorDataTooShort,

    Message(String),
}

impl fmt::Display for AppAttestError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            AppAttestError::Message(e) => write!(f, "{}", e),
            AppAttestError::InvalidNonce => write!(f, "invalid nonce"),
            AppAttestError::InvalidPublicKey => write!(f, "invalid public key"),
            AppAttestError::InvalidCounter => write!(f, "invalid counter"),
            AppAttestError::InvalidCredentialID => write!(f, "invalid credential ID"),
            AppAttestError::InvalidAAGUID => write!(f, "invalid AAGUID"),
            AppAttestError::InvalidSignature => write!(f, "invalid signature"),
            AppAttestError::InvalidAppID => write!(f, "invalid App ID"),
            AppAttestError::InvalidFormat => {
                write!(f, "invalid attestation format (expected apple-appattest)")
            }
            AppAttestError::ExpectedASN1Node => write!(f, "expected ASN1 node"),
            AppAttestError::ExpectedOctetStringInsideASN1Node => {
                write!(f, "expected octet string inside ASN1 node")
            }
            AppAttestError::AuthenticatorDataTooShort => {
                write!(f, "authenticator data is too short")
            }
        }
    }
}

impl Error for AppAttestError {}
