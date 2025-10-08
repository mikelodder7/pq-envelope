use thiserror::Error;

/// The error type for this crate.
#[derive(Copy, Clone, Debug, Error)]
pub enum Error {
    /// Error from the OQS library
    #[error("OQS error")]
    Oqs,
    /// Error from the AES Key Wrap library
    #[error("AES Key Wrap error")]
    AesKw,
    /// Error from the AES GCM library
    #[error("AES GCM error")]
    AesGcm,
    /// Invalid scheme name when using Scheme.parse()
    #[error("Invalid scheme name: {0}")]
    InvalidSchemeName(#[from] derive_more::FromStrError),
    /// Invalid scheme value when using Scheme::try_from(u8)
    #[error("Invalid scheme value: {0}")]
    InvalidSchemeValue(#[from] derive_more::TryFromReprError<u8>),
    /// Invalid scheme type when using Scheme::try_into(u8)
    #[error("Invalid scheme type: {0}")]
    InvalidSchemeType(#[from] derive_more::TryIntoError<u8>),
    /// Invalid encapsulation key size
    #[error("Invalid encapsulation key size {0}")]
    InvalidEncapsulationKey(usize),
    /// Invalid capsule size
    #[error("Invalid capsule size {0}")]
    InvalidCapsule(usize),
    /// Error converting bytes to a capsule
    #[error("Capsule conversion error")]
    CapsuleConversion,
    /// Error converting bytes to an encapsulation key
    #[error("Encapsulation key conversion error")]
    EncapsulationKeyConversion,
    /// Mismatched schemes among recipients
    #[error("Mismatched schemes among recipients")]
    SchemeMismatch,
    /// No recipients provided when creating an envelope
    #[error("No recipients provided for envelope")]
    NoRecipients,
    /// Invalid decapsulation key
    #[error("Decapsulation key does not correspond to any capsule")]
    InvalidDecapsulationKey,
}

impl From<oqs::Error> for Error {
    fn from(_: oqs::Error) -> Self {
        Error::Oqs
    }
}

impl From<aes_kw::Error> for Error {
    fn from(_: aes_kw::Error) -> Self {
        Error::AesKw
    }
}

impl From<aes_gcm::Error> for Error {
    fn from(_: aes_gcm::Error) -> Self {
        Error::AesGcm
    }
}

/// A specialized `Result` type for this crate.
pub type Result<T> = std::result::Result<T, Error>;
