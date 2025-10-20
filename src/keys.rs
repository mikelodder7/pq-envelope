use crate::{Error, Result, Scheme, util::*};
use derive_more::Display;
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use std::{
    fmt::{self, Debug, Formatter},
    ops::Deref,
};

macro_rules! serde_impl {
    ($name:ident, $err:expr) => {
        impl Serialize for $name {
            fn serialize<S>(&self, s: S) -> std::result::Result<S::Ok, S::Error>
            where
                S: Serializer,
            {
                serdect::slice::serialize_hex_lower_or_bin(&self.0, s)
            }
        }

        impl<'de> Deserialize<'de> for $name {
            fn deserialize<D>(d: D) -> std::result::Result<Self, D::Error>
            where
                D: Deserializer<'de>,
            {
                let bytes = serdect::slice::deserialize_hex_or_bin_vec(d)?;
                Self::from_slice(&bytes).map_err(|_| serde::de::Error::custom($err))
            }
        }
    };
}

/// A public encapsulation key
#[derive(Clone, Display, Eq, PartialEq)]
#[display("{}", hex::encode(self.0.as_ref()))]
#[repr(transparent)]
pub struct PublicKey(oqs::kem::PublicKey);

impl AsRef<[u8]> for PublicKey {
    fn as_ref(&self) -> &[u8] {
        self.0.as_ref()
    }
}

impl Deref for PublicKey {
    type Target = oqs::kem::PublicKey;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl Debug for PublicKey {
    fn fmt(&self, f: &mut Formatter) -> fmt::Result {
        debug_key(&self.0, scheme_from_public_key_length, f)
    }
}

impl From<oqs::kem::PublicKey> for PublicKey {
    fn from(pk: oqs::kem::PublicKey) -> Self {
        PublicKey(pk)
    }
}

serde_impl!(PublicKey, "invalid public key");

impl PublicKey {
    /// Convert a public key from a slice of bytes
    pub fn from_slice(bytes: &[u8]) -> Result<Self> {
        let kem: oqs::kem::Kem = scheme_from_public_key_length(bytes.len())?.into();
        kem.public_key_from_bytes(bytes)
            .map(|p| Self(p.to_owned()))
            .ok_or(Error::InvalidEncapsulationKey(bytes.len()))
    }
}

/// A private decapsulation key
#[derive(Clone, Display, Eq, PartialEq)]
#[display("{}", hex::encode(self.0.as_ref()))]
#[repr(transparent)]
pub struct SecretKey(oqs::kem::SecretKey);

impl AsRef<[u8]> for SecretKey {
    fn as_ref(&self) -> &[u8] {
        self.0.as_ref()
    }
}

impl Deref for SecretKey {
    type Target = oqs::kem::SecretKey;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl Debug for SecretKey {
    fn fmt(&self, f: &mut Formatter) -> fmt::Result {
        debug_key(&self.0, scheme_from_secret_key_length, f)
    }
}

impl From<oqs::kem::SecretKey> for SecretKey {
    fn from(pk: oqs::kem::SecretKey) -> Self {
        SecretKey(pk)
    }
}

serde_impl!(SecretKey, "invalid secret key");

impl SecretKey {
    /// Convert a secret key from a slice of bytes
    pub fn from_slice(bytes: &[u8]) -> Result<Self> {
        let kem: oqs::kem::Kem = scheme_from_public_key_length(bytes.len())?.into();
        kem.secret_key_from_bytes(bytes)
            .map(|p| Self(p.to_owned()))
            .ok_or(Error::InvalidDecapsulationKey)
    }
}

fn debug_key<B: AsRef<[u8]>, S: FnOnce(usize) -> Result<Scheme>>(
    b: B,
    s: S,
    f: &mut Formatter,
) -> fmt::Result {
    let bytes = b.as_ref();
    let scheme = s(bytes.len()).map_err(|_| fmt::Error)?;
    write!(f, "{} {{ {} }}", scheme, hex::encode(bytes))
}
