use crate::{Error, PublicKey, SecretKey};
use derive_more::{Display, FromStr, TryFrom, TryInto};
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use sha3::{
    Shake128, Shake256,
    digest::{ExtendableOutput, HashMarker, Update, XofReader},
};
use zeroize::Zeroize;

/// The type of [`Scheme`]s supported by this crate.
///
/// They are divided into three categories:
///
/// * `Small`: Where the focus is on optimizing the size of the envelope. Underneath, it creates an envelope using
///     - AES-256-GCM as the data encryption algorithm or data encryption key (DEK).
///     - ClassicMcEliece348864 as the key encapsulation mechanism (KEM) to produce the key encryption key (KEK).
///     - SHAKE256 as the key derivation function (KDF).
///     - AES-256-KW to encrypt the DEK with the KEK.
///     - The resulting envelope is 96 bytes for the KEM ciphertext, 40 bytes for the wrapped DEK
///       and N bytes for the encrypted data, 16 bytes for the authentication tag.
/// * `Secure`: Where the focus is on optimizing security. Underneath, it creates an envelope using
///      - AES-256-GCM as the data encryption algorithm or data encryption key (DEK).
///      - FrodoKem1344Aes as the key encapsulation mechanism (KEM) to produce the key encryption key (KEK).
///      - SHAKE256 as the key derivation function (KDF).
///      - AES-256-KW to encrypt the DEK with the KEK.
///     - The resulting envelope is 21632 bytes for the KEM ciphertext, 40 bytes for the wrapped DEK
///       and N bytes for the encrypted data, 16 bytes for the authentication tag.
/// * `Nist`: Where the focus is on using NIST standardized algorithms. Underneath, it creates an envelope using
///    - AES-256-GCM as the data encryption algorithm or data encryption key (DEK).
///    - MLKEM768 as the key encapsulation mechanism (KEM) to produce the key encryption key (KEK).
///    - SHAKE256 as the key derivation function (KDF).
///    - AES-256-KW to encrypt the DEK with the KEK.
///     - The resulting envelope is 1088 bytes for the KEM ciphertext, 40 bytes for the wrapped DEK
///       and N bytes for the encrypted data, 16 bytes for the authentication tag.
///
/// `Nist` has a good balance between size and security,
/// while using only NIST standardized algorithms.
/// The key sizes are relatively small and the best performance.
///
/// `Small` is suitable for scenarios where envelope size is a critical factor,
/// however, it requires the largest key sizes.
///
/// `Secure` offers the highest security level, but comes with a
/// significant increase in envelope and key size, and the slowest performance.
#[derive(
    Copy,
    Clone,
    Debug,
    Default,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
    Hash,
    rkyv::Archive,
    rkyv::Serialize,
    rkyv::Deserialize,
    Display,
    FromStr,
    TryFrom,
    TryInto,
)]
#[display("{}")]
#[try_from(repr)]
#[repr(u8)]
#[rkyv(compare(PartialEq), derive(Debug))]
pub enum Scheme {
    #[default]
    #[display("Nist")]
    /// Enveloped using NIST standardized algorithms.
    Nist = 1,
    #[display("Small")]
    /// Enveloped optimized for space.
    Small = 2,
    #[display("Secure")]
    /// Enveloped optimized for security.
    Secure = 3,
}

impl Serialize for Scheme {
    fn serialize<S>(&self, s: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        if s.is_human_readable() {
            s.serialize_str(&self.to_string())
        } else {
            s.serialize_u8(self.into())
        }
    }
}

impl<'de> Deserialize<'de> for Scheme {
    fn deserialize<D>(d: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        if d.is_human_readable() {
            let s = String::deserialize(d)?;
            s.parse().map_err(serde::de::Error::custom)
        } else {
            let v = u8::deserialize(d)?;
            v.try_into().map_err(serde::de::Error::custom)
        }
    }
}

impl From<Scheme> for u8 {
    fn from(scheme: Scheme) -> Self {
        scheme as u8
    }
}

impl From<&Scheme> for u8 {
    fn from(scheme: &Scheme) -> Self {
        *scheme as u8
    }
}

impl From<Scheme> for oqs::kem::Kem {
    fn from(scheme: Scheme) -> Self {
        match scheme {
            Scheme::Small => {
                oqs::kem::Kem::new(oqs::kem::Algorithm::ClassicMcEliece348864).expect("Invalid KEM")
            }
            Scheme::Secure => {
                oqs::kem::Kem::new(oqs::kem::Algorithm::FrodoKem1344Aes).expect("Invalid KEM")
            }
            Scheme::Nist => oqs::kem::Kem::new(oqs::kem::Algorithm::MlKem768).expect("Invalid KEM"),
        }
    }
}

impl From<&Scheme> for oqs::kem::Kem {
    fn from(value: &Scheme) -> Self {
        oqs::kem::Kem::from(*value)
    }
}

impl TryFrom<&oqs::kem::Kem> for Scheme {
    type Error = Error;

    fn try_from(kem: &oqs::kem::Kem) -> Result<Self, Self::Error> {
        Self::try_from(kem.algorithm())
    }
}

impl TryFrom<oqs::kem::Algorithm> for Scheme {
    type Error = Error;

    fn try_from(alg: oqs::kem::Algorithm) -> Result<Self, Self::Error> {
        match alg {
            oqs::kem::Algorithm::ClassicMcEliece348864 => Ok(Scheme::Small),
            oqs::kem::Algorithm::FrodoKem1344Aes => Ok(Scheme::Secure),
            oqs::kem::Algorithm::MlKem768 => Ok(Scheme::Nist),
            _ => Err(Error::InvalidSchemeValue(derive_more::TryFromReprError {
                input: alg as u8,
            })),
        }
    }
}

impl Scheme {
    /// Generate a new public/private key pair for the specified scheme.
    pub fn key_pair(&self) -> crate::Result<(PublicKey, SecretKey)> {
        let kem: oqs::kem::Kem = self.into();
        let (pk, sk) = kem.keypair()?;
        Ok((pk.into(), sk.into()))
    }
    #[cfg(test)]
    pub(crate) const fn recipient_binary_size(&self) -> usize {
        match self {
            Scheme::Small => crate::SCHEME_SMALL_CAPSULE_LENGTH + 41,
            Scheme::Nist => crate::SCHEME_NIST_CAPSULE_LENGTH + 42,
            Scheme::Secure => crate::SCHEME_SECURE_CAPSULE_LENGTH + 43,
        }
    }

    pub(crate) fn create_kek<B: AsRef<[u8]>>(&self, shared_secret: B) -> aes_kw::KekAes256 {
        let mut kek = match self {
            Scheme::Small | Scheme::Nist => self.kdf_kek::<Shake128, B>(shared_secret, 32),
            Scheme::Secure => self.kdf_kek::<Shake256, B>(shared_secret, 64),
        };

        let kw = aes_kw::KekAes256::new(
            &aes_gcm::aes::cipher::generic_array::GenericArray::clone_from_slice(&kek),
        );
        kek.zeroize();
        kw
    }

    fn kdf_kek<H: ExtendableOutput + Update + Default + HashMarker, B: AsRef<[u8]>>(
        &self,
        shared_secret: B,
        required_length: usize,
    ) -> [u8; 32] {
        let mut shaker = H::default();
        shaker.update(b"pq-envelope");
        shaker.update(b"key-encryption-key");
        shaker.update(self.to_string().as_bytes());
        shaker.update(shared_secret.as_ref());
        shaker.update(&[32u8]);
        let mut reader = shaker.finalize_xof();
        let mut kek = vec![0u8; required_length];
        reader.read(&mut kek);
        <[u8; 32]>::try_from(&kek[required_length - 32..required_length])
            .expect("KDF output length is always >= 32 bytes")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rkyv::{access, deserialize, rancor::Error, to_bytes};
    use rstest::*;

    #[rstest]
    #[case::small(Scheme::Small, "Small")]
    #[case::nist(Scheme::Nist, "Nist")]
    #[case::secure(Scheme::Secure, "Secure")]
    fn serialization_human_readable(#[case] scheme: Scheme, #[case] value: &str) {
        let serialized = serde_json::to_string(&scheme).unwrap();
        assert_eq!(serialized, format!("\"{}\"", value));
        let deserialized: Scheme = serde_json::from_str(&serialized).unwrap();
        assert_eq!(scheme, deserialized);
    }

    #[rstest]
    #[case::nist(Scheme::Nist, 1u8)]
    #[case::small(Scheme::Small, 2u8)]
    #[case::secure(Scheme::Secure, 3u8)]
    fn serialization_non_human_readable(#[case] scheme: Scheme, #[case] value: u8) {
        let serialized = postcard::to_stdvec(&scheme).unwrap();
        assert_eq!(serialized.len(), 1);
        assert_eq!(serialized[0], value);
        let deserialized: Scheme = postcard::from_bytes(&serialized).unwrap();
        assert_eq!(scheme, deserialized);
    }

    #[rstest]
    #[case::nist(Scheme::Nist)]
    #[case::small(Scheme::Small)]
    #[case::secure(Scheme::Secure)]
    fn rkyv_tests(#[case] scheme: Scheme) {
        let serialized = to_bytes::<Error>(&scheme).unwrap();
        let archive = access::<ArchivedScheme, Error>(&serialized[..]).unwrap();
        assert_eq!(archive, &scheme);
        let deserialized = deserialize::<Scheme, Error>(archive).unwrap();
        assert_eq!(deserialized, scheme);
    }
}
