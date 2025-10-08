use crate::util::scheme_from_ciphertext_length;
use crate::*;
use serde::{
    Deserialize, Deserializer, Serialize, Serializer,
    de::{MapAccess, Visitor},
    ser::SerializeStruct,
};

/// The recipient structure that holds the necessary metadata for a recipient to decrypt the data.
#[derive(Clone, Debug)]
pub struct Recipient {
    /// The KEM ciphertext
    pub(crate) capsule: oqs::kem::Ciphertext,
    /// The wrapped data encryption key (DEK)
    pub(crate) wrapped_dek: [u8; 40],
}

impl std::fmt::Display for Recipient {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{{ capsule: {}, wrapped_dek: {} }}",
            hex::encode(self.capsule.as_ref()),
            hex::encode(self.wrapped_dek)
        )
    }
}

impl Serialize for Recipient {
    fn serialize<S>(&self, s: S) -> std::result::Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        if s.is_human_readable() {
            let mut state = s.serialize_struct("Recipient", 2)?;
            state.serialize_field("capsule", &hex::encode(&self.capsule))?;
            state.serialize_field("wrapped_dek", &hex::encode(self.wrapped_dek))?;
            state.end()
        } else {
            let mut state = s.serialize_struct("Recipient", 2)?;
            state.serialize_field("capsule", self.capsule.as_ref())?;
            state.serialize_field("wrapped_dek", &serde_big_array::Array(self.wrapped_dek))?;
            state.end()
        }
    }
}

impl<'de> Deserialize<'de> for Recipient {
    fn deserialize<D>(d: D) -> std::result::Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        fn process_capsule_bytes(capsule_bytes: &[u8]) -> Result<oqs::kem::Ciphertext> {
            let scheme = scheme_from_ciphertext_length(capsule_bytes.len())?;
            let kem: oqs::kem::Kem = scheme.into();
            kem.ciphertext_from_bytes(capsule_bytes)
                .map(|pk| pk.to_owned())
                .ok_or(Error::CapsuleConversion)
        }

        if d.is_human_readable() {
            struct RecipientVisitor;

            impl<'de> Visitor<'de> for RecipientVisitor {
                type Value = Recipient;

                fn expecting(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
                    write!(f, "a map representing a Recipient")
                }

                fn visit_map<A>(self, mut map: A) -> std::result::Result<Self::Value, A::Error>
                where
                    A: MapAccess<'de>,
                {
                    let mut capsule: Option<String> = None;
                    let mut wrapped_dek: Option<String> = None;
                    while let Some(key) = map.next_key::<String>()? {
                        match key.as_str() {
                            "capsule" => {
                                if capsule.is_some() {
                                    return Err(serde::de::Error::duplicate_field("capsule"));
                                }
                                capsule = Some(map.next_value()?);
                            }
                            "wrapped_dek" => {
                                if wrapped_dek.is_some() {
                                    return Err(serde::de::Error::duplicate_field("wrapped_dek"));
                                }
                                wrapped_dek = Some(map.next_value()?);
                            }
                            _ => {
                                return Err(serde::de::Error::unknown_field(
                                    &key,
                                    &["capsule", "wrapped_dek"],
                                ));
                            }
                        }
                    }
                    let capsule =
                        capsule.ok_or_else(|| serde::de::Error::missing_field("capsule"))?;
                    let wrapped_dek = wrapped_dek
                        .ok_or_else(|| serde::de::Error::missing_field("wrapped_dek"))?;

                    let capsule_bytes = hex::decode(&capsule).map_err(serde::de::Error::custom)?;
                    let wrapped_dek_bytes =
                        hex::decode(&wrapped_dek).map_err(serde::de::Error::custom)?;
                    if wrapped_dek_bytes.len() != 40 {
                        return Err(serde::de::Error::custom("wrapped_dek must be 40 bytes"));
                    }
                    let mut wrapped_dek_array = [0u8; 40];
                    wrapped_dek_array.copy_from_slice(&wrapped_dek_bytes);

                    let capsule =
                        process_capsule_bytes(&capsule_bytes).map_err(serde::de::Error::custom)?;

                    Ok(Recipient {
                        capsule,
                        wrapped_dek: wrapped_dek_array,
                    })
                }
            }
            d.deserialize_struct("Recipient", &["capsule", "wrapped_dek"], RecipientVisitor)
        } else {
            #[derive(Deserialize)]
            struct RecipientHelper {
                capsule: Vec<u8>,
                #[serde(with = "serde_big_array::BigArray")]
                wrapped_dek: [u8; 40],
            }
            let helper = RecipientHelper::deserialize(d)?;

            Ok(Recipient {
                capsule: process_capsule_bytes(&helper.capsule)
                    .map_err(serde::de::Error::custom)?,
                wrapped_dek: helper.wrapped_dek,
            })
        }
    }
}

impl Recipient {
    pub(crate) fn new(
        data_encryption_key: &[u8; 32],
        recipient_public_key: &oqs::kem::PublicKey,
        scheme: Scheme,
    ) -> Result<Self> {
        let kem: oqs::kem::Kem = scheme.into();
        let (capsule, shared_secret) = kem.encapsulate(recipient_public_key)?;
        let kw = scheme.create_kek(shared_secret);
        let mut wrapped_dek = [0u8; 40];
        kw.wrap(data_encryption_key, &mut wrapped_dek)?;

        Ok(Recipient {
            capsule,
            wrapped_dek,
        })
    }

    pub(crate) fn unwrap_dek(
        &self,
        recipient_secret_key: &oqs::kem::SecretKey,
        scheme: Scheme,
    ) -> Result<[u8; 32]> {
        let kem: oqs::kem::Kem = scheme.into();
        let shared_secret = kem.decapsulate(recipient_secret_key, &self.capsule)?;
        let kw = scheme.create_kek(shared_secret);
        let mut dek = [0u8; 32];
        kw.unwrap(&self.wrapped_dek, &mut dek)?;
        Ok(dek)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rstest::*;

    #[rstest]
    #[case::small(Scheme::Small)]
    #[case::nist(Scheme::Nist)]
    #[case::secure(Scheme::Secure)]
    fn serialization_human_readable(#[case] scheme: Scheme) {
        let (pk, _sk) = scheme.key_pair().unwrap();
        let dek = [0u8; 32];
        let recipient = Recipient::new(&dek, &pk, scheme).unwrap();
        let serialized = serde_json::to_string(&recipient).unwrap();
        let deserialized: Recipient = serde_json::from_str(&serialized).unwrap();
        assert_eq!(recipient.capsule.as_ref(), deserialized.capsule.as_ref());
        assert_eq!(recipient.wrapped_dek, deserialized.wrapped_dek);
    }

    #[rstest]
    #[case::small(Scheme::Small)]
    #[case::nist(Scheme::Nist)]
    #[case::secure(Scheme::Secure)]
    fn serialization_binary(#[case] scheme: Scheme) {
        let (pk, _sk) = scheme.key_pair().unwrap();
        let dek = [0u8; 32];
        let recipient = Recipient::new(&dek, &pk, scheme).unwrap();
        let serialized = postcard::to_stdvec(&recipient).unwrap();
        let deserialized: Recipient = postcard::from_bytes(&serialized).unwrap();
        assert_eq!(recipient.capsule.as_ref(), deserialized.capsule.as_ref());
        assert_eq!(recipient.wrapped_dek, deserialized.wrapped_dek);

        assert_eq!(serialized.len(), scheme.recipient_binary_size());
    }

    #[rstest]
    #[case::small(Scheme::Small)]
    #[case::nist(Scheme::Nist)]
    #[case::secure(Scheme::Secure)]
    fn dek_unwrap(#[case] scheme: Scheme) {
        let (pk, sk) = scheme.key_pair().unwrap();
        let dek = [1u8; 32];
        let recipient = Recipient::new(&dek, &pk, scheme).unwrap();
        let unwrapped_dek = recipient.unwrap_dek(&sk, scheme).unwrap();
        assert_eq!(dek, unwrapped_dek);
    }

    #[test]
    fn incompatibility() {
        let (pk_small, sk_small) = Scheme::Small.key_pair().unwrap();
        let (pk_nist, sk_nist) = Scheme::Nist.key_pair().unwrap();
        let dek = [1u8; 32];
        let recipient_small = Recipient::new(&dek, &pk_small, Scheme::Small).unwrap();
        let recipient_nist = Recipient::new(&dek, &pk_nist, Scheme::Nist).unwrap();
        assert!(recipient_small.unwrap_dek(&sk_nist, Scheme::Nist).is_err());
        assert!(recipient_nist.unwrap_dek(&sk_small, Scheme::Small).is_err());
    }
}
