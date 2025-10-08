use crate::*;
use aes_gcm::{Aes256Gcm, Key, KeyInit, Nonce, aead::Aead};
use rand::prelude::*;
use serde::de::SeqAccess;
use serde::{
    Deserialize, Deserializer, Serialize, Serializer,
    de::{Error as DError, MapAccess, Visitor},
    ser::SerializeStruct,
};

/// The envelope structure that holds the encrypted data along with the necessary metadata.
#[derive(Clone, Debug)]
pub struct Envelope {
    /// The encrypted data
    ciphertext: Vec<u8>,
    /// The recipient-specific KEM ciphertext
    recipients: Vec<Recipient>,
}

impl std::fmt::Display for Envelope {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "Envelope {{ recipients: [{}], ciphertext: {} }}",
            self.display_recipients(),
            hex::encode(&self.ciphertext),
        )
    }
}

impl Serialize for Envelope {
    fn serialize<S>(&self, s: S) -> std::result::Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        if s.is_human_readable() {
            let mut state = s.serialize_struct("Envelope", 2)?;
            state.serialize_field("recipients", &self.recipients)?;
            state.serialize_field("ciphertext", &hex::encode(&self.ciphertext))?;
            state.end()
        } else {
            let mut state = s.serialize_struct("Envelope", 2)?;
            state.serialize_field("recipients", &self.recipients)?;
            state.serialize_field("ciphertext", &self.ciphertext)?;
            state.end()
        }
    }
}

impl<'de> Deserialize<'de> for Envelope {
    fn deserialize<D>(d: D) -> std::result::Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        if d.is_human_readable() {
            struct EnvelopeVisitor;

            impl<'de> Visitor<'de> for EnvelopeVisitor {
                type Value = Envelope;

                fn expecting(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
                    write!(f, "struct Envelope or map")
                }

                fn visit_map<A>(self, mut map: A) -> std::result::Result<Self::Value, A::Error>
                where
                    A: MapAccess<'de>,
                {
                    let mut recipients: Option<Vec<Recipient>> = None;
                    let mut ciphertext: Option<String> = None;

                    while let Some(key) = map.next_key::<&str>()? {
                        match key {
                            "recipients" => {
                                if recipients.is_some() {
                                    return Err(DError::duplicate_field("recipients"));
                                }
                                recipients = Some(map.next_value()?);
                            }
                            "ciphertext" => {
                                if ciphertext.is_some() {
                                    return Err(DError::duplicate_field("ciphertext"));
                                }
                                ciphertext = Some(map.next_value()?);
                            }
                            _ => {
                                let _: serde::de::IgnoredAny = map.next_value()?;
                            }
                        }
                    }

                    let recipients =
                        recipients.ok_or_else(|| DError::missing_field("recipients"))?;
                    let ciphertext_hex =
                        ciphertext.ok_or_else(|| DError::missing_field("ciphertext"))?;
                    let ciphertext = hex::decode(&ciphertext_hex)
                        .map_err(|_| DError::custom("Invalid hex in ciphertext"))?;

                    Ok(Envelope {
                        recipients,
                        ciphertext,
                    })
                }
            }
            d.deserialize_struct("Envelope", &["recipients", "ciphertext"], EnvelopeVisitor)
        } else {
            struct EnvelopeVisitor;
            impl<'de> Visitor<'de> for EnvelopeVisitor {
                type Value = Envelope;

                fn expecting(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
                    write!(f, "struct Envelope or map")
                }

                fn visit_seq<A>(self, mut seq: A) -> std::result::Result<Self::Value, A::Error>
                where
                    A: SeqAccess<'de>,
                {
                    let recipients = seq
                        .next_element()?
                        .ok_or_else(|| DError::missing_field("recipients"))?;
                    let ciphertext = seq
                        .next_element()?
                        .ok_or_else(|| DError::missing_field("ciphertext"))?;

                    Ok(Envelope {
                        recipients,
                        ciphertext,
                    })
                }
            }
            d.deserialize_struct("Envelope", &["recipients", "ciphertext"], EnvelopeVisitor)
        }
    }
}

impl Envelope {
    pub(crate) fn display_recipients(&self) -> String {
        let mut s = String::new();
        for (i, r) in self.recipients.iter().enumerate() {
            if i > 0 {
                s.push_str(", ");
            }
            s.push_str(&format!("{}", r));
        }
        s
    }

    /// Create a new envelope for the given recipients with the specified data.
    ///
    /// Optionally, an already existing data encryption key can be provided.
    /// However, if it is not provided, a new one will be created.
    pub fn new<B: AsRef<[u8]>>(
        recipients: &[oqs::kem::PublicKey],
        data: B,
        data_encryption_key: Option<[u8; 32]>,
    ) -> Result<Self> {
        if recipients.is_empty() {
            return Err(Error::NoRecipients);
        }

        let mut rng = rand::rng();
        let dek = data_encryption_key.unwrap_or_else(|| rng.random());
        let mut envelope_recipients = Vec::with_capacity(recipients.len());
        let mut scheme: Option<Scheme> = None;

        for pk in recipients {
            match scheme {
                None => {
                    scheme = Some(scheme_from_public_key_length(pk.as_ref().len())?);
                }
                Some(s) => {
                    let pk_scheme = scheme_from_public_key_length(pk.as_ref().len())?;
                    if s != pk_scheme {
                        return Err(Error::SchemeMismatch);
                    }
                }
            }
            let s = scheme.expect("scheme should be set");
            envelope_recipients.push(Recipient::new(&dek, pk, s)?);
        }

        Ok(Self {
            recipients: envelope_recipients,
            ciphertext: Self::encrypt_data(data, &dek)?,
        })
    }

    /// Return the list of recipients that can decrypt the data
    pub fn recipients(&self) -> &[Recipient] {
        &self.recipients
    }

    /// Return the encrypted data
    pub fn ciphertext(&self) -> &[u8] {
        &self.ciphertext
    }

    /// Decrypt the envelope using the recipient's secret key
    ///
    /// This method will attempt to decrypt the envelope using each recipient's capsule
    /// until one succeeds. If none succeed, an error is returned.
    pub fn decrypt_by_recipient_secret_key(
        &self,
        recipient_secret_key: &oqs::kem::SecretKey,
    ) -> Result<Vec<u8>> {
        let scheme = scheme_from_secret_key_length(recipient_secret_key.as_ref().len())?;
        for recipient in &self.recipients {
            if let Ok(k) = recipient.unwrap_dek(recipient_secret_key, scheme) {
                return Self::decrypt_data(&self.ciphertext, &k);
            }
        }
        Err(Error::InvalidDecapsulationKey)
    }

    /// Decrypt the envelope using the recipient's index and secret key
    ///
    /// This method will attempt to decrypt the envelope using the recipient at the specified index.
    /// If the index is out of bounds or the decryption fails, an error is returned
    pub fn decrypt_by_recipient_index(
        &self,
        index: usize,
        recipient_secret_key: &oqs::kem::SecretKey,
    ) -> Result<Vec<u8>> {
        if index >= self.recipients.len() {
            return Err(Error::InvalidDecapsulationKey);
        }
        let scheme = scheme_from_secret_key_length(recipient_secret_key.as_ref().len())?;
        let recipient = &self.recipients[index];
        let dek = recipient.unwrap_dek(recipient_secret_key, scheme)?;
        Self::decrypt_data(&self.ciphertext, &dek)
    }

    fn encrypt_data<B: AsRef<[u8]>>(data: B, dek: &[u8; 32]) -> Result<Vec<u8>> {
        let mut rng = rand::rng();
        let nonce: [u8; 12] = rng.random();
        let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(dek));
        let nonce = Nonce::clone_from_slice(&nonce);
        let mut ciphertext = cipher.encrypt(&nonce, data.as_ref())?;
        let mut result = Vec::with_capacity(nonce.len() + ciphertext.len());
        result.extend_from_slice(&nonce);
        result.append(&mut ciphertext);
        Ok(result)
    }

    fn decrypt_data<B: AsRef<[u8]>>(ciphertext: B, dek: &[u8; 32]) -> Result<Vec<u8>> {
        let ct = ciphertext.as_ref();
        if ct.len() < 28 {
            return Err(Error::AesGcm);
        }
        let (nonce, ct) = ct.split_at(12);
        let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(dek));
        let nonce = Nonce::clone_from_slice(nonce);
        let plaintext = cipher.decrypt(&nonce, ct)?;
        Ok(plaintext)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rstest::*;

    #[rstest]
    #[case(Scheme::Small, 5)]
    #[case(Scheme::Nist, 4)]
    #[case(Scheme::Secure, 3)]
    fn serialization_human_readable(#[case] scheme: Scheme, #[case] num_recipients: usize) {
        let mut recipients_pk = Vec::with_capacity(num_recipients);
        let mut recipients_sk = Vec::with_capacity(num_recipients);

        for _ in 0..num_recipients {
            let (pk, sk) = scheme.key_pair().unwrap();
            recipients_pk.push(pk);
            recipients_sk.push(sk);
        }

        let data = b"Hello, world!";
        let envelope = Envelope::new(&recipients_pk, data.as_ref(), None).unwrap();
        let serialized = serde_json::to_string(&envelope).unwrap();
        let deserialized: Envelope = serde_json::from_str(&serialized).unwrap();
        assert_eq!(envelope.ciphertext, deserialized.ciphertext);
        assert_eq!(envelope.recipients.len(), deserialized.recipients.len());
        for (r1, r2) in envelope
            .recipients
            .iter()
            .zip(deserialized.recipients.iter())
        {
            assert_eq!(r1.capsule.as_ref(), r2.capsule.as_ref());
            assert_eq!(r1.wrapped_dek, r2.wrapped_dek);
        }
    }

    #[rstest]
    #[case(Scheme::Small, 4)]
    #[case(Scheme::Nist, 5)]
    #[case(Scheme::Secure, 3)]
    fn serialization_binary(#[case] scheme: Scheme, #[case] num_recipients: usize) {
        let mut recipients_pk = Vec::with_capacity(num_recipients);
        let mut recipients_sk = Vec::with_capacity(num_recipients);
        for _ in 0..num_recipients {
            let (pk, sk) = scheme.key_pair().unwrap();
            recipients_pk.push(pk);
            recipients_sk.push(sk);
        }

        let data = b"Hello, world!";
        let envelope = Envelope::new(&recipients_pk, data.as_ref(), None).unwrap();
        let serialized = postcard::to_stdvec(&envelope).unwrap();
        let deserialized: Envelope = postcard::from_bytes(&serialized).unwrap();
        assert_eq!(envelope.ciphertext, deserialized.ciphertext);
        assert_eq!(envelope.recipients.len(), deserialized.recipients.len());
        for (r1, r2) in envelope
            .recipients
            .iter()
            .zip(deserialized.recipients.iter())
        {
            assert_eq!(r1.capsule.as_ref(), r2.capsule.as_ref());
            assert_eq!(r1.wrapped_dek, r2.wrapped_dek);
        }
    }

    #[rstest]
    #[case(Scheme::Small, 6)]
    #[case(Scheme::Nist, 4)]
    #[case(Scheme::Secure, 5)]
    fn decryption(#[case] scheme: Scheme, #[case] num_recipients: usize) {
        let mut recipients_pk = Vec::with_capacity(num_recipients);
        let mut recipients_sk = Vec::with_capacity(num_recipients);
        for _ in 0..num_recipients {
            let (pk, sk) = scheme.key_pair().unwrap();
            recipients_pk.push(pk);
            recipients_sk.push(sk);
        }

        let data = b"envelope decryption";
        let envelope = Envelope::new(&recipients_pk, data.as_ref(), None).unwrap();
        for sk in &recipients_sk {
            let decrypted = envelope.decrypt_by_recipient_secret_key(sk).unwrap();
            assert_eq!(decrypted, data.as_ref());
        }

        for (i, sk) in recipients_sk.iter().enumerate() {
            let decrypted = envelope.decrypt_by_recipient_index(i, sk).unwrap();
            assert_eq!(decrypted, data.as_ref());
            let decrypt_fail = envelope.decrypt_by_recipient_index((i + 1) % sk.len(), sk);
            assert!(decrypt_fail.is_err());
        }
    }
}
