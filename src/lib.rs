//! A Hybrid PQ Encryption envelope scheme
//!
//! An envelope is an encrypted payload that only the specified
//! list of receivers can decrypt. Each receiver must possess their
//! own decryption key
//!
//! The scheme works as follows:
//!
//! 1. Create an AES-256-GCM data encryption key (DEK).
//! 2. Encrypt the payload with the DEK.
//! 3. Use a receiver's public key to encrypt the DEK.
//!   - This public key is a post-quantum key encapsulation mechanism (KEM) encapsulation key.
//!   - The encapsulation key creates a `capsule` to be stored and a session key.
//!   - The session key goes through a key derivation function (KDF) to produce
//!     a key encryption key (KEK).
//!   - The KDF is either SHA3's SHAKE128 or SHAKE256 depending on the security level.
//!   - The KEK combined with AES-256-KW creates a wrapped DEK which is also stored.
//!   - The metadata consisting of the wrapped DEK and the `capsule` is called the `recipient`.
//! 4. The envelope consists of the encrypted payload and a list of recipients.
//!
//! The envelope can be decrypted using a receiver's decapsulation key.
//!
//! 1. The decapsulation key opens the `capsule` to extract the session key.
//! 2. The session key goes through a KDF to produce the KEK.
//! 3. Using the KEK, the DEK is unwrapped.
//! 4. The payload can be decrypted using the DEK.
//!
//! Envelope size and security can be determined using an associated [`Scheme`]
//! depending on the use case. The most common [`Scheme`] to use where size isn't
//! an issue for the envelope or keys and performance is the best
//! is [`Scheme::Nist`] which uses ML-KEM-768. This is also the default.
//!
//! However, for settings where size is important use [`Scheme::Small`] which priorities
//! envelope size but requires the largest key sizes. This scheme uses ClassicMcEliece348864.
//!
//! For high security settings [`Scheme::Secure`] which prioritizes 256-bit PQ security
//! use [`Scheme::Secure`] which uses FrodoKEM1344.
//!
//! The overhead for each recipient is in bytes
//!
//! | Scheme | Encapsulation Key | Decapsulation Key | Recipient |
//! | ------ | ----------------- | ----------------- | --------- |
//! | Nist | 1,184 | 2,400 | 1,088 Cap + 40 KW = 1,128 |
//! | Small | 261,120 | 6,492 | 96 Cap + 40 KW = 136 |
//! | Secure | 21,520 | 43,088 | 21,632 Cap + 40 KW = 22,303 |
//!
//! # Usage
//! To create a receiver, select an appropriate scheme and create their keys:
//! ```
//! use pq_envelope::{Scheme, Envelope};
//!
//! let scheme = Scheme::Nist;
//! let (r1_pk, r1_sk) = scheme.key_pair().unwrap();
//! let (r2_pk, r2_sk) = scheme.key_pair().unwrap();
//! let (r3_pk, r3_sk) = scheme.key_pair().unwrap();
//! let plaintext = b"Hello World!".to_vec();
//!
//! let envelope = Envelope::new(
//!     &[r1_pk, r2_pk, r3_pk],
//!     &plaintext,
//!     None,
//! ).unwrap();
//!
//! // Uses trial decapsulation to find the intended recipient
//! assert_eq!(plaintext, envelope.decrypt_by_recipient_secret_key(&r1_sk).unwrap());
//! assert_eq!(plaintext, envelope.decrypt_by_recipient_secret_key(&r2_sk).unwrap());
//! assert_eq!(plaintext, envelope.decrypt_by_recipient_secret_key(&r3_sk).unwrap());
//!
//! // Or if the recipient is already known by its index
//! assert_eq!(plaintext, envelope.decrypt_by_recipient_index(0, &r1_sk).unwrap());
//! assert_eq!(plaintext, envelope.decrypt_by_recipient_index(1, &r2_sk).unwrap());
//! assert_eq!(plaintext, envelope.decrypt_by_recipient_index(2, &r3_sk).unwrap());
//!
//! let (_r4_pk, r4_sk) = scheme.key_pair().unwrap();
//!
//! // r4 doesn't have recipient data so this should fail
//! assert!(envelope.decrypt_by_recipient_secret_key(&r4_sk).is_err());
//! ```
//!
//! All methods support serialization for storage and retrieval.
//! For this purpose, everything implements [`serde::Serialize`], [`serde::Deserialize`].
//! And for faster serialization, the `rkyv` crate has also been implemented.

#![cfg_attr(docsrs, feature(doc_cfg))]
#![warn(
    missing_docs,
    missing_debug_implementations,
    missing_copy_implementations,
    trivial_casts,
    trivial_numeric_casts,
    unused,
    clippy::mod_module_files
)]
#![deny(clippy::unwrap_used)]

mod envelope;
mod error;
mod recipient;
mod scheme;
mod util;

use util::*;

/// The length of the capsule for `Scheme::Small`
pub const SCHEME_SMALL_CAPSULE_LENGTH: usize =
    oqs::ffi::kem::OQS_KEM_classic_mceliece_348864_length_ciphertext as usize;
/// The length of the capsule for `Scheme::Secure`
pub const SCHEME_SECURE_CAPSULE_LENGTH: usize =
    oqs::ffi::kem::OQS_KEM_frodokem_1344_aes_length_ciphertext as usize;
/// The length of the capsule for `Scheme::Nist`
pub const SCHEME_NIST_CAPSULE_LENGTH: usize =
    oqs::ffi::kem::OQS_KEM_ml_kem_768_length_ciphertext as usize;

/// The length of the encapsulation key for `Scheme::Small`
pub const SCHEME_SMALL_PUBLIC_KEY_LENGTH: usize =
    oqs::ffi::kem::OQS_KEM_classic_mceliece_348864_length_public_key as usize;
/// The length of the encapsulation key for `Scheme::Secure`
pub const SCHEME_SECURE_PUBLIC_KEY_LENGTH: usize =
    oqs::ffi::kem::OQS_KEM_frodokem_1344_aes_length_public_key as usize;
/// The length of the encapsulation key for `Scheme::Nist`
pub const SCHEME_NIST_PUBLIC_KEY_LENGTH: usize =
    oqs::ffi::kem::OQS_KEM_ml_kem_768_length_public_key as usize;

/// The length of the decapsulation key for `Scheme::Small`
pub const SCHEME_SMALL_SECRET_KEY_LENGTH: usize =
    oqs::ffi::kem::OQS_KEM_classic_mceliece_348864_length_secret_key as usize;
/// The length of the decapsulation key for `Scheme::Secure`
pub const SCHEME_SECURE_SECRET_KEY_LENGTH: usize =
    oqs::ffi::kem::OQS_KEM_frodokem_1344_aes_length_secret_key as usize;
/// The length of the decapsulation key for `Scheme::Nist`
pub const SCHEME_NIST_SECRET_KEY_LENGTH: usize =
    oqs::ffi::kem::OQS_KEM_ml_kem_768_length_secret_key as usize;

/// The length of the shared secret for `Scheme::Small`
pub const SCHEME_SMALL_SHARED_SECRET_LENGTH: usize =
    oqs::ffi::kem::OQS_KEM_classic_mceliece_348864_length_shared_secret as usize;
/// The length of the shared secret for `Scheme::Secure`
pub const SCHEME_SECURE_SHARED_SECRET_LENGTH: usize =
    oqs::ffi::kem::OQS_KEM_frodokem_1344_aes_length_shared_secret as usize;
/// The length of the shared secret for `Scheme::Nist`
pub const SCHEME_NIST_SHARED_SECRET_LENGTH: usize =
    oqs::ffi::kem::OQS_KEM_ml_kem_768_length_shared_secret as usize;

pub use envelope::Envelope;
pub use error::{Error, Result};
pub use recipient::Recipient;
pub use scheme::Scheme;
