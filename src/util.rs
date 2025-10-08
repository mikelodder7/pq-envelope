use crate::*;

pub fn scheme_from_ciphertext_length(len: usize) -> Result<Scheme> {
    match len {
        SCHEME_SMALL_CAPSULE_LENGTH => Ok(Scheme::Small),
        SCHEME_SECURE_CAPSULE_LENGTH => Ok(Scheme::Secure),
        SCHEME_NIST_CAPSULE_LENGTH => Ok(Scheme::Nist),
        _ => Err(Error::InvalidCapsule(len)),
    }
}

pub fn scheme_from_public_key_length(len: usize) -> Result<Scheme> {
    match len {
        SCHEME_SMALL_PUBLIC_KEY_LENGTH => Ok(Scheme::Small),
        SCHEME_SECURE_PUBLIC_KEY_LENGTH => Ok(Scheme::Secure),
        SCHEME_NIST_PUBLIC_KEY_LENGTH => Ok(Scheme::Nist),
        _ => Err(Error::InvalidEncapsulationKey(len)),
    }
}

pub fn scheme_from_secret_key_length(len: usize) -> Result<Scheme> {
    match len {
        SCHEME_SMALL_SECRET_KEY_LENGTH => Ok(Scheme::Small),
        SCHEME_SECURE_SECRET_KEY_LENGTH => Ok(Scheme::Secure),
        SCHEME_NIST_SECRET_KEY_LENGTH => Ok(Scheme::Nist),
        _ => Err(Error::InvalidEncapsulationKey(len)),
    }
}
