use std::error::Error;

use thiserror::Error;

/// NIST's minimum for passwords people choose themselves.
const NIST_MINIMUM_PASSWORD_LENGTH: usize = 8;

/// Validate a password against criteria.
pub trait PasswordValidator {
    /// Why a password isn't accepted.
    type Error: Error + Send + Sync + 'static;

    /// Accept the password, or say why not.
    fn validate(&self, password: &str) -> Result<(), Self::Error>;
}

/// A password has to have at least this many characters. The default is
/// NIST's minimum for passwords people choose themselves, 8. A shorter
/// password is refused with [`PasswordTooShort`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct MinimumLengthPasswordValidator {
    minimum: usize,
}

impl MinimumLengthPasswordValidator {
    /// A validator for passwords of at least `minimum` characters.
    pub fn new(minimum: usize) -> MinimumLengthPasswordValidator {
        MinimumLengthPasswordValidator { minimum }
    }
}

impl Default for MinimumLengthPasswordValidator {
    fn default() -> MinimumLengthPasswordValidator {
        MinimumLengthPasswordValidator::new(NIST_MINIMUM_PASSWORD_LENGTH)
    }
}

impl PasswordValidator for MinimumLengthPasswordValidator {
    type Error = PasswordTooShort;

    fn validate(&self, password: &str) -> Result<(), PasswordTooShort> {
        if password.chars().count() < self.minimum {
            return Err(PasswordTooShort {
                minimum: self.minimum,
            });
        }
        Ok(())
    }
}

/// The password has fewer characters than the minimum.
#[derive(Debug, Error, PartialEq, Eq)]
#[error("the password is shorter than {minimum} characters")]
pub struct PasswordTooShort {
    /// How many characters a password has to have at least.
    pub minimum: usize,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn accepts_password_of_minimum_length() {
        assert_eq!(
            MinimumLengthPasswordValidator::new(5).validate("abcde"),
            Ok(())
        );
    }

    #[test]
    fn refuses_shorter_password() {
        assert_eq!(
            MinimumLengthPasswordValidator::new(5).validate("abcd"),
            Err(PasswordTooShort { minimum: 5 })
        );
    }

    #[test]
    fn counts_characters_rather_than_bytes() {
        assert_eq!(
            MinimumLengthPasswordValidator::new(5).validate("ÄÖÜ"),
            Err(PasswordTooShort { minimum: 5 })
        );
    }

    #[test]
    fn default_minimum_is_nists() {
        assert_eq!(
            MinimumLengthPasswordValidator::default(),
            MinimumLengthPasswordValidator::new(8)
        );
    }
}
