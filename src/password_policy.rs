use std::error::Error;

use thiserror::Error;

/// NIST's minimum for passwords people choose themselves.
const NIST_MINIMUM_PASSWORD_LENGTH: usize = 8;

/// What a password has to be like to be accepted, when creating a user or
/// changing a password.
pub trait PasswordPolicy {
    /// Why a password isn't accepted.
    type Error: Error + Send + Sync + 'static;

    /// Accept the password, or say why not.
    fn check(&self, password: &str) -> Result<(), Self::Error>;
}

/// A password has to have at least this many characters. The default is
/// NIST's minimum for passwords people choose themselves, 8.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct MinimumLength(pub usize);

impl Default for MinimumLength {
    fn default() -> MinimumLength {
        MinimumLength(NIST_MINIMUM_PASSWORD_LENGTH)
    }
}

impl PasswordPolicy for MinimumLength {
    type Error = PasswordTooShort;

    fn check(&self, password: &str) -> Result<(), PasswordTooShort> {
        let MinimumLength(minimum) = *self;
        if password.chars().count() < minimum {
            return Err(PasswordTooShort { minimum });
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
        assert_eq!(MinimumLength(5).check("abcde"), Ok(()));
    }

    #[test]
    fn refuses_shorter_password() {
        assert_eq!(
            MinimumLength(5).check("abcd"),
            Err(PasswordTooShort { minimum: 5 })
        );
    }

    #[test]
    fn counts_characters_rather_than_bytes() {
        assert_eq!(
            MinimumLength(5).check("ÄÖÜ"),
            Err(PasswordTooShort { minimum: 5 })
        );
    }

    #[test]
    fn default_minimum_is_nists() {
        assert_eq!(MinimumLength::default(), MinimumLength(8));
    }
}
