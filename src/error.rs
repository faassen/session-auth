use std::error::Error;

use thiserror::Error;
use tokio::task::JoinError;

use crate::password_validator::PasswordTooShort;

/// An error of the application's stores, whatever its type.
pub type BoxError = Box<dyn Error + Send + Sync>;

/// Why an operation of `Auth` failed. `E` is why its password validator
/// didn't accept a password.
#[derive(Debug, Error)]
pub enum AuthError<E = PasswordTooShort> {
    /// The username already exists.
    #[error("the username is taken")]
    UsernameTaken,
    /// We tried to look up a username that doesn't exist.
    #[error("there is no user with the username")]
    UnknownUsername,
    /// The password validator didn't accept the password.
    #[error(transparent)]
    InvalidPassword(E),
    /// An error coming from the application generated in its storage traits
    /// implementations.
    #[error(transparent)]
    Store(StoreError),
    /// Hashing or verifying a password, on a thread for blocking work,
    /// panicked.
    #[error("the password task failed")]
    PasswordTask(#[from] JoinError),
    /// The operating system gave no random bytes for a session token.
    #[error("no randomness for a session token")]
    Randomness(#[from] getrandom::Error),
}

/// An application level store failed to keep or give back what it was asked
/// for. The application's own error goes along as the source, so it can be
/// logged.
#[derive(Debug, Error)]
#[error("the store failed")]
pub struct StoreError(#[source] BoxError);

/// So a store's error can be returned with `?`.
impl<E> From<BoxError> for AuthError<E> {
    fn from(box_error: BoxError) -> AuthError<E> {
        AuthError::Store(StoreError(box_error))
    }
}
