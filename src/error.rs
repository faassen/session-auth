use std::error::Error;

use thiserror::Error;
use tokio::task::JoinError;

use crate::auth::MINIMUM_PASSWORD_LENGTH;

/// Why an operation of `Auth` failed.
#[derive(Debug, Error)]
pub enum AuthError {
    #[error("the username is taken")]
    UsernameTaken,
    #[error("there is no user with the username")]
    UnknownUsername,
    #[error("the password is shorter than {MINIMUM_PASSWORD_LENGTH} characters")]
    PasswordTooShort,
    #[error(transparent)]
    Store(#[from] StoreError),
    /// Hashing or verifying a password, on a thread for blocking work,
    /// panicked.
    #[error("the password task failed")]
    PasswordTask(#[from] JoinError),
    /// The operating system gave no random bytes for a session token.
    #[error("no randomness for a session token")]
    Randomness(#[from] getrandom::Error),
}

/// A store failed to keep or give back what it was asked for. The
/// application's own error goes along as the source, so it can be logged.
#[derive(Debug, Error)]
#[error("the store failed")]
pub struct StoreError(#[source] Box<dyn Error + Send + Sync>);

impl StoreError {
    pub fn new(error: impl Into<Box<dyn Error + Send + Sync>>) -> StoreError {
        StoreError(error.into())
    }
}
