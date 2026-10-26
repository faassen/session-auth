#![doc = include_str!("../README.md")]

mod auth;
mod auth_builder;
#[cfg(feature = "axum")]
pub mod axum;
#[cfg(feature = "cli")]
pub mod cli;
#[cfg(feature = "cookie")]
pub mod cookie;
mod credentials;
mod error;
#[cfg(test)]
mod memory_store;
mod password_policy;
mod password_store;
mod session_store;
mod session_token;

pub use auth::{Auth, Session};
pub use auth_builder::AuthBuilder;
pub use credentials::Credentials;
pub use error::{AuthError, BoxError, StoreError};
pub use password_policy::{MinimumLength, PasswordPolicy, PasswordTooShort};
pub use password_store::{PasswordStore, PasswordUser};
pub use session_store::{SessionInfo, SessionStore};
pub use session_token::{SessionToken, TokenHash};
