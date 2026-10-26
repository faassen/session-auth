//! [`PasswordStore`]: crate::PasswordStore
//! [`SessionStore`]: crate::SessionStore
//! [`Auth`]: crate::Auth
#![cfg_attr(feature = "cookie", doc = "[`cookie`]: crate::cookie")]
#![cfg_attr(feature = "axum", doc = "[`axum`]: crate::axum")]
#![cfg_attr(feature = "cli", doc = "[`cli`]: crate::cli")]
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
mod password_store;
mod password_validator;
mod session_store;
mod session_token;

pub use auth::{Auth, Session};
pub use auth_builder::AuthBuilder;
pub use credentials::Credentials;
pub use error::{AuthError, BoxError, StoreError};
pub use password_store::{PasswordStore, PasswordUser};
pub use password_validator::{MinimumLengthPasswordValidator, PasswordTooShort, PasswordValidator};
pub use session_store::{SessionInfo, SessionStore};
pub use session_token::{SessionToken, TokenHash};
