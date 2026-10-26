#![doc = include_str!("../README.md")]

mod auth;
mod auth_builder;
#[cfg(feature = "cli")]
mod cli;
mod credentials;
mod error;
#[cfg(test)]
mod memory_store;
mod password_auth_info_store;
mod password_policy;
#[cfg(feature = "cookie")]
mod session_cookie;
mod session_store;
mod session_token;

pub use auth::{Auth, Session};
pub use auth_builder::AuthBuilder;
#[cfg(feature = "cli")]
pub use cli::{PasswordUserCommand, run_password_user_command};
pub use credentials::Credentials;
pub use error::{AuthError, BoxError, StoreError};
pub use password_auth_info_store::{PasswordAuthInfo, PasswordAuthInfoStore};
pub use password_policy::{MinimumLength, PasswordPolicy, PasswordTooShort};
#[cfg(feature = "cookie")]
pub use session_cookie::SessionCookie;
pub use session_store::{SessionInfo, SessionStore};
pub use session_token::{SessionToken, TokenHash};
