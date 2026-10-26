use std::future::Future;

use crate::error::BoxError;

/// The login information the application needs to store per user (identified by
/// username).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PasswordAuthInfo<UserId> {
    /// Application-level user id.
    pub user_id: UserId,
    /// An Argon2 PHC string.
    pub password_hash: String,
}

/// How to create and get password information for users in your application.
///
/// Implement this store trait in your application on top of whatever storage
/// it's using.
pub trait PasswordAuthInfoStore: Send + Sync {
    /// Application-level user id.
    type UserId: Clone;

    fn get_password_auth_info(
        &self,
        username: &str,
    ) -> impl Future<Output = Result<Option<PasswordAuthInfo<Self::UserId>>, BoxError>> + Send;

    /// Create a user who logs in with the username and the password hash:
    /// the user and their password auth info both or neither. `None` if the
    /// username is taken.
    fn create_user_with_password_hash(
        &self,
        username: &str,
        password_hash: String,
    ) -> impl Future<Output = Result<Option<Self::UserId>, BoxError>> + Send;

    /// Set the password hash of the user with the username.
    fn set_password_hash(
        &self,
        username: &str,
        password_hash: String,
    ) -> impl Future<Output = Result<(), BoxError>> + Send;
}
