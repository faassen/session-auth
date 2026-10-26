use std::future::Future;

use jiff::Timestamp;

use crate::error::BoxError;
use crate::session_token::TokenHash;

/// The information the application needs to store per session (identified by
/// token hash).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SessionInfo<UserId> {
    /// Application-level user id.
    pub user_id: UserId,
    pub expires_at: Timestamp,
}

/// How the application writes and obtain session information.
///
/// Implement this trait in your application on top of whatever storage it's
/// using.
pub trait SessionStore: Send + Sync {
    type UserId: Clone;

    fn get_session(
        &self,
        token_hash: &TokenHash,
    ) -> impl Future<Output = Result<Option<SessionInfo<Self::UserId>>, BoxError>> + Send;

    fn set_session(
        &self,
        token_hash: &TokenHash,
        session_info: SessionInfo<Self::UserId>,
    ) -> impl Future<Output = Result<(), BoxError>> + Send;

    fn remove_session(
        &self,
        token_hash: &TokenHash,
    ) -> impl Future<Output = Result<(), BoxError>> + Send;

    /// Remove all sessions of the user.
    fn remove_user_sessions(
        &self,
        user_id: &Self::UserId,
    ) -> impl Future<Output = Result<(), BoxError>> + Send;

    /// Remove the expired sessions. A session has expired when its
    /// `expires_at` is equal to or earlier than `now`.
    fn remove_expired_sessions(
        &self,
        now: Timestamp,
    ) -> impl Future<Output = Result<(), BoxError>> + Send;
}
