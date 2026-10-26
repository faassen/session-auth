use std::future::Future;

use jiff::Timestamp;

use crate::error::BoxError;
use crate::session_token::TokenHash;

/// The information the application needs to store per session (identified by
/// token hash).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SessionInfo<UserId> {
    /// Application-level user id associated with this session.
    pub user_id: UserId,
    /// When the session expires.
    pub expires_at: Timestamp,
}

/// How the application stores, gets and removes sessions.
///
/// Implement this trait in your application on top of whatever storage it's
/// using.
pub trait SessionStore: Send + Sync {
    /// Application-level user id, the same as the password store's.
    type UserId: Clone;

    /// Get the session with the token hash, or `None` if there is none. An
    /// expired session may still be returned: the caller checks
    /// `expires_at`.
    fn get_session(
        &self,
        token_hash: &TokenHash,
    ) -> impl Future<Output = Result<Option<SessionInfo<Self::UserId>>, BoxError>> + Send;

    /// Store the session under the token hash, replacing any session that
    /// has it.
    fn set_session(
        &self,
        token_hash: &TokenHash,
        session_info: SessionInfo<Self::UserId>,
    ) -> impl Future<Output = Result<(), BoxError>> + Send;

    /// Remove the session with the token hash. It's not an error if there
    /// is none.
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
