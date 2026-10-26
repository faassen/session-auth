use std::future::Future;

use jiff::Timestamp;

use crate::error::StoreError;
use crate::session_token::TokenHash;

/// The information the application needs to store per session (identified by
/// token hash).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SessionInfo<UserId> {
    /// Application-level user id.
    pub user_id: UserId,
    pub expires_at: Timestamp,
}

pub trait SessionStore: Send + Sync {
    type UserId: Clone;

    fn get_session(
        &self,
        token_hash: &TokenHash,
    ) -> impl Future<Output = Result<Option<SessionInfo<Self::UserId>>, StoreError>> + Send;

    fn set_session(
        &self,
        token_hash: &TokenHash,
        session_info: SessionInfo<Self::UserId>,
    ) -> impl Future<Output = Result<(), StoreError>> + Send;

    fn remove_session(
        &self,
        token_hash: &TokenHash,
    ) -> impl Future<Output = Result<(), StoreError>> + Send;

    /// Remove all sessions of the user.
    fn remove_user_sessions(
        &self,
        user_id: &Self::UserId,
    ) -> impl Future<Output = Result<(), StoreError>> + Send;

    /// Remove the expired sessions. A session has expired when its
    /// `expires_at` is equal to or earlier than `now`.
    fn remove_expired_sessions(
        &self,
        now: Timestamp,
    ) -> impl Future<Output = Result<(), StoreError>> + Send;
}
