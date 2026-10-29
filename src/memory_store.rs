use std::collections::HashMap;
use std::sync::atomic::{AtomicI64, Ordering};
use std::sync::{Mutex, MutexGuard};

use jiff::Timestamp;

use crate::error::BoxError;
use crate::password_store::{PasswordStore, PasswordUser};
use crate::session_store::{SessionInfo, SessionStore};
use crate::session_token::TokenHash;

/// The last user id `next_user_id` made.
static LAST_USER_ID: AtomicI64 = AtomicI64::new(0);

/// Applications should only hand out a user id they have created. Here we
/// enforce this in the type: the user id of the memory stores can only be
/// created by creating a user.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct MemoryUserId(i64);

fn next_user_id() -> MemoryUserId {
    MemoryUserId(LAST_USER_ID.fetch_add(1, Ordering::Relaxed) + 1)
}

/// An in-memory password store for testing purposes.
#[derive(Default)]
pub struct MemoryPasswordStore {
    password_users: Mutex<HashMap<String, PasswordUser<MemoryUserId>>>,
}

impl PasswordStore for MemoryPasswordStore {
    type UserId = MemoryUserId;

    async fn get_user(
        &self,
        username: &str,
    ) -> Result<Option<PasswordUser<MemoryUserId>>, BoxError> {
        Ok(lock(&self.password_users).get(username).cloned())
    }

    async fn create_user_with_password_hash(
        &self,
        username: &str,
        password_hash: String,
    ) -> Result<Option<MemoryUserId>, BoxError> {
        let mut password_users = lock(&self.password_users);
        if password_users.contains_key(username) {
            return Ok(None);
        }
        let user_id = next_user_id();
        password_users.insert(
            username.to_string(),
            PasswordUser {
                user_id,
                password_hash,
            },
        );
        Ok(Some(user_id))
    }

    async fn set_password_hash(
        &self,
        username: &str,
        password_hash: String,
    ) -> Result<(), BoxError> {
        if let Some(password_auth_info) = lock(&self.password_users).get_mut(username) {
            password_auth_info.password_hash = password_hash;
        }
        Ok(())
    }
}

/// An in-memory session store, used for testing purposes.
#[derive(Default)]
pub struct MemorySessionStore {
    session_infos: Mutex<HashMap<TokenHash, SessionInfo<MemoryUserId>>>,
}

impl MemorySessionStore {
    /// Whether there are no sessions.
    pub fn is_empty(&self) -> bool {
        lock(&self.session_infos).is_empty()
    }
}

impl SessionStore for MemorySessionStore {
    type UserId = MemoryUserId;

    async fn get_session(
        &self,
        token_hash: &TokenHash,
    ) -> Result<Option<SessionInfo<MemoryUserId>>, BoxError> {
        Ok(lock(&self.session_infos).get(token_hash).cloned())
    }

    async fn set_session(
        &self,
        token_hash: &TokenHash,
        session_info: SessionInfo<MemoryUserId>,
    ) -> Result<(), BoxError> {
        lock(&self.session_infos).insert(token_hash.clone(), session_info);
        Ok(())
    }

    async fn remove_session(&self, token_hash: &TokenHash) -> Result<(), BoxError> {
        lock(&self.session_infos).remove(token_hash);
        Ok(())
    }

    async fn remove_user_sessions(&self, user_id: &MemoryUserId) -> Result<(), BoxError> {
        lock(&self.session_infos).retain(|_, session_info| session_info.user_id != *user_id);
        Ok(())
    }

    async fn remove_expired_sessions(&self, now: Timestamp) -> Result<(), BoxError> {
        lock(&self.session_infos).retain(|_, session_info| session_info.expires_at > now);
        Ok(())
    }
}

fn lock<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
    mutex
        .lock()
        .expect("a test panicked while holding the lock")
}
