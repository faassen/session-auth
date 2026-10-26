use std::sync::{Arc, LazyLock};

use jiff::{SignedDuration, Timestamp};
use password_auth::{generate_hash, verify_password};
use tokio::sync::Semaphore;
use tokio::task::spawn_blocking;

use crate::credentials::Credentials;
use crate::error::AuthError;
use crate::password_auth_info_store::PasswordAuthInfoStore;
use crate::session_store::{SessionInfo, SessionStore};
use crate::session_token::SessionToken;

/// NIST's minimum for passwords people choose themselves.
pub const MINIMUM_PASSWORD_LENGTH: usize = 8;
/// How long a session lasts after the login. It's never extended.
const SESSION_LIFETIME: SignedDuration = SignedDuration::from_hours(30 * 24);
/// Hashing or verifying a password takes some 19 MiB and a core while it runs, so we want
/// to prevent denial of service by limiting how much we verify at any point in
/// time.
const MAXIMUM_CONCURRENT_VERIFICATIONS: usize = 4;

/// Verified against when there's no user with the username, so an unknown
/// username takes as long to refuse as a wrong password, and the time doesn't
/// tell which usernames exist.
static DUMMY_PASSWORD_HASH: LazyLock<String> = LazyLock::new(|| generate_hash("dummy password"));

/// A new session: the token for the browser's cookie, and when the session
/// expires, which the cookie can expire with.
///
/// It has no `Debug`, so the token can't end up in a log.
pub struct Session {
    pub session_token: SessionToken,
    pub expires_at: Timestamp,
}

/// The authentication API the application integrates with. This crate takes
/// care of the authentication details, the application handles storage and UI.
#[derive(Clone)]
pub struct Auth<P, S> {
    password_auth_info_store: P,
    session_store: S,
    semaphore: Arc<Semaphore>,
}

impl<P, S> Auth<P, S>
where
    P: PasswordAuthInfoStore,
    S: SessionStore<UserId = P::UserId>,
{
    /// Initialize with the application's password authentication store and session store.
    pub fn new(password_auth_info_store: P, session_store: S) -> Auth<P, S> {
        Auth {
            password_auth_info_store,
            session_store,
            semaphore: Arc::new(Semaphore::new(MAXIMUM_CONCURRENT_VERIFICATIONS)),
        }
    }

    /// Create a user who logs in with the credentials, giving back their user
    /// id. Fails if the username is taken, or the password is shorter than
    /// `MINIMUM_PASSWORD_LENGTH`.
    pub async fn create_user(&self, credentials: &Credentials) -> Result<P::UserId, AuthError> {
        check_password_length(&credentials.password)?;
        let password_hash = self.hash(&credentials.password).await?;
        self.password_auth_info_store
            .create_user_with_password_hash(&credentials.username, password_hash)
            .await?
            .ok_or(AuthError::UsernameTaken)
    }

    /// Change the password of the user with the credentials' username to
    /// theirs, ending the user's sessions. Fails if there's no user with the
    /// username, or the password is shorter than `MINIMUM_PASSWORD_LENGTH`.
    pub async fn change_password(&self, credentials: &Credentials) -> Result<(), AuthError> {
        check_password_length(&credentials.password)?;
        let Some(password_auth_info) = self
            .password_auth_info_store
            .get_password_auth_info(&credentials.username)
            .await?
        else {
            return Err(AuthError::UnknownUsername);
        };
        let password_hash = self.hash(&credentials.password).await?;
        self.password_auth_info_store
            .set_password_hash(&credentials.username, password_hash)
            .await?;
        // Only after the password changed, so a session can't start with the
        // old password in between and survive.
        self.session_store
            .remove_user_sessions(&password_auth_info.user_id)
            .await?;
        Ok(())
    }

    /// A new session for the user with the credentials, or `None` if
    /// there's none. Verifying is slow on purpose, and there is
    /// a semaphore in place to avoid verifying too many simultaneously.
    pub async fn log_in(
        &self,
        credentials: &Credentials,
        now: Timestamp,
    ) -> Result<Option<Session>, AuthError> {
        let Some(password_auth_info) = self
            .password_auth_info_store
            .get_password_auth_info(&credentials.username)
            .await?
        else {
            // even if we can't find the user we verify a dummy password so
            // this cannot be used to probe quickly which usernames exist.
            self.verify(DUMMY_PASSWORD_HASH.clone(), &credentials.password)
                .await?;
            return Ok(None);
        };
        if !self
            .verify(password_auth_info.password_hash, &credentials.password)
            .await?
        {
            return Ok(None);
        }
        // clean up any expired sessions
        self.session_store.remove_expired_sessions(now).await?;
        let session_token = SessionToken::generate()?;
        let expires_at = now + SESSION_LIFETIME;
        self.session_store
            .set_session(
                &session_token.token_hash(),
                SessionInfo {
                    user_id: password_auth_info.user_id,
                    expires_at,
                },
            )
            .await?;
        Ok(Some(Session {
            session_token,
            expires_at,
        }))
    }

    /// Get the user id for this session.
    ///
    /// If the session is unknown or expired, returns `None`.
    pub async fn identify(
        &self,
        session_token: &SessionToken,
        now: Timestamp,
    ) -> Result<Option<P::UserId>, AuthError> {
        let session_info = self
            .session_store
            .get_session(&session_token.token_hash())
            .await?;
        if let Some(session_info) = session_info
            && session_info.expires_at > now
        {
            Ok(Some(session_info.user_id))
        } else {
            Ok(None)
        }
    }

    /// End the session the token is of, if any.
    pub async fn log_out(&self, session_token: &SessionToken) -> Result<(), AuthError> {
        self.session_store
            .remove_session(&session_token.token_hash())
            .await?;
        Ok(())
    }

    /// The password's hash.
    async fn hash(&self, password: &str) -> Result<String, AuthError> {
        let password = password.to_string();
        self.run_password_task(move || generate_hash(password))
            .await
    }

    /// Whether the password has the hash.
    async fn verify(&self, password_hash: String, password: &str) -> Result<bool, AuthError> {
        let password = password.to_string();
        self.run_password_task(move || verify_password(password, &password_hash).is_ok())
            .await
    }

    /// Run hashing or verifying a password on a thread for blocking work, as
    /// it's slow on purpose. It uses the semaphore to restrict how many can
    /// happen at one time to avoid denial of service via logging in.
    async fn run_password_task<T: Send + 'static>(
        &self,
        password_task: impl FnOnce() -> T + Send + 'static,
    ) -> Result<T, AuthError> {
        // Here we try to acquire a permit, and wait if the maximum has been
        // handed out already.
        // The permit goes along into the spawned thread, so it's only given
        // back once the task is done, even if the caller is dropped before.
        let semaphore_permit = self
            .semaphore
            .clone()
            .acquire_owned()
            .await
            .expect("the semaphore is never closed");
        Ok(spawn_blocking(move || {
            let output = password_task();
            drop(semaphore_permit);
            output
        })
        .await?)
    }
}

/// Fails if the password is shorter than `MINIMUM_PASSWORD_LENGTH`.
fn check_password_length(password: &str) -> Result<(), AuthError> {
    if password.chars().count() < MINIMUM_PASSWORD_LENGTH {
        return Err(AuthError::PasswordTooShort);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use password_auth::verify_password;

    use crate::memory_store::{MemoryPasswordAuthInfoStore, MemorySessionStore, MemoryUserId};

    use super::*;

    const USERNAME: &str = "jan";
    const PASSWORD: &str = "correct horse";
    const NEW_PASSWORD: &str = "battery staple";

    fn auth() -> Auth<MemoryPasswordAuthInfoStore, MemorySessionStore> {
        Auth::new(
            MemoryPasswordAuthInfoStore::default(),
            MemorySessionStore::default(),
        )
    }

    fn credentials(password: &str) -> Credentials {
        Credentials {
            username: USERNAME.to_string(),
            password: password.to_string(),
        }
    }

    /// The credentials of another user than `credentials`'.
    fn other_credentials() -> Credentials {
        Credentials {
            username: "piet".to_string(),
            password: PASSWORD.to_string(),
        }
    }

    #[tokio::test]
    async fn creates_user() {
        let auth = auth();

        let memory_user_id = auth.create_user(&credentials(PASSWORD)).await.unwrap();

        let password_auth_info = auth
            .password_auth_info_store
            .get_password_auth_info(USERNAME)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(password_auth_info.user_id, memory_user_id);
        assert!(verify_password(PASSWORD, &password_auth_info.password_hash).is_ok());
    }

    #[tokio::test]
    async fn refuses_taken_username() {
        let auth = auth();
        create_user(&auth, &credentials(PASSWORD)).await;

        let auth_error = auth
            .create_user(&credentials("other password"))
            .await
            .unwrap_err();

        assert!(matches!(auth_error, AuthError::UsernameTaken));
    }

    #[tokio::test]
    async fn refuses_short_password() {
        let auth = auth();

        let auth_error = auth.create_user(&credentials("short")).await.unwrap_err();

        assert!(matches!(auth_error, AuthError::PasswordTooShort));
        assert!(
            auth.password_auth_info_store
                .get_password_auth_info(USERNAME)
                .await
                .unwrap()
                .is_none()
        );
    }

    #[tokio::test]
    async fn changes_password() {
        let auth = auth();
        let memory_user_id = create_user(&auth, &credentials(PASSWORD)).await;

        auth.change_password(&credentials(NEW_PASSWORD))
            .await
            .unwrap();

        let password_auth_info = auth
            .password_auth_info_store
            .get_password_auth_info(USERNAME)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(password_auth_info.user_id, memory_user_id);
        assert!(verify_password(NEW_PASSWORD, &password_auth_info.password_hash).is_ok());
        assert!(verify_password(PASSWORD, &password_auth_info.password_hash).is_err());
    }

    #[tokio::test]
    async fn changing_password_ends_only_the_users_sessions() {
        let auth = auth();
        create_user(&auth, &credentials(PASSWORD)).await;
        let other_memory_user_id = create_user(&auth, &other_credentials()).await;
        let session_token = log_in(&auth, &credentials(PASSWORD)).await;
        let other_session_token = log_in(&auth, &other_credentials()).await;

        auth.change_password(&credentials(NEW_PASSWORD))
            .await
            .unwrap();

        assert_eq!(auth.identify(&session_token, now()).await.unwrap(), None);
        assert_eq!(
            auth.identify(&other_session_token, now()).await.unwrap(),
            Some(other_memory_user_id)
        );
    }

    #[tokio::test]
    async fn refuses_to_change_password_of_unknown_username() {
        let auth = auth();

        let auth_error = auth
            .change_password(&credentials(NEW_PASSWORD))
            .await
            .unwrap_err();

        assert!(matches!(auth_error, AuthError::UnknownUsername));
    }

    #[tokio::test]
    async fn refuses_to_change_to_short_password() {
        let auth = auth();
        create_user(&auth, &credentials(PASSWORD)).await;

        let auth_error = auth
            .change_password(&credentials("short"))
            .await
            .unwrap_err();

        assert!(matches!(auth_error, AuthError::PasswordTooShort));
        let password_auth_info = auth
            .password_auth_info_store
            .get_password_auth_info(USERNAME)
            .await
            .unwrap()
            .unwrap();
        assert!(verify_password(PASSWORD, &password_auth_info.password_hash).is_ok());
    }

    #[tokio::test]
    async fn logs_in_with_credentials() {
        let auth = auth();
        let memory_user_id = create_user(&auth, &credentials(PASSWORD)).await;

        let session = auth
            .log_in(&credentials(PASSWORD), now())
            .await
            .unwrap()
            .unwrap();

        let session_info = auth
            .session_store
            .get_session(&session.session_token.token_hash())
            .await
            .unwrap()
            .unwrap();
        assert_eq!(session_info.user_id, memory_user_id);
        assert_eq!(session_info.expires_at, now() + SESSION_LIFETIME);
        assert_eq!(session.expires_at, session_info.expires_at);
    }

    #[tokio::test]
    async fn refuses_to_log_in_with_wrong_password() {
        let auth = auth();
        create_user(&auth, &credentials(PASSWORD)).await;

        let session = auth
            .log_in(&credentials("wrong horse"), now())
            .await
            .unwrap();

        assert!(session.is_none());
    }

    #[tokio::test]
    async fn refuses_to_log_in_with_unknown_username() {
        let auth = auth();

        let session = auth.log_in(&credentials(PASSWORD), now()).await.unwrap();

        assert!(session.is_none());
    }

    #[tokio::test]
    async fn logging_in_removes_expired_sessions() {
        let auth = auth();
        create_user(&auth, &credentials(PASSWORD)).await;
        let expired_session_token = log_in(&auth, &credentials(PASSWORD)).await;

        let later = now() + SESSION_LIFETIME + SignedDuration::from_secs(1);
        let session_token = auth
            .log_in(&credentials(PASSWORD), later)
            .await
            .unwrap()
            .unwrap()
            .session_token;

        let session_store = &auth.session_store;
        assert!(
            session_store
                .get_session(&expired_session_token.token_hash())
                .await
                .unwrap()
                .is_none()
        );
        assert!(
            session_store
                .get_session(&session_token.token_hash())
                .await
                .unwrap()
                .is_some()
        );
    }

    #[tokio::test]
    async fn identifies_user_of_session() {
        let auth = auth();
        let memory_user_id = create_user(&auth, &credentials(PASSWORD)).await;
        let session_token = log_in(&auth, &credentials(PASSWORD)).await;

        let user_id = auth.identify(&session_token, now()).await.unwrap();

        assert_eq!(user_id, Some(memory_user_id));
    }

    #[tokio::test]
    async fn identifies_no_user_once_session_expired() {
        let auth = auth();
        create_user(&auth, &credentials(PASSWORD)).await;
        let session_token = log_in(&auth, &credentials(PASSWORD)).await;

        let user_id = auth
            .identify(&session_token, now() + SESSION_LIFETIME)
            .await
            .unwrap();

        assert_eq!(user_id, None);
    }

    #[tokio::test]
    async fn identifies_no_user_of_unknown_token() {
        let auth = auth();

        let user_id = auth
            .identify(&SessionToken::generate().unwrap(), now())
            .await
            .unwrap();

        assert_eq!(user_id, None);
    }

    #[tokio::test]
    async fn logs_out() {
        let auth = auth();
        create_user(&auth, &credentials(PASSWORD)).await;
        let session_token = log_in(&auth, &credentials(PASSWORD)).await;

        auth.log_out(&session_token).await.unwrap();

        assert_eq!(auth.identify(&session_token, now()).await.unwrap(), None);
    }

    #[tokio::test]
    async fn logging_out_ends_only_that_session() {
        let auth = auth();
        let memory_user_id = create_user(&auth, &credentials(PASSWORD)).await;
        let session_token = log_in(&auth, &credentials(PASSWORD)).await;
        let other_session_token = log_in(&auth, &credentials(PASSWORD)).await;

        auth.log_out(&session_token).await.unwrap();

        assert_eq!(
            auth.identify(&other_session_token, now()).await.unwrap(),
            Some(memory_user_id)
        );
    }

    #[tokio::test]
    async fn logging_out_of_unknown_session_succeeds() {
        let auth = auth();

        let result = auth.log_out(&SessionToken::generate().unwrap()).await;

        assert!(result.is_ok());
    }

    async fn create_user(
        auth: &Auth<MemoryPasswordAuthInfoStore, MemorySessionStore>,
        credentials: &Credentials,
    ) -> MemoryUserId {
        auth.create_user(credentials).await.unwrap()
    }

    /// The token of a new session, logged in `now`.
    async fn log_in(
        auth: &Auth<MemoryPasswordAuthInfoStore, MemorySessionStore>,
        credentials: &Credentials,
    ) -> SessionToken {
        auth.log_in(credentials, now())
            .await
            .unwrap()
            .unwrap()
            .session_token
    }

    fn now() -> Timestamp {
        "2026-10-26T12:00:00Z".parse().unwrap()
    }
}
