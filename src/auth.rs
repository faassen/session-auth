use std::sync::{Arc, LazyLock};

use jiff::Timestamp;
use password_auth::generate_hash;

use crate::auth_settings::AuthSettings;
#[cfg(feature = "cookie")]
use crate::cookie::SessionCookie;
use crate::credentials::Credentials;
use crate::error::AuthError;
use crate::password_store::PasswordStore;
use crate::password_validator::{MinimumLengthPasswordValidator, PasswordValidator};
use crate::session_store::{SessionInfo, SessionStore};
use crate::session_token::SessionToken;

/// Verified against when there's no user with the username, so an unknown
/// username takes as long to refuse as a wrong password, and the time doesn't
/// tell which usernames exist.
static DUMMY_PASSWORD_HASH: LazyLock<String> = LazyLock::new(|| generate_hash("dummy password"));

/// A session consists of a session token by which it can be identified and the
/// time when it expires.
///
/// It has no `Debug`, so the token can't end up in a log.
pub struct Session {
    /// The token that identifies the session. This is used by the cookie.
    pub session_token: SessionToken,
    /// When the session expires.
    pub expires_at: Timestamp,
}

/// The authentication API the application integrates with. This crate takes
/// care of the authentication details, the application handles storage and UI.
#[derive(Clone)]
pub struct Auth<P, S, V = MinimumLengthPasswordValidator> {
    auth_settings: Arc<AuthSettings<V>>,
    password_store: P,
    session_store: S,
}

impl<P, S, V> Auth<P, S, V>
where
    P: PasswordStore,
    S: SessionStore<UserId = P::UserId>,
    V: PasswordValidator,
{
    /// Initialize with the application's settings, password authentication
    /// store and session store.
    pub fn new(
        auth_settings: Arc<AuthSettings<V>>,
        password_store: P,
        session_store: S,
    ) -> Auth<P, S, V> {
        Auth {
            auth_settings,
            password_store,
            session_store,
        }
    }

    /// The cookie that holds the session token.
    #[cfg(feature = "cookie")]
    pub fn session_cookie(&self) -> SessionCookie {
        self.auth_settings.session_cookie
    }

    /// Create a user who logs in with the credentials, giving back their user
    /// id. Fails if the username is taken, or the password validator doesn't
    /// accept the password.
    pub async fn create_user(
        &self,
        credentials: &Credentials,
    ) -> Result<P::UserId, AuthError<V::Error>> {
        self.auth_settings
            .validate_password(&credentials.password)?;
        let password_hash = self.auth_settings.hash(&credentials.password).await?;
        self.password_store
            .create_user_with_password_hash(&credentials.username, password_hash)
            .await?
            .ok_or(AuthError::UsernameTaken)
    }

    /// Change the password of the user with the credentials' username to
    /// theirs, ending the user's sessions. Fails if there's no user with the
    /// username, or the password validator doesn't accept the password.
    pub async fn change_password(
        &self,
        credentials: &Credentials,
    ) -> Result<(), AuthError<V::Error>> {
        self.auth_settings
            .validate_password(&credentials.password)?;
        let Some(password_auth_info) = self.password_store.get_user(&credentials.username).await?
        else {
            return Err(AuthError::UnknownUsername);
        };
        let password_hash = self.auth_settings.hash(&credentials.password).await?;
        self.password_store
            .set_password_hash(&credentials.username, password_hash)
            .await?;
        // Only after the password changed, so a session can't start with the
        // old password in between and survive.
        self.session_store
            .remove_user_sessions(&password_auth_info.user_id)
            .await?;
        Ok(())
    }

    /// End all sessions of the user with the id, such as when they may no
    /// longer log in.
    pub async fn end_sessions(&self, user_id: &P::UserId) -> Result<(), AuthError<V::Error>> {
        self.session_store.remove_user_sessions(user_id).await?;
        Ok(())
    }

    /// The user id of the user with the credentials, or `None` if there's
    /// none. Verifying is slow on purpose, and there is a semaphore in place
    /// to avoid verifying too many simultaneously.
    pub async fn verify(
        &self,
        credentials: &Credentials,
    ) -> Result<Option<P::UserId>, AuthError<V::Error>> {
        let Some(password_auth_info) = self.password_store.get_user(&credentials.username).await?
        else {
            // even if we can't find the user we verify a dummy password so
            // this cannot be used to probe quickly which usernames exist.
            self.auth_settings
                .verify(DUMMY_PASSWORD_HASH.clone(), &credentials.password)
                .await?;
            return Ok(None);
        };
        if !self
            .auth_settings
            .verify(password_auth_info.password_hash, &credentials.password)
            .await?
        {
            return Ok(None);
        }
        Ok(Some(password_auth_info.user_id))
    }

    /// A new session for the user with the credentials, or `None` if
    /// there's none. Verifies the credentials like `verify`.
    pub async fn log_in(
        &self,
        credentials: &Credentials,
        now: Timestamp,
    ) -> Result<Option<Session>, AuthError<V::Error>> {
        let Some(user_id) = self.verify(credentials).await? else {
            return Ok(None);
        };
        // clean up any expired sessions
        self.session_store.remove_expired_sessions(now).await?;
        let session_token = SessionToken::generate()?;
        let expires_at = now + self.auth_settings.session_lifetime;
        self.session_store
            .set_session(
                &session_token.token_hash(),
                SessionInfo {
                    user_id,
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
    ) -> Result<Option<P::UserId>, AuthError<V::Error>> {
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
    pub async fn log_out(&self, session_token: &SessionToken) -> Result<(), AuthError<V::Error>> {
        self.session_store
            .remove_session(&session_token.token_hash())
            .await?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use jiff::SignedDuration;
    use password_auth::verify_password;
    use thiserror::Error;

    use crate::auth_settings_builder::DEFAULT_SESSION_LIFETIME;
    use crate::memory_store::{MemoryPasswordStore, MemorySessionStore, MemoryUserId};
    use crate::password_validator::PasswordTooShort;

    use super::*;

    const USERNAME: &str = "jan";
    const PASSWORD: &str = "correct horse";
    const NEW_PASSWORD: &str = "battery staple";

    fn auth() -> Auth<MemoryPasswordStore, MemorySessionStore> {
        memory_auth(AuthSettings::default())
    }

    /// An auth with the settings and empty memory stores.
    fn memory_auth<V: PasswordValidator>(
        auth_settings: AuthSettings<V>,
    ) -> Auth<MemoryPasswordStore, MemorySessionStore, V> {
        Auth::new(
            Arc::new(auth_settings),
            MemoryPasswordStore::default(),
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
            .password_store
            .get_user(USERNAME)
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

        assert!(matches!(
            auth_error,
            AuthError::InvalidPassword(PasswordTooShort { minimum: 8 })
        ));
        assert!(
            auth.password_store
                .get_user(USERNAME)
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
            .password_store
            .get_user(USERNAME)
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
    async fn ends_only_the_users_sessions() {
        let auth = auth();
        let memory_user_id = create_user(&auth, &credentials(PASSWORD)).await;
        let other_memory_user_id = create_user(&auth, &other_credentials()).await;
        let session_token = log_in(&auth, &credentials(PASSWORD)).await;
        let other_session_token = log_in(&auth, &other_credentials()).await;

        auth.end_sessions(&memory_user_id).await.unwrap();

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

        assert!(matches!(
            auth_error,
            AuthError::InvalidPassword(PasswordTooShort { minimum: 8 })
        ));
        let password_auth_info = auth
            .password_store
            .get_user(USERNAME)
            .await
            .unwrap()
            .unwrap();
        assert!(verify_password(PASSWORD, &password_auth_info.password_hash).is_ok());
    }

    #[tokio::test]
    async fn verifies_credentials() {
        let auth = auth();
        let memory_user_id = create_user(&auth, &credentials(PASSWORD)).await;

        let user_id = auth.verify(&credentials(PASSWORD)).await.unwrap();

        assert_eq!(user_id, Some(memory_user_id));
    }

    #[tokio::test]
    async fn verifies_no_user_with_wrong_password() {
        let auth = auth();
        create_user(&auth, &credentials(PASSWORD)).await;

        let user_id = auth.verify(&credentials("wrong horse")).await.unwrap();

        assert_eq!(user_id, None);
    }

    #[tokio::test]
    async fn verifies_no_user_with_unknown_username() {
        let auth = auth();

        let user_id = auth.verify(&credentials(PASSWORD)).await.unwrap();

        assert_eq!(user_id, None);
    }

    #[tokio::test]
    async fn verifying_starts_no_session() {
        let auth = auth();
        create_user(&auth, &credentials(PASSWORD)).await;

        auth.verify(&credentials(PASSWORD)).await.unwrap();

        assert!(auth.session_store.is_empty());
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
        assert_eq!(session_info.expires_at, now() + DEFAULT_SESSION_LIFETIME);
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

        let later = now() + DEFAULT_SESSION_LIFETIME + SignedDuration::from_secs(1);
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
            .identify(&session_token, now() + DEFAULT_SESSION_LIFETIME)
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

    #[tokio::test]
    async fn session_lasts_configured_lifetime() {
        let session_lifetime = SignedDuration::from_hours(1);
        let auth = memory_auth(
            AuthSettings::builder()
                .session_lifetime(session_lifetime)
                .build(),
        );
        create_user(&auth, &credentials(PASSWORD)).await;

        let session = auth
            .log_in(&credentials(PASSWORD), now())
            .await
            .unwrap()
            .unwrap();

        assert_eq!(session.expires_at, now() + session_lifetime);
    }

    #[tokio::test]
    async fn refuses_password_by_configured_validator() {
        let auth = memory_auth(AuthSettings::builder().password_validator(NoHorses).build());

        let auth_error = auth.create_user(&credentials(PASSWORD)).await.unwrap_err();

        assert!(matches!(
            auth_error,
            AuthError::InvalidPassword(HorsePassword)
        ));
    }

    /// A password validator that refuses passwords with a horse in them.
    struct NoHorses;

    /// The password has a horse in it.
    #[derive(Debug, Error)]
    #[error("the password has a horse in it")]
    struct HorsePassword;

    impl PasswordValidator for NoHorses {
        type Error = HorsePassword;

        fn validate(&self, password: &str) -> Result<(), HorsePassword> {
            if password.contains("horse") {
                return Err(HorsePassword);
            }
            Ok(())
        }
    }

    async fn create_user(
        auth: &Auth<MemoryPasswordStore, MemorySessionStore>,
        credentials: &Credentials,
    ) -> MemoryUserId {
        auth.create_user(credentials).await.unwrap()
    }

    /// The token of a new session, logged in `now`.
    async fn log_in(
        auth: &Auth<MemoryPasswordStore, MemorySessionStore>,
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
