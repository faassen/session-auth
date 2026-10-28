use std::sync::Arc;

use jiff::SignedDuration;
use password_auth::{generate_hash, verify_password};
use tokio::sync::Semaphore;
use tokio::task::spawn_blocking;

use crate::auth_settings_builder::AuthSettingsBuilder;
#[cfg(feature = "cookie")]
use crate::cookie::SessionCookie;
use crate::error::AuthError;
use crate::password_validator::{MinimumLengthPasswordValidator, PasswordValidator};

/// What an [`Auth`] needs besides its stores: the settings, and what limits
/// how many passwords are hashed or verified at once. The application shares
/// it between its `Auth`s, so the limit holds for all of them together.
///
/// [`Auth`]: crate::Auth
pub struct AuthSettings<V = MinimumLengthPasswordValidator> {
    pub(crate) session_lifetime: SignedDuration,
    password_validator: V,
    semaphore: Arc<Semaphore>,
    #[cfg(feature = "cookie")]
    pub(crate) session_cookie: SessionCookie,
}

impl AuthSettings {
    /// A builder of settings, to change the defaults with.
    pub fn builder() -> AuthSettingsBuilder {
        AuthSettingsBuilder::new()
    }
}

impl Default for AuthSettings {
    /// The settings with the defaults.
    fn default() -> AuthSettings {
        AuthSettings::builder().build()
    }
}

impl<V: PasswordValidator> AuthSettings<V> {
    /// Initialize with the settings of the builder.
    pub(crate) fn from_builder(auth_settings_builder: AuthSettingsBuilder<V>) -> AuthSettings<V> {
        AuthSettings {
            session_lifetime: auth_settings_builder.session_lifetime,
            password_validator: auth_settings_builder.password_validator,
            semaphore: Arc::new(Semaphore::new(
                auth_settings_builder.maximum_concurrent_verifications,
            )),
            #[cfg(feature = "cookie")]
            session_cookie: auth_settings_builder.session_cookie,
        }
    }

    /// Fails if the password validator doesn't accept the password.
    pub(crate) fn validate_password(&self, password: &str) -> Result<(), AuthError<V::Error>> {
        self.password_validator
            .validate(password)
            .map_err(AuthError::InvalidPassword)
    }

    /// The password's hash.
    pub(crate) async fn hash(&self, password: &str) -> Result<String, AuthError<V::Error>> {
        let password = password.to_string();
        self.run_password_task(move || generate_hash(password))
            .await
    }

    /// Whether the password has the hash.
    pub(crate) async fn verify(
        &self,
        password_hash: String,
        password: &str,
    ) -> Result<bool, AuthError<V::Error>> {
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
    ) -> Result<T, AuthError<V::Error>> {
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
