use jiff::SignedDuration;

use crate::auth_settings::AuthSettings;
#[cfg(feature = "cookie")]
use crate::cookie::SessionCookie;
use crate::password_validator::{MinimumLengthPasswordValidator, PasswordValidator};

/// How long a session lasts by default.
pub(crate) const DEFAULT_SESSION_LIFETIME: SignedDuration = SignedDuration::from_hours(30 * 24);
/// How many passwords are hashed or verified at once by default.
const DEFAULT_MAXIMUM_CONCURRENT_VERIFICATIONS: usize = 4;
/// The name of the session cookie by default.
#[cfg(feature = "cookie")]
const DEFAULT_SESSION_COOKIE_NAME: &str = "session";

/// Builds an `AuthSettings`, from `AuthSettings::builder`. Falls back on
/// defaults for builder methods that aren't used.
///
/// ```
/// # use jiff::SignedDuration;
/// # use session_auth::{AuthSettings, MinimumLengthPasswordValidator};
/// let auth_settings = AuthSettings::builder()
///     .session_lifetime(SignedDuration::from_hours(7 * 24))
///     .password_validator(MinimumLengthPasswordValidator::new(12))
///     .build();
/// ```
pub struct AuthSettingsBuilder<V = MinimumLengthPasswordValidator> {
    pub(crate) session_lifetime: SignedDuration,
    pub(crate) maximum_concurrent_verifications: usize,
    pub(crate) password_validator: V,
    #[cfg(feature = "cookie")]
    pub(crate) session_cookie: SessionCookie,
}

impl AuthSettingsBuilder {
    /// A builder with the defaults.
    pub(crate) fn new() -> AuthSettingsBuilder {
        AuthSettingsBuilder {
            session_lifetime: DEFAULT_SESSION_LIFETIME,
            maximum_concurrent_verifications: DEFAULT_MAXIMUM_CONCURRENT_VERIFICATIONS,
            password_validator: MinimumLengthPasswordValidator::default(),
            #[cfg(feature = "cookie")]
            session_cookie: SessionCookie::new(DEFAULT_SESSION_COOKIE_NAME),
        }
    }
}

impl<V: PasswordValidator> AuthSettingsBuilder<V> {
    /// How long a session lasts after the login. It's never extended. 30
    /// days by default.
    pub fn session_lifetime(mut self, session_lifetime: SignedDuration) -> AuthSettingsBuilder<V> {
        self.session_lifetime = session_lifetime;
        self
    }

    /// How many passwords are hashed or verified at once, at most; the rest
    /// wait. Hashing or verifying a password takes some 19 MiB and a core
    /// while it runs, so this keeps logging in from being used to exhaust
    /// the server. 4 by default.
    pub fn maximum_concurrent_verifications(
        mut self,
        maximum_concurrent_verifications: usize,
    ) -> AuthSettingsBuilder<V> {
        self.maximum_concurrent_verifications = maximum_concurrent_verifications;
        self
    }

    /// What a password has to be like to be accepted.
    /// [`MinimumLengthPasswordValidator`] by default.
    pub fn password_validator<W: PasswordValidator>(
        self,
        password_validator: W,
    ) -> AuthSettingsBuilder<W> {
        AuthSettingsBuilder {
            session_lifetime: self.session_lifetime,
            maximum_concurrent_verifications: self.maximum_concurrent_verifications,
            password_validator,
            #[cfg(feature = "cookie")]
            session_cookie: self.session_cookie,
        }
    }

    /// The name of the session cookie. `session` by default.
    #[cfg(feature = "cookie")]
    pub fn cookie_name(mut self, cookie_name: &'static str) -> AuthSettingsBuilder<V> {
        self.session_cookie = SessionCookie::new(cookie_name);
        self
    }

    /// The `AuthSettings`.
    pub fn build(self) -> AuthSettings<V> {
        AuthSettings::from_builder(self)
    }
}
