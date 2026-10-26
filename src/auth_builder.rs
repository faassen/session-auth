use jiff::SignedDuration;

use crate::auth::Auth;
#[cfg(feature = "cookie")]
use crate::cookie::SessionCookie;
use crate::password_policy::{MinimumLength, PasswordPolicy};
use crate::password_store::PasswordStore;
use crate::session_store::SessionStore;

/// How long a session lasts by default.
pub(crate) const DEFAULT_SESSION_LIFETIME: SignedDuration = SignedDuration::from_hours(30 * 24);
/// How many passwords are hashed or verified at once by default.
const DEFAULT_MAXIMUM_CONCURRENT_VERIFICATIONS: usize = 4;
/// The name of the session cookie by default.
#[cfg(feature = "cookie")]
const DEFAULT_SESSION_COOKIE_NAME: &str = "session";

/// Builds an `Auth`, from `Auth::builder`. What isn't set keeps its default.
///
/// ```
/// # use jiff::SignedDuration;
/// # use session_auth::{Auth, MinimumLength, PasswordStore, SessionStore};
/// fn auth<P, S>(password_store: P, session_store: S) -> Auth<P, S>
/// where
///     P: PasswordStore,
///     S: SessionStore<UserId = P::UserId>,
/// {
///     Auth::builder(password_store, session_store)
///         .session_lifetime(SignedDuration::from_hours(7 * 24))
///         .password_policy(MinimumLength(12))
///         .build()
/// }
/// ```
pub struct AuthBuilder<P, S, V = MinimumLength> {
    pub(crate) password_store: P,
    pub(crate) session_store: S,
    pub(crate) session_lifetime: SignedDuration,
    pub(crate) maximum_concurrent_verifications: usize,
    pub(crate) password_policy: V,
    #[cfg(feature = "cookie")]
    pub(crate) session_cookie: SessionCookie,
}

impl<P, S> AuthBuilder<P, S>
where
    P: PasswordStore,
    S: SessionStore<UserId = P::UserId>,
{
    /// A builder with the defaults, for the stores.
    pub(crate) fn new(password_store: P, session_store: S) -> AuthBuilder<P, S> {
        AuthBuilder {
            password_store,
            session_store,
            session_lifetime: DEFAULT_SESSION_LIFETIME,
            maximum_concurrent_verifications: DEFAULT_MAXIMUM_CONCURRENT_VERIFICATIONS,
            password_policy: MinimumLength::default(),
            #[cfg(feature = "cookie")]
            session_cookie: SessionCookie::new(DEFAULT_SESSION_COOKIE_NAME),
        }
    }
}

impl<P, S, V> AuthBuilder<P, S, V>
where
    P: PasswordStore,
    S: SessionStore<UserId = P::UserId>,
    V: PasswordPolicy,
{
    /// How long a session lasts after the login. It's never extended. 30
    /// days by default.
    pub fn session_lifetime(mut self, session_lifetime: SignedDuration) -> AuthBuilder<P, S, V> {
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
    ) -> AuthBuilder<P, S, V> {
        self.maximum_concurrent_verifications = maximum_concurrent_verifications;
        self
    }

    /// What a password has to be like to be accepted. `MinimumLength` by
    /// default.
    pub fn password_policy<W: PasswordPolicy>(self, password_policy: W) -> AuthBuilder<P, S, W> {
        AuthBuilder {
            password_store: self.password_store,
            session_store: self.session_store,
            session_lifetime: self.session_lifetime,
            maximum_concurrent_verifications: self.maximum_concurrent_verifications,
            password_policy,
            #[cfg(feature = "cookie")]
            session_cookie: self.session_cookie,
        }
    }

    /// The name of the session cookie. `session` by default.
    #[cfg(feature = "cookie")]
    pub fn cookie_name(mut self, cookie_name: &'static str) -> AuthBuilder<P, S, V> {
        self.session_cookie = SessionCookie::new(cookie_name);
        self
    }

    /// The `Auth`.
    pub fn build(self) -> Auth<P, S, V> {
        Auth::from_builder(self)
    }
}
