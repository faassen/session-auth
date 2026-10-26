//! The cookie that holds the session token. Requires the default `cookie` feature.
//!
#![cfg_attr(
    feature = "axum",
    doc = "Note that if you use the [axum integration](crate::axum)"
)]
#![cfg_attr(
    not(feature = "axum"),
    doc = "Note that if you use the axum integration"
)]
//! the cookie is managed for you automatically.

use cookie::time::OffsetDateTime;
use cookie::{Cookie, SameSite};

use crate::auth::Session;

/// The path of the cookie: a session is for the whole site.
const SESSION_COOKIE_PATH: &str = "/";

/// The cookie that holds the token of a session.
///
/// The cookie can't be read by scripts, is only sent over HTTPS or to
/// localhost, and isn't sent along with requests from other sites, except if a
/// link is followed. It expires with the session.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SessionCookie {
    name: &'static str,
}

impl SessionCookie {
    /// The session cookie with the name.
    pub const fn new(name: &'static str) -> SessionCookie {
        SessionCookie { name }
    }

    /// The name of the cookie, to get it from the request's cookies with.
    pub fn name(&self) -> &'static str {
        self.name
    }

    /// The cookie with the session token. It is sent to the browser
    /// once you log in.
    pub fn cookie(&self, session: &Session) -> Cookie<'static> {
        let expires = OffsetDateTime::from_unix_timestamp(session.expires_at.as_second())
            .expect("a jiff timestamp is in the range of time");
        Cookie::build((self.name, session.session_token.as_str().to_string()))
            .path(SESSION_COOKIE_PATH)
            .http_only(true)
            .secure(true)
            .same_site(SameSite::Lax)
            .expires(expires)
            .build()
    }

    /// A cookie to remove the cookie. Used when logging out.
    pub fn removal_cookie(&self) -> Cookie<'static> {
        Cookie::build(self.name).path(SESSION_COOKIE_PATH).build()
    }
}

#[cfg(test)]
mod tests {
    use cookie::Expiration;
    use jiff::Timestamp;

    use crate::session_token::SessionToken;

    use super::*;

    const SESSION_COOKIE: SessionCookie = SessionCookie::new("session");

    fn session() -> Session {
        Session {
            session_token: SessionToken::generate().unwrap(),
            expires_at: "2026-11-25T12:00:00Z".parse::<Timestamp>().unwrap(),
        }
    }

    #[test]
    fn cookie_holds_session_token() {
        let session = session();

        let cookie = SESSION_COOKIE.cookie(&session);

        assert_eq!(cookie.name(), "session");
        assert_eq!(cookie.value(), session.session_token.as_str());
    }

    #[test]
    fn cookie_is_kept_from_scripts_and_other_sites() {
        let cookie = SESSION_COOKIE.cookie(&session());

        assert_eq!(cookie.path(), Some("/"));
        assert_eq!(cookie.http_only(), Some(true));
        assert_eq!(cookie.secure(), Some(true));
        assert_eq!(cookie.same_site(), Some(SameSite::Lax));
    }

    #[test]
    fn cookie_expires_with_session() {
        let cookie = SESSION_COOKIE.cookie(&session());

        let Some(Expiration::DateTime(expires)) = cookie.expires() else {
            panic!("the cookie has no expiry date");
        };
        assert_eq!(expires.unix_timestamp(), 1_795_608_000);
    }

    #[test]
    fn removal_cookie_has_name_and_path() {
        let cookie = SESSION_COOKIE.removal_cookie();

        assert_eq!(cookie.name(), "session");
        assert_eq!(cookie.path(), Some("/"));
    }
}
