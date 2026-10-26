use std::convert::Infallible;
use std::sync::Arc;

use axum::extract::{FromRef, FromRequestParts};
use axum::http::request::Parts;
use axum_extra::extract::cookie::CookieJar;
use jiff::Timestamp;

use crate::auth::Auth;
use crate::credentials::Credentials;
use crate::error::AuthError;
use crate::password_store::PasswordStore;
use crate::password_validator::PasswordValidator;
use crate::session_store::SessionStore;
use crate::session_token::SessionToken;

/// The session of a request.
///
/// `A` is the application's [`Auth`]. The extractor gets it from the router's
/// state as an `Arc<A>`, so the state has to give one by [`FromRef`]. You can do this
/// by deriving `FromRef` on a state with an `Arc<A>` field.
pub struct AuthSession<A> {
    auth: Arc<A>,
    cookie_jar: CookieJar,
}

impl<P, S, V> AuthSession<Auth<P, S, V>>
where
    P: PasswordStore,
    S: SessionStore<UserId = P::UserId>,
    V: PasswordValidator,
{
    /// The user id of the request's session. `None` if we cannot find the
    /// session or the session isn't active.
    pub async fn user_id(&self) -> Result<Option<P::UserId>, AuthError<V::Error>> {
        if let Some(session_token) = self.session_token() {
            self.auth.identify(&session_token, Timestamp::now()).await
        } else {
            Ok(None)
        }
    }

    /// Log in with credentials, creating a new session. 
    ///
    /// Return the cookie jar in your own axum handler so the session cookie is added.
    /// Returns `None` if the credentials are wrong.
    pub async fn log_in(
        self,
        credentials: &Credentials,
    ) -> Result<Option<CookieJar>, AuthError<V::Error>> {
        if let Some(session) = self.auth.log_in(credentials, Timestamp::now()).await? {
            let cookie = self.auth.session_cookie().cookie(&session);
            Ok(Some(self.cookie_jar.add(cookie)))
        } else {
            Ok(None)
        }
    }

    /// End the session of the request's session cookie, if any. 
    /// 
    /// Return the cookie jar in your own axum handler so the session cookie is
    /// removed.
    pub async fn log_out(self) -> Result<CookieJar, AuthError<V::Error>> {
        if let Some(session_token) = self.session_token() {
            self.auth.log_out(&session_token).await?;
        }
        let removal_cookie = self.auth.session_cookie().removal_cookie();
        Ok(self.cookie_jar.remove(removal_cookie))
    }

    /// The session token in the request's session cookie, if there's one
    /// that can be a token.
    fn session_token(&self) -> Option<SessionToken> {
        self.cookie_jar
            .get(self.auth.session_cookie().name())
            .and_then(|cookie| SessionToken::parse(cookie.value()))
    }
}

impl<A, S> FromRequestParts<S> for AuthSession<A>
where
    Arc<A>: FromRef<S>,
    A: Send + Sync,
    S: Send + Sync,
{
    type Rejection = Infallible;

    async fn from_request_parts(parts: &mut Parts, state: &S) -> Result<Self, Infallible> {
        Ok(AuthSession {
            auth: Arc::from_ref(state),
            cookie_jar: CookieJar::from_headers(&parts.headers),
        })
    }
}

#[cfg(test)]
mod tests {
    use axum::Router;
    use axum::body::{Body, to_bytes};
    use axum::extract::Request;
    use axum::http::header::{COOKIE, SET_COOKIE};
    use axum::http::{Method, StatusCode};
    use axum::routing::{get, post};
    use cookie::Cookie;
    use cookie::time::Duration;
    use tower::ServiceExt;

    use crate::memory_store::{MemoryPasswordStore, MemorySessionStore, MemoryUserId};

    use super::*;

    type MemoryAuth = Auth<MemoryPasswordStore, MemorySessionStore>;

    fn credentials() -> Credentials {
        Credentials {
            username: "jan".to_string(),
            password: "correct horse".to_string(),
        }
    }

    /// The auth, with a user, the user's id, and the token of their session.
    async fn logged_in_auth(auth: MemoryAuth) -> (Arc<MemoryAuth>, MemoryUserId, SessionToken) {
        let memory_user_id = auth.create_user(&credentials()).await.unwrap();
        let session = auth
            .log_in(&credentials(), Timestamp::now())
            .await
            .unwrap()
            .unwrap();
        (Arc::new(auth), memory_user_id, session.session_token)
    }

    fn memory_auth() -> MemoryAuth {
        Auth::new(
            MemoryPasswordStore::default(),
            MemorySessionStore::default(),
        )
    }

    /// A router that answers with the user id of the session at `/`, and
    /// logs in with `credentials` at `/log-in` and out at `/log-out`.
    fn router(auth: Arc<MemoryAuth>) -> Router {
        Router::new()
            .route(
                "/",
                get(|auth_session: AuthSession<MemoryAuth>| async move {
                    format!("{:?}", auth_session.user_id().await.unwrap())
                }),
            )
            .route(
                "/log-in",
                post(|auth_session: AuthSession<MemoryAuth>| async move {
                    auth_session.log_in(&credentials()).await.unwrap().unwrap()
                }),
            )
            .route(
                "/log-out",
                post(|auth_session: AuthSession<MemoryAuth>| async move {
                    auth_session.log_out().await.unwrap()
                }),
            )
            .with_state(auth)
    }

    fn request(method: Method, path: &str, cookie_header: Option<&str>) -> Request {
        let mut request_builder = Request::builder().method(method).uri(path);
        if let Some(cookie_header) = cookie_header {
            request_builder = request_builder.header(COOKIE, cookie_header);
        }
        request_builder.body(Body::empty()).unwrap()
    }

    /// What `/` answers with the cookie header.
    async fn user_id_body(auth: Arc<MemoryAuth>, cookie_header: Option<&str>) -> String {
        let response = router(auth)
            .oneshot(request(Method::GET, "/", cookie_header))
            .await
            .unwrap();
        let bytes = to_bytes(response.into_body(), usize::MAX).await.unwrap();
        String::from_utf8(bytes.to_vec()).unwrap()
    }

    /// The cookie the response sets.
    async fn set_cookie(auth: Arc<MemoryAuth>, request: Request) -> Cookie<'static> {
        let response = router(auth).oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let header_value = response.headers().get(SET_COOKIE).unwrap();
        Cookie::parse(header_value.to_str().unwrap().to_string()).unwrap()
    }

    #[tokio::test]
    async fn user_id_of_session_cookie() {
        let (auth, memory_user_id, session_token) = logged_in_auth(memory_auth()).await;
        let cookie_header = format!("other=1; session={}", session_token.as_str());

        let body = user_id_body(auth, Some(&cookie_header)).await;

        assert_eq!(body, format!("{:?}", Some(memory_user_id)));
    }

    #[tokio::test]
    async fn no_user_id_without_cookie() {
        let (auth, _, _) = logged_in_auth(memory_auth()).await;

        assert_eq!(user_id_body(auth, None).await, "None");
    }

    #[tokio::test]
    async fn no_user_id_for_unknown_session() {
        let (auth, _, _) = logged_in_auth(memory_auth()).await;
        let cookie_header = format!("session={}", "a".repeat(64));

        assert_eq!(user_id_body(auth, Some(&cookie_header)).await, "None");
    }

    #[tokio::test]
    async fn user_id_by_configured_cookie_name() {
        let auth = Auth::builder(
            MemoryPasswordStore::default(),
            MemorySessionStore::default(),
        )
        .cookie_name("dentext_session")
        .build();
        let (auth, memory_user_id, session_token) = logged_in_auth(auth).await;

        let default_cookie_header = format!("session={}", session_token.as_str());
        let configured_cookie_header = format!("dentext_session={}", session_token.as_str());

        assert_eq!(
            user_id_body(auth.clone(), Some(&default_cookie_header)).await,
            "None"
        );
        assert_eq!(
            user_id_body(auth, Some(&configured_cookie_header)).await,
            format!("{:?}", Some(memory_user_id))
        );
    }

    #[tokio::test]
    async fn log_in_sets_session_cookie() {
        let (auth, memory_user_id, _) = logged_in_auth(memory_auth()).await;

        let cookie = set_cookie(auth.clone(), request(Method::POST, "/log-in", None)).await;

        assert_eq!(cookie.name(), "session");
        assert_eq!(cookie.http_only(), Some(true));
        let session_token = SessionToken::parse(cookie.value()).unwrap();
        assert_eq!(
            auth.identify(&session_token, Timestamp::now())
                .await
                .unwrap(),
            Some(memory_user_id)
        );
    }

    #[tokio::test]
    async fn log_out_ends_session_and_removes_cookie() {
        let (auth, _, session_token) = logged_in_auth(memory_auth()).await;
        let cookie_header = format!("session={}", session_token.as_str());

        let cookie = set_cookie(
            auth.clone(),
            request(Method::POST, "/log-out", Some(&cookie_header)),
        )
        .await;

        assert_eq!(cookie.name(), "session");
        assert_eq!(cookie.value(), "");
        assert_eq!(cookie.path(), Some("/"));
        assert_eq!(cookie.max_age(), Some(Duration::ZERO));
        assert_eq!(
            auth.identify(&session_token, Timestamp::now())
                .await
                .unwrap(),
            None
        );
    }

    #[tokio::test]
    async fn log_out_without_session_sets_no_cookie() {
        let (auth, _, _) = logged_in_auth(memory_auth()).await;

        let response = router(auth)
            .oneshot(request(Method::POST, "/log-out", None))
            .await
            .unwrap();

        assert!(response.headers().get(SET_COOKIE).is_none());
    }
}
