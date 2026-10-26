//! Logging in and out, and identifying the user of a request, by the session
//! cookie, in axum. Requires the `axum` feature.
//!
//! [`AuthSession`] gets the [`Auth`] from the router's state, so the state
//! has to give an `Arc` of it by [`FromRef`]:
//!
//! ```ignore
//! #[derive(Clone, FromRef)]
//! struct AppState {
//!     auth: Arc<AppAuth>,
//! }
//! ```
//!
//! Handlers then take it as an extractor:
//!
//! ```ignore
//! async fn home(auth_session: AuthSession<AppAuth>) -> Result<String, AppError> {
//!     if let Some(user_id) = auth_session.user_id().await? {
//!         Ok(format!("Hello, user {user_id}"))
//!     } else {
//!         Ok("Hello, stranger".to_string())
//!     }
//! }
//!
//! async fn logout(auth_session: AuthSession<AppAuth>) -> Result<Response, AppError> {
//!     let cookie_jar = auth_session.log_out().await?;
//!     Ok((cookie_jar, Redirect::to("/")).into_response())
//! }
//! ```
//!
//! [`Auth`]: crate::Auth
//! [`FromRef`]: axum::extract::FromRef

mod auth_session;

pub use auth_session::AuthSession;
