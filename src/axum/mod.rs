//! Logging in and out, and identifying the user of a request, by the session
//! cookie, in axum.

mod auth_session;

pub use auth_session::AuthSession;
