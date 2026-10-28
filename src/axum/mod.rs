//! [`AuthSession`] provides an API for Axum-based applications to log in and
//! out, and identifying the user of a request. Requires the `axum` feature.
//! 
//! You obtain [`AuthSession`] with an extractor in your handlers:
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
//! In order for this to work, your application must implement some glue so you
//! can obtain the [`Auth`] object wired for your application, which we'll name
//! `AppAuth` here. 
//!
//! ```ignore
//! type AppAuth = Auth<AppPasswordStore, AppSessionStore>;
//! ```
//! 
//! If you have it stored in the app state like this (using an `Arc` so it's
//! fast to clone):
//!
//! ```ignore
//! #[derive(Clone)]
//! struct AppState {
//!     auth: Arc<AppAuth>,
//! }
//! ```
//! 
//! Then you can wire it into your application using the following extractor:
//!  
//! ```ignore
//! impl FromRequestParts<AppState> for Arc<AppAuth> {
//!     type Rejection = Infallible;
//!
//!     async fn from_request_parts(
//!         _parts: &mut Parts,
//!         app_state: &AppState,
//!     ) -> Result<Arc<AppAuth>, Infallible> {
//!         Ok(app_state.auth.clone())
//!     }
//! }
//! ```
//!
//! Alternatively you may want to generate it per-request, for instance because
//! a middleware puts a database connection into the request, and the stores
//! should use it. The database connection could also be the database
//! transaction, if you have per-request database transaction handling. The app
//! state then holds the [`AuthSettings`], so that all the `Auth`s share them:
//!
//! ```ignore
//! #[derive(Clone)]
//! struct AppState {
//!     auth_settings: Arc<AuthSettings>,
//! }
//! ```
//!
//! This requires an extractor like this, imagining some kind of database
//! `Connection` is in an Axum request extension.
//!
//! ```ignore
//! impl FromRequestParts<AppState> for Arc<AppAuth> {
//!     type Rejection = AppError;
//!
//!     async fn from_request_parts(
//!         parts: &mut Parts,
//!         app_state: &AppState,
//!     ) -> Result<Arc<AppAuth>, AppError> {
//!         let connection = parts
//!             .extensions
//!             .get::<Connection>()
//!             .cloned()
//!             .ok_or(AppError::NoConnection)?;
//!         Ok(Arc::new(Auth::new(
//!             app_state.auth_settings.clone(),
//!             AppPasswordStore::new(connection.clone()),
//!             AppSessionStore::new(connection),
//!         )))
//!     }
//! }
//! ```
//!
//! If the extractor fails, its rejection is the rejection of [`AuthSession`]
//! too.
//!  
//! [`Auth`]: crate::Auth
//! [`AuthSettings`]: crate::AuthSettings

mod auth_session;

pub use auth_session::AuthSession;
