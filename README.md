# session-auth

This is a little framework to help you build session-based authentication for a
web application. It builds on a lot of existing functionality and pulls it
together in a convenient bundle.

In your application, you need to implement [`PasswordStore`] and
[`SessionStore`] on top of whatever database it is using.

After that, you build the [`AuthSettings`] with `AuthSettings::builder()`. You
can then either store an [`Auth`] instance in your application's store with this
as an `Arc`, and then use it whenever authentication is required, or instead you
only store `AuthSettings` in the state and create [`Auth`] on a per-request
basis.

You can use the auth API in your application on it to create users, log in to
get a session, and identify users by session.

Authentication during login is deliberately a costly operation, so to protect
against denial of service attacks, the settings include the limit on how many
passwords are hashed or verified at once.

The enabled by default `cookie` feature helps you manage your session cookies.
See [`cookie`] for more.

If you use Axum, which requires the `axum` feature, cookies are managed for you
automatically. See [`axum`] for more information.

If you use Clap for CLI parsing, the `cli` feature adds support for basic create
password and change user functionality. See [`cli`] for more information.

[`PasswordStore`]: https://docs.rs/session-auth/latest/session_auth/trait.PasswordStore.html
[`SessionStore`]: https://docs.rs/session-auth/latest/session_auth/trait.SessionStore.html
[`Auth`]: https://docs.rs/session-auth/latest/session_auth/struct.Auth.html
[`AuthSettings`]: https://docs.rs/session-auth/latest/session_auth/struct.AuthSettings.html
[`cookie`]: https://docs.rs/session-auth/latest/session_auth/cookie/index.html
[`axum`]: https://docs.rs/session-auth/latest/session_auth/axum/index.html
[`cli`]: https://docs.rs/session-auth/latest/session_auth/cli/index.html
