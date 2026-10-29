# Changes

## Unreleased

- Feature: if we want to ask for the password in the UI even though you're
  already logged in, such as in a password change UI, we need to be able to
  check credentials without actually logging in. There is now an `Auth::verify`
  to do that. We've also exposed this as `AuthSession::verify` on the Axum
  integration for convenience.

- Feature (Axum integration): There is now an `AuthSession::change_password` API
  for changing a user's password. This not only changes the password but also
  remove the user's session cookie if they're changing their own password,
  logging them out straight away.

- Feature (Axum integration): A convenience `AuthSession::create_user` API,
  like `Auth::create_user`, so a handler that adds users only needs the
  `AuthSession`.

## 0.2.0 (2026-10-28)

We want to support applications creating an `Auth` per request for scenarios
where the database connection is in the request rather than the app state. 
  
- Breaking: We want to make `Auth` cheap to create, yet still share its
  essential state. Extracted settings out of `Auth` into `AuthSettings`. You
  build it with `AuthSettings::builder()` This replaces `AuthBuilder` and
  `Auth::builder`. `AuthSettings` is in `Auth` as an `Arc`.

- Breaking: `AuthSession` gets the `Arc<Auth>` by `FromRequestParts` instead of
  `FromRef`; the application needs to implement this as glue. This means that
  you can instead also write an application specific `FromRequestParts` that
  constructs the `Auth` from the request, on the fly.

## 0.1.0 (2026-10-27)

- Initial release.
