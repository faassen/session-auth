# Changes

## Unreleased

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
