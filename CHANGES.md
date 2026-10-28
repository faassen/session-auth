# Changes

## Unreleased

We want to support applications creating multiple auths for scenarios where the
database connection is in the request rather than the app state. 
  
- Breaking: We want to make `Auth` cheap to create, yet still share its
  essential state. Extracted settings out of `Auth` into `AuthSettings`. You
  build it with `AuthSettings::builder()` This replaces `AuthBuilder` and
  `Auth::builder`. `AuthSettings` is in `Auth` as an `Arc`.

## 0.1.0 (2026-10-27)

- Initial release.
