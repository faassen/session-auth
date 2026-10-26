/// A username and password used by the user to log in.
///
/// It has no `Debug`, so the password can't end up in a log.
#[derive(Clone)]
pub struct Credentials {
    /// the user's username
    pub username: String,
    /// the user's password
    pub password: String,
}
