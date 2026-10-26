/// A username and password, as a user gives them to log in.
///
/// It has no `Debug`, so the password can't end up in a log.
#[derive(Clone)]
pub struct Credentials {
    pub username: String,
    pub password: String,
}
