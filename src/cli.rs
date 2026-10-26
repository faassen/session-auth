//! If you use `clap` you can use this to add password management cli
//! functionality in your application. Requires the `cli` feature.

use std::io::{IsTerminal, stdin};

use anyhow::{Context, Result, bail};
use clap::Subcommand;
use rpassword::prompt_password;

use crate::auth::Auth;
use crate::credentials::Credentials;
use crate::password_store::PasswordStore;
use crate::password_validator::PasswordValidator;
use crate::session_store::SessionStore;

/// The commands to manage the users who log in with a password.
#[derive(Subcommand)]
pub enum PasswordUserCommand {
    /// Create a user who logs in with the username and a password. Asks for the password.
    CreateUser {
        /// The username.
        username: String,
    },
    /// Change the password of the user with the username, which logs them
    /// out everywhere.
    ChangePassword {
        /// The username
        username: String,
    },
}

impl PasswordUserCommand {
    /// Run the command with the auth.
    pub async fn run<P, S, V>(self, auth: &Auth<P, S, V>) -> Result<()>
    where
        P: PasswordStore,
        S: SessionStore<UserId = P::UserId>,
        V: PasswordValidator,
    {
        match self {
            PasswordUserCommand::CreateUser { username } => {
                let credentials = Credentials {
                    username,
                    password: read_password()?,
                };
                auth.create_user(&credentials).await?;
            }
            PasswordUserCommand::ChangePassword { username } => {
                let credentials = Credentials {
                    username,
                    password: read_password()?,
                };
                auth.change_password(&credentials).await?;
            }
        }
        Ok(())
    }
}

/// The password, asked for twice without showing it, or read from standard
/// input if that isn't a terminal.
fn read_password() -> Result<String> {
    if !stdin().is_terminal() {
        let mut password = String::new();
        stdin()
            .read_line(&mut password)
            .context("reading the password")?;
        return Ok(password.trim_end_matches(['\r', '\n']).to_string());
    }
    let password = prompt_password("Password: ").context("reading the password")?;
    let repeated_password = prompt_password("Password again: ").context("reading the password")?;
    if password != repeated_password {
        bail!("the passwords differ");
    }
    Ok(password)
}
