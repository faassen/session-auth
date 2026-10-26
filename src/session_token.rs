use sha2::{Digest, Sha256};

/// How many random bytes a token has: too many to guess.
const TOKEN_BYTES: usize = 32;

/// The secret in the browser's cookie that says which session it's in.
///
/// It has no `Debug`, so the token can't end up in a log.
#[derive(Clone, PartialEq, Eq)]
pub struct SessionToken(String);

impl SessionToken {
    /// The token in a cookie's value, or `None` if the value can't be a
    /// token: it has to have the shape `generate` makes.
    pub fn parse(cookie_value: &str) -> Option<SessionToken> {
        let is_token = cookie_value.len() == TOKEN_BYTES * 2
            && cookie_value
                .bytes()
                .all(|byte| matches!(byte, b'0'..=b'9' | b'a'..=b'f'));
        if is_token {
            Some(SessionToken(cookie_value.to_string()))
        } else {
            None
        }
    }

    /// A new token is random bytes formatted as hexadecimal digits in a string.
    pub(crate) fn generate() -> Result<SessionToken, getrandom::Error> {
        let mut bytes = [0; TOKEN_BYTES];
        getrandom::fill(&mut bytes)?;
        Ok(SessionToken(
            bytes.iter().map(|byte| format!("{byte:02x}")).collect(),
        ))
    }

    /// The token as the cookie holds it.
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// We don't store the token directly in the session store, as
    /// then leaking the session store would leak information that could be used
    /// to create a new session. Instead we store a Sha256 digest.
    pub fn token_hash(&self) -> TokenHash {
        TokenHash(Sha256::digest(self.0.as_bytes()).into())
    }
}

/// The SHA-256 of a session token.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct TokenHash([u8; 32]);

impl TokenHash {
    /// The bytes of this token hash. The session store uses
    /// this as the key for session information.
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_generated_token() {
        let session_token = SessionToken::generate().unwrap();

        let parsed_session_token = SessionToken::parse(session_token.as_str()).unwrap();

        assert_eq!(parsed_session_token.as_str(), session_token.as_str());
    }

    #[test]
    fn refuses_empty_value() {
        assert!(SessionToken::parse("").is_none());
    }

    #[test]
    fn refuses_too_short_value() {
        assert!(SessionToken::parse(&"a".repeat(63)).is_none());
    }

    #[test]
    fn refuses_too_long_value() {
        assert!(SessionToken::parse(&"a".repeat(65)).is_none());
    }

    #[test]
    fn refuses_non_hexadecimal_value() {
        assert!(SessionToken::parse(&"g".repeat(64)).is_none());
    }

    #[test]
    fn refuses_uppercase_value() {
        assert!(SessionToken::parse(&"A".repeat(64)).is_none());
    }

    #[test]
    fn refuses_multibyte_value() {
        // 32 characters of two bytes each, so 64 bytes long.
        assert!(SessionToken::parse(&"é".repeat(32)).is_none());
    }
}
