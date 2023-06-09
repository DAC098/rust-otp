#[derive(Debug)]
pub enum Error {
    /// potential error generated when creating hmac's
    InvalidKeyLength,
    UnixEpochError,
}

pub type Result<T> = std::result::Result<T, Error>;

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Error::InvalidKeyLength => write!(
                f, "invalid key length"
            ),
            Error::UnixEpochError => write!(
                f, "error generating unix epoch"
            )
        }
    }
}

impl std::error::Error for Error {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        None
    }
}

impl From<hmac::digest::InvalidLength> for Error {
    fn from(_: hmac::digest::InvalidLength) -> Self {
        Error::InvalidKeyLength
    }
}
