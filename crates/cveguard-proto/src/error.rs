use std::fmt;

/// Fail-closed error. Display text never includes file bytes, argv, or secrets.
#[derive(Debug)]
pub enum Error {
    Schema(String),
    Io(std::io::Error),
    Busy,
    Full,
    NotInDebut(&'static str),
    Invalid(String),
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Schema(s) | Self::Invalid(s) => f.write_str(s),
            Self::Io(e) => write!(f, "{e}"),
            Self::Busy => f.write_str("ring consumer already attached"),
            Self::Full => f.write_str("ring is full"),
            Self::NotInDebut(s) => f.write_str(s),
        }
    }
}

impl std::error::Error for Error {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Io(e) => Some(e),
            _ => None,
        }
    }
}

impl From<std::io::Error> for Error {
    fn from(e: std::io::Error) -> Self {
        Self::Io(e)
    }
}

pub(crate) fn schema(msg: &str) -> Error {
    Error::Schema(msg.to_owned())
}

pub(crate) fn invalid(msg: &str) -> Error {
    Error::Invalid(msg.to_owned())
}
