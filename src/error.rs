#[derive(Debug, Clone, Copy)]
pub enum Sha2Corrupted {
    Success,
    BadParam,
    StateError,
}

impl Sha2Corrupted {
    pub fn into_result<T>(self, value: T) -> Result<T> {
        match self {
            Sha2Corrupted::Success => Ok(value),
            _ => Err(Error(self)),
        }
    }
}

#[derive(Debug)]
pub struct Error(Sha2Corrupted);

impl std::error::Error for Error {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        None
    }
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let Self(status) = self;

        match status {
            Sha2Corrupted::StateError => write!(f, "invalid state"),
            Sha2Corrupted::BadParam => write!(f, "bad parameter"),
            Sha2Corrupted::Success => unreachable!(),
        }
    }
}

pub type Result<T> = std::result::Result<T, Error>;
