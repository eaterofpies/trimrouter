use std::fmt;

#[derive(Debug)]
pub enum RouterError {
    Netlink(rtnetlink::Error),
    Io(std::io::Error),
    AddrParse(std::net::AddrParseError),
    InterfaceNotFound(String),
    ParseInt(std::num::ParseIntError),
    Generic(String),
}

impl fmt::Display for RouterError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Netlink(e) => write!(f, "Netlink error: {}", e),
            Self::Io(e) => write!(f, "I/O error: {}", e),
            Self::AddrParse(e) => write!(f, "Address parsing failed: {}", e),
            Self::InterfaceNotFound(name) => write!(f, "Interface not found: {}", name),
            Self::ParseInt(e) => write!(f, "Parse int error: {}", e),
            Self::Generic(msg) => write!(f, "Router error: {}", msg),
        }
    }
}

impl std::error::Error for RouterError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Netlink(e) => Some(e),
            Self::Io(e) => Some(e),
            Self::AddrParse(e) => Some(e),
            Self::ParseInt(e) => Some(e),
            _ => None,
        }
    }
}

impl From<rtnetlink::Error> for RouterError {
    fn from(err: rtnetlink::Error) -> Self {
        Self::Netlink(err)
    }
}

impl From<std::io::Error> for RouterError {
    fn from(err: std::io::Error) -> Self {
        Self::Io(err)
    }
}

impl From<std::net::AddrParseError> for RouterError {
    fn from(err: std::net::AddrParseError) -> Self {
        Self::AddrParse(err)
    }
}

impl From<String> for RouterError {
    fn from(err: String) -> Self {
        Self::Generic(err)
    }
}

impl From<&str> for RouterError {
    fn from(err: &str) -> Self {
        Self::Generic(err.to_string())
    }
}

impl From<rustables::error::BuilderError> for RouterError {
    fn from(err: rustables::error::BuilderError) -> Self {
        Self::Generic(err.to_string())
    }
}

impl From<rustables::error::QueryError> for RouterError {
    fn from(err: rustables::error::QueryError) -> Self {
        Self::Generic(err.to_string())
    }
}

impl From<Box<dyn std::error::Error>> for RouterError {
    fn from(err: Box<dyn std::error::Error>) -> Self {
        Self::Generic(err.to_string())
    }
}

impl From<std::num::ParseIntError> for RouterError {
    fn from(err: std::num::ParseIntError) -> Self {
        Self::ParseInt(err)
    }
}
