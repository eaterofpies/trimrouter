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

macro_rules! impl_from {
    ($from:ty => @string) => {
        impl From<$from> for RouterError {
            fn from(err: $from) -> Self {
                Self::Generic(err.to_string())
            }
        }
    };
    ($from:ty => $variant:ident) => {
        impl From<$from> for RouterError {
            fn from(err: $from) -> Self {
                Self::$variant(err)
            }
        }
    };
}

impl_from!(rtnetlink::Error => Netlink);
impl_from!(std::io::Error => Io);
impl_from!(std::net::AddrParseError => AddrParse);
impl_from!(std::num::ParseIntError => ParseInt);
impl_from!(String => Generic);
impl_from!(&str => @string);
impl_from!(rustables::error::BuilderError => @string);
impl_from!(rustables::error::QueryError => @string);
impl_from!(Box<dyn std::error::Error> => @string);
impl_from!(ipnet::AddrParseError => @string);
