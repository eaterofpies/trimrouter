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

#[cfg(test)]
#[allow(unused_imports)]
mod tests {
    use super::*;
    use std::error::Error;

    #[test]
    fn test_router_error_display_all_variants() {
        let io_err = RouterError::Io(std::io::Error::new(
            std::io::ErrorKind::NotFound,
            "file missing",
        ));
        assert!(io_err.to_string().contains("I/O error: file missing"));

        let addr_err: RouterError = "127.0.0.999"
            .parse::<std::net::Ipv4Addr>()
            .unwrap_err()
            .into();
        assert!(addr_err.to_string().contains("Address parsing failed"));

        let not_found = RouterError::InterfaceNotFound("eth0".to_string());
        assert_eq!(not_found.to_string(), "Interface not found: eth0");

        let parse_int: RouterError = "abc".parse::<u8>().unwrap_err().into();
        assert!(parse_int.to_string().contains("Parse int error"));

        let generic = RouterError::from("custom error message");
        assert_eq!(generic.to_string(), "Router error: custom error message");

        let generic_string = RouterError::from("custom string".to_string());
        assert_eq!(generic_string.to_string(), "Router error: custom string");
    }

    #[test]
    fn test_router_error_source() {
        let io_err = RouterError::Io(std::io::Error::new(
            std::io::ErrorKind::PermissionDenied,
            "access denied",
        ));
        assert!(io_err.source().is_some());

        let generic = RouterError::Generic("none".to_string());
        assert!(generic.source().is_none());

        let iface = RouterError::InterfaceNotFound("lan".to_string());
        assert!(iface.source().is_none());
    }
}
