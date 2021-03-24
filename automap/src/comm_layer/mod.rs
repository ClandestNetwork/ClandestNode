// Copyright (c) 2019-2021, MASQ (https://masq.ai) and/or its affiliates. All rights reserved.

use std::any::Any;
use std::fmt::{Display, Formatter, Debug};
use std::fmt;
use std::net::{IpAddr, Ipv6Addr, SocketAddr};
use std::str::FromStr;

use crate::protocols::utils::ParseError;

pub mod igdp;
pub mod pcp;
mod pcp_pmp_common;
pub mod pmp;

#[derive(Clone, PartialEq, Debug)]
pub enum AutomapErrorCause {
    NetworkConfiguration,
    ProtocolNotImplemented,
    ProtocolFailed,
    Unknown(String),
}

#[derive(Clone, PartialEq, Debug)]
pub enum AutomapError {
    NoLocalIpAddress,
    CantFindDefaultGateway,
    IPv6Unsupported(Ipv6Addr),
    FindRouterError(String, AutomapErrorCause),
    GetPublicIpError(String),
    SocketBindingError(String, SocketAddr),
    SocketPrepError(AutomapErrorCause),
    SocketSendError(AutomapErrorCause),
    SocketReceiveError(AutomapErrorCause),
    PacketParseError(ParseError),
    ProtocolError(String),
    PermanentLeasesOnly,
    AddMappingError(String),
    DeleteMappingError(String),
    TransactionFailure(String),
}

impl AutomapError {
    pub fn cause(&self) -> AutomapErrorCause {
        match self {
            AutomapError::NoLocalIpAddress => AutomapErrorCause::NetworkConfiguration,
            AutomapError::CantFindDefaultGateway => AutomapErrorCause::ProtocolFailed,
            AutomapError::IPv6Unsupported(_) => AutomapErrorCause::NetworkConfiguration,
            AutomapError::FindRouterError(_, aec) => aec.clone(),
            AutomapError::GetPublicIpError(_) => AutomapErrorCause::ProtocolFailed,
            AutomapError::SocketBindingError(_, _) => AutomapErrorCause::NetworkConfiguration,
            AutomapError::SocketPrepError(aec) => aec.clone(),
            AutomapError::SocketSendError(aec) => aec.clone(),
            AutomapError::SocketReceiveError(aec) => aec.clone(),
            AutomapError::PacketParseError(_) => AutomapErrorCause::ProtocolFailed,
            AutomapError::ProtocolError(_) => AutomapErrorCause::ProtocolFailed,
            AutomapError::PermanentLeasesOnly => AutomapErrorCause::Unknown("".to_string()),
            AutomapError::AddMappingError(_) => AutomapErrorCause::ProtocolFailed,
            AutomapError::DeleteMappingError(_) => AutomapErrorCause::ProtocolFailed,
            AutomapError::TransactionFailure(_) => AutomapErrorCause::ProtocolFailed,
        }
    }
}

pub trait Transactor {
    fn find_routers(&self) -> Result<Vec<IpAddr>, AutomapError>;
    fn get_public_ip(&self, router_ip: IpAddr) -> Result<IpAddr, AutomapError>;
    fn add_mapping(
        &self,
        router_ip: IpAddr,
        hole_port: u16,
        lifetime: u32,
    ) -> Result<u32, AutomapError>;
    fn delete_mapping(&self, router_ip: IpAddr, hole_port: u16) -> Result<(), AutomapError>;
    fn method(&self) -> Method;
    fn as_any(&self) -> &dyn Any;
}

impl Debug for dyn Transactor {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "{} Transactor", self.method())
    }
}

pub trait LocalIpFinder {
    fn find(&self) -> Result<IpAddr, AutomapError>;
}

pub struct LocalIpFinderReal {}

impl LocalIpFinder for LocalIpFinderReal {
    fn find(&self) -> Result<IpAddr, AutomapError> {
        match local_ipaddress::get() {
            Some(ip_str) => Ok(IpAddr::from_str(&ip_str).unwrap_or_else(|_| {
                panic!("Invalid IP address from local_ipaddress::get: '{}'", ip_str)
            })),
            None => Err(AutomapError::NoLocalIpAddress),
        }
    }
}

impl Default for LocalIpFinderReal {
    fn default() -> Self {
        Self::new()
    }
}

impl LocalIpFinderReal {
    pub fn new() -> Self {
        Self {}
    }
}

#[derive(PartialEq, Debug)]
pub enum Method {
    Pmp,
    Pcp,
    Igdp,
}

impl Display for Method {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        match self {
            Method::Pmp => write!(f, "PMP protocol"),
            Method::Pcp => write!(f, "PCP protocol"),
            Method::Igdp => write!(f, "IGDP protocol"),
        }
    }
}

#[cfg(test)]
mod tests {
    use std::cell::RefCell;

    use super::*;

    pub struct LocalIpFinderMock {
        find_results: RefCell<Vec<Result<IpAddr, AutomapError>>>,
    }

    impl LocalIpFinder for LocalIpFinderMock {
        fn find(&self) -> Result<IpAddr, AutomapError> {
            self.find_results.borrow_mut().remove(0)
        }
    }

    impl LocalIpFinderMock {
        pub fn new() -> Self {
            Self {
                find_results: RefCell::new(vec![]),
            }
        }

        pub fn find_result(self, result: Result<IpAddr, AutomapError>) -> Self {
            self.find_results.borrow_mut().push(result);
            self
        }
    }

    #[test]
    fn causes_work() {
        let errors_and_expectations = vec![
            (AutomapError::NoLocalIpAddress, AutomapErrorCause::NetworkConfiguration),
            (AutomapError::CantFindDefaultGateway, AutomapErrorCause::ProtocolFailed),
            (AutomapError::IPv6Unsupported(Ipv6Addr::from_str("::").unwrap()), AutomapErrorCause::NetworkConfiguration),
            (AutomapError::FindRouterError(String::new(), AutomapErrorCause::NetworkConfiguration), AutomapErrorCause::NetworkConfiguration),
            (AutomapError::GetPublicIpError(String::new()), AutomapErrorCause::ProtocolFailed),
            (AutomapError::SocketBindingError(String::new(), SocketAddr::from_str("1.2.3.4:1234").unwrap()), AutomapErrorCause::NetworkConfiguration),
            (AutomapError::SocketPrepError(AutomapErrorCause::Unknown("Booga".to_string())), AutomapErrorCause::Unknown("Booga".to_string())),
            (AutomapError::SocketSendError(AutomapErrorCause::Unknown("Booga".to_string())), AutomapErrorCause::Unknown("Booga".to_string())),
            (AutomapError::SocketReceiveError(AutomapErrorCause::Unknown("Booga".to_string())), AutomapErrorCause::Unknown("Booga".to_string())),
            (AutomapError::PacketParseError(ParseError::WrongVersion(3)), AutomapErrorCause::ProtocolFailed),
            (AutomapError::ProtocolError(String::new()), AutomapErrorCause::ProtocolFailed),
            (AutomapError::PermanentLeasesOnly, AutomapErrorCause::Unknown("".to_string())),
            (AutomapError::AddMappingError(String::new()), AutomapErrorCause::ProtocolFailed),
            (AutomapError::DeleteMappingError(String::new()), AutomapErrorCause::ProtocolFailed),
            (AutomapError::TransactionFailure(String::new()), AutomapErrorCause::ProtocolFailed),
        ];

        let errors_and_actuals = errors_and_expectations
            .iter()
            .map(|(error, _)| (error.clone(), error.cause()))
            .collect::<Vec<(AutomapError, AutomapErrorCause)>>();

        assert_eq! (errors_and_actuals, errors_and_expectations);
    }
}
