// Copyright (c) 2019-2021, MASQ (https://masq.ai). All rights reserved.

#[cfg(target_os = "windows")]
extern crate winreg;

#[cfg(target_os = "macos")]
extern crate core_foundation;
#[cfg(target_os = "macos")]
extern crate system_configuration;

#[cfg(target_os = "windows")]
mod adapter_wrapper;
mod dns_modifier;
mod dns_modifier_factory;
mod dynamic_store_dns_modifier;
#[cfg(target_os = "windows")]
mod ipconfig_wrapper;
mod resolv_conf_dns_modifier;
#[cfg(target_os = "windows")]
mod win_dns_modifier;
mod utils;

use std::net::IpAddr;
use crate::dns_inspector::dns_modifier_factory::{DnsModifierFactoryReal, DnsModifierFactory};
use std::fmt::{Formatter, Debug};
use std::fmt;

#[derive (Clone, PartialEq)]
pub enum DnsInspectionError {
    NotConnected,
    BadEntryFormat(String),
    InvalidConfigFile(String),
    ConflictingEntries(String),
    InaccessibleInterface(String),
    RegistryQueryOsError(String),
    ConfigValueTypeError(String), // State:/Network/Service/booga/DNS/ServerAddresses
}

impl Debug for DnsInspectionError {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        match self {
            DnsInspectionError::NotConnected => write!(f, "This system does not appear to be connected to a network"),
            DnsInspectionError::BadEntryFormat(msg) => write! (f, "Bad entry format: {}", msg),
            DnsInspectionError::InvalidConfigFile(msg) => write! (f, "Invalid config file: {}", msg),
            DnsInspectionError::ConflictingEntries(_) => unimplemented!(),
            DnsInspectionError::InaccessibleInterface(_) => unimplemented!(),
            DnsInspectionError::RegistryQueryOsError(_) => unimplemented!(),
            DnsInspectionError::ConfigValueTypeError(msg) => write! (f, "Config value is not of the correct type: {}", msg),
        }
    }
}

pub fn dns_servers () -> Result<Vec<IpAddr>, DnsInspectionError> {
    let factory = DnsModifierFactoryReal::new();
    let modifier = factory.make().unwrap();
    modifier.inspect()
}

#[cfg(test)]
pub mod tests {
    use super::*;
    use crate::dns_inspector::dns_modifier_factory::{DnsModifierFactoryReal, DnsModifierFactory};

    #[test]
    fn dns_inspection_errors_render_properly() {
        let strings = vec![
            DnsInspectionError::NotConnected,
            DnsInspectionError::BadEntryFormat("bad entry format".to_string()),
            DnsInspectionError::InvalidConfigFile("invalid config file".to_string()),
            DnsInspectionError::ConfigValueTypeError("type error".to_string()),
        ].into_iter()
            .map(|e| format!("{:?}", e))
            .collect::<Vec<String>>();

        assert_eq! (strings, vec![
            "This system does not appear to be connected to a network".to_string(),
            "Bad entry format: bad entry format".to_string(),
            "Invalid config file: invalid config file".to_string(),
            "Config value is not of the correct type: type error".to_string(),
        ])
    }

    #[test]
    fn dns_servers_works() {
        let factory = DnsModifierFactoryReal::new();
        let modifier = factory.make().unwrap();
        let expected_result = modifier.inspect();

        let actual_result = dns_servers();

        assert_eq! (actual_result, expected_result);
    }
}
