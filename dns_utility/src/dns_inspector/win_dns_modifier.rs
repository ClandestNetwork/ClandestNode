// Copyright (c) 2017-2019, Substratum LLC (https://substratum.net) and/or its affiliates. All rights reserved.

use crate::dns_inspector::dns_modifier::DnsModifier;
use crate::dns_inspector::ipconfig_wrapper::{IpconfigWrapper, IpconfigWrapperReal};
use crate::netsh::{Netsh, NetshCommand, NetshError};
use std::collections::HashSet;
use std::fmt::Debug;
use std::io;
use winreg::enums::*;
use winreg::RegKey;
use std::net::IpAddr;
use std::str::FromStr;

const NOT_FOUND: i32 = 2;
const PERMISSION_DENIED: i32 = 5;
const PERMISSION_DENIED_STR: &str = "Permission denied";

pub struct WinDnsModifier {
    hive: Box<dyn RegKeyTrait>,
    ipconfig: Box<dyn IpconfigWrapper>,
    netsh: Box<dyn Netsh>,
}

impl DnsModifier for WinDnsModifier {
    fn type_name(&self) -> &'static str {
        "WinDnsModifier"
    }
    fn inspect(&self) ->  Result<Vec<IpAddr>, String> {
        let interfaces = self.find_interfaces_to_inspect()?;
        let dns_server_list_csv = self.find_dns_server_list(interfaces)?;
        let ip_vec:Vec<_> = dns_server_list_csv.split(',')
            .flat_map(|ip_str| IpAddr::from_str(&ip_str))
            .collect();
        Ok(ip_vec)
    }
}

impl Default for WinDnsModifier {
    fn default() -> Self {
        WinDnsModifier {
            hive: Box::new(RegKeyReal::new(
                RegKey::predef(HKEY_LOCAL_MACHINE),
                "HKEY_LOCAL_MACHINE",
            )),
            ipconfig: Box::new(IpconfigWrapperReal {}),
            netsh: Box::new(NetshCommand {}),
        }
    }
}

impl WinDnsModifier {
    pub fn new() -> Self {
        Default::default()
    }

    pub fn find_interfaces_to_inspect(&self) -> Result<Vec<Box<dyn RegKeyTrait>>, String> {
        self.find_interfaces(KEY_READ)
    }

    fn find_interfaces(&self, access_required: u32) -> Result<Vec<Box<dyn RegKeyTrait>>, String> {
        let interface_key = self.handle_reg_error(
            access_required == KEY_READ,
            self.hive.open_subkey_with_flags(
                "SYSTEM\\CurrentControlSet\\Services\\Tcpip\\Parameters\\Interfaces",
                access_required,
            ),
        )?;
        let gateway_interfaces: Vec<Box<dyn RegKeyTrait>> = interface_key
            .enum_keys()
            .into_iter()
            .flatten()
            .flat_map(|interface_name| {
                interface_key.open_subkey_with_flags(&interface_name[..], access_required)
            })
            .filter(|interface| {
                WinDnsModifier::get_default_gateway(interface.as_ref()).is_some()
                    && interface.get_value("NameServer").is_ok()
            })
            .collect();
        if gateway_interfaces.is_empty() {
            return Err("This system has no accessible network interfaces configured with default gateways and DNS servers".to_string());
        }
        let distinct_gateway_ips: HashSet<String> = gateway_interfaces
            .iter()
            .flat_map(|interface| WinDnsModifier::get_default_gateway(interface.as_ref()))
            .collect();
        if distinct_gateway_ips.len() > 1 {
            let msg = match access_required {
                code if code == KEY_ALL_ACCESS => "Manual configuration required.",
                code if code == KEY_READ => "Cannot summarize DNS settings.",
                _ => "",
            };
            Err (format! ("This system has {} active network interfaces configured with {} different default gateways. {}",
                gateway_interfaces.len (), distinct_gateway_ips.len (), msg))
        } else {
            Ok(gateway_interfaces)
        }
    }

    pub fn find_dns_server_list(
        &self,
        interfaces: Vec<Box<dyn RegKeyTrait>>,
    ) -> Result<String, String> {
        let interfaces_len = interfaces.len();
        let list_result_vec: Vec<Result<String, String>> = interfaces
            .into_iter()
            .map(|interface| self.find_dns_servers_for_interface(interface))
            .collect();
        let errors: Vec<String> = list_result_vec
            .iter()
            .flat_map(|result_ref| match *result_ref {
                Err(ref e) => Some(e.clone()),
                Ok(_) => None,
            })
            .collect();
        if !errors.is_empty() {
            return Err(errors.join(", "));
        }
        let list_set: HashSet<String> = list_result_vec
            .into_iter()
            .flat_map(|result| match result {
                Err(e) => panic!("Error magically appeared: {}", e),
                Ok(list) => Some(list),
            })
            .collect();
        if list_set.len() > 1 {
            Err (format! ("This system has {} active network interfaces configured with {} different DNS server lists. Cannot summarize DNS settings.", interfaces_len, list_set.len ()))
        } else {
            let list_vec = list_set.into_iter().collect::<Vec<String>>();
            Ok(list_vec[0].clone())
        }
    }

    fn find_dns_servers_for_interface(
        &self,
        interface: Box<dyn RegKeyTrait>,
    ) -> Result<String, String> {
        match (
            interface.get_value("DhcpNameServer"),
            interface.get_value("NameServer"),
        ) {
            (Err(_), Err(_)) => Err(
                "Interface has neither NameServer nor DhcpNameServer; probably not connected"
                    .to_string(),
            ),
            (Err(_), Ok(ref permanent)) if permanent == &String::new() => Err(
                "Interface has neither NameServer nor DhcpNameServer; probably not connected"
                    .to_string(),
            ),
            (Ok(ref dhcp), Err(_)) => Ok(dhcp.clone()),
            (Ok(ref dhcp), Ok(ref permanent)) if permanent == &String::new() => Ok(dhcp.clone()),
            (_, Ok(permanent)) => Ok(permanent),
        }
    }

    fn set_nameservers(
        &self,
        interface: &dyn RegKeyTrait,
        nameservers: &str,
    ) -> Result<(), String> {
        if let Some(friendly_name) = self.find_adapter_friendly_name(interface) {
            match self.netsh.set_nameserver(&friendly_name, nameservers) {
                Ok(()) => Ok(()),
                Err(NetshError::IOError(ref e)) if e.raw_os_error() == Some(PERMISSION_DENIED) => {
                    Err(PERMISSION_DENIED_STR.to_string())
                }
                Err(NetshError::IOError(ref e)) => Err(e.to_string()),
                Err(e) => Err(format!("{:?}", e)),
            }
        } else {
            Err(format!(
                "Could not find adapter name for interface: {}",
                interface.path()
            ))
        }
    }

    fn find_adapter_friendly_name(&self, interface: &dyn RegKeyTrait) -> Option<String> {
        if let Ok(adapters) = self.ipconfig.get_adapters() {
            adapters
                .into_iter()
                .find(|adapter| {
                    adapter.adapter_name().to_lowercase() == interface.path().to_lowercase()
                })
                .map(|adapter| adapter.friendly_name().to_string())
        } else {
            None
        }
    }

    fn handle_reg_error<T>(&self, read_only: bool, result: io::Result<T>) -> Result<T, String> {
        match result {
            Ok(retval) => Ok(retval),
            Err(ref e) if e.raw_os_error() == Some(PERMISSION_DENIED) => Err(String::from(
                "You must have administrative privilege to modify your DNS settings",
            )),
            Err(ref e) if e.raw_os_error() == Some(NOT_FOUND) => Err(format!(
                "Registry contains no DNS information {}",
                if read_only { "to display" } else { "to modify" }
            )),
            Err(ref e) => Err(format!("Unexpected error: {:?}", e)),
        }
    }

    fn is_subverted(name_servers: &str) -> bool {
        name_servers == "127.0.0.1" || name_servers.starts_with("127.0.0.1,")
    }

    fn get_default_gateway(interface: &dyn RegKeyTrait) -> Option<String> {
        let string_opt = match (
            interface.get_value("DefaultGateway"),
            interface.get_value("DhcpDefaultGateway"),
        ) {
            (Ok(_), Ok(ddg)) => Some(ddg),
            (Ok(dg), Err(_)) => Some(dg),
            (Err(_), Ok(ddg)) => Some(ddg),
            (Err(_), Err(_)) => None,
        };
        match string_opt {
            Some(ref s) if s.is_empty() => None,
            Some(s) => Some(s),
            None => None,
        }
    }
}

pub trait RegKeyTrait: Debug {
    fn path(&self) -> &str;
    fn enum_keys(&self) -> Vec<io::Result<String>>;
    fn open_subkey_with_flags(&self, path: &str, perms: u32) -> io::Result<Box<dyn RegKeyTrait>>;
    fn get_value(&self, path: &str) -> io::Result<String>;
    fn set_value(&self, path: &str, value: &str) -> io::Result<()>;
    fn delete_value(&self, path: &str) -> io::Result<()>;
}

#[derive(Debug)]
struct RegKeyReal {
    delegate: RegKey,
    path: String,
}

impl RegKeyTrait for RegKeyReal {
    fn path(&self) -> &str {
        &self.path
    }

    fn enum_keys(&self) -> Vec<io::Result<String>> {
        self.delegate.enum_keys().collect()
    }

    fn open_subkey_with_flags(&self, path: &str, perms: u32) -> io::Result<Box<dyn RegKeyTrait>> {
        match self.delegate.open_subkey_with_flags(path, perms) {
            Ok(delegate) => Ok(Box::new(RegKeyReal {
                delegate,
                path: path.to_string(),
            })),
            Err(e) => Err(e),
        }
    }

    fn get_value(&self, name: &str) -> io::Result<String> {
        self.delegate.get_value(name)
    }

    fn set_value(&self, name: &str, value: &str) -> io::Result<()> {
        self.delegate.set_value(name, &value.to_string())
    }

    fn delete_value(&self, name: &str) -> io::Result<()> {
        self.delegate.delete_value(name)
    }
}

impl RegKeyReal {
    pub fn new(delegate: RegKey, path: &str) -> RegKeyReal {
        RegKeyReal {
            delegate,
            path: path.to_string(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dns_inspector::adapter_wrapper::test_utils::AdapterWrapperStub;
    use crate::dns_inspector::adapter_wrapper::AdapterWrapper;
    use crate::dns_inspector::ipconfig_wrapper::test_utils::IpconfigWrapperMock;
    use masq_lib::test_utils::fake_stream_holder::FakeStreamHolder;
    use std::cell::RefCell;
    use std::collections::HashMap;
    use std::io::Error;
    use std::sync::Arc;
    use std::sync::Mutex;

    #[test]
    fn is_subverted_says_no_if_masq_dns_appears_too_late() {
        let result = WinDnsModifier::is_subverted(&"1.1.1.1,127.0.0.1".to_string());

        assert_eq!(result, false)
    }

    #[test]
    fn is_subverted_says_no_if_first_dns_is_only_masq_like() {
        let result = WinDnsModifier::is_subverted(&"127.0.0.11".to_string());

        assert_eq!(result, false)
    }

    #[test]
    fn is_subverted_says_yes_if_first_dns_is_masq() {
        let result = WinDnsModifier::is_subverted(&"127.0.0.1,1.1.1.1".to_string());

        assert_eq!(result, true)
    }

    #[test]
    fn get_default_gateway_sees_dhcp_if_both_are_specified() {
        // Many people think this is incorrect behavior, but it seems to be the way Win7+ does things.
        let interface: Box<dyn RegKeyTrait> = Box::new(
            RegKeyMock::default()
                .get_value_result("DefaultGateway", Ok("DefaultGateway".to_string()))
                .get_value_result("DhcpDefaultGateway", Ok("DhcpDefaultGateway".to_string())),
        );

        let result = WinDnsModifier::get_default_gateway(interface.as_ref());

        assert_eq!(result, Some("DhcpDefaultGateway".to_string()))
    }

    #[test]
    fn get_default_gateway_sees_naked_default_if_it_is_the_only_one_specified() {
        let interface: Box<dyn RegKeyTrait> = Box::new(
            RegKeyMock::default()
                .get_value_result("DefaultGateway", Ok("DefaultGateway".to_string()))
                .get_value_result(
                    "DhcpDefaultGateway",
                    Err(Error::from_raw_os_error(NOT_FOUND)),
                ),
        );

        let result = WinDnsModifier::get_default_gateway(interface.as_ref());

        assert_eq!(result, Some("DefaultGateway".to_string()))
    }

    #[test]
    fn get_default_gateway_sees_dhcp_default_if_it_is_the_only_one_specified() {
        let interface: Box<dyn RegKeyTrait> = Box::new(
            RegKeyMock::default()
                .get_value_result("DefaultGateway", Err(Error::from_raw_os_error(NOT_FOUND)))
                .get_value_result("DhcpDefaultGateway", Ok("DhcpDefaultGateway".to_string())),
        );

        let result = WinDnsModifier::get_default_gateway(interface.as_ref());

        assert_eq!(result, Some("DhcpDefaultGateway".to_string()))
    }

    #[test]
    fn get_default_gateway_sees_nothing_if_nothing_is_specified() {
        let interface: Box<dyn RegKeyTrait> = Box::new(
            RegKeyMock::default()
                .get_value_result("DefaultGateway", Err(Error::from_raw_os_error(NOT_FOUND)))
                .get_value_result(
                    "DhcpDefaultGateway",
                    Err(Error::from_raw_os_error(NOT_FOUND)),
                ),
        );

        let result = WinDnsModifier::get_default_gateway(interface.as_ref());

        assert_eq!(result, None)
    }

    #[test]
    fn windnsmodifier_knows_its_type_name() {
        let subject = WinDnsModifier::default();

        let result = subject.type_name();

        assert_eq!(result, "WinDnsModifier");
    }

    #[test]
    fn find_dns_servers_for_interface_handles_all_info_missing() {
        let interface: Box<dyn RegKeyTrait> = Box::new(
            RegKeyMock::default()
                .get_value_result("NameServer", Err(Error::from_raw_os_error(NOT_FOUND)))
                .get_value_result("DhcpNameServer", Err(Error::from_raw_os_error(NOT_FOUND))),
        );
        let subject = WinDnsModifier::new();

        let result = subject.find_dns_servers_for_interface(interface);

        assert_eq!(
            result,
            Err(
                "Interface has neither NameServer nor DhcpNameServer; probably not connected"
                    .to_string()
            )
        );
    }

    #[test]
    fn find_dns_servers_for_interface_handles_name_server_missing() {
        let interface: Box<dyn RegKeyTrait> = Box::new(
            RegKeyMock::default()
                .get_value_result("NameServer", Err(Error::from_raw_os_error(NOT_FOUND)))
                .get_value_result(
                    "DhcpNameServer",
                    Ok("name server list from DHCP".to_string()),
                ),
        );
        let subject = WinDnsModifier::new();

        let result = subject.find_dns_servers_for_interface(interface);

        assert_eq!(result, Ok("name server list from DHCP".to_string()));
    }

    #[test]
    fn find_dns_servers_for_interface_handles_dhcp_name_server_missing() {
        let interface: Box<dyn RegKeyTrait> = Box::new(
            RegKeyMock::default()
                .get_value_result(
                    "NameServer",
                    Ok("name server list from permanent".to_string()),
                )
                .get_value_result("DhcpNameServer", Err(Error::from_raw_os_error(NOT_FOUND))),
        );
        let subject = WinDnsModifier::new();

        let result = subject.find_dns_servers_for_interface(interface);

        assert_eq!(result, Ok("name server list from permanent".to_string()));
    }

    #[test]
    fn find_dns_servers_for_interface_handles_both_dhcp_and_nameserver() {
        let interface: Box<dyn RegKeyTrait> = Box::new(
            RegKeyMock::default()
                .get_value_result(
                    "NameServer",
                    Ok("name server list from permanent".to_string()),
                )
                .get_value_result(
                    "DhcpNameServer",
                    Ok("name server list from DHCP".to_string()),
                ),
        );
        let subject = WinDnsModifier::new();

        let result = subject.find_dns_servers_for_interface(interface);

        assert_eq!(result, Ok("name server list from permanent".to_string()));
    }

    #[test]
    fn find_dns_servers_for_interface_handles_nameserver_blank_and_dhcp_nameserver_present() {
        let interface: Box<dyn RegKeyTrait> = Box::new(
            RegKeyMock::default()
                .get_value_result("NameServer", Ok("".to_string()))
                .get_value_result(
                    "DhcpNameServer",
                    Ok("name server list from DHCP".to_string()),
                ),
        );
        let subject = WinDnsModifier::new();

        let result = subject.find_dns_servers_for_interface(interface);

        assert_eq!(result, Ok("name server list from DHCP".to_string()));
    }

    #[test]
    fn find_dns_servers_for_interface_handles_nameserver_blank_and_dhcp_nameserver_missing() {
        let interface: Box<dyn RegKeyTrait> = Box::new(
            RegKeyMock::default()
                .get_value_result("NameServer", Ok("".to_string()))
                .get_value_result("DhcpNameServer", Err(Error::from_raw_os_error(NOT_FOUND))),
        );
        let subject = WinDnsModifier::new();

        let result = subject.find_dns_servers_for_interface(interface);

        assert_eq!(
            result,
            Err(
                "Interface has neither NameServer nor DhcpNameServer; probably not connected"
                    .to_string()
            )
        );
    }

    #[test]
    fn set_nameservers_complains_if_it_cant_find_the_adapter_friendly_name() {
        let mut subject = WinDnsModifier::new();
        let ipconfig =
            IpconfigWrapperMock::new().get_adapters_result(Err(Error::from_raw_os_error(3).into()));
        subject.ipconfig = Box::new(ipconfig);
        let interface = RegKeyMock::new("the_interface");

        let result = subject.set_nameservers(&interface, "nevermind");

        assert_eq!(
            result,
            Err("Could not find adapter name for interface: the_interface".to_string())
        );
    }

    #[test]
    fn inspect_complains_if_no_interfaces_key_exists() {
        let stream_holder = FakeStreamHolder::new();
        let hive = RegKeyMock::default()
            .open_subkey_with_flags_result(Err(Error::from_raw_os_error(NOT_FOUND)));
        let mut subject = WinDnsModifier::default();
        subject.hive = Box::new(hive);

        let result = subject.inspect();

        assert_eq!(
            result.err().unwrap(),
            "Registry contains no DNS information to display".to_string()
        );
        assert_eq!(stream_holder.stdout.get_string(), String::new());
    }

    #[test]
    fn inspect_complains_about_unexpected_os_error() {
        let hive =
            RegKeyMock::default().open_subkey_with_flags_result(Err(Error::from_raw_os_error(3)));
        let mut subject = WinDnsModifier::default();
        subject.hive = Box::new(hive);

        let result = subject.inspect();

        let string_err = result.err().unwrap();
        assert_eq!(
            string_err.starts_with("Unexpected error: "),
            true,
            "{}",
            &string_err
        );
        assert_eq!(string_err.contains("code: 3"), true, "{}", &string_err);
    }

    #[test]
    fn inspect_complains_if_no_interfaces_have_default_gateway_or_dhcp_default_gateway_values() {
        let one_interface = RegKeyMock::default()
            .get_value_result("DefaultGateway", Err(Error::from_raw_os_error(NOT_FOUND)))
            .get_value_result(
                "DhcpDefaultGateway",
                Err(Error::from_raw_os_error(NOT_FOUND)),
            );
        let another_interface = RegKeyMock::default()
            .get_value_result("DefaultGateway", Err(Error::from_raw_os_error(NOT_FOUND)))
            .get_value_result(
                "DhcpDefaultGateway",
                Err(Error::from_raw_os_error(NOT_FOUND)),
            );
        let interfaces = RegKeyMock::default()
            .enum_keys_result(vec![Ok("one_interface"), Ok("another_interface")])
            .open_subkey_with_flags_result(Ok(Box::new(one_interface)))
            .open_subkey_with_flags_result(Ok(Box::new(another_interface)));
        let hive = RegKeyMock::default().open_subkey_with_flags_result(Ok(Box::new(interfaces)));
        let mut subject = WinDnsModifier::default();
        subject.hive = Box::new(hive);

        let result = subject.inspect();

        assert_eq!(result.err().unwrap(), "This system has no accessible network interfaces configured with default gateways and DNS servers".to_string());
    }

    #[test]
    fn inspect_complains_if_interfaces_have_blank_default_gateway_and_dhcp_default_gateway_values()
    {
        let one_interface = RegKeyMock::default()
            .get_value_result("DefaultGateway", Ok(String::new()))
            .get_value_result("DhcpDefaultGateway", Ok(String::new()));
        let another_interface = RegKeyMock::default()
            .get_value_result("DefaultGateway", Ok(String::new()))
            .get_value_result("DhcpDefaultGateway", Ok(String::new()));
        let interfaces = RegKeyMock::default()
            .enum_keys_result(vec![Ok("one_interface"), Ok("another_interface")])
            .open_subkey_with_flags_result(Ok(Box::new(one_interface)))
            .open_subkey_with_flags_result(Ok(Box::new(another_interface)));
        let hive = RegKeyMock::default().open_subkey_with_flags_result(Ok(Box::new(interfaces)));
        let mut subject = WinDnsModifier::default();
        subject.hive = Box::new(hive);

        let result = subject.inspect();

        assert_eq!(result.err().unwrap(), "This system has no accessible network interfaces configured with default gateways and DNS servers".to_string());
    }

    #[test]
    fn inspect_complains_if_interfaces_have_different_gateway_values() {
        let one_interface = RegKeyMock::default()
            .get_value_result("DefaultGateway", Ok("Gateway IP".to_string()))
            .get_value_result(
                "DhcpDefaultGateway",
                Err(Error::from_raw_os_error(NOT_FOUND)),
            )
            .get_value_result("NameServer", Ok("8.8.8.8".to_string()));
        let another_interface = RegKeyMock::default()
            .get_value_result("DefaultGateway", Err(Error::from_raw_os_error(NOT_FOUND)))
            .get_value_result("DhcpDefaultGateway", Ok("DHCP Gateway IP".to_string()))
            .get_value_result("NameServer", Ok("8.8.8.8".to_string()));
        let last_interface = RegKeyMock::default()
            .get_value_result("DefaultGateway", Err(Error::from_raw_os_error(NOT_FOUND)))
            .get_value_result("DhcpDefaultGateway", Ok("DHCP Gateway IP".to_string()))
            .get_value_result("NameServer", Ok("8.8.8.8".to_string()));
        let interfaces = RegKeyMock::default()
            .enum_keys_result(vec![
                Ok("one_interface"),
                Ok("another_interface"),
                Ok("last_interface"),
            ])
            .open_subkey_with_flags_result(Ok(Box::new(one_interface)))
            .open_subkey_with_flags_result(Ok(Box::new(another_interface)))
            .open_subkey_with_flags_result(Ok(Box::new(last_interface)));
        let hive = RegKeyMock::default().open_subkey_with_flags_result(Ok(Box::new(interfaces)));
        let mut subject = WinDnsModifier::default();
        subject.hive = Box::new(hive);

        let result = subject.inspect();

        assert_eq!(result.err().unwrap(), "This system has 3 active network interfaces configured with 2 different default gateways. Cannot summarize DNS settings.".to_string());
    }

    #[test]
    fn inspect_complains_if_interfaces_have_different_dns_server_lists() {
        let one_interface = RegKeyMock::default()
            .get_value_result("DefaultGateway", Ok("1.2.3.4".to_string()))
            .get_value_result(
                "DhcpDefaultGateway",
                Err(Error::from_raw_os_error(NOT_FOUND)),
            )
            .get_value_result("NameServer", Ok("2.3.4.5,6.7.8.9".to_string()))
            .get_value_result("DhcpNameServer", Err(Error::from_raw_os_error(NOT_FOUND)));
        let another_interface = RegKeyMock::default()
            .get_value_result("DefaultGateway", Ok("1.2.3.4".to_string()))
            .get_value_result(
                "DhcpDefaultGateway",
                Err(Error::from_raw_os_error(NOT_FOUND)),
            )
            .get_value_result("NameServer", Ok("3.4.5.6,7.8.9.0".to_string()))
            .get_value_result("DhcpNameServer", Err(Error::from_raw_os_error(NOT_FOUND)));
        let interfaces = RegKeyMock::default()
            .enum_keys_result(vec![Ok("one_interface"), Ok("another_interface")])
            .open_subkey_with_flags_result(Ok(Box::new(one_interface)))
            .open_subkey_with_flags_result(Ok(Box::new(another_interface)));
        let hive = RegKeyMock::default().open_subkey_with_flags_result(Ok(Box::new(interfaces)));
        let ipconfig = IpconfigWrapperMock::new();
        let mut subject = WinDnsModifier::default();
        subject.hive = Box::new(hive);
        subject.ipconfig = Box::new(
            ipconfig
                .get_adapters_result(build_adapter_stubs(&[
                    ("one_interface", "Ethernet"),
                    ("another_interface", "Wifi"),
                ]))
                .get_adapters_result(build_adapter_stubs(&[
                    ("one_interface", "Ethernet"),
                    ("another_interface", "Wifi"),
                ])),
        );

        let result = subject.inspect();

        assert_eq!(result.err().unwrap(), "This system has 2 active network interfaces configured with 2 different DNS server lists. Cannot summarize DNS settings.".to_string());
    }

    #[test]
    fn inspect_works_if_everything_is_fine() {
        let one_active_interface = RegKeyMock::default()
            .get_value_result("DefaultGateway", Ok("Common Gateway IP".to_string()))
            .get_value_result(
                "DhcpDefaultGateway",
                Err(Error::from_raw_os_error(NOT_FOUND)),
            )
            .get_value_result("NameServer", Ok("8.8.8.8,8.8.8.9".to_string()))
            .get_value_result("DhcpNameServer", Ok("goober".to_string()));
        let another_active_interface = RegKeyMock::default()
            .get_value_result("DefaultGateway", Err(Error::from_raw_os_error(NOT_FOUND)))
            .get_value_result("DhcpDefaultGateway", Ok("Common Gateway IP".to_string()))
            .get_value_result("NameServer", Ok("8.8.8.8,8.8.8.9".to_string()))
            .get_value_result("DhcpNameServer", Ok("ignored".to_string()));
        let inactive_interface = RegKeyMock::default()
            .get_value_result("DefaultGateway", Err(Error::from_raw_os_error(NOT_FOUND)))
            .get_value_result(
                "DhcpDefaultGateway",
                Err(Error::from_raw_os_error(NOT_FOUND)),
            );
        let interfaces = RegKeyMock::default()
            .enum_keys_result(vec![
                Ok("one_active_interface"),
                Ok("another_active_interface"),
                Ok("inactive_interface"),
            ])
            .open_subkey_with_flags_result(Ok(Box::new(one_active_interface)))
            .open_subkey_with_flags_result(Ok(Box::new(another_active_interface)))
            .open_subkey_with_flags_result(Ok(Box::new(inactive_interface)));
        let hive = RegKeyMock::default().open_subkey_with_flags_result(Ok(Box::new(interfaces)));
        let mut subject = WinDnsModifier::default();
        subject.hive = Box::new(hive);
        let ipconfig = IpconfigWrapperMock::new();
        subject.ipconfig = Box::new(ipconfig.get_adapters_result(build_adapter_stubs(&[
            ("one_active_interface", "Ethernet"),
            ("another_active_interface", "Wifi"),
        ])));

        let result = subject.inspect();

        assert_eq!(result.unwrap(), vec![IpAddr::from_str("8.8.8.8").unwrap(),IpAddr::from_str("8.8.8.9").unwrap()]);
    }

    fn build_adapter_stubs(
        names: &[(&str, &str)],
    ) -> Result<Vec<Box<dyn AdapterWrapper>>, ipconfig::error::Error> {
        Ok(names
            .iter()
            .map(|(adapter_name, friendly_name)| {
                Box::new(AdapterWrapperStub {
                    adapter_name: adapter_name.to_string(),
                    friendly_name: friendly_name.to_string(),
                }) as Box<dyn AdapterWrapper>
            })
            .collect())
    }

    #[derive(Debug, Default)]
    struct RegKeyMock {
        path: String,
        enum_keys_results: RefCell<Vec<Vec<io::Result<String>>>>,
        open_subkey_with_flags_parameters: Arc<Mutex<Vec<(String, u32)>>>,
        open_subkey_with_flags_results: RefCell<Vec<io::Result<Box<dyn RegKeyTrait>>>>,
        get_value_parameters: Arc<Mutex<Vec<String>>>,
        get_value_results: RefCell<HashMap<String, Vec<io::Result<String>>>>,
        set_value_parameters: Arc<Mutex<Vec<(String, String)>>>,
        set_value_results: RefCell<HashMap<String, Vec<io::Result<()>>>>,
        delete_value_parameters: Arc<Mutex<Vec<String>>>,
        delete_value_results: RefCell<HashMap<String, Vec<io::Result<()>>>>,
    }

    impl RegKeyTrait for RegKeyMock {
        fn path(&self) -> &str {
            &self.path
        }

        fn enum_keys(&self) -> Vec<io::Result<String>> {
            self.enum_keys_results.borrow_mut().remove(0)
        }

        fn open_subkey_with_flags(
            &self,
            path: &str,
            perms: u32,
        ) -> io::Result<Box<dyn RegKeyTrait>> {
            self.open_subkey_with_flags_parameters
                .lock()
                .unwrap()
                .push((String::from(path), perms));
            self.open_subkey_with_flags_results.borrow_mut().remove(0)
        }

        fn get_value(&self, path: &str) -> io::Result<String> {
            self.get_value_parameters
                .lock()
                .unwrap()
                .push(String::from(path));
            self.get_result(&self.get_value_results, "get_value", path)
        }

        fn set_value(&self, path: &str, value: &str) -> io::Result<()> {
            self.set_value_parameters
                .lock()
                .unwrap()
                .push((String::from(path), String::from(value)));
            self.get_result(&self.set_value_results, "set_value", path)
        }

        fn delete_value(&self, path: &str) -> io::Result<()> {
            self.delete_value_parameters
                .lock()
                .unwrap()
                .push(String::from(path));
            self.get_result(&self.delete_value_results, "delete_value", path)
        }
    }

    impl RegKeyMock {
        pub fn new(path: &str) -> RegKeyMock {
            RegKeyMock {
                path: path.to_string(),
                enum_keys_results: RefCell::new(vec![]),
                open_subkey_with_flags_parameters: Arc::new(Mutex::new(vec![])),
                open_subkey_with_flags_results: RefCell::new(vec![]),
                get_value_parameters: Arc::new(Mutex::new(vec![])),
                get_value_results: RefCell::new(HashMap::new()),
                set_value_parameters: Arc::new(Mutex::new(vec![])),
                set_value_results: RefCell::new(HashMap::new()),
                delete_value_parameters: Arc::new(Mutex::new(vec![])),
                delete_value_results: RefCell::new(HashMap::new()),
            }
        }

        pub fn enum_keys_result(self, result: Vec<io::Result<&str>>) -> RegKeyMock {
            self.enum_keys_results.borrow_mut().push(
                result
                    .into_iter()
                    .map(|item| match item {
                        Err(e) => Err(e),
                        Ok(slice) => Ok(String::from(slice)),
                    })
                    .collect(),
            );
            self
        }

        pub fn open_subkey_with_flags_result(
            self,
            result: io::Result<Box<dyn RegKeyTrait>>,
        ) -> RegKeyMock {
            self.open_subkey_with_flags_results
                .borrow_mut()
                .push(result);
            self
        }

        pub fn get_value_result(self, name: &str, result: io::Result<String>) -> RegKeyMock {
            self.prepare_result(&self.get_value_results, name, result);
            self
        }

        fn prepare_result<T>(
            &self,
            results: &RefCell<HashMap<String, Vec<io::Result<T>>>>,
            name: &str,
            result: io::Result<T>,
        ) {
            let mut results_map = results.borrow_mut();
            let vec_exists = { results_map.contains_key(name) };
            if vec_exists {
                let mut results_opt = results_map.get_mut(name);
                let results_ref = results_opt.as_mut().unwrap();
                results_ref.push(result);
            } else {
                let results = vec![result];
                results_map.insert(String::from(name), results);
            }
        }

        fn get_result<T: Clone + Debug>(
            &self,
            results: &RefCell<HashMap<String, Vec<io::Result<T>>>>,
            method: &str,
            name: &str,
        ) -> io::Result<T> {
            let mut results_map = results.borrow_mut();
            let results_opt = results_map.get_mut(name);
            let results_ref = results_opt
                .expect(format!("No results prepared for {} ({})", method, name).as_str());
            if results_ref.len() > 1 {
                self.get_result_mutable(results_ref)
            } else {
                self.get_result_immutable(results_ref, method, name)
            }
        }

        fn get_result_immutable<T: Clone + Debug>(
            &self,
            results: &Vec<io::Result<T>>,
            method: &str,
            name: &str,
        ) -> io::Result<T> {
            if results.len() == 0 {
                panic!("No results prepared for {} ({})", method, name)
            };
            let result_ref = results.first().unwrap();
            match result_ref {
                &Ok(ref s) => Ok(s.clone()),
                &Err(ref e) if e.raw_os_error().is_some() => {
                    Err(Error::from_raw_os_error(e.raw_os_error().unwrap()))
                }
                &Err(ref e) => Err(Error::from(e.kind())),
            }
        }

        fn get_result_mutable<T: Clone + Debug>(
            &self,
            results: &mut Vec<io::Result<T>>,
        ) -> io::Result<T> {
            results.remove(0)
        }
    }
}
