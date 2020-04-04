// Copyright (c) 2019-2020, MASQ (https://masq.ai). All rights reserved.

use std::collections::HashMap;
use masq_lib::messages::{UiSetupResponseValue, UiSetupResponseValueStatus};
use masq_lib::messages::UiSetupResponseValueStatus::{Default, Set, Blank, Configured, Required};
use masq_lib::shared_schema::shared_app;
use crate::node_configurator::{app_head, RealDirsWrapper, DirsWrapper};
use crate::node_configurator::node_configurator_standard::standard::{privileged_parse_args, unprivileged_parse_args};
use masq_lib::command::StdStreams;
use masq_lib::multi_config::{MultiConfig, CommandLineVcl};
use crate::bootstrapper::BootstrapperConfig;
use crate::database::db_initializer::{DbInitializerReal, DbInitializer};
use crate::persistent_configuration::{PersistentConfigurationReal, PersistentConfiguration};
use masq_lib::test_utils::fake_stream_holder::{ByteArrayReader, ByteArrayWriter};
use std::net::{IpAddr};
use crate::blockchain::blockchain_interface::chain_name_from_id;
use crate::sub_lib::neighborhood::{NeighborhoodMode, NodeDescriptor};
use crate::sub_lib::accountant::DEFAULT_EARNING_WALLET;
use itertools::Itertools;
use crate::test_utils::main_cryptde;

pub trait SetupReporter {
    fn get_modified_setup (&self, existing_setup: &HashMap<String, UiSetupResponseValue>, incoming_setup: Vec<UiSetupResponseValue>) -> HashMap<String, UiSetupResponseValue>;
}

pub struct SetupReporterReal {

}

impl SetupReporter for SetupReporterReal {
    fn get_modified_setup(&self, existing_setup: &HashMap<String, UiSetupResponseValue>, incoming_setup: Vec<UiSetupResponseValue>) -> HashMap<String, UiSetupResponseValue> {
        // get all parameter names
        // get default values
        // get configured values
        // get get incoming setup
        // combine well in large bowl
        unimplemented!()
    }
}

impl SetupReporterReal {
    pub fn get_parameter_names() -> Vec<String> {
        let schema = shared_app(app_head());
        schema
            .p
            .opts
            .iter()
            .flat_map(|opt| {
                let name = opt.b.name;
                let delimited = format!("|{}|", name);
                if "|ui-port|crash-point|fake-public-key|".contains (&delimited) {
                    return None;
                }
                #[cfg(target_os = "windows")]
                    {
                        if name == "real-user" {
                            return None;
                        }
                    }
                Some(name.to_string())
            })
            .collect()
    }

    pub fn get_default_params() -> HashMap<String, UiSetupResponseValue> {
        let schema = shared_app(app_head());
        schema
            .p
            .opts
            .iter()
            .flat_map(|opt| {
                let name = opt.b.name;
                match opt.v.default_val {
                    Some(os_str) => {
                        let value = match os_str.to_str() {
                            Some(v) => v,
                            None => unimplemented!(),
                        };
                        Some((name.to_string(), UiSetupResponseValue::new (name, value, Default)))
                    },
                    None => None,
                }
            })
            .collect()
    }

    pub fn get_configured_values(params: &HashMap<String, UiSetupResponseValue>) -> HashMap<String, UiSetupResponseValue> {
        let mut args = params.iter()
            .filter (|(_, value)| value.status == Set)
            .flat_map (|(_, value)| vec![format!("--{}", value.name), value.value.clone()])
            .collect::<Vec<String>>();
        args.insert (0, "program".to_string());
        let vcl = CommandLineVcl::new (args);
        let multi_config = MultiConfig::new(&shared_app(app_head()), vec![Box::new(vcl)]);
        let mut streams = StdStreams{
            stdin: &mut ByteArrayReader::new(b""),
            stdout: &mut ByteArrayWriter::new(),
            stderr: &mut ByteArrayWriter::new(),
        };
        let mut config = BootstrapperConfig::new();
        privileged_parse_args (&multi_config, &mut config, &mut streams);
        let initializer = DbInitializerReal::new();
        let path = &config.data_directory;
        let chain_id = config.blockchain_bridge_config.chain_id;
        let mut past_neighbors_opt: Option<Vec<NodeDescriptor>> = None;
        let mut clandestine_port_opt: Option<u16> = None;
        let mut gas_price_opt: Option<u64> = None;
        match initializer.initialize(path, chain_id, false) {
            Ok (conn) => {
                let persistent_config = PersistentConfigurationReal::from(conn);
                if let Some(db_password) = params.get ("db-password") {
                    past_neighbors_opt = match persistent_config.past_neighbors(&db_password.value) {
                        Ok(pno) => pno,
                        Err(_) => None
                    };
                }
                clandestine_port_opt = Some (persistent_config.clandestine_port());
                gas_price_opt = Some (persistent_config.gas_price());
                unprivileged_parse_args(&multi_config, &mut config, &mut streams, Some (&persistent_config));
            },
            Err (_) => {
                unprivileged_parse_args(&multi_config, &mut config, &mut streams, None);
            }
        }
        let mut result = params.clone();
        match (result.get ("blockchain-service-url"), config.blockchain_bridge_config.blockchain_service_url) {
            (Some (bsu), _) => unimplemented!(), //(),
            (None, Some (bsu)) => unimplemented!(), //set_param(&result, "blockchain-service-url", bsu, Set),
            (None, None) => Self::set_param(&mut result, "blockchain-service-url", "", Blank),
        }
        match (result.get ("clandestine-port"), clandestine_port_opt) {
            (Some (set), _) => unimplemented!(), //(),
            (None, Some (persisted)) => Self::set_param(&mut result, "clandestine-port", &format!("{}", persisted), Configured),
            (None, None) => unimplemented!(), // Self::set_param(&mut result, "clandestine-port", "", Blank),
        }
        match result.get ("config-file") {
            Some (cf) => unimplemented!(), //(),
            None => Self::set_param(&mut result, "config-file", "", Blank),
        }
        match result.get ("consuming-private-key") {
            Some (cpk) => unimplemented!(), //(),
            None => Self::set_param(&mut result, "consuming-private-key", "", Blank),
        }
        match (result.get ("data-directory"), config.data_directory, RealDirsWrapper{}.data_dir()) {
            (Some (dd), _, _) => (),
            (None, cdd, Some (dwdd)) if (cdd == dwdd) => unimplemented!(), //Self::set_param(&mut result, "data-directory", cdd.to_str().expect ("Illegal data directory"), Default),
            (None, cdd, _) => unimplemented!(), //Self::set_param(&mut result, "data-directory", cdd.to_str().expect ("Illegal data directory"), Configured),
        }
        match (result.get ("db-password"), config.db_password_opt) {
            (Some (dbpw), _) => (),
            (None, Some (dbpw)) => unimplemented!(), // Self::set_param(&mut result, "db-password", &dbpw, Configured), // may be impossible
            (None, None) => unimplemented!(), //Self::set_param (&mut result, "db-password", "", Blank),
        }
        match (result.get("dns-servers"), config.dns_servers.iter().map(|sa| format!("{}", sa.ip())).collect_vec().join(",")) {
            (Some (dss), _) => unimplemented!(), //(),
            (None, dss) if dss == "1.1.1.1".to_string() => Self::set_param (&mut result, "dns-servers", &dss, Default),
            (None, dss) => unimplemented!(), //Self::set_param (&mut result, "dns-servers", &dss, Configured),
        }
        match (result.get ("earning-wallet"), config.earning_wallet) {
            (Some (ew), _) => unimplemented!(), //(),
            (None, ew) if ew.address() == DEFAULT_EARNING_WALLET.address() => unimplemented!(), //Self::set_param (&mut result, "earning-wallet", &ewa.to_string(), Default),
            (None, ew) => Self::set_param (&mut result, "earning-wallet", &ew.to_string(), Configured)
        }
        match (result.get ("chain"), chain_id) {
            (Some (chain), _) => unimplemented!(), //(),
            (None, chain_id) => Self::set_param(&mut result, "chain", chain_name_from_id(chain_id), Default),
        }
        match (result.get ("gas-price"), gas_price_opt) {
            (Some (gp), _) => unimplemented!(), //(),
            (None, Some(gp)) => Self::set_param(&mut result, "gas-price", &format!("{}", gp), Configured),
            (None, None) => unimplemented!(), //Self::set_param(&mut result, "gas-price", "", Blank),
        }
        match (result.get ("ip"), &config.neighborhood_config.mode) {
            (Some (ip), _) => (),
            (None, NeighborhoodMode::Standard (node_addr, _, _)) => unimplemented!(), //may be impossible
            (None, _) => unimplemented!(), //Self::set_param(&mut result, "ip", "", Required),
        }
        match (result.get ("log-level"), config.log_level) {
            (Some (level), _) => (),
            (None, level) => unimplemented!(), //Self::set_param(&mut result, "log-level", &Self::enum_to_value(level.to_string()), Configured),
        }
        match (result.get ("neighborhood-mode"), &config.neighborhood_config.mode) {
            (Some (mode), _) => (),
            (None, mode) => unimplemented!(), //Self::set_param(&mut result, "neighborhood-mode", &Self::enum_to_value(format!("{}", mode)), Configured)
        }
        match (result.get ("neighbors"), past_neighbors_opt) {
            (Some (pn), _) => unimplemented!(), //(),
            (None, Some (pn)) => Self::set_param(&mut result, "neighbors", &Self::node_descriptors_to_neighbors (pn), Configured),
            (None, None) => unimplemented!(), //Self::set_param(&mut result, "neighbors", "", Blank),
        }
        #[cfg(not(target_os = "windows"))]
        match (result.get ("real-user"), config.real_user) {
            (Some (ru), _) => (),
            (None, ru) => unimplemented!(), //Self::set_param(&mut result, "real-user", &ru.to_string(), Configured),
        }
        result
    }

    fn set_param(params: &mut HashMap<String, UiSetupResponseValue>, name: &str, value: &str, status: UiSetupResponseValueStatus) {
        params.insert (name.to_string(), UiSetupResponseValue::new (name, value, status));
    }

    fn enum_to_value (enum_string: String) -> String {
        let mut result = String::new();
        let chars = enum_string.chars().collect_vec();
        for idx in 1..chars.len() {
            let c1 = chars[idx - 1];
            let c2 = chars[idx];
            if c1.is_lowercase() && c2.is_uppercase() {
                result.push (c1);
                result.push ('-');
            }
            else {
                result.push (c1)
            }
        }
        result.push(chars[chars.len() - 1]);
        result.to_lowercase()
    }

    fn node_descriptors_to_neighbors (node_descriptors: Vec<NodeDescriptor>) -> String {
        node_descriptors.into_iter()
            .map (|nd| nd.to_string (main_cryptde()))
            .collect_vec()
            .join (",")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use masq_lib::test_utils::utils::ensure_node_home_directory_exists;
    use masq_lib::messages::UiSetupResponseValueStatus::{Set, Blank, Configured, Required};
    use crate::database::db_initializer::{DbInitializer, DbInitializerReal};
    use crate::persistent_configuration::{PersistentConfigurationReal, PersistentConfiguration};
    use crate::blockchain::blockchain_interface::chain_id_from_name;
    use crate::sub_lib::cryptde::{PublicKey};
    use crate::bootstrapper::RealUser;
    use std::default::Default;
    use crate::sub_lib::node_addr::NodeAddr;
    use std::str::FromStr;

    #[test]
    fn parameter_names_include_some_classic_ones() {
        let result = SetupReporterReal::get_parameter_names();

        assert_eq! (result.contains (&"dns-servers".to_string()), true, "{:?}", result);
        assert_eq! (result.contains (&"ip".to_string()), true, "{:?}", result);
        assert_eq! (result.contains (&"log-level".to_string()), true, "{:?}", result);
        assert_eq! (result.contains (&"dns-servers".to_string()), true, "{:?}", result);
    }

    #[test]
    fn parameter_names_doesnt_include_censored_values() {
        let result = SetupReporterReal::get_parameter_names();

        assert_eq!(result.contains(&"ui-port".to_string()), false, "{:?}", result);
        assert_eq!(result.contains(&"fake-public-key".to_string()), false, "{:?}", result);
        assert_eq!(result.contains(&"crash-point".to_string()), false, "{:?}", result);
        #[cfg(target_os = "windows")]
        assert_eq!(result.contains(&"real-user".to_string()), false, "{:?}", result);
    }

    #[test]
    fn everything_in_defaults_is_properly_constructed() {
        let result = SetupReporterReal::get_default_params();

        assert_eq! (result.is_empty(), false, "{:?}", result); // if we don't have any defaults, let's get rid of all this
        result.into_iter().for_each (|(name, value)| {
            assert_eq! (name, value.name);
            assert_eq! (value.status, Default);
        });
    }

    #[test]
    fn some_items_are_censored_from_defaults() {
        let result = SetupReporterReal::get_default_params();

        assert_eq!(result.get("ui-port"), None, "{:?}", result);
        #[cfg(target_os = "windows")]
        assert_eq!(result.get("real-user"), None, "{:?}", result);
    }

    #[test]
    fn get_configured_values() {
        let home_dir = ensure_node_home_directory_exists("setup_reporter", "get_configured_values");
        let db_initializer = DbInitializerReal::new ();
        let conn = db_initializer.initialize (&home_dir, chain_id_from_name("mainnet"), true).unwrap();
        let config = PersistentConfigurationReal::from (conn);
        config.set_password ("password");
        config.set_clandestine_port (1234);
        config.set_mnemonic_seed (b"booga booga", "password");
        config.set_consuming_wallet_derivation_path("m/44'/60'/1'/2/3", "password");
        config.set_earning_wallet_address("0x0000000000000000000000000000000000000000");
        config.set_gas_price (1234567890);
        let neighbor1 = NodeDescriptor{
            encryption_public_key: PublicKey::new(b"ABCD"),
            mainnet: true,
            node_addr_opt: Some (NodeAddr::new (&IpAddr::from_str("1.2.3.4").unwrap(), &vec![1234]))
        };
        let neighbor2 = NodeDescriptor{
            encryption_public_key: PublicKey::new(b"EFGH"),
            mainnet: true,
            node_addr_opt: Some (NodeAddr::new (&IpAddr::from_str("5.6.7.8").unwrap(), &vec![5678]))
        };
        config.set_past_neighbors(Some(vec![neighbor1, neighbor2]), "password");

        let params = vec![
            ("data-directory", home_dir.to_str().unwrap(), Set),
            ("db-password", "password", Set),
            ("ip", "4.3.2.1", Set),
            ("log-level", "warn", Default),
            ("neighborhood-mode", "standard", Default),
            #[cfg(not(target_os = "windows"))]
            ("real-user", &RealUser::default().populate().to_string(), Default),
        ].into_iter()
            .map (|(name, value, status)| (name.to_string(), UiSetupResponseValue::new(name, value, status)))
            .collect::<HashMap<String, UiSetupResponseValue>>();

        let result = SetupReporterReal::get_configured_values (&params);

        let expected_result = vec![
            ("blockchain-service-url", "", Blank),
            ("chain", "mainnet", Default),
            ("clandestine-port", "1234", Configured),
            ("config-file", "", Blank),
            ("consuming-private-key", "", Blank),
            ("data-directory", home_dir.to_str().unwrap(), Set),
            ("db-password", "password", Set),
            ("dns-servers", "1.1.1.1", Default),
            ("earning-wallet", "0x0000000000000000000000000000000000000000", Configured),
            ("gas-price", "1234567890", Configured),
            ("ip", "4.3.2.1", Set),
            ("log-level", "warn", Default),
            ("neighborhood-mode", "standard", Default),
            ("neighbors", "QUJDRA@1.2.3.4:1234,RUZHSA@5.6.7.8:5678", Configured),
            #[cfg(not(target_os = "windows"))]
            ("real-user", &RealUser::default().populate().to_string(), Default),
        ].into_iter()
            .map (|(name, value, status)| (name.to_string(), UiSetupResponseValue::new(name, value, status)))
            .collect_vec();
        let presentable_result = result.into_iter()
            .sorted_by_key (|(k, _)| k.clone())
            .collect_vec();
        assert_eq! (presentable_result, expected_result);
    }
}