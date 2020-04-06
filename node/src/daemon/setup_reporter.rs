// Copyright (c) 2019-2020, MASQ (https://masq.ai). All rights reserved.

use std::collections::{HashMap, HashSet};
use masq_lib::messages::{UiSetupResponseValue, UiSetupResponseValueStatus};
use masq_lib::messages::UiSetupResponseValueStatus::{Default, Set, Blank, Configured, Required};
use masq_lib::shared_schema::shared_app;
use crate::node_configurator::{app_head, RealDirsWrapper, DirsWrapper, determine_config_file_path};
use crate::node_configurator::node_configurator_standard::standard::{privileged_parse_args, unprivileged_parse_args, make_service_mode_multi_config};
use masq_lib::command::StdStreams;
use masq_lib::multi_config::{MultiConfig, CommandLineVcl, EnvironmentVcl, ConfigFileVcl};
use crate::bootstrapper::BootstrapperConfig;
use crate::database::db_initializer::{DbInitializerReal, DbInitializer};
use crate::persistent_configuration::{PersistentConfigurationReal, PersistentConfiguration};
use masq_lib::test_utils::fake_stream_holder::{ByteArrayReader, ByteArrayWriter};
use std::net::{IpAddr};
use crate::blockchain::blockchain_interface::chain_name_from_id;
use crate::sub_lib::neighborhood::{NodeDescriptor};
use crate::sub_lib::accountant::DEFAULT_EARNING_WALLET;
use itertools::Itertools;
use crate::test_utils::main_cryptde;
use std::collections::hash_map::RandomState;

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
    pub fn get_parameter_names() -> HashSet<String> {
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

    pub fn get_values (setup_params: &HashMap<String, UiSetupResponseValue>) -> HashMap<String, UiSetupResponseValue> {
        let mut args = setup_params.iter()
            .filter (|(_, value)| value.status == Set)
            .flat_map (|(_, value)| vec![format!("--{}", value.name), value.value.clone()])
            .collect::<Vec<String>>();
        args.insert (0, "program".to_string());
        let app = shared_app(app_head());
        let (config_file_path, user_specified) = determine_config_file_path(&app, &args);
        
        let configured_multi_config = {
            MultiConfig::new(
                &app,
                vec![
                    Box::new(EnvironmentVcl::new(&app)),
                    Box::new(ConfigFileVcl::new(&config_file_path, user_specified)),
                ],
            )
        };
        let setup_multi_config = {
            MultiConfig::new(
                &app,
                vec![
                    Box::new(CommandLineVcl::new(args.clone())),
                ],
            )
        };
        let mut streams = StdStreams{
            stdin: &mut ByteArrayReader::new(b""),
            stdout: &mut ByteArrayWriter::new(),
            stderr: &mut ByteArrayWriter::new(),
        };
        let mut bootstrap_config = BootstrapperConfig::new();
        privileged_parse_args (&setup_multi_config, &mut bootstrap_config, &mut streams);
        let initializer = DbInitializerReal::new();
        let path = &bootstrap_config.data_directory;
        let chain_id = bootstrap_config.blockchain_bridge_config.chain_id;
        let value_retrievers = retrievers();
        match initializer.initialize(path, chain_id, false) {
            Ok (conn) => {
                let persistent_config = PersistentConfigurationReal::from(conn);
                unprivileged_parse_args(&setup_multi_config, &mut bootstrap_config, &mut streams, Some (&persistent_config));
                Self::combine_values(value_retrievers, &setup_multi_config, &configured_multi_config, &bootstrap_config, Some (&persistent_config))
            },
            Err (_) => {
                unprivileged_parse_args(&setup_multi_config, &mut bootstrap_config, &mut streams, None);
                Self::combine_values(value_retrievers, &setup_multi_config, &configured_multi_config, &bootstrap_config, None)
            }
        }
    }
    
    fn combine_values (
        value_retrievers: Vec<Box<dyn ValueRetriever>>,
        setup_multi_config: &MultiConfig,
        configured_multi_config: &MultiConfig,
        bootstrap_config: &BootstrapperConfig,
        persistent_config_opt: Option<&dyn PersistentConfiguration>,
    ) -> HashMap<String, UiSetupResponseValue> {
        let mut result = Self::get_default_params();
        let db_password_opt = value_m!(setup_multi_config, "db-password", String);
        value_retrievers.iter().for_each(|retriever| {
            if let Some(value) = retriever.configured_value(bootstrap_config, persistent_config_opt, &db_password_opt) {
                result.insert (retriever.value_name().to_string(), UiSetupResponseValue::new (retriever.value_name(), &value, Configured));
            }
            if let Some(value) = value_m! (configured_multi_config, retriever.value_name(), String) {
                if let Some(existing_value) = result.get (retriever.value_name()) {
                    if value != existing_value.value {
                        result.insert(retriever.value_name().to_string(), UiSetupResponseValue::new(retriever.value_name(), &value, Set));
                    }
                }
                else {
                    result.insert(retriever.value_name().to_string(), UiSetupResponseValue::new(retriever.value_name(), &value, Configured));
                }
            }
            if let Some(value) = value_m! (setup_multi_config, retriever.value_name(), String) {
                if let Some(existing_value) = result.get (retriever.value_name()) {
                    if value != existing_value.value {
                        result.insert(retriever.value_name().to_string(), UiSetupResponseValue::new(retriever.value_name(), &value, Set));
                    }
                }
                else {
                    result.insert(retriever.value_name().to_string(), UiSetupResponseValue::new(retriever.value_name(), &value, Set));
                }
            }
        });
        let mut unencountered: HashMap<String, UiSetupResponseValue> = HashMap::new();
        value_retrievers.into_iter()
            .filter (|retriever| !result.contains_key (retriever.value_name()))
            .map (|retriever| {
                let is_required = retriever.is_required(&result);
                (retriever, is_required)
            })
            .for_each(|(retriever, is_required)| {
                let status = if is_required {
                    Required
                }
                else {
                    Blank
                };
                unencountered.insert (retriever.value_name().to_string(), UiSetupResponseValue::new (retriever.value_name(), "", status));
            });
        result.extend (unencountered);
        let permitted_keys = Self::get_parameter_names();
        result.into_iter().filter (|(key, _)| permitted_keys.contains (key)).collect()
    }

    // pub fn get_configured_values(params: &HashMap<String, UiSetupResponseValue>) -> HashMap<String, UiSetupResponseValue> {
    //     let mut args = params.iter()
    //         .filter (|(_, value)| value.status == Set)
    //         .flat_map (|(_, value)| vec![format!("--{}", value.name), value.value.clone()])
    //         .collect::<Vec<String>>();
    //     args.insert (0, "program".to_string());
    //     let app = shared_app(app_head());
    //
    //     let (config_file_path, user_specified) = determine_config_file_path(app, args);
    //     MultiConfig::new(
    //         &app,
    //         vec![
    //             Box::new(EnvironmentVcl::new(&app)),
    //             Box::new(ConfigFileVcl::new(&config_file_path, user_specified)),
    //         ],
    //     );
    //     // Box::new(CommandLineVcl::new(args.clone())),
    //
    //
    //     let multi_config = make_service_mode_multi_config(&app, &args);
    //     let mut streams = StdStreams{
    //         stdin: &mut ByteArrayReader::new(b""),
    //         stdout: &mut ByteArrayWriter::new(),
    //         stderr: &mut ByteArrayWriter::new(),
    //     };
    //     let mut config = BootstrapperConfig::new();
    //     privileged_parse_args (&multi_config, &mut config, &mut streams);
    //     let initializer = DbInitializerReal::new();
    //     let path = &config.data_directory;
    //     let chain_id = config.blockchain_bridge_config.chain_id;
    //     let mut past_neighbors_opt: Option<Vec<NodeDescriptor>> = None;
    //     let mut clandestine_port_opt: Option<u16> = None;
    //     let mut gas_price_opt: Option<u64> = None;
    //     match initializer.initialize(path, chain_id, false) {
    //         Ok (conn) => {
    //             let persistent_config = PersistentConfigurationReal::from(conn);
    //             if let Some(db_password) = params.get ("db-password") {
    //                 past_neighbors_opt = match persistent_config.past_neighbors(&db_password.value) {
    //                     Ok(pno) => pno,
    //                     Err(_) => None
    //                 };
    //             }
    //             clandestine_port_opt = Some (persistent_config.clandestine_port());
    //             gas_price_opt = Some (persistent_config.gas_price());
    //             unprivileged_parse_args(&multi_config, &mut config, &mut streams, Some (&persistent_config));
    //         },
    //         Err (_) => {
    //             unprivileged_parse_args(&multi_config, &mut config, &mut streams, None);
    //         }
    //     }
    //     let mut result = params.clone();
    //     match (result.get ("blockchain-service-url"), config.blockchain_bridge_config.blockchain_service_url) {
    //         (Some (bsu), _) => (),
    //         (None, Some (bsu)) => unimplemented!(), //set_param(&result, "blockchain-service-url", bsu, Set),
    //         (None, None) => Self::set_param(&mut result, "blockchain-service-url", "", Blank),
    //     }
    //     match (result.get ("clandestine-port"), clandestine_port_opt) {
    //         (Some (set), _) => (),
    //         (None, Some (persisted)) => Self::set_param(&mut result, "clandestine-port", &format!("{}", persisted), Configured),
    //         (None, None) => unimplemented!(), // Self::set_param(&mut result, "clandestine-port", "", Blank),
    //     }
    //     match result.get ("config-file") {
    //         Some (cf) => unimplemented!(), //(),
    //         None => Self::set_param(&mut result, "config-file", "", Blank),
    //     }
    //     match result.get ("consuming-private-key") {
    //         Some (cpk) => (),
    //         None => Self::set_param(&mut result, "consuming-private-key", "", Blank),
    //     }
    //     match (result.get ("data-directory"), config.data_directory, RealDirsWrapper{}.data_dir()) {
    //         (Some (dd), _, _) => (),
    //         (None, cdd, Some (dwdd)) if (cdd == dwdd) => unimplemented!(), //Self::set_param(&mut result, "data-directory", cdd.to_str().expect ("Illegal data directory"), Default),
    //         (None, cdd, _) => unimplemented!(), //Self::set_param(&mut result, "data-directory", cdd.to_str().expect ("Illegal data directory"), Configured),
    //     }
    //     match (result.get ("db-password"), config.db_password_opt) {
    //         (Some (dbpw), _) => (),
    //         (None, Some (dbpw)) => Self::set_param(&mut result, "db-password", &dbpw, Configured),
    //         (None, None) => unimplemented!(), //Self::set_param (&mut result, "db-password", "", Blank),
    //     }
    //     match (result.get("dns-servers"), config.dns_servers.iter().map(|sa| format!("{}", sa.ip())).collect_vec().join(",")) {
    //         (Some (dss), _) => unimplemented!(), //(),
    //         (None, dss) if dss == "1.1.1.1".to_string() => Self::set_param (&mut result, "dns-servers", &dss, Default),
    //         (None, dss) => Self::set_param (&mut result, "dns-servers", &dss, Configured),
    //     }
    //     match (result.get ("earning-wallet"), config.earning_wallet) {
    //         (Some (ew), _) => unimplemented!(), //(),
    //         (None, ew) if ew.address() == DEFAULT_EARNING_WALLET.address() => Self::set_param (&mut result, "earning-wallet", &ew.to_string(), Default),
    //         (None, ew) => Self::set_param (&mut result, "earning-wallet", &ew.to_string(), Configured)
    //     }
    //     match (result.get ("chain"), chain_id) {
    //         (Some (chain), _) => (),
    //         (None, chain_id) => Self::set_param(&mut result, "chain", chain_name_from_id(chain_id), Default),
    //     }
    //     match (result.get ("gas-price"), gas_price_opt) {
    //         (Some (gp), _) => unimplemented!(), //(),
    //         (None, Some(gp)) => Self::set_param(&mut result, "gas-price", &format!("{}", gp), Configured),
    //         (None, None) => unimplemented!(), //Self::set_param(&mut result, "gas-price", "", Blank),
    //     }
    //     match (result.get ("ip"), &config.neighborhood_config.mode) {
    //         (Some (ip), _) => (),
    //         (None, crate::sub_lib::neighborhood::NeighborhoodMode::Standard (node_addr, _, _)) => unimplemented!(), //may be impossible until auto IP detection
    //         (None, _) => unimplemented!(), //Self::set_param(&mut result, "ip", "", Required),
    //     }
    //     match (result.get ("log-level"), config.log_level) {
    //         (Some (level), _) => (),
    //         (None, level) => unimplemented!(), //Self::set_param(&mut result, "log-level", &Self::enum_to_value(level.to_string()), Configured),
    //     }
    //     match (result.get ("neighborhood-mode"), &config.neighborhood_config.mode) {
    //         (Some (mode), _) => (),
    //         (None, mode) => unimplemented!(), //Self::set_param(&mut result, "neighborhood-mode", &Self::enum_to_value(format!("{}", mode)), Configured)
    //     }
    //     match (result.get ("neighbors"), past_neighbors_opt) {
    //         (Some (pn), _) => unimplemented!(), //(),
    //         (None, Some (pn)) => Self::set_param(&mut result, "neighbors", &Self::node_descriptors_to_neighbors (pn), Configured),
    //         (None, None) => Self::set_param(&mut result, "neighbors", "", Blank),
    //     }
    //     #[cfg(not(target_os = "windows"))]
    //     match (result.get ("real-user"), config.real_user) {
    //         (Some (ru), _) => (),
    //         (None, ru) => Self::set_param(&mut result, "real-user", &ru.to_string(), Configured),
    //     }
    //     result
    // }

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

}

trait ValueRetriever {
    fn value_name(&self) -> &'static str;

    fn configured_value(&self,
        bootstrapper_config: &BootstrapperConfig,
        persistent_config_opt: Option<&dyn PersistentConfiguration>,
        db_password_opt: &Option<String>,
    ) -> Option<String> {
        None
    }

    fn set_value(&self, multi_config: &MultiConfig) -> Option<String> {
        value_m! (multi_config, self.value_name(), String)
    }

    fn is_required(&self, _params: &HashMap<String, UiSetupResponseValue>) -> bool {
        false
    }
}

struct BlockchainBridgeUrl {}
impl ValueRetriever for BlockchainBridgeUrl {
    fn value_name(&self) -> &'static str {
        "blockchain-service-url"
    }
}

struct Chain {}
impl ValueRetriever for Chain {
    fn value_name(&self) -> &'static str {
        "chain"
    }
}

struct ClandestinePort {}
impl ValueRetriever for ClandestinePort {
    fn value_name(&self) -> &'static str {
        "clandestine-port"
    }

    fn configured_value(&self, _bootstrapper_config: &BootstrapperConfig, persistent_config_opt: Option<&dyn PersistentConfiguration>, db_password_opt: &Option<String>) -> Option<String> {
        persistent_config_opt.map (|pc| pc.clandestine_port().to_string())
    }
}

struct ConfigFile {}
impl ValueRetriever for ConfigFile {
    fn value_name(&self) -> &'static str {
        "config-file"
    }
}

struct ConsumingPrivateKey {}
impl ValueRetriever for ConsumingPrivateKey {
    fn value_name(&self) -> &'static str {
        "consuming-private-key"
    }
}

struct DataDirectory {}
impl ValueRetriever for DataDirectory {
    fn value_name(&self) -> &'static str {
        "data-directory"
    }
}

struct DbPassword {}
impl ValueRetriever for DbPassword {
    fn value_name(&self) -> &'static str {
        "db-password"
    }
}

struct DnsServers {}
impl ValueRetriever for DnsServers {
    fn value_name(&self) -> &'static str {
        "dns-servers"
    }

    fn is_required(&self, _params: &HashMap<String, UiSetupResponseValue>) -> bool {
        true
    }
}

struct EarningWallet {}
impl ValueRetriever for EarningWallet {
    fn value_name(&self) -> &'static str {
        "earning-wallet"
    }

    fn configured_value(&self, bootstrapper_config: &BootstrapperConfig, persistent_config_opt: Option<&dyn PersistentConfiguration>, db_password_opt: &Option<String>) -> Option<String> {
        Some(bootstrapper_config.earning_wallet.to_string())
    }
}

struct GasPrice {}
impl ValueRetriever for GasPrice {
    fn value_name(&self) -> &'static str {
        "gas-price"
    }

    fn configured_value(&self, bootstrapper_config: &BootstrapperConfig, persistent_config_opt: Option<&dyn PersistentConfiguration>, db_password_opt: &Option<String>) -> Option<String> {
        persistent_config_opt.map(|pc| pc.gas_price().to_string())
    }
}

struct Ip {}
impl ValueRetriever for Ip {
    fn value_name(&self) -> &'static str {
        "ip"
    }

    fn is_required(&self, params: &HashMap<String, UiSetupResponseValue>) -> bool {
        // TODO SPIKE
        match params.get ("neighborhood-mode") {
            Some (nhm) => !"|zero-hop|consume-only|".contains (&format!("|{}|", nhm.value)),
            None => true
        }
        // TODO SPIKE
    }
}

struct LogLevel {}
impl ValueRetriever for LogLevel {
    fn value_name(&self) -> &'static str {
        "log-level"
    }
}

struct NeighborhoodMode {}
impl ValueRetriever for NeighborhoodMode {
    fn value_name(&self) -> &'static str {
        "neighborhood-mode"
    }
}

fn node_descriptors_to_neighbors (node_descriptors: Vec<NodeDescriptor>) -> String {
    node_descriptors.into_iter()
        .map (|nd| nd.to_string (main_cryptde()))
        .collect_vec()
        .join (",")
}

struct Neighbors {}
impl ValueRetriever for Neighbors {
    fn value_name(&self) -> &'static str {
        "neighbors"
    }

    fn configured_value(&self, bootstrapper_config: &BootstrapperConfig, persistent_config_opt: Option<&dyn PersistentConfiguration>, db_password_opt: &Option<String>) -> Option<String> {
        match (persistent_config_opt, db_password_opt) {
            (Some(pc), Some(pw)) => match pc.past_neighbors(&pw) {
                Ok(Some(pns)) => Some (node_descriptors_to_neighbors(pns)),
                _ => None
            },
            _ => None
        }
    }
}

struct RealUser {}
impl ValueRetriever for RealUser {
    fn value_name(&self) -> &'static str {
        "real-user"
    }

    fn configured_value(&self, bootstrapper_config: &BootstrapperConfig, persistent_config_opt: Option<&dyn PersistentConfiguration>, db_password_opt: &Option<String>) -> Option<String> {
        #[cfg(target_os = "windows")]
        {
            None
        }
        #[cfg(not(target_os = "windows"))]
        {
            Some(crate::bootstrapper::RealUser::default().populate().to_string())
        }
    }
}

fn retrievers () -> Vec<Box<dyn ValueRetriever>> {
    vec![
        Box::new (BlockchainBridgeUrl{}),
        Box::new (Chain{}),
        Box::new (ClandestinePort{}),
        Box::new (ConfigFile{}),
        Box::new (ConsumingPrivateKey{}),
        Box::new (DataDirectory{}),
        Box::new (DbPassword{}),
        Box::new (DnsServers{}),
        Box::new (EarningWallet{}),
        Box::new (GasPrice{}),
        Box::new (Ip{}),
        Box::new (LogLevel{}),
        Box::new (NeighborhoodMode{}),
        Box::new (Neighbors{}),
        Box::new (RealUser{}),
    ]
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
    use std::fs::File;
    use std::io::Write;

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
    fn get_configured_values_database_populated_only_requireds_set() {
        let home_dir = ensure_node_home_directory_exists("setup_reporter", "get_configured_values_database_populated_only_requireds_set");
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
        ].into_iter()
            .map (|(name, value, status)| (name.to_string(), UiSetupResponseValue::new(name, value, status)))
            .collect::<HashMap<String, UiSetupResponseValue>>();

        let result = SetupReporterReal::get_values (&params);

        let expected_result = vec![
            ("blockchain-service-url", "", Blank),
            ("chain", "mainnet", Default),
            ("clandestine-port", "1234", Configured),
            ("config-file", "config.toml", Default),
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
            ("real-user", &RealUser::default().populate().to_string(), Configured),
        ].into_iter()
            .map (|(name, value, status)| (name.to_string(), UiSetupResponseValue::new(name, value, status)))
            .collect_vec();
        let presentable_result = result.into_iter()
            .sorted_by_key (|(k, _)| k.clone())
            .collect_vec();
        assert_eq! (presentable_result, expected_result);
    }

    #[test]
    fn get_configured_values_database_nonexistent_everything_set() {
        let home_dir = ensure_node_home_directory_exists("setup_reporter", "get_configured_values_database_nonexistent_everything_set");
        let params = vec![
            ("blockchain-service-url", "https://example.com", Set),
            ("chain", "ropsten", Set),
            ("clandestine-port", "1234", Set),
            ("consuming-private-key", "0011223344556677001122334455667700112233445566770011223344556677", Set),
            ("data-directory", home_dir.to_str().unwrap(), Set),
            ("db-password", "password", Set),
            ("dns-servers", "8.8.8.8", Set),
            ("earning-wallet", "0x0123456789012345678901234567890123456789", Set),
            ("gas-price", "50", Set),
            ("ip", "4.3.2.1", Set),
            ("log-level", "error", Set),
            ("neighborhood-mode", "originate-only", Set),
            ("neighbors", "MTIzNDU2Nzg5MTEyMzQ1Njc4OTIxMjM0NTY3ODkzMTI@1.2.3.4:1234,MTIzNDU2Nzg5MTEyMzQ1Njc4OTIxMjM0NTY3ODkzMTI@5.6.7.8:5678", Set),
            #[cfg(not(target_os = "windows"))]
            ("real-user", "9999:9999:booga", Set),
        ].into_iter()
            .map (|(name, value, status)| (name.to_string(), UiSetupResponseValue::new(name, value, status)))
            .collect::<HashMap<String, UiSetupResponseValue>>();

        let result = SetupReporterReal::get_values (&params);

        let expected_result = vec![
            ("blockchain-service-url", "https://example.com", Set),
            ("chain", "ropsten", Set),
            ("clandestine-port", "1234", Set),
            ("config-file", "config.toml", Default),
            ("consuming-private-key", "0011223344556677001122334455667700112233445566770011223344556677", Set),
            ("data-directory", home_dir.to_str().unwrap(), Set),
            ("db-password", "password", Set),
            ("dns-servers", "8.8.8.8", Set),
            ("earning-wallet", "0x0123456789012345678901234567890123456789", Set),
            ("gas-price", "50", Set),
            ("ip", "4.3.2.1", Set),
            ("log-level", "error", Set),
            ("neighborhood-mode", "originate-only", Set),
            ("neighbors", "MTIzNDU2Nzg5MTEyMzQ1Njc4OTIxMjM0NTY3ODkzMTI@1.2.3.4:1234,MTIzNDU2Nzg5MTEyMzQ1Njc4OTIxMjM0NTY3ODkzMTI@5.6.7.8:5678", Set),
            #[cfg(not(target_os = "windows"))]
            ("real-user", "9999:9999:booga", Set),
        ].into_iter()
            .map (|(name, value, status)| (name.to_string(), UiSetupResponseValue::new(name, value, status)))
            .collect_vec();
        let presentable_result = result.into_iter()
            .sorted_by_key (|(k, _)| k.clone())
            .collect_vec();
        assert_eq! (presentable_result, expected_result);
    }
}