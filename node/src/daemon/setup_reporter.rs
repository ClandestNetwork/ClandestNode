// Copyright (c) 2019-2020, MASQ (https://masq.ai). All rights reserved.

use crate::blockchain::blockchain_interface::chain_name_from_id;
use crate::bootstrapper::BootstrapperConfig;
use crate::database::db_initializer::{DbInitializer, DbInitializerReal};
use crate::node_configurator::node_configurator_standard::standard::{
    privileged_parse_args, unprivileged_parse_args,
};
use crate::node_configurator::{app_head, data_directory_from_context, determine_config_file_path};
use crate::persistent_configuration::{PersistentConfiguration, PersistentConfigurationReal};
use crate::sub_lib::neighborhood::NodeDescriptor;
use crate::test_utils::main_cryptde;
use clap::value_t;
use itertools::Itertools;
use masq_lib::command::StdStreams;
use masq_lib::constants::DEFAULT_CHAIN_NAME;
use masq_lib::messages::UiSetupResponseValueStatus::{Blank, Configured, Default, Required, Set};
use masq_lib::messages::{UiSetupRequestValue, UiSetupResponseValue};
use masq_lib::multi_config::{CommandLineVcl, ConfigFileVcl, EnvironmentVcl, MultiConfig};
use masq_lib::shared_schema::shared_app;
use masq_lib::test_utils::fake_stream_holder::{ByteArrayReader, ByteArrayWriter};
use std::collections::{HashMap, HashSet};

pub type SetupCluster = HashMap<String, UiSetupResponseValue>;

pub trait SetupReporter {
    fn get_modified_setup(
        &self,
        existing_setup: SetupCluster,
        incoming_setup: Vec<UiSetupRequestValue>,
    ) -> SetupCluster;
}

pub struct SetupReporterReal {}

impl SetupReporter for SetupReporterReal {
    fn get_modified_setup(
        &self,
        existing_setup: SetupCluster,
        incoming_setup: Vec<UiSetupRequestValue>,
    ) -> SetupCluster {
        let to_clear_out = incoming_setup
            .iter()
            .filter(|p| p.value.is_none())
            .map(|p| p.name.clone())
            .collect::<HashSet<String>>();
        let incoming_setup_translated = incoming_setup
            .iter()
            .flat_map(|uisrv| match &uisrv.value {
                None => None,
                Some(value) => Some((
                    uisrv.name.to_string(),
                    UiSetupResponseValue::new(&uisrv.name, value, Set),
                )),
            })
            .collect::<SetupCluster>();
        let mut existing_and_incoming = existing_setup
            .iter()
            .flat_map(|(k, v)| match v.status {
                Blank => None,
                Required => None,
                _ => Some((k.clone(), v.clone())),
            })
            .collect::<SetupCluster>();
        existing_and_incoming.extend(incoming_setup_translated.clone());
        let required_and_available_value_names = value_retrievers()
            .into_iter()
            .filter(|vr| vr.is_required(&existing_and_incoming))
            .filter(|vr| existing_and_incoming.contains_key(vr.value_name()))
            .map(|vr| vr.value_name())
            .collect_vec();
        let mut incoming_setup_plus_available_required = required_and_available_value_names
            .into_iter()
            .flat_map(|name| match existing_and_incoming.get(name) {
                None => None,
                Some(uisrv) => Some((name.to_string(), uisrv.clone())),
            })
            .collect::<SetupCluster>();
        incoming_setup_plus_available_required.extend(incoming_setup_translated);
        let mut combined_args = incoming_setup_plus_available_required
            .into_iter()
            .flat_map(|(_, uisrv)| vec![format!("--{}", uisrv.name), uisrv.value])
            .collect_vec();
        combined_args.insert(0, "program".to_string());
        let app = shared_app(app_head());
        let (config_file_path, user_specified) = determine_config_file_path(&app, &combined_args);

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
                vec![Box::new(CommandLineVcl::new(combined_args.clone()))],
            )
        };
        let combined_multi_config = {
            MultiConfig::new(
                &app,
                vec![
                    Box::new(CommandLineVcl::new(combined_args)),
                    Box::new(EnvironmentVcl::new(&app)),
                    Box::new(ConfigFileVcl::new(&config_file_path, user_specified)),
                ],
            )
        };
        let mut streams = StdStreams {
            stdin: &mut ByteArrayReader::new(b""),
            stdout: &mut ByteArrayWriter::new(),
            stderr: &mut ByteArrayWriter::new(),
        };
        let mut bootstrap_config = BootstrapperConfig::new();
        privileged_parse_args(&combined_multi_config, &mut bootstrap_config, &mut streams);
        let initializer = DbInitializerReal::new();
        let path = &bootstrap_config.data_directory;
        let chain_id = bootstrap_config.blockchain_bridge_config.chain_id;
        let value_retrievers = value_retrievers();
        match initializer.initialize(path, chain_id, false) {
            Ok(conn) => {
                let persistent_config = PersistentConfigurationReal::from(conn);
                unprivileged_parse_args(
                    &combined_multi_config,
                    &mut bootstrap_config,
                    &mut streams,
                    Some(&persistent_config),
                );
                Self::combine_values(
                    existing_setup,
                    value_retrievers,
                    &setup_multi_config,
                    &configured_multi_config,
                    &bootstrap_config,
                    Some(&persistent_config),
                    to_clear_out,
                )
            }
            Err(_) => {
                unprivileged_parse_args(
                    &combined_multi_config,
                    &mut bootstrap_config,
                    &mut streams,
                    None,
                );
                Self::combine_values(
                    existing_setup,
                    value_retrievers,
                    &setup_multi_config,
                    &configured_multi_config,
                    &bootstrap_config,
                    None,
                    to_clear_out,
                )
            }
        }
    }
}

impl SetupReporterReal {
    pub fn new() -> Self {
        Self {}
    }

    pub fn get_default_params() -> SetupCluster {
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
                        Some((
                            name.to_string(),
                            UiSetupResponseValue::new(name, value, Default),
                        ))
                    }
                    None => None,
                }
            })
            .collect()
    }

    fn combine_values(
        existing_setup: SetupCluster,
        value_retrievers: Vec<Box<dyn ValueRetriever>>,
        setup_multi_config: &MultiConfig,
        configured_multi_config: &MultiConfig,
        bootstrap_config: &BootstrapperConfig,
        persistent_config_opt: Option<&dyn PersistentConfiguration>,
        to_clear_out: HashSet<String>,
    ) -> SetupCluster {
        let mut result = SetupReporterReal::get_default_params()
            .into_iter()
            .chain(existing_setup)
            .collect::<SetupCluster>();
        let db_password_opt = value_m!(setup_multi_config, "db-password", String);
        value_retrievers.iter().for_each(|retriever| {
            let already_set = match result.get(retriever.value_name()) {
                Some(uisrv) => uisrv.status == Set,
                None => false,
            };
            if !already_set {
                if let Some(value) = retriever.computed_default(
                    &bootstrap_config,
                    persistent_config_opt,
                    &db_password_opt,
                ) {
                    result.insert(
                        retriever.value_name().to_string(),
                        UiSetupResponseValue::new(retriever.value_name(), &value, Default),
                    );
                }
                if let Some(value) =
                    value_m!(configured_multi_config, retriever.value_name(), String)
                {
                    if let Some(existing_value) = result.get(retriever.value_name()) {
                        if (existing_value.status == Default) && (value != existing_value.value) {
                            result.insert(
                                retriever.value_name().to_string(),
                                UiSetupResponseValue::new(
                                    retriever.value_name(),
                                    &value,
                                    Configured,
                                ),
                            );
                        } else {
                        }
                    } else {
                        result.insert(
                            retriever.value_name().to_string(),
                            UiSetupResponseValue::new(retriever.value_name(), &value, Configured),
                        );
                    }
                }
                if let Some(value) = value_m!(setup_multi_config, retriever.value_name(), String) {
                    if let Some(existing_value) = result.get(retriever.value_name()) {
                        if (existing_value.status != Set) && (value != existing_value.value) {
                            result.insert(
                                retriever.value_name().to_string(),
                                UiSetupResponseValue::new(retriever.value_name(), &value, Set),
                            );
                        } else {
                        }
                    } else {
                        result.insert(
                            retriever.value_name().to_string(),
                            UiSetupResponseValue::new(retriever.value_name(), &value, Set),
                        );
                    }
                }
            }
        });
        let mut unvalued: SetupCluster = HashMap::new();
        value_retrievers
            .into_iter()
            .filter(|retriever| {
                !result.contains_key(retriever.value_name())
                    || to_clear_out.contains(&retriever.value_name().to_string())
            })
            .map(|retriever| {
                let is_required = retriever.is_required(&result);
                (retriever, is_required)
            })
            .for_each(|(retriever, is_required)| {
                let status = if is_required { Required } else { Blank };
                unvalued.insert(
                    retriever.value_name().to_string(),
                    UiSetupResponseValue::new(retriever.value_name(), "", status),
                );
            });
        result.extend(unvalued);
        let permitted_keys = Self::get_parameter_names();
        result
            .into_iter()
            .filter(|(key, _)| permitted_keys.contains(key))
            .collect()
    }

    fn get_parameter_names() -> HashSet<String> {
        let schema = shared_app(app_head());
        schema
            .p
            .opts
            .iter()
            .flat_map(|opt| {
                let name = opt.b.name;
                let delimited = format!("|{}|", name);
                if "|ui-port|crash-point|fake-public-key|".contains(&delimited) {
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
}

trait ValueRetriever {
    fn value_name(&self) -> &'static str;

    fn computed_default(
        &self,
        _bootstrapper_config: &BootstrapperConfig,
        _persistent_config_opt: Option<&dyn PersistentConfiguration>,
        _db_password_opt: &Option<String>,
    ) -> Option<String> {
        None
    }

    fn set_value(&self, multi_config: &MultiConfig) -> Option<String> {
        value_m!(multi_config, self.value_name(), String)
    }

    fn is_required(&self, _params: &SetupCluster) -> bool {
        false
    }
}

fn is_required_for_blockchain(params: &SetupCluster) -> bool {
    match params.get("neighborhood-mode") {
        Some(nhm) if &nhm.value == "zero-hop" => false,
        _ => true,
    }
}

struct BlockchainServiceUrl {}
impl ValueRetriever for BlockchainServiceUrl {
    fn value_name(&self) -> &'static str {
        "blockchain-service-url"
    }

    fn is_required(&self, params: &SetupCluster) -> bool {
        is_required_for_blockchain(params)
    }
}

struct Chain {}
impl ValueRetriever for Chain {
    fn value_name(&self) -> &'static str {
        "chain"
    }

    fn computed_default(
        &self,
        _bootstrapper_config: &BootstrapperConfig,
        _persistent_config_opt: Option<&dyn PersistentConfiguration>,
        _db_password_opt: &Option<String>,
    ) -> Option<String> {
        Some(DEFAULT_CHAIN_NAME.to_string())
    }

    fn is_required(&self, _params: &SetupCluster) -> bool {
        true
    }
}

struct ClandestinePort {}
impl ValueRetriever for ClandestinePort {
    fn value_name(&self) -> &'static str {
        "clandestine-port"
    }

    fn computed_default(
        &self,
        _bootstrapper_config: &BootstrapperConfig,
        persistent_config_opt: Option<&dyn PersistentConfiguration>,
        _db_password_opt: &Option<String>,
    ) -> Option<String> {
        persistent_config_opt.map(|pc| pc.clandestine_port().to_string())
    }

    fn is_required(&self, _params: &SetupCluster) -> bool {
        true
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

    fn computed_default(
        &self,
        bootstrapper_config: &BootstrapperConfig,
        _persistent_config_opt: Option<&dyn PersistentConfiguration>,
        _db_password_opt: &Option<String>,
    ) -> Option<String> {
        let real_user = &bootstrapper_config.real_user;
        let chain_name = chain_name_from_id(bootstrapper_config.blockchain_bridge_config.chain_id);
        let data_directory_opt = None;
        Some(
            data_directory_from_context(&real_user, &data_directory_opt, chain_name)
                .to_string_lossy()
                .to_string(),
        )
    }

    fn is_required(&self, _params: &SetupCluster) -> bool {
        true
    }
}

struct DbPassword {}
impl ValueRetriever for DbPassword {
    fn value_name(&self) -> &'static str {
        "db-password"
    }

    fn is_required(&self, params: &SetupCluster) -> bool {
        is_required_for_blockchain(params)
    }
}

struct DnsServers {}
impl ValueRetriever for DnsServers {
    fn value_name(&self) -> &'static str {
        "dns-servers"
    }

    fn computed_default(
        &self,
        _bootstrapper_config: &BootstrapperConfig,
        _persistent_config_opt: Option<&dyn PersistentConfiguration>,
        _db_password_opt: &Option<String>,
    ) -> Option<String> {
        Some("1.1.1.1".to_string())
    }

    fn is_required(&self, _params: &SetupCluster) -> bool {
        true
    }
}

struct EarningWallet {}
impl ValueRetriever for EarningWallet {
    fn value_name(&self) -> &'static str {
        "earning-wallet"
    }

    fn computed_default(
        &self,
        bootstrapper_config: &BootstrapperConfig,
        _persistent_config_opt: Option<&dyn PersistentConfiguration>,
        _db_password_opt: &Option<String>,
    ) -> Option<String> {
        Some(bootstrapper_config.earning_wallet.to_string())
    }

    fn is_required(&self, params: &SetupCluster) -> bool {
        is_required_for_blockchain(params)
    }
}

struct GasPrice {}
impl ValueRetriever for GasPrice {
    fn value_name(&self) -> &'static str {
        "gas-price"
    }

    fn computed_default(
        &self,
        _bootstrapper_config: &BootstrapperConfig,
        persistent_config_opt: Option<&dyn PersistentConfiguration>,
        _db_password_opt: &Option<String>,
    ) -> Option<String> {
        persistent_config_opt.map(|pc| pc.gas_price().to_string())
    }

    fn is_required(&self, params: &SetupCluster) -> bool {
        is_required_for_blockchain(params)
    }
}

struct Ip {}
impl ValueRetriever for Ip {
    fn value_name(&self) -> &'static str {
        "ip"
    }

    fn is_required(&self, params: &SetupCluster) -> bool {
        match params.get("neighborhood-mode") {
            Some(nhm) if &nhm.value == "standard" => true,
            Some(_) => false,
            None => true,
        }
    }
}

struct LogLevel {}
impl ValueRetriever for LogLevel {
    fn value_name(&self) -> &'static str {
        "log-level"
    }

    fn computed_default(
        &self,
        _bootstrapper_config: &BootstrapperConfig,
        _persistent_config_opt: Option<&dyn PersistentConfiguration>,
        _db_password_opt: &Option<String>,
    ) -> Option<String> {
        Some("warn".to_string())
    }

    fn is_required(&self, _params: &SetupCluster) -> bool {
        true
    }
}

struct NeighborhoodMode {}
impl ValueRetriever for NeighborhoodMode {
    fn value_name(&self) -> &'static str {
        "neighborhood-mode"
    }

    fn computed_default(
        &self,
        _bootstrapper_config: &BootstrapperConfig,
        _persistent_config_opt: Option<&dyn PersistentConfiguration>,
        _db_password_opt: &Option<String>,
    ) -> Option<String> {
        Some("standard".to_string())
    }

    fn is_required(&self, _params: &SetupCluster) -> bool {
        true
    }
}

fn node_descriptors_to_neighbors(node_descriptors: Vec<NodeDescriptor>) -> String {
    node_descriptors
        .into_iter()
        .map(|nd| nd.to_string(main_cryptde()))
        .collect_vec()
        .join(",")
}

struct Neighbors {}
impl ValueRetriever for Neighbors {
    fn value_name(&self) -> &'static str {
        "neighbors"
    }

    fn computed_default(
        &self,
        _bootstrapper_config: &BootstrapperConfig,
        persistent_config_opt: Option<&dyn PersistentConfiguration>,
        db_password_opt: &Option<String>,
    ) -> Option<String> {
        match (persistent_config_opt, db_password_opt) {
            (Some(pc), Some(pw)) => match pc.past_neighbors(&pw) {
                Ok(Some(pns)) => Some(node_descriptors_to_neighbors(pns)),
                _ => None,
            },
            _ => None,
        }
    }

    fn is_required(&self, _params: &SetupCluster) -> bool {
        match _params.get("neighborhood-mode") {
            Some(nhm) if &nhm.value == "standard" => false,
            Some(nhm) if &nhm.value == "zero-hop" => false,
            _ => true,
        }
    }
}

struct RealUser {}
impl ValueRetriever for RealUser {
    fn value_name(&self) -> &'static str {
        "real-user"
    }

    fn computed_default(
        &self,
        _bootstrapper_config: &BootstrapperConfig,
        _persistent_config_opt: Option<&dyn PersistentConfiguration>,
        _db_password_opt: &Option<String>,
    ) -> Option<String> {
        #[cfg(target_os = "windows")]
        {
            None
        }
        #[cfg(not(target_os = "windows"))]
        {
            Some(
                crate::bootstrapper::RealUser::default()
                    .populate()
                    .to_string(),
            )
        }
    }
}

fn value_retrievers() -> Vec<Box<dyn ValueRetriever>> {
    vec![
        Box::new(BlockchainServiceUrl {}),
        Box::new(Chain {}),
        Box::new(ClandestinePort {}),
        Box::new(ConfigFile {}),
        Box::new(ConsumingPrivateKey {}),
        Box::new(DataDirectory {}),
        Box::new(DbPassword {}),
        Box::new(DnsServers {}),
        Box::new(EarningWallet {}),
        Box::new(GasPrice {}),
        Box::new(Ip {}),
        Box::new(LogLevel {}),
        Box::new(NeighborhoodMode {}),
        Box::new(Neighbors {}),
        Box::new(RealUser {}),
    ]
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::blockchain::blockchain_interface::chain_id_from_name;
    use crate::bootstrapper::RealUser;
    use crate::database::db_initializer::{DbInitializer, DbInitializerReal};
    use crate::persistent_configuration::{
        PersistentConfigError, PersistentConfiguration, PersistentConfigurationReal,
    };
    use crate::sub_lib::cryptde::PublicKey;
    use crate::sub_lib::node_addr::NodeAddr;
    use crate::sub_lib::wallet::Wallet;
    use crate::test_utils::persistent_configuration_mock::PersistentConfigurationMock;
    use masq_lib::messages::UiSetupResponseValueStatus::{Blank, Configured, Required, Set};
    use masq_lib::test_utils::environment_guard::EnvironmentGuard;
    use masq_lib::test_utils::utils::ensure_node_home_directory_exists;
    #[cfg(not(target_os = "windows"))]
    use std::default::Default;
    use std::net::IpAddr;
    use std::str::FromStr;
    use std::sync::{Arc, Mutex};

    #[test]
    fn parameter_names_include_some_classic_ones() {
        let result = SetupReporterReal::get_parameter_names();

        assert_eq!(
            result.contains(&"dns-servers".to_string()),
            true,
            "{:?}",
            result
        );
        assert_eq!(result.contains(&"ip".to_string()), true, "{:?}", result);
        assert_eq!(
            result.contains(&"log-level".to_string()),
            true,
            "{:?}",
            result
        );
        assert_eq!(
            result.contains(&"dns-servers".to_string()),
            true,
            "{:?}",
            result
        );
    }

    #[test]
    fn parameter_names_doesnt_include_censored_values() {
        let result = SetupReporterReal::get_parameter_names();

        assert_eq!(
            result.contains(&"ui-port".to_string()),
            false,
            "{:?}",
            result
        );
        assert_eq!(
            result.contains(&"fake-public-key".to_string()),
            false,
            "{:?}",
            result
        );
        assert_eq!(
            result.contains(&"crash-point".to_string()),
            false,
            "{:?}",
            result
        );
        #[cfg(target_os = "windows")]
        assert_eq!(
            result.contains(&"real-user".to_string()),
            false,
            "{:?}",
            result
        );
    }

    #[test]
    fn everything_in_defaults_is_properly_constructed() {
        let result = SetupReporterReal::get_default_params();

        assert_eq!(result.is_empty(), false, "{:?}", result); // if we don't have any defaults, let's get rid of all this
        result.into_iter().for_each(|(name, value)| {
            assert_eq!(name, value.name);
            assert_eq!(value.status, Default);
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
    fn get_modified_setup_database_populated_only_requireds_set() {
        let _guard = EnvironmentGuard::new();
        let home_dir = ensure_node_home_directory_exists(
            "setup_reporter",
            "get_configured_values_database_populated_only_requireds_set",
        );
        let db_initializer = DbInitializerReal::new();
        let conn = db_initializer
            .initialize(&home_dir, chain_id_from_name("mainnet"), true)
            .unwrap();
        let config = PersistentConfigurationReal::from(conn);
        config.set_password("password");
        config.set_clandestine_port(1234);
        config
            .set_mnemonic_seed(b"booga booga", "password")
            .unwrap();
        config.set_consuming_wallet_derivation_path("m/44'/60'/1'/2/3", "password");
        config.set_earning_wallet_address("0x0000000000000000000000000000000000000000");
        config.set_gas_price(1234567890);
        let neighbor1 = NodeDescriptor {
            encryption_public_key: PublicKey::new(b"ABCD"),
            mainnet: true,
            node_addr_opt: Some(NodeAddr::new(
                &IpAddr::from_str("1.2.3.4").unwrap(),
                &vec![1234],
            )),
        };
        let neighbor2 = NodeDescriptor {
            encryption_public_key: PublicKey::new(b"EFGH"),
            mainnet: true,
            node_addr_opt: Some(NodeAddr::new(
                &IpAddr::from_str("5.6.7.8").unwrap(),
                &vec![5678],
            )),
        };
        config
            .set_past_neighbors(Some(vec![neighbor1, neighbor2]), "password")
            .unwrap();

        let incoming_setup = vec![
            ("data-directory", home_dir.to_str().unwrap()),
            ("db-password", "password"),
            ("ip", "4.3.2.1"),
        ]
        .into_iter()
        .map(|(name, value)| UiSetupRequestValue::new(name, value))
        .collect_vec();
        let subject = SetupReporterReal::new();

        let result = subject.get_modified_setup(HashMap::new(), incoming_setup);

        let expected_result = vec![
            ("blockchain-service-url", "", Required),
            ("chain", "mainnet", Default),
            ("clandestine-port", "1234", Default),
            ("config-file", "config.toml", Default),
            ("consuming-private-key", "", Blank),
            ("data-directory", home_dir.to_str().unwrap(), Set),
            ("db-password", "password", Set),
            ("dns-servers", "1.1.1.1", Default),
            (
                "earning-wallet",
                "0x0000000000000000000000000000000000000000",
                Default,
            ),
            ("gas-price", "1234567890", Default),
            ("ip", "4.3.2.1", Set),
            ("log-level", "warn", Default),
            ("neighborhood-mode", "standard", Default),
            (
                "neighbors",
                "QUJDRA@1.2.3.4:1234,RUZHSA@5.6.7.8:5678",
                Default,
            ),
            #[cfg(not(target_os = "windows"))]
            (
                "real-user",
                &RealUser::default().populate().to_string(),
                Default,
            ),
        ]
        .into_iter()
        .map(|(name, value, status)| {
            (
                name.to_string(),
                UiSetupResponseValue::new(name, value, status),
            )
        })
        .collect_vec();
        let presentable_result = result
            .into_iter()
            .sorted_by_key(|(k, _)| k.clone())
            .collect_vec();
        assert_eq!(presentable_result, expected_result);
    }

    #[test]
    fn get_modified_setup_database_nonexistent_everything_preexistent() {
        let _guard = EnvironmentGuard::new();
        let home_dir = ensure_node_home_directory_exists(
            "setup_reporter",
            "get_configured_values_database_nonexistent_everything_set",
        );
        let existing_setup = vec![
            ("blockchain-service-url", "https://example.com"),
            ("chain", "ropsten"),
            ("clandestine-port", "1234"),
            ("consuming-private-key", "0011223344556677001122334455667700112233445566770011223344556677"),
            ("data-directory", home_dir.to_str().unwrap()),
            ("db-password", "password"),
            ("dns-servers", "8.8.8.8"),
            ("earning-wallet", "0x0123456789012345678901234567890123456789"),
            ("gas-price", "50"),
            ("ip", "4.3.2.1"),
            ("log-level", "error"),
            ("neighborhood-mode", "originate-only"),
            ("neighbors", "MTIzNDU2Nzg5MTEyMzQ1Njc4OTIxMjM0NTY3ODkzMTI@1.2.3.4:1234,MTIzNDU2Nzg5MTEyMzQ1Njc4OTIxMjM0NTY3ODkzMTI@5.6.7.8:5678"),
            #[cfg(not(target_os = "windows"))]
            ("real-user", "9999:9999:booga"),
        ].into_iter()
            .map (|(name, value)| (name.to_string(), UiSetupResponseValue::new(name, value, Set)))
            .collect::<SetupCluster>();
        let subject = SetupReporterReal::new();

        let result = subject.get_modified_setup(existing_setup, vec![]);

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
        let presentable_result = result
            .into_iter()
            .sorted_by_key(|(k, _)| k.clone())
            .collect_vec();
        assert_eq!(presentable_result, expected_result);
    }

    #[test]
    fn get_modified_setup_database_nonexistent_everything_set() {
        let _guard = EnvironmentGuard::new();
        let home_dir = ensure_node_home_directory_exists(
            "setup_reporter",
            "get_configured_values_database_nonexistent_everything_set",
        );
        let incoming_setup = vec![
            ("blockchain-service-url", "https://example.com"),
            ("chain", "ropsten"),
            ("clandestine-port", "1234"),
            ("consuming-private-key", "0011223344556677001122334455667700112233445566770011223344556677"),
            ("data-directory", home_dir.to_str().unwrap()),
            ("db-password", "password"),
            ("dns-servers", "8.8.8.8"),
            ("earning-wallet", "0x0123456789012345678901234567890123456789"),
            ("gas-price", "50"),
            ("ip", "4.3.2.1"),
            ("log-level", "error"),
            ("neighborhood-mode", "originate-only"),
            ("neighbors", "MTIzNDU2Nzg5MTEyMzQ1Njc4OTIxMjM0NTY3ODkzMTI@1.2.3.4:1234,MTIzNDU2Nzg5MTEyMzQ1Njc4OTIxMjM0NTY3ODkzMTI@5.6.7.8:5678"),
            #[cfg(not(target_os = "windows"))]
            ("real-user", "9999:9999:booga"),
        ].into_iter()
            .map (|(name, value)| UiSetupRequestValue::new(name, value))
            .collect_vec();
        let subject = SetupReporterReal::new();

        let result = subject.get_modified_setup(HashMap::new(), incoming_setup);

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
        let presentable_result = result
            .into_iter()
            .sorted_by_key(|(k, _)| k.clone())
            .collect_vec();
        assert_eq!(presentable_result, expected_result);
    }

    #[test]
    fn get_modified_setup_database_nonexistent_nothing_set_everything_in_environment() {
        let _guard = EnvironmentGuard::new();
        let home_dir = ensure_node_home_directory_exists(
            "setup_reporter",
            "get_configured_values_database_nonexistent_nothing_set_everything_in_environment",
        );
        vec![
            ("SUB_BLOCKCHAIN_SERVICE_URL", "https://example.com"),
            ("SUB_CHAIN", "ropsten"),
            ("SUB_CLANDESTINE_PORT", "1234"),
            ("SUB_CONSUMING_PRIVATE_KEY", "0011223344556677001122334455667700112233445566770011223344556677"),
            ("SUB_DATA_DIRECTORY", home_dir.to_str().unwrap()),
            ("SUB_DB_PASSWORD", "password"),
            ("SUB_DNS_SERVERS", "8.8.8.8"),
            ("SUB_EARNING_WALLET", "0x0123456789012345678901234567890123456789"),
            ("SUB_GAS_PRICE", "50"),
            ("SUB_IP", "4.3.2.1"),
            ("SUB_LOG_LEVEL", "error"),
            ("SUB_NEIGHBORHOOD_MODE", "originate-only"),
            ("SUB_NEIGHBORS", "MTIzNDU2Nzg5MTEyMzQ1Njc4OTIxMjM0NTY3ODkzMTI@1.2.3.4:1234,MTIzNDU2Nzg5MTEyMzQ1Njc4OTIxMjM0NTY3ODkzMTI@5.6.7.8:5678"),
            #[cfg(not(target_os = "windows"))]
            ("SUB_REAL_USER", "9999:9999:booga"),
        ].into_iter()
            .for_each (|(name, value)| std::env::set_var (name, value));
        let params = vec![];
        let subject = SetupReporterReal::new();

        let result = subject.get_modified_setup(HashMap::new(), params);

        let expected_result = vec![
            ("blockchain-service-url", "https://example.com", Configured),
            ("chain", "ropsten", Configured),
            ("clandestine-port", "1234", Configured),
            ("config-file", "config.toml", Default),
            ("consuming-private-key", "0011223344556677001122334455667700112233445566770011223344556677", Configured),
            ("data-directory", home_dir.to_str().unwrap(), Configured),
            ("db-password", "password", Configured),
            ("dns-servers", "8.8.8.8", Configured),
            ("earning-wallet", "0x0123456789012345678901234567890123456789", Configured),
            ("gas-price", "50", Configured),
            ("ip", "4.3.2.1", Configured),
            ("log-level", "error", Configured),
            ("neighborhood-mode", "originate-only", Configured),
            ("neighbors", "MTIzNDU2Nzg5MTEyMzQ1Njc4OTIxMjM0NTY3ODkzMTI@1.2.3.4:1234,MTIzNDU2Nzg5MTEyMzQ1Njc4OTIxMjM0NTY3ODkzMTI@5.6.7.8:5678", Configured),
            #[cfg(not(target_os = "windows"))]
            ("real-user", "9999:9999:booga", Configured),
        ].into_iter()
            .map (|(name, value, status)| (name.to_string(), UiSetupResponseValue::new(name, value, status)))
            .collect_vec();
        let presentable_result = result
            .into_iter()
            .sorted_by_key(|(k, _)| k.clone())
            .collect_vec();
        assert_eq!(presentable_result, expected_result);
    }

    #[test]
    fn get_modified_setup_database_nonexistent_all_but_requireds_cleared() {
        let _guard = EnvironmentGuard::new();
        let home_dir = ensure_node_home_directory_exists(
            "setup_reporter",
            "get_configured_values_database_nonexistent_all_but_requireds_cleared",
        );
        vec![
            ("SUB_BLOCKCHAIN_SERVICE_URL", "https://example.com"),
            ("SUB_CHAIN", "ropsten"),
            ("SUB_CLANDESTINE_PORT", "1234"),
            ("SUB_CONSUMING_PRIVATE_KEY", "0011223344556677001122334455667700112233445566770011223344556677"),
            ("SUB_DATA_DIRECTORY", home_dir.to_str().unwrap()),
            ("SUB_DB_PASSWORD", "password"),
            ("SUB_DNS_SERVERS", "8.8.8.8"),
            ("SUB_EARNING_WALLET", "0x0123456789012345678901234567890123456789"),
            ("SUB_GAS_PRICE", "50"),
            ("SUB_IP", "4.3.2.1"),
            ("SUB_LOG_LEVEL", "error"),
            ("SUB_NEIGHBORHOOD_MODE", "originate-only"),
            ("SUB_NEIGHBORS", "MTIzNDU2Nzg5MTEyMzQ1Njc4OTIxMjM0NTY3ODkzMTI@1.2.3.4:1234,MTIzNDU2Nzg5MTEyMzQ1Njc4OTIxMjM0NTY3ODkzMTI@5.6.7.8:5678"),
            #[cfg(not(target_os = "windows"))]
            ("SUB_REAL_USER", "9999:9999:booga"),
        ].into_iter()
            .for_each (|(name, value)| std::env::set_var (name, value));
        let params = vec![
            "blockchain-service-url",
            "clandestine-port",
            "config-file",
            "consuming-private-key",
            "db-password",
            "neighbors",
            #[cfg(not(target_os = "windows"))]
            "real-user",
        ]
        .into_iter()
        .map(|name| UiSetupRequestValue::clear(name))
        .collect_vec();
        let subject = SetupReporterReal::new();

        let result = subject.get_modified_setup(HashMap::new(), params);

        let expected_result = vec![
            ("blockchain-service-url", "", Required),
            ("chain", "ropsten", Configured),
            ("clandestine-port", "", Required),
            ("config-file", "", Blank),
            ("consuming-private-key", "", Blank),
            ("data-directory", home_dir.to_str().unwrap(), Configured),
            ("db-password", "", Required),
            ("dns-servers", "8.8.8.8", Configured),
            (
                "earning-wallet",
                "0x0123456789012345678901234567890123456789",
                Configured,
            ),
            ("gas-price", "50", Configured),
            ("ip", "4.3.2.1", Configured),
            ("log-level", "error", Configured),
            ("neighborhood-mode", "originate-only", Configured),
            ("neighbors", "", Required),
            #[cfg(not(target_os = "windows"))]
            ("real-user", "", Blank),
        ]
        .into_iter()
        .map(|(name, value, status)| {
            (
                name.to_string(),
                UiSetupResponseValue::new(name, value, status),
            )
        })
        .collect_vec();
        let presentable_result = result
            .into_iter()
            .sorted_by_key(|(k, _)| k.clone())
            .collect_vec();
        assert_eq!(presentable_result, expected_result);
    }

    #[test]
    fn chain_computed_default() {
        let subject = Chain {};

        let result = subject.computed_default(&BootstrapperConfig::new(), None, &None);

        assert_eq!(result, Some(DEFAULT_CHAIN_NAME.to_string()));
    }

    #[test]
    fn clandestine_port_computed_default_present() {
        let persistent_config = PersistentConfigurationMock::new().clandestine_port_result(1234);
        let subject = ClandestinePort {};

        let result =
            subject.computed_default(&BootstrapperConfig::new(), Some(&persistent_config), &None);

        assert_eq!(result, Some("1234".to_string()))
    }

    #[test]
    fn clandestine_port_computed_default_absent() {
        let subject = ClandestinePort {};

        let result = subject.computed_default(&BootstrapperConfig::new(), None, &None);

        assert_eq!(result, None)
    }

    #[test]
    fn data_directory_computed_default() {
        let real_user = RealUser::null().populate();
        let expected = data_directory_from_context(&real_user, &None, DEFAULT_CHAIN_NAME)
            .to_string_lossy()
            .to_string();
        let mut config = BootstrapperConfig::new();
        config.real_user = real_user;
        config.blockchain_bridge_config.chain_id = chain_id_from_name(DEFAULT_CHAIN_NAME);

        let subject = DataDirectory {};

        let result = subject.computed_default(&config, None, &None);

        assert_eq!(result, Some(expected))
    }

    #[test]
    fn dns_servers_computed_default() {
        let subject = DnsServers {};

        let result = subject.computed_default(&BootstrapperConfig::new(), None, &None);

        assert_eq!(result, Some("1.1.1.1".to_string()))
    }

    #[test]
    fn earning_wallet_computed_default() {
        let mut config = BootstrapperConfig::new();
        config.earning_wallet = Wallet::new("0x1234567890123456789012345678901234567890");
        let subject = EarningWallet {};

        let result = subject.computed_default(&config, None, &None);

        assert_eq!(
            result,
            Some("0x1234567890123456789012345678901234567890".to_string())
        )
    }

    #[test]
    fn gas_price_computed_default_present() {
        let persistent_config = PersistentConfigurationMock::new().gas_price_result(57);
        let subject = GasPrice {};

        let result =
            subject.computed_default(&BootstrapperConfig::new(), Some(&persistent_config), &None);

        assert_eq!(result, Some("57".to_string()))
    }

    #[test]
    fn gas_price_computed_default_absent() {
        let subject = GasPrice {};

        let result = subject.computed_default(&BootstrapperConfig::new(), None, &None);

        assert_eq!(result, None)
    }

    #[test]
    fn log_level_computed_default() {
        let subject = LogLevel {};

        let result = subject.computed_default(&BootstrapperConfig::new(), None, &None);

        assert_eq!(result, Some("warn".to_string()))
    }

    #[test]
    fn neighborhood_mode_computed_default() {
        let subject = NeighborhoodMode {};

        let result = subject.computed_default(&BootstrapperConfig::new(), None, &None);

        assert_eq!(result, Some("standard".to_string()))
    }

    #[test]
    fn neighbors_computed_default_present_present_present_ok() {
        let past_neighbors_params_arc = Arc::new(Mutex::new(vec![]));
        let persistent_config = PersistentConfigurationMock::new()
            .past_neighbors_params(&past_neighbors_params_arc)
            .past_neighbors_result(Ok(Some(vec![
                NodeDescriptor::from_str(
                    main_cryptde(),
                    "MTEyMjMzNDQ1NTY2Nzc4ODExMjIzMzQ0NTU2Njc3ODg@1.2.3.4:1234",
                )
                .unwrap(),
                NodeDescriptor::from_str(
                    main_cryptde(),
                    "ODg3NzY2NTU0NDMzMjIxMTg4Nzc2NjU1NDQzMzIyMTE@4.3.2.1:4321",
                )
                .unwrap(),
            ])));
        let subject = Neighbors {};

        let result = subject.computed_default(
            &BootstrapperConfig::new(),
            Some(&persistent_config),
            &Some("password".to_string()),
        );

        assert_eq! (result, Some ("MTEyMjMzNDQ1NTY2Nzc4ODExMjIzMzQ0NTU2Njc3ODg@1.2.3.4:1234,ODg3NzY2NTU0NDMzMjIxMTg4Nzc2NjU1NDQzMzIyMTE@4.3.2.1:4321".to_string()));
        let past_neighbors_params = past_neighbors_params_arc.lock().unwrap();
        assert_eq!(*past_neighbors_params, vec!["password".to_string()])
    }

    #[test]
    fn neighbors_computed_default_present_present_err() {
        let past_neighbors_params_arc = Arc::new(Mutex::new(vec![]));
        let persistent_config = PersistentConfigurationMock::new()
            .past_neighbors_params(&past_neighbors_params_arc)
            .past_neighbors_result(Err(PersistentConfigError::PasswordError));
        let subject = Neighbors {};

        let result = subject.computed_default(
            &BootstrapperConfig::new(),
            Some(&persistent_config),
            &Some("password".to_string()),
        );

        assert_eq!(result, None);
        let past_neighbors_params = past_neighbors_params_arc.lock().unwrap();
        assert_eq!(*past_neighbors_params, vec!["password".to_string()])
    }

    #[test]
    fn neighbors_computed_default_present_absent() {
        // absence of configured result will cause panic if past_neighbors is called
        let persistent_config = PersistentConfigurationMock::new();
        let subject = Neighbors {};

        let result =
            subject.computed_default(&BootstrapperConfig::new(), Some(&persistent_config), &None);

        assert_eq!(result, None);
    }

    #[test]
    fn neighbors_computed_default_absent() {
        let subject = Neighbors {};

        let result = subject.computed_default(&BootstrapperConfig::new(), None, &None);

        assert_eq!(result, None);
    }

    #[cfg(not(target_os = "windows"))]
    #[test]
    fn real_user_computed_default() {
        let subject = crate::daemon::setup_reporter::RealUser {};

        let result = subject.computed_default(&BootstrapperConfig::new(), None, &None);

        assert_eq!(result, Some(RealUser::default().populate().to_string()));
    }

    #[cfg(target_os = "windows")]
    #[test]
    fn real_user_computed_default() {
        let subject = crate::daemon::setup_reporter::RealUser {};

        let result = subject.computed_default(&BootstrapperConfig::new(), None, &None);

        assert_eq!(result, None);
    }

    fn verify_requirements(
        subject: &dyn ValueRetriever,
        param_name: &str,
        value_predictions: Vec<(&str, bool)>,
    ) {
        value_predictions
            .into_iter()
            .for_each(|(param_value, prediction)| {
                let params = vec![(
                    param_name.to_string(),
                    UiSetupResponseValue::new(param_name, param_value, Set),
                )]
                .into_iter()
                .collect::<SetupCluster>();

                let result = subject.is_required(&params);

                assert_eq!(result, prediction, "{:?}", params);
            })
    }

    fn verify_needed_for_blockchain(subject: &dyn ValueRetriever) {
        verify_requirements(
            subject,
            "neighborhood-mode",
            vec![
                ("standard", true),
                ("zero-hop", false),
                ("originate-only", true),
                ("consume-only", true),
            ],
        );
    }

    #[test]
    fn ip_requirements() {
        verify_requirements(
            &Ip {},
            "neighborhood-mode",
            vec![
                ("standard", true),
                ("zero-hop", false),
                ("originate-only", false),
                ("consume-only", false),
            ],
        );
    }

    #[test]
    fn neighbors_requirements() {
        verify_requirements(
            &Neighbors {},
            "neighborhood-mode",
            vec![
                ("standard", false),
                ("zero-hop", false),
                ("originate-only", true),
                ("consume-only", true),
            ],
        );
    }

    #[test]
    fn blockchain_requirements() {
        verify_needed_for_blockchain(&BlockchainServiceUrl {});
        verify_needed_for_blockchain(&DbPassword {});
        verify_needed_for_blockchain(&EarningWallet {});
        verify_needed_for_blockchain(&GasPrice {});
    }

    #[test]
    fn dumb_requirements() {
        let params = HashMap::new();
        assert_eq!(BlockchainServiceUrl {}.is_required(&params), true);
        assert_eq!(Chain {}.is_required(&params), true);
        assert_eq!(ClandestinePort {}.is_required(&params), true);
        assert_eq!(ConfigFile {}.is_required(&params), false);
        assert_eq!(ConsumingPrivateKey {}.is_required(&params), false);
        assert_eq!(DataDirectory {}.is_required(&params), true);
        assert_eq!(DbPassword {}.is_required(&params), true);
        assert_eq!(DnsServers {}.is_required(&params), true);
        assert_eq!(EarningWallet {}.is_required(&params), true);
        assert_eq!(GasPrice {}.is_required(&params), true);
        assert_eq!(Ip {}.is_required(&params), true);
        assert_eq!(LogLevel {}.is_required(&params), true);
        assert_eq!(NeighborhoodMode {}.is_required(&params), true);
        assert_eq!(Neighbors {}.is_required(&params), true);
        assert_eq!(
            crate::daemon::setup_reporter::RealUser {}.is_required(&params),
            false
        );
    }

    #[test]
    fn run_me_privileged() {
        let real_user = RealUser::null().populate();
        let directory = data_directory_from_context(&real_user, &None, "mainnet");
        eprintln!("default data directory: {:?}", directory);
    }
}
