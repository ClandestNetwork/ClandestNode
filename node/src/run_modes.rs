// Copyright (c) 2017-2019, Substratum LLC (https://substratum.net) and/or its affiliates. All rights reserved.

use crate::daemon::daemon_initializer::{DaemonInitializer, RecipientsFactoryReal, RerunnerReal};
use crate::daemon::ChannelFactoryReal;
use crate::database::config_dumper;
use crate::node_configurator::node_configurator_generate_wallet::NodeConfiguratorGenerateWallet;
use crate::node_configurator::node_configurator_initialization::NodeConfiguratorInitialization;
use crate::node_configurator::node_configurator_recover_wallet::NodeConfiguratorRecoverWallet;
use crate::node_configurator::{NodeConfigurator, WalletCreationConfig};
use crate::privilege_drop::{PrivilegeDropper, PrivilegeDropperReal};
use crate::server_initializer::ServerInitializer;
use actix::System;
use futures::future::Future;
use masq_lib::command::{Command, StdStreams};

#[derive(Debug, PartialEq)]
enum Mode {
    GenerateWallet,
    RecoverWallet,
    DumpConfig,
    Initialization,
    Service,
}

pub struct RunModes {
    privilege_dropper: Box<dyn PrivilegeDropper>
}

impl RunModes {
    pub fn new () -> Self {
        Self {
            privilege_dropper: Box::new(PrivilegeDropperReal::new())
        }
    }

    pub fn go(&self, args: &Vec<String>, streams: &mut StdStreams<'_>) -> i32 {
        let (mode, privilege_required) = self.determine_mode_and_priv_req(args);
        let privilege_as_expected = self.privilege_dropper.expect_privilege(privilege_required);
        if !privilege_as_expected {
            let (requirement, recommendation) = if privilege_required {
                ("must", "sudo")
            } else {
                ("must not", "without sudo")
            };
            writeln! (
                streams.stderr,
                "MASQNode in {:?} mode {} run with root privilege; try {}",
                mode,
                requirement,
                recommendation
            ).expect("writeln! failed");
            return 1
        }
        match mode {
            Mode::GenerateWallet => self.generate_wallet(args, streams),
            Mode::RecoverWallet => self.recover_wallet(args, streams),
            Mode::DumpConfig => self.dump_config(args, streams),
            Mode::Initialization => self.initialization(args, streams),
            Mode::Service => self.run_service(args, streams),
        }
    }

    fn determine_mode_and_priv_req(&self, args: &Vec<String>) -> (Mode, bool) {
        if args.contains(&"--dump-config".to_string()) {
            (Mode::DumpConfig, false)
        } else if args.contains(&"--recover-wallet".to_string()) {
            (Mode::RecoverWallet, false)
        } else if args.contains(&"--generate-wallet".to_string()) {
            (Mode::GenerateWallet, false)
        } else if args.contains(&"--initialization".to_string()) {
            (Mode::Initialization, true)
        } else {
            (Mode::Service, true)
        }
    }

    fn run_service(&self, args: &Vec<String>, streams: &mut StdStreams<'_>) -> i32 {
        let system = System::new("main");

        let mut server_initializer = ServerInitializer::new();
        server_initializer.go(streams, args);

        actix::spawn(server_initializer.map_err(|_| {
            System::current().stop_with_code(1);
        }));

        system.run()
    }

    fn generate_wallet(&self, args: &Vec<String>, streams: &mut StdStreams<'_>) -> i32 {
        let configurator = NodeConfiguratorGenerateWallet::new();
        self.configuration_run(args, streams, &configurator)
    }

    fn recover_wallet(&self, args: &Vec<String>, streams: &mut StdStreams<'_>) -> i32 {
        let configurator = NodeConfiguratorRecoverWallet::new();
        self.configuration_run(args, streams, &configurator)
    }

    fn dump_config(&self, args: &Vec<String>, streams: &mut StdStreams<'_>) -> i32 {
        config_dumper::dump_config(args, streams)
    }

    fn initialization(&self, args: &Vec<String>, streams: &mut StdStreams<'_>) -> i32 {
        let configurator = NodeConfiguratorInitialization {};
        let config = configurator.configure(args, streams);
        let mut initializer = DaemonInitializer::new(
            config,
            Box::new(ChannelFactoryReal::new()),
            Box::new(RecipientsFactoryReal::new()),
            Box::new(RerunnerReal::new()),
        );
        initializer.go(streams, args);
        1
    }

    fn configuration_run(
        &self,
        args: &Vec<String>,
        streams: &mut StdStreams<'_>,
        configurator: &dyn NodeConfigurator<WalletCreationConfig>,
    ) -> i32 {
        let config = configurator.configure(args, streams);
        self.privilege_dropper.drop_privileges(&config.real_user);
        panic!();//0
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::RefCell;
    use std::sync::{Arc, Mutex};
    use crate::server_initializer::test_utils::PrivilegeDropperMock;
    use masq_lib::test_utils::fake_stream_holder::FakeStreamHolder;

    struct NodeConfiguratorMock {
        configure_params: Arc<Mutex<Vec<Vec<String>>>>,
        configure_results: RefCell<Vec<String>>
    }

    impl NodeConfigurator<String> for NodeConfiguratorMock {
        fn configure(&self, args: &Vec<String>, _streams: &mut StdStreams<'_>) -> String {
            self.configure_params.lock().unwrap().push(args.clone());
            self.configure_results.borrow_mut().remove (0)
        }
    }

    impl NodeConfiguratorMock {
        pub fn _new () -> Self {
            Self {
                configure_params: Arc::new (Mutex::new (vec![])),
                configure_results: RefCell::new (vec![]),
            }
        }

        pub fn _configure_params (mut self, params: &Arc<Mutex<Vec<Vec<String>>>>) -> Self {
            self.configure_params = params.clone();
            self
        }

        pub fn _configure_result (self, result: String) -> Self {
            self.configure_results.borrow_mut ().push (result);
            self
        }
    }

    #[test]
    fn generate_wallet() {
        [["--generate-wallet"]]
            .iter()
            .for_each(|args| check_mode(args, Mode::GenerateWallet, false));
    }

    #[test]
    fn recover_wallet() {
        [["--recover-wallet"]]
            .iter()
            .for_each(|args| check_mode(args, Mode::RecoverWallet, false));
    }

    #[test]
    fn dump_config() {
        [["--dump-config"]]
            .iter()
            .for_each(|args| check_mode(args, Mode::DumpConfig, false));
    }

    #[test]
    fn initialization() {
        [["--initialization"]]
            .iter()
            .for_each(|args| check_mode(args, Mode::Initialization, true));
    }

    #[test]
    fn both_generate_and_recover() {
        [
            ["--generate-wallet", "--recover-wallet"],
            ["--recover-wallet", "--generate-wallet"],
        ]
        .iter()
        .for_each(|args| check_mode(args, Mode::RecoverWallet, false));
    }

    #[test]
    fn everything_beats_initialization() {
        check_mode(
            &["--initialization", "--generate-wallet"],
            Mode::GenerateWallet, false,
        );
        check_mode(
            &["--initialization", "--recover-wallet"],
            Mode::RecoverWallet, false,
        );
        check_mode(&["--initialization", "--dump-config"], Mode::DumpConfig, false);
        check_mode(
            &["--generate-wallet", "--initialization"],
            Mode::GenerateWallet, false,
        );
        check_mode(
            &["--recover-wallet", "--initialization"],
            Mode::RecoverWallet, false,
        );
        check_mode(&["--dump-config", "--initialization"], Mode::DumpConfig, false);
    }

    #[test]
    fn dump_config_rules_all() {
        [
            ["--booga", "--goober", "--generate-wallet", "--dump-config"],
            ["--booga", "--goober", "--recover-wallet", "--dump-config"],
            ["--booga", "--goober", "--initialization", "--dump-config"],
            [
                "--generate-wallet",
                "--recover_wallet",
                "--initialization",
                "--dump-config",
            ],
        ]
        .iter()
        .for_each(|args| check_mode(args, Mode::DumpConfig, false));
    }

    #[test]
    fn run_servers() {
        check_mode(&[], Mode::Service, true)
    }

    #[test]
    fn initialization_and_service_modes_complain_without_privilege() {
        let mut subject = RunModes::new ();
        let params_arc = Arc::new (Mutex::new (vec![]));
        let privilege_dropper = PrivilegeDropperMock::new()
            .expect_privilege_params (&params_arc)
            .expect_privilege_result(false)
            .expect_privilege_result(false);
        subject.privilege_dropper = Box::new (privilege_dropper);
        let mut initialization_holder = FakeStreamHolder::new();
        let mut service_mode_holder = FakeStreamHolder::new();

        let initialization_exit_code = subject.go (&vec!["--initialization".to_string()], &mut initialization_holder.streams());
        let service_mode_exit_code = subject.go (&vec![], &mut service_mode_holder.streams());

        assert_eq! (initialization_exit_code, 1);
        assert_eq! (initialization_holder.stdout.get_string (), "");
        assert_eq! (initialization_holder.stderr.get_string (), "MASQNode in Initialization mode must run with root privilege; try sudo\n");
        assert_eq! (service_mode_exit_code, 1);
        assert_eq! (service_mode_holder.stdout.get_string (), "");
        assert_eq! (service_mode_holder.stderr.get_string (), "MASQNode in Service mode must run with root privilege; try sudo\n");
        let params = params_arc.lock().unwrap();
        assert_eq! (*params, vec![true, true])
    }

    #[test]
    fn modes_other_than_initialization_and_service_complain_about_privilege() {
        let mut subject = RunModes::new ();
        let params_arc = Arc::new (Mutex::new (vec![]));
        let privilege_dropper = PrivilegeDropperMock::new()
            .expect_privilege_params (&params_arc)
            .expect_privilege_result(false)
            .expect_privilege_result(false)
            .expect_privilege_result(false);
        subject.privilege_dropper = Box::new (privilege_dropper);
        let mut generate_wallet_holder = FakeStreamHolder::new();
        let mut recover_wallet_holder = FakeStreamHolder::new();
        let mut dump_config_holder = FakeStreamHolder::new();

        let generate_wallet_exit_code = subject.go (&vec!["--generate-wallet".to_string()], &mut generate_wallet_holder.streams());
        let recover_wallet_exit_code = subject.go (&vec!["--recover-wallet".to_string()], &mut recover_wallet_holder.streams());
        let dump_config_exit_code = subject.go (&vec!["--dump-config".to_string()], &mut dump_config_holder.streams());

        assert_eq! (generate_wallet_exit_code, 1);
        assert_eq! (generate_wallet_holder.stdout.get_string (), "");
        assert_eq! (generate_wallet_holder.stderr.get_string (), "MASQNode in GenerateWallet mode must not run with root privilege; try without sudo\n");
        assert_eq! (recover_wallet_exit_code, 1);
        assert_eq! (recover_wallet_holder.stdout.get_string (), "");
        assert_eq! (recover_wallet_holder.stderr.get_string (), "MASQNode in RecoverWallet mode must not run with root privilege; try without sudo\n");
        assert_eq! (dump_config_exit_code, 1);
        assert_eq! (dump_config_holder.stdout.get_string (), "");
        assert_eq! (dump_config_holder.stderr.get_string (), "MASQNode in DumpConfig mode must not run with root privilege; try without sudo\n");
        let params = params_arc.lock().unwrap();
        assert_eq! (*params, vec![false, false, false])
    }

    fn check_mode(args: &[&str], expected_mode: Mode, privilege_required: bool) {
        let mut augmented_args: Vec<&str> = vec!["--unrelated"];
        augmented_args.extend(args);
        augmented_args.push("--unrelated");
        let args = strs_to_strings(augmented_args);
        let subject = RunModes::new();

        let (actual_mode, actual_privilege_required) = subject.determine_mode_and_priv_req(&args);

        assert_eq!(actual_mode, expected_mode, "args: {:?}", args);
        assert_eq!(actual_privilege_required, privilege_required, "args: {:?}", args);
    }

    fn strs_to_strings(strs: Vec<&str>) -> Vec<String> {
        strs.into_iter().map(|str| str.to_string()).collect()
    }
}
