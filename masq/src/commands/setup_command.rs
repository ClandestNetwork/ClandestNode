// Copyright (c) 2019-2020, MASQ (https://masq.ai) and/or its affiliates. All rights reserved.

use crate::command_context::{CommandContext};
use clap::{value_t, App, SubCommand};
use masq_lib::messages::{
    UiSetupRequest, UiSetupRequestValue,
    UiSetupResponse
};
use masq_lib::shared_schema::shared_app;
use std::fmt::Debug;
use crate::commands::commands::{Command, transaction, CommandError};

pub fn setup_subcommand() -> App<'static, 'static> {
    shared_app(SubCommand::with_name("setup")
        .about("Establishes (if Node is not already running) and displays startup parameters for MASQNode."))
}

#[derive(Debug, PartialEq)]
pub struct SetupCommand {
    pub values: Vec<UiSetupRequestValue>,
}

impl Command for SetupCommand {
    fn execute(&self, context: &mut dyn CommandContext) -> Result<(), CommandError> {
        let out_message = UiSetupRequest {
            values: self.values.clone(),
        };
        let result: Result<UiSetupResponse, CommandError> = transaction(out_message, context);
        match result {
            Ok(mut response) => {
                response.values.sort_by(|a, b| {
                    a.name
                        .partial_cmp(&b.name)
                        .expect("String comparison failed")
                });
                if response.running {
                    writeln!(context.stdout(), "Note: no changes were made to the setup because the Node is currently running.")
                        .expect ("writeln! failed");
                }
                writeln!(context.stdout(), "NAME                      VALUE")
                    .expect("writeln! failed");
                response.values.into_iter().for_each(|value| {
                    writeln!(context.stdout(), "{:26}{}", value.name, value.value)
                        .expect("writeln! failed")
                });
                Ok(())
            }
            Err(e) => Err(e),
        }
    }
}

impl SetupCommand {
    pub fn new(pieces: Vec<String>) -> Self {
        let matches = setup_subcommand().get_matches_from(&pieces);
        let mut values = pieces
            .iter()
            .filter(|piece| (*piece).starts_with("--"))
            .map(|piece| piece[2..].to_string())
            .map(|key| {
                let value = value_t!(matches, &key, String).expect("Value disappeared!");
                UiSetupRequestValue::new(&key, &value)
            })
            .collect::<Vec<UiSetupRequestValue>>();
        values.sort_by(|a, b| {
            a.name
                .partial_cmp(&b.name)
                .expect("String comparison failed")
        });
        Self { values }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::command_factory::{CommandFactory, CommandFactoryReal};
    use crate::test_utils::mocks::CommandContextMock;
    use masq_lib::messages::{
        UiSetupRequest, UiSetupResponse, UiSetupResponseValue};
    use masq_lib::ui_gateway::MessageTarget::ClientId;
    use masq_lib::ui_gateway::{NodeFromUiMessage, NodeToUiMessage};
    use std::sync::{Arc, Mutex};
    use masq_lib::messages::ToMessageBody;

    #[test]
    fn setup_command_happy_path_with_node_not_running() {
        let transact_params_arc = Arc::new(Mutex::new(vec![]));
        let mut context = CommandContextMock::new()
            .transact_params(&transact_params_arc)
            .transact_result(Ok(NodeToUiMessage {
                target: ClientId(0),
                body: UiSetupResponse {
                    running: false,
                    values: vec![
                        UiSetupResponseValue::new("chain", "ropsten"),
                        UiSetupResponseValue::new("neighborhood-mode", "zero-hop"),
                    ],
                }
                .tmb(0),
            }));
        let stdout_arc = context.stdout_arc();
        let stderr_arc = context.stderr_arc();
        let factory = CommandFactoryReal::new();
        let subject = factory
            .make(vec![
                "setup".to_string(),
                "--neighborhood-mode".to_string(),
                "zero-hop".to_string(),
                "--chain".to_string(),
                "ropsten".to_string(),
            ])
            .unwrap();

        let result = subject.execute(&mut context);

        assert_eq!(result, Ok(()));
        let transact_params = transact_params_arc.lock().unwrap();
        assert_eq!(
            *transact_params,
            vec![NodeFromUiMessage {
                client_id: 0,
                body: UiSetupRequest {
                    values: vec![
                        UiSetupRequestValue::new("chain", "ropsten"),
                        UiSetupRequestValue::new("neighborhood-mode", "zero-hop"),
                    ]
                }
                .tmb(0)
            }]
        );
        assert_eq! (stdout_arc.lock().unwrap().get_string(),
            "NAME                      VALUE\nchain                     ropsten\nneighborhood-mode         zero-hop\n");
        assert_eq!(stderr_arc.lock().unwrap().get_string(), String::new());
    }

    #[test]
    fn setup_command_happy_path_with_node_running() {
        let transact_params_arc = Arc::new(Mutex::new(vec![]));
        let mut context = CommandContextMock::new()
            .transact_params(&transact_params_arc)
            .transact_result(Ok(NodeToUiMessage {
                target: ClientId(0),
                body: UiSetupResponse {
                    running: true,
                    values: vec![
                        UiSetupResponseValue::new("chain", "ropsten"),
                        UiSetupResponseValue::new("neighborhood-mode", "zero-hop"),
                    ],
                }
                .tmb(0),
            }));
        let stdout_arc = context.stdout_arc();
        let stderr_arc = context.stderr_arc();
        let factory = CommandFactoryReal::new();
        let subject = factory
            .make(vec![
                "setup".to_string(),
                "--neighborhood-mode".to_string(),
                "zero-hop".to_string(),
                "--chain".to_string(),
                "ropsten".to_string(),
            ])
            .unwrap();

        let result = subject.execute(&mut context);

        assert_eq!(result, Ok(()));
        let transact_params = transact_params_arc.lock().unwrap();
        assert_eq!(
            *transact_params,
            vec![NodeFromUiMessage {
                client_id: 0,
                body: UiSetupRequest {
                    values: vec![
                        UiSetupRequestValue::new("chain", "ropsten"),
                        UiSetupRequestValue::new("neighborhood-mode", "zero-hop"),
                    ]
                }
                .tmb(0)
            }]
        );
        assert_eq! (stdout_arc.lock().unwrap().get_string(),
            "Note: no changes were made to the setup because the Node is currently running.\nNAME                      VALUE\nchain                     ropsten\nneighborhood-mode         zero-hop\n");
        assert_eq!(stderr_arc.lock().unwrap().get_string(), String::new());
    }
}
