// Copyright (c) 2019-2020, MASQ (https://masq.ai) and/or its affiliates. All rights reserved.

use std::fmt::Debug;
use crate::command_context::{CommandContext, ContextError};
use std::collections::HashMap;
use masq_lib::messages::{FromMessageBody, ToMessageBody, UiSetup, UiSetupValue, UiMessageError, UiStartOrder, UiStartResponse, UiShutdownOrder};
use masq_lib::ui_gateway::{NodeFromUiMessage, NodeToUiMessage};
use crate::commands::CommandError::{ConnectionDropped, Transmission, UnexpectedResponse, Other, Payload};
use std::thread;
use std::time::Duration;

#[derive (Debug, PartialEq)]
pub enum CommandError {
    ConnectionDropped,
    Transmission(String),
    Reception(String),
    UnexpectedResponse(UiMessageError),
    Payload(u64, String),
    Other(String),
}

pub trait Command: Debug {
    fn execute(&self, context: &mut dyn CommandContext) -> Result<(), CommandError>;
}

#[derive (Debug, PartialEq)]
pub struct SetupCommand {
    pub values: HashMap<String, String>,
}

impl Command for SetupCommand {
    fn execute(&self, context: &mut dyn CommandContext) -> Result<(), CommandError> {
        let mut values: Vec<UiSetupValue> = self.values.iter()
            .map (|(name, value)| UiSetupValue::new (name, value))
            .collect();
        values.sort_by(|a, b| a.name.partial_cmp(&b.name).expect("String comparison failed"));
        let out_message = UiSetup {
            values
        };
        let result: Result<UiSetup, CommandError> = two_way_transaction (out_message, context);
        match result {
            Ok(mut response) => {
                response.values
                    .sort_by(|a, b| a.name.partial_cmp(&b.name).expect("String comparison failed"));
                writeln!(context.stdout(), "NAME                      VALUE").expect ("write! failed");
                response.values.into_iter()
                    .for_each (|value| writeln!(context.stdout(), "{:26}{}", value.name, value.value).expect ("write! failed"));
                Ok(())
            },
            Err(e) => Err(e),
        }
    }
}

impl SetupCommand {
    pub fn new (pieces: Vec<String>) -> Self {
        let values = pieces.into_iter()
            .skip(1)
            .map(|attr| {
                let pair: Vec<&str> = attr.split ('=').collect();
                (pair[0].to_string(), pair[1].to_string())
            })
            .collect::<HashMap<String, String>> ();
        Self {
            values
        }
    }

    pub fn validator (value: String) -> Result<(), String> {
        if value.starts_with ('=') || value.ends_with ('=') || !value.contains ('=') {
            Err(format!("Attribute syntax: <name>=<value>, not {}", value))
        }
        else {
            Ok(())
        }
    }
}

#[derive (Debug, PartialEq, Default)]
pub struct StartCommand {}

impl Command for StartCommand {
    fn execute(&self, context: &mut dyn CommandContext) -> Result<(), CommandError> {
        let out_message = UiStartOrder {};
        let result: Result<UiStartResponse, CommandError> = two_way_transaction (out_message, context);
        match result {
            Ok(response) => {
                writeln!(context.stdout(), "MASQNode successfully started as process {}, listening for UIs on port {}", response.new_process_id, response.redirect_ui_port).expect("write! failed");
                Ok(())
            },
            Err(e) => Err(e),
        }
    }
}

impl StartCommand {
    pub fn new () -> Self {
        Self::default()
    }
}

const DEFAULT_SHUTDOWN_ATTEMPT_INTERVAL: u64 = 250; // milliseconds
const DEFAULT_SHUTDOWN_ATTEMPT_LIMIT: u64 = 4; // milliseconds

#[derive (Debug, PartialEq)]
pub struct ShutdownCommand {
    attempt_interval: u64,
    attempt_limit: u64,
}

impl Command for ShutdownCommand {
    fn execute(&self, context: &mut dyn CommandContext) -> Result<(), CommandError> {
        let mut attempts_remaining = self.attempt_limit;
        let input = UiShutdownOrder {};
        loop {
            match one_way_transmission(input.clone(), context) {
                Ok(_) => (),
                Err(ConnectionDropped) => {
                    writeln! (context.stdout(), "MASQNode was instructed to shut down and has broken its connection").expect ("write! failed");
                    return Ok (())
                },
                Err(Transmission(msg)) => {
                    return Err(Transmission(msg))
                },
                Err(impossible) => panic!("Never happen: {:?}", impossible),
            }
            thread::sleep (Duration::from_millis(self.attempt_interval));
            attempts_remaining -= 1;
            if attempts_remaining == 0 {
                writeln! (context.stderr(), "MASQNode ignored the instruction to shut down and is still running").expect ("write! failed");
                return Err(Other("Shutdown failed".to_string()))
            }
        }
    }
}

impl Default for ShutdownCommand {
    fn default() -> Self {
        Self{
            attempt_interval: DEFAULT_SHUTDOWN_ATTEMPT_INTERVAL,
            attempt_limit: DEFAULT_SHUTDOWN_ATTEMPT_LIMIT,
        }
    }
}

impl ShutdownCommand {
    pub fn new () -> Self {
        Self::default()
    }
}

fn one_way_transmission<I> (input: I, context: &mut dyn CommandContext) -> Result<(), CommandError> where I: ToMessageBody {
    match context.send (NodeFromUiMessage {
        client_id: 0,
        body: input.tmb(0)
    }) {
        Ok(_) => Ok(()),
        Err(ContextError::ConnectionDropped(_)) => {
            Err(ConnectionDropped)
        },
        Err(ContextError::PayloadError(code, message)) => {
            panic! ("A one-way message should never produce a two-way error like PayloadError({}, {})", code, message)
        },
        Err(ContextError::Other(msg)) => {
            writeln!(context.stderr(), "Couldn't send command to Node or Daemon: {}", msg).expect("write! failed");
            Err(Transmission(msg))
        },
    }
}

fn two_way_transaction<I, O> (input: I, context: &mut dyn CommandContext) -> Result<O, CommandError> where I: ToMessageBody, O: FromMessageBody {
    let ntum: NodeToUiMessage = match context.transact (NodeFromUiMessage {
        client_id: 0,
        body: input.tmb(0)
    }) {
        Ok(ntum) => ntum,
        Err(ContextError::ConnectionDropped(_)) => {
            return Err(ConnectionDropped)
        },
        Err(ContextError::PayloadError(code, message)) => {
            return Err(Payload(code, message))
        },
        Err(ContextError::Other(msg)) => {
            writeln!(context.stderr(), "Couldn't send command to Node or Daemon: {}", msg).expect ("write! failed");
            return Err(Transmission(msg))
        },
    };
    let response: O = match O::fmb (ntum.body) {
        Ok ((r, _)) => r,
        Err (e) => {
            writeln!(context.stderr(), "Node or Daemon is acting erratically: {}", e).expect ("write! failed");
            return Err(UnexpectedResponse(e))
        }
    };
    Ok(response)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_utils::mocks::CommandContextMock;
    use std::sync::{Mutex, Arc};
    use masq_lib::ui_gateway::{NodeToUiMessage, NodeFromUiMessage, MessageBody};
    use masq_lib::ui_gateway::MessageTarget::ClientId;
    use crate::commands::CommandError::{Transmission, UnexpectedResponse, Payload, Other};
    use masq_lib::messages::{UiShutdownOrder, UiStartResponse, UiStartOrder};
    use masq_lib::ui_gateway::MessagePath::{TwoWay};
    use crate::command_context::ContextError;
    use std::time::SystemTime;

    #[test]
    fn one_way_transmission_passes_dropped_connection_error() {
        let mut context = CommandContextMock::new()
            .send_result (Err(ContextError::ConnectionDropped("booga".to_string())));

        let result = one_way_transmission(UiShutdownOrder{}, &mut context);

        assert_eq! (result, Err(ConnectionDropped));
    }

    #[test]
    #[should_panic(expected = "A one-way message should never produce a two-way error like PayloadError(10, booga)")]
    fn one_way_transmission_panics_on_two_way_error() {
        let mut context = CommandContextMock::new()
            .send_result (Err(ContextError::PayloadError(10, "booga".to_string())));

        let _ = one_way_transmission(UiShutdownOrder{}, &mut context);
    }

    #[test]
    fn one_way_transmission_passes_other_error() {
        let mut context = CommandContextMock::new()
            .send_result (Err(ContextError::Other("booga".to_string())));
        let stdout_arc = context.stdout_arc();
        let stderr_arc = context.stderr_arc();

        let result = one_way_transmission(UiShutdownOrder{}, &mut context);

        assert_eq! (result, Err(Transmission("booga".to_string())));
        assert_eq! (stdout_arc.lock().unwrap().get_string(), String::new());
        assert_eq! (stderr_arc.lock().unwrap().get_string(), "Couldn't send command to Node or Daemon: booga\n".to_string());
    }

    #[test]
    fn two_way_transaction_passes_dropped_connection_error () {
        let mut context = CommandContextMock::new()
            .transact_result (Err(ContextError::ConnectionDropped("booga".to_string())));

        let result: Result<UiStartResponse, CommandError>  = two_way_transaction(UiStartOrder{}, &mut context);

        assert_eq! (result, Err(ConnectionDropped));
    }

    #[test]
    fn two_way_transaction_passes_payload_error () {
        let mut context = CommandContextMock::new()
            .transact_result (Err(ContextError::PayloadError(10, "booga".to_string())));

        let result: Result<UiStartResponse, CommandError>  = two_way_transaction(UiStartOrder{}, &mut context);

        assert_eq! (result, Err(Payload(10, "booga".to_string())));
    }

    #[test]
    fn two_way_transaction_passes_other_error() {
        let mut context = CommandContextMock::new()
            .transact_result (Err(ContextError::Other("booga".to_string())));
        let stdout_arc = context.stdout_arc();
        let stderr_arc = context.stderr_arc();

        let result: Result<UiStartResponse, CommandError>  = two_way_transaction(UiStartOrder{}, &mut context);

        assert_eq! (result, Err(Transmission("booga".to_string())));
        assert_eq! (stdout_arc.lock().unwrap().get_string(), String::new());
        assert_eq! (stderr_arc.lock().unwrap().get_string(), "Couldn't send command to Node or Daemon: booga\n".to_string());
    }

    #[test]
    fn two_way_transaction_handles_deserialization_error() {
        let mut context = CommandContextMock::new()
            .transact_result (Ok(NodeToUiMessage {
                target: ClientId(0),
                body: MessageBody {
                    opcode: "booga".to_string(),
                    path: TwoWay(1234),
                    payload: Ok ("unparseable".to_string())
                }
            }));
        let stdout_arc = context.stdout_arc();
        let stderr_arc = context.stderr_arc();

        let result: Result<UiStartResponse, CommandError>  = two_way_transaction(UiStartOrder{}, &mut context);

        assert_eq! (result, Err(UnexpectedResponse(UiMessageError::UnexpectedMessage("booga".to_string(), TwoWay(1234)))));
        assert_eq! (stdout_arc.lock().unwrap().get_string(), String::new());
        assert_eq! (stderr_arc.lock().unwrap().get_string(), "Node or Daemon is acting erratically: Unexpected two-way message from context 1234 with opcode 'booga'\n".to_string());
    }

    #[test]
    fn setup_command_validator_rejects_arg_without_equals() {
        let result = SetupCommand::validator ("noequals".to_string());

        assert_eq! (result, Err("Attribute syntax: <name>=<value>, not noequals".to_string()));
    }

    #[test]
    fn setup_command_validator_rejects_arg_with_initial_equals() {
        let result = SetupCommand::validator ("=initialequals".to_string());

        assert_eq! (result, Err("Attribute syntax: <name>=<value>, not =initialequals".to_string()));
    }

    #[test]
    fn setup_command_validator_rejects_arg_with_terminal_equals() {
        let result = SetupCommand::validator ("terminalequals=".to_string());

        assert_eq! (result, Err("Attribute syntax: <name>=<value>, not terminalequals=".to_string()));
    }

    #[test]
    fn setup_command_validator_accepts_valid_attribute() {
        let result = SetupCommand::validator ("central=equals".to_string());

        assert_eq! (result, Ok(()));
    }

    #[test]
    fn setup_command_happy_path () {
        let transact_params_arc = Arc::new (Mutex::new (vec![]));
        let mut context = CommandContextMock::new()
            .transact_params(&transact_params_arc)
            .transact_result (Ok (NodeToUiMessage {
                target: ClientId(0),
                body: UiSetup {
                    values: vec![
                        UiSetupValue::new ("c", "3"),
                        UiSetupValue::new ("dddd", "4444"),
                    ]
                }.tmb (0)
            }));
        let stdout_arc = context.stdout_arc();
        let stderr_arc = context.stderr_arc();
        let subject = SetupCommand::new (vec!["setup".to_string(), "a=1".to_string(), "bbbb=2222".to_string()]);

        let result = subject.execute (&mut context);

        assert_eq! (result, Ok(()));
        let transact_params = transact_params_arc.lock().unwrap();
        assert_eq! (*transact_params, vec![NodeFromUiMessage {
            client_id: 0,
            body: UiSetup {
                values: vec![
                    UiSetupValue::new ("a", "1"),
                    UiSetupValue::new ("bbbb", "2222"),
                ]
            }.tmb(0)
        }]);
        assert_eq! (stdout_arc.lock().unwrap().get_string(),
            "NAME                      VALUE\nc                         3\ndddd                      4444\n");
        assert_eq! (stderr_arc.lock().unwrap().get_string(), String::new());
    }

    #[test]
    fn start_command_happy_path () {
        let transact_params_arc = Arc::new (Mutex::new (vec![]));
        let mut context = CommandContextMock::new()
            .transact_params(&transact_params_arc)
            .transact_result (Ok (NodeToUiMessage {
                target: ClientId(0),
                body: UiStartResponse {
                    new_process_id: 1234,
                    redirect_ui_port: 4321,
                }.tmb (0)
            }));
        let stdout_arc = context.stdout_arc();
        let stderr_arc = context.stderr_arc();
        let subject = StartCommand::new ();

        let result = subject.execute (&mut context);

        assert_eq! (result, Ok(()));
        let transact_params = transact_params_arc.lock().unwrap();
        assert_eq! (*transact_params, vec![NodeFromUiMessage {
            client_id: 0,
            body: UiStartOrder {}.tmb(0)
        }]);
        assert_eq! (stdout_arc.lock().unwrap().get_string(),
                    "MASQNode successfully started as process 1234, listening for UIs on port 4321\n");
        assert_eq! (stderr_arc.lock().unwrap().get_string(), String::new());
    }

    #[test]
    fn shutdown_command_defaults_parameters() {
        let subject = ShutdownCommand::new();

        assert_eq! (subject.attempt_interval, DEFAULT_SHUTDOWN_ATTEMPT_INTERVAL);
        assert_eq! (subject.attempt_limit, DEFAULT_SHUTDOWN_ATTEMPT_LIMIT);
    }

    #[test]
    fn shutdown_command_happy_path () {
        let send_params_arc = Arc::new (Mutex::new (vec![]));
        let mut context = CommandContextMock::new()
            .send_params(&send_params_arc)
            .send_result (Ok (()))
            .send_result (Ok (()))
            .send_result (Err(ContextError::ConnectionDropped("booga".to_string())));
        let stdout_arc = context.stdout_arc();
        let stderr_arc = context.stderr_arc();
        let mut subject = ShutdownCommand::new ();
        subject.attempt_interval = 10;
        subject.attempt_limit = 3;

        let result = subject.execute (&mut context);

        assert_eq! (result, Ok(()));
        let send_params = send_params_arc.lock().unwrap();
        assert_eq! (*send_params, vec![
            NodeFromUiMessage {
                client_id: 0,
                body: UiShutdownOrder {}.tmb(0)
            },
            NodeFromUiMessage {
                client_id: 0,
                body: UiShutdownOrder {}.tmb(0)
            },
            NodeFromUiMessage {
                client_id: 0,
                body: UiShutdownOrder {}.tmb(0)
            },
        ]);
        assert_eq! (stdout_arc.lock().unwrap().get_string(),
                    "MASQNode was instructed to shut down and has broken its connection\n");
        assert_eq! (stderr_arc.lock().unwrap().get_string(), String::new());
    }

    #[test]
    fn shutdown_command_uses_interval() {
        let mut context = CommandContextMock::new()
            .send_result (Ok (()));
        let stdout_arc = context.stdout_arc();
        let stderr_arc = context.stderr_arc();
        let mut subject = ShutdownCommand::new ();
        subject.attempt_interval = 100;
        subject.attempt_limit = 1;
        let before = SystemTime::now();

        let result = subject.execute (&mut context);

        let after = SystemTime::now();
        assert_eq! (result, Err(Other("Shutdown failed".to_string())));
        let interval = after.duration_since(before).unwrap().as_millis();
        assert! (interval >= subject.attempt_interval as u128, "Not waiting long enough per attempt: {} < {}", interval, subject.attempt_interval);
        assert! (interval < (subject.attempt_interval as u128 * 2), "Waiting too long per attempt: {} >> {}", interval, subject.attempt_interval);
        assert_eq! (stdout_arc.lock().unwrap().get_string(), String::new());
        assert_eq! (stderr_arc.lock().unwrap().get_string(),
                    "MASQNode ignored the instruction to shut down and is still running\n");
    }
}
