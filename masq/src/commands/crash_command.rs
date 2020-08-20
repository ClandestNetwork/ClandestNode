// Copyright (c) 2019-2020, MASQ (https://masq.ai) and/or its affiliates. All rights reserved.

use crate::command_context::CommandContext;
use crate::commands::commands_common::{send, Command, CommandError};
use clap::{App, SubCommand};
use masq_lib::messages::UiCrashRequest;
use std::fmt::Debug;

#[derive(Debug)]
pub struct CrashCommand {
    panic_message: String,
}

pub fn crash_subcommand() -> App<'static, 'static> {
    SubCommand::with_name("crash")
        .about("Causes the Node to crash with a specified message. Only valid if the Node has been started with --crash-point message")
}

impl Command for CrashCommand {
    fn execute(&self, context: &mut dyn CommandContext) -> Result<(), CommandError> {
        let input = UiCrashRequest {
            panic_message: self.panic_message.clone(),
        };
        let result = send(input, context);
        match result {
            Ok(_) => Ok(()),
            Err(e) => Err(e.into()),
        }
    }
}

impl CrashCommand {
    pub fn new(panic_message: &str) -> Self {
        Self {
            panic_message: panic_message.to_string(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::command_context::ContextError;
    use crate::command_factory::{CommandFactory, CommandFactoryReal};
    use crate::test_utils::mocks::CommandContextMock;
    use masq_lib::messages::ToMessageBody;
    use std::sync::{Arc, Mutex};

    #[test]
    fn testing_command_factory_here() {
        let factory = CommandFactoryReal::new();
        let mut context = CommandContextMock::new().send_result(Ok(()));
        let subject = factory
            .make(vec!["crash".to_string(), "panic message".to_string()])
            .unwrap();

        let result = subject.execute(&mut context);

        assert_eq!(result, Ok(()));
    }

    #[test]
    fn crash_command_with_a_message() {
        let send_params_arc = Arc::new(Mutex::new(vec![]));
        let mut context = CommandContextMock::new()
            .send_params(&send_params_arc)
            .send_result(Ok(()));
        let stdout_arc = context.stdout_arc();
        let stderr_arc = context.stderr_arc();
        let factory = CommandFactoryReal::new();
        let subject = factory
            .make(vec!["crash".to_string(), "These are the times".to_string()])
            .unwrap();

        let result = subject.execute(&mut context);

        assert_eq!(result, Ok(()));
        assert_eq!(stdout_arc.lock().unwrap().get_string(), String::new());
        assert_eq!(stderr_arc.lock().unwrap().get_string(), String::new());
        let send_params = send_params_arc.lock().unwrap();
        assert_eq!(
            *send_params,
            vec![UiCrashRequest {
                panic_message: "These are the times".to_string()
            }
            .tmb(0)]
        )
    }

    #[test]
    fn crash_command_without_a_message() {
        let send_params_arc = Arc::new(Mutex::new(vec![]));
        let mut context = CommandContextMock::new()
            .send_params(&send_params_arc)
            .send_result(Ok(()));
        let stdout_arc = context.stdout_arc();
        let stderr_arc = context.stderr_arc();
        let factory = CommandFactoryReal::new();
        let subject = factory.make(vec!["crash".to_string()]).unwrap();

        let result = subject.execute(&mut context);

        assert_eq!(result, Ok(()));
        assert_eq!(stdout_arc.lock().unwrap().get_string(), String::new());
        assert_eq!(stderr_arc.lock().unwrap().get_string(), String::new());
        let send_params = send_params_arc.lock().unwrap();
        assert_eq!(
            *send_params,
            vec![UiCrashRequest {
                panic_message: "Intentional crash".to_string()
            }
            .tmb(0)]
        )
    }

    #[test]
    fn crash_command_handles_send_failure() {
        let mut context = CommandContextMock::new()
            .send_result(Err(ContextError::ConnectionDropped("blah".to_string())));
        let subject = CrashCommand::new("message");

        let result = subject.execute(&mut context);

        assert_eq!(
            result,
            Err(CommandError::ConnectionProblem("blah".to_string()))
        )
    }
}
