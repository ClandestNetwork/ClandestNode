// Copyright (c) 2019-2020, MASQ (https://masq.ai) and/or its affiliates. All rights reserved.

use crate::commands::{Command, CommandError};
use crate::command_context::CommandContextReal;
use crate::schema::app;
use clap::value_t;

pub trait CommandProcessorFactory {
    fn make(&self, args: &[String]) -> Box<dyn CommandProcessor>;
}

pub struct CommandProcessorFactoryReal {
}

impl CommandProcessorFactory for CommandProcessorFactoryReal {
    fn make(&self, args: &[String]) -> Box<dyn CommandProcessor> {
        let matches = app().get_matches_from(args);
        let ui_port = value_t!(matches, "ui-port", u16).expect ("ui-port is not properly defaulted");
        let context = CommandContextReal::new (ui_port);
        Box::new (CommandProcessorReal {
            context
        })
    }
}

impl CommandProcessorFactoryReal {
    pub fn new () -> Self {
        Self {
        }
    }
}

pub trait CommandProcessor {
    fn process (&mut self, command: Box<dyn Command>) -> Result<(), CommandError>;
    fn shutdown (&mut self);
}

pub struct CommandProcessorReal {
    #[allow (dead_code)]
    context: CommandContextReal
}

impl CommandProcessor for CommandProcessorReal {
    fn process(&mut self, _command: Box<dyn Command>) -> Result<(), CommandError> {
        unimplemented!()
    }

    fn shutdown(&mut self) {
        unimplemented!()
    }
}

impl CommandProcessorReal {
    pub fn new(_args: &Vec<String>) -> Self {
        unimplemented!()
    }
}

pub struct CommandProcessorNull {}

impl CommandProcessor for CommandProcessorNull {
    fn process(&mut self, _command: Box<dyn Command>) -> Result<(), CommandError> {
        panic!("masq was not properly initialized")
    }

    fn shutdown(&mut self) {
        panic!("masq was not properly initialized")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::commands::SetupCommand;
    use masq_lib::utils::find_free_port;
    use crate::test_utils::mock_websockets_server::MockWebSocketsServer;
    use masq_lib::ui_gateway::NodeFromUiMessage;
    use masq_lib::messages::UiShutdownOrder;
    use crate::command_context::CommandContext;
    use crate::websockets_client::nfum;
    use masq_lib::messages::ToMessageBody;

    #[test]
    #[should_panic(expected = "masq was not properly initialized")]
    fn null_command_processor_process_panics_properly() {
        let mut subject = CommandProcessorNull{};

        subject.process (Box::new (SetupCommand{values: vec![]})).unwrap();
    }

    #[test]
    #[should_panic(expected = "masq was not properly initialized")]
    fn null_command_processor_shutdown_panics_properly() {
        let mut subject = CommandProcessorNull{};

        subject.shutdown ();
    }

    #[derive (Debug)]
    struct TestCommand{}

    impl Command for TestCommand {
        fn execute<'a>(&self, context: &mut dyn CommandContext) -> Result<(), CommandError> {
            context.send (nfum(UiShutdownOrder{})).unwrap();
            Ok(())
        }
    }

    #[test]
    fn factory_parses_out_the_correct_port_when_specified() {
        let port = find_free_port();
        let args = ["masq".to_string(), "--ui-port".to_string(), format!("{}", port)];
        let subject = CommandProcessorFactoryReal::new ();
        let server = MockWebSocketsServer::new(port);
        let stop_handle = server.start();

        let mut result = subject.make (&args);

        let command = TestCommand{};
        result.process (Box::new (command)).unwrap();
        let received = stop_handle.stop();
        assert_eq! (received, vec![Ok(NodeFromUiMessage {
            client_id: 0,
            body: UiShutdownOrder{}.tmb(0),
        })]);
    }
}
