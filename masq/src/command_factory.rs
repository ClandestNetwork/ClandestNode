// Copyright (c) 2019-2020, MASQ (https://masq.ai) and/or its affiliates. All rights reserved.

use crate::commands::{Command, SetupCommand};

#[derive(Debug, PartialEq)]
pub enum CommandFactoryError {
    SyntaxError(String),
}

pub trait CommandFactory {
    fn make(&self, pieces: Vec<String>) -> Result<Box<dyn Command>, CommandFactoryError>;
}

#[derive(Default)]
pub struct CommandFactoryReal {}

impl CommandFactory for CommandFactoryReal {
    fn make(&self, pieces: Vec<String>) -> Result<Box<dyn Command>, CommandFactoryError> {
        let command = match pieces[0].as_str() {
            "setup" => Box::new (SetupCommand::new(pieces)),
            unrecognized => unimplemented!("Unrecognized subcommand: '{}'", unrecognized)
        };
        Ok(command)
    }
}

impl CommandFactoryReal {
    #[allow(dead_code)]
    pub fn new() -> Self {
        Self::default()
    }
}
