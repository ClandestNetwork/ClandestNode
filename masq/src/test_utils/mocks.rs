// Copyright (c) 2019-2020, MASQ (https://masq.ai) and/or its affiliates. All rights reserved.

use std::sync::{Mutex, Arc};
use std::cell::RefCell;
use crate::command_factory::{CommandFactoryError, CommandFactory};
use masq_lib::ui_gateway::{NodeFromUiMessage, NodeToUiMessage};
use masq_lib::messages::{UiShutdownOrder, UiSetup};
use lazy_static::lazy_static;
use masq_lib::messages::ToMessageBody;
use crate::commands::{CommandError, Command};
use crate::command_context::{CommandContext};
use crate::commands::CommandError::Transaction;
use crate::command_processor::{CommandProcessor, CommandProcessorFactory};
use crate::websockets_client::nfum;
use std::io::{Read, Write};
use masq_lib::test_utils::fake_stream_holder::{ByteArrayWriterInner, ByteArrayWriter};

lazy_static! {
    pub static ref ONE_WAY_MESSAGE: NodeFromUiMessage = NodeFromUiMessage {
        client_id: 0,
        body: UiShutdownOrder {}.tmb(0),
    };
    pub static ref TWO_WAY_MESSAGE: NodeFromUiMessage = NodeFromUiMessage {
        client_id: 0,
        body: UiSetup {values: vec![]}.tmb(0),
    };
}

pub struct CommandFactoryMock {
    make_params: Arc<Mutex<Vec<Vec<String>>>>,
    make_results: RefCell<Vec<Result<Box<dyn Command>, CommandFactoryError>>>,
}

impl CommandFactory for CommandFactoryMock {
    fn make(&self, pieces: Vec<String>) -> Result<Box<dyn Command>, CommandFactoryError> {
        self.make_params.lock().unwrap().push(pieces);
        self.make_results.borrow_mut().remove(0)
    }
}

impl CommandFactoryMock {
    pub fn new() -> Self {
        Self {
            make_params: Arc::new (Mutex::new (vec![])),
            make_results: RefCell::new (vec![]),
        }
    }

    pub fn make_params(mut self, params: &Arc<Mutex<Vec<Vec<String>>>>) -> Self {
        self.make_params = params.clone();
        self
    }

    pub fn make_result(self, result: Result<Box<dyn Command>, CommandFactoryError>) -> Self {
        self.make_results.borrow_mut().push (result);
        self
    }
}

pub struct CommandContextMock {
    transact_params: Arc<Mutex<Vec<NodeFromUiMessage>>>,
    transact_results: RefCell<Vec<Result<NodeToUiMessage, String>>>,
    stdout: Box<dyn Write>,
    stdout_arc: Arc<Mutex<ByteArrayWriterInner>>,
    stderr: Box<dyn Write>,
    stderr_arc: Arc<Mutex<ByteArrayWriterInner>>,
}

impl CommandContext for CommandContextMock {
    fn send(&mut self, _message: NodeFromUiMessage) -> Result<(), String> {
        unimplemented!()
    }

    fn transact(&mut self, message: NodeFromUiMessage) -> Result<NodeToUiMessage, String> {
        self.transact_params.lock().unwrap().push (message);
        self.transact_results.borrow_mut ().remove (0)
    }

    fn stdin(&mut self) -> &mut Box<dyn Read> {
        unimplemented!()
    }

    fn stdout(&mut self) -> &mut Box<dyn Write> {
        &mut self.stdout
    }

    fn stderr(&mut self) -> &mut Box<dyn Write> {
        &mut self.stderr
    }

    fn close(&mut self) {
        unimplemented!()
    }
}

impl CommandContextMock {
    pub fn new () -> Self {
        let stdout = ByteArrayWriter::new();
        let stdout_arc = stdout.inner_arc();
        let stderr = ByteArrayWriter::new();
        let stderr_arc = stderr.inner_arc();
        Self {
            transact_params: Arc::new (Mutex::new (vec![])),
            transact_results: RefCell::new (vec![]),
            stdout: Box::new (stdout),
            stdout_arc,
            stderr: Box::new (stderr),
            stderr_arc,
        }
    }

    pub fn transact_params(mut self, params: &Arc<Mutex<Vec<NodeFromUiMessage>>>) -> Self {
        self.transact_params = params.clone();
        self
    }

    pub fn transact_result(self, result: Result<NodeToUiMessage, String>) -> Self {
        self.transact_results.borrow_mut().push (result);
        self
    }

    pub fn stdout_arc(&self) -> Arc<Mutex<ByteArrayWriterInner>> {
        self.stdout_arc.clone()
    }

    pub fn stderr_arc(&self) -> Arc<Mutex<ByteArrayWriterInner>> {
        self.stderr_arc.clone()
    }
}

pub struct CommandProcessorMock {
    process_params: Arc<Mutex<Vec<Box<dyn Command>>>>,
    process_results: RefCell<Vec<Result<(), CommandError>>>,
    close_params: Arc<Mutex<Vec<()>>>,
}

impl CommandProcessor for CommandProcessorMock {
    fn process(&mut self, command: Box<dyn Command>) -> Result<(), CommandError> {
        self.process_params.lock().unwrap().push (command);
        self.process_results.borrow_mut().remove(0)
    }

    fn close(&mut self) {
        self.close_params.lock().unwrap().push (());
    }
}

impl CommandProcessorMock {
    pub fn new() -> Self {
        Self {
            process_params: Arc::new (Mutex::new (vec![])),
            process_results: RefCell::new (vec![]),
            close_params: Arc::new (Mutex::new (vec![])),
        }
    }

    pub fn process_params (mut self, params: &Arc<Mutex<Vec<Box<dyn Command>>>>) -> Self {
        self.process_params = params.clone();
        self
    }

    pub fn process_result (self, result: Result<(), CommandError>) -> Self {
        self.process_results.borrow_mut().push (result);
        self
    }

    pub fn shutdown_params (mut self, params: &Arc<Mutex<Vec<()>>>) -> Self {
        self.close_params = params.clone();
        self
    }
}

pub struct CommandProcessorFactoryMock {
    make_params: Arc<Mutex<Vec<Vec<String>>>>,
    make_results: RefCell<Vec<Box<dyn CommandProcessor>>>,
}

impl CommandProcessorFactory for CommandProcessorFactoryMock {
    fn make(&self, args: &[String]) -> Box<dyn CommandProcessor> {
        self.make_params.lock().unwrap().push (args.iter().map(|s| s.clone()).collect());
        self.make_results.borrow_mut().remove(0)
    }
}

impl CommandProcessorFactoryMock {
    pub fn new () -> Self {
        Self {
            make_params: Arc::new (Mutex::new (vec![])),
            make_results: RefCell::new (vec![]),
        }
    }

    pub fn make_params(mut self, params: &Arc<Mutex<Vec<Vec<String>>>>) -> Self {
        self.make_params = params.clone();
        self
    }

    pub fn make_result(self, result: Box<dyn CommandProcessor>) -> Self {
        self.make_results.borrow_mut().push (result);
        self
    }
}

pub struct MockCommand<T: ToMessageBody + Clone> {
    message: T,
    execute_results: RefCell<Vec<Result<(), CommandError>>>,
}

impl<T: ToMessageBody + Clone> std::fmt::Debug for MockCommand<T> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> Result<(), std::fmt::Error> {
        write! (f, "MockCommand")
    }
}

impl<T: ToMessageBody + Clone> Command for MockCommand<T> {
    fn execute(&self, context: &mut dyn CommandContext) -> Result<(), CommandError> {
        write!(context.stdout(), "MockCommand output").unwrap();
        write!(context.stderr(), "MockCommand error").unwrap();
        match context.transact(nfum(self.message.clone())) {
            Ok(_) => self.execute_results.borrow_mut().remove (0),
            Err(e) => Err(Transaction(e)),
        }
    }
}

impl<T: ToMessageBody + Clone> MockCommand<T> {
    pub fn new (message: T) -> Self {
        Self {
            message,
            execute_results: RefCell::new (vec![]),
        }
    }

    pub fn execute_result (self, result: Result<(), CommandError>) -> Self {
        self.execute_results.borrow_mut().push (result);
        self
    }
}
