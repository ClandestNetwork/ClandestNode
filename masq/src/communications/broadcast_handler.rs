// Copyright (c) 2019-2020, MASQ (https://masq.ai). All rights reserved.

use masq_lib::ui_gateway::MessageBody;
use std::io::Write;
use crate::commands::setup_command::SetupCommand;
use crossbeam_channel::{Sender, Receiver, unbounded, RecvError};
use std::thread::JoinHandle;
use std::thread;
use std::fmt::Debug;

pub struct BroadcastHandle {
    message_tx: Sender<MessageBody>,
    stop_tx: Sender<()>,
    stopper: JoinHandle<()>,
}

impl BroadcastHandle {
    pub fn send(&self, message_body: MessageBody) -> () {
        self.message_tx.send (message_body).expect ("Message send failed")
    }

    pub fn stop(self) -> () {
        self.stop_tx.send (()).expect ("Stop send failed");
        let join_result = self.stopper.join();
        match join_result {
            Ok (_) => (),
            Err (e) => panic! ("{:?}", e),
        }
    }
}

pub trait BroadcastHandler {
    fn start (&self, stream_factory: Box<dyn StreamFactory>) -> BroadcastHandle;
}

pub struct BroadcastHandlerReal {
    message_rx: Receiver<MessageBody>,
    stop_rx: Receiver<()>,
}

impl BroadcastHandler for BroadcastHandlerReal {
    fn start (&self, stream_factory: Box<dyn StreamFactory>) -> BroadcastHandle {
        let (message_tx, message_rx) = unbounded();
        let (stop_tx, stop_rx) = unbounded();
        let stopper = thread::spawn (move || {
            let (mut stdout, mut stderr) = stream_factory.make();
            while Self::thread_loop_guts(&message_rx, &stop_rx, stdout.as_mut(), stderr.as_mut()) {
            }
        });
        BroadcastHandle { message_tx, stop_tx, stopper }
    }
}

impl BroadcastHandlerReal {
    pub fn new () -> Self {
        Self {
            message_rx: unbounded().1,
            stop_rx: unbounded().1,
        }
    }

    fn thread_loop_guts(message_rx: &Receiver<MessageBody>, stop_rx: &Receiver<()>, stdout: &mut dyn Write, stderr: &mut dyn Write) -> bool {
        let mut retflag = true;
        select! {
            recv(message_rx) -> message_body_result => {
                Self::handle_message_body (message_body_result, stdout, stderr);
            },
            recv(stop_rx) -> _ => {
                retflag = false;
            },
        }
        retflag
    }

    fn handle_message_body (message_body_result: Result<MessageBody, RecvError>, stdout: &mut dyn Write, stderr: &mut dyn Write) {
        let message_body = message_body_result.expect ("Message from beyond the grave");
        match message_body.opcode.as_str() {
            "setup" => {
                SetupCommand::handle_broadcast (message_body, stdout, stderr)
            },
            opcode => {
                write! (stderr, "Discarding unrecognized broadcast with opcode '{}'\n\nmasq> ", opcode).expect ("write! failed");
            },
        }
    }
}

pub trait BroadcastHandlerOld: Send {
    fn handle(&self, message_body: MessageBody) -> ();
}

pub struct BroadcastHandlerRealOld {
    stream_factory: Box<dyn StreamFactory>,
}

impl BroadcastHandlerOld for BroadcastHandlerRealOld {
    fn handle(&self, message_body: MessageBody) -> () {
        panic! ("No provision made for receiving '{}' message as broadcast", message_body.opcode)
    }
}

impl BroadcastHandlerRealOld {
    pub fn new(stream_factory: Box<dyn StreamFactory>) -> Self {
        Self {
            stream_factory,
        }
    }
}

pub trait StreamFactory: Send + Debug {
    fn make (&self) -> (Box<dyn Write>, Box<dyn Write>);
}

#[derive (Clone, PartialEq, Debug)]
pub struct StreamFactoryReal {}

impl StreamFactory for StreamFactoryReal {
    fn make(&self) -> (Box<dyn Write>, Box<dyn Write>) {
        (Box::new (std::io::stdout()), Box::new (std::io::stderr()))
    }
}

impl StreamFactoryReal {
    pub fn new () -> Self {
        Self{}
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io;
    use std::cell::RefCell;
    use masq_lib::ui_gateway::MessagePath;
    use masq_lib::messages::UiSetupBroadcast;
    use masq_lib::messages::ToMessageBody;
    use crossbeam_channel::TryRecvError;
    use std::time::Duration;
    use crate::test_utils::mocks::TestStreamFactory;

    #[test]
    fn broadcast_of_setup_triggers_correct_handler() {
        let (factory, handle) = TestStreamFactory::new();
        let subject = BroadcastHandlerReal::new().start (Box::new (factory));
        let message = UiSetupBroadcast{
            running: true,
            values: vec![],
            errors: vec![]
        }.tmb(0);

        subject.send (message);

        let stdout = handle.stdout_so_far();
        subject.stop();
        assert_eq! (stdout.contains ("the Node is currently running"), true, "stdout: '{}' doesn't contain 'the Node is currently running'", stdout);
        assert_eq! (stdout.contains ("masq> "), true, "stdout: '{}' doesn't contain 'masq> '", stdout);
        assert_eq! (handle.stderr_so_far(), "".to_string(), "stderr: '{}'", stdout);
    }

    #[test]
    fn unexpected_broadcasts_are_ineffectual_but_dont_kill_the_handler () {
        let (factory, handle) = TestStreamFactory::new();
        let subject = BroadcastHandlerReal::new().start (Box::new (factory));
        let bad_message = MessageBody {
            opcode: "unrecognized".to_string(),
            path: MessagePath::FireAndForget,
            payload: (Ok("".to_string())),
        };
        let good_message = UiSetupBroadcast{
            running: true,
            values: vec![],
            errors: vec![]
        }.tmb(0);

        subject.send (bad_message);

        assert_eq! (handle.stdout_so_far(), String::new());
        assert_eq! (handle.stderr_so_far(), ("Discarding unrecognized broadcast with opcode 'unrecognized'\n\nmasq> "));

        subject.send (good_message);

        let stdout = handle.stdout_so_far();
        assert_eq! (stdout.contains ("the Node is currently running"), true, "stdout: '{}' doesn't contain 'the Node is currently running'", stdout);
        assert_eq! (handle.stderr_so_far(), String::new());
        subject.stop();
    }
}
