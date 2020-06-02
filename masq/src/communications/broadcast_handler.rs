// Copyright (c) 2019-2020, MASQ (https://masq.ai). All rights reserved.

use masq_lib::ui_gateway::MessageBody;
use std::io::Write;

pub trait BroadcastHandler: Send {
    fn handle(&self, message_body: MessageBody) -> ();
}

pub struct BroadcastHandlerReal {
    stream_factory: Box<dyn StreamFactory>,
}

impl BroadcastHandler for BroadcastHandlerReal {
    fn handle(&self, message_body: MessageBody) -> () {
        panic! ("No provision made for receiving '{}' message as broadcast", message_body.opcode)
    }
}

impl BroadcastHandlerReal {
    pub fn new(stream_factory: Box<dyn StreamFactory>) -> Self {
        Self {
            stream_factory,
        }
    }
}

pub trait StreamFactory: Send {
    fn make (&self) -> (Box<dyn Write>, Box<dyn Write>);
}

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
    use crossbeam_channel::{Receiver, Sender, unbounded};
    use std::cell::RefCell;
    use masq_lib::ui_gateway::MessagePath;
    use masq_lib::messages::UiSetupBroadcast;
    use masq_lib::messages::ToMessageBody;

    struct TestWrite {
        write_tx: Sender<String>
    }

    impl Write for TestWrite {
        fn write(&mut self, buf: &[u8]) -> Result<usize, io::Error> {
            let len = buf.len();
            let string = String::from_utf8(buf.to_vec()).unwrap();
            self.write_tx.send(string).unwrap();
            Ok(len)
        }

        fn flush(&mut self) -> Result<(), io::Error> {
            Ok(())
        }
    }

    impl TestWrite {
        fn new (write_tx: Sender<String>) -> Self {
            Self {
                write_tx,
            }
        }
    }

    struct TestStreamFactory {
        stdout_opt: RefCell<Option<TestWrite>>,
        stderr_opt: RefCell<Option<TestWrite>>,
    }

    impl StreamFactory for TestStreamFactory {
        fn make(&self) -> (Box<dyn Write>, Box<dyn Write>) {
            let stdout = self.stdout_opt.borrow_mut().take().unwrap();
            let stderr = self.stderr_opt.borrow_mut().take().unwrap();
            (Box::new (stdout), Box::new (stderr))
        }
    }

    impl TestStreamFactory {
        fn new () -> (TestStreamFactory, TestStreamFactoryHandle) {
            let (stdout_tx, stdout_rx) = unbounded();
            let (stderr_tx, stderr_rx) = unbounded();
            let stdout = TestWrite::new (stdout_tx);
            let stderr = TestWrite::new (stderr_tx);
            let factory = TestStreamFactory {
                stdout_opt: RefCell::new (Some (stdout)),
                stderr_opt: RefCell::new (Some (stderr)),
            };
            let handle = TestStreamFactoryHandle {
                stdout_rx,
                stderr_rx,
            };
            (factory, handle)
        }
    }

    struct TestStreamFactoryHandle {
        stdout_rx: Receiver<String>,
        stderr_rx: Receiver<String>,
    }

    impl TestStreamFactoryHandle {
        pub fn stdout_so_far (&self) -> String {
            Self::text_so_far(&self.stdout_rx)
        }

        pub fn stderr_so_far (&self) -> String {
            Self::text_so_far(&self.stderr_rx)
        }

        fn text_so_far (rx: &Receiver<String>) -> String {
            let mut accum = String::new();
            loop {
                match rx.try_recv() {
                    Ok (s) => accum.extend (s.chars()),
                    Err (_) => break,
                }
            }
            accum
        }
    }

    #[test]
    #[should_panic (expected = "No provision made for receiving 'unrecognized' message as broadcast")]
    fn broadcasts_without_handlers_cause_panics() {
        let (factory, handle) = TestStreamFactory::new();
        let subject = BroadcastHandlerReal::new (Box::new (factory));
        let message = MessageBody {
            opcode: "unrecognized".to_string(),
            path: MessagePath::FireAndForget,
            payload: (Ok("".to_string())),
        };

        subject.handle (message);
    }

    #[test]
    fn broadcast_of_setup_triggers_correct_handler() {
        let (factory, handle) = TestStreamFactory::new();
        let subject = BroadcastHandlerReal::new (Box::new (factory));
        let message = UiSetupBroadcast{
            running: true,
            values: vec![],
            errors: vec![]
        }.tmb(0);

        subject.handle (message);

        let stdout = handle.stdout_so_far();
        assert_eq! (stdout.contains ("the Node is currently running."), true);
        assert_eq! (stdout.contains ("masq> "), true);
    }
}
