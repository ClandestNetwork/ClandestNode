// Copyright (c) 2019-2020, MASQ (https://masq.ai). All rights reserved.

use masq_lib::ui_gateway::{MessageBody, MessagePath};
use crate::communications::node_connection::ClientError;
use crossbeam_channel::{Sender, Receiver};

pub enum NodeConversationTermination {
    Graceful,
    AttemptReconnect,
    Fatal,
}

pub struct NodeConversation {
    context_id: u64,
    message_body_send_tx: Sender<Result<MessageBody, u64>>,
    message_body_receive_rx: Receiver<Result<MessageBody, NodeConversationTermination>>,
}

impl NodeConversation {
    pub fn new (context_id: u64, message_body_send_tx: Sender<Result<MessageBody, u64>>, message_body_receive_rx: Receiver<Result<MessageBody, NodeConversationTermination>>) -> Self {
        Self {
            context_id,
            message_body_send_tx,
            message_body_receive_rx,
        }
    }

    pub fn context_id(&self) -> u64 {
        self.context_id
    }

    pub fn transact(&self, mut outgoing_msg: MessageBody) -> Result<MessageBody, ClientError> {
eprint! ("transact called: {:?}", outgoing_msg);
        outgoing_msg.path = MessagePath::Conversation(self.context_id());
        let result = match self.message_body_send_tx.send (Ok(outgoing_msg)) {
            Ok (_) => match self.message_body_receive_rx.recv() {
                Ok(Ok(body)) => Ok(body),
                Ok(Err(NodeConversationTermination::Graceful)) => Err(ClientError::ConnectionDropped(String::new())),
                Ok(Err(NodeConversationTermination::AttemptReconnect)) => unimplemented!("AttemptReconnect"),
                Ok(Err(NodeConversationTermination::Fatal)) => unimplemented!("Fatal"),
                Err(e) => Err(ClientError::ConnectionDropped(String::new())),
            },
            Err (e) => Err(ClientError::ConnectionDropped(String::new())),
        };
eprintln! (" -> {:?}", result);
        result
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crossbeam_channel::unbounded;
    use masq_lib::messages::{UiShutdownResponse, UiShutdownRequest};
    use masq_lib::messages::ToMessageBody;

    #[test]
    fn handles_successful_transaction () {
        let (message_body_send_tx, message_body_send_rx) = unbounded();
        let (message_body_receive_tx, message_body_receive_rx) = unbounded();
        let subject = NodeConversation::new (42, message_body_send_tx, message_body_receive_rx);
        message_body_receive_tx.send(Ok (UiShutdownResponse{}.tmb(42))).unwrap();

        let result = subject.transact (UiShutdownRequest{}.tmb(0)).unwrap();

        assert_eq! (result, UiShutdownResponse{}.tmb(42));
        let outgoing_message = message_body_send_rx.recv().unwrap().unwrap();
        assert_eq! (outgoing_message, UiShutdownRequest{}.tmb(42));
    }

    #[test]
    fn handles_gracefully_closed_conversation () {
        let (message_body_send_tx, message_body_send_rx) = unbounded();
        let (message_body_receive_tx, message_body_receive_rx) = unbounded();
        let subject = NodeConversation::new (42, message_body_send_tx, message_body_receive_rx);
        message_body_receive_tx.send(Err(NodeConversationTermination::Graceful)).unwrap();

        let result = subject.transact (UiShutdownRequest{}.tmb(0)).err().unwrap();

        assert_eq! (result, ClientError::ConnectionDropped(String::new()));
    }

    #[test]
    fn handles_broken_connection() {
        unimplemented!()
    }

    #[test]
    fn handles_send_error () {
        let (message_body_send_tx, _) = unbounded();
        let (_, message_body_receive_rx) = unbounded();
        let subject = NodeConversation::new (42, message_body_send_tx, message_body_receive_rx);

        let result = subject.transact (UiShutdownRequest{}.tmb(0)).err().unwrap();

        assert_eq! (result, ClientError::ConnectionDropped(String::new()));
    }

    #[test]
    fn handles_receive_error () {
        let (message_body_send_tx, message_body_send_rx) = unbounded();
        let (_, message_body_receive_rx) = unbounded();
        let subject = NodeConversation::new (42, message_body_send_tx, message_body_receive_rx);

        let result = subject.transact (UiShutdownRequest{}.tmb(0)).err().unwrap();

        assert_eq! (result, ClientError::ConnectionDropped(String::new()));
    }
}