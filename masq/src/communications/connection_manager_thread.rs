// Copyright (c) 2019-2020, MASQ (https://masq.ai). All rights reserved.

use crossbeam_channel::{Sender, Receiver, RecvError};
use std::collections::HashMap;
use masq_lib::ui_gateway::{MessageBody, MessagePath};
use websocket::sender::Writer;
use std::net::TcpStream;
use crate::communications::node_conversation::NodeConversation;
use std::thread;
use crate::communications::client_listener_thread::ClientListenerError;
use crossbeam_channel::unbounded;
use websocket::ws::sender::Sender as WsSender;
use masq_lib::ui_traffic_converter::UiTrafficConverter;
use websocket::OwnedMessage;

struct CmsInner {
    conversations: HashMap<u64, Sender<Option<MessageBody>>>,
    next_context_id: u64,
    conversation_trigger_rx: Receiver<()>,
    conversation_return_tx: Sender<NodeConversation>,
    listener_to_manager_rx: Receiver<Result<MessageBody, ClientListenerError>>,
    conversations_to_manager_tx: Sender<Result<MessageBody, u64>>,
    conversations_to_manager_rx: Receiver<Result<MessageBody, u64>>,
    talker_half: Writer<TcpStream>,
}

pub struct ConnectionManagerThread {
    inner_opt: Option<CmsInner>
}

impl ConnectionManagerThread {
    pub fn new(conversation_trigger_rx: Receiver<()>, conversation_return_tx: Sender<NodeConversation>, listener_to_manager_rx: Receiver<Result<MessageBody, ClientListenerError>>, talker_half: Writer<TcpStream>) -> Self {
        let (conversations_to_manager_tx, conversations_to_manager_rx) = unbounded();
        let inner = CmsInner {
            conversations: HashMap::new(),
            next_context_id: 1,
            conversation_trigger_rx,
            conversation_return_tx,
            listener_to_manager_rx,
            conversations_to_manager_tx,
            conversations_to_manager_rx,
            talker_half
        };
        ConnectionManagerThread {
            inner_opt: Some(inner),
        }
    }

    pub fn start(mut self) {
        let mut inner = self.inner_opt.take().expect("Inner disappeared!");
        thread::spawn (move || {
            loop {
                select! {
                    recv(inner.conversation_trigger_rx) -> _ => Self::handle_conversation_trigger (&mut inner),
                    recv(inner.listener_to_manager_rx) -> message_body_result_result => Self::handle_incoming_message_body (&mut inner, message_body_result_result),
                    recv(inner.conversations_to_manager_rx) -> message_body_result_result => Self::handle_outgoing_message_body (&mut inner, message_body_result_result),
                }
            }
        });
    }

    fn handle_conversation_trigger (inner: &mut CmsInner) {
        let (manager_to_conversation_tx, manager_to_conversation_rx) = unbounded();
        let context_id = inner.next_context_id;
        inner.next_context_id += 1;
        let conversation = NodeConversation::new (context_id, inner.conversations_to_manager_tx.clone(), manager_to_conversation_rx);
        inner.conversations.insert (context_id, manager_to_conversation_tx);
        match inner.conversation_return_tx.send (conversation) {
            Ok(_) => (),
            Err (e) => unimplemented! ("{:?}", e),
        }
    }

    fn handle_incoming_message_body (inner: &mut CmsInner, msg_result_result: Result<Result<MessageBody, ClientListenerError>, RecvError>) {
        match msg_result_result {
            Ok (msg_result) => match msg_result {
                Ok(message_body) => match message_body.path {
                    MessagePath::Conversation(context_id) => match inner.conversations.get(&context_id) {
                        Some(sender) => match sender.send(Some(message_body)) {
                            Ok(_) => (),
                            Err(e) => unimplemented!("{:?}", e),
                        },
                        None => unimplemented!(),
                    },
                    MessagePath::FireAndForget => unimplemented!(),
                },
                Err(e) => unimplemented!("{:?}", e),
            },
            Err (e) => unimplemented!("{:?}", e),
        }
    }

    fn handle_outgoing_message_body (inner: &mut CmsInner, msg_result_result: Result<Result<MessageBody, u64>, RecvError>) {
        match msg_result_result {
            Ok(msg_opt) => match msg_opt {
                Ok(message_body) => match inner.talker_half.sender.send_message(&mut inner.talker_half.stream, &OwnedMessage::Text(UiTrafficConverter::new_marshal(message_body))) {
                    Ok(_) => (),
                    Err(e) => unimplemented!("{:?}", e),
                },
                Err(context_id) => unimplemented!("{}", context_id),
            },
            Err(e) => unimplemented!("{:?}", e),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_utils::client_utils::make_client;
    use masq_lib::utils::find_free_port;
    use crate::test_utils::mock_websockets_server::{MockWebSocketsServer, MockWebSocketsServerStopHandle};
    use masq_lib::messages::{UiShutdownResponse, UiShutdownRequest, UiStartResponse, UiStartOrder};
    use std::thread;
    use masq_lib::messages::ToMessageBody;
    use crate::communications::client_listener_thread::ClientListenerThread;

    fn make_subject (server: MockWebSocketsServer) -> (ConnectionManagerThread, Sender<()>, Receiver<NodeConversation>, MockWebSocketsServerStopHandle) {
        let port = server.port();
        let (conversation_trigger_tx, conversation_trigger_rx) = unbounded();
        let (conversation_return_tx, conversation_return_rx) = unbounded();
        let (message_body_tx, message_body_rx) = unbounded();
        let stop_handle = server.start();
        let client = make_client(port);
        let (listener_half, talker_half) = client.split().unwrap();
        let client_listener_thread = ClientListenerThread::new(listener_half, message_body_tx);
        client_listener_thread.start();
        let subject = ConnectionManagerThread::new (conversation_trigger_rx, conversation_return_tx, message_body_rx, talker_half);
        (subject, conversation_trigger_tx, conversation_return_rx, stop_handle)
    }

    #[test]
    fn handles_interleaved_conversations () {
        let server = MockWebSocketsServer::new(find_free_port())
            .queue_response (UiShutdownResponse{}.tmb(2))
            .queue_response (UiShutdownResponse{}.tmb(1))
            .queue_response (UiStartResponse{new_process_id: 11, redirect_ui_port: 12}.tmb(1))
            .queue_response (UiStartResponse{new_process_id: 21, redirect_ui_port: 22}.tmb(2));
        let (subject, conversation_trigger_tx, conversation_return_rx, stop_handle) = make_subject (server);
        subject.start();
        conversation_trigger_tx.send (()).unwrap();
        conversation_trigger_tx.send (()).unwrap();
        let conversation1 = conversation_return_rx.recv().unwrap();
        let conversation2 = conversation_return_rx.recv().unwrap();

        let conversation1_handle = thread::spawn (move || {
            let response1 = conversation1.transact (UiShutdownRequest{}.tmb(0)).unwrap();
            let response2 = conversation1.transact (UiStartOrder{}.tmb(0)).unwrap();
            (response1, response2)
        });
        let conversation2_handle = thread::spawn (move || {
            let response1 = conversation2.transact (UiShutdownRequest{}.tmb(0)).unwrap();
            let response2 = conversation2.transact (UiStartOrder{}.tmb(0)).unwrap();
            (response1, response2)
        });

        let (conversation1_response1, conversation1_response2) = conversation1_handle.join().unwrap();
        let (conversation2_response1, conversation2_response2) = conversation2_handle.join().unwrap();
        assert_eq! (conversation1_response1, UiShutdownRequest{}.tmb(1));
        assert_eq! (conversation1_response2, UiStartResponse{new_process_id: 11, redirect_ui_port: 12}.tmb(1));
        assert_eq! (conversation2_response1, UiShutdownRequest{}.tmb(2));
        assert_eq! (conversation2_response2, UiStartResponse{new_process_id: 21, redirect_ui_port: 22}.tmb(2));
        let _ = stop_handle.stop();
    }
}
