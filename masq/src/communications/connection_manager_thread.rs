// Copyright (c) 2019-2020, MASQ (https://masq.ai). All rights reserved.

use crossbeam_channel::{Sender, Receiver, RecvError};
use std::collections::HashMap;
use masq_lib::ui_gateway::{MessageBody, MessagePath};
use websocket::sender::Writer;
use std::net::TcpStream;
use crate::communications::node_conversation::{NodeConversation, NodeConversationTermination};
use std::thread;
use crate::communications::client_listener_thread::{ClientListenerError, ClientListener};
use crossbeam_channel::unbounded;
use websocket::ws::sender::Sender as WsSender;
use masq_lib::ui_traffic_converter::UiTrafficConverter;
use websocket::OwnedMessage;
use masq_lib::utils::localhost;
use masq_lib::messages::NODE_UI_PROTOCOL;
use websocket::ClientBuilder;

pub struct ConnectionManager {
    conversation_trigger_tx: Sender<()>,
    conversation_return_rx: Receiver<NodeConversation>,
    disconnect_tx: Sender<()>,
    client_listener: ClientListener,
}

impl ConnectionManager {
    pub fn new () -> ConnectionManager {
        let client_listener = ClientListener::new();
        ConnectionManager {
            conversation_trigger_tx: unbounded().0,
            conversation_return_rx: unbounded().1,
            disconnect_tx: unbounded().0,
            client_listener,
        }
    }

    pub fn connect (&mut self, port: u16) -> Result<(), ClientListenerError> {
        let (listener_to_manager_tx, listener_to_manager_rx) = unbounded();
        let builder =
            ClientBuilder::new(format!("ws://{}:{}", localhost(), port).as_str()).expect("Bad URL");
        let client = match builder.add_protocol(NODE_UI_PROTOCOL).connect_insecure() {
            Ok(c) => c,
            Err (e) => return Err(ClientListenerError::Broken),
        };
        let (listener_half, talker_half) = client.split().unwrap();
        let client_listener = ClientListener::new();
        client_listener.start(listener_half, listener_to_manager_tx);
        let (conversation_trigger_tx, conversation_trigger_rx) = unbounded();
        let (conversation_return_tx, conversation_return_rx) = unbounded();
        let (disconnect_tx, disconnect_rx) = unbounded();
        self.conversation_trigger_tx = conversation_trigger_tx;
        self.conversation_return_rx = conversation_return_rx;
        self.disconnect_tx = disconnect_tx;
        let connection_manager_thread = ConnectionManagerThread::new(
            conversation_trigger_rx,
            conversation_return_tx,
            disconnect_rx,
        );
        connection_manager_thread.start (talker_half, listener_to_manager_rx);
        Ok(())
    }

    pub fn start_conversation (&self) -> NodeConversation {
        self.conversation_trigger_tx.send (()).expect("ConnectionManager is not connected");
        self.conversation_return_rx.recv().expect("ConnectionManager is not connected")
    }
}

struct CmsInner {
    conversations: HashMap<u64, Sender<Result<MessageBody, NodeConversationTermination>>>,
    next_context_id: u64,
    conversation_trigger_rx: Receiver<()>,
    conversation_return_tx: Sender<NodeConversation>,
    conversations_to_manager_tx: Sender<Result<MessageBody, u64>>,
    conversations_to_manager_rx: Receiver<Result<MessageBody, u64>>,
    disconnect_rx: Receiver<()>,
    talker_half: Option<Writer<TcpStream>>,
}

pub struct ConnectionManagerThread {
    inner_opt: Option<CmsInner>
}

impl ConnectionManagerThread {
    pub fn new(conversation_trigger_rx: Receiver<()>, conversation_return_tx: Sender<NodeConversation>, disconnect_rx: Receiver<()>) -> Self {
        let (conversations_to_manager_tx, conversations_to_manager_rx) = unbounded();
        let inner = CmsInner {
            conversations: HashMap::new(),
            next_context_id: 1,
            conversation_trigger_rx,
            conversation_return_tx,
            conversations_to_manager_tx,
            conversations_to_manager_rx,
            disconnect_rx,
            talker_half: None,
        };
        ConnectionManagerThread {
            inner_opt: Some(inner),
        }
    }

    pub fn start(mut self, talker_half: Writer<TcpStream>, listener_to_manager_rx: Receiver<Result<MessageBody, ClientListenerError>>) {
        let mut inner = self.inner_opt.take().expect("Inner disappeared!");
        inner.talker_half = Some (talker_half);
        thread::spawn (move || {
            loop {
                select! {
                    recv(inner.conversation_trigger_rx) -> _ => Self::handle_conversation_trigger (&mut inner),
                    recv(listener_to_manager_rx) -> message_body_result_result => Self::handle_incoming_message_body (&mut inner, message_body_result_result),
                    recv(inner.conversations_to_manager_rx) -> message_body_result_result => Self::handle_outgoing_message_body (&mut inner, message_body_result_result),
                    recv(inner.disconnect_rx) -> _ => Self::handle_disconnect (&mut inner),
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
            Err (e) => {
                inner.conversations.remove (&context_id);
            },
        }
    }

    fn handle_incoming_message_body (inner: &mut CmsInner, msg_result_result: Result<Result<MessageBody, ClientListenerError>, RecvError>) {
        match msg_result_result {
            Ok (msg_result) => match msg_result {
                Ok(message_body) => match message_body.path {
                    MessagePath::Conversation(context_id) => match inner.conversations.get(&context_id) {
                        Some(sender) => match sender.send(Ok(message_body)) {
                            Ok(_) => (),
                            Err(e) => unimplemented!("{:?}", e),
                        },
                        None => unimplemented!(),
                    },
                    MessagePath::FireAndForget => unimplemented!(),
                },
                Err(e) => unimplemented!("{:?}", e),
            },
            Err (e) => unimplemented! ("{:?}", e),
        }
    }

    fn handle_outgoing_message_body (inner: &mut CmsInner, msg_result_result: Result<Result<MessageBody, u64>, RecvError>) {
        let talker_half_ref = match inner.talker_half.as_mut() {
            Some (th) => th,
            None => unimplemented!(),
        };
        match msg_result_result {
            Ok(msg_opt) => match msg_opt {
                Ok(message_body) => match talker_half_ref.sender.send_message(&mut talker_half_ref.stream, &OwnedMessage::Text(UiTrafficConverter::new_marshal(message_body))) {
                    Ok(_) => (),
                    Err(e) => unimplemented!("{:?}", e),
                },
                Err(context_id) => unimplemented!("{}", context_id),
            },
            Err(e) => unimplemented!("{:?}", e),
        }
    }

    fn handle_disconnect (inner: &mut CmsInner) {
        unimplemented!()
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
    use crate::communications::client_listener_thread::ClientListener;

    fn make_subject (server: MockWebSocketsServer) -> (ConnectionManager, MockWebSocketsServerStopHandle) {
        let port = server.port();
        let stop_handle = server.start();
        let mut subject = ConnectionManager::new ();
        subject.connect(port);
        (subject, stop_handle)
    }

    #[test]
    fn handles_interleaved_conversations () {
        let server = MockWebSocketsServer::new(find_free_port())
            .queue_response (UiShutdownResponse{}.tmb(2))
            .queue_response (UiShutdownResponse{}.tmb(1))
            .queue_response (UiStartResponse{new_process_id: 11, redirect_ui_port: 12}.tmb(1))
            .queue_response (UiStartResponse{new_process_id: 21, redirect_ui_port: 22}.tmb(2));
        let (subject, stop_handle) = make_subject (server);
        let conversation1 = subject.start_conversation();
        let conversation2 = subject.start_conversation();

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

    fn make_inner() -> CmsInner {
        let port = find_free_port();
        CmsInner {
            conversations: HashMap::new(),
            next_context_id: 0,
            conversation_trigger_rx: unbounded().1,
            conversation_return_tx: unbounded().0,
            conversations_to_manager_tx: unbounded().0,
            conversations_to_manager_rx: unbounded().1,
            disconnect_rx: unbounded().1,
            talker_half: None,
        }
    }

    #[test]
    fn handles_failed_conversation_requester() {
        let mut inner = make_inner();
        let (conversation_return_tx, _) = unbounded();
        inner.next_context_id = 42;
        inner.conversation_return_tx = conversation_return_tx;

        ConnectionManagerThread::handle_conversation_trigger (&mut inner);

        assert_eq! (inner.next_context_id, 43);
        assert_eq! (inner.conversations.is_empty(), true);
    }
}
