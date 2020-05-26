// Copyright (c) 2019-2020, MASQ (https://masq.ai). All rights reserved.

use crossbeam_channel::{Sender, Receiver, RecvError};
use std::collections::{HashMap, HashSet};
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

pub trait BroadcastHandler: Send {
    fn handle (&self, message_body: MessageBody) -> ();
}

#[derive (Debug, Clone, PartialEq)]
pub enum OutgoingMessageType {
    ConversationMessage (MessageBody),
    FireAndForgetMessage (MessageBody, u64),
    SignOff (u64),
}

pub struct ConnectionManager {
    conversation_trigger_tx: Sender<()>,
    conversation_return_rx: Receiver<NodeConversation>,
    redirect_order_tx: Sender<u16>,
    redirect_response_rx: Receiver<Result<(), ClientListenerError>>,
    active_port_request_tx: Sender<()>,
    active_port_response_rx: Receiver<u16>,
}

impl ConnectionManager {
    pub fn new () -> ConnectionManager {
        ConnectionManager {
            conversation_trigger_tx: unbounded().0,
            conversation_return_rx: unbounded().1,
            redirect_order_tx: unbounded().0,
            redirect_response_rx: unbounded().1,
            active_port_request_tx: unbounded().0,
            active_port_response_rx: unbounded().1,
        }
    }

    pub fn connect (&mut self, port: u16, broadcast_handler: Box<dyn BroadcastHandler>) -> Result<(), ClientListenerError> {
        let (listener_to_manager_tx, listener_to_manager_rx) = unbounded();
        let talker_half = make_client_listener (port, listener_to_manager_tx)?;
        let (conversation_trigger_tx, conversation_trigger_rx) = unbounded();
        let (conversation_return_tx, conversation_return_rx) = unbounded();
        let (redirect_order_tx, redirect_order_rx) = unbounded();
        let (redirect_response_tx, redirect_response_rx) = unbounded();
        let (active_port_request_tx, active_port_request_rx) = unbounded();
        let (active_port_response_tx, active_port_response_rx) = unbounded();
        self.conversation_trigger_tx = conversation_trigger_tx;
        self.conversation_return_rx = conversation_return_rx;
        self.redirect_order_tx = redirect_order_tx;
        self.redirect_response_rx = redirect_response_rx;
        self.active_port_request_tx = active_port_request_tx;
        self.active_port_response_rx = active_port_response_rx;
        let inner = CmsInner {
            active_port: port,
            daemon_port: port,
            node_port: None,
            conversations: HashMap::new(),
            conversations_waiting: HashSet::new(),
            next_context_id: 1,
            conversation_trigger_rx,
            conversation_return_tx,
            conversations_to_manager_tx: unbounded().0,
            conversations_to_manager_rx: unbounded().1,
            listener_to_manager_rx,
            talker_half,
            broadcast_handler,
            redirect_order_rx,
            redirect_response_tx,
            active_port_request_rx,
            active_port_response_tx,
        };
        ConnectionManagerThread::start(inner);
        Ok(())
    }

    pub fn redirect (&self, redirect_port: u16) -> Result<(), ClientListenerError> {
        self.redirect_order_tx.send(redirect_port).expect ("ConnectionManagerThread is dead");
        self.redirect_response_rx.recv().expect ("ConnectionManagerThread is dead")
    }

    pub fn active_ui_port (&self) -> u16 {
        self.active_port_request_tx.send(()).expect ("ConnectionManagerThread is dead");
        self.active_port_response_rx.recv().expect ("ConnectionManagerThread is dead")
    }

    pub fn start_conversation (&self) -> NodeConversation {
        self.conversation_trigger_tx.send (()).expect("ConnectionManager is not connected");
        self.conversation_return_rx.recv().expect("ConnectionManager is not connected")
    }

    pub fn close (&self) {
        unimplemented!()
    }
}

fn make_client_listener (port: u16, listener_to_manager_tx: Sender<Result<MessageBody, ClientListenerError>>) -> Result <Writer<TcpStream>, ClientListenerError> {
    let builder =
        ClientBuilder::new(format!("ws://{}:{}", localhost(), port).as_str()).expect("Bad URL");
    let result = builder.add_protocol(NODE_UI_PROTOCOL).connect_insecure();
    let client = match result {
        Ok(c) => c,
        Err (_) => return Err(ClientListenerError::Broken),
    };
    let (listener_half, talker_half) = client.split().unwrap();
    let client_listener = ClientListener::new();
    client_listener.start(listener_half, listener_to_manager_tx);
    Ok(talker_half)
}

struct CmsInner {
    active_port: u16,
    daemon_port: u16,
    node_port: Option<u16>,
    conversations: HashMap<u64, Sender<Result<MessageBody, NodeConversationTermination>>>,
    conversations_waiting: HashSet<u64>,
    next_context_id: u64,
    conversation_trigger_rx: Receiver<()>,
    conversation_return_tx: Sender<NodeConversation>,
    conversations_to_manager_tx: Sender<OutgoingMessageType>,
    conversations_to_manager_rx: Receiver<OutgoingMessageType>,
    listener_to_manager_rx: Receiver<Result<MessageBody, ClientListenerError>>,
    talker_half: Writer<TcpStream>,
    broadcast_handler: Box<dyn BroadcastHandler>,
    redirect_order_rx: Receiver<u16>,
    redirect_response_tx: Sender<Result<(), ClientListenerError>>,
    active_port_request_rx: Receiver<()>,
    active_port_response_tx: Sender<u16>,
}

pub struct ConnectionManagerThread {}

impl ConnectionManagerThread {
    fn start(mut inner: CmsInner) -> () {
        let (conversations_to_manager_tx, conversations_to_manager_rx) = unbounded();
        inner.conversations_to_manager_tx = conversations_to_manager_tx;
        inner.conversations_to_manager_rx = conversations_to_manager_rx;
        Self::spawn_thread(inner);
    }

    fn spawn_thread(mut inner: CmsInner) {
        thread::spawn (move || {
            loop {
                inner = Self::thread_loop_guts(inner)
            }
        });
    }

    fn thread_loop_guts(inner: CmsInner) -> CmsInner {
        select! {
            recv(inner.conversation_trigger_rx) -> _ => Self::handle_conversation_trigger (inner),
            recv(inner.listener_to_manager_rx) -> message_body_result_result => Self::handle_incoming_message_body (inner, message_body_result_result),
            recv(inner.conversations_to_manager_rx) -> message_body_result_result => Self::handle_outgoing_message_body (inner, message_body_result_result),
            recv(inner.redirect_order_rx) -> redirect_order_result => Self::handle_redirect_order (inner, redirect_order_result),
            recv(inner.active_port_request_rx) -> _ => Self::handle_active_port_request (inner),
        }
    }

    fn handle_conversation_trigger (mut inner: CmsInner) -> CmsInner {
        let (manager_to_conversation_tx, manager_to_conversation_rx) = unbounded();
        let context_id = inner.next_context_id;
        inner.next_context_id += 1;
        let conversation = NodeConversation::new (context_id, inner.conversations_to_manager_tx.clone(), manager_to_conversation_rx);
        inner.conversations.insert (context_id, manager_to_conversation_tx);
        match inner.conversation_return_tx.send (conversation) {
            Ok(_) => (),
            Err (_) => {
                inner.conversations.remove (&context_id);
            },
        };
        inner
    }

    fn handle_incoming_message_body (mut inner: CmsInner, msg_result_result: Result<Result<MessageBody, ClientListenerError>, RecvError>) -> CmsInner {
        match msg_result_result {
            Ok (msg_result) => match msg_result {
                Ok(message_body) => match message_body.path {
                    MessagePath::Conversation(context_id) => match inner.conversations.get(&context_id) {
                        Some(sender) => match sender.send(Ok(message_body)) {
                            Ok(_) => { inner.conversations_waiting.remove (&context_id); },
                            Err(_) => { // The conversation waiting for this message died
                                let _ = inner.conversations.remove (&context_id);
                                let _ = inner.conversations_waiting.remove (&context_id);
                            },
                        },
                        None => { // The conversation waiting for this message is missing
                            // Should we print something to stderr here? We don't have a stderr handy...
                            ()
                        },
                    },
                    MessagePath::FireAndForget => {
eprintln! ("Handling broadcast of message: {:?}", message_body);
                        inner.broadcast_handler.handle (message_body)
                    },
                },
                Err(e) => if e.is_fatal() {
                    // Fatal connection error: connection is dead, need to reestablish
                    return Self::fallback (inner)
                }
                else {
                    // Non-fatal connection error: connection to server is still up, but we have
                    // no idea which conversation the message was meant for
                    // Should we print something to stderr here? We don't have a stderr handy...
                    ()
                },
            },
            Err (_) => return Self::fallback (inner),
        };
        inner
    }

    fn handle_outgoing_message_body (mut inner: CmsInner, msg_result_result: Result<OutgoingMessageType, RecvError>) -> CmsInner {
        match msg_result_result.expect ("Received message from beyond the grave") {
            OutgoingMessageType::ConversationMessage (message_body) => match message_body.path {
                MessagePath::Conversation(context_id) => {
                    let conversation_result = inner.conversations.get(&context_id);
                    match conversation_result {
                        Some(_) => {
                            let send_message_result = inner.talker_half.sender.send_message(&mut inner.talker_half.stream, &OwnedMessage::Text(UiTrafficConverter::new_marshal(message_body)));
                            match send_message_result {
                                Ok(_) => {inner.conversations_waiting.insert(context_id);},
                                Err(_) => inner = Self::fallback(inner),
                            }
                        },
                        None => () // conversation mentioned in message doesn't exist,
                    }
                },
                MessagePath::FireAndForget => panic!("NodeConversation should have prevented sending a FireAndForget message with transact()"),
            },
            OutgoingMessageType::FireAndForgetMessage(message_body, context_id) => match message_body.path {
                MessagePath::FireAndForget => match inner.conversations.get (&context_id) {
                    Some (conversation_tx) => match inner.talker_half.sender.send_message(&mut inner.talker_half.stream, &OwnedMessage::Text(UiTrafficConverter::new_marshal(message_body))) {
                        Ok (_) => {let _ = conversation_tx.send(Err(NodeConversationTermination::FiredAndForgotten));},
                        Err (_) => inner = Self::fallback(inner),
                    },
                    None => () // conversation mentioned in message doesn't exist,
                }
                MessagePath::Conversation(_) => panic!("NodeConversation should have prevented sending a Conversation message with send()"),
            },
            OutgoingMessageType::SignOff(context_id) => {
                let _ = inner.conversations.remove (&context_id);
                let _ = inner.conversations_waiting.remove (&context_id);
            },
        };
        inner
    }

    fn handle_redirect_order (mut inner: CmsInner, redirect_order: Result<u16, RecvError>) -> CmsInner {
        let node_port = redirect_order.expect ("Received message from beyond the grave");
        let (listener_to_manager_tx, listener_to_manager_rx) = unbounded();
        let talker_half = match make_client_listener(node_port, listener_to_manager_tx) {
            Ok (th) => th,
            Err (_) => {
                let _ = inner.redirect_response_tx.send (Err(ClientListenerError::Broken));
                return inner
            },
        };
        inner.node_port = Some(node_port);
        inner.active_port = node_port;
        inner.listener_to_manager_rx = listener_to_manager_rx;
        inner.talker_half = talker_half;
        inner = Self::disappoint_waiting_conversations(inner, NodeConversationTermination::Resend);
        inner.redirect_response_tx.send(Ok(())).expect ("ConnectionManager is dead");
        inner
    }

    fn handle_active_port_request (inner: CmsInner) -> CmsInner {
        inner.active_port_response_tx.send (inner.active_port).expect ("ConnectionManager is dead");
        inner
    }

    fn handle_disconnect (inner: CmsInner) -> CmsInner {
        unimplemented!()
    }

    fn fallback (mut inner: CmsInner) -> CmsInner {
        inner.node_port = None;
        inner.active_port = inner.daemon_port;
        let (listener_to_manager_tx, listener_to_manager_rx) = unbounded();
        inner.listener_to_manager_rx = listener_to_manager_rx;
        let talker_half = match make_client_listener(inner.active_port, listener_to_manager_tx) {
            Ok (th) => th,
            Err (_) => panic! ("Lost connection, couldn't fall back to Daemon"),
        };
        inner.talker_half = talker_half;
        inner = Self::disappoint_waiting_conversations(inner, NodeConversationTermination::Fatal);
        inner
    }

    fn disappoint_waiting_conversations (mut inner: CmsInner, error: NodeConversationTermination) -> CmsInner {
        inner.conversations_waiting.iter().for_each (|context_id| {
            let _ = inner.conversations.get(context_id).expect("conversations_waiting mishandled").send(Err(error));
        });
        inner.conversations_waiting.clear();
        inner
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_utils::client_utils::make_client;
    use masq_lib::utils::find_free_port;
    use crate::test_utils::mock_websockets_server::{MockWebSocketsServer, MockWebSocketsServerStopHandle};
    use masq_lib::messages::{UiShutdownResponse, UiShutdownRequest, UiStartResponse, UiStartOrder, UiSetupResponse, UiSetupRequest, UiSetupBroadcast, UiUnmarshalError};
    use std::thread;
    use masq_lib::messages::{ToMessageBody, FromMessageBody};
    use std::sync::{Mutex, Arc};
    use std::hash::Hash;
    use std::time::Duration;
    use crossbeam_channel::TryRecvError;

    struct NullBroadcastHandler;

    impl BroadcastHandler for NullBroadcastHandler {
        fn handle(&self, _message_body: MessageBody) -> () {}
    }

    fn make_subject (server: MockWebSocketsServer) -> (ConnectionManager, MockWebSocketsServerStopHandle) {
        let port = server.port();
        let stop_handle = server.start();
        let mut subject = ConnectionManager::new ();
        subject.connect(port, Box::new (NullBroadcastHandler{})).unwrap();
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

    #[test]
    fn handles_fire_and_forget_messages () {
        let server = MockWebSocketsServer::new(find_free_port());
        let (subject, stop_handle) = make_subject (server);
        let conversation = subject.start_conversation();
        let message1 = UiUnmarshalError{
            message: "Message 1".to_string(),
            bad_data: "Data 1".to_string()
        };
        let message2 = UiUnmarshalError{
            message: "Message 2".to_string(),
            bad_data: "Data 2".to_string()
        };

        conversation.send (message1.clone().tmb(0)).unwrap();
        conversation.send (message2.clone().tmb(0)).unwrap();

        thread::sleep (Duration::from_millis(200));
        let mut outgoing_messages = stop_handle.stop();
        assert_eq! (UiUnmarshalError::fmb(outgoing_messages.remove(0).unwrap()).unwrap(), (message1, 0));
        assert_eq! (UiUnmarshalError::fmb(outgoing_messages.remove(0).unwrap()).unwrap(), (message2, 0));
        assert_eq! (outgoing_messages.is_empty(), true);
    }

    #[test]
    fn conversations_waiting_is_set_correctly_for_normal_operation() {
        let port = find_free_port();
        let server = MockWebSocketsServer::new(port)
            .queue_string ("irrelevant")
            .queue_string ("irrelevant");
        let stop_handle = server.start();
        let (_, talker_half) = make_client(port).split().unwrap();
        let (listener_to_manager_tx, listener_to_manager_rx) = unbounded();
        let (conversations_to_manager_tx, conversations_to_manager_rx) = unbounded();
        let (conversation_trigger_tx, conversation_trigger_rx) = unbounded();
        let (conversation_return_tx, conversation_return_rx) = unbounded();
        let (_redirect_order_tx, redirect_order_rx) = unbounded();
        let (_active_port_request_tx, active_port_request_rx) = unbounded();
        let mut inner = make_inner();
        inner.next_context_id = 1;
        inner.conversation_trigger_rx = conversation_trigger_rx;
        inner.conversation_return_tx = conversation_return_tx;
        inner.listener_to_manager_rx = listener_to_manager_rx;
        inner.conversations_to_manager_tx = conversations_to_manager_tx;
        inner.conversations_to_manager_rx = conversations_to_manager_rx;
        inner.talker_half = talker_half;
        inner.redirect_order_rx = redirect_order_rx;
        inner.active_port_request_rx = active_port_request_rx;
        conversation_trigger_tx.send (()).unwrap();
        inner = ConnectionManagerThread::thread_loop_guts(inner);
        let conversation1 = conversation_return_rx.try_recv().unwrap();
        let (conversation1_tx, conversation1_rx) = conversation1.tx_rx();
        conversation_trigger_tx.send (()).unwrap();
        inner = ConnectionManagerThread::thread_loop_guts(inner);
        let conversation2 = conversation_return_rx.try_recv().unwrap();
        let (conversation2_tx, conversation2_rx) = conversation2.tx_rx();
        let get_existing_keys = |inner: &CmsInner| inner.conversations.iter().map(|(k, _)| *k).collect::<HashSet<u64>>();

        // Conversations 1 and 2, nobody waiting
        assert_eq! (get_existing_keys(&inner), vec_to_set(vec![1, 2]));
        assert_eq! (inner.conversations_waiting, vec_to_set(vec![]));

        // Send request from Conversation 1 and process it
        conversation1_tx.send (OutgoingMessageType::ConversationMessage (UiShutdownRequest{}.tmb (1))).unwrap();
        inner = ConnectionManagerThread::thread_loop_guts(inner); // send request 1

        // Conversations 1 and 2, 1 waiting
        assert_eq! (get_existing_keys(&inner), vec_to_set(vec![1, 2]));
        assert_eq! (inner.conversations_waiting, vec_to_set(vec![1]));

        // Send request from Conversation 2 and process it
        conversation2_tx.send (OutgoingMessageType::ConversationMessage (UiShutdownRequest{}.tmb(2))).unwrap();
        inner = ConnectionManagerThread::thread_loop_guts(inner);

        // Conversations 1 and 2, 1 and 2 waiting
        assert_eq! (get_existing_keys(&inner), vec_to_set(vec![1, 2]));
        assert_eq! (inner.conversations_waiting, vec_to_set(vec![1, 2]));

        // Receive response for Conversation 2, process it, pull it out
        let response2 = UiShutdownResponse{}.tmb(2);
        assert_eq! (response2.path, MessagePath::Conversation(2));
        listener_to_manager_tx.send(Ok(response2)).unwrap();
        inner = ConnectionManagerThread::thread_loop_guts(inner);
        let result2 = conversation2_rx.try_recv().unwrap().unwrap();

        // Conversations 1 and 2, 1 still waiting
        assert_eq! (result2, UiShutdownResponse{}.tmb(2));
        assert_eq! (get_existing_keys(&inner), vec_to_set(vec![1, 2]));
        assert_eq! (inner.conversations_waiting, vec_to_set(vec![1]));

        // Receive response for Conversation 1, process it, pull it out
        let response1 = UiShutdownResponse{}.tmb(1);
        assert_eq! (response1.path, MessagePath::Conversation(1));
        listener_to_manager_tx.send(Ok(response1)).unwrap();
        inner = ConnectionManagerThread::thread_loop_guts(inner);
        let result1 = conversation1_rx.try_recv().unwrap().unwrap();

        // Conversations 1 and 2, nobody waiting
        assert_eq! (result1, UiShutdownResponse{}.tmb(1));
        assert_eq! (result2, UiShutdownResponse{}.tmb(2));
        assert_eq! (get_existing_keys(&inner), vec_to_set(vec![1, 2]));
        assert_eq! (inner.conversations_waiting, vec_to_set(vec![]));

        // Conversation 1 signals exit; process it
        conversation1_tx.send(OutgoingMessageType::SignOff(1)).unwrap();
        inner = ConnectionManagerThread::thread_loop_guts(inner);

        // Only Conversation 2, nobody waiting
        assert_eq! (get_existing_keys(&inner), vec_to_set(vec![2]));
        assert_eq! (inner.conversations_waiting, vec_to_set(vec![]));

        // Conversation 2 signals exit; process it
        conversation2_tx.send(OutgoingMessageType::SignOff(2)).unwrap();
        inner = ConnectionManagerThread::thread_loop_guts(inner);

        // No more conversations, nobody waiting
        assert_eq! (get_existing_keys(&inner), vec_to_set(vec![]));
        assert_eq! (inner.conversations_waiting, vec_to_set(vec![]));

        let _ = stop_handle.stop();
    }

    #[test]
    fn handles_listener_fallback_from_node () {
        let daemon_port = find_free_port();
        let expected_incoming_message = UiSetupResponse{
            running: false,
            values: vec![],
            errors: vec![]
        }.tmb(4);
        let daemon = MockWebSocketsServer::new(daemon_port)
            .queue_response (expected_incoming_message.clone());
        let stop_handle = daemon.start();
        let node_port = find_free_port();
        let (conversation_tx, conversation_rx) = unbounded();
        let (decoy_tx, decoy_rx) = unbounded();
        let mut inner = make_inner();
        inner.active_port = node_port;
        inner.daemon_port = daemon_port;
        inner.node_port = Some (node_port);
        inner.conversations.insert (4, conversation_tx);
        inner.conversations.insert (5, decoy_tx);
        inner.conversations_waiting.insert (4);

        let inner = ConnectionManagerThread::handle_incoming_message_body (inner, Err(RecvError));

        let disconnect_notification = conversation_rx.try_recv().unwrap();
        assert_eq! (disconnect_notification, Err(NodeConversationTermination::Fatal));
        assert_eq! (decoy_rx.try_recv().is_err(), true); // no disconnect notification sent to conversation not waiting
        assert_eq! (inner.active_port, daemon_port);
        assert_eq! (inner.daemon_port, daemon_port);
        assert_eq! (inner.node_port, None);
        assert_eq! (inner.conversations_waiting.is_empty(), true);
        let _ = ConnectionManagerThread::handle_outgoing_message_body (inner, Ok (OutgoingMessageType::ConversationMessage (UiSetupRequest{ values: vec![] }.tmb(4))));
        let mut outgoing_messages = stop_handle.stop();
        assert_eq! (outgoing_messages.remove (0), Ok(UiSetupRequest{values: vec![]}.tmb(4)));
    }

    #[test]
    fn handles_redirect_from_daemon_to_node () {
        let daemon_port = find_free_port();
        let expected_daemon_outgoing_message = UiSetupRequest { values: vec![] };
        let expected_daemon_incoming_message = UiSetupResponse{
            running: false,
            values: vec![],
            errors: vec![]
        };
        let daemon = MockWebSocketsServer::new(daemon_port)
            .queue_response (expected_daemon_incoming_message.clone().tmb(1));
        let daemon_stop_handle = daemon.start();
        let node_port = find_free_port();
        let expected_node_outgoing_message = UiShutdownRequest{};
        let expected_node_incoming_message = UiShutdownResponse{};
        let node = MockWebSocketsServer::new(node_port)
            .queue_response (expected_node_incoming_message.clone().tmb(1));
        let node_stop_handle = node.start();
        let mut subject = ConnectionManager::new();
        subject.connect (daemon_port, Box::new (NullBroadcastHandler{})).unwrap();
        let conversation = subject.start_conversation();

        let active_port_1 = subject.active_ui_port();
        let daemon_response = conversation.transact (expected_daemon_outgoing_message.clone().tmb(1)).unwrap();
        let active_port_2 = subject.active_ui_port();
        subject.redirect (node_port).unwrap();
        let active_port_3 = subject.active_ui_port();
        let node_response = conversation.transact (expected_node_outgoing_message.clone().tmb(1)).unwrap();
        let active_port_4 = subject.active_ui_port();

        assert_eq! (UiSetupResponse::fmb(daemon_response).unwrap().0, expected_daemon_incoming_message);
        assert_eq! (UiShutdownResponse::fmb(node_response).unwrap().0, expected_node_incoming_message);
        assert_eq! (active_port_1, daemon_port);
        assert_eq! (active_port_2, daemon_port);
        assert_eq! (active_port_3, node_port);
        assert_eq! (active_port_4, node_port);
        let mut daemon_outgoing_messages = daemon_stop_handle.stop();
        let mut node_outgoing_messages = node_stop_handle.stop();
        assert_eq! (UiSetupRequest::fmb(daemon_outgoing_messages.remove (0).unwrap()).unwrap().0, expected_daemon_outgoing_message);
        assert_eq! (UiShutdownRequest::fmb(node_outgoing_messages.remove (0).unwrap()).unwrap().0, expected_node_outgoing_message);
    }

    #[test]
    fn handle_redirect_order_handles_rejection_from_node () {
        let node_port = find_free_port(); // won't put anything on this port
        let (redirect_response_tx, redirect_response_rx) = unbounded();
        let mut inner = make_inner();
        inner.redirect_response_tx = redirect_response_tx;

        ConnectionManagerThread::handle_redirect_order(inner, Ok(node_port));

        let response = redirect_response_rx.try_recv().unwrap();
        assert_eq! (response, Err(ClientListenerError::Broken));
    }

    #[test]
    fn handle_redirect_order_instructs_waiting_conversations_to_resend () {
        let node_port = find_free_port();
        let server = MockWebSocketsServer::new (node_port);
        let server_stop_handle = server.start();
        let (redirect_response_tx, redirect_response_rx) = unbounded();
        let (conversation1_tx, conversation1_rx) = unbounded();
        let (conversation2_tx, conversation2_rx) = unbounded();
        let conversations = vec![(1, conversation1_tx), (2, conversation2_tx)]
            .into_iter ()
            .collect();
        let conversations_waiting = vec_to_set(vec![1, 2]);
        let mut inner = make_inner();
        inner.redirect_response_tx = redirect_response_tx;
        inner.conversations = conversations;
        inner.conversations_waiting = conversations_waiting;

        inner = ConnectionManagerThread::handle_redirect_order(inner, Ok(node_port));

        let get_existing_keys = |inner: &CmsInner| inner.conversations.iter().map(|(k, _)| *k).collect::<HashSet<u64>>();
        assert_eq! (get_existing_keys (&inner), vec_to_set(vec![1, 2]));
        assert_eq! (inner.conversations_waiting.is_empty (), true);
        assert_eq! (conversation1_rx.try_recv().unwrap (), Err(NodeConversationTermination::Resend));
        assert_eq! (conversation2_rx.try_recv().unwrap (), Err(NodeConversationTermination::Resend));
        assert_eq! (redirect_response_rx.try_recv().unwrap(), Ok(()));
        let _ = server_stop_handle.stop();
    }

    #[test]
    #[should_panic (expected = "Lost connection, couldn't fall back to Daemon")]
    fn handles_listener_fallback_from_daemon () {
        let daemon_port = find_free_port();
        let (conversation_tx, _) = unbounded();
        let (decoy_tx, _) = unbounded();
        let mut inner = make_inner();
        inner.active_port = daemon_port;
        inner.daemon_port = daemon_port;
        inner.node_port = None;
        inner.conversations.insert (4, conversation_tx);
        inner.conversations.insert (5, decoy_tx);
        inner.conversations_waiting.insert (4);

        let _ = ConnectionManagerThread::handle_incoming_message_body (inner, Err(RecvError));
    }

    #[test]
    fn handles_fatal_reception_failure () {
        let daemon_port = find_free_port();
        let expected_incoming_message = UiSetupResponse{
            running: false,
            values: vec![],
            errors: vec![]
        }.tmb(4);
        let daemon = MockWebSocketsServer::new(daemon_port)
            .queue_response (expected_incoming_message.clone());
        let stop_handle = daemon.start();
        let node_port = find_free_port();
        let (conversation_tx, conversation_rx) = unbounded();
        let (decoy_tx, decoy_rx) = unbounded();
        let mut inner = make_inner();
        inner.active_port = node_port;
        inner.daemon_port = daemon_port;
        inner.node_port = Some (node_port);
        inner.conversations.insert (4, conversation_tx);
        inner.conversations.insert (5, decoy_tx);
        inner.conversations_waiting.insert (4);

        let inner = ConnectionManagerThread::handle_incoming_message_body (inner, Ok(Err(ClientListenerError::Broken)));

        let disconnect_notification = conversation_rx.try_recv().unwrap();
        assert_eq! (disconnect_notification, Err(NodeConversationTermination::Fatal));
        assert_eq! (decoy_rx.try_recv().is_err(), true); // no disconnect notification sent to conversation not waiting
        assert_eq! (inner.active_port, daemon_port);
        assert_eq! (inner.daemon_port, daemon_port);
        assert_eq! (inner.node_port, None);
        assert_eq! (inner.conversations_waiting.is_empty(), true);
        let _ = ConnectionManagerThread::handle_outgoing_message_body (inner, Ok (OutgoingMessageType::ConversationMessage (UiSetupRequest{ values: vec![] }.tmb(4))));
        let mut outgoing_messages = stop_handle.stop();
        assert_eq! (outgoing_messages.remove (0), Ok(UiSetupRequest{values: vec![]}.tmb(4)));
    }

    #[test]
    fn handles_nonfatal_reception_failure () {
        let daemon_port = find_free_port();
        let node_port = find_free_port();
        let (conversation_tx, conversation_rx) = unbounded();
        let mut inner = make_inner();
        inner.active_port = node_port;
        inner.daemon_port = daemon_port;
        inner.node_port = Some (node_port);
        inner.conversations.insert (4, conversation_tx);
        inner.conversations_waiting.insert (4);

        let inner = ConnectionManagerThread::handle_incoming_message_body (inner, Ok(Err(ClientListenerError::UnexpectedPacket)));

        assert_eq! (conversation_rx.try_recv().is_err(), true); // no disconnect notification sent
        assert_eq! (inner.active_port, node_port);
        assert_eq! (inner.daemon_port, daemon_port);
        assert_eq! (inner.node_port, Some(node_port));
        assert_eq! (inner.conversations_waiting.is_empty(), false);
    }

    struct TestBroadcastHandler {
        recording: Arc<Mutex<Vec<MessageBody>>>,
    }

    impl BroadcastHandler for TestBroadcastHandler {
        fn handle(&self, message_body: MessageBody) -> () {
            self.recording.lock().unwrap().push (message_body)
        }
    }

    impl TestBroadcastHandler {
        fn new () -> Self {
            Self {
                recording: Arc::new (Mutex::new (vec![]))
            }
        }

        fn recording_arc (&self) -> Arc<Mutex<Vec<MessageBody>>> {
            self.recording.clone()
        }
    }

    #[test]
    fn handles_broadcast () {
        let incoming_message = UiSetupBroadcast{
            running: false,
            values: vec![],
            errors: vec![]
        }.tmb(0);
        let (conversation_tx, conversation_rx) = unbounded();
        let broadcast_handler = TestBroadcastHandler::new();
        let recording_arc = broadcast_handler.recording_arc();
        let mut inner = make_inner();
        inner.conversations.insert (4, conversation_tx);
        inner.conversations_waiting.insert (4);
        inner.broadcast_handler = Box::new (broadcast_handler);

        let inner = ConnectionManagerThread::handle_incoming_message_body (inner, Ok(Ok(incoming_message.clone())));

        assert_eq! (conversation_rx.try_recv().is_err(), true); // no message to any conversation
        assert_eq! (inner.conversations_waiting.is_empty(), false);
        let recording = recording_arc.lock().unwrap();
        assert_eq! (*recording, vec![incoming_message]);
    }

    #[test]
    fn handles_response_to_nonexistent_conversation() {
        let incoming_message = UiSetupResponse{
            running: false,
            values: vec![],
            errors: vec![]
        }.tmb(3);
        let (conversation_tx, conversation_rx) = unbounded();
        let mut inner = make_inner();
        inner.conversations.insert (4, conversation_tx);
        inner.conversations_waiting.insert (4);

        let inner = ConnectionManagerThread::handle_incoming_message_body (inner, Ok(Ok(incoming_message.clone())));

        assert_eq! (conversation_rx.try_recv().is_err(), true); // no message to any conversation
        assert_eq! (inner.conversations_waiting.is_empty(), false);
    }

    #[test]
    fn handles_response_to_dead_conversation() {
        let incoming_message = UiSetupResponse{
            running: false,
            values: vec![],
            errors: vec![]
        }.tmb(4);
        let (conversation_tx, _) = unbounded();
        let mut inner = make_inner();
        inner.conversations.insert (4, conversation_tx);
        inner.conversations_waiting.insert (4);

        let inner = ConnectionManagerThread::handle_incoming_message_body (inner, Ok(Ok(incoming_message.clone())));

        assert_eq! (inner.conversations.is_empty(), true);
        assert_eq! (inner.conversations_waiting.is_empty(), true);
    }

    #[test]
    fn handles_failed_conversation_requester() {
        let mut inner = make_inner();
        let (conversation_return_tx, _) = unbounded();
        inner.next_context_id = 42;
        inner.conversation_return_tx = conversation_return_tx;

        let inner = ConnectionManagerThread::handle_conversation_trigger (inner);

        assert_eq! (inner.next_context_id, 43);
        assert_eq! (inner.conversations.is_empty(), true);
    }

    #[test]
    fn handles_fire_and_forget_outgoing_message() {
        let port = find_free_port();
        let server = MockWebSocketsServer::new(port);
        let stop_handle = server.start ();
        let (_, talker_half) = make_client (port).split().unwrap();
        let (conversations_to_manager_tx, conversations_to_manager_rx) = unbounded();
        let (conversation_trigger_tx, conversation_trigger_rx) = unbounded();
        let (conversation_return_tx, conversation_return_rx) = unbounded();
        let (_listener_to_manager_tx, listener_to_manager_rx) = unbounded();
        let (_redirect_order_tx, redirect_order_rx) = unbounded();
        let (_active_port_request_tx, active_port_request_rx) = unbounded();
        let mut inner = make_inner();
        inner.next_context_id = 1;
        inner.conversation_trigger_rx = conversation_trigger_rx;
        inner.conversation_return_tx = conversation_return_tx;
        inner.conversations_to_manager_tx = conversations_to_manager_tx;
        inner.conversations_to_manager_rx = conversations_to_manager_rx;
        inner.listener_to_manager_rx = listener_to_manager_rx;
        inner.talker_half = talker_half;
        inner.redirect_order_rx = redirect_order_rx;
        inner.active_port_request_rx = active_port_request_rx;
        conversation_trigger_tx.send (()).unwrap();
        inner = ConnectionManagerThread::thread_loop_guts(inner);
        let conversation = conversation_return_rx.try_recv().unwrap();
        let outgoing_message = UiUnmarshalError{ message: "".to_string(), bad_data: "".to_string() }.tmb(0);

        let inner = ConnectionManagerThread::handle_outgoing_message_body (inner, Ok (OutgoingMessageType::FireAndForgetMessage (outgoing_message.clone(), conversation.context_id())));

        assert_eq! (inner.conversations.len(), 1);
        assert_eq! (inner.conversations_waiting.is_empty(), true);
        let mut outgoing_messages = stop_handle.stop();
        assert_eq! (UiUnmarshalError::fmb(outgoing_messages.remove(0).unwrap()), UiUnmarshalError::fmb(outgoing_message));
    }

    #[test]
    fn handles_outgoing_conversation_messages_to_dead_server () {
        let daemon_port = find_free_port();
        let daemon_server = MockWebSocketsServer::new(daemon_port);
        let daemon_stop_handle = daemon_server.start();
        let (conversation1_tx, conversation1_rx) = unbounded();
        let (conversation2_tx, conversation2_rx) = unbounded();
        let (conversation3_tx, conversation3_rx) = unbounded();
        let conversations = vec![(1, conversation1_tx), (2, conversation2_tx), (3, conversation3_tx)].into_iter()
            .collect::<HashMap<u64, Sender<Result<MessageBody, NodeConversationTermination>>>>();
        let mut inner = make_inner();
        inner.daemon_port = daemon_port;
        inner.conversations = conversations;
        inner.conversations_waiting = vec_to_set(vec![2, 3]);

        inner = ConnectionManagerThread::handle_outgoing_message_body(inner, Ok(OutgoingMessageType::ConversationMessage(UiSetupRequest{ values: vec![] }.tmb(2))));

        let _ = daemon_stop_handle.stop();
        assert_eq! (conversation1_rx.try_recv(), Err(TryRecvError::Empty)); // Wasn't waiting
        assert_eq! (conversation2_rx.try_recv(), Ok(Err(NodeConversationTermination::Fatal))); // sender
        assert_eq! (conversation3_rx.try_recv(), Ok(Err(NodeConversationTermination::Fatal))); // innocent bystander
        assert_eq! (inner.conversations_waiting.is_empty(), true);
    }

    #[test]
    fn handles_outgoing_conversation_message_from_nonexistent_conversation () {
        let conversations = vec![(1, unbounded().0), (2, unbounded().0)].into_iter()
            .collect::<HashMap<u64, Sender<Result<MessageBody, NodeConversationTermination>>>>();
        let mut inner = make_inner();
        inner.conversations = conversations;
        inner.conversations_waiting = vec_to_set(vec![1]);

        inner = ConnectionManagerThread::handle_outgoing_message_body(inner, Ok(OutgoingMessageType::ConversationMessage(UiSetupRequest{ values: vec![] }.tmb(42))));

        assert_eq! (inner.conversations.len(), 2);
        assert_eq! (inner.conversations_waiting.len(), 1);
    }

    #[test]
    fn handles_outgoing_fire_and_forget_messages_to_dead_server () {
        let daemon_port = find_free_port();
        let daemon_server = MockWebSocketsServer::new(daemon_port);
        let daemon_stop_handle = daemon_server.start();
        let (conversation1_tx, conversation1_rx) = unbounded();
        let (conversation2_tx, conversation2_rx) = unbounded();
        let (conversation3_tx, conversation3_rx) = unbounded();
        let conversations = vec![(1, conversation1_tx), (2, conversation2_tx), (3, conversation3_tx)].into_iter()
            .collect::<HashMap<u64, Sender<Result<MessageBody, NodeConversationTermination>>>>();
        let mut inner = make_inner();
        inner.daemon_port = daemon_port;
        inner.conversations = conversations;
        inner.conversations_waiting = vec_to_set(vec![2, 3]);

        inner = ConnectionManagerThread::handle_outgoing_message_body(inner, Ok(OutgoingMessageType::FireAndForgetMessage(UiUnmarshalError{message: String::new(), bad_data: String::new()}.tmb(0), 2)));

        let _ = daemon_stop_handle.stop();
        assert_eq! (conversation1_rx.try_recv(), Err(TryRecvError::Empty)); // Wasn't waiting
        assert_eq! (conversation2_rx.try_recv(), Ok(Err(NodeConversationTermination::Fatal))); // sender
        assert_eq! (conversation3_rx.try_recv(), Ok(Err(NodeConversationTermination::Fatal))); // innocent bystander
        assert_eq! (inner.conversations_waiting.is_empty(), true);
    }

    #[test]
    fn handles_outgoing_fire_and_forget_message_from_nonexistent_conversation () {
        let conversations = vec![(1, unbounded().0), (2, unbounded().0)].into_iter()
            .collect::<HashMap<u64, Sender<Result<MessageBody, NodeConversationTermination>>>>();
        let mut inner = make_inner();
        inner.conversations = conversations;
        inner.conversations_waiting = vec_to_set(vec![1]);

        inner = ConnectionManagerThread::handle_outgoing_message_body(inner, Ok(OutgoingMessageType::FireAndForgetMessage(UiUnmarshalError{message: String::new(), bad_data: String::new()}.tmb(0), 42)));

        assert_eq! (inner.conversations.len(), 2);
        assert_eq! (inner.conversations_waiting.len(), 1);
    }

    #[test]
    fn handles_disconnect () {
        let port = find_free_port();
        let server = MockWebSocketsServer::new(port)
            .queue_owned_message (OwnedMessage::Close (None));
        let stop_handle = server.start();
        let client = make_client (port);
        let (listener_half, talker_half) = client.split().unwrap();
        let (conversation1_tx, conversation1_rx) = unbounded();
        let (conversation2_tx, conversation2_rx) = unbounded();
        let (conversation3_tx, conversation3_rx) = unbounded();
        let conversations = vec![(1, conversation1_tx), (2, conversation2_tx), (3, conversation3_tx)].into_iter()
            .collect::<HashMap<u64, Sender<Result<MessageBody, NodeConversationTermination>>>>();
        let mut inner = make_inner();
        inner.conversations = conversations;
        inner.conversations_waiting = vec_to_set(vec![2, 3]);
        inner.talker_half = talker_half;

        inner = ConnectionManagerThread::handle_disconnect (inner);


    }

    fn make_inner() -> CmsInner {
        CmsInner {
            active_port: 0,
            daemon_port: 0,
            node_port: None,
            conversations: HashMap::new(),
            conversations_waiting: HashSet::new(),
            next_context_id: 0,
            conversation_trigger_rx: unbounded().1,
            conversation_return_tx: unbounded().0,
            conversations_to_manager_tx: unbounded().0,
            conversations_to_manager_rx: unbounded().1,
            listener_to_manager_rx: unbounded().1,
            talker_half: make_broken_talker_half(),
            broadcast_handler: Box::new (NullBroadcastHandler{}),
            redirect_order_rx: unbounded().1,
            redirect_response_tx: unbounded().0,
            active_port_request_rx: unbounded().1,
            active_port_response_tx: unbounded().0,
        }
    }

    pub fn make_broken_talker_half () -> Writer<TcpStream> {
        let port = find_free_port();
        let server = MockWebSocketsServer::new(port);
        let stop_handle = server.start();
        let client = make_client (port);
        let (_, talker_half) = client.split().unwrap();
        let _ = stop_handle.kill();
        let _ = talker_half.shutdown_all();
        talker_half
    }

    pub fn vec_to_set<T>(vec: Vec<T>) -> HashSet<T>
        where
            T: Eq + Hash,
    {
        let set: HashSet<T> = vec.into_iter().collect();
        set
    }
}
