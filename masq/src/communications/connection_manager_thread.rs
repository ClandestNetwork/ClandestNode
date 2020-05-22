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
}

impl ConnectionManager {
    pub fn new () -> ConnectionManager {
        ConnectionManager {
            conversation_trigger_tx: unbounded().0,
            conversation_return_rx: unbounded().1,
        }
    }

    pub fn connect (&mut self, port: u16, broadcast_handler: Box<dyn BroadcastHandler>) -> Result<(), ClientListenerError> {
        let (listener_to_manager_tx, listener_to_manager_rx) = unbounded();
        let talker_half = make_client_listener (port, listener_to_manager_tx)?;
        let (conversation_trigger_tx, conversation_trigger_rx) = unbounded();
        let (conversation_return_tx, conversation_return_rx) = unbounded();
        self.conversation_trigger_tx = conversation_trigger_tx;
        self.conversation_return_rx = conversation_return_rx;
        ConnectionManagerThread::start(
            port,
            conversation_trigger_rx,
            conversation_return_tx,
            talker_half,
            listener_to_manager_rx,
            broadcast_handler,
        );
        Ok(())
    }

    pub fn start_conversation (&self) -> NodeConversation {
        self.conversation_trigger_tx.send (()).expect("ConnectionManager is not connected");
        self.conversation_return_rx.recv().expect("ConnectionManager is not connected")
    }
}

fn make_client_listener (port: u16, listener_to_manager_tx: Sender<Result<MessageBody, ClientListenerError>>) -> Result <Writer<TcpStream>, ClientListenerError> {
    let builder =
        ClientBuilder::new(format!("ws://{}:{}", localhost(), port).as_str()).expect("Bad URL");
    let client = match builder.add_protocol(NODE_UI_PROTOCOL).connect_insecure() {
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
}

pub struct ConnectionManagerThread {}

impl ConnectionManagerThread {
    pub fn start(
        port: u16,
        conversation_trigger_rx: Receiver<()>,
        conversation_return_tx: Sender<NodeConversation>,
        talker_half: Writer<TcpStream>,
        listener_to_manager_rx: Receiver<Result<MessageBody, ClientListenerError>>,
        broadcast_handler: Box<dyn BroadcastHandler>,
    ) -> () {
        let (conversations_to_manager_tx, conversations_to_manager_rx) = unbounded();
        let inner = CmsInner {
            active_port: port,
            daemon_port: port,
            node_port: None,
            conversations: HashMap::new(),
            conversations_waiting: HashSet::new(),
            next_context_id: 1,
            conversation_trigger_rx,
            conversation_return_tx,
            conversations_to_manager_tx,
            conversations_to_manager_rx,
            listener_to_manager_rx,
            talker_half,
            broadcast_handler,
        };
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
                            Ok(_) => {
                                inner.conversations_waiting.remove (&context_id);
                            },
                            Err(_) => {
                                // Should we print something to stderr here? We don't have a stderr handy...
                                ()
                            },
                        },
                        None => {
                            // Should we print something to stderr here? We don't have a stderr handy...
                            ()
                        },
                    },
                    MessagePath::FireAndForget => inner.broadcast_handler.handle (message_body),
                },
                Err(e) => if e.is_fatal() {
                    return Self::fallback (inner)
                }
                else {
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
                MessagePath::Conversation(context_id) => match inner.conversations.get(&context_id) {
                    Some(_) => match inner.talker_half.sender.send_message(&mut inner.talker_half.stream, &OwnedMessage::Text(UiTrafficConverter::new_marshal(message_body))) {
                        Ok(_) => {
                            inner.conversations_waiting.insert(context_id);
                        },
                        Err(e) => unimplemented!("{:?}", e),
                    },
                    None => unimplemented!(),
                },
                MessagePath::FireAndForget => panic!("NodeConversation should have prevented sending a FireAndForget message with transact()"),
            },
            OutgoingMessageType::FireAndForgetMessage(message_body, context_id) => match message_body.path {
                MessagePath::FireAndForget => match inner.conversations.get (&context_id) {
                    Some (conversation_tx) => match inner.talker_half.sender.send_message(&mut inner.talker_half.stream, &OwnedMessage::Text(UiTrafficConverter::new_marshal(message_body))) {
                        Ok (_) => {let _ = conversation_tx.send(Err(NodeConversationTermination::FiredAndForgotten));},
                        Err (e) => unimplemented! ("{:?}", e),
                    },
                    None => unimplemented!(),
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
        inner.conversations_waiting.iter().for_each (|context_id| {
            let _ = inner.conversations.get(context_id).expect("conversations_waiting mishandled").send(Err(NodeConversationTermination::Resend));
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
    fn conversations_waiting_is_set_correctly() {
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
        let mut inner = make_inner();
        inner.next_context_id = 1;
        inner.conversation_trigger_rx = conversation_trigger_rx;
        inner.conversation_return_tx = conversation_return_tx;
        inner.listener_to_manager_rx = listener_to_manager_rx;
        inner.conversations_to_manager_tx = conversations_to_manager_tx;
        inner.conversations_to_manager_rx = conversations_to_manager_rx;
        inner.talker_half = talker_half;
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
        assert_eq! (disconnect_notification, Err(NodeConversationTermination::Resend));
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
        assert_eq! (disconnect_notification, Err(NodeConversationTermination::Resend));
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

        assert_eq! (inner.conversations_waiting.is_empty(), false);
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
        let mut inner = make_inner();
        inner.next_context_id = 1;
        inner.conversation_trigger_rx = conversation_trigger_rx;
        inner.conversation_return_tx = conversation_return_tx;
        inner.conversations_to_manager_tx = conversations_to_manager_tx;
        inner.conversations_to_manager_rx = conversations_to_manager_rx;
        inner.listener_to_manager_rx = listener_to_manager_rx;
        inner.talker_half = talker_half;
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

    fn make_inner() -> CmsInner {
        let port = find_free_port();
        let server = MockWebSocketsServer::new(port);
        let stop_handle = server.start();
        let client = make_client (port);
        let (_, talker_half) = client.split().unwrap();
        let _ = stop_handle.stop();
        CmsInner {
            active_port: port,
            daemon_port: port,
            node_port: None,
            conversations: HashMap::new(),
            conversations_waiting: HashSet::new(),
            next_context_id: 0,
            conversation_trigger_rx: unbounded().1,
            conversation_return_tx: unbounded().0,
            conversations_to_manager_tx: unbounded().0,
            conversations_to_manager_rx: unbounded().1,
            listener_to_manager_rx: unbounded().1,
            talker_half,
            broadcast_handler: Box::new (NullBroadcastHandler{}),
        }
    }

    pub fn vec_to_set<T>(vec: Vec<T>) -> HashSet<T>
        where
            T: Eq + Hash,
    {
        let set: HashSet<T> = vec.into_iter().collect();
        set
    }
}
