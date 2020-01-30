// Copyright (c) 2019-2020, MASQ (https://masq.ai) and/or its affiliates. All rights reserved.
use masq_lib::ui_gateway::{NodeFromUiMessage, NodeToUiMessage};
use masq_lib::ui_traffic_converter::UiTrafficConverter;
use websocket::sync::Server;
use std::net::{SocketAddr};
use masq_lib::utils::localhost;
use std::sync::{Arc, Mutex};
use std::thread::JoinHandle;
use std::thread;
use websocket::OwnedMessage;
use websocket::result::WebSocketError;
use std::sync::mpsc::Sender;
use std::time::Duration;
use masq_lib::messages::NODE_UI_PROTOCOL;

pub struct MockWebSocketsServer {
    port: u16,
    pub protocol: String,
    responses_arc: Arc<Mutex<Vec<String>>>,
}

pub struct MockWebSocketsServerStopHandle {
    requests_arc: Arc<Mutex<Vec<Result<NodeFromUiMessage, String>>>>,
    stop_tx: Sender<()>,
    join_handle: JoinHandle<()>,
}

impl MockWebSocketsServer {
    pub fn new(port: u16) -> Self {
        Self {
            port,
            protocol: NODE_UI_PROTOCOL.to_string(),
            responses_arc: Arc::new(Mutex::new(vec![])),
        }
    }

    pub fn queue_response (self, message: NodeToUiMessage) -> Self {
        self.responses_arc.lock().unwrap().push (UiTrafficConverter::new_marshal_to_ui(message));
        self
    }

    pub fn queue_string (self, string: &str) -> Self {
        self.responses_arc.lock().unwrap().push (string.to_string());
        self
    }

    pub fn start (self) -> MockWebSocketsServerStopHandle {
        let server_arc = Arc::new(Mutex::new(Server::bind(SocketAddr::new(localhost(), self.port)).unwrap()));
        let inner_server_arc = server_arc.clone();
        let requests_arc = Arc::new(Mutex::new(vec![]));
        let inner_requests_arc = requests_arc.clone();
        let inner_responses_arc = self.responses_arc.clone();
        let (stop_tx, stop_rx) = std::sync::mpsc::channel();
        let (ready_tx, ready_rx) = std::sync::mpsc::channel();
        let join_handle = thread::spawn (move || {
            let mut server = inner_server_arc.lock().unwrap();
            let mut requests = inner_requests_arc.lock().unwrap();
            ready_tx.send(()).unwrap();
            let upgrade = server.accept().unwrap();
            if upgrade.protocols().iter().find(|p| *p == &self.protocol).is_none() {
                panic! ("No recognized protocol: {:?}", upgrade.protocols())
            }
            let mut client = upgrade.accept().unwrap();
            client.set_nonblocking(true).unwrap();
            loop {
                let incoming_opt = match client.recv_message() {
                    Err(WebSocketError::NoDataAvailable) => {
                        None
                    },
                    Err(WebSocketError::IoError(e)) if e.kind() == std::io::ErrorKind::WouldBlock => {
                        None
                    }
                    Err(e) => panic! ("Error serving WebSocket: {:?}", e),
                    Ok (OwnedMessage::Text(json)) => {
                        Some (match UiTrafficConverter::new_unmarshal_from_ui(&json, 0) {
                            Ok(msg) => Ok(msg),
                            Err(_) => Err(json),
                        })
                    },
                    Ok(x) => {
                        Some (Err(format!("{:?}", x)))
                    },
                };
                if let Some (incoming) = incoming_opt {
                    requests.push (incoming);
                    let outgoing: String = inner_responses_arc.lock().unwrap().remove(0);
                    if outgoing == "disconnect".to_string() {
                        break;
                    }
                    client.send_message (&OwnedMessage::Text(outgoing)).unwrap()
                }
                if stop_rx.try_recv().is_ok() {
                    client.send_message (&OwnedMessage::Close(None)).unwrap();
                    break;
                }
                thread::sleep(Duration::from_millis(100))
            }
        });
        ready_rx.recv().unwrap();
        thread::sleep (Duration::from_millis(250));
        MockWebSocketsServerStopHandle {
            requests_arc,
            stop_tx,
            join_handle,
        }
    }
}

impl MockWebSocketsServerStopHandle {
    pub fn stop (self) -> Vec<Result<NodeFromUiMessage, String>> {
        self.stop_tx.send(()).unwrap();
        let _ = self.join_handle.join();
        let guard = match self.requests_arc.lock() {
            Ok(guard) => guard,
            Err(poison_error) => poison_error.into_inner(),
        };
        (*guard).clone()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use masq_lib::ui_gateway::MessageTarget::ClientId;
    use masq_lib::messages::{UiSetup, UiSetupValue, UiShutdownOrder, NODE_UI_PROTOCOL};
    use masq_lib::test_utils::ui_connection::UiConnection;
    use masq_lib::utils::find_free_port;
    use masq_lib::messages::{FromMessageBody, ToMessageBody};

    #[test]
    fn two_in_two_out () {
        let port = find_free_port();
        let first_expected_response = NodeToUiMessage {
            target: ClientId(0),
            body: UiSetup {
                values: vec![
                    UiSetupValue{ name: "direction".to_string(), value: "to UI".to_string() }
                ]
            }.tmb(1234)
        };
        let second_expected_response = NodeToUiMessage {
            target: ClientId(0),
            body: UiShutdownOrder {}.tmb(0)
        };
        let stop_handle = MockWebSocketsServer::new(port)
            .queue_response (first_expected_response.clone())
            .queue_response (second_expected_response.clone())
            .start();
        let mut connection = UiConnection::new(port, NODE_UI_PROTOCOL);
        let first_request_payload = UiSetup {
            values: vec![
                UiSetupValue{ name: "direction".to_string(), value: "from UI".to_string() }
            ]
        };

        let first_actual_response: UiSetup = connection.transact_with_context_id(first_request_payload.clone(), 1234).unwrap();
        connection.send_string("}: Bad request :{".to_string());
        let second_actual_response: UiShutdownOrder = connection.receive().unwrap();

        let requests = stop_handle.stop();
        assert_eq! (requests[0], Ok(NodeFromUiMessage {
            client_id: 0,
            body: first_request_payload.tmb(1234),
        }));
        assert_eq! ((first_actual_response, 1234), UiSetup::fmb(first_expected_response.body).unwrap());
        assert_eq! (requests[1], Err("}: Bad request :{".to_string()));
        assert_eq! ((second_actual_response, 0), UiShutdownOrder::fmb(second_expected_response.body).unwrap());
    }
}
