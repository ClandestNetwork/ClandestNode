// Copyright (c) 2019-2020, MASQ (https://masq.ai) and/or its affiliates. All rights reserved.

use crate::websockets_client::{ClientError, NodeConnection};
use masq_lib::messages::{FromMessageBody, UiRedirect};
use masq_lib::ui_gateway::{NodeFromUiMessage, NodeToUiMessage};
use masq_lib::ui_traffic_converter::UiTrafficConverter;
use std::io;
use std::io::{Read, Write};

#[derive(Clone, Debug, PartialEq)]
pub enum ContextError {
    ConnectionDropped(String),
    PayloadError(u64, String),
    Other(String),
}

pub trait CommandContext {
    fn send(&mut self, message: NodeFromUiMessage) -> Result<(), ContextError>;
    fn transact(&mut self, message: NodeFromUiMessage) -> Result<NodeToUiMessage, ContextError>;
    fn stdin(&mut self) -> &mut dyn Read;
    fn stdout(&mut self) -> &mut dyn Write;
    fn stderr(&mut self) -> &mut dyn Write;
    fn close(&mut self);
}

pub struct CommandContextReal {
    connection: NodeConnection,
    pub stdin: Box<dyn Read>,
    pub stdout: Box<dyn Write>,
    pub stderr: Box<dyn Write>,
}

impl CommandContext for CommandContextReal {
    fn send(&mut self, message: NodeFromUiMessage) -> Result<(), ContextError> {
        let mut conversation = self.connection.start_conversation();
        match conversation.send(message) {
            Ok(_) => Ok(()),
            Err(ClientError::ConnectionDropped(e)) => Err(ContextError::ConnectionDropped(e)),
            Err(e) => Err(ContextError::Other(format!("{:?}", e))),
        }
    }

    fn transact(&mut self, message: NodeFromUiMessage) -> Result<NodeToUiMessage, ContextError> {
        let mut conversation = self.connection.start_conversation();
        let ntum = match conversation.transact(message) {
            Err(ClientError::ConnectionDropped(e)) => {
                return Err(ContextError::ConnectionDropped(e))
            }
            Err(e) => return Err(ContextError::Other(format!("{:?}", e))),
            Ok(ntum) => match ntum.body.payload {
                Err((code, msg)) => return Err(ContextError::PayloadError(code, msg)),
                Ok(_) => ntum,
            },
        };
        if ntum.body.opcode == "redirect".to_string() {
            match UiRedirect::fmb(ntum.body) {
                Ok((redirect, _)) => self.process_redirect(redirect),
                Err(e) => unimplemented!("{:?}", e),
            }
        } else {
            Ok(ntum)
        }
    }

    fn stdin(&mut self) -> &mut dyn Read {
        &mut self.stdin
    }

    fn stdout(&mut self) -> &mut dyn Write {
        &mut self.stdout
    }

    fn stderr(&mut self) -> &mut dyn Write {
        &mut self.stderr
    }

    fn close(&mut self) {
        let mut conversation = self.connection.start_conversation();
        conversation.close()
    }
}

impl CommandContextReal {
    pub fn new(port: u16) -> Self {
        Self {
            connection: NodeConnection::new(port).expect("Couldn't connect to Daemon or Node"),
            stdin: Box::new(io::stdin()),
            stdout: Box::new(io::stdout()),
            stderr: Box::new(io::stderr()),
        }
    }

    fn process_redirect(&mut self, redirect: UiRedirect) -> Result<NodeToUiMessage, ContextError> {
        let node_connection = match NodeConnection::new(redirect.port) {
            Ok(nc) => nc,
            Err(e) => unimplemented!("{:?}", e),
        };
        self.connection = node_connection;
        let message = match UiTrafficConverter::new_unmarshal_from_ui(&redirect.payload, 0) {
            Ok(msg) => msg,
            Err(e) => unimplemented!("{:?}", e),
        };
        self.transact(message)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::command_context::ContextError::{ConnectionDropped, PayloadError};
    use crate::test_utils::mock_websockets_server::MockWebSocketsServer;
    use crate::websockets_client::nfum;
    use masq_lib::messages::ToMessageBody;
    use masq_lib::messages::{
        FromMessageBody, UiFinancialsRequest, UiFinancialsResponse, UiRedirect,
    };
    use masq_lib::messages::{UiSetup, UiSetupValue, UiShutdownOrder};
    use masq_lib::test_utils::fake_stream_holder::{ByteArrayReader, ByteArrayWriter};
    use masq_lib::ui_gateway::MessageBody;
    use masq_lib::ui_gateway::MessagePath::TwoWay;
    use masq_lib::ui_gateway::MessageTarget::ClientId;
    use masq_lib::utils::find_free_port;

    #[test]
    fn works_when_everythings_fine() {
        let port = find_free_port();
        let stdin = ByteArrayReader::new(b"This is stdin.");
        let stdout = ByteArrayWriter::new();
        let stdout_arc = stdout.inner_arc();
        let stderr = ByteArrayWriter::new();
        let stderr_arc = stderr.inner_arc();
        let server = MockWebSocketsServer::new(port).queue_response(NodeToUiMessage {
            target: ClientId(0),
            body: UiSetup {
                values: vec![UiSetupValue {
                    name: "Okay,".to_string(),
                    value: "I did.".to_string(),
                }],
            }
            .tmb(1234),
        });
        let stop_handle = server.start();
        let mut subject = CommandContextReal::new(port);
        subject.stdin = Box::new(stdin);
        subject.stdout = Box::new(stdout);
        subject.stderr = Box::new(stderr);

        subject.send(nfum(UiShutdownOrder {})).unwrap();
        let response = subject
            .transact(nfum(UiSetup {
                values: vec![UiSetupValue {
                    name: "Say something".to_string(),
                    value: "to me.".to_string(),
                }],
            }))
            .unwrap();
        let mut input = String::new();
        subject.stdin().read_to_string(&mut input).unwrap();
        write!(subject.stdout(), "This is stdout.").unwrap();
        write!(subject.stderr(), "This is stderr.").unwrap();

        stop_handle.stop();
        assert_eq!(
            UiSetup::fmb(response.body).unwrap().0,
            UiSetup {
                values: vec![UiSetupValue {
                    name: "Okay,".to_string(),
                    value: "I did.".to_string(),
                }]
            }
        );
        assert_eq!(input, "This is stdin.".to_string());
        assert_eq!(
            stdout_arc.lock().unwrap().get_string(),
            "This is stdout.".to_string()
        );
        assert_eq!(
            stderr_arc.lock().unwrap().get_string(),
            "This is stderr.".to_string()
        );
    }

    #[test]
    fn works_when_server_sends_payload_error() {
        let port = find_free_port();
        let server = MockWebSocketsServer::new(port).queue_response(NodeToUiMessage {
            target: ClientId(0),
            body: MessageBody {
                opcode: "setup".to_string(),
                path: TwoWay(1234),
                payload: Err((101, "booga".to_string())),
            },
        });
        let stop_handle = server.start();
        let mut subject = CommandContextReal::new(port);

        let response = subject.transact(nfum(UiSetup { values: vec![] }));

        assert_eq!(response, Err(PayloadError(101, "booga".to_string())));
        stop_handle.stop();
    }

    #[test]
    fn works_when_server_sends_connection_error() {
        let port = find_free_port();
        let server = MockWebSocketsServer::new(port).queue_string("disconnect");
        let stop_handle = server.start();
        let mut subject = CommandContextReal::new(port);

        let response = subject.transact(nfum(UiSetup { values: vec![] }));

        stop_handle.stop();
        match response {
            Err(ConnectionDropped(_)) => (),
            x => panic!("Expected ConnectionDropped; got {:?} instead", x),
        }
    }

    #[test]
    fn close_sends_websockets_close() {
        let port = find_free_port();
        let server = MockWebSocketsServer::new(port);
        let stop_handle = server.start();
        let mut subject = CommandContextReal::new(port);

        subject.close();

        let received = stop_handle.stop();
        assert_eq!(received, vec![Err("Close(None)".to_string())])
    }

    #[test]
    fn can_follow_redirect() {
        let node_port = find_free_port();
        let node_server = MockWebSocketsServer::new(node_port).queue_response(NodeToUiMessage {
            target: ClientId(0),
            body: UiFinancialsResponse {
                payables: vec![],
                total_payable: 0,
                receivables: vec![],
                total_receivable: 0,
            }
            .tmb(1234),
        });
        let node_stop_handle = node_server.start();
        let daemon_port = find_free_port();
        let daemon_server = MockWebSocketsServer::new (daemon_port)
            .queue_response (NodeToUiMessage {
                target: ClientId(0),
                body: UiRedirect {
                    port: node_port,
                    opcode: "booga".to_string(),
                    context_id: Some(1234),
                    payload: r#"{"opcode":"financials","contextId":1234,"payload":{"payableMinimumAmount":0,"payableMaximumAge":0,"receivableMinimumAmount":0,"receivableMaximumAge":0}}"#.to_string()
                }.tmb(0)
            });
        let daemon_stop_handle = daemon_server.start();
        let request = NodeFromUiMessage {
            client_id: 0,
            body: UiFinancialsRequest {
                payable_minimum_amount: 0,
                payable_maximum_age: 0,
                receivable_minimum_amount: 0,
                receivable_maximum_age: 0,
            }
            .tmb(1234),
        };
        let mut subject = CommandContextReal::new(daemon_port);

        let result = subject.transact(request).unwrap();

        node_stop_handle.stop();
        daemon_stop_handle.stop();
        assert_eq!(result.body.path, TwoWay(1234));
        let (response, _) = UiFinancialsResponse::fmb(result.body).unwrap();
        assert_eq!(
            response,
            UiFinancialsResponse {
                payables: vec![],
                total_payable: 0,
                receivables: vec![],
                total_receivable: 0
            }
        );
    }
}
