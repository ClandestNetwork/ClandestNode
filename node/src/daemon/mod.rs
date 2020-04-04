// Copyright (c) 2019-2020, MASQ (https://masq.ai). All rights reserved.

pub mod daemon_initializer;
pub mod launch_verifier;
mod launcher;
mod setup_reporter;

#[cfg(test)]
mod mocks;

use crate::daemon::launch_verifier::{VerifierTools, VerifierToolsReal};
use crate::sub_lib::logger::Logger;
use crate::sub_lib::utils::NODE_MAILBOX_CAPACITY;
use actix::Recipient;
use actix::{Actor, Context, Handler, Message};
use masq_lib::messages::UiMessageError::UnexpectedMessage;
use masq_lib::messages::UiSetupResponseValueStatus::Set;
use masq_lib::messages::{
    FromMessageBody, ToMessageBody, UiMessageError, UiRedirect, UiSetupRequest, UiSetupResponse,
    UiSetupResponseValue, UiStartOrder, UiStartResponse, NODE_ALREADY_RUNNING_ERROR,
    NODE_LAUNCH_ERROR, NODE_NOT_RUNNING_ERROR,
};
use masq_lib::ui_gateway::MessagePath::{Conversation, FireAndForget};
use masq_lib::ui_gateway::MessageTarget::ClientId;
use masq_lib::ui_gateway::{MessageBody, MessagePath, NodeFromUiMessage, NodeToUiMessage};
use std::collections::HashMap;
use std::sync::mpsc::{Receiver, Sender};
use crate::daemon::setup_reporter::SetupReporterReal;

pub struct Recipients {
    ui_gateway_from_sub: Recipient<NodeFromUiMessage>,
    ui_gateway_to_sub: Recipient<NodeToUiMessage>,
    from_ui_subs: Vec<Recipient<NodeFromUiMessage>>,
    bind_message_subs: Vec<Recipient<DaemonBindMessage>>,
}

#[allow(clippy::type_complexity)]
pub trait ChannelFactory {
    fn make(
        &self,
    ) -> (
        Sender<HashMap<String, String>>,
        Receiver<HashMap<String, String>>,
    );
}

#[derive(Default)]
pub struct ChannelFactoryReal {}

impl ChannelFactoryReal {
    pub fn new() -> ChannelFactoryReal {
        ChannelFactoryReal {}
    }
}

#[derive(PartialEq, Debug)]
pub struct LaunchSuccess {
    pub new_process_id: u32,
    pub redirect_ui_port: u16,
}

pub trait Launcher {
    fn launch(&self, params: HashMap<String, String>) -> Result<Option<LaunchSuccess>, String>;
}

#[derive(Message, PartialEq, Clone)]
pub struct DaemonBindMessage {
    pub to_ui_message_recipient: Recipient<NodeToUiMessage>, // for everybody to send UI-bound messages to
    pub from_ui_message_recipient: Recipient<NodeFromUiMessage>, // for the WebsocketSupervisor to send inbound UI messages to the UiGateway
    pub from_ui_message_recipients: Vec<Recipient<NodeFromUiMessage>>, // for the UiGateway to relay inbound UI messages to everybody
}

pub struct Daemon {
    launcher: Box<dyn Launcher>,
    params: HashMap<String, UiSetupResponseValue>,
    ui_gateway_sub: Option<Recipient<NodeToUiMessage>>,
    node_process_id: Option<u32>,
    node_ui_port: Option<u16>,
    verifier_tools: Box<dyn VerifierTools>,
    logger: Logger,
}

impl Actor for Daemon {
    type Context = Context<Daemon>;
}

impl Handler<DaemonBindMessage> for Daemon {
    type Result = ();

    fn handle(&mut self, msg: DaemonBindMessage, ctx: &mut Self::Context) -> Self::Result {
        debug!(&self.logger, "Handling DaemonBindMessage");
        ctx.set_mailbox_capacity(NODE_MAILBOX_CAPACITY);
        self.ui_gateway_sub = Some(msg.to_ui_message_recipient);
        debug!(&self.logger, "DaemonBindMessage handled");
    }
}

impl Handler<NodeFromUiMessage> for Daemon {
    type Result = ();

    fn handle(&mut self, msg: NodeFromUiMessage, _ctx: &mut Self::Context) -> Self::Result {
        debug!(
            &self.logger,
            "Handing NodeFromUiMessage from client {}: {}", msg.client_id, msg.body.opcode
        );
        let client_id = msg.client_id;
        let opcode = msg.body.opcode.clone();
        // TODO: Gotta be a better way to arrange this code; but I'll wait until there are more than 2 choices
        let result: Result<(UiSetupRequest, u64), UiMessageError> =
            UiSetupRequest::fmb(msg.body.clone());
        match result {
            Ok((payload, context_id)) => self.handle_setup(client_id, context_id, payload),
            Err(UnexpectedMessage(_, _)) => {
                let result: Result<(UiStartOrder, u64), UiMessageError> =
                    UiStartOrder::fmb(msg.body.clone());
                match result {
                    Ok((_, context_id)) => self.handle_start_order(client_id, context_id),
                    Err(UnexpectedMessage(_, _)) => {
                        self.handle_unexpected_message(msg.client_id, msg.body);
                    }
                    Err(e) => error!(
                        &self.logger,
                        "Bad {} request from client {}: {:?}", opcode, client_id, e
                    ),
                }
            }
            Err(e) => error!(
                &self.logger,
                "Bad {} request from client {}: {:?}", opcode, client_id, e
            ),
        }
        debug!(&self.logger, "NodeFromUiMessage handled");
    }
}

impl Daemon {
    pub fn new(launcher: Box<dyn Launcher>) -> Daemon {
        Daemon {
            launcher,
            params: HashMap::new(),
            ui_gateway_sub: None,
            node_process_id: None,
            node_ui_port: None,
            verifier_tools: Box::new(VerifierToolsReal::new()),
            logger: Logger::new("Daemon"),
        }
    }

    // pub fn get_default_params() -> HashMap<String, String> { // TODO: Remove
    //     let schema = crate::node_configurator::node_configurator_initialization::app();
    //     schema
    //         .p
    //         .opts
    //         .iter()
    //         .flat_map(|opt| {
    //             let name = opt.b.name.to_string();
    //             if &name == "ui-port" {
    //                 return None;
    //             }
    //             #[cfg(target_os = "windows")]
    //             {
    //                 if &name == "real-user" {
    //                     return None;
    //                 }
    //             }
    //             match opt.v.default_val {
    //                 Some(os_str) => Some((name, os_str.to_str().unwrap().to_string())),
    //                 None => None,
    //             }
    //         })
    //         .collect()
    // }

    fn handle_setup(&mut self, client_id: u64, context_id: u64, payload: UiSetupRequest) {
        let running = if self.port_if_node_is_running().is_some() {
            true
        } else {
            payload.values.into_iter().for_each(|usv| {
                match usv.value {
                    None => self.params.remove(&usv.name),
                    Some(value) => self.params.insert(usv.name.clone(), UiSetupResponseValue::new (&usv.name, &value, Set)),
                };
            });
            false
        };
        let mut report = SetupReporterReal::get_default_params();
        report.extend(self.params.clone().into_iter());
        let msg = NodeToUiMessage {
            target: ClientId(client_id),
            body: UiSetupResponse {
                running,
                values: report
                    .into_iter()
                    .map(|(name, value)| value)
                    .collect(),
            }
            .tmb(context_id),
        };
        self.ui_gateway_sub
            .as_ref()
            .expect("UiGateway is unbound")
            .try_send(msg)
            .expect("UiGateway is dead");
    }

    fn handle_start_order(&mut self, client_id: u64, context_id: u64) {
        match self.port_if_node_is_running() {
            Some(_) => self.respond_to_ui(
                client_id,
                MessageBody {
                    opcode: "start".to_string(),
                    path: Conversation(context_id),
                    payload: Err((
                        NODE_ALREADY_RUNNING_ERROR,
                        "Could not launch Node: already running".to_string(),
                    )),
                },
            ),
            None => match self.launcher.launch(
                self.params.iter()
                    .filter(|(k, v)| v.status == Set)
                    .map(|(k, v)| (k.to_string(), v.value.to_string()))
                    .collect()
            ) {
                Ok(Some(success)) => {
                    self.node_process_id = Some(success.new_process_id);
                    self.node_ui_port = Some(success.redirect_ui_port);
                    self.respond_to_ui(
                        client_id,
                        UiStartResponse {
                            new_process_id: success.new_process_id,
                            redirect_ui_port: success.redirect_ui_port,
                        }
                        .tmb(context_id),
                    )
                }
                Ok(None) => (),
                Err(s) => self.respond_to_ui(
                    client_id,
                    MessageBody {
                        opcode: "start".to_string(),
                        path: Conversation(context_id),
                        payload: Err((NODE_LAUNCH_ERROR, format!("Could not launch Node: {}", s))),
                    },
                ),
            },
        }
    }

    fn handle_unexpected_message(&mut self, client_id: u64, body: MessageBody) {
        match self.port_if_node_is_running() {
            Some(port) => {
                info!(
                    &self.logger,
                    "Daemon is redirecting {} message from UI {} Node at port {}",
                    body.opcode,
                    client_id,
                    port
                );
                self.ui_gateway_sub
                    .as_ref()
                    .expect("UiGateway is unbound")
                    .try_send(NodeToUiMessage {
                        target: ClientId(client_id),
                        body: UiRedirect {
                            port,
                            opcode: body.opcode,
                            context_id: match body.path {
                                FireAndForget => None,
                                Conversation(context_id) => Some(context_id),
                            },
                            payload: match body.payload {
                                Ok(json) => json,
                                Err((_code, _message)) => unimplemented!(),
                            },
                        }
                        .tmb(0),
                    })
                    .expect("UiGateway is dead")
            }
            None => self.send_node_is_not_running_redirect(client_id, body.opcode),
        }
    }

    fn port_if_node_is_running(&mut self) -> Option<u16> {
        if let Some(process_id) = self.node_process_id {
            if self.verifier_tools.process_is_running(process_id) {
                Some(
                    self.node_ui_port
                        .expect("Internal error: node_process_id is set but node_ui_port is not"),
                )
            } else {
                self.node_process_id = None;
                self.node_ui_port = None;
                None
            }
        } else {
            None
        }
    }

    fn send_node_is_not_running_redirect(&self, client_id: u64, opcode: String) {
        error!(
            &self.logger,
            "Daemon is sending redirect error for {} message to UI {}: Node is not running",
            opcode,
            client_id
        );
        self.send_node_is_not_running_error(client_id, "redirect", &opcode, FireAndForget);
    }

    fn send_node_is_not_running_error(
        &self,
        client_id: u64,
        msg_opcode: &str,
        err_opcode: &str,
        path: MessagePath,
    ) {
        self.ui_gateway_sub
            .as_ref()
            .expect("UiGateway is unbound")
            .try_send(NodeToUiMessage {
                target: ClientId(client_id),
                body: MessageBody {
                    opcode: msg_opcode.to_string(),
                    path,
                    payload: Err((
                        NODE_NOT_RUNNING_ERROR,
                        format!("Cannot handle {} request: Node is not running", err_opcode),
                    )),
                },
            })
            .expect("UiGateway is dead")
    }

    fn respond_to_ui(&self, client_id: u64, body: MessageBody) {
        self.ui_gateway_sub
            .as_ref()
            .expect("UiGateway is unbound")
            .try_send(NodeToUiMessage {
                target: ClientId(client_id),
                body,
            })
            .expect("UiGateway is dead")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::daemon::mocks::VerifierToolsMock;
    use crate::daemon::LaunchSuccess;
    use crate::test_utils::recorder::{make_recorder, Recorder};
    use actix::System;
    use masq_lib::messages::{UiFinancialsRequest, UiRedirect, UiSetupRequest, UiSetupRequestValue, UiSetupResponse, UiShutdownRequest, UiStartOrder, UiStartResponse, NODE_ALREADY_RUNNING_ERROR, NODE_LAUNCH_ERROR, NODE_NOT_RUNNING_ERROR};
    use std::cell::RefCell;
    use std::collections::HashSet;
    use std::iter::FromIterator;
    use std::sync::{Arc, Mutex};
    use crate::daemon::setup_reporter::SetupReporterReal;

    struct LauncherMock {
        launch_params: Arc<Mutex<Vec<HashMap<String, String>>>>,
        launch_results: RefCell<Vec<Result<Option<LaunchSuccess>, String>>>,
    }

    impl Launcher for LauncherMock {
        fn launch(&self, params: HashMap<String, String>) -> Result<Option<LaunchSuccess>, String> {
            self.launch_params.lock().unwrap().push(params);
            self.launch_results.borrow_mut().remove(0)
        }
    }

    impl LauncherMock {
        fn new() -> LauncherMock {
            LauncherMock {
                launch_params: Arc::new(Mutex::new(vec![])),
                launch_results: RefCell::new(vec![]),
            }
        }

        fn launch_params(mut self, params: &Arc<Mutex<Vec<HashMap<String, String>>>>) -> Self {
            self.launch_params = params.clone();
            self
        }

        fn launch_result(self, result: Result<Option<LaunchSuccess>, String>) -> Self {
            self.launch_results.borrow_mut().push(result);
            self
        }
    }

    fn make_bind_message(ui_gateway: Recorder) -> DaemonBindMessage {
        let (stub, _, _) = make_recorder();
        let stub_sub = stub.start().recipient::<NodeFromUiMessage>();
        let ui_gateway_sub = ui_gateway.start().recipient::<NodeToUiMessage>();
        DaemonBindMessage {
            to_ui_message_recipient: ui_gateway_sub,
            from_ui_message_recipient: stub_sub,
            from_ui_message_recipients: vec![],
        }
    }

    #[test]
    fn accepts_empty_setup_when_node_is_not_running_and_returns_defaults() {
        let (ui_gateway, _, ui_gateway_recording_arc) = make_recorder();
        let verifier_tools = VerifierToolsMock::new().process_is_running_result(false);
        let system = System::new("test");
        let mut subject = Daemon::new(Box::new(LauncherMock::new()));
        subject.verifier_tools = Box::new(verifier_tools);
        let subject_addr = subject.start();
        subject_addr
            .try_send(make_bind_message(ui_gateway))
            .unwrap();

        subject_addr
            .try_send(NodeFromUiMessage {
                client_id: 1234,
                body: UiSetupRequest { values: vec![] }.tmb(4321),
            })
            .unwrap();

        System::current().stop();
        system.run();
        let ui_gateway_recording = ui_gateway_recording_arc.lock().unwrap();
        let record = ui_gateway_recording
            .get_record::<NodeToUiMessage>(0)
            .clone();
        assert_eq!(record.target, ClientId(1234));
        let (payload, context_id): (UiSetupResponse, u64) =
            UiSetupResponse::fmb(record.body).unwrap();
        assert_eq!(context_id, 4321);
        assert_eq!(payload.running, false);
        let actual_pairs: Vec<(String, UiSetupResponseValue)> = payload
            .values
            .into_iter()
            .map(|value| (value.name.clone(), value))
            .collect();
        let expected_pairs: Vec<(String, UiSetupResponseValue)> =
            SetupReporterReal::get_default_params().into_iter().collect();

        assert_eq!(actual_pairs, expected_pairs);
    }

    #[test]
    fn accepts_full_setup_when_node_is_not_running_and_returns_settings_then_remembers_them() {
        let (ui_gateway, _, ui_gateway_recording_arc) = make_recorder();
        let system = System::new("test");
        let verifier_tools = VerifierToolsMock::new().process_is_running_result(false);
        let mut subject = Daemon::new(Box::new(LauncherMock::new()));
        subject.verifier_tools = Box::new(verifier_tools);
        subject.params = vec![
            ("dns-servers", "8.8.8.8"),
            ("chain", "ropsten"),
            ("config-file", "biggles.txt"),
            ("db-password", "goober"),
            ("real-user", "1234:4321:hormel"),
        ]
        .into_iter()
        .map(|(k, v)| (k.to_string(), UiSetupResponseValue::new (k, v, Set)))
        .collect();
        let subject_addr = subject.start();
        subject_addr
            .try_send(make_bind_message(ui_gateway))
            .unwrap();

        subject_addr
            .try_send(NodeFromUiMessage {
                client_id: 1234,
                body: UiSetupRequest {
                    values: vec![
                        UiSetupRequestValue::clear("chain"),
                        UiSetupRequestValue::clear("config-file"),
                        UiSetupRequestValue::clear("db-password"),
                        UiSetupRequestValue::clear("real-user"),
                    ],
                }
                .tmb(4321),
            })
            .unwrap();

        System::current().stop();
        system.run();
        let ui_gateway_recording = ui_gateway_recording_arc.lock().unwrap();
        let record = ui_gateway_recording
            .get_record::<NodeToUiMessage>(0)
            .clone();
        assert_eq!(record.target, ClientId(1234));
        let (payload, context_id): (UiSetupResponse, u64) =
            UiSetupResponse::fmb(record.body).unwrap();
        assert_eq!(context_id, 4321);
        assert_eq!(payload.running, false);
        let actual_pairs: HashMap<String, UiSetupResponseValue> = payload
            .values
            .into_iter()
            .map(|value| (value.name.clone(), value))
            .collect();
        let mut expected_pairs = SetupReporterReal::get_default_params();
        adjust_expected_pairs(&mut expected_pairs, "dns-servers", "8.8.8.8");

        assert_eq!(actual_pairs, expected_pairs);
    }

    #[test]
    fn accepts_empty_setup_when_node_is_not_running_and_clears_existing_state() {
        let (ui_gateway, _, ui_gateway_recording_arc) = make_recorder();
        let system = System::new("test");
        let verifier_tools = VerifierToolsMock::new().process_is_running_result(false);
        let mut subject = Daemon::new(Box::new(LauncherMock::new()));
        subject.verifier_tools = Box::new(verifier_tools);
        let subject_addr = subject.start();
        subject_addr
            .try_send(make_bind_message(ui_gateway))
            .unwrap();
        subject_addr
            .try_send(NodeFromUiMessage {
                client_id: 1234,
                body: UiSetupRequest {
                    values: vec![
                        UiSetupRequestValue::new("chain", "ropsten"),
                        UiSetupRequestValue::new("config-file", "biggles.txt"),
                        UiSetupRequestValue::new("db-password", "goober"),
                        UiSetupRequestValue::new("real-user", "1234:4321:hormel"),
                    ],
                }
                .tmb(4321),
            })
            .unwrap();

        subject_addr
            .try_send(NodeFromUiMessage {
                client_id: 1234,
                body: UiSetupRequest { values: vec![] }.tmb(4321),
            })
            .unwrap();

        System::current().stop();
        system.run();
        let ui_gateway_recording = ui_gateway_recording_arc.lock().unwrap();
        let record = ui_gateway_recording
            .get_record::<NodeToUiMessage>(0)
            .clone();
        assert_eq!(record.target, ClientId(1234));
        let (payload, context_id): (UiSetupResponse, u64) =
            UiSetupResponse::fmb(record.body).unwrap();
        assert_eq!(context_id, 4321);
        assert_eq!(payload.running, false);
        let actual_pairs: HashMap<String, UiSetupResponseValue> = payload
            .values
            .into_iter()
            .map(|value| (value.name.to_string(), value))
            .collect();
        let mut expected_pairs = SetupReporterReal::get_default_params();
        adjust_expected_pairs(&mut expected_pairs, "chain", "ropsten");
        adjust_expected_pairs(&mut expected_pairs, "config-file", "biggles.txt");
        adjust_expected_pairs(&mut expected_pairs, "db-password", "goober");
        adjust_expected_pairs(&mut expected_pairs, "real-user", "1234:4321:hormel");

        assert_eq!(actual_pairs, expected_pairs);

        let record = ui_gateway_recording
            .get_record::<NodeToUiMessage>(1)
            .clone();
        assert_eq!(record.target, ClientId(1234));
        let (payload, context_id): (UiSetupResponse, u64) =
            UiSetupResponse::fmb(record.body).unwrap();
        assert_eq!(payload.running, false);
        assert_eq!(context_id, 4321);
        let actual_pairs: HashMap<String, UiSetupResponseValue> = payload
            .values
            .into_iter()
            .map(|value| (value.name.clone(), value))
            .collect();

        assert_eq!(actual_pairs, expected_pairs);
    }

    #[test]
    fn accepts_full_setup_when_node_is_running_and_ignores_it() {
        let (ui_gateway, _, ui_gateway_recording_arc) = make_recorder();
        let system = System::new("test");
        let verifier_tools = VerifierToolsMock::new().process_is_running_result(true);
        let mut subject = Daemon::new(Box::new(LauncherMock::new()));
        subject.node_ui_port = Some(1234);
        subject.node_process_id = Some(4321);
        subject.verifier_tools = Box::new(verifier_tools);
        let subject_addr = subject.start();
        subject_addr
            .try_send(make_bind_message(ui_gateway))
            .unwrap();

        subject_addr
            .try_send(NodeFromUiMessage {
                client_id: 1234,
                body: UiSetupRequest {
                    values: vec![
                        UiSetupRequestValue::new("chain", "ropsten"),
                        UiSetupRequestValue::new("config-file", "biggles.txt"),
                        UiSetupRequestValue::new("db-password", "goober"),
                        UiSetupRequestValue::new("real-user", "1234:4321:hormel"),
                    ],
                }
                .tmb(4321),
            })
            .unwrap();

        System::current().stop();
        system.run();
        let ui_gateway_recording = ui_gateway_recording_arc.lock().unwrap();
        let record = ui_gateway_recording
            .get_record::<NodeToUiMessage>(0)
            .clone();
        assert_eq!(record.target, ClientId(1234));
        let (payload, context_id): (UiSetupResponse, u64) =
            UiSetupResponse::fmb(record.body).unwrap();
        assert_eq!(context_id, 4321);
        assert_eq!(payload.running, true);
        let actual_pairs: Vec<(String, UiSetupResponseValue)> = payload
            .values
            .into_iter()
            .map(|value| (value.name.clone(), value))
            .collect();
        let expected_pairs: Vec<(String, UiSetupResponseValue)> =
            SetupReporterReal::get_default_params().into_iter().collect();

        assert_eq!(actual_pairs, expected_pairs);
    }

    #[test]
    fn setup_judges_node_not_running_when_port_and_pid_are_none_without_checking_os() {
        let (ui_gateway, _, ui_gateway_recording_arc) = make_recorder();
        let system = System::new("test");
        let verifier_tools = VerifierToolsMock::new();
        let mut subject = Daemon::new(Box::new(LauncherMock::new()));
        subject.node_ui_port = None;
        subject.node_process_id = None;
        subject.verifier_tools = Box::new(verifier_tools);
        let subject_addr = subject.start();
        subject_addr
            .try_send(make_bind_message(ui_gateway))
            .unwrap();

        subject_addr
            .try_send(NodeFromUiMessage {
                client_id: 1234,
                body: UiSetupRequest {
                    values: vec![UiSetupRequestValue::new("chain", "ropsten")],
                }
                .tmb(4321),
            })
            .unwrap();

        System::current().stop();
        system.run();
        let ui_gateway_recording = ui_gateway_recording_arc.lock().unwrap();
        let record = ui_gateway_recording
            .get_record::<NodeToUiMessage>(0)
            .clone();
        assert_eq!(record.target, ClientId(1234));
        let (payload, context_id): (UiSetupResponse, u64) =
            UiSetupResponse::fmb(record.body).unwrap();
        assert_eq!(context_id, 4321);
        assert_eq!(payload.running, false);
        let actual_pairs: Vec<(String, UiSetupResponseValue)> = payload
            .values
            .into_iter()
            .map(|value| (value.name.clone(), value))
            .collect();
        assert_eq!(
            actual_pairs.contains(&("chain".to_string(), UiSetupResponseValue::new("chain", "ropsten", Set))),
            true
        );
    }

    #[test]
    fn setup_judges_node_not_running_when_port_and_pid_are_set_but_os_says_different() {
        let (ui_gateway, _, ui_gateway_recording_arc) = make_recorder();
        let system = System::new("test");
        let verifier_tools = VerifierToolsMock::new().process_is_running_result(false); // only consulted once; second time, we already know
        let mut subject = Daemon::new(Box::new(LauncherMock::new()));
        subject.node_ui_port = Some(1234);
        subject.node_process_id = Some(4321);
        subject.verifier_tools = Box::new(verifier_tools);
        let subject_addr = subject.start();
        subject_addr
            .try_send(make_bind_message(ui_gateway))
            .unwrap();
        let msg = NodeFromUiMessage {
            client_id: 1234,
            body: UiSetupRequest {
                values: vec![UiSetupRequestValue::new("chain", "ropsten")],
            }
            .tmb(4321),
        };

        subject_addr.try_send(msg.clone()).unwrap(); // accepted because Node, thought to be up, turns out to be down
        subject_addr.try_send(msg.clone()).unwrap(); // accepted without asking because we already know Node is down

        System::current().stop();
        system.run();
        let ui_gateway_recording = ui_gateway_recording_arc.lock().unwrap();
        let check_record = |idx: usize| {
            let record = ui_gateway_recording
                .get_record::<NodeToUiMessage>(idx)
                .clone();
            assert_eq!(record.target, ClientId(1234));
            let (payload, context_id): (UiSetupResponse, u64) =
                UiSetupResponse::fmb(record.body).unwrap();
            assert_eq!(context_id, 4321);
            assert_eq!(payload.running, false);
            let actual_pairs: HashSet<(String, String)> = payload
                .values
                .into_iter()
                .map(|value| (value.name, value.value))
                .collect();
            assert_eq!(
                actual_pairs.contains(&("chain".to_string(), "ropsten".to_string())),
                true
            );
        };
        check_record(0);
        check_record(1);
    }

    #[test]
    fn overrides_defaults() {
        let (ui_gateway, _, ui_gateway_recording_arc) = make_recorder();
        let system = System::new("test");
        let verifier_tools = VerifierToolsMock::new();
        let mut subject = Daemon::new(Box::new(LauncherMock::new()));
        subject.verifier_tools = Box::new(verifier_tools);
        let subject_addr = subject.start();
        subject_addr
            .try_send(make_bind_message(ui_gateway))
            .unwrap();

        subject_addr
            .try_send(NodeFromUiMessage {
                client_id: 1234,
                body: UiSetupRequest {
                    values: vec![UiSetupRequestValue::new("dns-servers", "192.168.0.1")],
                }
                .tmb(4321),
            })
            .unwrap();

        System::current().stop();
        system.run();
        let ui_gateway_recording = ui_gateway_recording_arc.lock().unwrap();
        let record = ui_gateway_recording
            .get_record::<NodeToUiMessage>(0)
            .clone();
        assert_eq!(record.target, ClientId(1234));
        let (payload, context_id): (UiSetupResponse, u64) =
            UiSetupResponse::fmb(record.body).unwrap();
        assert_eq!(context_id, 4321);
        assert_eq!(payload.running, false);
        let actual_pairs: HashMap<String, UiSetupResponseValue> = payload
            .values
            .into_iter()
            .map(|value| (value.name.clone(), value))
            .collect();
        let mut expected_pairs = SetupReporterReal::get_default_params();
        adjust_expected_pairs (&mut expected_pairs, "dns-servers", "192.168.0.1");

        assert_eq!(actual_pairs, expected_pairs);
    }

    #[test]
    fn accepts_start_order_launches_and_replies_parent_success() {
        let (ui_gateway, _, ui_gateway_recording_arc) = make_recorder();
        let launch_params_arc = Arc::new(Mutex::new(vec![]));
        let launcher = LauncherMock::new()
            .launch_params(&launch_params_arc)
            .launch_result(Ok(Some(LaunchSuccess {
                new_process_id: 2345,
                redirect_ui_port: 5432,
            })));
        let verifier_tools = VerifierToolsMock::new();
        let system = System::new("test");
        let mut subject = Daemon::new(Box::new(launcher));
        subject
            .params
            .insert("db-password".to_string(), UiSetupResponseValue::new("db-password", "goober", Set));
        subject.verifier_tools = Box::new(verifier_tools);
        let subject_addr = subject.start();
        subject_addr
            .try_send(make_bind_message(ui_gateway))
            .unwrap();

        subject_addr
            .try_send(NodeFromUiMessage {
                client_id: 1234,
                body: UiStartOrder {}.tmb(4321),
            })
            .unwrap();

        System::current().stop();
        system.run();
        let launch_params = launch_params_arc.lock().unwrap();
        assert_eq!(
            *launch_params,
            vec![HashMap::from_iter(
                vec![("db-password", "goober")]
                    .into_iter()
                    .map(|(n, v)| (n.to_string(), v.to_string()))
            )]
        );
        let ui_gateway_recording = ui_gateway_recording_arc.lock().unwrap();
        let record = ui_gateway_recording
            .get_record::<NodeToUiMessage>(0)
            .clone();
        assert_eq!(record.target, ClientId(1234));
        let (payload, context_id): (UiStartResponse, u64) =
            UiStartResponse::fmb(record.body).unwrap();
        assert_eq!(context_id, 4321);
        assert_eq!(
            payload,
            UiStartResponse {
                new_process_id: 2345,
                redirect_ui_port: 5432
            }
        );
    }

    #[test]
    fn accepts_start_order_launches_and_replies_child_success() {
        let (ui_gateway, _, ui_gateway_recording_arc) = make_recorder();
        let launcher = LauncherMock::new().launch_result(Ok(None));
        let verifier_tools = VerifierToolsMock::new();
        let system = System::new("test");
        let mut subject = Daemon::new(Box::new(launcher));
        subject
            .params
            .insert("db-password".to_string(), UiSetupResponseValue::new("db-password", "goober", Set));
        subject.verifier_tools = Box::new(verifier_tools);
        let subject_addr = subject.start();
        subject_addr
            .try_send(make_bind_message(ui_gateway))
            .unwrap();

        subject_addr
            .try_send(NodeFromUiMessage {
                client_id: 1234,
                body: UiStartOrder {}.tmb(4321),
            })
            .unwrap();

        System::current().stop();
        system.run();
        let ui_gateway_recording = ui_gateway_recording_arc.lock().unwrap();
        assert_eq!(ui_gateway_recording.len(), 0);
    }

    #[test]
    fn maintains_setup_through_start_order() {
        let (ui_gateway, _, ui_gateway_recording_arc) = make_recorder();
        let launcher = LauncherMock::new().launch_result(Ok(Some(LaunchSuccess {
            new_process_id: 2345,
            redirect_ui_port: 5432,
        })));
        let verifier_tools = VerifierToolsMock::new()
            .process_is_running_result(false)
            .process_is_running_result(false)
            .process_is_running_result(false);
        let system = System::new("test");
        let mut subject = Daemon::new(Box::new(launcher));
        subject
            .params
            .insert("db-password".to_string(), UiSetupResponseValue::new("db-password", "goober", Set));
        subject.verifier_tools = Box::new(verifier_tools);
        let subject_addr = subject.start();
        subject_addr
            .try_send(make_bind_message(ui_gateway))
            .unwrap();

        subject_addr
            .try_send(NodeFromUiMessage {
                client_id: 1234,
                body: UiSetupRequest { values: vec![] }.tmb(4321),
            })
            .unwrap();
        subject_addr
            .try_send(NodeFromUiMessage {
                client_id: 1234,
                body: UiStartOrder {}.tmb(4321),
            })
            .unwrap();
        subject_addr
            .try_send(NodeFromUiMessage {
                client_id: 1234,
                body: UiSetupRequest { values: vec![] }.tmb(4321),
            })
            .unwrap();

        System::current().stop();
        system.run();
        let ui_gateway_recording = ui_gateway_recording_arc.lock().unwrap();
        let record = ui_gateway_recording
            .get_record::<NodeToUiMessage>(0)
            .clone();
        let (setup_before, _) = UiSetupResponse::fmb(record.body).unwrap();
        let setup_before_pairs = setup_before
            .values
            .into_iter()
            .map(|pair| (pair.name, pair.value))
            .collect::<HashSet<(String, String)>>();
        let record = ui_gateway_recording
            .get_record::<NodeToUiMessage>(2)
            .clone();
        let (setup_after, _) = UiSetupResponse::fmb(record.body).unwrap();
        let setup_after_pairs = setup_after
            .values
            .into_iter()
            .map(|pair| (pair.name, pair.value))
            .collect::<HashSet<(String, String)>>();
        assert_eq!(setup_after_pairs, setup_before_pairs);
    }

    #[test]
    fn accepts_start_order_launches_and_replies_failure() {
        let (ui_gateway, _, ui_gateway_recording_arc) = make_recorder();
        let launcher = LauncherMock::new().launch_result(Err("booga".to_string()));
        let verifier_tools = VerifierToolsMock::new();
        let system = System::new("test");
        let mut subject = Daemon::new(Box::new(launcher));
        subject
            .params
            .insert("db-password".to_string(), UiSetupResponseValue::new("db-password", "goober", Set));
        subject.verifier_tools = Box::new(verifier_tools);
        let subject_addr = subject.start();
        subject_addr
            .try_send(make_bind_message(ui_gateway))
            .unwrap();

        subject_addr
            .try_send(NodeFromUiMessage {
                client_id: 1234,
                body: UiStartOrder {}.tmb(4321),
            })
            .unwrap();

        System::current().stop();
        system.run();
        let ui_gateway_recording = ui_gateway_recording_arc.lock().unwrap();
        let record = ui_gateway_recording
            .get_record::<NodeToUiMessage>(0)
            .clone();
        assert_eq!(record.target, ClientId(1234));
        let (code, message) = record.body.payload.err().unwrap();
        assert_eq!(code, NODE_LAUNCH_ERROR);
        assert_eq!(message, "Could not launch Node: booga".to_string());
    }

    #[test]
    fn rejects_start_order_when_node_is_already_running() {
        let (ui_gateway, _, ui_gateway_recording_arc) = make_recorder();
        let launcher = LauncherMock::new().launch_result(Err("booga".to_string()));
        let verifier_tools = VerifierToolsMock::new().process_is_running_result(true);
        let system = System::new("test");
        let mut subject = Daemon::new(Box::new(launcher));
        subject
            .params
            .insert("db-password".to_string(), UiSetupResponseValue::new ("db-password", "goober", Set));
        subject.node_ui_port = Some(1234);
        subject.node_process_id = Some(3421);
        subject.verifier_tools = Box::new(verifier_tools);
        let subject_addr = subject.start();
        subject_addr
            .try_send(make_bind_message(ui_gateway))
            .unwrap();

        subject_addr
            .try_send(NodeFromUiMessage {
                client_id: 1234,
                body: UiStartOrder {}.tmb(4321),
            })
            .unwrap();

        System::current().stop();
        system.run();
        let ui_gateway_recording = ui_gateway_recording_arc.lock().unwrap();
        let record = ui_gateway_recording
            .get_record::<NodeToUiMessage>(0)
            .clone();
        assert_eq!(record.target, ClientId(1234));
        assert_eq!(&record.body.opcode, "start");
        let (code, message) = record.body.payload.err().unwrap();
        assert_eq!(code, NODE_ALREADY_RUNNING_ERROR);
        assert_eq!(
            message,
            "Could not launch Node: already running".to_string()
        );
    }

    #[test]
    fn sets_process_id_and_node_ui_port_upon_node_launch_success() {
        let (ui_gateway, _, _) = make_recorder();
        let launcher = LauncherMock::new().launch_result(Ok(Some(LaunchSuccess {
            new_process_id: 54321,
            redirect_ui_port: 7777,
        })));
        let verifier_tools = VerifierToolsMock::new();
        let mut subject = Daemon::new(Box::new(launcher));
        subject.ui_gateway_sub = Some(ui_gateway.start().recipient());
        subject.verifier_tools = Box::new(verifier_tools);

        subject.handle_start_order(1234, 2345);

        assert_eq!(subject.node_process_id, Some(54321));
        assert_eq!(subject.node_ui_port, Some(7777));
    }

    #[test]
    fn accepts_shutdown_order_after_start_and_returns_redirect() {
        let (ui_gateway, _, ui_gateway_recording_arc) = make_recorder();
        let system = System::new("test");
        let process_is_running_params_arc = Arc::new(Mutex::new(vec![]));
        let verifier_tools = VerifierToolsMock::new()
            .process_is_running_params(&process_is_running_params_arc)
            .process_is_running_result(true);
        let mut subject = Daemon::new(Box::new(LauncherMock::new()));
        subject.node_ui_port = Some(7777);
        subject.node_process_id = Some(8888);
        subject.verifier_tools = Box::new(verifier_tools);
        let subject_addr = subject.start();
        subject_addr
            .try_send(make_bind_message(ui_gateway))
            .unwrap();
        let body: MessageBody = UiShutdownRequest {}.tmb(4321); // Context ID is irrelevant

        subject_addr
            .try_send(NodeFromUiMessage {
                client_id: 1234,
                body: body.clone(),
            })
            .unwrap();

        System::current().stop();
        system.run();
        let ui_gateway_recording = ui_gateway_recording_arc.lock().unwrap();
        let record = ui_gateway_recording
            .get_record::<NodeToUiMessage>(0)
            .clone();
        assert_eq!(record.target, ClientId(1234));
        assert_eq!(record.body.path, FireAndForget);
        let (payload, context_id): (UiRedirect, u64) = UiRedirect::fmb(record.body).unwrap();
        assert_eq!(context_id, 0);
        assert_eq!(
            payload,
            UiRedirect {
                port: 7777,
                opcode: body.opcode,
                context_id: Some(4321),
                payload: body.payload.unwrap(),
            }
        );
        let process_is_running_params = process_is_running_params_arc.lock().unwrap();
        assert_eq!(*process_is_running_params, vec![8888])
    }

    #[test]
    fn accepts_shutdown_order_discovers_non_running_node_and_returns_redirect_error() {
        let (ui_gateway, _, _) = make_recorder();
        let system = System::new("test");
        let process_is_running_params_arc = Arc::new(Mutex::new(vec![]));
        let verifier_tools = VerifierToolsMock::new()
            .process_is_running_params(&process_is_running_params_arc)
            .process_is_running_result(false); // only consulted once; second time, we already know
        let mut subject = Daemon::new(Box::new(LauncherMock::new()));
        subject.node_ui_port = Some(7777);
        subject.node_process_id = Some(8888);
        subject.verifier_tools = Box::new(verifier_tools);
        let subject_addr = subject.start();
        subject_addr
            .try_send(make_bind_message(ui_gateway))
            .unwrap();
        let body: MessageBody = UiShutdownRequest {}.tmb(4321); // Context ID is irrelevant

        subject_addr
            .try_send(NodeFromUiMessage {
                client_id: 1234,
                body: body.clone(),
            })
            .unwrap(); // rejected because Node, thought to be up, discovered to be down
        subject_addr
            .try_send(NodeFromUiMessage {
                client_id: 1234,
                body: body.clone(),
            })
            .unwrap(); // rejected because Node known to be down

        System::current().stop();
        system.run();
        // no failure to retrieve second result from verifier_tools: test passes
    }

    #[test]
    fn accepts_financials_request_before_start_and_returns_error() {
        let (ui_gateway, _, ui_gateway_recording_arc) = make_recorder();
        let system = System::new("test");
        let verifier_tools = VerifierToolsMock::new();
        let mut subject = Daemon::new(Box::new(LauncherMock::new()));
        subject.node_ui_port = None;
        subject.node_process_id = None;
        subject.verifier_tools = Box::new(verifier_tools);
        let subject_addr = subject.start();
        subject_addr
            .try_send(make_bind_message(ui_gateway))
            .unwrap();
        let body: MessageBody = UiFinancialsRequest {
            payable_minimum_amount: 0,
            payable_maximum_age: 0,
            receivable_minimum_amount: 0,
            receivable_maximum_age: 0,
        }
        .tmb(4321);

        subject_addr
            .try_send(NodeFromUiMessage {
                client_id: 1234,
                body: body.clone(),
            })
            .unwrap();

        System::current().stop();
        system.run();
        let ui_gateway_recording = ui_gateway_recording_arc.lock().unwrap();
        let record = ui_gateway_recording
            .get_record::<NodeToUiMessage>(0)
            .clone();
        assert_eq!(record.target, ClientId(1234));
        assert_eq!(
            record.body.payload,
            Err((
                NODE_NOT_RUNNING_ERROR,
                "Cannot handle financials request: Node is not running".to_string()
            ))
        );
    }

    fn adjust_expected_pairs (expected_pairs: &mut HashMap<String, UiSetupResponseValue>, name: &str, value: &str) {
        expected_pairs.insert (name.to_string(), UiSetupResponseValue::new(name, value, Set));
    }
}
