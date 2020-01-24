// Copyright (c) 2019-2020, MASQ (https://masq.ai) and/or its affiliates. All rights reserved.

mod utils;

use masq_lib::utils::find_free_port;
use masq_lib::ui_gateway::{NodeToUiMessage, NodeFromUiMessage};
use masq_lib::ui_gateway::MessageTarget::ClientId;
use masq_lib::messages::{UiSetup, UiSetupValue};
use masq_lib::messages::ToMessageBody;
use crate::utils::MasqProcess;

//#[test]
//fn handles_setup_integration() {
//    let port = find_free_port();
//    let port_str = format!("{}", port);
//    let server_handle = MockWebSocketsServer::new(port)
//        .queue_response (NodeToUiMessage {
//            target: ClientId(0),
//            body: UiSetup {
//                values: vec![
//                    UiSetupValue { name: "fourthname".to_string(), value: "fourthvalue".to_string() },
//                    UiSetupValue { name: "fifthname".to_string(), value: "fifthvalue".to_string() },
//                ]
//            }.tmb(1234)
//        })
//        .start();
//
//    let masq_handle = MasqProcess::new()
//        .start_noninteractive (vec!["--ui-port", &port_str, "setup", "firstname=firstvalue", "secondname=second value", "third name=thirdvalue"]);
//
//    let (stdout, stderr, exit_code) = masq_handle.stop();
//
//    assert_eq! (exit_code, 0);
//    let requests = server_handle.stop();
//    assert_eq! (requests, vec! [Ok(
//        NodeFromUiMessage {
//            client_id: 0,
//            body: UiSetup {
//                values: vec! [
//                    UiSetupValue { name: "firstname".to_string(), value: "firstvalue".to_string() },
//                    UiSetupValue { name: "secondname".to_string(), value: "second value".to_string() },
//                    UiSetupValue { name: "third name".to_string(), value: "thirdvalue".to_string() },
//                ]
//            }.tmb(1234)
//        }
//    )]);
//    assert_eq! (&stdout,
//        "NAME                      VALUE\nfourthname                fourthvalue\nfifthname                 fifthvalue\n"
//    );
//    assert_eq! (&stderr, "");
//}
