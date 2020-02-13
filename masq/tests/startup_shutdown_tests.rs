// Copyright (c) 2019-2020, MASQ (https://masq.ai) and/or its affiliates. All rights reserved.

use crate::utils::MasqProcess;
use masq_cli_lib::test_utils::mock_websockets_server::MockWebSocketsServer;
use masq_lib::messages::{ToMessageBody, UiSetup, UiSetupValue};
use masq_lib::ui_gateway::MessageTarget::ClientId;
use masq_lib::ui_gateway::{NodeFromUiMessage, NodeToUiMessage};
use masq_lib::utils::find_free_port;

mod utils;

#[test]
fn handles_startup_and_shutdown_integration() {
    let masq_handle = MasqProcess::new().start_noninteractive(vec![
        "setup",
        "neighborhood-mode=zero-hop",
    ]);

    let (stdout, stderr, exit_code) = masq_handle.stop();

    assert_eq!(exit_code, 0);
    assert_eq! (stdout.contains ("neighborhood-mode         zero-hop"), true, "{}", stdout);
    assert_eq!(&stderr, "", "{}", stderr);

    let masq_handle = MasqProcess::new().start_noninteractive(vec![
        "start",
    ]);

    let (stdout, stderr, exit_code) = masq_handle.stop();

    assert_eq!(exit_code, 0);
    assert_eq! (stdout.contains ("MASQNode successfully started as process"), true, "{}", stdout);
    assert_eq!(&stderr, "", "{}", stderr);

    let masq_handle = MasqProcess::new().start_noninteractive(vec![
        "shutdown",
    ]);

    let (stdout, stderr, exit_code) = masq_handle.stop();

    assert_eq!(exit_code, 0);
    assert_eq! (stdout.contains ("MASQNode was instructed to shut down and has broken its connection"), true, "{}", stdout);
    assert_eq!(&stderr, "", "{}", stderr);
}
