// Copyright (c) 2019-2020, MASQ (https://masq.ai) and/or its affiliates. All rights reserved.

use crate::utils::DaemonProcess;
use crate::utils::MasqProcess;
use std::thread;
use std::time::Duration;

mod utils;

#[test]
fn setup_results_are_broadcast_to_all_uis() {
    let daemon_handle = DaemonProcess::new().start(5333);
    thread::sleep(Duration::from_millis(500));
    let mut setupper_handle = MasqProcess::new().start_interactive();
    let mut receiver_handle = MasqProcess::new().start_interactive();

    setupper_handle.type_command("setup --neighborhood-mode zero-hop");

    let (stdout, stderr) = receiver_handle.get_response();
    setupper_handle.type_command("exit");
    receiver_handle.type_command("exit");
    daemon_handle.kill();
    assert_eq!(&stderr, "", "{}", stderr);
    assert_eq!(
        stdout.contains("neighborhood-mode         zero-hop"),
        true,
        "{}",
        stdout
    );
}
