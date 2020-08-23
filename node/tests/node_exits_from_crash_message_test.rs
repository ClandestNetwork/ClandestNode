// Copyright (c) 2017-2019, Substratum LLC (https://substratum.net) and/or its affiliates. All rights reserved.

pub mod utils;

use crate::utils::CommandConfig;
use std::path::Path;
#[cfg(not(target_os = "windows"))]
use std::process;
#[cfg(not(target_os = "windows"))]
use std::thread;
#[cfg(not(target_os = "windows"))]
use std::time::Duration;
use websocket::{ClientBuilder, OwnedMessage};
use masq_lib::utils::{localhost, find_free_port};
use masq_lib::constants::DEFAULT_UI_PORT;
use masq_lib::ui_traffic_converter::UiTrafficConverter;
use masq_lib::messages::{UiCrashRequest, ToMessageBody};
use futures::future::*;
use tokio::prelude::*;
use tokio::runtime::Runtime;

#[test]
fn node_exits_from_blockchain_bridge_panic_integration() {
    start_node_and_request_crash(node_lib::blockchain::blockchain_bridge::CRASH_KEY);
}

fn start_node_and_request_crash (crash_key: &str) {
    let port = find_free_port();
    let panic_config = CommandConfig::new()
        .pair("--crash-point", "message")
        .pair("--neighborhood-mode", "zero-hop")
        .pair("--ui-port", format!("{}", port).as_str());
    let mut node = utils::MASQNode::start_standard(Some(panic_config));
    let msg = UiTrafficConverter::new_marshal (UiCrashRequest {
        actor: crash_key.to_string(),
        panic_message: "Test panic".to_string()
    }.tmb(0));
    let client =
        ClientBuilder::new(format!("ws://{}:{}", localhost(), port).as_str())
            .expect("Couldn't create ClientBuilder")
            .add_protocol("MASQNode-UIv2")
            .async_connect_insecure()
            .and_then(|(s, _)| s.send(OwnedMessage::Text(msg)));
    let mut rt = Runtime::new().expect("Couldn't create Runtime");
    rt.block_on(client)
        .expect("Couldn't block on descriptor_client");

    let success = node.wait_for_exit().unwrap().status.success();
    assert!(!success, "Did not fail as expected");
}