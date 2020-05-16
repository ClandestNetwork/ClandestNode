// Copyright (c) 2019-2020, MASQ (https://masq.ai) and/or its affiliates. All rights reserved.

use websocket::ClientBuilder;
use std::net::TcpStream;
use websocket::sync::Client;
use masq_lib::utils::localhost;
use masq_lib::messages::NODE_UI_PROTOCOL;

pub fn make_client (port: u16) -> Client<TcpStream> {
    let builder =
        ClientBuilder::new(format!("ws://{}:{}", localhost(), port).as_str()).expect("Bad URL");
    builder.add_protocol(NODE_UI_PROTOCOL).connect_insecure().unwrap()
}
