// Copyright (c) 2019-2020, MASQ (https://masq.ai). All rights reserved.

use crate::communications::connection_manager::BroadcastHandler;
use masq_lib::ui_gateway::MessageBody;

pub struct BroadcastHandlerReal {}

impl BroadcastHandler for BroadcastHandlerReal {
    fn handle(&self, _message_body: MessageBody) -> () {
        unimplemented!()
    }
}

impl BroadcastHandlerReal {
    pub fn new() -> Self {
        Self {}
    }
}
