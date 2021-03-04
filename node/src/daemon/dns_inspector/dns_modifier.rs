// Copyright (c) 2017-2019, Substratum LLC (https://substratum.net) and/or its affiliates. All rights reserved.

use crate::daemon::dns_inspector::DnsInspectionError;
use std::net::IpAddr;

pub trait DnsModifier {
    fn inspect(&self) -> Result<Vec<IpAddr>, DnsInspectionError>;
}
