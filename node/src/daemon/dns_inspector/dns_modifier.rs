// Copyright (c) 2017-2019, Substratum LLC (https://substratum.net) and/or its affiliates. All rights reserved.

use std::net::IpAddr;
use crate::daemon::dns_inspector::DnsInspectionError;

pub trait DnsModifier {
    fn inspect(&self) -> Result<Vec<IpAddr>, DnsInspectionError>;
}
