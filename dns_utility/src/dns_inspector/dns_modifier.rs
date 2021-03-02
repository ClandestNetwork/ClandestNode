// Copyright (c) 2017-2019, Substratum LLC (https://substratum.net) and/or its affiliates. All rights reserved.

use std::net::IpAddr;
use crate::dns_inspector::DnsInspectionError;

pub trait DnsModifier {
    fn type_name(&self) -> &'static str;
    fn inspect(&self) -> Result<Vec<IpAddr>, DnsInspectionError>;
}
