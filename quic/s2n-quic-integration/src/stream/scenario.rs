use crate::stream::Data;
use core::time::Duration;
use std::collections::BTreeMap;

// TODO derive(bolero_generator::TypeGenerator)

#[derive(Clone, Debug, PartialEq, PartialOrd, Eq, Ord)]
pub struct Scenario {
    pub client: Streams,
    pub server: Streams,
}

#[derive(Clone, Debug, PartialEq, PartialOrd, Eq, Ord)]
pub struct Streams {
    pub uni_streams: BTreeMap<u64, UniStream>,
    pub bidi_streams: BTreeMap<u64, BidiStream>,
}

#[derive(Copy, Clone, Debug, PartialEq, PartialOrd, Eq, Ord)]
pub struct UniStream {
    pub delay: Duration,
    pub local: Stream,
}

#[derive(Copy, Clone, Debug, PartialEq, PartialOrd, Eq, Ord)]
pub struct BidiStream {
    pub delay: Duration,
    pub local: Stream,
    pub peer: Stream,
}

#[derive(Copy, Clone, Debug, PartialEq, PartialOrd, Eq, Ord)]
pub struct Stream {
    pub data: Data,
    pub reset: Option<Error>,
    pub stop_sending: Option<Error>,
    pub send_amount: usize,
}

#[derive(Copy, Clone, Debug, PartialEq, PartialOrd, Eq, Ord)]
pub struct Error {
    pub offset: usize,
    pub code: u64,
}
