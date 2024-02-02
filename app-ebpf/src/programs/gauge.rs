use app_common::gauge::{increment_packets, MapInsertionError};
use aya_bpf::{bindings::xdp_action, programs::XdpContext};

use crate::{address::five_tuple, error::AbortMsg, mem::PointedOutOfRange};

pub fn main(ctx: &XdpContext) -> Result<u32, ParseError> {
    // Parse port number from the packet
    let Some(tuple) = five_tuple(ctx)? else {
        return Ok(xdp_action::XDP_PASS);
    };

    increment_packets(tuple.dst.port)?;

    Ok(xdp_action::XDP_PASS)
}

#[derive(Debug)]
pub enum ParseError {
    Mem(PointedOutOfRange),
    Map(MapInsertionError),
}
impl AbortMsg for ParseError {
    fn err_msg(&self) -> &'static str {
        match self {
            ParseError::Mem(_) => "pointed value out of range",
            ParseError::Map(_) => "failed to insert value to a map",
        }
    }
}
impl From<PointedOutOfRange> for ParseError {
    fn from(value: PointedOutOfRange) -> Self {
        Self::Mem(value)
    }
}
impl From<MapInsertionError> for ParseError {
    fn from(value: MapInsertionError) -> Self {
        Self::Map(value)
    }
}
