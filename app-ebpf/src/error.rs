use core::convert::Infallible;

pub trait AbortMsg {
    fn err_msg(&self) -> &str;
}
impl AbortMsg for Infallible {
    fn err_msg(&self) -> &str {
        ""
    }
}
