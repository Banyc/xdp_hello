pub trait ErrorMsg {
    fn err_msg(&self) -> &str;
}
impl ErrorMsg for () {
    fn err_msg(&self) -> &str {
        ""
    }
}
