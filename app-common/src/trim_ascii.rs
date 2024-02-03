#[inline]
pub fn trim_ascii_start(b: &[u8]) -> usize {
    let mut pos = 0;
    for c in b {
        if c.is_ascii_whitespace() {
            pos += 1;
        } else {
            break;
        }
    }
    pos
}

#[inline]
pub fn trim_ascii_end(b: &[u8]) -> usize {
    let mut pos = b.len();
    for c in b.iter().rev() {
        if pos == 0 {
            break;
        }
        if c.is_ascii_whitespace() {
            pos -= 1;
        } else {
            break;
        }
    }
    pos
}
