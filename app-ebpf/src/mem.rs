use aya_bpf::programs::XdpContext;

/// Get the data reference from the `ctx`
///
/// # Safety
///
/// You must guarantee that the data of type `T` at `offset` is valid
pub unsafe fn ref_at<T>(ctx: &XdpContext, offset: usize) -> Result<&T, PointedOutOfRange> {
    Ok(&*(ptr_at(ctx, offset)?))
}

pub fn ptr_at<T>(ctx: &XdpContext, offset: usize) -> Result<*const T, PointedOutOfRange> {
    let start = ctx.data();
    let pointed = start + offset;
    let end = ctx.data_end();
    let len = core::mem::size_of::<T>();
    if pointed + len > end {
        return Err(PointedOutOfRange);
    }
    Ok(pointed as _)
}
#[derive(Debug)]
pub struct PointedOutOfRange;

pub fn find(ctx: &XdpContext, from_offset: usize, pat: &[u8]) -> Option<usize> {
    let start = ctx.data() + from_offset;
    let txt_len = ctx.data_end() - start;
    if txt_len < pat.len() {
        return None;
    }

    /* A loop to slide pat[] one by one */
    'txt: for i in 0..=(txt_len - pat.len()).min(usize::MAX) {
        /* For current index i, check for pattern match */
        #[allow(clippy::needless_range_loop)]
        for j in 0..pat.len().min(usize::MAX) {
            let a: &u8 = unsafe { ref_at(ctx, from_offset + i + j) }.ok()?;
            if *a != pat[j] {
                continue 'txt;
            }
        }
        return Some(i);
    }
    None
}
