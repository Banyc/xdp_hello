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
