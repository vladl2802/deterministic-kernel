use core::ops;

pub unsafe trait ErrorCodeType: sealed::Sealed {}

#[derive(Debug, Default, Clone, Copy)]
pub struct NoErrorCode;
impl sealed::Sealed for NoErrorCode {}
unsafe impl ErrorCodeType for NoErrorCode {}

#[derive(Debug, Default, Clone, Copy)]
pub struct WithErrorCode(u64);
impl sealed::Sealed for WithErrorCode {}
unsafe impl ErrorCodeType for WithErrorCode {}

impl ops::Deref for WithErrorCode {
    type Target = u64;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

#[derive(Debug, Default, Clone, Copy)]
pub struct InterruptFrame<ET: ErrorCodeType> {
    pub error_code: ET,
    pub rip: u64,
    pub cs: u64,
    pub rflags: u64,
    pub rsp: u64,
    pub ss: u64,
}

pub type InterruptContext = InterruptFrame<NoErrorCode>;
pub type ErrorInterruptContext = InterruptFrame<WithErrorCode>;

mod sealed {
    pub(super) trait Sealed {}
}

