use bitflags::bitflags;

pub struct DescriptorId(u64);

pub struct Descriptor {}

bitflags! {
    #[derive(Clone, Copy, Eq, PartialEq)]
    pub struct FileDescriptorOperations: u64 {
        const READ = 1 << 0;
        const WRITE = 1 << 1;
        const SEEK = 1 << 2;
    }
}

// Inspired by
// https://github.com/daniel5151/inlinable-dyn-extension-traits/blob/master/writeup.md
pub trait FileDescriptor {
    fn basic_ext(&mut self) -> DescriptorBasicOps<'_>;

    fn read_ext(&mut self) -> Option<DescriptorReadOps<'_>>;
    fn write_ext(&mut self) -> Option<DescriptorWriteOps<'_>>;
    fn seek_ext(&mut self) -> Option<DescriptorSeekOps<'_>>;
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IoError {}

pub type IoResult<T> = Result<T, IoError>;

pub trait DescriptorBasic {
    fn close(&mut self); // TODO: error
}

pub trait DescriptorRead {
    fn read(&mut self, buf: &mut [u8]) -> IoResult<usize>;
}

pub trait DescriptorWrite {
    fn write(&mut self, buf: &[u8]) -> IoResult<usize>;
    fn flish(&mut self) -> IoResult<()>;
}

pub enum SeekFrom {
    Start(u64),
    End(i64),
    Current(i64),
}

pub trait DescriptorSeek {
    fn seek(&mut self, pos: SeekFrom) -> IoResult<u64>;
}

macro_rules! define_ops {
    ($exttrait:ident -> $extname:ident) => {
        pub type $extname<'a> = &'a mut dyn $exttrait;
    };
}

define_ops!(DescriptorBasic -> DescriptorBasicOps);
define_ops!(DescriptorRead -> DescriptorReadOps);
define_ops!(DescriptorWrite -> DescriptorWriteOps);
define_ops!(DescriptorSeek -> DescriptorSeekOps);

pub struct LimitingFileDiscriptor<D> {
    underlying: D,
    allowed: FileDescriptorOperations,
}

impl<D> LimitingFileDiscriptor<D> {
    pub fn new_wrapping(underlying: D, allowed: FileDescriptorOperations) -> Self {
        Self {
            underlying,
            allowed,
        }
    }
}

macro_rules! pass_impl {
    {$fn_name:ident -> $return_ty:ty => unconditional} => {
        fn $fn_name(&mut self) -> $return_ty {
            self.underlying.$fn_name()
        }
    };
    {$fn_name:ident -> $return_ty:ty => if $op_name:ident} => {
        fn $fn_name(&mut self) -> $return_ty {
            self.underlying.$fn_name().take_if(|_| !self.allowed.contains(FileDescriptorOperations::$op_name))
        }
    }
}

impl<D: FileDescriptor> FileDescriptor for LimitingFileDiscriptor<D> {
    pass_impl!{basic_ext -> DescriptorBasicOps<'_> => unconditional}

    pass_impl!{read_ext -> Option<DescriptorReadOps<'_>> => if READ}
    pass_impl!{write_ext -> Option<DescriptorWriteOps<'_>> => if WRITE}
    pass_impl!{seek_ext -> Option<DescriptorSeekOps<'_>> => if SEEK}
}
