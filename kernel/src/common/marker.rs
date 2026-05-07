#[derive(Debug, Clone, Copy, Default)]
pub struct Unsend(*const ());
unsafe impl Sync for Unsend {}

#[derive(Debug, Clone, Copy, Default)]
pub struct Unsync(*const ());
unsafe impl Send for Unsync {}
