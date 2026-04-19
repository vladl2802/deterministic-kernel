use core::{
    cell::UnsafeCell,
    fmt::{self, Write},
};

use crate::single_thread_lock::SingleThreadLock;

use arch_x86_64::instructions::{self, port};
use log;

// In general there is an idea that hypervisor will need to parse kernel logs
// in order to provide sence of time as kernel will not be aware of it

struct LogCollector {
    level: log::Level,
    logger: SingleThreadLock<Option<PortLogger>>,
}

// it's not true, but is required for now
unsafe impl Send for LogCollector {}
unsafe impl Sync for LogCollector {}

// UnsafeCell is used here until SpinLock is implemented
// as long as kernel does not have any concurrent actions
// PortLogger will not have concurrent `log` calls, so this is safe
// So for now `log` in interrupts is prohibitted
// TODO: what if we panicked during `log`? Can we reuse this port without UB?
struct PortLogger(UnsafeCell<PortWritter>);

// it's not true, but is required for now
unsafe impl Send for PortLogger {}
unsafe impl Sync for PortLogger {}

struct PortWritter(port::Port<u8>);

impl LogCollector {
    const fn new() -> Self {
        LogCollector {
            level: log::Level::Trace,
            logger: SingleThreadLock::new_unlocked(None),
        }
    }

    fn finish_init(&self, port: u16) {
        self.logger
            .with_lock(|logger| *logger = Some(PortLogger::new(port)));
    }

    // Must only be called after finish_init
    fn with_logger<R>(&self, body: impl FnOnce(&mut PortLogger) -> R) -> R {
        self.logger.with_lock(|logger| {
            let logger = logger.as_mut().expect("log collector not initialized");
            body(logger)
        })
    }
}

impl log::Log for LogCollector {
    fn enabled(&self, metadata: &log::Metadata) -> bool {
        metadata.level() <= self.level
    }

    fn log(&self, record: &log::Record) {
        if !self.enabled(record.metadata()) {
            return;
        }
        // TODO: probably need is_panicking check here
        // TODO: some binary protocol is needed, because panic could happen during logging

        // tsc here is temporal as it cannot be made deterministic (afaik)
        // instead of it I'm planning to use pmu counters
        // TODO: change to instructions_retired
        let tsc = unsafe { instructions::rdtsc() };

        let log_line = format_args!("{}-[{}]: {}", tsc, record.level(), record.args());
        self.with_logger(|logger| logger.log(&log_line));
    }

    fn flush(&self) {}
}

impl PortLogger {
    pub fn new(port: u16) -> Self {
        Self(UnsafeCell::new(PortWritter::new(port)))
    }

    pub fn log(&self, record: &fmt::Arguments) {
        let writter = unsafe { &mut *self.0.get() };
        writeln!(writter, "{}", record).expect("couldn't write log to port");
    }
}

impl PortWritter {
    pub fn new(port: u16) -> Self {
        Self(port::Port::new(port))
    }
}

impl Write for PortWritter {
    fn write_str(&mut self, s: &str) -> fmt::Result {
        s.bytes()
            .into_iter()
            .for_each(|byte| unsafe { self.0.write(byte) });
        Ok(())
    }
}

pub(crate) fn init(log_port: u16) {
    LOG_COLLECTOR.finish_init(log_port);
    log::set_logger(&LOG_COLLECTOR)
        .map(|()| log::set_max_level(log::LevelFilter::Trace))
        .expect("couldn't set log collector");
}

static LOG_COLLECTOR: LogCollector = LogCollector::new();
