//! Minimal leveled stderr logger. Level: 0 = warn, 1 = info, 2 = debug.

use std::sync::atomic::{AtomicU8, Ordering};

pub static LEVEL: AtomicU8 = AtomicU8::new(1);

pub fn set_level(l: u8) {
    LEVEL.store(l, Ordering::Relaxed);
}

pub fn enabled(l: u8) -> bool {
    LEVEL.load(Ordering::Relaxed) >= l
}

#[macro_export]
macro_rules! logw {
    ($($t:tt)*) => { eprintln!("[warn] {}", format_args!($($t)*)) };
}

#[macro_export]
macro_rules! logi {
    ($($t:tt)*) => {
        if $crate::log::enabled(1) { eprintln!("[info] {}", format_args!($($t)*)) }
    };
}

#[macro_export]
macro_rules! logd {
    ($($t:tt)*) => {
        if $crate::log::enabled(2) { eprintln!("[debug] {}", format_args!($($t)*)) }
    };
}
