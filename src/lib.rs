#![feature(trivial_bounds)]
#![feature(unboxed_closures)]
#![feature(fn_traits)]

extern crate futures;
extern crate futures_retry;
extern crate tokio_core;
extern crate tun_tap;
extern crate miscreant;
extern crate spake2;
extern crate keybob;

pub mod vpn;
pub mod en;
pub mod server;