//! `velcrux-server` library components.

#![forbid(unsafe_code)]

pub mod config;
pub mod dev_pki;
pub mod limits;
pub mod metrics;
pub mod server;
pub mod sessions;

pub use limits::LimitsManager;
