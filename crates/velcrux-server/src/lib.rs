//! `velcrux-server` library components.

#![forbid(unsafe_code)]

pub mod api;
pub mod config;
pub mod dev_pki;
pub mod limits;
pub mod metrics;
pub mod server;
pub mod sessions;

pub use api::{
    start_api_server, ApiServerContext, GcResponse, KillSessionResponse, ServerStatusResponse,
};
pub use limits::{LimitsManager, QuotaReservation, TenantQuotaInfo};
pub use sessions::{SessionInfo, SessionRegistry};
